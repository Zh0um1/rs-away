//! 把 [`SessionData`] 适配成 `AsyncRead + AsyncWrite`。
//!
//! 权威：`docs/plan.md` §4.8（会话模型）、§4.9（有界通道 32 帧 + 背压）。
//!
//! 会话层的业务代码（SOCKS5 中继、forward、shell、文件）都只想面对一条
//! 字节流；协议层给的是带 `seq` 的离散 `SessionData`。本模块就是这两者
//! 之间的桥：
//!
//! - 读方向：收 `seq` 严格递增的数据块，拼成字节流喂给 `poll_read`；
//!   序号跳变一律报错（v1 没有序号，乱序即数据损坏）。
//! - 写方向：`poll_write` 把字节切块、分配出站 `seq`、投进有界通道；
//!   通道满则返回 `Pending`（**背压**而不是无界缓存）。
//!
//! 对端节点必须显式携带（[`SessionOutbound::Data.dest`]）：v2 的帧没有
//! sender 字段，会话另一端无法从帧里反推出来。

use std::pin::Pin;
use std::task::{Context, Poll};

use stowaway_protocol::{
    ByteBuf, CloseReason, Message, NodeId, ProtocolError, SessionClose, SessionData, SessionKey,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::error::{CoreError, Result};

/// 会话流向外发的东西。
#[derive(Debug)]
pub enum SessionOutbound {
    /// 一块数据（`seq` 已由流分配）。
    Data {
        /// 会话对端。
        dest: NodeId,
        /// 已带序号的载荷。
        data: SessionData,
    },
    /// 会话结束。
    Close {
        /// 会话对端。
        dest: NodeId,
        /// 结束原因。
        close: SessionClose,
    },
}

impl SessionOutbound {
    /// 目标节点。
    #[must_use]
    pub const fn dest(&self) -> NodeId {
        match self {
            Self::Data { dest, .. } | Self::Close { dest, .. } => *dest,
        }
    }
}

/// 把出站事件翻译成「发给谁 + 发什么」。
#[must_use]
pub fn outbound_message(out: SessionOutbound) -> (NodeId, Message) {
    match out {
        SessionOutbound::Data { dest, data } => (dest, Message::SessionData(data)),
        SessionOutbound::Close { dest, close } => (dest, Message::SessionClose(close)),
    }
}

/// 一条会话的字节流视图。
#[derive(Debug)]
pub struct SessionStream {
    key: SessionKey,
    dest: NodeId,
    out: mpsc::Sender<SessionOutbound>,
    inbound: mpsc::Receiver<SessionData>,
    send_seq: u64,
    recv_seq: u64,
    read_buf: Vec<u8>,
    read_pos: usize,
    inbound_done: bool,
    outbound_done: bool,
}

impl SessionStream {
    /// 新建一条会话流，返回（流本身，入站数据投递端）。
    ///
    /// 投递端应交给 [`crate::Node::bind_session`]，由节点在收到
    /// `SessionData` 时把数据送进来。
    #[must_use]
    pub fn new(
        key: SessionKey,
        dest: NodeId,
        out: mpsc::Sender<SessionOutbound>,
        capacity: usize,
    ) -> (Self, mpsc::Sender<SessionData>) {
        let (in_tx, inbound) = mpsc::channel(capacity.max(1));
        let stream = Self {
            key,
            dest,
            out,
            inbound,
            send_seq: 0,
            recv_seq: 0,
            read_buf: Vec::new(),
            read_pos: 0,
            inbound_done: false,
            outbound_done: false,
        };
        (stream, in_tx)
    }

    /// 会话键。
    #[must_use]
    pub const fn key(&self) -> SessionKey {
        self.key
    }

    /// 会话对端。
    #[must_use]
    pub const fn dest(&self) -> NodeId {
        self.dest
    }

    /// 已发出的数据块数。
    #[must_use]
    pub const fn sent_blocks(&self) -> u64 {
        self.send_seq
    }

    /// 已接收的数据块数。
    #[must_use]
    pub const fn received_blocks(&self) -> u64 {
        self.recv_seq
    }

    /// 当前缓冲的未读字节数。
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.read_buf.len().saturating_sub(self.read_pos)
    }

    /// 收一块入站数据（序号必须严格递增）。
    fn accept(&mut self, data: SessionData) -> Result<()> {
        if data.key != self.key {
            return Err(CoreError::Protocol(ProtocolError::Payload(format!(
                "会话数据属于 {:?}，当前流是 {:?}",
                data.key, self.key
            ))));
        }
        if data.seq != self.recv_seq {
            return Err(CoreError::Protocol(ProtocolError::Payload(format!(
                "会话 {} 数据序号不连续：期望 {}，收到 {}",
                self.key.id, self.recv_seq, data.seq
            ))));
        }
        self.recv_seq += 1;
        if self.read_pos > 0 {
            self.read_buf.drain(..self.read_pos);
            self.read_pos = 0;
        }
        self.read_buf.extend_from_slice(&data.data);
        Ok(())
    }
}

impl AsyncRead for SessionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let me = &mut *self;
            if me.read_pos < me.read_buf.len() {
                let avail = &me.read_buf[me.read_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                me.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            if me.inbound_done {
                return Poll::Ready(Ok(()));
            }
            match me.inbound.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    if let Err(e) = me.accept(data) {
                        // 序号跳变属于协议违规：转成 io 错误让上层断开，
                        // 而不是假装读到 0 字节（v1 的静默空载荷，缺陷 #8/#9）。
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                }
                Poll::Ready(None) => {
                    me.inbound_done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SessionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = &mut *self;
        if me.outbound_done {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "会话已关闭",
            )));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match me.out.try_reserve() {
            Ok(permit) => {
                let seq = me.send_seq;
                me.send_seq += 1;
                permit.send(SessionOutbound::Data {
                    dest: me.dest,
                    data: SessionData {
                        key: me.key,
                        seq,
                        data: ByteBuf::from(data),
                    },
                });
                Poll::Ready(Ok(data.len()))
            }
            Err(mpsc::error::TrySendError::Full(())) => {
                // 有界通道满 → 明确背压（plan §4.9：满则 Pending）。
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                me.outbound_done = true;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "会话出站通道已关闭",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 出站数据由节点异步发送，这里没有可排空的本地缓冲。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        if me.outbound_done {
            return Poll::Ready(Ok(()));
        }
        me.outbound_done = true;
        let close = SessionClose {
            key: me.key,
            reason: CloseReason::Normal,
            detail: String::new(),
        };
        let _ = me.out.try_send(SessionOutbound::Close {
            dest: me.dest,
            close,
        });
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_protocol::NodeId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn key() -> SessionKey {
        SessionKey::new(NodeId::ADMIN, 7)
    }

    #[tokio::test]
    async fn write_assigns_monotonic_sequence_numbers() {
        let (tx, mut rx) = mpsc::channel(8);
        let (mut stream, _in) = SessionStream::new(key(), NodeId::ADMIN, tx, 8);
        stream.write_all(b"abc").await.expect("write");
        stream.write_all(b"de").await.expect("write");
        let SessionOutbound::Data { dest, data } = rx.recv().await.expect("recv") else {
            panic!("expected data");
        };
        assert_eq!(dest, NodeId::ADMIN);
        assert_eq!(data.seq, 0);
        assert_eq!(&data.data[..], b"abc");
        let SessionOutbound::Data { data, .. } = rx.recv().await.expect("recv") else {
            panic!("expected data");
        };
        assert_eq!(data.seq, 1);
        assert_eq!(&data.data[..], b"de");
    }

    #[tokio::test]
    async fn read_reassembles_blocks_in_order() {
        let (tx, _rx) = mpsc::channel(8);
        let (mut stream, inbound) = SessionStream::new(key(), NodeId::ADMIN, tx, 8);
        inbound
            .send(SessionData {
                key: key(),
                seq: 0,
                data: ByteBuf::from(&b"hello "[..]),
            })
            .await
            .expect("send");
        inbound
            .send(SessionData {
                key: key(),
                seq: 1,
                data: ByteBuf::from(&b"world"[..]),
            })
            .await
            .expect("send");
        drop(inbound);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, b"hello world");
    }

    #[tokio::test]
    async fn out_of_order_data_is_an_io_error() {
        let (tx, _rx) = mpsc::channel(8);
        let (mut stream, inbound) = SessionStream::new(key(), NodeId::ADMIN, tx, 8);
        inbound
            .send(SessionData {
                key: key(),
                seq: 3,
                data: ByteBuf::from(&b"x"[..]),
            })
            .await
            .expect("send");
        drop(inbound);
        let mut buf = [0u8; 4];
        let err = stream.read(&mut buf).await.expect_err("必须报错");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn full_outbound_channel_is_backpressure_not_loss() {
        let (tx, _rx) = mpsc::channel(1);
        let (mut stream, _in) = SessionStream::new(key(), NodeId::ADMIN, tx, 4);
        stream.write_all(b"first").await.expect("write");
        // 通道容量 1 已满：第二次写必须挂起（背压），而不是丢弃数据。
        let pending = tokio::time::timeout(std::time::Duration::from_millis(150), async {
            stream.write_all(b"second").await
        })
        .await;
        assert!(pending.is_err(), "满通道必须返回 Pending（背压）");
    }

    #[tokio::test]
    async fn shutdown_emits_close_with_reason_normal() {
        let (tx, mut rx) = mpsc::channel(8);
        let (mut stream, _in) = SessionStream::new(key(), NodeId::ADMIN, tx, 8);
        stream.shutdown().await.expect("shutdown");
        let SessionOutbound::Close { dest, close } = rx.recv().await.expect("recv") else {
            panic!("expected close");
        };
        assert_eq!(dest, NodeId::ADMIN);
        assert_eq!(close.key, key());
        assert_eq!(close.reason, CloseReason::Normal);
    }
}
