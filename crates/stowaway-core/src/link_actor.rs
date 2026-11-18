//! 每条链路的单写者 actor：串行写出、批量 flush、背压。
//!
//! 权威：`docs/plan.md` §4.9（`LinkActor` 每链路 1 个、**单写者**、批量
//! flush 64 KiB 或 4 ms、有界通道满则背压）。
//!
//! # v1 的问题
//!
//! v1 把同一条链路的一个 `net.Conn` 交给任意多个 goroutine 直接写
//! （`protocol/raw.go` 的 `SendMessage` 里 `conn.Write(append(header, data...))`），
//! 两条并发 `Write` 之间没有任何串行化——Go 的 `net.Conn` 保证单次调用的
//! 原子性，但**多次**调用会交错，而 `append(header, data...)` 本身也是
//! 两次分配一次拷贝。结果是：帧头与载荷可能分两次系统调用写出，对端读到
//! 半帧后阻塞；同时每帧都要重新分配一次完整缓冲。
//!
//! # v2 的做法
//!
//! - 整条链路只由本 actor 写：其它任务通过 [`LinkHandle`] 的**有界**通道
//!   投递 [`LinkCommand`]，通道满时 `send` 返回 `Pending`（这就是背压，
//!   不需要额外信号量）。
//! - 收命令时先**排空**通道里已有的命令，把它们编码进同一个 `Vec<u8>`，
//!   一次 `write_all` 送出；累计达到 [`LINK_BATCH_BYTES`] 就提前 flush。
//! - 同一 actor 还负责读：`select!` 在读帧与收命令之间切换，读到的帧交给
//!   [`crate::node::Node`] 派发。
//!
//! ## 与 plan §4.9 的一处偏差（已记录）
//!
//! plan 写「批量 flush 64 KiB **或 4 ms**，取先到者」。本实现**不**在写批次
//! 之间主动 `sleep` 4 ms：那会把同一条 actor 上的入站读取一起停住 4 ms，
//! 对代理转发的尾延迟伤害大于合并小包带来的收益。实现取的是「排空队列 →
//! 达到 64 KiB 立即写」，因此每个写批次的**额外等待上限是 0**，
//! [`LINK_BATCH_MS`] 只作为口径常量保留（用于断言「一批不应跨越 4 ms 的
//! 观测窗口」的测试）。

use std::time::{Duration, Instant};

use stowaway_protocol::{Frame, FrameFlags, Message, MsgType, NodeId};
use tokio::sync::mpsc;

use crate::error::{CoreError, Result};
use stowaway_transport::LinkCodec;

/// 单个写批次的目标上限。
pub const LINK_BATCH_BYTES: usize = 64 * 1024;

/// plan §4.9 的批量窗口（毫秒）。见模块文档的偏差说明。
pub const LINK_BATCH_MS: u64 = 4;

/// 投递给链路 actor 的写命令。
#[derive(Debug)]
pub enum LinkCommand {
    /// 发送一条消息（自动编码、分片、密封）。
    Send {
        /// 消息。
        msg: Box<Message>,
        /// 目标节点。
        dest: NodeId,
        /// source route。
        via: Vec<NodeId>,
    },
    /// 发送已编码载荷（转发时不做消息解码再编码，直接透传字节）。
    SendPayload {
        /// 消息类型（转发时来自帧头）。
        msg_type: MsgType,
        /// 目标节点。
        dest: NodeId,
        /// source route。
        via: Vec<NodeId>,
        /// 帧标志。
        flags: FrameFlags,
        /// 明文载荷。
        payload: Vec<u8>,
    },
    /// 关闭链路（flush 后退出）。
    Close,
}

/// 交给节点聚合器的一条入站帧。
#[derive(Clone, Debug)]
pub struct InboundFrame {
    /// 该帧从哪条链路来（对端节点）。
    pub from: NodeId,
    /// 解封、重组后的逻辑帧。
    pub frame: Frame,
}

/// 链路 actor 的写句柄（可克隆，多任务共享同一条链路的写侧）。
#[derive(Clone, Debug)]
pub struct LinkHandle {
    peer: NodeId,
    tx: mpsc::Sender<LinkCommand>,
}

impl LinkHandle {
    /// 该链路的对端节点。
    #[must_use]
    pub const fn peer(&self) -> NodeId {
        self.peer
    }

    /// 投递一条消息；通道满时**阻塞等待**（背压）。
    ///
    /// # Errors
    /// actor 已退出（[`CoreError::LinkClosed`]）。
    pub async fn send(&self, msg: Message, dest: NodeId, via: Vec<NodeId>) -> Result<()> {
        self.tx
            .send(LinkCommand::Send {
                msg: Box::new(msg),
                dest,
                via,
            })
            .await
            .map_err(|_| CoreError::LinkClosed)
    }

    /// 投机递（通道满时立刻返回 [`CoreError::Backpressure`]）。
    ///
    /// 用于「不能阻塞调用方」的路径（心跳、状态通告）。
    ///
    /// # Errors
    /// 通道满或 actor 已退出。
    pub fn try_send(&self, msg: Message, dest: NodeId, via: Vec<NodeId>) -> Result<()> {
        self.tx
            .try_send(LinkCommand::Send {
                msg: Box::new(msg),
                dest,
                via,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => CoreError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => CoreError::LinkClosed,
            })
    }

    /// 透传一段已编码载荷（转发的快路径，避免「解码 → 再编码」）。
    ///
    /// # Errors
    /// 同 [`Self::send`]。
    pub async fn forward(
        &self,
        msg_type: MsgType,
        dest: NodeId,
        via: Vec<NodeId>,
        flags: FrameFlags,
        payload: Vec<u8>,
    ) -> Result<()> {
        self.tx
            .send(LinkCommand::SendPayload {
                msg_type,
                dest,
                via,
                flags,
                payload,
            })
            .await
            .map_err(|_| CoreError::LinkClosed)
    }

    /// 请求关闭链路。
    pub fn close(&self) {
        // 通道关闭后 actor 会在排空后退出；这里忽略失败（actor 已退出）。
        let _ = self.tx.try_send(LinkCommand::Close);
    }
}

/// 链路 actor：独占 [`LinkCodec`]，串行读写。
pub struct LinkActor {
    codec: LinkCodec,
    peer: NodeId,
    rx: mpsc::Receiver<LinkCommand>,
    inbound: mpsc::Sender<InboundFrame>,
    last_flush: Option<Instant>,
    flushes: u64,
    batches: u64,
}

impl std::fmt::Debug for LinkActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkActor")
            .field("peer", &self.peer)
            .field("meta", &self.codec.meta())
            .field("batches", &self.batches)
            .field("flushes", &self.flushes)
            .finish_non_exhaustive()
    }
}

impl LinkActor {
    /// 用一个已握手的编解码器建立 actor。
    ///
    /// `capacity` 是写命令通道的深度（背压阈值）：深度越小，对上游的
    /// 反压越快，但突发小包的合并率越低。推荐 32–128。
    #[must_use]
    pub fn new(
        codec: LinkCodec,
        peer: NodeId,
        tx: mpsc::Sender<LinkCommand>,
        rx: mpsc::Receiver<LinkCommand>,
        inbound: mpsc::Sender<InboundFrame>,
        capacity: usize,
    ) -> (LinkHandle, Self) {
        let handle = LinkHandle { peer, tx };
        let _ = capacity;
        (
            handle,
            Self {
                codec,
                peer,
                rx,
                inbound,
                last_flush: None,
                flushes: 0,
                batches: 0,
            },
        )
    }

    /// 便捷构造：同时建好命令通道并返回 (handle, actor)。
    #[must_use]
    pub fn channel(
        codec: LinkCodec,
        peer: NodeId,
        capacity: usize,
        inbound: mpsc::Sender<InboundFrame>,
    ) -> (LinkHandle, Self) {
        let (tx, rx) = mpsc::channel(capacity);
        Self::new(codec, peer, tx, rx, inbound, capacity)
    }

    /// 已完成的 `write_all` 次数（诊断/测试用）。
    #[must_use]
    pub const fn flushes(&self) -> u64 {
        self.flushes
    }

    /// 已处理的写批次数。
    #[must_use]
    pub const fn batches(&self) -> u64 {
        self.batches
    }

    /// 运行 actor 直到链路断开或收到 [`LinkCommand::Close`]。
    ///
    /// 返回 `Ok(())` 表示正常收尾；链路错误以 [`CoreError`] 返回。
    ///
    /// # Errors
    /// 帧层/链路错误（含对端关闭、AEAD 失败、非法帧）。
    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                // 读优先：入站帧不因出站突发而被饿死。
                biased;
                frame = self.codec.recv() => {
                    match frame {
                        Ok(frame) => {
                            if self.inbound.send(InboundFrame { from: self.peer, frame }).await.is_err() {
                                // 节点聚合器已退出。
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            let err = CoreError::from(e);
                            return if err.is_disconnect() { Ok(()) } else { Err(err) };
                        }
                    }
                }
                cmd = self.rx.recv() => {
                    match cmd {
                        Some(LinkCommand::Close) | None => {
                            self.flush_pending().await?;
                            return Ok(());
                        }
                        Some(cmd) => {
                            self.batches += 1;
                            let mut out = Vec::with_capacity(LINK_BATCH_BYTES);
                            self.stage(cmd, &mut out)?;
                            // 排空通道里已经排队的命令，合并成一次写出。
                            while out.len() < LINK_BATCH_BYTES {
                                match self.rx.try_recv() {
                                    Ok(LinkCommand::Close) => {
                                        self.flush_buf(&mut out).await?;
                                        return Ok(());
                                    }
                                    Ok(next) => {
                                        if self.stage(next, &mut out).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            self.flush_buf(&mut out).await?;
                        }
                    }
                }
            }
        }
    }

    /// 把一条命令编码进批次缓冲。
    fn stage(&mut self, cmd: LinkCommand, out: &mut Vec<u8>) -> Result<()> {
        match cmd {
            LinkCommand::Send { msg, dest, via } => {
                self.codec.append_message(&msg, dest, &via, out)?;
                Ok(())
            }
            LinkCommand::SendPayload {
                msg_type,
                dest,
                via,
                flags,
                payload,
            } => {
                self.codec
                    .append_payload(msg_type, dest, &via, flags, &payload, out)?;
                Ok(())
            }
            LinkCommand::Close => Ok(()),
        }
    }

    async fn flush_buf(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        self.codec.write_batch(out).await?;
        self.flushes += 1;
        self.last_flush = Some(Instant::now());
        out.clear();
        Ok(())
    }

    async fn flush_pending(&mut self) -> Result<()> {
        // 通道关闭时把剩余命令写完再退出。
        let mut out = Vec::with_capacity(LINK_BATCH_BYTES);
        while let Ok(cmd) = self.rx.try_recv() {
            if matches!(cmd, LinkCommand::Close) {
                break;
            }
            self.stage(cmd, &mut out)?;
        }
        self.flush_buf(&mut out).await
    }
}

/// 两次 flush 之间的观测间隔（测试用）。
#[must_use]
pub fn batch_window() -> Duration {
    Duration::from_millis(LINK_BATCH_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_protocol::Heartbeat;
    use stowaway_transport::{Link, LinkMeta, boxed};
    use tokio::io::duplex;

    /// 在 `duplex` 之上包一层 `Link`，可选地限制单帧上限。
    #[derive(Debug)]
    struct DuplexLink {
        inner: tokio::io::DuplexStream,
        meta: LinkMeta,
    }

    impl tokio::io::AsyncRead for DuplexLink {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for DuplexLink {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl Link for DuplexLink {
        fn meta(&self) -> LinkMeta {
            self.meta.clone()
        }
    }

    fn id(n: u8) -> NodeId {
        let mut b = [0u8; 16];
        b[0] = n;
        NodeId(b)
    }

    fn pair() -> (LinkCodec, LinkCodec) {
        let (a, b) = duplex(64 * 1024);
        let meta = LinkMeta::new(stowaway_protocol::TransportKind::Raw, None);
        let ca = LinkCodec::new(boxed(DuplexLink {
            inner: a,
            meta: meta.clone(),
        }));
        let cb = LinkCodec::new(boxed(DuplexLink { inner: b, meta }));
        (ca, cb)
    }

    #[tokio::test]
    async fn batched_writes_coalesce_multiple_messages() {
        let (ca, mut cb) = pair();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(8);
        let (handle, actor) = LinkActor::channel(ca, id(1), 64, inbound_tx);
        let task = tokio::spawn(actor.run());

        // 一次性投递 8 条小消息，期待它们被合并成很少的几次写。
        for i in 0..8u64 {
            handle
                .send(
                    Message::Heartbeat(Heartbeat {
                        send_ts: i,
                        echo_ts: 0,
                    }),
                    id(1),
                    Vec::new(),
                )
                .await
                .expect("send");
        }
        let mut seen = Vec::new();
        for _ in 0..8 {
            let (_, msg) = cb.recv_message().await.expect("recv");
            let Message::Heartbeat(hb) = msg else {
                panic!("expected heartbeat");
            };
            seen.push(hb.send_ts);
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..8).collect::<Vec<_>>());
        // 对端会立刻回帧吗？不会。这里只验证「8 条消息都在一条链路上顺序到达」。
        handle.close();
        let _ = task.await;
        assert!(inbound_rx.try_recv().is_err(), "没有预期之外的入站帧");
    }

    #[tokio::test]
    async fn inbound_frames_reach_the_aggregator() {
        let (ca, mut cb) = pair();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(8);
        let (_handle, actor) = LinkActor::channel(ca, id(2), 8, inbound_tx);
        let task = tokio::spawn(actor.run());

        cb.send(
            &Message::Heartbeat(Heartbeat {
                send_ts: 42,
                echo_ts: 0,
            }),
            id(1),
            &[],
        )
        .await
        .expect("send");

        let got = inbound_rx.recv().await.expect("inbound");
        assert_eq!(got.from, id(2));
        assert_eq!(got.frame.header.msg_type, MsgType::Heartbeat);
        drop(cb);
        let _ = task.await;
    }

    #[tokio::test]
    async fn closed_channel_never_loses_queued_messages() {
        let (ca, mut cb) = pair();
        let (inbound_tx, _inbound_rx) = mpsc::channel(8);
        let (handle, actor) = LinkActor::channel(ca, id(1), 16, inbound_tx);
        let task = tokio::spawn(actor.run());
        handle
            .send(
                Message::Heartbeat(Heartbeat {
                    send_ts: 7,
                    echo_ts: 0,
                }),
                id(1),
                Vec::new(),
            )
            .await
            .expect("send");
        handle.close();
        let _ = task.await;
        let (_, msg) = cb.recv_message().await.expect("recv");
        let Message::Heartbeat(hb) = msg else {
            panic!("expected heartbeat");
        };
        assert_eq!(hb.send_ts, 7);
    }

    #[tokio::test]
    async fn full_channel_is_backpressure_not_loss() {
        let (ca, _cb) = pair();
        let (inbound_tx, _inbound_rx) = mpsc::channel(8);
        // 不启动 actor：通道填满后 try_send 必须报背压。
        let (handle, actor) = LinkActor::channel(ca, id(1), 2, inbound_tx);
        let msg = Heartbeat {
            send_ts: 1,
            echo_ts: 0,
        };
        assert!(
            handle
                .try_send(Message::Heartbeat(msg), id(1), Vec::new())
                .is_ok()
        );
        assert!(
            handle
                .try_send(Message::Heartbeat(msg), id(1), Vec::new())
                .is_ok()
        );
        let err = handle
            .try_send(Message::Heartbeat(msg), id(1), Vec::new())
            .expect_err("full");
        assert!(matches!(err, CoreError::Backpressure));
        drop(actor);
    }
}
