//! UDP ASSOCIATE 中继。
//!
//! 权威：`docs/plan.md` §4.8（`Socks5Udp` 是独立会话种类）、附录 A
//! （`UDPASSSTART` → `OpenSession{kind: Socks5Udp, direction: Inbound}`）。
//!
//! # 方向（修 F2）
//!
//! v1 里 **agent 发起** UDP 关联（`agent/handler/socks.go:540` 构造
//! `UDPAssStart`），由 admin 侧绑定 UDP 套接字并回 `UDPAssRes`
//! （`admin/handler/socks.go:259-330`）。旧方案把方向写反了；这里以源码
//! 为准。
//!
//! # 回程路由（为什么不需要地址表）
//!
//! 出口套接字收到的每一个数据报，其**来源地址就是回程目标**（RFC 1928
//! §7）。v1 把出口套接字 `connect` 到单一客户端地址
//! （`admin/handler/socks.go:330`）来回避「回包给谁」的问题，代价是同一
//! 时刻只能服务一个客户端，第二个客户端的数据报会串到第一个。
//!
//! v2 不做 `connect`：读到谁的来源地址，就在回包里写谁。

use std::io;
use std::net::SocketAddr;

use stowaway_protocol::{ByteBuf, Message, ServiceData, SessionKey, SessionReady};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::error::{CoreError, Result};
use crate::socks::{Parsed, Target, TargetAddr, UdpHeader};

/// 空闲多久后关闭出口套接字（v1 没有超时，端口泄漏）。
pub const UDP_IDLE_TIMEOUT_SECS: u64 = 120;

/// 单个 UDP 数据报上限（v1 用 1024，见 `agent/handler/socks.go:619`）。
pub const MAX_UDP_DATAGRAM: usize = 64 * 1024;

/// 一条 SOCKS5 UDP 数据报（目标 + 载荷）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// 目标地址。
    pub target: Target,
    /// 载荷。
    pub payload: Vec<u8>,
}

impl Datagram {
    /// 解析（含头部，拒绝分片）。
    ///
    /// # Errors
    /// 头部非法或分片标志非 0。
    pub fn parse(buf: &[u8]) -> std::result::Result<Self, crate::socks::SocksError> {
        match UdpHeader::parse(buf)? {
            Parsed::NeedMore => Err(crate::socks::SocksError::Truncated {
                need: 4,
                have: buf.len(),
            }),
            Parsed::Ready((header, offset), _) => Ok(Self {
                target: header.target,
                payload: buf[offset..].to_vec(),
            }),
        }
    }

    /// 编码成线格式。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = UdpHeader {
            target: self.target.clone(),
            frag: 0,
        }
        .encode();
        out.extend_from_slice(&self.payload);
        out
    }

    /// 若是 IP 字面量目标，返回 `SocketAddr`（域名需要 DNS，出口侧不做）。
    #[must_use]
    pub fn resolved(&self) -> Option<SocketAddr> {
        self.target.addr.socket_addr(self.target.port)
    }
}

/// 绑定出口 UDP 套接字。
///
/// # Errors
/// 绑定失败。
pub async fn bind_outlet(bind: SocketAddr) -> Result<UdpSocket> {
    Ok(UdpSocket::bind(bind).await?)
}

/// 会话就绪消息，`detail` 里带上实际的出口地址，客户端据此发数据报。
#[must_use]
pub fn ready_message(key: SessionKey, bind: SocketAddr) -> Message {
    Message::SessionReady(SessionReady {
        key,
        code: stowaway_protocol::SessionCode::Ok,
        detail: bind.to_string(),
    })
}

/// 目标是否需要域名解析。
#[must_use]
pub fn needs_resolution(target: &Target) -> bool {
    matches!(target.addr, TargetAddr::Domain(_))
}

/// 双向中继：会话通道 ↔ 出口套接字。
///
/// - 上行：`recv` 收到的 [`ServiceData`] 解出数据报，发给目标；
/// - 下行：出口套接字收到的数据报封成 [`ServiceData`] 回送，
///   回包头部里的目标就是来源地址。
///
/// 域名目标在当前实现里被跳过（出口侧不做 DNS：解析属于发起侧职责，
/// 而且不同节点看到的 DNS 结果可能不同）。
///
/// # Errors
/// I/O 失败、通道关闭。
pub async fn relay_datagrams<F>(
    socket: &UdpSocket,
    key: SessionKey,
    send: F,
    mut recv: mpsc::Receiver<ServiceData>,
    limit: usize,
) -> Result<()>
where
    F: Fn(ServiceData) -> Result<()>,
{
    let mut seq = 0u64;
    let mut buf = vec![0u8; limit.min(MAX_UDP_DATAGRAM)];
    loop {
        tokio::select! {
            biased;
            // 上行：会话 → 目标
            incoming = recv.recv() => {
                let Some(data) = incoming else {
                    return Ok(());
                };
                let Ok(dg) = Datagram::parse(&data.data) else {
                    continue;
                };
                let Some(target) = dg.resolved() else {
                    // 域名目标：出口侧不做 DNS。
                    continue;
                };
                socket.send_to(&dg.payload, target).await?;
            }
            // 下行：目标 → 会话
            got = socket.recv_from(&mut buf) => {
                let (n, from) = got?;
                let reply = Datagram {
                    target: Target {
                        addr: TargetAddr::Ip(from.ip()),
                        port: from.port(),
                    },
                    payload: buf[..n].to_vec(),
                };
                let payload = reply.encode();
                send(ServiceData {
                    key,
                    seq,
                    data: ByteBuf::from(payload),
                })?;
                seq = seq.wrapping_add(1);
            }
        }
    }
}

/// 把 I/O 错误包一层（便于调用方统一处理）。
#[must_use]
pub fn as_core(err: io::Error) -> CoreError {
    CoreError::Io(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_protocol::NodeId;

    fn key() -> SessionKey {
        SessionKey::new(NodeId::ADMIN, 11)
    }

    #[test]
    fn datagram_roundtrip_preserves_target_and_payload() {
        let dg = Datagram {
            target: Target {
                addr: TargetAddr::Ip("127.0.0.1".parse().expect("ip")),
                port: 53,
            },
            payload: b"hello".to_vec(),
        };
        let encoded = dg.encode();
        let parsed = Datagram::parse(&encoded).expect("parse");
        assert_eq!(parsed.target.port, 53);
        assert_eq!(parsed.payload, b"hello");
        assert_eq!(
            parsed.resolved(),
            Some("127.0.0.1:53".parse().expect("addr"))
        );
    }

    #[test]
    fn datagram_rejects_fragmented_input() {
        // 手工拼一个 FRAG != 0 的头部。
        let mut buf = vec![0x00u8, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 53];
        buf.extend_from_slice(b"x");
        assert!(
            Datagram::parse(&buf).is_err(),
            "分片数据报必须拒绝（RFC 1928：FRAG 非 0 表示分片）"
        );
    }

    #[test]
    fn domain_targets_need_resolution_and_have_no_socket_addr() {
        let target = Target {
            addr: TargetAddr::Domain("example.com".to_owned()),
            port: 80,
        };
        assert!(needs_resolution(&target));
        assert!(target.addr.socket_addr(80).is_none());
    }

    #[test]
    fn ready_message_carries_the_outlet_address() {
        let addr: SocketAddr = "127.0.0.1:5353".parse().expect("addr");
        let Message::SessionReady(ready) = ready_message(key(), addr) else {
            panic!("ready")
        };
        assert_eq!(ready.code, stowaway_protocol::SessionCode::Ok);
        assert_eq!(ready.detail, "127.0.0.1:5353");
    }

    #[tokio::test]
    async fn relay_moves_a_datagram_both_ways() {
        let outlet = bind_outlet("127.0.0.1:0".parse().expect("addr"))
            .await
            .expect("bind outlet");
        let outlet_addr = outlet.local_addr().expect("addr");
        // 出口地址会由 `ready_message` 通告给客户端；这里只确认绑定成功。
        assert_ne!(outlet_addr.port(), 0);

        // 外部对端：收到 ping 后回 pong。
        let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
        let peer_addr = peer.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((n, from)) = peer.recv_from(&mut buf).await {
                let _ = peer.send_to(&buf[..n], from).await;
            }
        });

        let (up_tx, up_rx) = mpsc::channel(8);
        let (down_tx, mut down_rx) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            let send = move |d: ServiceData| -> Result<()> {
                down_tx.try_send(d).map_err(|_| CoreError::Backpressure)
            };
            relay_datagrams(&outlet, key(), send, up_rx, MAX_UDP_DATAGRAM).await
        });

        let out = Datagram {
            target: Target {
                addr: TargetAddr::Ip(peer_addr.ip()),
                port: peer_addr.port(),
            },
            payload: b"ping-pong".to_vec(),
        };
        up_tx
            .send(ServiceData {
                key: key(),
                seq: 0,
                data: ByteBuf::from(out.encode()),
            })
            .await
            .expect("up");

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), down_rx.recv())
            .await
            .expect("timeout")
            .expect("data");
        let parsed = Datagram::parse(&got.data).expect("parse");
        assert_eq!(parsed.payload, b"ping-pong", "回包内容必须原样");
        assert_eq!(
            parsed.resolved(),
            Some(peer_addr),
            "回包头里的目标必须是数据报的来源地址（RFC 1928）"
        );
        task.abort();
    }
}
