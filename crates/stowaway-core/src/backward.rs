//! backward（反向映射）：由 agent 侧监听端口、admin 侧拨号。
//!
//! 权威：`docs/plan.md` §4.6/§4.8、附录 A（`BACKWARDTEST`/`BACKWARDSTART`）。
//!
//! # 与 forward 的三处不对称（都来自 v1 的真实语义）
//!
//! 1. **探测参数不同**：v1 的 `FORWARDTEST` 带的是「要拨的目标」，而
//!    `BACKWARDTEST` 带的是「要监听的端口」（`listen:<port>`）。这里照抄，
//!    因为接收方需要知道「你打算在哪个端口服务我」才能决定能否满足。
//! 2. **会话由被监听侧发起**：agent accept 到本地连接后才发 `OpenSession`
//!    （v1 `agent/handler/backward.go` 里 `Sender=自己`、`Accepter=ADMIN`、
//!    `Route=TEMP_ROUTE`）。所以 `direction` 是 `Inbound`（相对接收方
//!    admin 来说，这个会话要由它去拨号回来）。
//! 3. **一条本地连接一个会话键**：v1 用 `B_GETSEQCHAN` 逐条取新序号，
//!    共用一个键会让 admin 侧的会话表互相覆盖。

use std::net::SocketAddr;
use std::time::Duration;

use stowaway_protocol::{
    ConnectParam, Message, NodeId, OpenSession, ServiceParam, ServicePhase, ServiceRequest,
    SessionDirection, SessionKey, SessionKind,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::error::{CoreError, Result};
use crate::socks_server::{DIAL_TIMEOUT, relay};

/// 反向探测超时。
pub const BACKWARD_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// 一次反向映射的规格。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackwardSpec {
    /// 会话键（基础键；每条连接再派生子键）。
    pub key: SessionKey,
    /// 被监听侧要监听的端口。
    pub local_port: u16,
    /// admin 侧要拨的远端目标。
    pub remote_target: String,
}

impl BackwardSpec {
    /// 构造。
    #[must_use]
    pub fn new(key: SessionKey, local_port: u16, remote_target: impl Into<String>) -> Self {
        Self {
            key,
            local_port,
            remote_target: remote_target.into(),
        }
    }

    /// 探测消息：`ServiceRequest{kind: Connect, phase: Probe}`，参数是
    /// **监听端口**（`listen:<port>`），与 forward 的「目标地址」不同。
    #[must_use]
    pub fn probe(&self) -> Message {
        Message::ServiceRequest(ServiceRequest {
            key: self.key,
            kind: stowaway_protocol::ServiceKind::Connect,
            phase: ServicePhase::Probe,
            param: ServiceParam::Connect(ConnectParam {
                addr: format!("listen:{}", self.local_port),
            }),
        })
    }

    /// 执行消息。
    #[must_use]
    pub fn run(&self) -> Message {
        Message::ServiceRequest(ServiceRequest {
            key: self.key,
            kind: stowaway_protocol::ServiceKind::Connect,
            phase: ServicePhase::Run,
            param: ServiceParam::Connect(ConnectParam {
                addr: format!("listen:{}", self.local_port),
            }),
        })
    }
}

/// 被监听侧（agent）的监听器：每条本地连接产出一个上行会话。
#[derive(Debug)]
pub struct BackwardListener {
    addr: SocketAddr,
    key: SessionKey,
    listener: TcpListener,
    next_conn: u64,
}

impl BackwardListener {
    /// 绑定本地端口（`0` 表示由内核分配）。
    ///
    /// # Errors
    /// 端口被占用或权限不足。
    pub async fn bind(spec: &BackwardSpec) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", spec.local_port)).await?;
        let addr = listener.local_addr()?;
        Ok(Self {
            addr,
            key: spec.key,
            listener,
            next_conn: 0,
        })
    }

    /// 实际监听的地址。
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// 等一条本地连接，并为它分配独立会话键。
    ///
    /// 返回（连接、会话键、要发给 admin 的 `OpenSession`）。
    ///
    /// # Errors
    /// 监听器出错。
    pub async fn accept(&mut self) -> Result<(TcpStream, SessionKey, Message)> {
        let (stream, _) = self.listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let conn_key = SessionKey::new(self.key.origin, self.key.id.wrapping_add(self.next_conn));
        self.next_conn = self.next_conn.saturating_add(1);
        let msg = open_message(conn_key);
        Ok((stream, conn_key, msg))
    }
}

/// 上行会话开启消息（v1 的 `BACKWARDSTART`）。
///
/// `direction` 是 `Inbound`：相对接收方 admin 而言，「这个会话要由你拨号回来」。
#[must_use]
pub fn open_message(key: SessionKey) -> Message {
    Message::OpenSession(OpenSession {
        key,
        kind: SessionKind::Backward,
        direction: SessionDirection::Inbound,
        target: None,
        param: ServiceParam::None,
    })
}

/// admin 侧拨号到远端目标。
///
/// # Errors
/// 超时或连接失败。
pub async fn dial_remote(target: &str) -> Result<TcpStream> {
    match timeout(DIAL_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(CoreError::Io(e)),
        Err(_) => Err(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "反向映射拨号 {target} 超时（{} 秒）",
                DIAL_TIMEOUT.as_secs()
            ),
        ))),
    }
}

/// 反向中继：本地连接 ↔ 远端目标，返回（上行，下行）字节数。
///
/// # Errors
/// 任一侧 I/O 失败。
pub async fn relay_backward<A, B>(session: &mut A, remote: &mut B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    relay(remote, session).await.map_err(CoreError::Io)
}

/// 从消息流里等一个 `OpenSession`，返回（会话键，发起方）。
///
/// # Errors
/// 通道关闭（链路断开）。
pub async fn next_open(
    inbound: &mut mpsc::UnboundedReceiver<Message>,
) -> Result<(SessionKey, NodeId)> {
    while let Some(msg) = inbound.recv().await {
        if let Message::OpenSession(open) = msg {
            return Ok((open.key, open.key.origin));
        }
    }
    Err(CoreError::LinkClosed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn spec() -> BackwardSpec {
        BackwardSpec::new(SessionKey::new(NodeId::ADMIN, 5), 0, "127.0.0.1:9090")
    }

    #[test]
    fn probe_and_run_carry_listen_port_not_target() {
        let s = spec();
        let Message::ServiceRequest(probe) = s.probe() else {
            panic!("probe 必须是 ServiceRequest")
        };
        assert_eq!(probe.phase, ServicePhase::Probe);
        let ServiceParam::Connect(c) = probe.param else {
            panic!("必须是 Connect 参数")
        };
        // 与 forward 的关键差异：这里带的是监听端口。
        assert_eq!(c.addr, "listen:0");
        assert!(!c.addr.contains("9090"), "探测参数不应是远端目标");

        let Message::ServiceRequest(run) = s.run() else {
            panic!("run 必须是 ServiceRequest")
        };
        assert_eq!(run.phase, ServicePhase::Run);
    }

    #[test]
    fn open_message_is_inbound_and_backward_kind() {
        let key = SessionKey::new(NodeId::ADMIN, 6);
        let Message::OpenSession(open) = open_message(key) else {
            panic!("必须是 OpenSession")
        };
        assert_eq!(open.kind, SessionKind::Backward);
        assert_eq!(open.direction, SessionDirection::Inbound);
        assert_eq!(open.key, key);
        assert!(open.target.is_none());
    }

    #[tokio::test]
    async fn listener_binds_and_assigns_distinct_keys_per_connection() {
        let s = spec();
        let mut listener = BackwardListener::bind(&s).await.expect("bind");
        let addr = listener.local_addr();
        assert_ne!(addr.port(), 0);

        let client = tokio::spawn(async move {
            let mut a = TcpStream::connect(addr).await.expect("connect 1");
            let mut b = TcpStream::connect(addr).await.expect("connect 2");
            a.write_all(b"x").await.expect("w1");
            b.write_all(b"y").await.expect("w2");
            (a, b)
        });

        let (_conn1, key1, msg1) = listener.accept().await.expect("accept 1");
        let (_conn2, key2, msg2) = listener.accept().await.expect("accept 2");
        client.await.expect("join");

        assert_ne!(key1, key2, "每条连接必须有独立会话键");
        assert_eq!(key1.origin, s.key.origin);
        assert_eq!(key2.origin, s.key.origin);
        assert_eq!(key1.id, s.key.id);
        assert_eq!(key2.id, s.key.id + 1);
        assert!(matches!(msg1, Message::OpenSession(_)));
        assert!(matches!(msg2, Message::OpenSession(_)));
    }

    #[tokio::test]
    async fn relay_moves_bytes_both_ways_through_a_backward_session() {
        // 模拟「本地连接 ↔ 远端目标」，两侧都用真实 TCP。
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo");
        let echo_addr = echo.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.expect("accept");
            let mut buf = [0u8; 32];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let (mut local, mut remote) = tokio::io::duplex(4096);
        let mut target = TcpStream::connect(echo_addr).await.expect("dial");
        let task = tokio::spawn(async move { relay_backward(&mut local, &mut target).await });

        remote.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        remote.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
        task.abort();
    }

    #[tokio::test]
    async fn dial_to_closed_port_reports_error_not_hang() {
        // 127.0.0.1:1 在本机必然拒绝（特权端口 + 无监听）。
        let err = dial_remote("127.0.0.1:1").await.expect_err("必须失败");
        let text = err.to_string();
        assert!(
            text.contains("I/O") || text.contains("refused") || text.contains("超时"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn next_open_returns_key_and_origin() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let key = SessionKey::new(NodeId::ADMIN, 8);
        tx.send(Message::Heartbeat(stowaway_protocol::Heartbeat {
            send_ts: 1,
            echo_ts: 0,
        }))
        .expect("send hb");
        tx.send(open_message(key)).expect("send open");
        let (got_key, origin) = next_open(&mut rx).await.expect("next_open");
        assert_eq!(got_key, key);
        assert_eq!(origin, NodeId::ADMIN);
    }

    #[tokio::test]
    async fn next_open_reports_link_closed() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        drop(tx);
        let err = next_open(&mut rx).await.expect_err("必须报错");
        assert!(matches!(err, CoreError::LinkClosed));
    }
}
