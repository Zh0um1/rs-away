//! 桥接：`connect`（跨 admin）与 `sshtunnel`（经 SSH 端口转发）共用的
//! 「**扮演 admin 主动外连 + 把对端当子节点接入**」通路。
//!
//! 权威：`docs/plan.md` §2.6（v1 的 `connect`/`sshtunnel` 行为）、§5.1 第 2/11
//! 项、附录 A（`CONNECTSTART`/`CONNECTDONE`/`SSHTUNNELREQ`）、§8.5 场景 9、
//! §9 风险表（`docs/plan.md:731`）。
//!
//! # v1 的两个 handler 其实是一件事
//!
//! `agent/handler/sshtunnel.go` 与 `agent/handler/connect.go` 的骨架**逐句同构**：
//! 拿到一条字节流通路 → `ActivePreAuth` → 发一条**伪 HI**（`IsAdmin:1`，
//! 注释就写着 `// fake admin`）→ 等对端回 `IsAdmin:0` → 走 `CHILDUUIDREQ`
//! 要编号 → `C_NEWCHILD` 登记 → 回 `OK:1`。两者唯一的差别是通路怎么来：
//!
//! | | 通路 | 对端是谁 |
//! |---|---|---|
//! | `sshtunnel` | SSH `direct-tcpip` 到 `127.0.0.1:<port>` | SSH 服务器所在网络里的监听者 |
//! | `connect` | 裸 TCP（可叠 TLS）直连 `connect.Addr` | 另一台 admin 的监听端口 |
//!
//! 所以 v2 把它们合成一个模块：**通路是参数，握手与登记是同一段代码**。
//! 这正是「传输可插拔」在服务层的对应物。
//!
//! # 角色与编号（v2 用既有消息表达，不新增消息类型）
//!
//! v1 用 `HI.UUID` 传身份、用 `CHILDUUIDREQ` 要编号。v2 的 `Hello` **没有**
//! 节点编号字段（握手只绑 `eph_pub`/`nonce`/`transport`/`tls_fp`），所以编号
//! 交换放在握手之后的第一条业务消息里：
//!
//! 1. 桥接方 `client_handshake(NodeKind::Admin, ..)`——本端扮 **admin**（父），
//!    对端必须报 [`NodeKind::Agent`]（`crates/stowaway-crypto/src/handshake.rs:173`
//!    的 `opposite()` 会拒绝同角色，所以「两个 admin 直接互连」在密码学层
//!    就已经不成立了，不需要额外判断）；
//! 2. 桥接方紧接着发 `Join{node: <本端 NodeId>, kind: Admin}`——这条消息既
//!    「自我介绍」也「宣告我是你的父节点」；
//! 3. 对端回 `JoinAck{node, parent, root, depth}` 或先发自己的 `Join`。
//!
//! 因为 `Join` 的父节点恒为「链路对端」（`crates/stowaway-core/src/node.rs:439`
//! 的安全属性），对端无法通过伪造编号把别人的子树劫持到自己名下。
//!
//! # 已知限制
//!
//! `docs/plan.md:731` 已登记：跨 admin 桥接时**端到端密封退化到链路级**——
//! 桥的两侧各自密封，中间那台 admin 能看到明文。`flags.E2E` 在桥接段不成立，
//! 控制台必须提示。

use stowaway_protocol::{
    Join, JoinAck, Message, NodeId, NodeKind, ServiceKind, ServicePhase, ServiceRequest,
    SessionKey, SshParam, SshTunnelParam, TransportKind,
};
use stowaway_transport::{Link, LinkCodec, LinkMeta, TransportError, TransportSpec, dialer_for};

use crate::error::CoreError;
use crate::ssh::{self, SshConnection, SshError, SshSpec};

/// 桥接的两条通路。
#[derive(Clone, Debug)]
pub enum BridgeKind {
    /// SSH 端口转发：拨 SSH 服务器，再 `direct-tcpip` 到目标地址。
    SshTunnel {
        /// SSH 连接参数（含服务器地址）。
        ssh: SshSpec,
        /// 隧道参数。
        tunnel: SshTunnelParam,
    },
    /// 裸传输直连（`connect`，可叠 TLS）。
    Connect {
        /// 目标 `host:port`。
        addr: String,
        /// 显式指定传输；`None` 表示 `raw://<addr>`。
        transport: Option<TransportSpec>,
        /// TLS 配置；`None` 表示明文。
        tls: Option<stowaway_transport::TlsConfig>,
    },
}

impl BridgeKind {
    /// 该通路对应的服务种类（决定 `ServiceRequest.kind`）。
    #[must_use]
    pub const fn service_kind(&self) -> ServiceKind {
        match self {
            Self::SshTunnel { .. } => ServiceKind::SshTunnel,
            Self::Connect { .. } => ServiceKind::Connect,
        }
    }

    /// 该通路在链路层的传输种类（参与 transcript，防降级）。
    #[must_use]
    pub fn transport_kind(&self) -> TransportKind {
        match self {
            // SSH 通道是可靠有序字节流，语义上等价于 raw。
            Self::SshTunnel { .. } => TransportKind::Raw,
            Self::Connect { transport, .. } => {
                transport.as_ref().map_or(TransportKind::Raw, |s| s.kind)
            }
        }
    }

    /// 给控制台看的一行描述。
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::SshTunnel { ssh, tunnel } => format!(
                "ssh 隧道 {} → {}@{} → {}",
                tunnel.remote_target, ssh.user, ssh.addr, tunnel.remote_target
            ),
            Self::Connect { addr, .. } => format!("connect 到 {addr}"),
        }
    }
}

/// 一次桥接的规格。
#[derive(Clone, Debug)]
pub struct BridgeSpec {
    /// 会话键（用于把结果投给发起方）。
    pub key: SessionKey,
    /// 通路。
    pub kind: BridgeKind,
}

impl BridgeSpec {
    /// `connect`：直连 `addr`。
    #[must_use]
    pub fn connect(key: SessionKey, addr: impl Into<String>) -> Self {
        Self {
            key,
            kind: BridgeKind::Connect {
                addr: addr.into(),
                transport: None,
                tls: None,
            },
        }
    }

    /// `sshtunnel`：拨 `ssh_addr` 上的 SSH，再转发到 `tunnel.remote_target`。
    #[must_use]
    pub fn ssh_tunnel(
        key: SessionKey,
        ssh_addr: impl Into<String>,
        tunnel: &SshTunnelParam,
    ) -> Self {
        Self {
            key,
            kind: BridgeKind::SshTunnel {
                ssh: SshSpec::new(key, ssh_addr, &tunnel.ssh),
                tunnel: tunnel.clone(),
            },
        }
    }

    /// 换 TLS 配置（仅 `connect` 有意义）。
    #[must_use]
    pub fn with_tls(mut self, tls: stowaway_transport::TlsConfig) -> Self {
        if let BridgeKind::Connect { tls: slot, .. } = &mut self.kind {
            *slot = Some(tls);
        }
        self
    }

    /// 换传输（仅 `connect` 有意义）。
    #[must_use]
    pub fn with_transport(mut self, spec: TransportSpec) -> Self {
        if let BridgeKind::Connect { transport, .. } = &mut self.kind {
            *transport = Some(spec);
        }
        self
    }
}

/// 桥接错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// 传输层错误。
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// SSH 错误。
    #[error(transparent)]
    Ssh(#[from] SshError),

    /// 协议编解码错误。
    #[error(transparent)]
    Protocol(#[from] stowaway_protocol::ProtocolError),

    /// IO 错误。
    #[error("IO 错误：{0}")]
    Io(#[from] std::io::Error),

    /// 对端在登记阶段发了别的消息。
    #[error("桥接登记阶段收到了意外的 {actual}（期待 Join/JoinAck）")]
    Unexpected {
        /// 实际收到什么（消息名）。
        actual: &'static str,
    },

    /// 对端在登记阶段就断开。
    #[error("桥接登记阶段对端断开（还差 {expected}）")]
    Closed {
        /// 期待什么。
        expected: &'static str,
    },

    /// 地址非法。
    #[error("桥接地址非法：{0}")]
    BadAddr(String),

    /// 编号不一致（我们宣告的父编号与对端 ack 的不符）。
    #[error("桥接编号不一致：本端宣告 {expected}，对端 ack 为 {actual}")]
    IdMismatch {
        /// 本端宣告的。
        expected: NodeId,
        /// 对端 ack 的。
        actual: NodeId,
    },
}

impl BridgeError {
    /// 提升为 [`CoreError`]。
    #[must_use]
    pub fn as_core(&self) -> CoreError {
        match self {
            Self::Transport(e) => {
                CoreError::Protocol(stowaway_protocol::ProtocolError::Payload(e.to_string()))
            }
            other => {
                CoreError::Protocol(stowaway_protocol::ProtocolError::Payload(other.to_string()))
            }
        }
    }
}

/// 一条经 SSH 通道的 [`Link`]。
///
/// `russh` 的 `ChannelStream` 已经同时实现了 `AsyncRead`/`AsyncWrite`，这里
/// 只是补上 [`Link::meta`]——链路协议种类按 `raw` 上报，因为「SSH 通道」
/// 对上层就是一条可靠有序字节流，没有额外的分帧语义。
pub struct SshLink {
    inner: russh::ChannelStream<russh::client::Msg>,
}

impl std::fmt::Debug for SshLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshLink").finish_non_exhaustive()
    }
}

impl SshLink {
    /// 包装一个 SSH 通道。
    #[must_use]
    pub fn new(inner: russh::ChannelStream<russh::client::Msg>) -> Self {
        Self { inner }
    }
}

impl tokio::io::AsyncRead for SshLink {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for SshLink {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
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

impl Link for SshLink {
    fn meta(&self) -> LinkMeta {
        LinkMeta::new(TransportKind::Raw, None)
    }
}

/// 桥接建立后的产物。
pub struct BridgeOutcome {
    /// 已完成握手与编号交换的编解码器，可直接交给 `Node::attach_link`。
    pub codec: LinkCodec,
    /// 对端节点编号。
    pub peer: NodeId,
    /// 对端角色（按 [`opposite`] 恒为 `Agent`）。
    pub peer_kind: NodeKind,
    /// 握手结果（含派生密钥与 TH，用于审计）。
    pub handshake: stowaway_transport::HandshakeResult,
    /// 保持 SSH 连接存活；`None` 表示走裸传输。
    keepalive: Option<Box<SshConnection>>,
}

impl std::fmt::Debug for BridgeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeOutcome")
            .field("peer", &self.peer)
            .field("peer_kind", &self.peer_kind)
            .field("keepalive", &self.keepalive.is_some())
            .finish_non_exhaustive()
    }
}

impl BridgeOutcome {
    /// 通路是否是 SSH（控制台提示用）。
    #[must_use]
    pub const fn is_ssh(&self) -> bool {
        self.keepalive.is_some()
    }

    /// 对端声明的传输种类。
    #[must_use]
    pub const fn peer_transport(&self) -> TransportKind {
        self.handshake.peer_transport
    }
}

/// 拿一条通路（SSH 通道或裸传输链路）。
///
/// # Errors
/// 地址非法、SSH 连接/认证/通道失败、传输不支持。
async fn open_path(
    kind: &BridgeKind,
    secret: &stowaway_crypto::Secret,
) -> std::result::Result<(Box<dyn Link>, Option<Box<SshConnection>>, Option<[u8; 32]>), BridgeError>
{
    match kind {
        BridgeKind::SshTunnel { ssh, tunnel } => {
            let (host, port) = ssh
                .split_addr()
                .map_err(|e| BridgeError::BadAddr(e.to_string()))?;
            let _ = (host, port);
            // `remote_target` 形如 `host:port`；v1 里固定是 `127.0.0.1:<agent 监听端口>`。
            let (target_host, target_port) = split_target(&tunnel.remote_target)?;
            let conn = ssh::connect(ssh).await?;
            let channel = conn
                .open_direct_tcpip(&target_host, u32::from(target_port))
                .await?;
            let link: Box<dyn Link> = Box::new(SshLink::new(channel.into_stream()));
            Ok((link, Some(Box::new(conn)), None))
        }
        BridgeKind::Connect {
            addr,
            transport,
            tls,
        } => {
            let spec = match transport {
                Some(spec) => spec.clone(),
                None => TransportSpec::parse(&format!("raw://{addr}"))
                    .map_err(|e| BridgeError::Transport(TransportError::Spec(e)))?,
            };
            let spec = spec.resolve(&secret.digest()[..]);
            let dialer = dialer_for(&spec, tls.clone())?;
            let target = stowaway_transport::DialTarget {
                addr: spec
                    .resolve_addr()
                    .map_err(|e| BridgeError::Transport(TransportError::Spec(e)))?,
                domain: spec.effective_domain(),
                path: Some(spec.effective_path().to_owned()),
                tls: tls.clone(),
            };
            let link = stowaway_transport::Dialer::connect(&dialer, &target)
                .await
                .map_err(BridgeError::Io)?;
            let fp = tls.as_ref().and_then(|t| t.advertised_fingerprint());
            Ok((link, None, fp))
        }
    }
}

fn split_target(target: &str) -> std::result::Result<(String, u16), BridgeError> {
    let text = target.trim();
    let (host, port_text) = if let Some(rest) = text.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| BridgeError::BadAddr(text.to_owned()))?;
        (
            &rest[..end],
            rest[end + 1..].strip_prefix(':').unwrap_or(""),
        )
    } else {
        match text.rsplit_once(':') {
            Some((host, port)) => (host, port),
            None => return Err(BridgeError::BadAddr(text.to_owned())),
        }
    };
    if host.is_empty() || port_text.is_empty() {
        return Err(BridgeError::BadAddr(text.to_owned()));
    }
    let port: u16 = port_text
        .parse()
        .map_err(|_| BridgeError::BadAddr(text.to_owned()))?;
    Ok((host.to_owned(), port))
}

/// 扮演 admin 连上去，完成握手与编号交换。
///
/// `self_id` 是本端（扮 administrator 的那一侧）的节点编号；对端会在 `JoinAck`
/// 里确认它作为父节点。
///
/// # Errors
/// 通路建立失败、握手失败、对端在登记阶段断开或发了别的消息。
pub async fn bridge_connect(
    spec: &BridgeSpec,
    secret: &stowaway_crypto::Secret,
    self_id: NodeId,
) -> std::result::Result<BridgeOutcome, BridgeError> {
    let (link, keepalive, tls_fp) = open_path(&spec.kind, secret).await?;
    let mut codec = LinkCodec::new(link);

    // 本端扮 admin（父），对端必须报 agent（子）——同角色会在密码学层被拒。
    let handshake = codec
        .client_handshake(NodeKind::Admin, spec.kind.transport_kind(), tls_fp, secret)
        .await?;

    // 自我介绍：告知对端「我是谁」（子节点要拿这个编号当父节点的路由目标）。
    let join = Message::Join(Join {
        kind: NodeKind::Admin,
        listen: None,
        capabilities: 0,
        node: self_id,
    });
    codec.send(&join, NodeId::UNASSIGNED, &[]).await?;

    let peer = read_peers_registration(&mut codec, self_id).await?;

    Ok(BridgeOutcome {
        codec,
        peer,
        peer_kind: handshake.peer_kind,
        handshake,
        keepalive,
    })
}

/// 读对端在登记阶段发来的消息，返回对端编号。
///
/// 允许两种顺序（都是合法的）：对端先发 `Join`（自报编号），或先回 `JoinAck`
/// （确认我们的父身份）。
async fn read_peers_registration(
    codec: &mut LinkCodec,
    self_id: NodeId,
) -> std::result::Result<NodeId, BridgeError> {
    loop {
        let (frame, msg) = codec.recv_message().await?;
        let _ = frame;
        match msg {
            Message::Join(join) => {
                // 对端自报：`node` 是自己的编号（不是 UNASSIGNED）。
                if join.node.is_assigned() {
                    return Ok(join.node);
                }
            }
            Message::JoinAck(ack) => {
                // 对端确认我们宣告的父编号。
                if ack.node != self_id {
                    return Err(BridgeError::IdMismatch {
                        expected: self_id,
                        actual: ack.node,
                    });
                }
            }
            other => {
                return Err(BridgeError::Unexpected {
                    actual: message_name(&other),
                });
            }
        }
    }
}

/// 对端（被桥接的一侧）在收到 `Join` 后应做的登记。
///
/// 这条路走的是「自己是被连的一方」：把对端登记为**上游**、把它的编号当父节点。
///
/// 返回对端（父）编号，调用方应把它交给 `Node::attach_upstream`。
///
/// # Errors
/// 对端在登记阶段断开或发了别的消息。
pub async fn bridge_accept(
    codec: &mut LinkCodec,
) -> std::result::Result<(NodeId, Join), BridgeError> {
    let (_frame, msg) = codec
        .recv_message()
        .await
        .map_err(|_| BridgeError::Closed { expected: "Join" })?;
    match msg {
        Message::Join(join) => {
            if !join.node.is_assigned() {
                return Err(BridgeError::BadAddr(
                    "桥接 Join 必须携带具体父编号（不能是 UNASSIGNED）".to_owned(),
                ));
            }
            Ok((join.node, join))
        }
        other => Err(BridgeError::Unexpected {
            actual: message_name(&other),
        }),
    }
}

/// 回一条 `JoinAck`，把父编号与树的根/深度告诉对端。
///
/// # Errors
/// 发送失败。
pub async fn reply_join_ack(
    codec: &mut LinkCodec,
    ack: JoinAck,
) -> std::result::Result<(), BridgeError> {
    codec
        .send(&Message::JoinAck(ack), NodeId::UNASSIGNED, &[])
        .await?;
    Ok(())
}

/// 一条 `Join` 的通告消息（供桥接方在把自己的对端登记后向上游代子公告）。
#[must_use]
pub fn announce_message(child: NodeId, kind: NodeKind) -> Message {
    Message::Join(Join {
        kind,
        listen: None,
        capabilities: 0,
        node: child,
    })
}

/// `CONNECTSTART` / `SSHTUNNELREQ` 的上线形式。
///
/// v1 用两条独立消息（`CONNECTSTART{Addr}`、`SSHTUNNELREQ{...}`），v2 统一成
/// `ServiceRequest{kind: Connect|SshTunnel, phase: Run}`（`docs/plan.md` 附录 A）。
#[must_use]
pub fn open_message(spec: &BridgeSpec) -> Message {
    let param = match &spec.kind {
        BridgeKind::SshTunnel { tunnel, .. } => {
            stowaway_protocol::ServiceParam::SshTunnel(tunnel.clone())
        }
        BridgeKind::Connect { addr, .. } => {
            stowaway_protocol::ServiceParam::Connect(stowaway_protocol::ConnectParam {
                addr: addr.clone(),
            })
        }
    };
    Message::ServiceRequest(ServiceRequest {
        key: spec.key,
        kind: spec.kind.service_kind(),
        phase: ServicePhase::Run,
        param,
    })
}

/// `CONNECTDONE` / `SSHTUNNELRES` 的上线形式。
#[must_use]
pub fn done_message(
    key: SessionKey,
    code: stowaway_protocol::SessionCode,
    detail: impl Into<String>,
) -> Message {
    Message::ServiceReply(stowaway_protocol::ServiceReply {
        key,
        code,
        detail: detail.into(),
    })
}

/// 消息名（错误信息用；避免把整个 payload 打进日志）。
fn message_name(msg: &Message) -> &'static str {
    match msg {
        Message::Hello(_) => "Hello",
        Message::HelloAck(_) => "HelloAck",
        Message::AuthConfirm(_) => "AuthConfirm",
        Message::Heartbeat(_) => "Heartbeat",
        Message::Shutdown(_) => "Shutdown",
        Message::Join(_) => "Join",
        Message::JoinAck(_) => "JoinAck",
        Message::Rejoin(_) => "Rejoin",
        Message::NodeStatus(_) => "NodeStatus",
        Message::Memo(_) => "Memo",
        Message::OpenSession(_) => "OpenSession",
        Message::SessionReady(_) => "SessionReady",
        Message::SessionData(_) => "SessionData",
        Message::SessionClose(_) => "SessionClose",
        Message::ServiceRequest(_) => "ServiceRequest",
        Message::ServiceReply(_) => "ServiceReply",
        Message::ServiceData(_) => "ServiceData",
        Message::ServiceExit(_) => "ServiceExit",
    }
}

/// 桥接规格里的 SSH 参数（供控制台回显）。
#[must_use]
pub fn ssh_param_of(tunnel: &SshTunnelParam) -> SshParam {
    tunnel.ssh.clone()
}

/// 把 [`BridgeError`] 提升为 [`CoreError`]。
#[must_use]
pub fn as_core(err: &BridgeError) -> CoreError {
    err.as_core()
}

/// 结果别名。
pub type BridgeResult<T> = std::result::Result<T, BridgeError>;

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_crypto::Secret;
    use stowaway_protocol::{ConnectParam, NodeId, SshAuth};
    use stowaway_transport::{Link, LinkMeta, boxed};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

    fn id(n: u8) -> NodeId {
        let mut b = [0u8; 16];
        b[0] = n;
        NodeId(b)
    }

    fn key() -> SessionKey {
        SessionKey::new(NodeId::ADMIN, 3)
    }

    fn secret() -> Secret {
        Secret::load("bridge-shared-secret", 8).expect("secret")
    }

    #[derive(Debug)]
    struct TestLink {
        inner: DuplexStream,
    }

    impl AsyncRead for TestLink {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestLink {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
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

    impl Link for TestLink {
        fn meta(&self) -> LinkMeta {
            LinkMeta::new(TransportKind::Raw, None)
        }
    }

    // ---- 纯逻辑 ----

    #[test]
    fn connect_spec_parses_addr_and_kind() {
        let spec = BridgeSpec::connect(key(), "10.0.0.9:1080");
        assert_eq!(spec.kind.service_kind(), ServiceKind::Connect);
        assert_eq!(spec.kind.transport_kind(), TransportKind::Raw);
        assert!(spec.kind.describe().contains("10.0.0.9:1080"));
    }

    #[test]
    fn ssh_tunnel_spec_maps_param_to_ssh_spec() {
        let tunnel = SshTunnelParam {
            ssh: SshParam {
                user: "root".to_owned(),
                auth: SshAuth::Password("pw".to_owned()),
                command: String::new(),
            },
            local_port: 0,
            remote_target: "127.0.0.1:1080".to_owned(),
        };
        let spec = BridgeSpec::ssh_tunnel(key(), "10.0.0.5:22", &tunnel);
        match &spec.kind {
            BridgeKind::SshTunnel { ssh, .. } => {
                assert_eq!(ssh.addr, "10.0.0.5:22");
                assert_eq!(ssh.user, "root");
            }
            other => panic!("通路种类不对：{other:?}"),
        }
        assert_eq!(spec.kind.service_kind(), ServiceKind::SshTunnel);
        // SSH 通道在链路层等价于 raw（参与 transcript）。
        assert_eq!(spec.kind.transport_kind(), TransportKind::Raw);
    }

    #[test]
    fn open_message_uses_connect_param_for_connect() {
        let spec = BridgeSpec::connect(key(), "127.0.0.1:9");
        match open_message(&spec) {
            Message::ServiceRequest(req) => {
                assert_eq!(req.kind, ServiceKind::Connect);
                assert_eq!(req.phase, ServicePhase::Run);
                match req.param {
                    stowaway_protocol::ServiceParam::Connect(ConnectParam { addr }) => {
                        assert_eq!(addr, "127.0.0.1:9");
                    }
                    other => panic!("参数种类不对：{other:?}"),
                }
            }
            other => panic!("消息种类不对：{other:?}"),
        }
    }

    #[test]
    fn target_split_handles_ipv6_and_rejects_garbage() {
        assert_eq!(
            split_target("127.0.0.1:1080").expect("拆"),
            ("127.0.0.1".to_owned(), 1080)
        );
        assert_eq!(
            split_target("[::1]:2222").expect("拆"),
            ("::1".to_owned(), 2222)
        );
        for bad in ["127.0.0.1", "", ":80", "h:"] {
            assert!(split_target(bad).is_err(), "{bad:?} 不该被接受");
        }
    }

    #[test]
    fn announce_message_carries_the_child_id() {
        match announce_message(id(7), NodeKind::Agent) {
            Message::Join(join) => {
                assert_eq!(join.node, id(7));
                assert_eq!(join.kind, NodeKind::Agent);
            }
            other => panic!("消息种类不对：{other:?}"),
        }
    }

    // ---- 桥接全流程（duplex 上跑真握手 + 真登记）----

    #[tokio::test]
    async fn bridge_registers_the_peer_and_exchanges_ids() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = LinkCodec::new(boxed(TestLink { inner: a }));
        let mut server = LinkCodec::new(boxed(TestLink { inner: b }));
        let s = secret();
        let s2 = secret();
        let self_id = NodeId::ADMIN;

        let client_task = tokio::spawn(async move {
            client
                .client_handshake(NodeKind::Admin, TransportKind::Raw, None, &s2)
                .await
                .map(|_| client)
        });
        let server_task = tokio::spawn(async move {
            server
                .server_handshake(NodeKind::Agent, TransportKind::Raw, None, &s)
                .await
                .map(|_| server)
        });
        let mut client = client_task.await.expect("join").expect("client 握手");
        let mut server = server_task.await.expect("join").expect("server 握手");

        // 桥接方先发自我介绍，再读登记。
        client
            .send(
                &Message::Join(Join {
                    kind: NodeKind::Admin,
                    listen: None,
                    capabilities: 0,
                    node: self_id,
                }),
                NodeId::UNASSIGNED,
                &[],
            )
            .await
            .expect("发 Join");

        // 被桥接方：读 Join，登记父编号，回 ack，再自报编号。
        let (parent, _join) = bridge_accept(&mut server).await.expect("accept");
        assert_eq!(parent, self_id, "父编号必须是我们宣告的 admin");
        reply_join_ack(
            &mut server,
            JoinAck {
                node: self_id,
                parent: NodeId::UNASSIGNED,
                root: id(9),
                depth: 1,
            },
        )
        .await
        .expect("ack");
        server
            .send(
                &announce_message(id(7), NodeKind::Agent),
                NodeId::UNASSIGNED,
                &[],
            )
            .await
            .expect("自报");

        let peer = read_peers_registration(&mut client, self_id)
            .await
            .expect("读登记");
        assert_eq!(peer, id(7), "对端编号应来自它的自报 Join");
    }

    #[tokio::test]
    async fn ack_with_a_different_id_is_rejected() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = LinkCodec::new(boxed(TestLink { inner: a }));
        let mut server = LinkCodec::new(boxed(TestLink { inner: b }));
        let s = secret();
        let s2 = secret();
        let client_task = tokio::spawn(async move {
            client
                .client_handshake(NodeKind::Admin, TransportKind::Raw, None, &s2)
                .await
                .map(|_| client)
        });
        let server_task = tokio::spawn(async move {
            server
                .server_handshake(NodeKind::Agent, TransportKind::Raw, None, &s)
                .await
                .map(|_| server)
        });
        let mut client = client_task.await.expect("join").expect("client");
        let server = server_task.await.expect("join").expect("server");

        // 对端错误地把父编号 ack 成了别人。
        let mut server = server;
        reply_join_ack(
            &mut server,
            JoinAck {
                node: id(42),
                parent: NodeId::UNASSIGNED,
                root: id(9),
                depth: 1,
            },
        )
        .await
        .expect("ack");

        let err = read_peers_registration(&mut client, NodeId::ADMIN)
            .await
            .expect_err("编号不符必须报错");
        match err {
            BridgeError::IdMismatch { expected, actual } => {
                assert_eq!(expected, NodeId::ADMIN);
                assert_eq!(actual, id(42));
            }
            other => panic!("错误种类不对：{other:?}"),
        }
    }

    #[tokio::test]
    async fn non_registration_message_is_reported_not_guessed() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = LinkCodec::new(boxed(TestLink { inner: a }));
        let mut server = LinkCodec::new(boxed(TestLink { inner: b }));
        let s = secret();
        let s2 = secret();
        let client_task = tokio::spawn(async move {
            client
                .client_handshake(NodeKind::Admin, TransportKind::Raw, None, &s2)
                .await
                .map(|_| client)
        });
        let server_task = tokio::spawn(async move {
            server
                .server_handshake(NodeKind::Agent, TransportKind::Raw, None, &s)
                .await
                .map(|_| server)
        });
        let mut client = client_task.await.expect("join").expect("client");
        let mut server = server_task.await.expect("join").expect("server");

        server
            .send(
                &Message::Memo(stowaway_protocol::Memo::default()),
                NodeId::UNASSIGNED,
                &[],
            )
            .await
            .expect("发 Memo");

        let err = read_peers_registration(&mut client, NodeId::ADMIN)
            .await
            .expect_err("非登记消息必须报错");
        match err {
            BridgeError::Unexpected { actual } => assert_eq!(actual, "Memo"),
            other => panic!("错误种类不对：{other:?}"),
        }
    }
}
