//! 运行时装配：把传输、握手、引导、引擎拼成一个能跑的东西。
//!
//! 引擎（[`crate::engine`]）只关心「节点之间怎么说话」，这里关心
//! 「第一条链路怎么建立」。v1 把这件事散在 `agent/initial`、
//! `admin/initial`、`agent/process` 三处，靠 9 个 `Mode` 常量分支，
//! 且不匹配就 `os.Exit(1)`（缺陷 #10 的另一面：失败没有语义）。
//!
//! # 一条链路只有两种身份
//!
//! 握手里的角色与 socket 方向**无关**（plan §4.2：`Hello.kind` 决定谁是谁）。
//! 因此握完手之后，谁分配编号只取决于**对端角色**，与「谁拨的号」无关：
//!
//! | 对端角色 | 我的身份 | 引导 | 谁调 [`lead`]/[`follow`] |
//! |---|---|---|---|
//! | `Agent` | 父节点（Admin 或已入网的上游） | 读 `Join` → 分配编号 | 本端 [`lead`] |
//! | `Admin` | 子节点（Agent） | 发 `Join{UNASSIGNED}` → 收编号 | 本端 [`follow`] |
//!
//! 于是四种「谁监听、谁拨号」的组合自动归一：**编号永远由父节点分配**
//! （plan 附录 A 第 3、4 行），子节点只申领。把这条规则写成两个函数，
//! 而不是给 `Node` 开一个「改自己编号」的后门。

use std::net::SocketAddr;
use std::sync::Arc;

use stowaway_crypto::Secret;
use stowaway_protocol::{JoinAck, NodeId, NodeKind, TransportKind};
use stowaway_transport::{
    AnyListener, DialTarget, HandshakeResult, LinkCodec, Listener, TransportSpec, dialer_for,
    listener_for,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::alloc::{NodeIdAllocator, salt_from_secret};
use crate::bootstrap::{assign_id, request_id};
use crate::engine::{Engine, EngineHandle, Event, HeartbeatConfig};
use crate::error::{CoreError, Result};
use crate::node::NodeConfig;
use crate::service::ServiceConfig;

/// 一次运行所需的全部外部输入。
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// 节点配置（`me` 在 [`follow`] 里会被父节点分配的编号覆盖）。
    pub node: NodeConfig,
    /// 共享密钥。
    pub secret: Arc<Secret>,
    /// 服务执行配置（agent 侧用得上；admin 侧留默认）。
    pub services: ServiceConfig,
    /// 心跳配置；`None` 表示不开启（plan §4.12：默认只应答、不主动探）。
    pub heartbeat: Option<HeartbeatConfig>,
}

impl RuntimeConfig {
    /// 新建配置。
    #[must_use]
    pub fn new(node: NodeConfig, secret: Arc<Secret>) -> Self {
        Self {
            node,
            secret,
            services: ServiceConfig::default(),
            heartbeat: None,
        }
    }

    /// 编号分配器的盐：由密钥派生，保证同一部署的编号形状稳定（见 `alloc`）。
    #[must_use]
    pub fn allocator(&self) -> NodeIdAllocator {
        let digest = self.secret.digest();
        NodeIdAllocator::new(salt_from_secret(&digest))
    }
}

/// 一个跑起来的节点：引擎句柄 + 事件流 + 后台任务。
#[derive(Debug)]
pub struct Runtime {
    handle: EngineHandle,
    events: mpsc::UnboundedReceiver<Event>,
    engine: JoinHandle<Result<()>>,
}

impl Runtime {
    /// 用已知编号起一个节点。
    #[must_use]
    pub fn start(cfg: RuntimeConfig) -> Self {
        let (events_tx, events) = mpsc::unbounded_channel();
        let (handle, engine, _inbound) = Engine::new(cfg.node, events_tx);
        let engine = match cfg.heartbeat {
            Some(hb) => engine.with_heartbeat(hb),
            None => engine,
        };
        let engine = tokio::spawn(engine.run());
        Self {
            handle,
            events,
            engine,
        }
    }

    /// 引擎句柄（对外唯一入口）。
    #[must_use]
    pub fn handle(&self) -> EngineHandle {
        self.handle.clone()
    }

    /// 下一条事件。引擎退出后返回 `None` —— 调用方据此收摊，而不是当成错误。
    pub async fn next_event(&mut self) -> Option<Event> {
        self.events.recv().await
    }

    /// 收下当前已到达的全部事件（主循环一轮一次）。
    pub fn drain_events(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        while let Ok(ev) = self.events.try_recv() {
            out.push(ev);
        }
        out
    }

    /// 引擎是否已退出。
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.engine.is_finished()
    }

    /// 优雅关停：广播 `Shutdown` 并等引擎收摊。
    ///
    /// # Errors
    /// 引擎任务异常退出（panic 或被取消）。
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.handle.shutdown().await;
        self.engine
            .await
            .map_err(|e| CoreError::Io(std::io::Error::other(format!("引擎任务异常退出：{e}"))))?
    }
}

/// 握完手后「我在链路哪一侧」。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// 对端是 `Admin`：本端是子节点，需要申领编号。
    Child,
    /// 对端是 `Agent`：本端是父节点，需要分配编号。
    Parent,
}

/// 由对端角色推断本端身份。
///
/// 对端角色与本端相同时握手层已拒（`HandshakeError::WrongRole`），
/// 所以这里只有两分支；写成函数是为了让「谁分配」这条规则只有一处定义。
#[must_use]
pub const fn side_of(peer_kind: NodeKind) -> Side {
    match peer_kind {
        // 对端是 Admin → 它是我的上游，我申领编号。
        NodeKind::Admin => Side::Child,
        // 对端是 Agent → 它是我的子节点，我分配编号。
        NodeKind::Agent => Side::Parent,
    }
}

/// 子节点侧：在已握手的链路上申领编号，起引擎，把链路挂成上游。
///
/// `cfg.node.me` 会被父节点分配的编号覆盖 —— 这正是「编号只有一个来源」。
///
/// # Errors
/// 申领失败（对端没按引导流程回 `JoinAck`）、登记被拒。
pub async fn follow(
    codec: LinkCodec,
    cfg: RuntimeConfig,
    parent: NodeId,
    parent_kind: NodeKind,
) -> Result<(Runtime, JoinAck)> {
    let mut codec = codec;
    let (me, ack) = request_id(&mut codec, NodeKind::Agent).await?;
    let mut node = cfg.node;
    node.me = me;
    node.kind = NodeKind::Agent;
    let runtime = Runtime::start(RuntimeConfig { node, ..cfg });
    runtime
        .handle()
        .attach_link(codec, parent, parent, parent_kind)
        .await?;
    Ok((runtime, ack))
}

/// 父节点侧：在已握手的链路上读 `Join`、分配编号、登记为子节点。
///
/// # Errors
/// 对端没按引导流程发 `Join`（例如直接发业务消息）、或登记被拒（重复/超深/成环）。
pub async fn lead(
    handle: &EngineHandle,
    codec: LinkCodec,
    alloc: &mut NodeIdAllocator,
    me: NodeId,
    root: NodeId,
    my_depth: u16,
) -> Result<NodeId> {
    let mut codec = codec;
    let (child, _join) = assign_id(&mut codec, alloc, me, root, my_depth).await?;
    handle
        .attach_link(codec, child, me, NodeKind::Agent)
        .await?;
    Ok(child)
}

/// 一个已握手完成的入站/出站链路，加上它的对端信息。
#[derive(Debug)]
pub struct Link {
    /// 已密封的编解码器。
    pub codec: LinkCodec,
    /// 握手结果（对端角色、传输种类、TLS 指纹）。
    pub handshake: HandshakeResult,
    /// 对端地址。
    pub peer: SocketAddr,
}

/// 拨号并按 `role` 握手。
///
/// # Errors
/// 拨号失败、握手失败（对端角色与 `role` 相同时被拒）。
pub async fn dial(
    spec: &TransportSpec,
    target: &DialTarget,
    role: NodeKind,
    secret: &Secret,
) -> Result<Link> {
    let dialer = dialer_for(spec, target.tls.clone())?;
    let (codec, handshake) =
        stowaway_transport::dialer_handshake(&dialer, spec, target, role, secret).await?;
    Ok(Link {
        codec,
        handshake,
        peer: target.addr,
    })
}

/// 经上游代理拨号，并在代理打通的字节流上照常完成 TLS + 前导 + 握手。
///
/// 与 [`dial`] 的唯一区别是「那条 TCP 是谁开的」：直接拨号由
/// `RawDialer::connect` 自己开，这里由 `upstream_proxy::dial_via_proxy`
/// 按 SOCKS5 / HTTP `CONNECT` 开。从代理回 `OK` 那一刻起，字节流与直连
/// 没有任何区别，所以后续一律复用生产路径（`tcp::link_over` +
/// `dialer_handshake` 的握手部分），不另写一份——修 #12 的前提是**只改
/// 拨号这一段**，而不是把整条链路复制一份。
///
/// 约束（plan §4.11 / §5.2）：只支持 `raw` 传输。`ws` 的 `Host`/路径与
/// `kcp` 的 UDP 语义都与「代理一条 TCP」不兼容，且两者的握手 transcript
/// 会把传输种类算进去，硬塞只会得到难解释的校验失败。
///
/// # Errors
/// 代理拨号失败、传输不是 `raw`、TLS 装配失败、握手失败。
pub async fn dial_through_proxy(
    spec: &TransportSpec,
    target: &DialTarget,
    proxy: &crate::upstream_proxy::ProxySpec,
    role: NodeKind,
    secret: &Secret,
) -> Result<Link> {
    if spec.kind != stowaway_protocol::TransportKind::Raw {
        return Err(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "上游代理只支持 raw 传输（tls 可叠加在 raw 上）；当前是 {:?}",
                spec.kind
            ),
        )));
    }
    // 目标地址的写法：有 SNI/Host 时用 `<domain>:<port>`（虚拟主机才路由得到），
    // 否则用 IP:port。这里的 `authority` 是**代理**要拨的目标，与 TLS 的 SNI
    // 无关——`DialTarget.domain` 恰好同时能当两者用，是 v1 就有的约定。
    let authority = match target.domain.as_deref() {
        Some(domain) => format!("{domain}:{}", target.addr.port()),
        None => target.addr.to_string(),
    };
    let stream = crate::upstream_proxy::dial_via_proxy(proxy, &authority).await?;
    let link = stowaway_transport::tcp::link_over(stream, target).await?;
    let mut codec = LinkCodec::new(link);
    let handshake = codec
        .client_handshake(role, spec.kind, None, secret)
        .await?;
    Ok(Link {
        codec,
        handshake,
        peer: target.addr,
    })
}

/// 绑一个监听器。
///
/// # Errors
/// 传输未编译、地址非法、bind 失败。
pub async fn bind(
    spec: &TransportSpec,
    tls: Option<stowaway_transport::TlsConfig>,
) -> Result<(AnyListener, TransportKind, SocketAddr)> {
    let kind = spec.kind;
    // `listener_for` 先返回构造器（`Result`），await 它才得到 bind 结果。
    let listener = listener_for(spec, tls)?.await?;
    let addr = listener.local_addr().map_err(CoreError::Io)?;
    Ok((listener, kind, addr))
}

/// 接受一条入站链路并做完握手。
///
/// # Errors
/// 接受失败、握手失败（含对端角色与本端相同）。
pub async fn accept(
    listener: &mut AnyListener,
    kind: TransportKind,
    secret: &Secret,
    role: NodeKind,
    expected_tls_fp: Option<[u8; 32]>,
) -> Result<Link> {
    let (codec, handshake, peer) =
        stowaway_transport::listener_handshake(listener, kind, expected_tls_fp, role, secret)
            .await?;
    Ok(Link {
        codec,
        handshake,
        peer,
    })
}

#[cfg(test)]
mod tests {
    use super::{Link, Runtime, RuntimeConfig, Side, accept, bind, dial, follow, lead, side_of};
    use crate::alloc::NodeIdAllocator;
    use crate::node::NodeConfig;
    use std::sync::Arc;
    use stowaway_crypto::Secret;
    use stowaway_protocol::{NodeId, NodeKind, TransportKind};
    use stowaway_transport::{DialTarget, TransportSpec};

    fn secret() -> Arc<Secret> {
        Arc::new(Secret::load("runtime-shared-secret", 8).expect("secret"))
    }

    fn spec_for(addr: std::net::SocketAddr) -> TransportSpec {
        TransportSpec::parse(&format!("raw://{addr}")).expect("spec")
    }

    #[test]
    fn side_is_decided_by_the_peer_role_only() {
        assert_eq!(side_of(NodeKind::Admin), Side::Child);
        assert_eq!(side_of(NodeKind::Agent), Side::Parent);
    }

    #[test]
    fn allocator_salt_is_derived_from_the_secret() {
        let a = RuntimeConfig::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin), secret());
        let b = RuntimeConfig::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin), secret());
        assert_eq!(a.allocator().salt(), b.allocator().salt());
        let other = RuntimeConfig::new(
            NodeConfig::new(NodeId::ADMIN, NodeKind::Admin),
            Arc::new(Secret::load("another-secret-value", 8).expect("secret")),
        );
        assert_ne!(a.allocator().salt(), other.allocator().salt());
    }

    #[tokio::test]
    async fn runtime_starts_and_reports_its_own_id() {
        let cfg = RuntimeConfig::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin), secret());
        let rt = Runtime::start(cfg);
        let snap = rt.handle().snapshot().await.expect("snapshot");
        assert_eq!(snap.me, Some(NodeId::ADMIN));
        rt.shutdown().await.expect("shutdown");
    }

    /// 场景 A：Admin 监听，Agent 拨入 —— Admin 分配编号。
    #[tokio::test]
    async fn admin_listens_and_agent_dials_in() {
        let spec = TransportSpec::parse("raw://127.0.0.1:0").expect("spec");
        let (mut listener, kind, addr) = bind(&spec, None).await.expect("bind");
        assert_eq!(kind, TransportKind::Raw);

        let admin_cfg =
            RuntimeConfig::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin), secret());
        let admin = Runtime::start(admin_cfg);
        let admin_handle = admin.handle();
        let mut alloc = NodeIdAllocator::new([1, 2, 3, 4]);
        let s = secret();

        let parent_side = tokio::spawn(async move {
            let link: Link = accept(&mut listener, kind, &s, NodeKind::Admin, None)
                .await
                .expect("accept");
            assert_eq!(link.handshake.peer_kind, NodeKind::Agent);
            assert_eq!(side_of(link.handshake.peer_kind), Side::Parent);
            let child = lead(
                &admin_handle,
                link.codec,
                &mut alloc,
                NodeId::ADMIN,
                NodeId::ADMIN,
                0,
            )
            .await
            .expect("lead");
            (child, link.peer)
        });

        let child_side = tokio::spawn(async move {
            let link = dial(
                &spec_for(addr),
                &DialTarget::plain(addr),
                NodeKind::Agent,
                secret().as_ref(),
            )
            .await
            .expect("dial");
            assert_eq!(link.handshake.peer_kind, NodeKind::Admin);
            assert_eq!(side_of(link.handshake.peer_kind), Side::Child);
            follow(
                link.codec,
                RuntimeConfig::new(
                    NodeConfig::new(NodeId::UNASSIGNED, NodeKind::Agent),
                    secret(),
                ),
                NodeId::ADMIN,
                NodeKind::Admin,
            )
            .await
            .expect("follow")
        });

        let (child_id, peer) = parent_side.await.expect("parent side");
        let (child_rt, ack) = child_side.await.expect("child side");
        assert_eq!(ack.node, child_id, "两侧对同一个编号必须一致");
        assert_ne!(child_id, NodeId::ADMIN);
        assert_ne!(child_id, NodeId::UNASSIGNED);
        // 父侧看到的 `peer` 是子端的**临时端口**，不是监听端口：能校验的
        // 只是「确实是本机来的连接」，强行比对监听端口会把语义写错。
        assert!(peer.ip().is_loopback(), "对端应来自回环：{peer}");
        assert_ne!(peer.port(), 0);

        let snap = child_rt.handle().snapshot().await.expect("snapshot");
        assert_eq!(snap.me, Some(child_id), "本端编号必须就是父节点分配的那个");
        assert!(snap.nodes.iter().any(|n| n.node == NodeId::ADMIN));
        let admin_snap = admin.handle().snapshot().await.expect("snapshot");
        assert!(admin_snap.nodes.iter().any(|n| n.node == child_id));

        child_rt.shutdown().await.expect("shutdown child");
        admin.shutdown().await.expect("shutdown admin");
    }

    /// 场景 B：Agent 监听，Admin 拨入 —— Admin 依然是分配方。
    #[tokio::test]
    async fn agent_listens_and_admin_dials_in() {
        let spec = TransportSpec::parse("raw://127.0.0.1:0").expect("spec");
        let (mut listener, kind, addr) = bind(&spec, None).await.expect("bind");
        let s = secret();
        let s_for_agent = secret();

        // Agent 侧：握手时自报 Agent，等 Admin 分配编号。
        let agent_side = tokio::spawn(async move {
            let link = accept(&mut listener, kind, &s_for_agent, NodeKind::Agent, None)
                .await
                .expect("accept");
            assert_eq!(link.handshake.peer_kind, NodeKind::Admin);
            follow(
                link.codec,
                RuntimeConfig::new(
                    NodeConfig::new(NodeId::UNASSIGNED, NodeKind::Agent),
                    secret(),
                ),
                NodeId::ADMIN,
                NodeKind::Admin,
            )
            .await
            .expect("follow")
        });

        // Admin 侧：主动拨号，扮父节点。
        let admin_cfg =
            RuntimeConfig::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin), secret());
        let admin = Runtime::start(admin_cfg);
        let admin_handle = admin.handle();
        let mut alloc = NodeIdAllocator::new([7, 7, 7, 7]);
        let link = dial(
            &spec_for(addr),
            &DialTarget::plain(addr),
            NodeKind::Admin,
            &s,
        )
        .await
        .expect("dial");
        assert_eq!(link.handshake.peer_kind, NodeKind::Agent);
        let child = lead(
            &admin_handle,
            link.codec,
            &mut alloc,
            NodeId::ADMIN,
            NodeId::ADMIN,
            0,
        )
        .await
        .expect("lead");

        let (agent_rt, ack) = agent_side.await.expect("agent side");
        assert_eq!(ack.node, child);
        agent_rt.shutdown().await.expect("shutdown agent");
        admin.shutdown().await.expect("shutdown admin");
    }

    /// 两侧都自报同一个角色时必须被握手拒掉（不是静默半开）。
    #[tokio::test]
    async fn same_role_on_both_ends_is_rejected_by_the_handshake() {
        let spec = TransportSpec::parse("raw://127.0.0.1:0").expect("spec");
        let (mut listener, kind, addr) = bind(&spec, None).await.expect("bind");
        let s = secret();
        let server = tokio::spawn(async move {
            let res = accept(&mut listener, kind, &s, NodeKind::Agent, None).await;
            res.map(|_| ())
        });
        let client = tokio::spawn(async move {
            dial(
                &spec_for(addr),
                &DialTarget::plain(addr),
                NodeKind::Agent,
                secret().as_ref(),
            )
            .await
            .map(|_| ())
        });
        let (a, b) = tokio::join!(server, client);
        let server = a.expect("join");
        let client = b.expect("join");
        assert!(
            server.is_err() || client.is_err(),
            "两侧同为 Agent 时至少一侧必须失败"
        );
    }
}
