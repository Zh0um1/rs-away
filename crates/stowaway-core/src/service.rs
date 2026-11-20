//! agent 侧服务执行：把引擎交上来的服务请求真正做掉。
//!
//! 引擎只负责「有那么一个请求、它属于哪个会话」（[`crate::engine::Event`]），
//! 具体怎么做是这里的事（plan §4.9 的 `ServiceActor`）。每个服务一个任务，
//! 生命周期绑在会话上：会话关掉、任务结束。
//!
//! # 为什么服务层要独立成模块
//!
//! v1 把这些散在 `agent/handler/*.go` 的 `go handleXxx(...)` 里，起停靠
//! `Manager` 里的 map 与裸计数器，出错就是打印 + 静默（缺陷 #9）。v2 把
//! 「会话」当唯一句柄：请求进、数据进出、退出出，中间不共享可变状态，
//! 因此可以在单测里直接喂一条 `ServiceRequest` 看它做了什么。
//!
//! # 数据通路
//!
//! 每个 `Run` 类服务的第一步都是 `engine.open_stream(key, from)` ——
//! 拿一条 [`SessionStream`]，它同时是 `AsyncRead + AsyncWrite`，
//! 于是「会话 ↔ 本地」两侧都成了字节流，直接 `copy_bidirectional` 即可
//! （v1 每个 handler 都手写一遍同样的循环）。文件传输例外：它需要逐块
//! 校验与落盘，所以自己读会话流。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use stowaway_crypto::Secret;
use stowaway_protocol::{
    CloseReason, ConnectParam, FileDirection, FileParam, Message, NodeId, NodeKind, ServiceData,
    ServiceExit, ServiceKind, ServiceParam, ServicePhase, ServiceReply, ServiceRequest,
    SessionCode, SessionKey, SessionKind, ShellParam, SshParam, SshTunnelParam,
};
use stowaway_transport::{TlsConfig, TransportSpec};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::alloc::NodeIdAllocator;
use crate::bridge::announce_message;
use crate::engine::EngineHandle;
use crate::error::{CoreError, Result};
use crate::session_stream::SessionStream;
use crate::socks_server::{dial_code, dial_target};

/// 单个服务的终局。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// 结果码（决定对端看到 `ServiceExit.code`）。
    pub code: SessionCode,
    /// 人类可读的原因（成功时写做了什么，失败时写为什么）。
    pub detail: String,
    /// 搬运的字节数（上行，下行）。
    pub bytes: (u64, u64),
}

impl Outcome {
    /// 成功。
    #[must_use]
    pub fn ok(detail: impl Into<String>, bytes: (u64, u64)) -> Self {
        Self {
            code: SessionCode::Ok,
            detail: detail.into(),
            bytes,
        }
    }

    /// 失败（默认按「对端拒绝了」上报）。
    #[must_use]
    pub fn failed(code: SessionCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            bytes: (0, 0),
        }
    }

    /// 转成回给发起方的 `ServiceExit`。
    #[must_use]
    pub fn exit_message(&self, key: SessionKey) -> Message {
        Message::ServiceExit(ServiceExit {
            key,
            code: self.code,
            detail: self.detail.clone(),
        })
    }
}

/// agent 侧服务执行器的配置。
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// 文件落盘根目录（**必填**：v1 直接用客户端给的文件名，缺陷 #13）。
    pub download_dir: PathBuf,
    /// shell 的字符集（`--cs gbk` 时生效，见 plan §4.10 F6）。
    pub charset: crate::shell::Charset,
    /// SSH host key 策略（默认 `Strict`，绝不照抄 v1 的 `InsecureIgnoreHostKey`）。
    pub host_key_policy: crate::ssh::HostKeyPolicy,
    /// known_hosts 路径；`None` 表示用默认位置。
    pub known_hosts: Option<PathBuf>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            download_dir: std::env::temp_dir().join("stowaway-downloads"),
            charset: crate::shell::Charset::Utf8,
            host_key_policy: crate::ssh::HostKeyPolicy::Strict,
            known_hosts: None,
        }
    }
}

/// 一个已启动的服务任务。
#[derive(Debug)]
pub struct ServiceTask {
    /// 会话键。
    pub key: SessionKey,
    /// 服务种类。
    pub kind: ServiceKind,
    /// 后台任务。
    pub handle: JoinHandle<()>,
}

/// `listen` 服务需要的运行时上下文。
///
/// 与其它服务不同，`listen` 不是「拿一条会话流搬字节」，而是在本机 **bind
/// 一个新端口**并把拨进来的对端登记成自己的子节点（`agent/handler/listen.go`
/// 的语义：本节点临时扮 admin，与 `bridge` 同一套握手）。这需要三样东西：
/// 传输层规格、连线的密码学材料、以及一个**只属于本运行时**的编号分配器
/// （编号必须由父节点分配，不能让对端自己编）。
///
/// 没有这份上下文时 `listen` 显式 `Denied`，而不是假装能监听——探测说
/// 「可以」而执行说「没做」必须让调用方看得见（plan §4.14 E20）。
pub struct ListenContext {
    /// 连线密钥材料（握手与密封都要）。
    pub secret: Arc<Secret>,
    /// 要 bind 的传输层规格（`raw://0.0.0.0:9000` 之类）。
    pub spec: TransportSpec,
    /// 子节点编号分配器：`listen` 每接入一个对端就发一次号。
    pub alloc: Mutex<NodeIdAllocator>,
    /// 我的编号（也是子节点看到的 `parent`）。
    pub me: NodeId,
    /// 根节点编号（透传给子节点的 `JoinAck.root`）。
    pub root: NodeId,
    /// 我的深度（子节点是 `depth + 1`）。
    pub depth: u16,
    /// 上游节点编号；`None` 表示本节点就是根（没有上游可公告）。
    pub upstream: Option<NodeId>,
    /// 服务端 TLS 配置；`None` 表示明文。
    pub tls: Option<TlsConfig>,
}

impl ListenContext {
    /// 新建上下文。
    #[must_use]
    pub fn new(
        secret: Arc<Secret>,
        spec: TransportSpec,
        alloc: NodeIdAllocator,
        me: NodeId,
        root: NodeId,
        depth: u16,
    ) -> Self {
        Self {
            secret,
            spec,
            alloc: Mutex::new(alloc),
            me,
            root,
            depth,
            upstream: None,
            tls: None,
        }
    }

    /// 带上上游节点编号（接入子节点后要向上游代子公告）。
    #[must_use]
    pub fn with_upstream(mut self, upstream: Option<NodeId>) -> Self {
        self.upstream = upstream;
        self
    }

    /// 带上服务端 TLS 配置。
    #[must_use]
    pub fn with_tls(mut self, tls: Option<TlsConfig>) -> Self {
        self.tls = tls;
        self
    }
}

impl std::fmt::Debug for ListenContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `TlsConfig` 没有 `Debug`，`Secret` 的 `Debug` 已经脱敏；这里只打
        // 能安全展开的部分，避免为了 derive 而给 `TlsConfig` 造一个假实现。
        f.debug_struct("ListenContext")
            .field("spec", &self.spec)
            .field("me", &self.me)
            .field("root", &self.root)
            .field("depth", &self.depth)
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

/// 服务执行器：把引擎事件变成真实动作。
#[derive(Clone, Debug)]
pub struct Services {
    config: Arc<ServiceConfig>,
    /// 引擎句柄（服务要靠它开会话流、回消息）。
    engine: EngineHandle,
    /// 会话目标（`OpenSession.target`，SSH / connect 用得上）。
    target: Option<String>,
    /// `listen` 的运行时上下文（没装配时 `listen` 显式失败）。
    listen: Option<Arc<ListenContext>>,
}

impl Services {
    /// 新建执行器。
    #[must_use]
    pub fn new(config: ServiceConfig, engine: EngineHandle) -> Self {
        Self {
            config: Arc::new(config),
            engine,
            target: None,
            listen: None,
        }
    }

    /// 带上 `listen` 的运行时上下文。
    ///
    /// 只有真正持有传输层与编号分配器的那一端（agent 的被动模式）才装配它；
    /// 没装配时 `listen` 回 `Denied` 并给出原因。
    #[must_use]
    pub fn with_listen_context(mut self, ctx: ListenContext) -> Self {
        self.listen = Some(Arc::new(ctx));
        self
    }

    /// 同上，但复用已有的 `Arc`（事件循环里每条 `ServiceRequest` 都要用同一个
    /// 分配器，重复 `Arc::new` 会让每个服务拿到一份各自推进的编号序列）。
    #[must_use]
    pub fn with_listen_context_shared(mut self, ctx: Arc<ListenContext>) -> Self {
        self.listen = Some(ctx);
        self
    }

    /// 带上会话目标（SSH 的 `host:port`、connect 的地址都在这）。
    #[must_use]
    pub fn with_target(mut self, target: Option<String>) -> Self {
        self.target = target;
        self
    }

    /// 配置。
    #[must_use]
    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    /// 引擎句柄。
    #[must_use]
    pub const fn engine(&self) -> &EngineHandle {
        &self.engine
    }

    /// 处理一条服务请求，返回启动的任务（`Probe` 会当场答复、返回 `None`）。
    ///
    /// # Errors
    /// 请求形状非法（例如 `Run/File` 缺 `FileParam`）。
    pub async fn handle(&self, req: ServiceRequest, from: NodeId) -> Result<Option<ServiceTask>> {
        match (req.phase, req.kind) {
            (ServicePhase::Probe, kind) => {
                self.reply_probe(req.key, kind, from).await;
                Ok(None)
            }
            (ServicePhase::Run, ServiceKind::File) => {
                let param = file_param(&req.param)?;
                Ok(Some(self.spawn(
                    req.key,
                    from,
                    ServiceKind::File,
                    move |s| Box::pin(async move { s.run_file(req.key, from, param).await }),
                )))
            }
            (ServicePhase::Run, ServiceKind::Shell) => {
                let param = shell_param(&req.param)?;
                Ok(Some(self.spawn(
                    req.key,
                    from,
                    ServiceKind::Shell,
                    move |s| Box::pin(async move { s.run_shell(req.key, from, param).await }),
                )))
            }
            (ServicePhase::Run, ServiceKind::Ssh) => {
                let param = ssh_param(&req.param)?;
                Ok(Some(self.spawn(
                    req.key,
                    from,
                    ServiceKind::Ssh,
                    move |s| Box::pin(async move { s.run_ssh(req.key, from, param).await }),
                )))
            }
            (ServicePhase::Run, ServiceKind::SshTunnel) => {
                let param = ssh_tunnel_param(&req.param)?;
                Ok(Some(self.spawn(
                    req.key,
                    from,
                    ServiceKind::SshTunnel,
                    move |s| Box::pin(async move { s.run_ssh_tunnel(req.key, from, param).await }),
                )))
            }
            (ServicePhase::Run, ServiceKind::Connect) => {
                let addr = connect_addr(&req.param)?;
                Ok(Some(self.spawn(
                    req.key,
                    from,
                    ServiceKind::Connect,
                    move |s| Box::pin(async move { s.run_connect(req.key, from, addr).await }),
                )))
            }
            // `listen` 与 `backward` 的 Run 都要装配真实资源：`listen` 在本机
            // bind 一个传输层端口把拨入者接成子节点，`backward` 在本机 bind
            // 一个 TCP 监听口并逐连接向发起方要一条会话。
            (ServicePhase::Run, ServiceKind::Listen) => {
                // 监听地址随 `ServiceParam::Connect(addr)` 下发（Service 族没有
                // 通用的「地址」变体，连接类参数是唯一的地址载体）；空或缺省时
                // 用 `ListenContext.spec` 里的地址。
                let override_addr = match &req.param {
                    ServiceParam::Connect(ConnectParam { addr }) if !addr.trim().is_empty() => {
                        Some(addr.clone())
                    }
                    _ => None,
                };
                let Some(ctx) = self.listen.clone() else {
                    let detail =
                        "本进程没有装配监听上下文（listen 需要传输层与编号分配器）".to_owned();
                    self.reply(req.key, from, SessionCode::Denied, &detail)
                        .await;
                    return Ok(None);
                };
                Ok(Some(self.spawn(
                    req.key,
                    from,
                    ServiceKind::Listen,
                    move |s| {
                        Box::pin(
                            async move { s.run_listen(req.key, from, ctx, override_addr).await },
                        )
                    },
                )))
            }
            (ServicePhase::Run, ServiceKind::Backward) => {
                let addr = connect_addr(&req.param)?;
                Ok(Some(self.spawn(
                    req.key,
                    from,
                    ServiceKind::Backward,
                    move |s| Box::pin(async move { s.run_backward(req.key, from, addr).await }),
                )))
            }
        }
    }

    /// 起一个服务任务，结束时把 `ServiceExit` 回给发起方。
    fn spawn<F>(&self, key: SessionKey, from: NodeId, kind: ServiceKind, work: F) -> ServiceTask
    where
        F: FnOnce(Services) -> std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send>>
            + Send
            + 'static,
    {
        let me = self.clone();
        let worker = me.clone();
        let out = self.engine.clone();
        let handle = tokio::spawn(async move {
            let outcome = work(worker).await;
            let _ = out.send(outcome.exit_message(key), from).await;
        });
        ServiceTask { key, kind, handle }
    }

    /// 探测一律当场答复：能不能服务，取决于本地前置条件是否就绪。
    async fn reply_probe(&self, key: SessionKey, kind: ServiceKind, from: NodeId) {
        let detail = match kind {
            ServiceKind::File => format!("可写入 {}", self.config.download_dir.display()),
            ServiceKind::Shell => "可创建 PTY".to_owned(),
            ServiceKind::Ssh => format!("host key 策略 {}", self.config.host_key_policy.as_tag()),
            ServiceKind::SshTunnel | ServiceKind::Connect => "可拨号".to_owned(),
            ServiceKind::Listen => "可在指定端口被动监听".to_owned(),
            ServiceKind::Backward => "可做反向映射".to_owned(),
        };
        let reply = Message::ServiceReply(ServiceReply {
            key,
            code: SessionCode::Ok,
            detail,
        });
        let _ = self.engine.send(reply, from).await;
    }

    /// 开一条会话流；会话未登记时补登记（绑定即接受）。
    ///
    /// 顺序（plan §4.14 E18）：**先 `stream`、再 [`Self::confirm`]**。反过来
    /// 发起方一收到 `Ok` 就会开写，而这边还没有接收者，第一批数据必被丢成
    /// 「尚未就绪」。`ServiceRequest` 驱动的服务（connect/file/shell/ssh）
    /// 从没有 `OpenSession` 帮它登记会话，所以 `kind` 必须随流一起给出。
    async fn stream(
        &self,
        key: SessionKey,
        from: NodeId,
        kind: stowaway_protocol::SessionKind,
    ) -> Result<SessionStream> {
        self.engine.open_stream(key, from, kind).await
    }

    /// 回报会话就绪/失败（顺序见 [`Self::stream`] 的说明）。
    async fn confirm(
        &self,
        key: SessionKey,
        from: NodeId,
        kind: SessionKind,
        code: SessionCode,
        detail: &str,
    ) {
        // 失败路径从来没建过流，会话也就没登记过；不补登记就推不动状态，
        // `sessions.ready` 报 `UnknownSession`、Ready 根本发不出去，发起方
        // 只能等到超时——失败也必须把码送回去（plan §4.14 E18）。
        if let Err(e) = self.engine.ensure_session(key, kind).await {
            tracing::warn!("会话 {key:?} 无法登记，{} 送不回去：{e}", code_tag(code));
            return;
        }
        if let Err(e) = self
            .engine
            .ready_session(key, from, code, detail.to_owned())
            .await
        {
            // 到这一步还失败，说明链路已经断了。
            tracing::warn!("回报会话 {key:?} 的 {} 失败：{e}", code_tag(code));
        }
    }

    /// 回一条 `ServiceReply`（`listen`/`backward` 这类「先告诉对端我起没起来」的
    /// 服务用它，而不是 `SessionReady`：它们的首个答复是「监听成功/失败」，
    /// 与某条会话无关，见 `docs/plan.md` 附录 A 第 13、26 行）。
    async fn reply(&self, key: SessionKey, from: NodeId, code: SessionCode, detail: &str) {
        let reply = Message::ServiceReply(ServiceReply {
            key,
            code,
            detail: detail.to_owned(),
        });
        if let Err(e) = self.engine.send(reply, from).await {
            tracing::warn!("把 {} 送回去失败：{e}", code_tag(code));
        }
    }

    // —— 各服务 ——

    /// `listen`：在本机 bind 一个传输层端口，把拨进来的对端接成子节点。
    ///
    /// 与 `bridge` 同一套握手：本端临时扮 admin，对端扮 agent 申领编号。
    /// 编号只能由父节点分配，所以这里必然走 [`crate::bootstrap::assign_id`]；
    /// 接入成功后向上游补一条 `Join{node: <child>}` 代子公告，否则上游不知道
    /// 多了一个孙节点（plan §4.7）。
    async fn run_listen(
        &self,
        key: SessionKey,
        from: NodeId,
        ctx: Arc<ListenContext>,
        override_addr: Option<String>,
    ) -> Outcome {
        let mut spec = ctx.spec.clone();
        if let Some(raw) = override_addr {
            let addr = match parse_listen_addr(&raw) {
                Ok(a) => a,
                Err(e) => {
                    let detail = e.to_string();
                    self.reply(key, from, SessionCode::Denied, &detail).await;
                    return Outcome::failed(SessionCode::Denied, detail);
                }
            };
            spec.host = addr.ip().to_string();
            spec.port = addr.port();
        }
        let (mut listener, kind, addr) = match crate::runtime::bind(&spec, ctx.tls.clone()).await {
            Ok(v) => v,
            Err(e) => {
                let detail = format!("{spec} 监听失败：{e}");
                self.reply(key, from, SessionCode::Denied, &detail).await;
                return Outcome::failed(SessionCode::Denied, detail);
            }
        };
        self.reply(
            key,
            from,
            SessionCode::Ok,
            &format!("已在 {addr} 监听（{kind:?}）"),
        )
        .await;
        let expected = ctx.tls.as_ref().and_then(TlsConfig::advertised_fingerprint);
        loop {
            let link = match crate::runtime::accept(
                &mut listener,
                kind,
                &ctx.secret,
                NodeKind::Admin,
                expected,
            )
            .await
            {
                Ok(link) => link,
                Err(e) => {
                    // 单次握手失败不该拖垮监听（v1 在这里直接 return，端口就此失守）。
                    tracing::warn!("{addr} 入站握手失败，继续监听：{e}");
                    continue;
                }
            };
            let mut codec = link.codec;
            // 分配编号：锁内只推进状态，`await` 都在锁外（迁移/接入都可能等很久）。
            let assigned = {
                let mut guard = ctx.alloc.lock().await;
                crate::bootstrap::assign_id(&mut codec, &mut guard, ctx.me, ctx.root, ctx.depth)
                    .await
            };
            let (child, _join) = match assigned {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("{addr} 接入失败（入网引导）：{e}");
                    continue;
                }
            };
            if let Some(upstream) = ctx.upstream {
                // 代子公告：让所有上游知道这个孙节点（引擎收到 `Join{node}` 会自登记）。
                if let Err(e) = self
                    .engine
                    .send(announce_message(child, NodeKind::Agent), upstream)
                    .await
                {
                    tracing::warn!("向上游 {upstream} 公告 {child} 失败：{e}");
                }
            }
            if let Err(e) = self
                .engine
                .attach_link(codec, child, ctx.me, NodeKind::Agent)
                .await
            {
                tracing::warn!("把 {child} 挂上链路失败：{e}");
                continue;
            }
            tracing::info!("{addr} 已接入子节点 {child}");
        }
    }

    /// `backward`：在本机 bind 一个 TCP 端口，每条进来连接向发起方要一条会话。
    ///
    /// 与 forward 相反：forward 是「本端监听、数据往外送」，backward 是
    /// 「本端监听、每条连接另开一条会话由对端拨回目标」（v1 `BACKWARDSTART`
    /// 的语义）。`ServiceParam` 里带的是**监听端口**（`listen:<port>`）。
    async fn run_backward(&self, key: SessionKey, from: NodeId, addr: String) -> Outcome {
        let port = match backward_port(&addr) {
            Ok(p) => p,
            Err(e) => {
                let detail = e.to_string();
                self.reply(key, from, SessionCode::Denied, &detail).await;
                return Outcome::failed(SessionCode::Denied, detail);
            }
        };
        let spec = crate::backward::BackwardSpec::new(key, port, String::new());
        let mut listener = match crate::backward::BackwardListener::bind(&spec).await {
            Ok(l) => l,
            Err(e) => {
                let detail = format!("反向映射监听 {port} 失败：{e}");
                self.reply(key, from, SessionCode::Denied, &detail).await;
                return Outcome::failed(SessionCode::Denied, detail);
            }
        };
        let bind_addr = listener.local_addr();
        self.reply(
            key,
            from,
            SessionCode::Ok,
            &format!("已在 {bind_addr} 监听（反向映射）"),
        )
        .await;
        let mut conns = 0u64;
        loop {
            let (mut stream, conn_key, open) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("{bind_addr} 接受连接失败，继续监听：{e}");
                    continue;
                }
            };
            conns = conns.saturating_add(1);
            // 每条连接独立会话：共用键会让同一条链路上建立的多条连接互相覆盖
            // （v1 的「一次一条连接」是真限制，v2 用 `SessionKey{origin,id}` 消歧，E8）。
            if let Err(e) = self
                .engine
                .register_session(conn_key, SessionKind::Backward)
                .await
            {
                tracing::warn!("反向连接 {conn_key:?} 登记失败：{e}");
                continue;
            }
            if let Err(e) = self.engine.send(open, from).await {
                tracing::warn!("反向连接 {conn_key:?} 通知发起方失败：{e}");
                continue;
            }
            let mut session = match self.stream(conn_key, from, SessionKind::Backward).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("反向连接 {conn_key:?} 开会话流失败：{e}");
                    continue;
                }
            };
            match self.engine.await_ready(conn_key).await {
                Ok(SessionCode::Ok) => {}
                Ok(code) => {
                    tracing::warn!("反向连接 {conn_key:?} 被拒绝：{}", code_tag(code));
                    self.engine
                        .close_session(conn_key, CloseReason::Refused)
                        .await
                        .ok();
                    continue;
                }
                Err(e) => {
                    tracing::warn!("反向连接 {conn_key:?} 等就绪失败：{e}");
                    continue;
                }
            }
            // 中继在独立任务里跑：一条连接慢不该阻塞下一条连接进来。
            let engine = self.engine.clone();
            tokio::spawn(async move {
                match crate::backward::relay_backward(&mut session, &mut stream).await {
                    Ok(bytes) => tracing::debug!("反向连接 {conn_key:?} 结束：{bytes:?}"),
                    Err(e) => tracing::warn!("反向连接 {conn_key:?} 中继中断：{e}"),
                }
                engine
                    .close_session(conn_key, CloseReason::Normal)
                    .await
                    .ok();
            });
        }
    }

    async fn run_connect(&self, key: SessionKey, from: NodeId, addr: String) -> Outcome {
        let local = match dial_target(&addr).await {
            Ok(s) => s,
            Err(e) => {
                let code = dial_code(&e);
                let detail = format!("拨号 {addr} 失败：{e}");
                self.confirm(key, from, SessionKind::Socks5, code, &detail)
                    .await;
                return Outcome::failed(code, detail);
            }
        };
        // 先把会话流绑到本端（`Node::bind_session`）**再**回「可以发数据了」：
        // 反过来会让发起方收到 Ready 就开写，而这边还没有接收者（plan §4.14 E18）。
        let mut session = match self.stream(key, from, SessionKind::Socks5).await {
            Ok(s) => s,
            Err(e) => {
                let detail = e.to_string();
                self.confirm(
                    key,
                    from,
                    SessionKind::Socks5,
                    SessionCode::Refused,
                    &detail,
                )
                .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        self.confirm(
            key,
            from,
            SessionKind::Socks5,
            SessionCode::Ok,
            &format!("已连上 {addr}"),
        )
        .await;
        let mut local = local;
        match relay_stream(&mut session, &mut local).await {
            Ok(bytes) => Outcome::ok(format!("{addr} 转发结束"), bytes),
            Err(e) => Outcome::failed(SessionCode::Refused, format!("{addr} 转发中断：{e}")),
        }
    }

    async fn run_file(&self, key: SessionKey, from: NodeId, param: FileParam) -> Outcome {
        // 方向决定「谁发谁收」：`ServiceRequest` 没有 direction 字段（那是
        // `OpenSession` 的属性），所以方向随 `FileParam.direction` 一起给
        // （plan §4.14 E25）。
        match param.direction {
            FileDirection::Upload => self.run_file_upload(key, from, param).await,
            FileDirection::Download => self.run_file_download(key, from, param).await,
        }
    }

    /// 上传：对端推数据，本端落盘并校验。
    async fn run_file_upload(&self, key: SessionKey, from: NodeId, param: FileParam) -> Outcome {
        let root = &self.config.download_dir;
        if param.size > 0 && param.sha256 == [0u8; 32] {
            return Outcome::failed(SessionCode::Denied, "缺少 sha256，拒绝无校验传输");
        }
        // `IncomingFile::new` 自己会做 `safe_join`：这里必须把**根目录**交给它，
        // 不能先 join 再把它当 root 传进去——那会拼成 `<root>/<name>/<name>`，
        // 于是 `File::create` 撞上刚被建出来的同名目录（`Is a directory`）。
        let mut file = match crate::file::IncomingFile::new(key, root, &param) {
            Ok(f) => f,
            Err(e) => return Outcome::failed(SessionCode::Denied, format!("无法落盘：{e}")),
        };
        let path = file.path.clone();
        let mut hasher = Sha256::new();
        // 打开一次、顺序追加：早先在这里对每块都 `fs::write`，那是**整文件覆盖**，
        // 第二块就把第一块盖掉（plan §8.5 场景 5 会立刻暴露）。`write_all` 到同一个
        // 句柄上才是「分块传输」的正确写法。
        let mut sink = match tokio::fs::File::create(&path).await {
            Ok(f) => f,
            Err(e) => return Outcome::failed(SessionCode::Refused, format!("创建文件失败：{e}")),
        };
        // 先把会话流绑到本端（`Node::bind_session`）**再**回「可以发数据了」：
        // 反过来会让发起方收到 Ready 就开写，而这边还没有接收者（plan §4.14 E18）。
        let mut session = match self.stream(key, from, SessionKind::File).await {
            Ok(s) => s,
            Err(e) => {
                let detail = e.to_string();
                self.confirm(key, from, SessionKind::File, SessionCode::Refused, &detail)
                    .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        self.confirm(
            key,
            from,
            SessionKind::File,
            SessionCode::Ok,
            &format!("可写入 {}", path.display()),
        )
        .await;
        let mut buf = vec![0u8; crate::file::FILE_CHUNK];
        let mut received = 0u64;
        loop {
            let n = match session.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => return Outcome::failed(SessionCode::Refused, format!("读会话失败：{e}")),
            };
            hasher.update(&buf[..n]);
            if let Err(e) = file.accept(n) {
                return Outcome::failed(SessionCode::Denied, format!("超出声明长度：{e}"));
            }
            if let Err(e) = sink.write_all(&buf[..n]).await {
                return Outcome::failed(SessionCode::Refused, format!("写盘失败：{e}"));
            }
            received = received.saturating_add(n as u64);
        }
        // 显式 flush：hash 校验通过前不想让数据停在页缓存里被当作已落盘。
        if let Err(e) = sink.flush().await {
            return Outcome::failed(SessionCode::Refused, format!("落盘失败：{e}"));
        }
        drop(sink);
        if let Err(e) = file.finish() {
            return Outcome::failed(SessionCode::Denied, format!("传输不完整：{e}"));
        }
        if param.size > 0 {
            let got: [u8; 32] = hasher.finalize().into();
            if got != param.sha256 {
                return Outcome::failed(SessionCode::Denied, "sha256 不匹配，已落盘但不可信");
            }
        }
        Outcome::ok(
            format!("已写入 {}（{received} 字节）", path.display()),
            (received, 0),
        )
    }

    /// 下载：本端读文件、先发清单头再发分片。
    ///
    /// 接收方在下载方向**不可能**预先知道长度与摘要，所以先把
    /// [`crate::file::manifest`] 的 40 字节写进流（`size ‖ sha256`），
    /// 之后才是分片；对端按清单校验（plan §4.14 E25）。
    ///
    /// 只允许读 `--download-dir` 下的单段文件名：下载方向同样受
    /// [`crate::file::validate_name`] 约束。读任意路径不写盘、危害小于
    /// 上传，但「能读 `/etc/shadow`」本身就是越权，规则一致更好讲。
    async fn run_file_download(&self, key: SessionKey, from: NodeId, param: FileParam) -> Outcome {
        let path = match crate::file::safe_join(&self.config.download_dir, &param.name) {
            Ok(p) => p,
            Err(e) => {
                let detail = format!("文件名不可用：{e}");
                self.confirm(key, from, SessionKind::File, SessionCode::Denied, &detail)
                    .await;
                return Outcome::failed(SessionCode::Denied, detail);
            }
        };
        let meta = match tokio::fs::metadata(&path).await {
            Ok(m) if m.is_file() => m,
            Ok(_) => {
                let detail = format!("{} 不是普通文件", path.display());
                self.confirm(key, from, SessionKind::File, SessionCode::NotFound, &detail)
                    .await;
                return Outcome::failed(SessionCode::NotFound, detail);
            }
            Err(e) => {
                let detail = format!("打不开 {}：{e}", path.display());
                self.confirm(key, from, SessionKind::File, SessionCode::NotFound, &detail)
                    .await;
                return Outcome::failed(SessionCode::NotFound, detail);
            }
        };
        let size = meta.len();
        let digest = match crate::file::sha256_file(&path).await {
            Ok(d) => d,
            Err(e) => {
                let detail = format!("读 {} 失败：{e}", path.display());
                self.confirm(key, from, SessionKind::File, SessionCode::Refused, &detail)
                    .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        // 先绑流再回 Ready（plan §4.14 E18）。
        let mut session = match self.stream(key, from, SessionKind::File).await {
            Ok(s) => s,
            Err(e) => {
                let detail = e.to_string();
                self.confirm(key, from, SessionKind::File, SessionCode::Refused, &detail)
                    .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        self.confirm(
            key,
            from,
            SessionKind::File,
            SessionCode::Ok,
            &format!("准备发送 {}（{size} 字节）", path.display()),
        )
        .await;

        // 清单头：对端据此建文件、算期望长度与摘要。
        if let Err(e) = session
            .write_all(&crate::file::manifest(size, &digest))
            .await
        {
            return Outcome::failed(SessionCode::Refused, format!("写清单失败：{e}"));
        }
        let mut sink = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            Err(e) => return Outcome::failed(SessionCode::Refused, format!("打开失败：{e}")),
        };
        let mut buf = vec![0u8; crate::file::FILE_CHUNK];
        let mut sent = 0u64;
        loop {
            let n = match sink.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => return Outcome::failed(SessionCode::Refused, format!("读盘失败：{e}")),
            };
            if let Err(e) = session.write_all(&buf[..n]).await {
                return Outcome::failed(SessionCode::Refused, format!("写会话失败：{e}"));
            }
            sent = sent.saturating_add(n as u64);
        }
        if let Err(e) = session.shutdown().await {
            return Outcome::failed(SessionCode::Refused, format!("收尾失败：{e}"));
        }
        Outcome::ok(
            format!("已发送 {}（{sent} 字节）", path.display()),
            (0, sent),
        )
    }

    async fn run_shell(&self, key: SessionKey, from: NodeId, param: ShellParam) -> Outcome {
        let spec = crate::shell::ShellSpec::new(key, &param).with_charset(self.config.charset);
        let mut pty = match crate::shell::spawn(&spec) {
            Ok(p) => p,
            Err(e) => {
                let detail = format!("PTY 起不来：{e}");
                self.confirm(
                    key,
                    from,
                    SessionKind::ShellPty,
                    SessionCode::Refused,
                    &detail,
                )
                .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        // 先把会话流绑到本端（`Node::bind_session`）**再**回「可以发数据了」：
        // 反过来会让发起方收到 Ready 就开写，而这边还没有接收者（plan §4.14 E18）。
        let mut session = match self.stream(key, from, SessionKind::ShellPty).await {
            Ok(s) => s,
            Err(e) => {
                let detail = e.to_string();
                self.confirm(
                    key,
                    from,
                    SessionKind::ShellPty,
                    SessionCode::Refused,
                    &detail,
                )
                .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        self.confirm(
            key,
            from,
            SessionKind::ShellPty,
            SessionCode::Ok,
            &format!("PTY {}x{}", param.cols, param.rows),
        )
        .await;
        let mut up = 0u64;
        let mut down = 0u64;
        let mut inbuf = vec![0u8; crate::shell::SHELL_READ_BUF];
        loop {
            tokio::select! {
                biased;
                // 上行：会话 → PTY（可能是数据，也可能是 resize 控制帧）
                got = session.read(&mut inbuf) => {
                    match got {
                        Ok(0) => break,
                        Ok(n) => {
                            up = up.saturating_add(n as u64);
                            match crate::shell::parse_frame(&inbuf[..n]) {
                                Ok(crate::shell::ShellFrame::Data(data)) => {
                                    if let Err(e) = pty.write(&data) {
                                        return Outcome::failed(SessionCode::Refused, format!("写 PTY 失败：{e}"));
                                    }
                                }
                                Ok(crate::shell::ShellFrame::Resize { cols, rows }) => {
                                    if let Err(e) = pty.resize(cols, rows) {
                                        return Outcome::failed(SessionCode::Refused, format!("resize 失败：{e}"));
                                    }
                                }
                                Err(e) => {
                                    return Outcome::failed(SessionCode::Refused, format!("shell 帧非法：{e}"));
                                }
                            }
                        }
                        Err(e) => return Outcome::failed(SessionCode::Refused, format!("读会话失败：{e}")),
                    }
                }
                // 下行：PTY → 会话（带数据标签）
                out = pty.next_output() => {
                    match out {
                        Ok(Some(chunk)) => {
                            down = down.saturating_add(chunk.len() as u64);
                            let mut payload = Vec::with_capacity(1 + chunk.len());
                            payload.push(crate::shell::SHELL_TAG_DATA);
                            payload.extend_from_slice(&chunk);
                            if let Err(e) = session.write_all(&payload).await {
                                return Outcome::failed(SessionCode::Refused, format!("写会话失败：{e}"));
                            }
                        }
                        Ok(None) => break,
                        Err(e) => return Outcome::failed(SessionCode::Refused, format!("PTY 读失败：{e}")),
                    }
                }
            }
        }
        Outcome::ok("PTY 已退出", (up, down))
    }

    async fn run_ssh(&self, key: SessionKey, from: NodeId, param: SshParam) -> Outcome {
        let Some(addr) = self.target.clone() else {
            return Outcome::failed(SessionCode::Denied, "SSH 请求缺少目标地址");
        };
        let mut spec = crate::ssh::SshSpec::new(key, addr.clone(), &param)
            .with_policy(self.config.host_key_policy);
        if let Some(kh) = &self.config.known_hosts {
            spec = spec.with_known_hosts(kh.clone());
        }
        if spec.is_interactive() {
            let mut shell = match crate::ssh::open_shell(&spec, None).await {
                Ok(s) => s,
                Err(e) => {
                    let detail = format!("SSH 失败：{e}");
                    self.confirm(key, from, SessionKind::Ssh, SessionCode::Refused, &detail)
                        .await;
                    return Outcome::failed(SessionCode::Refused, detail);
                }
            };
            // 先把会话流绑到本端（`Node::bind_session`）**再**回「可以发数据了」：
            // 反过来会让发起方收到 Ready 就开写，而这边还没有接收者（plan §4.14 E18）。
            let mut session = match self.stream(key, from, SessionKind::Ssh).await {
                Ok(s) => s,
                Err(e) => {
                    let detail = e.to_string();
                    self.confirm(key, from, SessionKind::Ssh, SessionCode::Refused, &detail)
                        .await;
                    return Outcome::failed(SessionCode::Refused, detail);
                }
            };
            self.confirm(
                key,
                from,
                SessionKind::Ssh,
                SessionCode::Ok,
                &format!("SSH 交互会话就绪（{addr}）"),
            )
            .await;
            let mut up = 0u64;
            let mut down = 0u64;
            let mut buf = vec![0u8; 4096];
            loop {
                tokio::select! {
                    biased;
                    got = session.read(&mut buf) => {
                        match got {
                            Ok(0) => break,
                            Ok(n) => {
                                up = up.saturating_add(n as u64);
                                if let Err(e) = shell.write(&buf[..n]).await {
                                    return Outcome::failed(SessionCode::Refused, format!("写 SSH 失败：{e}"));
                                }
                            }
                            Err(e) => return Outcome::failed(SessionCode::Refused, format!("读会话失败：{e}")),
                        }
                    }
                    out = shell.next_output() => {
                        match out {
                            Ok(Some(chunk)) => {
                                down = down.saturating_add(chunk.len() as u64);
                                if let Err(e) = session.write_all(&chunk).await {
                                    return Outcome::failed(SessionCode::Refused, format!("写会话失败：{e}"));
                                }
                            }
                            Ok(None) => break,
                            Err(e) => return Outcome::failed(SessionCode::Refused, format!("SSH 读失败：{e}")),
                        }
                    }
                }
            }
            return Outcome::ok(format!("SSH 交互会话结束（{addr}）"), (up, down));
        }
        let out = match crate::ssh::run_command(&spec, &param.command).await {
            Ok(out) => out,
            Err(e) => {
                let detail = format!("SSH 失败：{e}");
                self.confirm(key, from, SessionKind::Ssh, SessionCode::Refused, &detail)
                    .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        // 先把会话流绑到本端（`Node::bind_session`）**再**回「可以发数据了」：
        // 反过来会让发起方收到 Ready 就开写，而这边还没有接收者（plan §4.14 E18）。
        let mut session = match self.stream(key, from, SessionKind::Ssh).await {
            Ok(s) => s,
            Err(e) => {
                let detail = e.to_string();
                self.confirm(key, from, SessionKind::Ssh, SessionCode::Refused, &detail)
                    .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        self.confirm(
            key,
            from,
            SessionKind::Ssh,
            SessionCode::Ok,
            &format!("SSH 命令已执行（{addr}）"),
        )
        .await;
        let n = out.output.len() as u64;
        if let Err(e) = session.write_all(&out.output).await {
            return Outcome::failed(SessionCode::Refused, format!("写会话失败：{e}"));
        }
        Outcome::ok(format!("SSH 命令退出码 {:?}", out.exit_status), (0, n))
    }

    async fn run_ssh_tunnel(
        &self,
        key: SessionKey,
        from: NodeId,
        param: SshTunnelParam,
    ) -> Outcome {
        let addr = format!("127.0.0.1:{}", param.local_port);
        let mut spec = crate::ssh::SshSpec::new(key, addr, &param.ssh)
            .with_policy(self.config.host_key_policy);
        if let Some(kh) = &self.config.known_hosts {
            spec = spec.with_known_hosts(kh.clone());
        }
        let (host, port) = match split_target(&param.remote_target) {
            Ok(v) => v,
            Err(e) => return Outcome::failed(SessionCode::Denied, e.to_string()),
        };
        let (conn, channel) = match crate::ssh::open_tunnel(&spec, &host, port).await {
            Ok(v) => v,
            Err(e) => {
                let detail = format!("SSH 隧道失败：{e}");
                self.confirm(
                    key,
                    from,
                    SessionKind::SshTunnel,
                    SessionCode::Refused,
                    &detail,
                )
                .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        // 先把会话流绑到本端（`Node::bind_session`）**再**回「可以发数据了」：
        // 反过来会让发起方收到 Ready 就开写，而这边还没有接收者（plan §4.14 E18）。
        let mut session = match self.stream(key, from, SessionKind::SshTunnel).await {
            Ok(s) => s,
            Err(e) => {
                let detail = e.to_string();
                self.confirm(
                    key,
                    from,
                    SessionKind::SshTunnel,
                    SessionCode::Refused,
                    &detail,
                )
                .await;
                return Outcome::failed(SessionCode::Refused, detail);
            }
        };
        self.confirm(
            key,
            from,
            SessionKind::SshTunnel,
            SessionCode::Ok,
            &format!("SSH 隧道就绪 → {host}:{port}"),
        )
        .await;
        let mut stream = channel.into_stream();
        let res = relay_stream(&mut session, &mut stream).await;
        conn.disconnect("stowaway tunnel closed").await.ok();
        match res {
            Ok(bytes) => Outcome::ok(format!("SSH 隧道 → {host}:{port} 结束"), bytes),
            Err(e) => Outcome::failed(SessionCode::Refused, format!("隧道中断：{e}")),
        }
    }
}

/// 双向搬运一条字节流到一条会话流，返回（上行，下行）字节数。
///
/// 这是所有「把会话当管道用」的服务（ssh 隧道 / connect 桥 / 交互会话）
/// 共用的核心：会话流是 `AsyncRead + AsyncWrite`，本地那一侧也是，直接
/// `copy_bidirectional` 即可 —— v1 每个 handler 都手写一遍同样的循环。
///
/// # Errors
/// 任一侧 IO 失败。
pub async fn relay_stream<A, B>(session: &mut A, local: &mut B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(session, local)
        .await
        .map_err(CoreError::Io)
}

/// 一条 `ServiceData` 是否属于该会话（服务任务分发时用）。
///
/// # Errors
/// 会话键不匹配。
pub fn check_data(data: &ServiceData, expect: SessionKey) -> Result<()> {
    if data.key != expect {
        return Err(bad_param(format!(
            "服务数据属于会话 {:?}，期望 {:?}",
            data.key, expect
        )));
    }
    Ok(())
}

fn connect_addr(param: &ServiceParam) -> Result<String> {
    match param {
        ServiceParam::Connect(ConnectParam { addr }) if !addr.is_empty() => Ok(addr.clone()),
        ServiceParam::Connect(_) => Err(bad_param("ConnectParam.addr 为空")),
        _ => Err(bad_param("Connect 请求必须带 ConnectParam")),
    }
}

fn file_param(param: &ServiceParam) -> Result<FileParam> {
    match param {
        ServiceParam::File(p) => Ok(p.clone()),
        _ => Err(bad_param("File 请求必须带 FileParam")),
    }
}

fn shell_param(param: &ServiceParam) -> Result<ShellParam> {
    match param {
        ServiceParam::Shell(p) => Ok(p.clone()),
        ServiceParam::None => Ok(ShellParam {
            cols: 80,
            rows: 24,
            term: crate::shell::DEFAULT_TERM.to_owned(),
        }),
        _ => Err(bad_param("Shell 请求的参数种类不对")),
    }
}

fn ssh_param(param: &ServiceParam) -> Result<SshParam> {
    match param {
        ServiceParam::Ssh(p) => Ok(p.clone()),
        _ => Err(bad_param("Ssh 请求必须带 SshParam")),
    }
}

fn ssh_tunnel_param(param: &ServiceParam) -> Result<SshTunnelParam> {
    match param {
        ServiceParam::SshTunnel(p) => Ok(p.clone()),
        _ => Err(bad_param("SshTunnel 请求必须带 SshTunnelParam")),
    }
}

fn bad_param(msg: impl Into<String>) -> CoreError {
    CoreError::Protocol(stowaway_protocol::ProtocolError::Payload(msg.into()))
}

/// `SessionCode` 的短文本（日志里用；`Debug` 会带类型前缀）。
fn code_tag(code: SessionCode) -> &'static str {
    match code {
        SessionCode::Ok => "ok",
        SessionCode::Refused => "refused",
        SessionCode::Timeout => "timeout",
        SessionCode::NotFound => "not-found",
        SessionCode::Denied => "denied",
    }
}

/// 拆 `host:port`（支持 `[::1]:22`）。
///
/// # Errors
/// 缺少端口、端口非法。
pub fn split_target(target: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let Some((h, tail)) = rest.split_once(']') else {
            return Err(bad_param(format!("地址缺少 `]`：{target}")));
        };
        let Some(p) = tail.strip_prefix(':') else {
            return Err(bad_param(format!("IPv6 地址必须带端口：{target}")));
        };
        (h.to_owned(), p)
    } else {
        let Some((h, p)) = target.rsplit_once(':') else {
            return Err(bad_param(format!("地址必须形如 host:port：{target}")));
        };
        (h.to_owned(), p)
    };
    if host.is_empty() {
        return Err(bad_param(format!("地址缺少主机部分：{target}")));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| bad_param(format!("端口不是合法数字：{target}")))?;
    if port == 0 {
        return Err(bad_param("端口不能为 0"));
    }
    Ok((host, port))
}

/// 监听地址解析（`[ip:]<port>` 或裸端口）。
///
/// # Errors
/// 端口非法。
pub fn parse_listen_addr(input: &str) -> Result<SocketAddr> {
    let with_host = if input.contains(':') {
        input.to_owned()
    } else {
        format!("0.0.0.0:{input}")
    };
    with_host
        .parse()
        .map_err(|_| bad_param(format!("监听地址非法：{input}")))
}

/// 从 `listen:<port>`（`BackwardSpec` 的约定载荷）或裸端口里取出监听端口。
///
/// backward 的 `ConnectParam.addr` 不是目标地址而是**本端要监听的端口**
/// （v1 `BACKWARDTEST` 带的是 `RPort`），所以这里只认 `listen:` 前缀与纯数字，
/// 其余一律报错——把 `1.2.3.4:80` 当成监听端口的后果是静默监听在 80 上。
pub fn backward_port(input: &str) -> Result<u16> {
    let raw = input.trim();
    let raw = raw.strip_prefix("listen:").unwrap_or(raw);
    let port: u16 = raw
        .parse()
        .map_err(|_| bad_param(format!("backward 的监听端口非法：{input}")))?;
    if port == 0 {
        return Err(bad_param("backward 的监听端口不能是 0"));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::{Outcome, Outcome as _O, backward_port, parse_listen_addr, split_target};
    use stowaway_protocol::{NodeId, SessionCode, SessionKey};

    #[test]
    fn outcome_ok_and_failed_carry_the_right_code() {
        let ok = Outcome::ok("fine", (1, 2));
        assert_eq!(ok.code, SessionCode::Ok);
        assert_eq!(ok.bytes, (1, 2));
        let bad = _O::failed(SessionCode::Denied, "nope");
        assert_eq!(bad.code, SessionCode::Denied);
        assert_eq!(bad.bytes, (0, 0));
        assert!(matches!(
            ok.exit_message(SessionKey::new(NodeId::ADMIN, 1)),
            stowaway_protocol::Message::ServiceExit(_)
        ));
    }

    #[test]
    fn split_target_handles_ipv6_and_rejects_garbage() {
        assert_eq!(
            split_target("example.com:22").expect("ok"),
            ("example.com".to_owned(), 22)
        );
        assert_eq!(
            split_target("[::1]:2222").expect("ok"),
            ("::1".to_owned(), 2222)
        );
        assert!(split_target("example.com").is_err(), "缺端口必须报错");
        assert!(split_target(":22").is_err(), "缺主机必须报错");
        assert!(split_target("host:0").is_err(), "端口 0 必须报错");
        assert!(split_target("[::1").is_err(), "缺 `]` 必须报错");
    }

    #[test]
    fn listen_addr_accepts_bare_port_and_explicit_host() {
        assert_eq!(
            parse_listen_addr("1080").expect("ok").to_string(),
            "0.0.0.0:1080"
        );
        assert_eq!(
            parse_listen_addr("127.0.0.1:1080").expect("ok").to_string(),
            "127.0.0.1:1080"
        );
        assert!(parse_listen_addr("not-a-port").is_err());
    }

    #[test]
    fn backward_port_accepts_listen_prefix_and_bare_port() {
        assert_eq!(backward_port("listen:9000").expect("ok"), 9000);
        assert_eq!(backward_port("9000").expect("ok"), 9000);
        assert_eq!(backward_port("  listen:1 ").expect("ok"), 1);
        assert!(
            backward_port("127.0.0.1:9000").is_err(),
            "backward 的载荷是监听端口，把目标地址当端口必须报错而不是静默取 127"
        );
        assert!(backward_port("listen:0").is_err(), "端口 0 无处可听");
        assert!(backward_port("listen:not-a-port").is_err());
    }

    #[test]
    fn listen_context_debug_does_not_leak_the_secret() {
        use super::ListenContext;
        use crate::alloc::NodeIdAllocator;
        use std::sync::Arc;
        let secret = Arc::new(stowaway_crypto::Secret::load("listen-ctx-secret", 8).expect("ok"));
        let ctx = ListenContext::new(
            secret,
            stowaway_transport::TransportSpec::parse("raw://127.0.0.1:0").expect("spec"),
            NodeIdAllocator::new([1, 2, 3, 4]),
            NodeId::ADMIN,
            NodeId::ADMIN,
            0,
        );
        let shown = format!("{ctx:?}");
        assert!(shown.contains("ListenContext"), "要能认出类型：{shown}");
        assert!(
            !shown.contains("listen-ctx-secret"),
            "Debug 绝不能把密钥打出来：{shown}"
        );
        assert!(
            shown.contains("tls: false"),
            "明文时 tls 必须是 false：{shown}"
        );
    }

    #[test]
    fn data_for_another_session_is_rejected() {
        let data = stowaway_protocol::ServiceData {
            key: SessionKey::new(NodeId::ADMIN, 1),
            seq: 0,
            data: stowaway_protocol::ByteBuf::from(vec![1, 2, 3]),
        };
        assert!(super::check_data(&data, SessionKey::new(NodeId::ADMIN, 1)).is_ok());
        assert!(super::check_data(&data, SessionKey::new(NodeId::ADMIN, 2)).is_err());
    }
}
