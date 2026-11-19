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
use stowaway_protocol::{
    ConnectParam, FileParam, Message, NodeId, ServiceData, ServiceExit, ServiceKind, ServiceParam,
    ServicePhase, ServiceReply, ServiceRequest, SessionCode, SessionKey, ShellParam, SshParam,
    SshTunnelParam,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;

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

/// 服务执行器：把引擎事件变成真实动作。
#[derive(Clone, Debug)]
pub struct Services {
    config: Arc<ServiceConfig>,
    /// 引擎句柄（服务要靠它开会话流、回消息）。
    engine: EngineHandle,
    /// 会话目标（`OpenSession.target`，SSH / connect 用得上）。
    target: Option<String>,
}

impl Services {
    /// 新建执行器。
    #[must_use]
    pub fn new(config: ServiceConfig, engine: EngineHandle) -> Self {
        Self {
            config: Arc::new(config),
            engine,
            target: None,
        }
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
            // `listen` 与 `backward` 的 Run 阶段要装配新链路（共享编号分配器 + 传输层
            // 监听），那是运行时职责而非服务职责；P6 只交付命令、参数校验与 Probe，
            // 执行在 P7 联调阶段补（见 docs/plan.md §4.14 E17）。这里显式失败，
            // 不静默成功——探测说「可以」而执行说「没做」必须让调用方看得见。
            (ServicePhase::Run, kind @ (ServiceKind::Listen | ServiceKind::Backward)) => {
                let addr = connect_addr(&req.param)?;
                Ok(Some(self.spawn(req.key, from, kind, move |s| {
                    Box::pin(async move { s.run_deferred(req.key, from, kind, addr).await })
                })))
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

    /// 开一条会话流；会话未登记 / 已绑定都报错。
    async fn stream(&self, key: SessionKey, from: NodeId) -> Result<SessionStream> {
        self.engine.open_stream(key, from).await
    }

    // —— 各服务 ——

    /// `listen` / `backward` 的执行体（P6 显式拒绝，见 [`Self::handle`] 的注释）。
    async fn run_deferred(
        &self,
        key: SessionKey,
        from: NodeId,
        kind: ServiceKind,
        addr: String,
    ) -> Outcome {
        let _ = (key, from);
        Outcome::failed(
            SessionCode::Refused,
            format!("{kind:?} 的执行尚未接通（{addr}）：P6 只交付命令与探测，见 plan §4.14 E17"),
        )
    }

    async fn run_connect(&self, key: SessionKey, from: NodeId, addr: String) -> Outcome {
        let local = match dial_target(&addr).await {
            Ok(s) => s,
            Err(e) => return Outcome::failed(dial_code(&e), format!("拨号 {addr} 失败：{e}")),
        };
        let mut session = match self.stream(key, from).await {
            Ok(s) => s,
            Err(e) => return Outcome::failed(SessionCode::Refused, e.to_string()),
        };
        let mut local = local;
        match relay_stream(&mut session, &mut local).await {
            Ok(bytes) => Outcome::ok(format!("{addr} 转发结束"), bytes),
            Err(e) => Outcome::failed(SessionCode::Refused, format!("{addr} 转发中断：{e}")),
        }
    }

    async fn run_file(&self, key: SessionKey, from: NodeId, param: FileParam) -> Outcome {
        let root = &self.config.download_dir;
        if param.size > 0 && param.sha256 == [0u8; 32] {
            return Outcome::failed(SessionCode::Denied, "缺少 sha256，拒绝无校验传输");
        }
        let path = match crate::file::safe_join(root, &param.name) {
            Ok(p) => p,
            Err(e) => return Outcome::failed(SessionCode::Denied, format!("文件名不可用：{e}")),
        };
        let mut session = match self.stream(key, from).await {
            Ok(s) => s,
            Err(e) => return Outcome::failed(SessionCode::Refused, e.to_string()),
        };
        // 逐块读会话流 → 写盘 → 记账，最后核对长度与摘要。
        let mut file = match crate::file::IncomingFile::new(key, &path, &param) {
            Ok(f) => f,
            Err(e) => return Outcome::failed(SessionCode::Denied, format!("无法落盘：{e}")),
        };
        let mut hasher = Sha256::new();
        // 打开一次、顺序追加：早先在这里对每块都 `fs::write`，那是**整文件覆盖**，
        // 第二块就把第一块盖掉（plan §8.5 场景 5 会立刻暴露）。`write_all` 到同一个
        // 句柄上才是「分块传输」的正确写法。
        let mut sink = match tokio::fs::File::create(&path).await {
            Ok(f) => f,
            Err(e) => return Outcome::failed(SessionCode::Refused, format!("创建文件失败：{e}")),
        };
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

    async fn run_shell(&self, key: SessionKey, from: NodeId, param: ShellParam) -> Outcome {
        let spec = crate::shell::ShellSpec::new(key, &param).with_charset(self.config.charset);
        let mut session = match self.stream(key, from).await {
            Ok(s) => s,
            Err(e) => return Outcome::failed(SessionCode::Refused, e.to_string()),
        };
        let mut pty = match crate::shell::spawn(&spec) {
            Ok(p) => p,
            Err(e) => return Outcome::failed(SessionCode::Refused, format!("PTY 起不来：{e}")),
        };
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
        let mut session = match self.stream(key, from).await {
            Ok(s) => s,
            Err(e) => return Outcome::failed(SessionCode::Refused, e.to_string()),
        };
        if spec.is_interactive() {
            let mut shell = match crate::ssh::open_shell(&spec, None).await {
                Ok(s) => s,
                Err(e) => return Outcome::failed(SessionCode::Refused, format!("SSH 失败：{e}")),
            };
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
        match crate::ssh::run_command(&spec, &param.command).await {
            Ok(out) => {
                let n = out.output.len() as u64;
                if let Err(e) = session.write_all(&out.output).await {
                    return Outcome::failed(SessionCode::Refused, format!("写会话失败：{e}"));
                }
                Outcome::ok(format!("SSH 命令退出码 {:?}", out.exit_status), (0, n))
            }
            Err(e) => Outcome::failed(SessionCode::Refused, format!("SSH 失败：{e}")),
        }
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
            Err(e) => return Outcome::failed(SessionCode::Refused, format!("SSH 隧道失败：{e}")),
        };
        let mut session = match self.stream(key, from).await {
            Ok(s) => s,
            Err(e) => return Outcome::failed(SessionCode::Refused, e.to_string()),
        };
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

#[cfg(test)]
mod tests {
    use super::{Outcome, Outcome as _O, parse_listen_addr, split_target};
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
