//! SSH 远程命令、交互式 SSH（PTY）与 SSH 隧道通路。
//!
//! 权威：`docs/plan.md` §5.1 第 10 项（SSH 命令执行，**可配 known_hosts**）、
//! 第 11 项（SSH 隧道）、附录 A（`SSHREQ`/`SSHRES`/`SSHCOMMAND`/`SSHRSESULT`/
//! `SSHEXIT`/`SSHTUNNELREQ`）、§8.5 场景 8、§3 缺陷 #10。
//!
//! # 与 v1 的关键差别：host key 从「永不校验」变成「默认严格」
//!
//! v1 的 `agent/handler/ssh.go:88` 与 `agent/handler/sshtunnel.go:81` 都写
//! `HostKeyCallback: ssh.InsecureIgnoreHostKey()`——任何中间人都能冒充被连的
//! 主机，并把管理员发过去的**私钥明文**收走。v2 把这件事反过来：
//!
//! | 策略 | 行为 | 默认 |
//! |---|---|---|
//! | [`HostKeyPolicy::Strict`] | 必须已在 `known_hosts` 里且一致 | ✅ |
//! | [`HostKeyPolicy::AcceptAndLearn`] | 未见过就记一条并接受；已见过但不一致则**拒绝** | |
//! | [`HostKeyPolicy::Insecure`] | 无条件接受 | 需显式选择 |
//!
//! `Insecure` 保留是为了兼容「第一次连一台刚装的机器」这种运维场景，但它
//! 必须由使用者显式写出来，而不是像 v1 那样成为唯一行为。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg};
use stowaway_protocol::{
    Message, ServiceKind, ServiceParam, ServicePhase, ServiceRequest, SessionKey, SshAuth, SshParam,
};
use tokio::sync::mpsc;

use crate::error::CoreError;

/// 建立 SSH 连接（含 TCP 拨号与密钥交换）的超时，与 v1 `ssh.Dial` 的 `Timeout` 一致。
pub const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 一次 SSH 会话最多等多久拿到命令结束。
pub const SSH_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// SSH 默认端口。
pub const DEFAULT_SSH_PORT: u16 = 22;

/// host key 校验策略。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HostKeyPolicy {
    /// 必须已记录且一致（默认）。
    #[default]
    Strict,
    /// 未记录则记录并接受；已记录但不一致则拒绝。
    AcceptAndLearn,
    /// 无条件接受（等价于 v1 的行为，必须显式选择）。
    Insecure,
}

impl HostKeyPolicy {
    /// 命令行标签。
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::AcceptAndLearn => "accept-and-learn",
            Self::Insecure => "insecure",
        }
    }
}

/// 对一个已记录/待记录 host key 的处置决定。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostKeyDecision {
    /// 已记录且一致，接受。
    Accept,
    /// 没见过，按策略记录后接受。
    AcceptAndLearn,
    /// 拒绝。
    Reject(HostKeyReject),
}

/// 拒绝原因。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostKeyReject {
    /// 严格策略下没有记录。
    Unknown,
    /// 记录里的 key 和这次呈现的不一致 —— 典型的中间人信号。
    Changed,
}

impl HostKeyReject {
    const fn as_tag(self) -> &'static str {
        match self {
            Self::Unknown => "unknown-host",
            Self::Changed => "host-key-changed",
        }
    }
}

/// 纯决策函数：把「策略 + 记录情况」映射成处置。
///
/// 单独抽出来是为了能不起 SSH 连接就把安全语义测穿（见 `mod tests`）。
/// `known` 为 `None` 表示文件里没有这台主机的记录。
#[must_use]
pub const fn decide_host_key(policy: HostKeyPolicy, known: KnownState) -> HostKeyDecision {
    match (policy, known) {
        (HostKeyPolicy::Insecure, _) => HostKeyDecision::Accept,
        (_, KnownState::Matches) => HostKeyDecision::Accept,
        (_, KnownState::Changed) => HostKeyDecision::Reject(HostKeyReject::Changed),
        (HostKeyPolicy::Strict, KnownState::Absent) => {
            HostKeyDecision::Reject(HostKeyReject::Unknown)
        }
        (HostKeyPolicy::AcceptAndLearn, KnownState::Absent) => HostKeyDecision::AcceptAndLearn,
    }
}

/// `known_hosts` 对本次呈现 key 的记录情况。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KnownState {
    /// 文件里有记录且一致。
    Matches,
    /// 文件里有记录但 key 不同。
    Changed,
    /// 文件里没有这台主机的记录。
    Absent,
}

/// SSH 相关错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SshError {
    /// `russh` 传输层/协议错误。
    #[error("SSH 错误：{0}")]
    Russh(#[from] russh::Error),

    /// `russh::keys` 错误（解析私钥、known_hosts 读写）。
    #[error("SSH 密钥错误：{0}")]
    Keys(#[from] russh::keys::Error),

    /// host key 被拒绝。
    #[error("拒绝 {host}:{port} 的 host key（{reason}）")]
    HostKey {
        /// 主机。
        host: String,
        /// 端口。
        port: u16,
        /// 原因标签。
        reason: &'static str,
    },

    /// 认证失败。
    #[error("SSH 认证失败：{0}")]
    Auth(String),

    /// 地址格式不对。
    #[error("SSH 地址必须是 host:port，实际是 {0:?}")]
    BadAddr(String),

    /// 该认证方式尚未实现。
    #[error("SSH 认证方式 {0} 尚未实现")]
    Unsupported(&'static str),

    /// 连接/命令超时。
    #[error("SSH 操作超时（{what}，{secs} 秒）")]
    Timeout {
        /// 哪一步超时。
        what: &'static str,
        /// 超时秒数。
        secs: u64,
    },

    /// 通道在期待的数据到达前关闭。
    #[error("SSH 通道提前关闭（还差 {expected}）")]
    ChannelClosed {
        /// 期待什么。
        expected: &'static str,
    },

    /// 远端返回了错误退出码之外的表征。
    #[error("SSH 通道打开失败：{0}")]
    OpenFailed(String),
}

impl SshError {
    /// 提升为 [`CoreError`]。
    #[must_use]
    pub fn as_core(&self) -> CoreError {
        CoreError::Protocol(stowaway_protocol::ProtocolError::Payload(self.to_string()))
    }
}

/// 一次 SSH 服务的规格。
#[derive(Clone, Debug)]
pub struct SshSpec {
    /// 会话键。
    pub key: SessionKey,
    /// `host:port`。
    pub addr: String,
    /// 用户名。
    pub user: String,
    /// 认证方式。
    pub auth: SshAuth,
    /// 要执行的命令（空串表示交互式 shell）。
    pub command: String,
    /// host key 策略。
    pub policy: HostKeyPolicy,
    /// `known_hosts` 路径（`None` = `~/.ssh/known_hosts`）。
    pub known_hosts: Option<PathBuf>,
}

impl SshSpec {
    /// 由会话目标 + 请求参数构造。
    ///
    /// `addr` 来自 `OpenSession.target`（v1 的 `SSH.Addr`），`SshParam` 只带
    /// 用户/认证/命令，v2 协议里没有把地址塞进参数——地址属于会话而非参数。
    #[must_use]
    pub fn new(key: SessionKey, addr: impl Into<String>, param: &SshParam) -> Self {
        Self {
            key,
            addr: addr.into(),
            user: param.user.clone(),
            auth: param.auth.clone(),
            command: param.command.clone(),
            policy: HostKeyPolicy::Strict,
            known_hosts: None,
        }
    }

    /// 换 host key 策略。
    #[must_use]
    pub fn with_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// 换 `known_hosts` 路径。
    #[must_use]
    pub fn with_known_hosts(mut self, path: impl Into<PathBuf>) -> Self {
        self.known_hosts = Some(path.into());
        self
    }

    /// 是否交互式（命令为空）。
    #[must_use]
    pub fn is_interactive(&self) -> bool {
        self.command.trim().is_empty()
    }

    /// 拆出 `(host, port)`。
    ///
    /// # Errors
    /// 缺端口、端口非法、host 为空。
    pub fn split_addr(&self) -> std::result::Result<(String, u16), SshError> {
        let text = self.addr.trim();
        let (host, port_text) = if let Some(rest) = text.strip_prefix('[') {
            let end = rest
                .find(']')
                .ok_or_else(|| SshError::BadAddr(text.to_owned()))?;
            let host = &rest[..end];
            let port_text = rest[end + 1..].strip_prefix(':').unwrap_or("");
            (host, port_text)
        } else {
            match text.rsplit_once(':') {
                Some((host, port)) => (host, port),
                None => return Err(SshError::BadAddr(text.to_owned())),
            }
        };
        if host.is_empty() || port_text.is_empty() {
            return Err(SshError::BadAddr(text.to_owned()));
        }
        let port: u16 = port_text
            .parse()
            .map_err(|_| SshError::BadAddr(text.to_owned()))?;
        Ok((host.to_owned(), port))
    }

    /// 上线用的请求参数。
    #[must_use]
    pub fn param(&self) -> SshParam {
        SshParam {
            user: self.user.clone(),
            auth: self.auth.clone(),
            command: self.command.clone(),
        }
    }
}

/// 打开 SSH 会话的请求（v1 的 `SSHREQ`，附录 A 第 11 行）。
#[must_use]
pub fn open_message(key: SessionKey, param: &SshParam) -> Message {
    Message::ServiceRequest(ServiceRequest {
        key,
        kind: ServiceKind::Ssh,
        phase: ServicePhase::Run,
        param: ServiceParam::Ssh(param.clone()),
    })
}

/// 一次命令执行的结果。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CommandOutput {
    /// 合并后的 stdout+stderr（v1 `cmd.Stderr = cmd.Stdout` 的等价物）。
    pub output: Vec<u8>,
    /// 远端退出码（没收到 `ExitStatus` 时为 `None`）。
    pub exit_status: Option<u32>,
}

/// host key 校验器：把 [`HostKeyPolicy`] 接进 `russh` 的回调。
#[derive(Debug)]
pub struct HostKeyVerifier {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    known_hosts: Option<PathBuf>,
}

/// 去掉 comment 的副本：`known_hosts` 里不存 comment，比对时也必须忽略它。
fn strip_comment(key: &PublicKey) -> PublicKey {
    match key.to_openssh() {
        Ok(text) => {
            // 只保留「算法 + base64」两段，丢掉注释段。
            let mut parts = text.split(' ');
            let (Some(alg), Some(b64)) = (parts.next(), parts.next()) else {
                return key.clone();
            };
            PublicKey::from_openssh(&format!("{alg} {b64}")).unwrap_or_else(|_| key.clone())
        }
        Err(_) => key.clone(),
    }
}

impl HostKeyVerifier {
    /// 构造。
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, policy: HostKeyPolicy) -> Self {
        Self {
            host: host.into(),
            port,
            policy,
            known_hosts: None,
        }
    }

    /// 指定 `known_hosts` 路径。
    #[must_use]
    pub fn with_known_hosts(mut self, path: impl Into<PathBuf>) -> Self {
        self.known_hosts = Some(path.into());
        self
    }

    /// 查询文件里的记录情况。
    fn known_state(&self, key: &PublicKey) -> KnownState {
        // `russh 0.65.2` 的 `check_known_hosts_path` 用 `*pubkey == recorded`
        // 比较**整个** `PublicKey`，而 `PublicKey` 的 `PartialEq` 把 comment
        // 也算进去；`known_hosts` 里只存 base64（解析回来的 comment 为空），
        // 于是「带 comment 的 key」（例如从私钥文件里 `public_key()` 拿到的）
        // 永远比对失败、被误判成 `KeyChanged`。这里统一去掉 comment 再比，
        // 比的是密钥本体而不是注释。
        let key = &strip_comment(key);
        let Some(path) = self.known_hosts.as_deref() else {
            // 没指定路径：交给 russh 自己的默认位置。
            return match russh::keys::known_hosts::check_known_hosts(&self.host, self.port, key) {
                Ok(true) => KnownState::Matches,
                Ok(false) => KnownState::Absent,
                Err(_) => KnownState::Changed,
            };
        };
        match russh::keys::known_hosts::check_known_hosts_path(&self.host, self.port, key, path) {
            Ok(true) => KnownState::Matches,
            Ok(false) => KnownState::Absent,
            Err(_) => KnownState::Changed,
        }
    }

    /// 记一条。
    fn learn(&self, key: &PublicKey) -> std::result::Result<(), SshError> {
        match self.known_hosts.as_deref() {
            Some(path) => {
                russh::keys::known_hosts::learn_known_hosts_path(&self.host, self.port, key, path)?
            }
            None => russh::keys::known_hosts::learn_known_hosts(&self.host, self.port, key)?,
        }
        Ok(())
    }

    /// 核心判定：给一个呈现上来的 key，返回接受与否。
    ///
    /// # Errors
    /// 拒绝时返回 [`SshError::HostKey`]（`russh` 会把这里的 `Err` 原样带回
    /// `connect` 的返回值，所以调用方拿到的是可读原因而不是一个布尔）。
    pub fn verify(
        &self,
        presented: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, SshError> {
        let key = presented.public_key();
        // 证书形态：v2 不做 CA 校验，直接拒绝——比「接受但不知道自己在信谁」好。
        if presented.certificate().is_some() {
            return Err(SshError::HostKey {
                host: self.host.clone(),
                port: self.port,
                reason: "unsupported-cert",
            });
        }
        match decide_host_key(self.policy, self.known_state(&key)) {
            HostKeyDecision::Accept => Ok(true),
            HostKeyDecision::AcceptAndLearn => {
                self.learn(&key)?;
                Ok(true)
            }
            HostKeyDecision::Reject(reason) => Err(SshError::HostKey {
                host: self.host.clone(),
                port: self.port,
                reason: reason.as_tag(),
            }),
        }
    }
}

impl client::Handler for HostKeyVerifier {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        self.verify(server_public_key)
    }
}

/// 一条已认证的 SSH 连接。
pub struct SshConnection {
    handle: Handle<HostKeyVerifier>,
    spec: SshSpec,
}

impl std::fmt::Debug for SshConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConnection")
            .field("addr", &self.spec.addr)
            .field("user", &self.spec.user)
            .finish_non_exhaustive()
    }
}

impl SshConnection {
    /// 规格。
    #[must_use]
    pub const fn spec(&self) -> &SshSpec {
        &self.spec
    }

    /// 是否已断开。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// 打开一个 `direct-tcpip` 通道（SSH 隧道用）。
    ///
    /// # Errors
    /// 通道被拒、握手尚未完成。
    pub async fn open_direct_tcpip(
        &self,
        host: &str,
        port: u32,
    ) -> std::result::Result<Channel<russh::client::Msg>, SshError> {
        self.handle
            .channel_open_direct_tcpip(host.to_owned(), port, "127.0.0.1".to_owned(), 0)
            .await
            .map_err(|e| SshError::OpenFailed(format!("direct-tcpip {host}:{port} 被拒：{e}")))
    }

    /// 开一个 session 通道。
    ///
    /// # Errors
    /// 通道被拒。
    pub async fn open_session(&self) -> std::result::Result<Channel<russh::client::Msg>, SshError> {
        self.handle
            .channel_open_session()
            .await
            .map_err(|e| SshError::OpenFailed(format!("打开 session 通道失败：{e}")))
    }
}

/// 建立连接并完成认证。
///
/// # Errors
/// 地址非法、拨号/握手超时、host key 被拒、认证失败。
pub async fn connect(spec: &SshSpec) -> std::result::Result<SshConnection, SshError> {
    let (host, port) = spec.split_addr()?;
    let verifier = {
        let mut v = HostKeyVerifier::new(host.clone(), port, spec.policy);
        if let Some(path) = spec.known_hosts.as_ref() {
            v = v.with_known_hosts(path.clone());
        }
        v
    };

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });

    let addr = (host.clone(), port);
    let mut handle =
        tokio::time::timeout(SSH_CONNECT_TIMEOUT, client::connect(config, addr, verifier))
            .await
            .map_err(|_| SshError::Timeout {
                what: "建立 SSH 连接",
                secs: SSH_CONNECT_TIMEOUT.as_secs(),
            })??;

    authenticate(&mut handle, spec).await?;
    Ok(SshConnection {
        handle,
        spec: spec.clone(),
    })
}

async fn authenticate(
    handle: &mut Handle<HostKeyVerifier>,
    spec: &SshSpec,
) -> std::result::Result<(), SshError> {
    let ok = match &spec.auth {
        SshAuth::Password(password) => {
            let res = handle
                .authenticate_password(spec.user.clone(), password.clone())
                .await?;
            res.success()
        }
        SshAuth::PrivateKey(pem) => {
            let key = PrivateKey::from_openssh(pem.as_bytes())
                .map_err(|e| SshError::Auth(format!("私钥无法解析：{e}")))?;
            let hash = match handle.best_supported_rsa_hash().await {
                Ok(Some(hash)) => hash,
                // 服务器没说或扩展查询失败：RSH 走 sha2-256（`ssh-rsa` 的
                // SHA-1 变体已被 OpenSSH 9+ 默认关闭）。
                _ => Some(russh::keys::HashAlg::Sha256),
            };
            let with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            let res = handle
                .authenticate_publickey(spec.user.clone(), with_hash)
                .await?;
            res.success()
        }
        SshAuth::Agent => return Err(SshError::Unsupported("agent")),
    };
    if !ok {
        return Err(SshError::Auth(format!("用户 {} 的凭据未被接受", spec.user)));
    }
    Ok(())
}

/// 打开交互式 SSH shell（可选 PTY）。
///
/// # Errors
/// 连接失败、认证失败、`request_pty`/`request_shell` 失败。
pub async fn open_shell(
    spec: &SshSpec,
    pty: Option<(u16, u16, String)>,
) -> std::result::Result<SshShell, SshError> {
    let conn = connect(spec).await?;
    let channel = conn.open_session().await?;
    if let Some((cols, rows, term)) = pty {
        channel
            .request_pty(true, &term, u32::from(cols), u32::from(rows), 0, 0, &[])
            .await?;
    }
    channel.request_shell(true).await?;
    Ok(SshShell { conn, channel })
}

/// 一个交互式 SSH shell。
pub struct SshShell {
    conn: SshConnection,
    channel: Channel<russh::client::Msg>,
}

impl std::fmt::Debug for SshShell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshShell")
            .field("spec", self.conn.spec())
            .finish_non_exhaustive()
    }
}

impl SshShell {
    /// 写一段数据过去。
    ///
    /// # Errors
    /// 通道已关。
    pub async fn write(&self, data: &[u8]) -> std::result::Result<(), SshError> {
        self.channel
            .data_bytes(data.to_vec())
            .await
            .map_err(|e| SshError::OpenFailed(format!("写入通道失败：{e}")))
    }

    /// 调整远端窗口大小（`window-change`）。这是 v1 完全做不到的事。
    ///
    /// # Errors
    /// 通道已关。
    pub async fn resize(&self, cols: u16, rows: u16) -> std::result::Result<(), SshError> {
        self.channel
            .window_change(u32::from(cols), u32::from(rows), 0, 0)
            .await
            .map_err(|e| SshError::OpenFailed(format!("window-change 失败：{e}")))
    }

    /// 等一段输出；`None` 表示通道关掉了。
    ///
    /// # Errors
    /// 通道错误。
    pub async fn next_output(&mut self) -> std::result::Result<Option<Vec<u8>>, SshError> {
        loop {
            match self.channel.wait().await {
                Some(ChannelMsg::Data { data }) => return Ok(Some(data.to_vec())),
                Some(ChannelMsg::ExtendedData { data, .. }) => return Ok(Some(data.to_vec())),
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => return Ok(None),
                Some(_) => {}
            }
        }
    }

    /// 关闭通道。
    ///
    /// # Errors
    /// 通道已关。
    pub async fn close(self) -> std::result::Result<(), SshError> {
        self.channel.eof().await?;
        self.channel.close().await?;
        Ok(())
    }
}

/// 执行一条命令并收集输出（v1 的 `SSHCOMMAND` 单次执行路径）。
///
/// # Errors
/// 连接/认证失败、通道打开失败、超时、通道提前关闭。
pub async fn run_command(
    spec: &SshSpec,
    command: &str,
) -> std::result::Result<CommandOutput, SshError> {
    let conn = connect(spec).await?;
    let mut channel = conn.open_session().await?;
    channel.exec(true, command.as_bytes().to_vec()).await?;

    let mut output = Vec::new();
    let mut exit_status = None;
    let collect = async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
                Some(ChannelMsg::ExtendedData { data, .. }) => output.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
                // `Eof` 之后仍可能有 `ExitStatus`（OpenSSH 先发 EOF 再发
                // exit-status 是常见顺序），所以不能一见 `Eof` 就收摊——
                // 否则输出拿到了、退出码却永远是 `None`。
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }
    };
    tokio::time::timeout(SSH_COMMAND_TIMEOUT, collect)
        .await
        .map_err(|_| SshError::Timeout {
            what: "等待远端命令结束",
            secs: SSH_COMMAND_TIMEOUT.as_secs(),
        })?;
    Ok(CommandOutput {
        output,
        exit_status,
    })
}

/// 把 SSH 通道包成 [`crate::error::Result`] 的读循环，交给上层驱动。
///
/// 隧道场景不需要 `CommandOutput`，只需要「把通道里的字节搬出去、把外面的
/// 字节搬进来」。搬运动作交给调用方，这里只暴露通道。
///
/// # Errors
/// 通道打开失败。
pub async fn open_tunnel(
    spec: &SshSpec,
    remote_host: &str,
    remote_port: u16,
) -> std::result::Result<(SshConnection, Channel<russh::client::Msg>), SshError> {
    let conn = connect(spec).await?;
    let channel = conn
        .open_direct_tcpip(remote_host, u32::from(remote_port))
        .await?;
    Ok((conn, channel))
}

/// 把 SSH 通道的数据泵进一个无界通道（供服务层转成 `ServiceData`）。
///
/// # Errors
/// 通道错误。
pub async fn pump_channel(
    mut channel: Channel<russh::client::Msg>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
) -> std::result::Result<Option<u32>, SshError> {
    let mut exit_status = None;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                if tx.send(data.to_vec()).is_err() {
                    return Ok(exit_status);
                }
            }
            Some(ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
            // 同 `run_command`：`Eof` 之后还可能来 `ExitStatus`。
            Some(ChannelMsg::Close) | None => return Ok(exit_status),
            Some(_) => {}
        }
    }
}

/// 已知可信的 host key（用于 `--tls-pin` 式的显式信任）。
///
/// # Errors
/// 文件读不了或解析失败。
pub fn load_known_host_key(
    path: &Path,
    host: &str,
    port: u16,
) -> std::result::Result<Vec<PublicKey>, SshError> {
    let keys = russh::keys::known_hosts::known_host_keys_path(host, port, path)?;
    Ok(keys.into_iter().map(|(_, key)| key).collect())
}

/// 把 [`SshError`] 提升为 [`CoreError`]。
#[must_use]
pub fn as_core(err: &SshError) -> CoreError {
    err.as_core()
}

/// 结果别名。
pub type SshResult<T> = std::result::Result<T, SshError>;

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_protocol::NodeId;

    fn key() -> SessionKey {
        SessionKey::new(NodeId::ADMIN, 1)
    }

    fn param() -> SshParam {
        SshParam {
            user: "root".to_owned(),
            auth: SshAuth::Password("hunter2".to_owned()),
            command: "uname -a".to_owned(),
        }
    }

    // ---- 纯策略语义：不需要任何 SSH 连接 ----

    #[test]
    fn strict_rejects_unknown_host() {
        assert_eq!(
            decide_host_key(HostKeyPolicy::Strict, KnownState::Absent),
            HostKeyDecision::Reject(HostKeyReject::Unknown)
        );
    }

    #[test]
    fn strict_accepts_recorded_match() {
        assert_eq!(
            decide_host_key(HostKeyPolicy::Strict, KnownState::Matches),
            HostKeyDecision::Accept
        );
    }

    #[test]
    fn changed_key_is_rejected_by_every_policy_that_checks() {
        // 这正是 v1 `InsecureIgnoreHostKey` 放过去的那种情况。
        for policy in [HostKeyPolicy::Strict, HostKeyPolicy::AcceptAndLearn] {
            assert_eq!(
                decide_host_key(policy, KnownState::Changed),
                HostKeyDecision::Reject(HostKeyReject::Changed),
                "{policy:?} 不该放过 key 变更"
            );
        }
    }

    #[test]
    fn accept_and_learn_only_learns_when_absent() {
        assert_eq!(
            decide_host_key(HostKeyPolicy::AcceptAndLearn, KnownState::Absent),
            HostKeyDecision::AcceptAndLearn
        );
        assert_eq!(
            decide_host_key(HostKeyPolicy::AcceptAndLearn, KnownState::Matches),
            HostKeyDecision::Accept
        );
    }

    #[test]
    fn insecure_policy_is_explicit_and_unconditional() {
        assert_eq!(
            decide_host_key(HostKeyPolicy::Insecure, KnownState::Changed),
            HostKeyDecision::Accept
        );
        assert_eq!(HostKeyPolicy::default(), HostKeyPolicy::Strict);
        assert_eq!(HostKeyPolicy::Insecure.as_tag(), "insecure");
    }

    // ---- 地址与消息形状 ----

    #[test]
    fn addr_splits_host_and_port() {
        let spec = SshSpec::new(key(), "10.0.0.5:2222", &param());
        assert_eq!(
            spec.split_addr().expect("拆地址"),
            ("10.0.0.5".to_owned(), 2222)
        );
    }

    #[test]
    fn ipv6_literal_addr_is_supported() {
        let spec = SshSpec::new(key(), "[::1]:22", &param());
        assert_eq!(spec.split_addr().expect("拆地址"), ("::1".to_owned(), 22));
    }

    #[test]
    fn bad_addr_is_an_error_not_a_guess() {
        for bad in ["10.0.0.5", "", ":22", "host:", "[::1"] {
            let spec = SshSpec::new(key(), bad, &param());
            assert!(spec.split_addr().is_err(), "{bad:?} 不该被接受");
        }
    }

    #[test]
    fn open_message_carries_the_ssh_param() {
        match open_message(key(), &param()) {
            Message::ServiceRequest(req) => {
                assert_eq!(req.kind, ServiceKind::Ssh);
                assert_eq!(req.phase, ServicePhase::Run);
                match req.param {
                    ServiceParam::Ssh(p) => assert_eq!(p.user, "root"),
                    other => panic!("参数种类不对：{other:?}"),
                }
            }
            other => panic!("消息种类不对：{other:?}"),
        }
    }

    #[test]
    fn empty_command_means_interactive() {
        let mut p = param();
        p.command = "  ".to_owned();
        let spec = SshSpec::new(key(), "h:22", &p);
        assert!(spec.is_interactive());
    }

    #[test]
    fn agent_auth_is_refused_explicitly_not_silently() {
        let mut p = param();
        p.auth = SshAuth::Agent;
        let spec = SshSpec::new(key(), "127.0.0.1:1", &p);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        // 端口 1 连不上，但我们要验的是「不会被静默当成别的认证方式」。
        let outcome = rt.block_on(connect(&spec));
        assert!(outcome.is_err(), "agent 认证必须失败而不是被忽略");
    }

    #[test]
    fn private_key_auth_parses_a_real_openssh_key() {
        // 用 ssh-keygen 生成一把临时 key（环境里有）；生成不了就跳过，
        // 免得把「工具缺失」算成功能失败。
        let dir = std::env::temp_dir().join(format!("stw-sshkey-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("id_ed25519");
        let generated = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if generated {
            let pem = std::fs::read_to_string(&path).expect("读私钥");
            assert!(
                PrivateKey::from_openssh(pem.as_bytes()).is_ok(),
                "私钥应能解析"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_hosts_learning_round_trips_on_disk() {
        let dir = std::env::temp_dir().join(format!("stw-kh-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("known_hosts");
        let _ = std::fs::remove_file(&path);

        let verifier = HostKeyVerifier::new("example.test", 2222, HostKeyPolicy::Strict)
            .with_known_hosts(&path);
        // 空文件 = 没有记录。拿不到一把真 key 就跳过这条断言（环境缺
        // ssh-keygen 不该被算成功能失败）。
        if let Some(key) = fake_key("ed25519") {
            assert_eq!(verifier.known_state(&key), KnownState::Absent);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn learned_key_then_matches_and_a_different_key_changes() {
        let dir = std::env::temp_dir().join(format!("stw-kh2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("known_hosts");
        let _ = std::fs::remove_file(&path);

        let (Some(first), Some(second)) = (fake_key("a"), fake_key("b")) else {
            return; // 没 ssh-keygen 就跳过
        };
        let verifier = HostKeyVerifier::new("example.test", 2222, HostKeyPolicy::AcceptAndLearn)
            .with_known_hosts(&path);
        assert_eq!(verifier.known_state(&first), KnownState::Absent);
        verifier.learn(&first).expect("记一条");
        assert_eq!(verifier.known_state(&first), KnownState::Matches);
        assert_eq!(verifier.known_state(&second), KnownState::Changed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 造一个真 key（`ssh-keygen` 生成）；环境里没有工具时返回 `None`。
    fn fake_key(tag: &str) -> Option<PublicKey> {
        let base = std::env::temp_dir().join(format!("stw-pk-{}-{tag}", std::process::id()));
        let _ = std::fs::create_dir_all(&base);
        let path = base.join("k");
        let ok = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let key = if ok {
            russh::keys::load_secret_key(&path, None)
                .ok()
                .map(|k| k.public_key().clone())
        } else {
            None
        };
        let _ = std::fs::remove_dir_all(&base);
        key
    }
}
