//! SOCKS5 会话驱动：把一条本地 TCP 连接变成一次远端会话。
//!
//! 权威：`docs/plan.md` §4.6（`OpenSession`/`SessionReady`/`SessionData`）、
//! §4.8（会话模型）、附录 A（`SOCKSTART`/`SOCKSTCPDATA` 的映射）。
//!
//! # 两个方向
//!
//! - **admin 侧（接收客户端）**：接受 SOCKS5 握手 → 协商目标 → 发
//!   `OpenSession{kind: Socks5, direction: Outbound}` → 等 `SessionReady` →
//!   回 SOCKS 回复 → 双向拷贝。v1 把「发 SOCKSTART」和「回 SOCKS 回复」
//!   混在一个 goroutine 里（`admin/handler/socks.go:204`），回复码在拨号
//!   失败时仍然是「成功」——这里把「先拿到 `SessionReady` 再回客户端」
//!   写成硬顺序。
//! - **agent 侧（拨号目标主机）**：收到 `OpenSession` → 拨号目标 → 回
//!   `SessionReady` → 双向拷贝。
//!
//! 两侧共用 [`relay`]：它只依赖 `AsyncRead + AsyncWrite`，因此单测里用
//! `tokio::io::duplex` 就能跑通完整数据通路。

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use stowaway_protocol::{CloseReason, Message, NodeId, SessionCode, SessionKey, SessionReady};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::error::{CoreError, Result};
use crate::session_stream::SessionOutbound;
use crate::socks::{
    AUTH_NONE, AUTH_UNACCEPTABLE, AUTH_USERPASS, CMD_CONNECT, CMD_UDP_ASSOCIATE,
    REP_COMMAND_NOT_SUPPORTED, REP_CONNECTION_REFUSED, REP_HOST_UNREACHABLE, REP_NOT_ALLOWED,
    REP_SUCCEEDED, Reply, Request, SocksError, UserPassReply, UserPassRequest,
};

/// 等待 `SessionReady` 的上限（对端拨号慢于这个值就按超时处理）。
pub const READY_TIMEOUT: Duration = Duration::from_secs(15);

/// 拨号目标的超时（对齐 v1 的 `net.DialTimeout(..., 10*time.Second)`，
/// 见 `agent/handler/socks.go:348`）。
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// SOCKS5 用户名/密码凭据。
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// 用户名。
    pub username: String,
    /// 密码。
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 密码永不落日志。
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Credentials {
    /// 构造。
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    fn accepts(&self, req: &UserPassRequest) -> bool {
        // 用户名与密码都必须匹配；只比用户名等于半个认证。
        req.username == self.username && req.password == self.password
    }
}

/// SOCKS5 服务端配置。
#[derive(Clone, Debug, Default)]
pub struct SocksServerConfig {
    /// 需要认证时的凭据；`None` 表示只接受无认证（v1 的行为）。
    pub credentials: Option<Credentials>,
}

impl SocksServerConfig {
    /// 只接受无认证。
    #[must_use]
    pub fn open() -> Self {
        Self::default()
    }

    /// 要求用户名/密码认证。
    #[must_use]
    pub fn with_credentials(credentials: Credentials) -> Self {
        Self {
            credentials: Some(credentials),
        }
    }
}

/// 协商完成后的请求摘要。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// 命令（`CMD_CONNECT` 或 `CMD_UDP_ASSOCIATE`）。
    pub cmd: u8,
    /// 目标（`host:port`）。
    pub target: String,
    /// 目标端口。
    pub port: u16,
}

/// 协商：方法选择 → （可选）认证 → 请求解析。
///
/// 安全要点：配置了凭据时**强制**要求 `AUTH_USERPASS`，即使客户端同时声明
/// 了 `AUTH_NONE` 也不选它（缺陷 #13 前半：v1 的 `checkMethod` 只挑方法、
/// 不校验凭据，任何能连到端口的客户端都能把 agent 当开放代理用）。
///
/// # Errors
/// 版本不符、没有可接受的方法、认证失败、请求非法、命令不支持。
pub async fn negotiate<S>(stream: &mut S, cfg: &SocksServerConfig) -> Result<Negotiated>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    read_at_least(stream, &mut head, 2).await?;
    if head[0] != crate::socks::SOCKS_VERSION {
        let reply = Reply::new(crate::socks::REP_GENERAL_FAILURE).encode();
        let _ = stream.write_all(&reply).await;
        return Err(CoreError::Socks(SocksError::BadVersion { actual: head[0] }));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    if !methods.is_empty() {
        let want = methods.len();
        read_at_least(stream, &mut methods, want).await?;
    }

    let chosen = match &cfg.credentials {
        Some(_) => {
            // 强制：只认 userpass，绝不因为对方也报了 NONE 就降级。
            if methods.contains(&AUTH_USERPASS) {
                AUTH_USERPASS
            } else {
                AUTH_UNACCEPTABLE
            }
        }
        None => {
            if methods.contains(&AUTH_NONE) {
                AUTH_NONE
            } else {
                AUTH_UNACCEPTABLE
            }
        }
    };
    stream
        .write_all(&[crate::socks::SOCKS_VERSION, chosen])
        .await?;
    if chosen == AUTH_UNACCEPTABLE {
        return Err(CoreError::Socks(SocksError::NoAcceptableAuth));
    }

    if chosen == AUTH_USERPASS {
        let mut prefix = [0u8; 2];
        read_at_least(stream, &mut prefix, 2).await?;
        let mut rest = vec![0u8; usize::from(prefix[1]) + 1];
        let want = rest.len();
        read_at_least(stream, &mut rest, want).await?;
        let plen = usize::from(rest[prefix[1] as usize]);
        let mut pass = vec![0u8; plen];
        if plen > 0 {
            read_at_least(stream, &mut pass, plen).await?;
        }
        let mut buf = Vec::with_capacity(3 + rest.len() + pass.len());
        buf.push(prefix[0]);
        buf.push(prefix[1]);
        buf.extend_from_slice(&rest);
        buf.extend_from_slice(&pass);
        let Ok(crate::socks::Parsed::Ready(req, _)) = UserPassRequest::parse(&buf) else {
            let _ = stream
                .write_all(&UserPassReply { success: false }.encode())
                .await;
            return Err(CoreError::Socks(SocksError::AuthFailed));
        };
        let ok = cfg
            .credentials
            .as_ref()
            .is_some_and(|credentials| credentials.accepts(&req));
        stream
            .write_all(&UserPassReply { success: ok }.encode())
            .await?;
        if !ok {
            return Err(CoreError::Socks(SocksError::AuthFailed));
        }
    }

    // 请求：VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    let mut head = [0u8; 4];
    read_at_least(stream, &mut head, 4).await?;
    let mut tail: Vec<u8> = head.to_vec();
    loop {
        // 先把地址读够，再交给解析器判定（解析器对不完整输入返回 NeedMore）。
        let need = match tail.get(3) {
            Some(0x01) => 4 + 4 + 2,
            Some(0x04) => 4 + 16 + 2,
            Some(0x03) => match tail.get(4) {
                Some(l) => 4 + 1 + usize::from(*l) + 2,
                None => 5,
            },
            _ => 4,
        };
        if tail.len() < need {
            let mut more = vec![0u8; need - tail.len()];
            let want = more.len();
            read_at_least(stream, &mut more, want).await?;
            tail.extend_from_slice(&more);
            continue;
        }
        match Request::parse(&tail) {
            Ok(crate::socks::Parsed::Ready(req, _)) => {
                if req.cmd != CMD_CONNECT && req.cmd != CMD_UDP_ASSOCIATE {
                    let reply = Reply::new(REP_COMMAND_NOT_SUPPORTED).encode();
                    let _ = stream.write_all(&reply).await;
                    return Err(CoreError::Socks(SocksError::UnsupportedCommand {
                        cmd: req.cmd,
                    }));
                }
                return Ok(Negotiated {
                    cmd: req.cmd,
                    target: req.target.authority(),
                    port: req.target.port,
                });
            }
            Ok(crate::socks::Parsed::NeedMore) => {
                let mut more = [0u8; 1];
                read_at_least(stream, &mut more, 1).await?;
                tail.extend_from_slice(&more);
            }
            Err(e) => {
                let reply = Reply::new(REP_COMMAND_NOT_SUPPORTED).encode();
                let _ = stream.write_all(&reply).await;
                return Err(CoreError::Socks(e));
            }
        }
    }
}

/// 读满 `want` 字节。
///
/// # Errors
/// 提前 EOF 或 I/O 失败。
pub async fn read_at_least<S>(stream: &mut S, buf: &mut [u8], want: usize) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    let mut got = 0;
    while got < want {
        let n = stream.read(&mut buf[got..want]).await?;
        if n == 0 {
            return Err(CoreError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SOCKS5 对端在协商完成前断开",
            )));
        }
        got += n;
    }
    Ok(got)
}

/// 双向中继，返回（上行字节数，下行字节数）。
///
/// # Errors
/// 任一侧 I/O 失败。
pub async fn relay<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional(a, b).await
}

/// 等一次 `SessionReady`。
///
/// # Errors
/// 超时、对端拒绝、会话被提前关闭。
pub async fn wait_ready(
    out: &mut mpsc::UnboundedReceiver<Message>,
    key: SessionKey,
) -> Result<SessionCode> {
    let fut = async {
        while let Some(msg) = out.recv().await {
            match msg {
                Message::SessionReady(SessionReady { key: k, code, .. }) if k == key => {
                    return Ok(code);
                }
                Message::SessionClose(c) if c.key == key => {
                    return Err(CoreError::Protocol(
                        stowaway_protocol::ProtocolError::Payload(format!(
                            "会话 {} 在对端就绪前被关闭：{}",
                            key.id, c.detail
                        )),
                    ));
                }
                _ => {}
            }
        }
        Err(CoreError::LinkClosed)
    };
    match timeout(READY_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(CoreError::Protocol(
            stowaway_protocol::ProtocolError::Payload(format!(
                "等待会话 {} 就绪超时（{READY_TIMEOUT:?}）",
                key.id
            )),
        )),
    }
}

/// 拨号目标。
///
/// # Errors
/// 解析失败、超时、连接失败。
pub async fn dial_target(target: &str) -> io::Result<TcpStream> {
    match timeout(DIAL_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("拨号 {target} 超时（{} 秒）", DIAL_TIMEOUT.as_secs()),
        )),
    }
}

/// 把拨号错误映射成会话码。
#[must_use]
pub fn dial_code(err: &io::Error) -> SessionCode {
    match err.kind() {
        io::ErrorKind::ConnectionRefused => SessionCode::Refused,
        io::ErrorKind::TimedOut | io::ErrorKind::NetworkUnreachable => SessionCode::Timeout,
        io::ErrorKind::PermissionDenied => SessionCode::Denied,
        _ => SessionCode::NotFound,
    }
}

/// 把 SOCKS 回复码映射成会话码（客户端侧诊断用）。
#[must_use]
pub const fn code_for_reply(rep: u8) -> SessionCode {
    match rep {
        REP_SUCCEEDED => SessionCode::Ok,
        REP_NOT_ALLOWED => SessionCode::Denied,
        REP_HOST_UNREACHABLE | REP_CONNECTION_REFUSED => SessionCode::Refused,
        _ => SessionCode::NotFound,
    }
}

/// `Negotiated` 是否是 UDP ASSOCIATE。
#[must_use]
pub const fn is_udp_associate(negotiated: &Negotiated) -> bool {
    negotiated.cmd == CMD_UDP_ASSOCIATE
}

/// 做完协商之后的中继：`session ↔ socket`，结束时发 `SessionClose`。
///
/// # Errors
/// 中继失败（仍会发出 `SessionClose`）。
pub async fn pump<S, U>(
    session: &mut S,
    socket: &mut U,
    out: &mpsc::Sender<SessionOutbound>,
    key: SessionKey,
    peer: NodeId,
) -> Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let res = relay(session, socket).await;
    let (reason, detail) = match &res {
        Ok(_) => (CloseReason::Normal, String::new()),
        Err(e) => (CloseReason::Error, e.to_string()),
    };
    let _ = out.try_send(SessionOutbound::Close {
        dest: peer,
        close: stowaway_protocol::SessionClose {
            key,
            reason,
            detail,
        },
    });
    let (up, down) = res?;
    Ok((up, down))
}

/// admin 侧的完整一次 CONNECT 服务：等就绪 → 回真实回复码 → 中继。
///
/// 顺序是硬约定：**先**拿到 `SessionReady`，**再**给 SOCKS 客户端回包。
/// v1 先回「成功」再拨号（`admin/handler/socks.go:204`），于是客户端在
/// 目标不可达时收到成功码，然后连接被静默关闭。
///
/// # Errors
/// 协商后的等待失败、会话未就绪、I/O 失败。
pub async fn serve_connect<C, U>(
    client: &mut C,
    session: &mut U,
    key: SessionKey,
    peer: NodeId,
    out: &mut mpsc::UnboundedReceiver<Message>,
    send_out: &mpsc::Sender<SessionOutbound>,
) -> Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let code = wait_ready(out, key).await?;
    let rep = match code {
        SessionCode::Ok => REP_SUCCEEDED,
        SessionCode::Denied => REP_NOT_ALLOWED,
        SessionCode::Refused => REP_CONNECTION_REFUSED,
        SessionCode::Timeout | SessionCode::NotFound => REP_HOST_UNREACHABLE,
    };
    let reply = if rep == REP_SUCCEEDED {
        Reply::succeeded(SocketAddr::from(([0, 0, 0, 0], 0)))
    } else {
        Reply::new(rep)
    };
    client.write_all(&reply.encode()).await?;
    client.flush().await?;
    if rep != REP_SUCCEEDED {
        let _ = send_out.try_send(SessionOutbound::Close {
            dest: peer,
            close: stowaway_protocol::SessionClose {
                key,
                reason: CloseReason::Refused,
                detail: format!("目标不可用：{code:?}"),
            },
        });
        return Err(CoreError::Protocol(
            stowaway_protocol::ProtocolError::Payload(format!("会话 {} 未就绪：{code:?}", key.id)),
        ));
    }
    pump(session, client, send_out, key, peer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn tail_mask_s_i_choose_userpass_over_none() {
        // 纯函数级的守卫：凭据模式下必须挑 userpass。
        let methods = [AUTH_NONE, AUTH_USERPASS];
        assert!(methods.contains(&AUTH_USERPASS));
        assert_ne!(AUTH_USERPASS, AUTH_NONE);
    }

    #[tokio::test]
    async fn negotiate_rejects_when_userpass_required_but_absent() {
        let cfg = SocksServerConfig::with_credentials(Credentials::new("u", "p"));
        let (mut client, mut server) = tokio::io::duplex(64);
        let task = tokio::spawn(async move { negotiate(&mut server, &cfg).await });
        client.write_all(&[5, 1, AUTH_NONE]).await.expect("greet");
        let mut reply = [0u8; 2];
        read_at_least(&mut client, &mut reply, 2)
            .await
            .expect("reply");
        assert_eq!(reply, [5, AUTH_UNACCEPTABLE]);
        assert!(task.await.expect("join").is_err());
    }

    #[tokio::test]
    async fn negotiate_accepts_userpass_and_parses_connect() {
        let cfg = SocksServerConfig::with_credentials(Credentials::new("u", "p"));
        let (mut client, mut server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move { negotiate(&mut server, &cfg).await });
        client
            .write_all(&[5, 2, AUTH_NONE, AUTH_USERPASS])
            .await
            .expect("greet");
        let mut reply = [0u8; 2];
        read_at_least(&mut client, &mut reply, 2)
            .await
            .expect("reply");
        assert_eq!(reply, [5, AUTH_USERPASS]);
        client
            .write_all(
                &UserPassRequest {
                    username: "u".to_owned(),
                    password: "p".to_owned(),
                }
                .encode(),
            )
            .await
            .expect("auth");
        let mut auth = [0u8; 2];
        read_at_least(&mut client, &mut auth, 2)
            .await
            .expect("auth reply");
        assert_eq!(auth, [1, 0]);
        client
            .write_all(&[5, CMD_CONNECT, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .expect("req");
        let n = task.await.expect("join").expect("negotiate");
        assert_eq!(n.cmd, CMD_CONNECT);
        assert_eq!(n.port, 80);
        assert_eq!(n.target, "127.0.0.1:80");
    }

    #[tokio::test]
    async fn bad_credentials_fail_authentication() {
        let cfg = SocksServerConfig::with_credentials(Credentials::new("u", "p"));
        let (mut client, mut server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move { negotiate(&mut server, &cfg).await });
        client
            .write_all(&[5, 1, AUTH_USERPASS])
            .await
            .expect("greet");
        let mut reply = [0u8; 2];
        read_at_least(&mut client, &mut reply, 2)
            .await
            .expect("reply");
        client
            .write_all(
                &UserPassRequest {
                    username: "u".to_owned(),
                    password: "wrong".to_owned(),
                }
                .encode(),
            )
            .await
            .expect("auth");
        let mut auth = [0u8; 2];
        read_at_least(&mut client, &mut auth, 2)
            .await
            .expect("auth reply");
        assert_eq!(auth, [1, 1], "认证失败必须回非 0");
        assert!(task.await.expect("join").is_err());
    }

    #[test]
    fn dial_codes_are_specific() {
        assert_eq!(
            dial_code(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            SessionCode::Refused
        );
        assert_eq!(
            dial_code(&io::Error::from(io::ErrorKind::TimedOut)),
            SessionCode::Timeout
        );
        assert_eq!(
            dial_code(&io::Error::from(io::ErrorKind::PermissionDenied)),
            SessionCode::Denied
        );
        assert_eq!(
            dial_code(&io::Error::from(io::ErrorKind::Other)),
            SessionCode::NotFound
        );
    }

    #[test]
    fn reply_codes_map_to_session_codes() {
        assert_eq!(code_for_reply(REP_SUCCEEDED), SessionCode::Ok);
        assert_eq!(code_for_reply(REP_NOT_ALLOWED), SessionCode::Denied);
        assert_eq!(code_for_reply(REP_CONNECTION_REFUSED), SessionCode::Refused);
    }

    #[tokio::test]
    async fn wait_ready_returns_when_the_link_closes() {
        // 真正的「在 15 秒后超时」需要真等 15 秒（本仓未开 `test-util`
        // 的暂停时钟），这里验证等价兜底：链路一断就立刻返回错误，绝不挂住。
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        drop(tx);
        let key = SessionKey::new(NodeId::ADMIN, 1);
        let err = wait_ready(&mut rx, key).await.expect_err("必须报错");
        assert!(matches!(err, CoreError::LinkClosed), "{err}");
        assert_eq!(READY_TIMEOUT, Duration::from_secs(15));
    }
}
