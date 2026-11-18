//! 经上游代理拨号（修缺陷 #12）。
//!
//! 权威：`docs/plan.md` §3 缺陷表 #12、§5.1 第 12 项（`-socks5-proxy` /
//! `-http-proxy` 必须保留）。
//!
//! # 修的缺陷 #12
//!
//! v1 的 `share/proxy.go` 有两处问题：
//!
//! 1. **负索引 panic**：HTTP 代理回包判定写成 `resultBuf[begin-4:begin]`
//!    （`share/proxy.go:205`），代理若在 `\r\n\r\n` 出现前就断开
//!    （`begin < 4`），切片下界为负即 panic，整进程崩溃。
//! 2. **不发认证**：CONNECT 请求从不带 `Proxy-Authorization`
//!    （用户给了 `-http-proxyu/-http-proxyp` 也无效）。
//!
//! v2 的做法：先比长度再切片（永不出现负下界），认证头按 RFC 7617 正确
//! 编码。

use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{CoreError, Result};
use crate::socks::{
    AUTH_NONE, AUTH_UNACCEPTABLE, AUTH_USERPASS, CMD_CONNECT, Parsed, REP_SUCCEEDED, Reply,
    Request, SOCKS_VERSION, Target, TargetAddr, UserPassReply, UserPassRequest,
};

/// 连接上游代理的超时。
pub const PROXY_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// 上游 HTTP 代理回包的最长等待字节数（防止对端无限吐数据）。
pub const MAX_PROXY_RESPONSE: usize = 40 * 960;

/// HTTP 响应头的结束标记。
pub const HEADER_END: &[u8] = b"\r\n\r\n";

/// 上游代理规格。
#[derive(Clone, PartialEq, Eq)]
pub enum ProxySpec {
    /// SOCKS5 上游。
    Socks5 {
        /// 代理地址 `host:port`。
        addr: String,
        /// 用户名（可为空）。
        username: String,
        /// 密码（可为空）。
        password: String,
    },
    /// HTTP CONNECT 上游。
    Http {
        /// 代理地址 `host:port`。
        addr: String,
        /// 用户名（可为空）。
        username: String,
        /// 密码（可为空）。
        password: String,
    },
}

impl std::fmt::Debug for ProxySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 密码永不落日志。
        match self {
            Self::Socks5 { addr, username, .. } => f
                .debug_struct("ProxySpec::Socks5")
                .field("addr", addr)
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Http { addr, username, .. } => f
                .debug_struct("ProxySpec::Http")
                .field("addr", addr)
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

impl ProxySpec {
    /// SOCKS5 上游。
    #[must_use]
    pub fn socks5(
        addr: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::Socks5 {
            addr: addr.into(),
            username: username.into(),
            password: password.into(),
        }
    }

    /// HTTP 上游。
    #[must_use]
    pub fn http(
        addr: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::Http {
            addr: addr.into(),
            username: username.into(),
            password: password.into(),
        }
    }

    /// 代理自身的地址。
    #[must_use]
    pub fn addr(&self) -> &str {
        match self {
            Self::Socks5 { addr, .. } | Self::Http { addr, .. } => addr,
        }
    }

    /// 是否配置了凭据。
    #[must_use]
    pub fn has_credentials(&self) -> bool {
        match self {
            Self::Socks5 {
                username, password, ..
            }
            | Self::Http {
                username, password, ..
            } => !username.is_empty() || !password.is_empty(),
        }
    }

    fn credentials(&self) -> (&str, &str) {
        match self {
            Self::Socks5 {
                username, password, ..
            }
            | Self::Http {
                username, password, ..
            } => (username, password),
        }
    }
}

impl std::fmt::Display for ProxySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socks5 { addr, .. } => write!(f, "socks5://{addr}"),
            Self::Http { addr, .. } => write!(f, "http://{addr}"),
        }
    }
}

/// 经上游代理连到 `target`。
///
/// # Errors
/// 代理地址不可达、超时、代理拒绝、协议回包非法。
pub async fn dial_via_proxy(spec: &ProxySpec, target: &str) -> Result<TcpStream> {
    let (host, port) = split_host_port(target)?;
    let stream = match timeout(PROXY_DIAL_TIMEOUT, TcpStream::connect(spec.addr())).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(CoreError::Io(e)),
        Err(_) => {
            return Err(CoreError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "连接上游代理 {} 超时（{} 秒）",
                    spec.addr(),
                    PROXY_DIAL_TIMEOUT.as_secs()
                ),
            )));
        }
    };
    let _ = stream.set_nodelay(true);
    let (username, password) = spec.credentials();
    match spec {
        ProxySpec::Socks5 { .. } => socks5_connect(stream, &host, port, username, password).await,
        ProxySpec::Http { .. } => http_connect(stream, &host, port, username, password).await,
    }
}

/// 拆分 `host:port`（支持 `[::1]:80`）。
fn split_host_port(target: &str) -> Result<(String, u16)> {
    let invalid = || {
        CoreError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("目标地址必须形如 host:port，实际是 {target:?}"),
        ))
    };
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(invalid)?;
        let port = tail.strip_prefix(':').ok_or_else(invalid)?;
        (host.to_owned(), port)
    } else {
        let (host, port) = target.rsplit_once(':').ok_or_else(invalid)?;
        (host.to_owned(), port)
    };
    if host.is_empty() {
        return Err(invalid());
    }
    let port: u16 = port.parse().map_err(|_| invalid())?;
    if port == 0 {
        return Err(invalid());
    }
    Ok((host, port))
}

async fn socks5_connect(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<TcpStream> {
    let has_creds = !username.is_empty() || !password.is_empty();
    let greeting: &[u8] = if has_creds {
        &[SOCKS_VERSION, 2, AUTH_NONE, AUTH_USERPASS]
    } else {
        &[SOCKS_VERSION, 1, AUTH_NONE]
    };
    stream.write_all(greeting).await?;

    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method[0] != SOCKS_VERSION {
        return Err(protocol_error(format!(
            "上游 SOCKS5 代理版本错误：{}",
            method[0]
        )));
    }
    if method[1] == AUTH_UNACCEPTABLE {
        return Err(protocol_error("上游 SOCKS5 代理没有可接受的方法"));
    }
    if method[1] == AUTH_USERPASS {
        if !has_creds {
            return Err(protocol_error(
                "上游 SOCKS5 代理要求用户名/密码认证，但未配置凭据",
            ));
        }
        stream
            .write_all(
                &UserPassRequest {
                    username: username.to_owned(),
                    password: password.to_owned(),
                }
                .encode(),
            )
            .await?;
        let mut auth = [0u8; 2];
        stream.read_exact(&mut auth).await?;
        match UserPassReply::parse(&auth)? {
            reply if !reply.success => {
                return Err(protocol_error("上游 SOCKS5 代理认证失败"));
            }
            _ => {}
        }
    } else if method[1] != AUTH_NONE {
        return Err(protocol_error(format!(
            "上游 SOCKS5 代理选择了未预期的方法：{}",
            method[1]
        )));
    }

    let request = Request {
        cmd: CMD_CONNECT,
        target: Target {
            addr: if let Ok(ip) = host.parse() {
                TargetAddr::Ip(ip)
            } else {
                TargetAddr::Domain(host.to_owned())
            },
            port,
        },
    };
    stream.write_all(&request.encode()).await?;

    // 增量读回包：只有解析器说「够了」才继续；上限 300 字节。
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    loop {
        match Reply::parse(&buf)? {
            Parsed::Ready(reply, _) => {
                if reply.rep != REP_SUCCEEDED {
                    return Err(protocol_error(format!(
                        "上游 SOCKS5 代理拒绝 CONNECT：回复码 {:#04x}",
                        reply.rep
                    )));
                }
                return Ok(stream);
            }
            Parsed::NeedMore => {
                if buf.len() >= 300 {
                    return Err(protocol_error("上游 SOCKS5 回包超过 300 字节仍未结束"));
                }
                let mut chunk = [0u8; 64];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Err(protocol_error("上游 SOCKS5 代理在回复前断开"));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

async fn http_connect(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<TcpStream> {
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if !username.is_empty() || !password.is_empty() {
        let token = base64(format!("{username}:{password}").as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("Proxy-Connection: Keep-Alive\r\nContent-Length: 0\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(protocol_error("上游 HTTP 代理在响应头结束前断开"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_PROXY_RESPONSE {
            return Err(protocol_error(format!(
                "上游 HTTP 代理回包超过 {} KiB",
                MAX_PROXY_RESPONSE / 1024
            )));
        }
        // 缺陷 #12 的正面修法：**先比长度，再判结尾**，绝不做 begin-4 切片。
        if buf.len() >= HEADER_END.len() && buf.ends_with(HEADER_END) {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let first = text.lines().next().unwrap_or_default();
    let status = first
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());
    match status {
        Some(200) => Ok(stream),
        Some(code) => Err(protocol_error(format!(
            "上游 HTTP 代理拒绝 CONNECT：{first}（状态码 {code}）"
        ))),
        None => Err(protocol_error(format!(
            "上游 HTTP 代理响应行无法解析：{first}"
        ))),
    }
}

fn protocol_error(msg: impl Into<String>) -> CoreError {
    CoreError::Io(io::Error::other(msg.into()))
}

/// RFC 4648 标准 alphabet 的 Base64（不引入新依赖）。
#[must_use]
pub fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"alice:s3cret"), "YWxpY2U6czNjcmV0");
    }

    #[test]
    fn split_host_port_handles_ipv6_and_bad_input() {
        assert_eq!(
            split_host_port("example.com:8080").expect("ok"),
            ("example.com".to_owned(), 8080)
        );
        assert_eq!(
            split_host_port("[::1]:443").expect("ok"),
            ("::1".to_owned(), 443)
        );
        assert!(split_host_port("example.com").is_err());
        assert!(split_host_port("example.com:0").is_err());
        assert!(split_host_port(":80").is_err());
    }

    #[test]
    fn proxy_spec_reports_credentials() {
        assert!(!ProxySpec::socks5("127.0.0.1:1080", "", "").has_credentials());
        assert!(ProxySpec::socks5("127.0.0.1:1080", "u", "").has_credentials());
        assert_eq!(
            ProxySpec::http("127.0.0.1:8080", "u", "p").to_string(),
            "http://127.0.0.1:8080"
        );
        // 凭据不落日志。
        let dbg = format!("{:?}", ProxySpec::http("127.0.0.1:8080", "alice", "s3cret"));
        assert!(!dbg.contains("s3cret"), "{dbg}");
    }

    /// 缺陷 #12（上半）：代理只回 2 字节就断开，v1 会切 `[-2:0]` panic。
    #[tokio::test]
    async fn defect_12_short_http_response_never_panics() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(b"HT").await;
            drop(s);
        });
        let err = dial_via_proxy(&ProxySpec::http(addr.to_string(), "", ""), "example.com:80")
            .await
            .expect_err("短响应必须是错误");
        assert!(err.to_string().contains("断开"), "{err}");
    }

    /// 缺陷 #12（下半）：CONNECT 必须带 `Proxy-Authorization`。
    #[tokio::test]
    async fn defect_12_http_connect_sends_proxy_authorization() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.expect("read");
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = tx.send(text);
            let _ = s
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let spec = ProxySpec::http(addr.to_string(), "alice", "s3cret");
        let stream = dial_via_proxy(&spec, "example.com:80").await.expect("ok");
        drop(stream);
        let request = rx.recv().await.expect("request");
        assert!(
            request.contains("Proxy-Authorization: Basic YWxpY2U6czNjcmV0"),
            "CONNECT 必须带认证头：{request}"
        );
        assert!(
            request.starts_with("CONNECT example.com:80 HTTP/1.1"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn http_proxy_rejects_with_status_code() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await;
        });
        let err = dial_via_proxy(&ProxySpec::http(addr.to_string(), "", ""), "example.com:80")
            .await
            .expect_err("407 必须失败");
        assert!(err.to_string().contains("407"), "{err}");
    }

    #[tokio::test]
    async fn socks5_proxy_with_credentials_negotiates_userpass() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut greet = [0u8; 4];
            s.read_exact(&mut greet).await.expect("greet");
            assert_eq!(greet, [5, 2, 0, 2], "有凭据时应当同时提供 NONE 与 USERPASS");
            s.write_all(&[5, 2]).await.expect("method");
            let mut head = [0u8; 2];
            s.read_exact(&mut head).await.expect("ulen");
            let ulen = usize::from(head[1]);
            let mut user = vec![0u8; ulen];
            s.read_exact(&mut user).await.expect("user");
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await.expect("plen");
            let mut pass = vec![0u8; usize::from(plen[0])];
            s.read_exact(&mut pass).await.expect("pass");
            assert_eq!(ulen, 5, "alice 是 5 字节");
            assert_eq!(&user, b"alice");
            assert_eq!(plen[0], 6, "s3cret 是 6 字节");
            assert_eq!(&pass, b"s3cret");
            s.write_all(&[1, 0]).await.expect("auth ok");
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.expect("request");
            assert_eq!(req[0], SOCKS_VERSION);
            assert_eq!(req[1], CMD_CONNECT);
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .expect("reply");
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let spec = ProxySpec::socks5(addr.to_string(), "alice", "s3cret");
        let stream = dial_via_proxy(&spec, "127.0.0.1:80").await.expect("ok");
        drop(stream);
    }

    #[tokio::test]
    async fn socks5_proxy_rejection_is_error_not_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).await.expect("greet");
            s.write_all(&[5, 0]).await.expect("method");
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.expect("request");
            // REP = 0x05（连接被拒绝）。
            s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .expect("reply");
        });
        let err = dial_via_proxy(&ProxySpec::socks5(addr.to_string(), "", ""), "127.0.0.1:80")
            .await
            .expect_err("拒绝必须是错误");
        assert!(err.to_string().contains("拒绝 CONNECT"), "{err}");
    }
}
