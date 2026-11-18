//! 原始 TCP 传输（可叠加 TLS 外壳）。
//!
//! 权威：`docs/design/transport.md` §5（嗅探）、§6（矩阵）、`docs/plan.md` §4.11。
//!
//! 嗅探规则（修 v1 的 F10：`--tls-enable` 时先包 TLS 再读 token，导致回落逻辑失效）：
//!
//! ```text
//! accept → peek(8)，**不消费**
//!   ├─ 首字节 0x16 且本端配了 TLS → 包 TLS，握手*后*再消费前导
//!   ├─ 前缀 == "STW2"           → 明文 raw，随即消费掉这 4 字节前导
//!   └─ 其它                      → ReuseFallback（交调用方做端口复用回落/关闭）
//! ```
//!
//! **前导是线上约定，不是嗅探副产物**：`peek` 只取不消费，所以拨号端必须先显式
//! `write_all(MAGIC)`，接受端在判明 `Raw`/`Tls` 后显式 `read_exact` 把它吃掉，
//! 否则这 4 字节会留在流里被上层当成帧头（v1 没有这份前导，`protocol/raw.go:26`
//! 的 `CNegotiate()` 是空实现）。

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use stowaway_protocol::{MAGIC, TransportKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{Result, TransportError};
use crate::link::{DialTarget, Dialer, Link, LinkMeta, Listener};

/// 嗅探窗口：超过此时长仍凑不齐判定所需字节，就按非本协议处理。
///
/// 选 300ms：真实客户端的 `Hello` 是一帧、必然一次 write 出去；
/// 若对端是 HTTP 客户端，它也在等我们响应，两边都不能无限等。
const PEEK_TIMEOUT_MS: u64 = 300;

/// 明文 TCP 链路。
///
/// `peer` 只在构造 `meta` 时用一次，保留字段便于排障时 `dbg`（见 `Debug` 实现）。
pub struct RawLink<S> {
    inner: S,
    #[allow(dead_code)]
    peer: SocketAddr,
    meta: LinkMeta,
}

impl<S> std::fmt::Debug for RawLink<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawLink")
            .field("peer", &self.peer)
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

impl<S> RawLink<S> {
    /// 包装一个已完成握手/设置的流。
    #[must_use]
    pub fn new(inner: S, peer: SocketAddr, kind: TransportKind) -> Self {
        Self {
            inner,
            peer,
            meta: LinkMeta::new(kind, Some(peer)),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RawLink<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RawLink<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> Link for RawLink<S> {
    fn meta(&self) -> LinkMeta {
        self.meta.clone()
    }
}

/// TCP 监听器。
#[derive(Debug)]
pub struct RawListener {
    listener: TcpListener,
    tls: Option<crate::TlsConfig>,
    nodelay: bool,
    keepalive: Option<Duration>,
}

impl RawListener {
    /// 绑定并监听。
    ///
    /// # Errors
    /// 端口被占用、权限不足等返回 [`TransportError::Io`]。
    pub async fn bind(
        addr: SocketAddr,
        tls: Option<crate::TlsConfig>,
        nodelay: bool,
        keepalive: Option<Duration>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            tls,
            nodelay,
            keepalive,
        })
    }

    /// 本端是否启用 TLS。
    #[must_use]
    pub const fn tls_enabled(&self) -> bool {
        self.tls.is_some()
    }
}

impl Listener for RawListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    async fn accept(&mut self) -> io::Result<(Box<dyn Link>, SocketAddr)> {
        {
            let (stream, peer) = self.listener.accept().await?;
            apply_sockopts(&stream, self.nodelay, self.keepalive)?;

            // peek(8)：只取不消费，避免与后续 TLS/协议解析抢字节。
            // 循环累计：单次 peek 可能只返回 1 字节（TCP 分段），
            // 而 `MAGIC` 需要 4 字节才能判定。超时视为非本协议流量。
            let mut probe = [0u8; 8];
            let mut n = 0usize;
            let deadline = Duration::from_millis(PEEK_TIMEOUT_MS);
            let started = std::time::Instant::now();
            while n < probe.len() {
                let got = stream.peek(&mut probe[n..]).await?;
                if got == 0 {
                    break;
                }
                n += got;
                // TLS 只看首字节即可判定；raw 需要 4 字节；凑够后立即退出。
                let enough = if probe[0] == 0x16 {
                    n >= 1
                } else {
                    n >= MAGIC.len()
                };
                if enough || started.elapsed() >= deadline {
                    break;
                }
            }
            let peeked = &probe[..n];

            let wants_tls = self.tls.is_some();
            // 一个字节都没读到（对端连上即关）按「非本协议」处理，交给回落路径。
            let protocol = crate::sniff::classify(peeked, wants_tls)
                .unwrap_or(crate::sniff::Protocol::Foreign);

            if protocol == crate::sniff::Protocol::Tls {
                #[cfg(feature = "tls")]
                {
                    let tls = self
                        .tls
                        .as_ref()
                        .ok_or_else(|| crate::error::invalid_input("TLS 配置在 accept 期间消失"))?;
                    let server = tls.server_config().ok_or_else(|| {
                        crate::error::invalid_input("服务端 TLS 配置缺失（监听端未派发证书）")
                    })?;
                    let acceptor = tokio_rustls::TlsAcceptor::from(server);
                    let mut tls_stream = acceptor.accept(stream).await?;
                    // 前导在 TLS 内层：握手完成后才读得到，读掉再交给上层。
                    consume_preamble(&mut tls_stream).await?;
                    return Ok((
                        crate::link::boxed(RawLink::new(tls_stream, peer, TransportKind::Raw)),
                        peer,
                    ));
                }
                #[cfg(not(feature = "tls"))]
                {
                    return Err(crate::error::invalid_input(
                        "收到 TLS 记录但本构建未编译 tls feature",
                    ));
                }
            }

            if protocol == crate::sniff::Protocol::Raw {
                // `peek` 不消费：这 4 字节前导仍在流里，必须显式读掉，
                // 否则上层会把 `STW2` 当成帧版本字节。
                let mut stream = stream;
                consume_preamble(&mut stream).await?;
                return Ok((
                    crate::link::boxed(RawLink::new(stream, peer, TransportKind::Raw)),
                    peer,
                ));
            }

            if protocol == crate::sniff::Protocol::Ws {
                // ws 由独立端口/监听器处理；同端口共存时这里明确报错而不是猜测。
                // 用 `UnrecognizedPeer`（kind = InvalidData）而不是 `invalid_input`：
                // 对上游 PEMBE 来说这是「对端协议不符」，与端口复用回落同类可重试错误。
                return Err(to_io(&TransportError::UnrecognizedPeer {
                    peeked: n,
                    hex: hex_preview(peeked),
                }));
            }

            Err(to_io(&TransportError::ReuseFallback {
                peeked: n,
                hex: hex_preview(peeked),
            }))
        }
    }
}

/// TCP 拨号器。
#[derive(Clone, Debug)]
pub struct RawDialer {
    nodelay: bool,
    keepalive: Option<Duration>,
}

impl RawDialer {
    /// 按规格构造。
    #[must_use]
    pub const fn new(nodelay: bool, keepalive: Option<Duration>) -> Self {
        Self { nodelay, keepalive }
    }
}

impl Dialer for RawDialer {
    async fn connect(&self, target: &DialTarget) -> io::Result<Box<dyn Link>> {
        {
            let stream = TcpStream::connect(target.addr).await?;
            apply_sockopts(&stream, self.nodelay, self.keepalive)?;

            #[cfg(feature = "tls")]
            if let Some(tls) = target.tls.as_ref() {
                let config = tls.client_config().map_err(|e| to_io(&e))?;
                let sni = target
                    .domain
                    .clone()
                    .unwrap_or_else(|| target.addr.ip().to_string());
                let name = rustls::pki_types::ServerName::try_from(sni.clone())
                    .map_err(|_| crate::error::invalid_input(format!("非法 SNI：{sni}")))?;
                let connector = tokio_rustls::TlsConnector::from(config);
                let mut tls_stream = connector.connect(name, stream).await?;
                // 前导写在 TLS 内层：必须先完成握手。它是线上约定的一部分，
                // 服务端靠它把本连接判定为 Stowaway 流量。
                tls_stream.write_all(&MAGIC).await?;
                tls_stream.flush().await?;
                return Ok(crate::link::boxed(RawLink::new(
                    tls_stream,
                    target.addr,
                    TransportKind::Raw,
                )));
            }

            #[cfg(not(feature = "tls"))]
            if target.tls.is_some() {
                return Err(to_io(&TransportError::FeatureDisabled {
                    kind: "tls",
                    feature: "tls",
                }));
            }

            // 明文：连上就先自报家门，服务端 `peek` 才有东西可看。
            let mut stream = stream;
            stream.write_all(&MAGIC).await?;
            stream.flush().await?;
            Ok(crate::link::boxed(RawLink::new(
                stream,
                target.addr,
                TransportKind::Raw,
            )))
        }
    }
}

/// 读掉 4 字节 `MAGIC` 前导（接受端专用）。
///
/// `peek` 只取不消费，所以判定为 raw 之后必须显式读掉，
/// 否则 `STW2` 会作为帧版本字节进到 [`crate::LinkCodec`] 里，
/// 表现为 `BadVersion { actual: b'S' }` 这种极难定位的握手失败。
async fn consume_preamble<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<()> {
    let mut got = [0u8; MAGIC.len()];
    stream.read_exact(&mut got).await?;
    if got != MAGIC {
        return Err(crate::error::invalid_input(format!(
            "前导不匹配：期望 {}，实际 {}",
            crate::sniff::hex_preview(&MAGIC),
            crate::sniff::hex_preview(&got)
        )));
    }
    Ok(())
}

/// 应用 `TCP_NODELAY` / `SO_KEEPALIVE`（v1 全仓零命中，见 plan §2.10）。
fn apply_sockopts(
    stream: &TcpStream,
    nodelay: bool,
    keepalive: Option<Duration>,
) -> io::Result<()> {
    let sock = socket2::SockRef::from(stream);
    sock.set_tcp_nodelay(nodelay)?;
    if let Some(secs) = keepalive {
        let ka = socket2::TcpKeepalive::new().with_time(secs);
        sock.set_tcp_keepalive(&ka)?;
    }
    Ok(())
}

/// 把 [`TransportError`] 降级为 `io::Error`（[`Listener`] 契约只允许 `io::Result`）。
pub(crate) fn to_io(e: &TransportError) -> io::Error {
    match e {
        TransportError::Io(inner) => io::Error::new(inner.kind(), format!("{e}")),
        TransportError::ReuseFallback { .. } => {
            io::Error::new(io::ErrorKind::InvalidData, format!("{e}"))
        }
        TransportError::UnrecognizedPeer { .. } => {
            io::Error::new(io::ErrorKind::InvalidData, format!("{e}"))
        }
        TransportError::FeatureDisabled { .. } => {
            io::Error::new(io::ErrorKind::Unsupported, format!("{e}"))
        }
        _ => io::Error::other(format!("{e}")),
    }
}

/// 十六进制预览（最多 8 字节，避免日志膨胀）。
pub(crate) fn hex_preview(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes.iter().take(8) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_preview_truncates_to_eight_bytes() {
        let long = [0xabu8; 32];
        assert_eq!(hex_preview(&long).len(), 16);
        assert_eq!(hex_preview(&[0x53, 0x54, 0x57, 0x32]), "53545732");
    }

    #[tokio::test]
    async fn raw_listener_and_dialer_roundtrip() {
        let listener = RawListener::bind("127.0.0.1:0".parse().expect("addr"), None, true, None)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let mut listener = listener;

        let client = tokio::spawn(async move {
            let dialer = RawDialer::new(true, None);
            let target = DialTarget::plain(addr);
            let mut link = dialer.connect(&target).await.expect("connect");
            // 前导由 `connect` 自己发出并被 `accept` 消费，这里直接写业务字节：
            // 若前导泄漏到链路里，读到的一定不是 payload。
            tokio::io::AsyncWriteExt::write_all(&mut link, b"payload")
                .await
                .expect("write");
        });

        let (mut link, _peer) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 7];
        tokio::io::AsyncReadExt::read_exact(&mut link, &mut buf)
            .await
            .expect("read");
        assert_eq!(&buf, b"payload", "前导必须已被 accept 消费掉");
        assert_eq!(link.meta().kind, TransportKind::Raw);
        client.await.expect("client join");
    }

    #[tokio::test]
    async fn non_stowaway_traffic_is_reuse_fallback() {
        let mut listener =
            RawListener::bind("127.0.0.1:0".parse().expect("addr"), None, true, None)
                .await
                .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let _client = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.expect("connect");
            // SSH 横幅：既不是 `STW2` 也不是 HTTP 方法前缀 → 端口复用回落。
            tokio::io::AsyncWriteExt::write_all(&mut s, b"SSH-2.0-OpenSSH_9.6\r\n")
                .await
                .expect("write");
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let err = match listener.accept().await {
            Ok(_) => panic!("应回落"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("端口复用回落"));
    }
}
