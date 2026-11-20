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
//!   ├─ "GET " / "POST " / ...   → ws 走错端口，报 UnrecognizedPeer（**不走回落**）
//!   └─ 其它（Foreign）           → 配了回落目标就原样转走并继续 accept；
//!                                  没配则 ReuseFallback（交调用方决定转发/关闭）
//! ```
//!
//! # 端口复用回落
//!
//! 对应 v1 `agent/initial/method.go` 的 `ProxyStream` / `CopyTraffic`。v1 的
//! 做法是「读出若干字节 → 拨号 → 把已读字节补写过去 → 双向对拷」；v2 换成
//! `MSG_PEEK` 嗅探后**根本不需要补写**：判定所读的字节从未被消费，整条流
//! 仍然完整地躺在内核接收缓冲里。因此回落只是「拨号 + `copy_bidirectional`」，
//! 不会出现 v1 那种「补写顺序与并发读交错」的竞态。
//!
//! 回落是**旁路**：`accept` 把该连接交给单独的 `tokio::spawn` 任务后立刻回到
//! 监听循环，回落的成功率/时延都不影响本协议链路的接入速度。
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

/// 端口复用回落时双向对拷的缓冲区大小（10 KiB）。
///
/// 与 v1 `agent/initial/method.go` 的 `CopyTraffic` 保持一致：v1 用
/// `make([]byte, 10240)` 固定分配，不随流量增长。v2 同样用固定大小，
/// 让每条回落连接的常驻内存可预测（回落连接数不受本协议控制，
/// 若按吞吐动态放大缓冲区，一条慢速大流量旁路就能吃掉整台机器的内存）。
pub const FALLBACK_BUF: usize = 10 * 1024;

/// 回落拨号超时：目标端口可能已关闭或正在排队，`accept` 不能因此挂住。
///
/// 10s 与 v1 的 `net.Dial` 依赖内核 SYN 重试（约 1s/2s/4s/8s）量级相当，
/// 但显式给上限——内核默认可能重试到 2 分钟以上，那会让回落任务长时间
/// 占着一条已建立的入向连接。
const FALLBACK_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

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
    fallback: Option<SocketAddr>,
}

impl RawListener {
    /// 绑定并监听。
    ///
    /// 默认**没有**回落目标：端口复用的目标是要么由上层策略决定、要么由
    /// iptables 规则决定，不该藏在 `bind` 的入参里。这也保证既有调用点
    /// （`crate::codec::listener_for` 等）零改动。
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
            fallback: None,
        })
    }

    /// 设置端口复用回落目标（链式构造）。
    ///
    /// `Some(addr)`：判定为非本协议流量时，把整条流原样转给 `addr`，并继续
    /// 接受下一个连接；`None`：恢复「返回 [`TransportError::ReuseFallback`]
    /// 由调用方决定」的既有语义。
    ///
    /// 用 `const fn` + `mut self` 而非 `&mut self`：监听器在 `Listener::accept`
    /// 之外不该被可变借用，链式写法也让 `bind(...).with_fallback(..)` 可读。
    #[must_use]
    pub const fn with_fallback(mut self, target: Option<SocketAddr>) -> Self {
        self.fallback = target;
        self
    }

    /// 当前回落目标。
    #[must_use]
    pub const fn fallback(&self) -> Option<SocketAddr> {
        self.fallback
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
        // 循环只为「回落成功」这一个理由而存在：一条陌生连接被转走后，
        // 本监听器应当继续为上层的下一条本协议连接服务，而不是把它自己
        // 变成一个「一次只处理一条连接」的串行转发器。
        //
        // 其余分支（TLS 握手、前导、ws、无回落时的 ReuseFallback）都原样
        // `return`，所以循环不会改变任何既有的错误时序与语义。
        loop {
            let (stream, peer) = self.listener.accept().await?;
            apply_sockopts(&stream, self.nodelay, self.keepalive)?;

            // peek(8)：只取不消费，避免与后续 TLS/协议解析抢字节。
            // 循环累计：单次 peek 可能只返回 1 字节（TCP 分段），
            // 而 `MAGIC` 需要 4 字节才能判定。超时视为非本协议流量。
            //
            // 「不消费」也是端口复用回落能「整条流原样转走」的前提：
            // 判为陌生流量时这 n 个字节仍在 socket 里，回落方直接对拷即可。
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
                //
                // 即便配了回落目标，ws 也**不**走回落：它是已知协议、只是接到了
                // 错的端口，转给后端只会得到一份 400，不如立刻把误配暴露出来。
                return Err(to_io(&TransportError::UnrecognizedPeer {
                    peeked: n,
                    hex: hex_preview(peeked),
                }));
            }

            // —— Foreign：非本协议流量 ——
            let Some(target) = self.fallback else {
                // 没有回落目标：保持既有契约（调用方自己决定转发还是关闭）。
                return Err(to_io(&TransportError::ReuseFallback {
                    peeked: n,
                    hex: hex_preview(peeked),
                }));
            };

            // 有回落目标：把这条流交给旁路任务后立刻回去接下一个连接。
            // 不在这里 `await` 对拷——回落连接的存活时间由外部流量决定，
            // 若内联等待，一条长连接 SSH 会话就能让本监听器停止接入本协议流量。
            let hex = hex_preview(peeked);
            tokio::spawn(async move {
                // 任务返回值只留在后台：错误必须落日志，否则回落失败会表现为
                // 「客户端莫名其妙被断连」而服务端一声不吭，线上极难定位。
                match proxy_to_fallback(stream, target).await {
                    Ok(up) => {
                        tracing::debug!(%target, %peer, up, %hex, "端口复用回落结束");
                    }
                    Err(e) => {
                        tracing::debug!(%target, %peer, error = %e, %hex, "端口复用回落失败");
                    }
                }
            });
        }
    }
}

/// 把一条**尚含未消费前导字节**的入向连接原样转交给回落目标。
///
/// 对应 v1 `agent/initial/method.go` 的 `ProxyStream`：拨号 → 双向对拷。
///
/// # 前提（改动者必读）
///
/// 本函数**假定 `stream` 里一个字节都还没被消费**。`tcp.rs` 的嗅探用的是
/// `TcpStream::peek`（`MSG_PEEK`），它只把数据复制出来看，不推进接收队列，
/// 所以判为 `Foreign` 时那几个字节（最多 8 个）仍完整留在流里，直接对拷即可。
///
/// **如果把嗅探改成 `read`，这里必须先把读出来的字节补写给 `target`**，
/// 否则客户端请求行/SSH 横幅的前几个字节会被静默吞掉，表现为「后端收到
/// 半截请求」——v1 正是因为先 `io.ReadFull` 才不得不手动 `reuseConn.Write(message)`。
///
/// 不在此处做任何协议解析：回落目标可能是任意协议（SSH/HTTP/MySQL…）。
///
/// # 返回值
/// 上行（客户端 → 目标）字节数，即 `copy_bidirectional` 的 `a→b` 计数。
/// 下行字节数不回传：调用方只据此判断「有没有真的转过去」。
///
/// # Errors
/// - 拨号超过 10 秒 → [`io::ErrorKind::TimedOut`]（文案带目标地址）；
/// - 拨号被拒绝/不可达 → 对应 [`io::ErrorKind`]；
/// - 对拷中途失败 → 底层错误。对拷阶段的部分字节可能已送出，
///   这是 TCP 旁路的固有性质（与 v1 一致），不做补偿。
pub async fn proxy_to_fallback(stream: TcpStream, target: SocketAddr) -> io::Result<u64> {
    let dial = TcpStream::connect(target);
    let mut upstream = match tokio::time::timeout(FALLBACK_DIAL_TIMEOUT, dial).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        // 超时文案要具体：只说「超时」无法区分「后端没起」与「iptables 把包吃了」。
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "端口复用回落：拨号 {target} 超时（{} 秒）",
                    FALLBACK_DIAL_TIMEOUT.as_secs()
                ),
            ));
        }
    };
    // 回落链路是逐条交互型流量（SSH/HTTP），Nagle 只会增加往返延迟；
    // 失败也无所谓（设置了只影响时延），因此 `ok()` 而非传播错误。
    upstream.set_nodelay(true).ok();

    let mut inbound = stream;
    // `copy_bidirectional_with_sizes` 才是带缓冲区大小的版本；裸
    // `copy_bidirectional` 固定 8 KiB，与 v1 的 10 KiB 不一致。
    // 若未来 tokio 移除了这个 API，等价写法是两个 `tokio::io::copy` 任务
    // （`copy` 不接受缓冲大小参数，只能用 tokio 内部默认值，届时
    // `FALLBACK_BUF` 会退化为「无用文档常量」，需要在 doc 里注明差异）。
    let (up, _down) = tokio::io::copy_bidirectional_with_sizes(
        &mut inbound,
        &mut upstream,
        FALLBACK_BUF,
        FALLBACK_BUF,
    )
    .await?;
    Ok(up)
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
