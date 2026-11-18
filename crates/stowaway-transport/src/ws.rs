//! WebSocket 传输：在 `WebSocketStream` 之上补出 `AsyncRead`/`AsyncWrite`。
//!
//! 权威：`docs/design/transport.md` §9（已知限制第一条）。
//!
//! 为什么需要适配层：`tokio-tungstenite 0.30` 的 `WebSocketStream<S>` 只实现
//! `Stream<Item = Result<Message>>` 与 `Sink<Message>`，**不实现** `AsyncRead`/`AsyncWrite`，
//! 因此不能直接 `tokio::io::copy`。本模块把它桥接成字节流：
//!
//! - **读**：`Message::Binary` 的字节进读缓冲；`Ping` 由 tungstenite 自动回 `Pong`
//!   （`protocol/mod.rs` 内 `set_additional(Frame::pong(..))`），这里只把控制帧吞掉；
//!   `Close` 记为 EOF（`Ok(0)`），符合半关闭语义。
//! - **写**：每次 `poll_write` 把调用方给的字节**整段**打成一条 `Message::Binary`
//!   （不跨 `poll_write` 缓冲，因为 `Ready(len)` 之后调用方可能立刻发下一段）。
//!
//! 握手：服务端用 [`accept_async`](tokio_tungstenite::accept_async)，客户端用
//! [`client_async`](tokio_tungstenite::client_async)。**不**用 `Connector`——本仓
//! `tokio-tungstenite` 只开了 `handshake` feature；TLS 由本模块先用
//! `tokio-rustls` 包好，再把 `Box<dyn TokioStream>` 交给 tungstenite。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream};
use stowaway_protocol::TransportKind;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::error::Result;
use crate::link::{DialTarget, Dialer, Link, LinkMeta, Listener};

/// 默认 ws 升级路径（与 v1 `protocol/websocket.go` 的 `websocketPath` 一致）。
pub const DEFAULT_WS_PATH: &str = "/deadbeef";

/// 把「可能是 TLS、也可能是明文」的流统一成 `AsyncRead + AsyncWrite`。
///
/// `Box<dyn TokioStream>` 自身实现了 `AsyncRead`/`AsyncWrite`（tokio 为
/// `Box<T: ?Sized + ... + Unpin>` 提供了 impl），因此可以直接交给 tungstenite。
pub trait TokioStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> TokioStream for T {}

/// 把 `WebSocketStream` 包成字节流链路。
pub struct WsLink<S> {
    inner: WebSocketStream<S>,
    meta: LinkMeta,
    /// 读方向尚未消费完的字节。
    read_buf: Vec<u8>,
    /// 读方向在读缓冲里的起点。
    read_pos: usize,
    /// 对端已发 `Close`（再读即 `Ok(0)`）。
    peer_closed: bool,
}

impl<S> std::fmt::Debug for WsLink<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsLink")
            .field("meta", &self.meta)
            .field("buffered", &self.buffered())
            .field("peer_closed", &self.peer_closed)
            .finish_non_exhaustive()
    }
}

impl<S> WsLink<S> {
    /// 包装一个已完成 ws 握手的流。
    #[must_use]
    pub fn new(inner: WebSocketStream<S>, peer: SocketAddr) -> Self {
        Self {
            inner,
            meta: LinkMeta::new(TransportKind::Ws, Some(peer)),
            read_buf: Vec::new(),
            read_pos: 0,
            peer_closed: false,
        }
    }

    /// 已缓存的未读字节数（诊断用）。
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.read_buf.len().saturating_sub(self.read_pos)
    }

    /// 覆盖 `max_frame`（ws 的分帧上限由监听侧指定）。
    #[must_use]
    pub fn with_max_frame(mut self, max_frame: usize) -> Self {
        self.meta.max_frame = max_frame;
        self
    }
}

impl<S> AsyncRead for WsLink<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // 1) 先把缓冲里的字节交给调用方（一次 poll_read 不保证读完，留下次）。
            let remaining = self.read_buf.len().saturating_sub(self.read_pos);
            if remaining > 0 {
                let take = remaining.min(buf.remaining());
                buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
                self.read_pos += take;
                if self.read_pos >= self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2) 对端已关闭：返回 EOF（半关闭语义）。
            if self.peer_closed {
                return Poll::Ready(Ok(()));
            }

            // 3) 从 ws 读下一条消息；只把 Binary 喂进字节流。
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.peer_closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(format!("ws 读取失败：{e}"))));
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        if data.is_empty() {
                            // 空消息不产生字节，继续读下一条。
                            continue;
                        }
                        self.read_buf.clear();
                        self.read_buf.extend_from_slice(&data);
                        self.read_pos = 0;
                    }
                    Message::Close(_) => {
                        self.peer_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    // Ping/Pong/Text/Frame：不进入字节流。
                    _ => continue,
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsLink<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.peer_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ws 对端已关闭",
            )));
        }

        // poll_ready 保证 Sink 有余量；不足则 Pending（背压，不无限缓存）。
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(format!("ws 写入不可用：{e}"))));
            }
            Poll::Ready(Ok(())) => {}
        }

        let payload = bytes::Bytes::copy_from_slice(data);
        match Pin::new(&mut self.inner).start_send(Message::Binary(payload)) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(e) => Poll::Ready(Err(io::Error::other(format!("ws 发送失败：{e}")))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(format!("ws flush 失败：{e}")))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(format!("ws 关闭失败：{e}")))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> Link for WsLink<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    fn meta(&self) -> LinkMeta {
        self.meta.clone()
    }
}

/// ws 监听器：握手升级后产出 [`WsLink`]。
#[derive(Debug)]
pub struct WsListener {
    listener: tokio::net::TcpListener,
    path: String,
    // `tls` feature 关闭时该字段只用于「显式报 FeatureDisabled」，不读内容。
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    tls: Option<crate::TlsConfig>,
    max_frame: usize,
}

impl WsListener {
    /// 绑定并监听。
    ///
    /// # Errors
    /// 端口占用/权限不足时返回 [`crate::TransportError::Io`]。
    pub async fn bind(
        addr: SocketAddr,
        path: impl Into<String>,
        // `tls` feature 关闭时该字段只用于「显式报 FeatureDisabled」，不读内容。
        #[cfg_attr(not(feature = "tls"), allow(dead_code))] tls: Option<crate::TlsConfig>,
    ) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            path: path.into(),
            tls,
            max_frame: stowaway_protocol::FRAGMENT_MAX,
        })
    }

    /// 期望的升级路径（日志与诊断用）。
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl Listener for WsListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    async fn accept(&mut self) -> io::Result<(Box<dyn Link>, SocketAddr)> {
        {
            let (stream, peer) = self.listener.accept().await?;

            #[cfg(feature = "tls")]
            let stream: Box<dyn TokioStream> = {
                if let Some(tls) = self.tls.as_ref() {
                    let server = tls.server_config().ok_or_else(|| {
                        crate::error::invalid_input("ws 监听端缺少服务端 TLS 配置")
                    })?;
                    let acceptor = tokio_rustls::TlsAcceptor::from(server);
                    Box::new(acceptor.accept(stream).await?)
                } else {
                    Box::new(stream)
                }
            };
            #[cfg(not(feature = "tls"))]
            let stream: Box<dyn TokioStream> = Box::new(stream);

            let ws = tokio_tungstenite::accept_async(stream)
                .await
                .map_err(|e| io::Error::other(format!("ws 服务端握手失败：{e}")))?;
            let link = WsLink::new(ws, peer).with_max_frame(self.max_frame);
            Ok((crate::link::boxed(link), peer))
        }
    }
}

/// ws 拨号器。
#[derive(Clone, Debug)]
pub struct WsDialer {
    path: String,
    domain: Option<String>,
    // `tls` feature 关闭时该字段只用于「显式报 FeatureDisabled」，不读内容。
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    tls: Option<crate::TlsConfig>,
}

impl WsDialer {
    /// 构造。
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        domain: Option<String>,
        tls: Option<crate::TlsConfig>,
    ) -> Self {
        Self {
            path: path.into(),
            domain,
            tls,
        }
    }
}

impl Dialer for WsDialer {
    async fn connect(&self, target: &DialTarget) -> io::Result<Box<dyn Link>> {
        {
            let tcp = tokio::net::TcpStream::connect(target.addr).await?;
            let host = self
                .domain
                .clone()
                .or_else(|| target.domain.clone())
                .unwrap_or_else(|| target.addr.ip().to_string());

            #[cfg(feature = "tls")]
            let stream: Box<dyn TokioStream> = {
                if let Some(tls) = self.tls.as_ref() {
                    let config = tls
                        .client_config()
                        .map_err(|e| io::Error::other(format!("ws 客户端 TLS 配置失败：{e}")))?;
                    let name = rustls::pki_types::ServerName::try_from(host.clone())
                        .map_err(|_| crate::error::invalid_input(format!("非法 SNI：{host}")))?;
                    let connector = tokio_rustls::TlsConnector::from(config);
                    Box::new(connector.connect(name, tcp).await?)
                } else {
                    Box::new(tcp)
                }
            };
            #[cfg(not(feature = "tls"))]
            let stream: Box<dyn TokioStream> = Box::new(tcp);

            let path = target.path.clone().unwrap_or_else(|| self.path.clone());
            let uri: tokio_tungstenite::tungstenite::http::Uri = format!("ws://{host}{path}")
                .parse()
                .map_err(|e| io::Error::other(format!("ws URI 非法（{host}{path}）：{e}")))?;
            let request = tokio_tungstenite::tungstenite::client::ClientRequestBuilder::new(uri);

            let (ws, _resp) = tokio_tungstenite::client_async(request, stream)
                .await
                .map_err(|e| io::Error::other(format!("ws 客户端握手失败：{e}")))?;
            Ok(crate::link::boxed(WsLink::new(ws, target.addr)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_matches_v1() {
        assert_eq!(DEFAULT_WS_PATH, "/deadbeef");
    }

    #[test]
    fn dialer_keeps_path_and_domain() {
        let d = WsDialer::new("/x", None, None);
        assert_eq!(d.path, "/x");
        assert!(d.domain.is_none());
    }
}
