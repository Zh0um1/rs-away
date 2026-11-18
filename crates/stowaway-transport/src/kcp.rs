//! KCP 传输（UDP 之上的可靠有序字节流）。
//!
//! 权威：`docs/design/transport.md` §8（新增传输六步清单）、§6（矩阵：**kcp 不与 TLS 叠加**）。
//!
//! 关键约束（照文档实现，勿改）：
//!
//! - `tokio_kcp::KcpStream::connect(config, addr)` **只收 `SocketAddr`**（不是
//!   `ToSocketAddrs`），域名解析必须在本模块之前完成（[`crate::TransportSpec::resolve_addr`]）。
//! - `conv` 由 `HKDF(secret, "kcp-conv")` 派生（[`stowaway_crypto::kcp_conv`]），
//!   因此同一部署内所有节点默认会谈同一个 `conv`；显式 `conv=` 时启动期应告警。
//!   非本部署的包在 conv 校验处被丢弃。
//! - `max_frame = mtu × 8`：KCP 的每次发送受 MTU 限制，但一次 `write` 会被拆成
//!   多段；把单逻辑帧上限压到 8 段可避免段级重传放大。
//! - 本传输是**报文型**（`datagram_backed = true`），但 `KcpStream` 实现了
//!   `AsyncRead`/`AsyncWrite` 且内部 `stream` 模式会把写入串成有序字节流，
//!   因此 [`Link`](crate::link::Link) 的「字节流」承诺成立。

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use stowaway_protocol::TransportKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_kcp::{KcpConfig, KcpListener as InnerListener, KcpNoDelayConfig, KcpStream};

use crate::error::{Result, TransportError};
use crate::link::{DialTarget, Dialer, Link, LinkMeta, Listener};

/// 「一段」的说明性字节数：`max_frame = mtu × 8`。
const SEGMENTS_PER_FRAME: usize = 8;

/// 把 [`crate::TransportSpec`] 的 kcp 参数翻成 `KcpConfig`。
///
/// # Errors
/// `mtu`/`wnd` 越界时返回 [`TransportError::Spec`]。
pub fn kcp_config(spec: &crate::TransportSpec) -> Result<KcpConfig> {
    let mtu = spec.mtu.unwrap_or(1400);
    if !(576..=1400).contains(&mtu) {
        return Err(TransportError::Spec(crate::SpecError::BadParam {
            scheme: "kcp",
            key: "mtu".to_owned(),
            value: mtu.to_string(),
            reason: "必须在 576..=1400",
        }));
    }
    let wnd = spec.wnd.unwrap_or((256, 256));
    let nodelay = if spec.nodelay {
        KcpNoDelayConfig::fastest()
    } else {
        KcpNoDelayConfig::normal()
    };
    Ok(KcpConfig {
        mtu: usize::from(mtu),
        nodelay,
        wnd_size: wnd,
        session_expire: Duration::from_secs(90),
        // 每次写后立刻 flush：Stowaway 的帧已经是「攒好再发」的批量，
        // 再让 KCP 多攒一层只会增加延迟。
        flush_write: true,
        flush_acks_input: true,
        // 字节流语义（不是报文语义）：Link 承诺的是有序字节流。
        stream: true,
        allow_recv_empty_packet: false,
    })
}

/// KCP 链路。
pub struct KcpLink {
    inner: KcpStream,
    #[allow(dead_code)]
    peer: SocketAddr,
    meta: LinkMeta,
}

impl std::fmt::Debug for KcpLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcpLink").field("meta", &self.meta).finish()
    }
}

impl KcpLink {
    /// 包装一条已建立的 KCP 流。
    #[must_use]
    pub fn new(inner: KcpStream, peer: SocketAddr, mtu: usize) -> Self {
        let mut meta = LinkMeta::new(TransportKind::Kcp, Some(peer));
        meta.max_frame = mtu.saturating_mul(SEGMENTS_PER_FRAME);
        Self { inner, peer, meta }
    }
}

impl AsyncRead for KcpLink {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for KcpLink {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Link for KcpLink {
    fn meta(&self) -> LinkMeta {
        self.meta.clone()
    }
}

/// KCP 监听器。
pub struct KcpListener {
    inner: InnerListener,
    mtu: usize,
}

impl std::fmt::Debug for KcpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcpListener")
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl KcpListener {
    /// 按 spec 绑定。
    ///
    /// # Errors
    /// UDP 端口占用、参数越界。
    pub async fn bind(spec: &crate::TransportSpec, addr: SocketAddr) -> Result<Self> {
        let config = kcp_config(spec)?;
        let inner = InnerListener::bind(config, addr)
            .await
            .map_err(|e| TransportError::Io(io::Error::other(format!("kcp 绑定失败：{e}"))))?;
        Ok(Self {
            inner,
            mtu: config.mtu,
        })
    }
}

impl Listener for KcpListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    async fn accept(&mut self) -> io::Result<(Box<dyn Link>, SocketAddr)> {
        {
            let (stream, peer) = self
                .inner
                .accept()
                .await
                .map_err(|e| io::Error::other(format!("kcp 接受连接失败：{e}")))?;
            Ok((
                crate::link::boxed(KcpLink::new(stream, peer, self.mtu)),
                peer,
            ))
        }
    }
}

/// KCP 拨号器。
#[derive(Clone, Debug)]
pub struct KcpDialer {
    config: KcpConfig,
    conv: Option<u32>,
}

impl KcpDialer {
    /// 从 spec 构造（`conv` 缺省则用 `connect`，由调用方先 `resolve`）。
    ///
    /// # Errors
    /// 参数越界。
    pub fn from_spec(spec: &crate::TransportSpec) -> Result<Self> {
        Ok(Self {
            config: kcp_config(spec)?,
            conv: spec.conv,
        })
    }

    /// 配置（诊断用）。
    #[must_use]
    pub const fn config(&self) -> &KcpConfig {
        &self.config
    }
}

impl Dialer for KcpDialer {
    async fn connect(&self, target: &DialTarget) -> io::Result<Box<dyn Link>> {
        {
            let mtu = self.config.mtu;
            let stream = match self.conv {
                Some(conv) => KcpStream::connect_with_conv(&self.config, conv, target.addr).await,
                None => KcpStream::connect(&self.config, target.addr).await,
            }
            .map_err(|e| io::Error::other(format!("kcp 连接失败：{e}")))?;
            Ok(crate::link::boxed(KcpLink::new(stream, target.addr, mtu)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(q: &str) -> crate::TransportSpec {
        crate::TransportSpec::parse(q).expect("spec 合法")
    }

    #[test]
    fn config_uses_derived_conv() {
        let s = spec("kcp://127.0.0.1:4000").resolve(b"deployment-secret");
        assert!(s.conv.is_some());
        let d = KcpDialer::from_spec(&s).expect("dialer");
        assert_eq!(d.conv, s.conv);
    }

    #[test]
    fn max_frame_is_mtu_times_eight() {
        let s = spec("kcp://127.0.0.1:4000?mtu=600");
        let cfg = kcp_config(&s).expect("config");
        assert_eq!(cfg.mtu, 600);
        assert_eq!(cfg.mtu * SEGMENTS_PER_FRAME, 4800);
        assert!(cfg.stream, "必须用流模式才能兑现 Link 的字节流承诺");
    }

    #[test]
    fn bad_mtu_is_rejected_at_parse_time() {
        // `mtu` 的 576..=1400 约束在 spec 解析期就生效（不等到 dialer 构造）。
        let e = crate::TransportSpec::parse("kcp://127.0.0.1:4000?mtu=9999");
        match e {
            Err(crate::SpecError::BadParam { key, .. }) => assert_eq!(key, "mtu"),
            other => panic!("期望 BadParam(mtu)，实得 {other:?}"),
        }
    }
}
