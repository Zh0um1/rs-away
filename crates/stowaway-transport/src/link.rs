//! `Link` 抽象：**字节流** + 元数据。
//!
//! 权威契约见 `docs/design/transport.md` §3。四条不可缩小语义承诺：
//!
//! 1. **可靠有序**（丢包/重传由传输内部处理，上层只见完整有序字节流）；
//! 2. **字节流不保边界**：一次 `poll_read` 可能只给半帧或多帧，分帧是
//!    [`crate::codec`] 的职责；
//! 3. **背压**：对端不读时写方必须 `Pending`，不允许无限缓存；
//! 4. **取消安全**：`poll_read` 被 drop 不得丢弃已读字节。
//!
//! 新增传输**必须**同时在 `TransportKind`、[`AnyListener`]、[`AnyDialer`]
//! 三处加分支，禁止 `_ =>` 兜底（编译期强制穷举）。

use core::future::Future;
use std::io;
use std::net::SocketAddr;

use stowaway_protocol::{FRAGMENT_MAX, TransportKind};
use tokio::io::{AsyncRead, AsyncWrite};

/// 链路元数据。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkMeta {
    /// 传输种类。
    pub kind: TransportKind,
    /// 对端地址（KCP 等可能未知时为 `None`）。
    pub peer: Option<SocketAddr>,
    /// 该传输能承载的单帧上限（超过由帧层分片）。
    pub max_frame: usize,
    /// 是否报文型（UDP/KCP 为 true：一次写对应一次报文）。
    pub datagram_backed: bool,
}

impl LinkMeta {
    /// 按传输种类构造，`max_frame` 缺省用 [`FRAGMENT_MAX`]。
    #[must_use]
    pub fn new(kind: TransportKind, peer: Option<SocketAddr>) -> Self {
        Self {
            kind,
            peer,
            max_frame: FRAGMENT_MAX,
            datagram_backed: kind.is_datagram_backed(),
        }
    }

    /// 覆盖单帧上限（KCP 按 `mtu × 8` 上报，见 transport.md §8）。
    #[must_use]
    pub const fn with_max_frame(mut self, max_frame: usize) -> Self {
        self.max_frame = max_frame;
        self
    }
}

/// 一条已建立的双向字节流。
///
/// 用 `Box<dyn Link>` 传递以避免泛型传染到 core；
/// 只有 1–3 个实现，动态派发开销可忽略。
pub trait Link: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    /// 链路元数据（种类、对端、单帧上限）。
    fn meta(&self) -> LinkMeta;
}

/// 拨号目标：把「连到哪里」与「怎么连」分开。
#[derive(Clone, Debug)]
pub struct DialTarget {
    /// 已解析的对端地址。
    pub addr: SocketAddr,
    /// ws 的 Host/SNI（也用于 TLS 的 SNI）。
    pub domain: Option<String>,
    /// ws 的路径。
    pub path: Option<String>,
    /// TLS 配置；`None` 表示明文。
    pub tls: Option<crate::TlsConfig>,
}

impl DialTarget {
    /// 明文目标。
    #[must_use]
    pub fn plain(addr: SocketAddr) -> Self {
        Self {
            addr,
            domain: None,
            path: None,
            tls: None,
        }
    }

    /// 是否要求 TLS。
    #[must_use]
    pub const fn wants_tls(&self) -> bool {
        self.tls.is_some()
    }
}

/// 监听器：一次 `accept` 产出一条 [`Link`]。
///
/// 用 AFIT 而非 `async_trait`：避免为每个实现分配 `Box<Future>`。
pub trait Listener {
    /// 实际监听地址（端口 0 时用于取回内核分配的端口）。
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// 接受一条新链路。
    fn accept(&mut self) -> impl Future<Output = io::Result<(Box<dyn Link>, SocketAddr)>> + Send;
}

/// 拨号器：按 [`DialTarget`] 建立一条 [`Link`]。
pub trait Dialer {
    /// 建立链路。
    fn connect(
        &self,
        target: &DialTarget,
    ) -> impl Future<Output = io::Result<Box<dyn Link>>> + Send;
}

/// 监听器枚举。
///
/// 每进程只有 1–3 个监听器，枚举分派零成本，且能逐 feature 裁剪；
/// 反例是 `dyn Listener`：AFIT 使 trait 无法直接成为 trait object。
#[derive(Debug)]
pub enum AnyListener {
    /// 原始 TCP（也可能是包了 TLS 的 TCP）。
    #[cfg(feature = "transport-raw")]
    Raw(crate::tcp::RawListener),
    /// WebSocket。
    #[cfg(feature = "transport-ws")]
    Ws(crate::ws::WsListener),
    /// KCP（UDP）。
    #[cfg(feature = "transport-kcp")]
    Kcp(crate::kcp::KcpListener),
}

impl AnyListener {
    /// 监听器对应的传输种类。
    #[must_use]
    pub fn kind(&self) -> TransportKind {
        match self {
            #[cfg(feature = "transport-raw")]
            Self::Raw(_) => TransportKind::Raw,
            #[cfg(feature = "transport-ws")]
            Self::Ws(_) => TransportKind::Ws,
            #[cfg(feature = "transport-kcp")]
            Self::Kcp(_) => TransportKind::Kcp,
        }
    }
}

impl Listener for AnyListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            #[cfg(feature = "transport-raw")]
            Self::Raw(l) => l.local_addr(),
            #[cfg(feature = "transport-ws")]
            Self::Ws(l) => l.local_addr(),
            #[cfg(feature = "transport-kcp")]
            Self::Kcp(l) => l.local_addr(),
        }
    }

    async fn accept(&mut self) -> io::Result<(Box<dyn Link>, SocketAddr)> {
        {
            match self {
                #[cfg(feature = "transport-raw")]
                Self::Raw(l) => l.accept().await,
                #[cfg(feature = "transport-ws")]
                Self::Ws(l) => l.accept().await,
                #[cfg(feature = "transport-kcp")]
                Self::Kcp(l) => l.accept().await,
            }
        }
    }
}

/// 拨号器枚举。
#[derive(Clone, Debug)]
pub enum AnyDialer {
    /// 原始 TCP（也可能是包了 TLS 的 TCP）。
    #[cfg(feature = "transport-raw")]
    Raw(crate::tcp::RawDialer),
    /// WebSocket。
    #[cfg(feature = "transport-ws")]
    Ws(crate::ws::WsDialer),
    /// KCP（UDP）。
    #[cfg(feature = "transport-kcp")]
    Kcp(crate::kcp::KcpDialer),
}

impl AnyDialer {
    /// 拨号器对应的传输种类。
    #[must_use]
    pub fn kind(&self) -> TransportKind {
        match self {
            #[cfg(feature = "transport-raw")]
            Self::Raw(_) => TransportKind::Raw,
            #[cfg(feature = "transport-ws")]
            Self::Ws(_) => TransportKind::Ws,
            #[cfg(feature = "transport-kcp")]
            Self::Kcp(_) => TransportKind::Kcp,
        }
    }
}

impl Dialer for AnyDialer {
    async fn connect(&self, target: &DialTarget) -> io::Result<Box<dyn Link>> {
        {
            match self {
                #[cfg(feature = "transport-raw")]
                Self::Raw(d) => d.connect(target).await,
                #[cfg(feature = "transport-ws")]
                Self::Ws(d) => d.connect(target).await,
                #[cfg(feature = "transport-kcp")]
                Self::Kcp(d) => d.connect(target).await,
            }
        }
    }
}

/// 把任意 [`Link`] 装箱。
#[must_use]
pub fn boxed(link: impl Link) -> Box<dyn Link> {
    Box::new(link)
}

/// 本进程可用的传输种类（受 feature 裁剪影响）。
///
/// 用于启动日志与 `--up`/`--down` 的错误提示：用户在 tier-3 目标上写
/// `ws://` 时应看到「当前构建未编译该传输」而非「未知 scheme」。
#[must_use]
pub fn compiled_transports() -> Vec<TransportKind> {
    // 用 `vec![]` 一次性构造而不是 `Vec::new()` + `push`：后者在
    // 「只开一种传输」时会被 clippy 判为 `vec_init_then_push`。
    #[cfg_attr(
        not(any(
            feature = "transport-raw",
            feature = "transport-ws",
            feature = "transport-kcp"
        )),
        allow(unused_mut)
    )]
    let mut kinds = Vec::with_capacity(3);
    #[cfg(feature = "transport-raw")]
    kinds.extend([TransportKind::Raw]);
    #[cfg(feature = "transport-ws")]
    kinds.extend([TransportKind::Ws]);
    #[cfg(feature = "transport-kcp")]
    kinds.extend([TransportKind::Kcp]);
    kinds
}
