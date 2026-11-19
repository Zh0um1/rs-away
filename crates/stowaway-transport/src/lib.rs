//! 连接协议 / 传输抽象层：`Link` / `Listener` / `Dialer`、三种传输与帧编解码。
//!
//! 权威契约与一致性闸门见 `docs/design/transport.md`；帧格式与握手见
//! `docs/plan.md` §4.4/§4.5。
//!
//! # 分层
//!
//! ```text
//! 应用消息  stowaway-protocol::Message
//!    │ encode
//!    ▼
//! 帧层      codec::LinkCodec（分片 / 密封 / 握手接线）
//!    ▼
//! 密封层    stowaway-crypto::LinkSealer（AAD = 整帧头）
//!    ▼
//! 链路层    link::Link（字节流，不保边界）
//!    ▼
//! 传输      tcp（raw，可叠 TLS） / ws / kcp
//! ```
//!
//! # 硬约束
//!
//! 新增传输必须在 **三处** 加分支：`stowaway_protocol::TransportKind`（含
//! `wire_id`）、[`link::AnyListener`]、[`link::AnyDialer`]。任何 `_ =>` 兜底
//! 都视为违规——编译期穷举是「传输可插拔」不被悄悄退化的唯一保障。
#![forbid(unsafe_code)]
// 库代码禁止直接打印（由二进制/调用方决定输出方式）。
#![deny(clippy::print_stdout, clippy::print_stderr)]
// 至少要编译进一种传输：`AnyListener`/`AnyDialer` 的变体由 feature 决定，
// 一个都不开时它们是空枚举，`Link` 抽象退化为「无链路可建」。这是配置错误，
// 应在编译期大声失败，而不是给出一份什么都不能做的库。
#[cfg(not(any(
    feature = "transport-raw",
    feature = "transport-ws",
    feature = "transport-kcp"
)))]
compile_error!(
    "至少启用一种传输：`transport-raw` / `transport-ws` / `transport-kcp`（见 docs/design/transport.md §6）"
);

pub mod codec;
pub mod error;
#[cfg(feature = "transport-kcp")]
pub mod kcp;
pub mod link;
pub mod sniff;
pub mod spec;
#[cfg(feature = "transport-raw")]
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tls;
/// `tls` 关闭时的 `TlsConfig` 占位（保证公共签名在 tier-3 目标上仍可编译）。
#[cfg(not(feature = "tls"))]
pub mod tls_off;
#[cfg(feature = "transport-ws")]
pub mod ws;

pub use codec::{
    COUNTER_LEN, HandshakeResult, LinkCodec, SEAL_OVERHEAD, TAG_LEN, dialer_for, dialer_handshake,
    listener_for, listener_handshake,
};
pub use error::{Result, TransportError};
pub use link::{
    AnyDialer, AnyListener, DialTarget, Dialer, Link, LinkMeta, Listener, boxed,
    compiled_transports,
};
pub use sniff::{Protocol, SNIFF_LEN, classify, hex_preview};
pub use spec::{SpecError, TransportSpec};
#[cfg(feature = "tls")]
pub use tls::{
    ClientVerify, TlsConfig, derive_cert, parse_pin, peer_fingerprint_der, spki_fingerprint,
};
#[cfg(not(feature = "tls"))]
pub use tls_off::{ClientVerify, TlsConfig};
