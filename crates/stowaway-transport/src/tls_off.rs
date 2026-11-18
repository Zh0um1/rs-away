//! `tls` feature 关闭时的 `TlsConfig` 占位类型。
//!
//! 为什么需要它：`DialTarget` / `RawListener` / `WsListener` / `dialer_for` 等
//! **公共签名**里都有 `Option<TlsConfig>`，而 tier-3 目标（`armv5te`、`mipsel`）
//! 必须能在 `--no-default-features` 下编译——ring/aws-lc-rs 在这些目标上不可用。
//! 若把这些签名整体 `#[cfg]` 掉，调用方代码将被 feature 传染，所以保留一个
//! 恒定存在的类型，只把「真正的 TLS 能力」挡在 feature 后面。
//!
//! 语义：占位 `TlsConfig` 可以被构造、被放进 `DialTarget`，但任何尝试真正使用
//! TLS 的路径（`RawDialer::connect` / `RawListener::accept` 的 TLS 分支）都会在
//! 运行时返回 [`crate::TransportError::FeatureDisabled`]——**启动期就失败**，
//! 不会出现「静默降级成明文」这种最坏情况。

/// TLS 配置占位：`tls` feature 关闭时唯一存在的形态。
///
/// 它不携带任何配置（没有 `server`、`verify`、`sni`），因此无法表达「我要
/// 校验这个指纹」。这正是意图：没有 TLS 就没有 TLS 语义。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TlsConfig;

impl TlsConfig {
    /// 恒为 `None`：关闭 `tls` 时没有任何指纹可advertise。
    #[must_use]
    pub const fn advertised_fingerprint(&self) -> Option<[u8; 32]> {
        None
    }

    /// 恒为 `None`：没有服务端配置。
    #[must_use]
    pub const fn fingerprint(&self) -> Option<[u8; 32]> {
        None
    }
}
