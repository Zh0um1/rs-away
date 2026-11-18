//! 传输层错误。
//!
//! 约定：**任何错误都不 panic**（plan.md §3 缺陷 #1–#4 的回归要求）。
//! IO 错误一律保留 `ErrorKind`，上层据此区分「对端关闭」「对端重置」「超时」。

use std::io;

/// 传输层错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// 底层 IO 失败。
    #[error("IO 失败：{0}")]
    Io(#[from] io::Error),

    /// 传输规格非法。
    #[error("传输规格非法：{0}")]
    Spec(#[from] crate::SpecError),

    /// TLS 配置或握手失败。
    #[error("TLS 失败：{0}")]
    Tls(String),

    /// 证书指纹不匹配（`--tls-pin` 校验失败）。
    #[error("证书指纹不匹配：期望 {expected}，实际 {actual}")]
    PinMismatch {
        /// 期望的指纹（`sha256:<hex>`）。
        expected: String,
        /// 实际观察到的指纹。
        actual: String,
    },

    /// 对端证书缺失。
    #[error("对端未提供证书")]
    NoPeerCertificate,

    /// 帧编解码失败。
    #[error("帧编解码失败：{0}")]
    Protocol(#[from] stowaway_protocol::ProtocolError),

    /// 握手（3-flight）失败。
    #[error("握手失败：{0}")]
    Handshake(#[from] stowaway_crypto::HandshakeError),

    /// 密封层失败。
    #[error("密封层失败：{0}")]
    Sealer(#[from] stowaway_crypto::SealerError),

    /// 握手顺序错误（对端发了不属于当前阶段的帧）。
    #[error("握手顺序错误：期望 {expected}，收到 {actual}")]
    HandshakeOrder {
        /// 期望的消息类型。
        expected: &'static str,
        /// 实际收到的消息类型。
        actual: &'static str,
    },

    /// 单帧超过链路可承载上限且无法分片。
    #[error("单帧 {actual} 字节超过链路上限 {max} 字节")]
    FrameTooLarge {
        /// 实际长度。
        actual: usize,
        /// 上限。
        max: usize,
    },

    /// 未启用的传输。
    #[error("传输 `{kind}` 未编译进本二进制（缺 feature `{feature}`）")]
    FeatureDisabled {
        /// 传输种类名。
        kind: &'static str,
        /// 需要的 feature。
        feature: &'static str,
    },

    /// 嗅探失败（既不是 STW2 也不是 HTTP 升级）。
    #[error("首字节嗅探无法识别对端协议（首 {peeked} 字节：{hex}）")]
    UnrecognizedPeer {
        /// 已 peek 的字节数。
        peeked: usize,
        /// 十六进制预览。
        hex: String,
    },

    /// 端口复用回落（由上层决定是否转发）。
    #[error("非本协议流量，需端口复用回落（首 {peeked} 字节：{hex}）")]
    ReuseFallback {
        /// 已 peek 的字节数。
        peeked: usize,
        /// 十六进制预览。
        hex: String,
    },
}

/// 结果别名。
pub type Result<T> = std::result::Result<T, TransportError>;

impl TransportError {
    /// 是否属于「对端断开」类错误（可重连，不算故障）。
    #[must_use]
    pub fn is_disconnect(&self) -> bool {
        match self {
            Self::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
            ),
            _ => false,
        }
    }
}

/// 把 [`SSpecError`](crate::SpecError) 之类的 `Display` 值转成 `io::Error`。
#[cfg_attr(not(feature = "transport-raw"), allow(dead_code))]
pub(crate) fn invalid_input(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}
