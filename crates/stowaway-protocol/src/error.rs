//! 协议层错误类型。
//!
//! 所有解析路径都必须返回 `Err` 而不是 panic（缺陷 #1–#4 的回归基线，
//! 见 docs/plan.md §3 与 §8.6）。

use thiserror::Error;

/// 协议层错误。**不得**包含载荷原文，避免日志泄漏密文或密钥材料。
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// 缓冲区在字段中途耗尽。
    #[error("帧截断：需要 {need} 字节，剩余 {have} 字节（字段 {field}）")]
    Truncated {
        /// 期望读取的字节数。
        need: usize,
        /// 实际剩余字节数。
        have: usize,
        /// 出错字段名，便于 fuzz 归因。
        field: &'static str,
    },

    /// varint 超过 10 字节或超出目标类型。
    #[error("varint 非法：{reason}")]
    BadVarint {
        /// 说明。
        reason: &'static str,
    },

    /// 版本不是 [`crate::VERSION`]。
    #[error("不支持的版本 {actual}（期望 {expected}）")]
    BadVersion {
        /// 实际读到的版本号。
        actual: u8,
        /// 期望版本号。
        expected: u8,
    },

    /// 魔数不匹配。
    #[error("魔数不匹配")]
    BadMagic,

    /// `flags` 含未定义的位。
    #[error("未知 flags 位：0x{value:02x}")]
    BadFlags {
        /// 实际字节。
        value: u8,
    },

    /// 未知消息类型（未在 [`crate::MsgType`] 中定义）。
    #[error("未知消息类型 {msg_type}")]
    UnknownMsgType {
        /// 实际类型值。
        msg_type: u16,
    },

    /// `via_count` 超过 [`crate::MAX_VIA`]。
    #[error("via_count {actual} 超过上限 {max}")]
    TooManyVia {
        /// 实际个数。
        actual: usize,
        /// 上限。
        max: usize,
    },

    /// `payload_len` 超过 [`crate::MAX_FRAME`]。
    #[error("payload_len {actual} 超过上限 {max}")]
    PayloadTooLarge {
        /// 实际长度。
        actual: usize,
        /// 上限。
        max: usize,
    },

    /// 消息载荷的 postcard 解码/编码失败。
    #[error("消息载荷编解码失败：{0}")]
    Payload(String),

    /// 帧尾部有多余字节（严格解析，拒绝同一 TCP 段内拼接的隐式边界）。
    #[error("帧尾部有 {bytes} 字节多余数据")]
    TrailingBytes {
        /// 多余字节数。
        bytes: usize,
    },

    /// 握手报文与期望的 flight 不符（越权跳步）。
    #[error("握手顺序错误：期望 {expected}，收到 {actual}")]
    HandshakeOrder {
        /// 期望的 flight 名。
        expected: &'static str,
        /// 实际收到的 flight 名。
        actual: &'static str,
    },

    /// 枚举字段出现未定义取值（schema 冻结，不允许隐式扩展）。
    #[error("{ty} 的取值 {value} 未定义")]
    UnknownEnumValue {
        /// 枚举类型名（`stringify!` 得到）。
        ty: &'static str,
        /// 实际取值。
        value: u64,
    },

    /// 握手字段取值非法（角色、传输类型、长度等）。
    #[error("握手字段非法：{0}")]
    HandshakeField(&'static str),
}

/// 便捷别名。
pub type Result<T> = core::result::Result<T, ProtocolError>;
