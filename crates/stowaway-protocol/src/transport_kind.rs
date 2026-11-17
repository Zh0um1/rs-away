//! 传输类型枚举（协议层视角）。
//!
//! 与 `stowaway-transport::TransportKind` 同构，但**协议 crate 不依赖 transport**
//! （依赖方向单向，见 docs/plan.md §4.1）。这里只保留握手需要的线编码
//! `wire_id()` 与 `transport.md` §3 的 `is_datagram_backed()` 判据。

use serde::{Deserialize, Serialize};

/// 承载 v2 帧的连接类型。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum TransportKind {
    /// 裸 TCP（`raw://`）。
    #[default]
    Raw = 1,
    /// WebSocket over TCP（`ws://`）。
    Ws = 2,
    /// KCP over UDP（`kcp://`，feature `transport-kcp`，默认关）。
    Kcp = 3,
    /// QUIC（占位，v2 不实现）。
    Quic = 4,
}

impl TransportKind {
    /// 线编码。**只追加，不复用旧值**（握手 transcript 绑定此值，
    /// 篡改会导致 proof 校验失败，见 docs/plan.md §4.5）。
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        self as u8
    }

    /// 线解码；未知值返回 `None`（由调用方转成 `HandshakeField` 错误）。
    #[must_use]
    pub const fn from_wire_id(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Raw),
            2 => Some(Self::Ws),
            3 => Some(Self::Kcp),
            4 => Some(Self::Quic),
            _ => None,
        }
    }

    /// 是否基于数据报：决定 `LinkMeta::max_frame` 与重传语义。
    #[must_use]
    pub const fn is_datagram_backed(self) -> bool {
        matches!(self, Self::Kcp | Self::Quic)
    }

    /// 人类可读名（用于日志与控制台）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Ws => "ws",
            Self::Kcp => "kcp",
            Self::Quic => "quic",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_ids_are_stable_and_distinct() {
        assert_eq!(TransportKind::Raw.wire_id(), 1);
        assert_eq!(TransportKind::Ws.wire_id(), 2);
        assert_eq!(TransportKind::Kcp.wire_id(), 3);
        assert_eq!(TransportKind::Quic.wire_id(), 4);
        for k in [
            TransportKind::Raw,
            TransportKind::Ws,
            TransportKind::Kcp,
            TransportKind::Quic,
        ] {
            assert_eq!(TransportKind::from_wire_id(k.wire_id()), Some(k));
        }
        assert_eq!(TransportKind::from_wire_id(0), None);
        assert_eq!(TransportKind::from_wire_id(5), None);
        assert_eq!(TransportKind::from_wire_id(255), None);
    }

    #[test]
    fn datagram_backed_flags() {
        assert!(!TransportKind::Raw.is_datagram_backed());
        assert!(!TransportKind::Ws.is_datagram_backed());
        assert!(TransportKind::Kcp.is_datagram_backed());
        assert!(TransportKind::Quic.is_datagram_backed());
    }
}
