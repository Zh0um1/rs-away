//! 节点标识与角色。

use core::fmt;
use serde::{Deserialize, Serialize};

/// 节点 ID：16 字节定长（取代 v1 的 10 字节 `Sender`/`Accepter` 与 UUID 字符串）。
///
/// 定长才能零拷贝解析，且 `dest`/`via` 都不再需要长度前缀
/// （docs/plan.md §4.4 解析约束）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 16]);

impl NodeId {
    /// 全零占位，等价 v1 的 `TEMP_UUID` 语义（仅用于「尚未分配」）。
    pub const UNASSIGNED: Self = Self([0u8; 16]);

    /// 广播占位，等价 v1 的 `ADMIN_UUID`（admin 作为根，恒为全 `0xff`）。
    pub const ADMIN: Self = Self([0xffu8; 16]);

    /// 从字节构造。
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// 原始字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// 是否已分配（非全零）。
    #[must_use]
    pub fn is_assigned(&self) -> bool {
        self.0 != [0u8; 16]
    }

    /// 控制台显示用短 ID（前 4 字节 hex，8 个字符）。
    #[must_use]
    pub fn short(&self) -> String {
        let mut s = String::with_capacity(8);
        for b in &self.0[..4] {
            // `{:02x}` 不可能失败，且不需要 `char::from_digit` 的 Option 分支。
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::ADMIN {
            f.write_str("NodeId(ADMIN)")
        } else if *self == Self::UNASSIGNED {
            f.write_str("NodeId(UNASSIGNED)")
        } else {
            write!(f, "NodeId({})", self.short())
        }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// 节点角色。admin 是树根且唯一，agent 可级联。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeKind {
    /// 控制端（v1 的 admin）。作为 `Default` 以便消息结构体可 `derive(Default)`。
    #[default]
    Admin = 0,
    /// 被控端（v1 的 agent），可继续挂子节点。
    Agent = 1,
}

impl NodeKind {
    /// 线编码。
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        self as u8
    }

    /// 线解码。
    #[must_use]
    pub const fn from_wire_id(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Admin),
            1 => Some(Self::Agent),
            _ => None,
        }
    }

    /// 是否为 admin。
    #[must_use]
    pub const fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }
}

/// 会话复合键：`(发起方, 序号)`。
///
/// v1 只用单个 `Seq`，而 SOCKS 由 admin 分配、backward 由 agent 分配，
/// `connect` 桥接两侧可能撞号（docs/plan.md §4.8）。
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, Serialize, Deserialize,
)]
pub struct SessionKey {
    /// 发起会话的节点。
    pub origin: NodeId,
    /// 发起方自增序号，从 1 开始（0 保留）。
    pub id: u64,
}

impl SessionKey {
    /// 构造。
    #[must_use]
    pub const fn new(origin: NodeId, id: u64) -> Self {
        Self { origin, id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodeid_short_is_8_hex_chars() {
        let id = NodeId::new([
            0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ]);
        assert_eq!(id.short(), "deadbeef");
        assert!(id.is_assigned());
        assert_eq!(NodeId::UNASSIGNED.short(), "00000000");
        assert!(!NodeId::UNASSIGNED.is_assigned());
    }

    #[test]
    fn admin_marker_is_all_ff() {
        assert_eq!(NodeId::ADMIN.0, [0xff; 16]);
        assert_eq!(format!("{}", NodeId::ADMIN), "NodeId(ADMIN)");
        assert_eq!(format!("{}", NodeId::UNASSIGNED), "NodeId(UNASSIGNED)");
    }

    #[test]
    fn session_key_not_ordered_by_origin_only() {
        // origin 相同、id 不同必须相等比较正确（复合键的意义）。
        let a = SessionKey::new(NodeId::ADMIN, 1);
        let b = SessionKey::new(NodeId::ADMIN, 2);
        assert_ne!(a, b);
        assert!(a < b);
    }
}
