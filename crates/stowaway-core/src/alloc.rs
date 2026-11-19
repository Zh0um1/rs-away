//! 节点编号分配。
//!
//! v1 由 admin 侧 `dispatchChildUUID` 分配、子节点通过 `CHILDUUIDREQ`/`RES` 领取
//! （`admin/handler/uuid.go`）。v2 的 `Join{node: UNASSIGNED}` + `JoinAck{node}`
//! 承担同一职责（plan 附录 A 第 3、4 行）。**分配权只在父节点**：子节点不自造
//! 编号，否则两个不通信的分支可能撞号。
//!
//! 编号形状（16 字节）：
//!
//! ```text
//! 53 54 57 32 | salt(4) | seq(8)
//! 'S' 'T' 'W' '2'
//! ```
//!
//! - 首 4 字节是魔数，方便在日志与 `ss -tnp` 里一眼认出是 stowaway 节点；
//! - `salt` 让同一次部署的编号与别人的部署不撞；
//! - `seq` 单调递增，重启后从 1 重来 —— 与 v1 一致（admin 重启后整棵树重建，
//!   `history` 的编号复用前提就是「同一轮 admin 生命周期内」）。
//!
//! 首字节固定为 `0x53`，因此**恒不等于** [`NodeId::UNASSIGNED`]（全零）与
//! [`NodeId::ADMIN`]（全 `0xff`）—— 这两个值是保留值，绝不能被分配出去。

use stowaway_protocol::NodeId;

/// 节点编号前缀（ASCII `STW2`）。
pub const NODE_ID_MAGIC: [u8; 4] = *b"STW2";

/// 单调的节点编号分配器。
#[derive(Clone, Debug)]
pub struct NodeIdAllocator {
    salt: [u8; 4],
    seq: u64,
}

impl NodeIdAllocator {
    /// 用给定盐构造；`seq` 从 0 开始，第一次 [`Self::next`] 返回 1。
    #[must_use]
    pub const fn new(salt: [u8; 4]) -> Self {
        Self { salt, seq: 0 }
    }

    /// 盐（诊断用）。
    #[must_use]
    pub const fn salt(&self) -> [u8; 4] {
        self.salt
    }

    /// 已分配的个数。
    #[must_use]
    pub const fn allocated(&self) -> u64 {
        self.seq
    }

    /// 分配下一个编号。
    ///
    /// `seq` 溢出（2⁶⁴ 次）时回绕到 1 —— 现实中不可能到达，但回绕也不会
    /// 产生保留值，因为首字节是魔数。
    ///
    /// 不实现 `Iterator`：分配是**有副作用的状态推进**，不是迭代；
    /// 叫 `next` 会诱导 `for id in alloc` 这种误用。
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> NodeId {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&NODE_ID_MAGIC);
        bytes[4..8].copy_from_slice(&self.salt);
        bytes[8..].copy_from_slice(&self.seq.to_be_bytes());
        NodeId::new(bytes)
    }

    /// 本分配器发出的编号是否合法（供接收方校验对端自报的编号）。
    ///
    /// 只检查形状，不检查「是不是我发过的」—— 跨父节点的编号本就互不知晓。
    #[must_use]
    pub fn owns(&self, node: NodeId) -> bool {
        let b = node.as_bytes();
        b[..4] == NODE_ID_MAGIC && b[4..8] == self.salt
    }
}

/// 由 secret 摘要派生盐：同一部署的编号空间稳定，跨部署不撞。
#[must_use]
pub fn salt_from_secret(digest: &[u8; 32]) -> [u8; 4] {
    let mut salt = [0u8; 4];
    salt.copy_from_slice(&digest[..4]);
    salt
}

#[cfg(test)]
mod tests {
    use super::{NODE_ID_MAGIC, NodeIdAllocator, salt_from_secret};
    use stowaway_protocol::NodeId;

    #[test]
    fn ids_are_monotonic_and_never_reserved() {
        let mut a = NodeIdAllocator::new([1, 2, 3, 4]);
        let first = a.next();
        let second = a.next();
        assert_ne!(first, second, "连续分配必须不同");
        assert_ne!(first, NodeId::UNASSIGNED, "绝不能分配未分配值");
        assert_ne!(first, NodeId::ADMIN, "绝不能分配 admin 保留值");
        assert!(first.is_assigned());
        assert_ne!(first.as_bytes(), NodeId::ADMIN.as_bytes());
        assert_eq!(a.allocated(), 2);
        // 首个编号的 seq 是 1。
        assert_eq!(first.as_bytes()[..4], NODE_ID_MAGIC);
        assert_eq!(&first.as_bytes()[8..], &1u64.to_be_bytes());
        assert_eq!(&second.as_bytes()[8..], &2u64.to_be_bytes());
    }

    #[test]
    fn allocator_recognises_its_own_ids_only() {
        let mut a = NodeIdAllocator::new([9, 9, 9, 9]);
        let mine = a.next();
        let mut other = NodeIdAllocator::new([7, 7, 7, 7]);
        let theirs = other.next();
        assert!(a.owns(mine), "自己发的一定认得出");
        assert!(!a.owns(theirs), "别人的盐不同，不认");
        assert!(!a.owns(NodeId::ADMIN), "保留值没有魔数");
        assert!(!a.owns(NodeId::UNASSIGNED));
    }

    #[test]
    fn salt_is_derived_from_the_secret_digest() {
        let mut d = [0u8; 32];
        d[0] = 0xaa;
        d[1] = 0xbb;
        d[2] = 0xcc;
        d[3] = 0xdd;
        assert_eq!(salt_from_secret(&d), [0xaa, 0xbb, 0xcc, 0xdd]);
    }
}
