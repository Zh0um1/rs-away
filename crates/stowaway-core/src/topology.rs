//! 拓扑：节点树、编号、链路 epoch 与路由缓存。
//!
//! 权威：`docs/plan.md` §4.7（派发规则）、§4.9（`TopologyActor` 只持元数据）。
//!
//! # 为什么需要 epoch
//!
//! v1 的路由是「每跳把 `route` 冒号串前一段吃掉」，链路上没有任何东西能
//! 判断「这条路由还算不算数」；某条链路断开后，缓存下来的下一跳仍会被
//! 使用，帧被写进一个已经死掉的 socket（或更糟：写进重建后属于别的节点
//! 的链路）。
//!
//! v2 的做法是给「链路集合」一个单调递增的 [`Topology::epoch`]：任何链路
//! 建立/断开都让 epoch +1 并**整体清空**路由缓存。缓存条目自带写入时的
//! epoch，[`Topology::next_hop`] 只认 epoch 相同的条目，因此**不存在**
//! 「过期路由仍被使用」的窗口——即使调用方漏了 `invalidate`，旧条目也会
//! 因为 epoch 不符而被丢弃。

use std::collections::{BTreeMap, BTreeSet, HashMap};

use stowaway_protocol::{NodeId, NodeKind};

use crate::error::{CoreError, Result};

/// 一个节点的拓扑元数据（不含任何 socket / channel）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeMeta {
    /// 节点编号。
    pub node: NodeId,
    /// 上游（父）节点；根节点为 [`NodeId::UNASSIGNED`]。
    pub parent: NodeId,
    /// 到根的深度（根为 0）。
    pub depth: u16,
    /// 角色。
    pub kind: NodeKind,
    /// 该节点面向下游暴露的监听地址（诊断用）。
    pub listen: Option<String>,
    /// 能力位（预留）。
    pub capabilities: u32,
}

impl NodeMeta {
    /// 构造根/子节点元数据。
    #[must_use]
    pub const fn new(node: NodeId, parent: NodeId, depth: u16, kind: NodeKind) -> Self {
        Self {
            node,
            parent,
            depth,
            kind,
            listen: None,
            capabilities: 0,
        }
    }
}

/// 路由缓存条目。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// 下一跳节点。
    pub next_hop: NodeId,
    /// 写入该条目时的拓扑 epoch。
    pub epoch: u64,
}

/// 节点树 + 路由缓存。
///
/// 只保存元数据；链路的读写由 [`crate::link_actor::LinkActor`] 负责。
#[derive(Clone, Debug)]
pub struct Topology {
    me: NodeId,
    root: NodeId,
    max_depth: u16,
    epoch: u64,
    nodes: BTreeMap<NodeId, NodeMeta>,
    children: BTreeMap<NodeId, BTreeSet<NodeId>>,
    route_cache: HashMap<NodeId, RouteEntry>,
}

impl Topology {
    /// 以自己为根建立拓扑（admin 侧、或尚未 Join 的 agent 侧）。
    ///
    /// `max_depth` 用于拒绝无限深的树（v1 没有这个约束，深链会耗尽栈）。
    #[must_use]
    pub fn new(me: NodeId, kind: NodeKind, max_depth: u16) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(me, NodeMeta::new(me, NodeId::UNASSIGNED, 0, kind));
        Self {
            me,
            root: me,
            max_depth,
            epoch: 0,
            nodes,
            children: BTreeMap::new(),
            route_cache: HashMap::new(),
        }
    }

    /// 本节点编号。
    #[must_use]
    pub const fn me(&self) -> NodeId {
        self.me
    }

    /// 根节点编号。
    #[must_use]
    pub const fn root(&self) -> NodeId {
        self.root
    }

    /// 当前拓扑 epoch。
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// 本节点的深度。
    #[must_use]
    pub fn my_depth(&self) -> u16 {
        self.nodes.get(&self.me).map_or(0, |m| m.depth)
    }

    /// 全部节点（按编号有序，便于稳定输出）。
    pub fn nodes(&self) -> impl Iterator<Item = &NodeMeta> {
        self.nodes.values()
    }

    /// 节点数量（含自身）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// 是否只有自己。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    /// 查一个节点。
    #[must_use]
    pub fn get(&self, node: NodeId) -> Option<&NodeMeta> {
        self.nodes.get(&node)
    }

    /// 某节点的直接子节点。
    #[must_use]
    pub fn children_of(&self, node: NodeId) -> Vec<NodeId> {
        self.children
            .get(&node)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// 自己的直接子节点。
    #[must_use]
    pub fn my_children(&self) -> Vec<NodeId> {
        self.children_of(self.me)
    }

    /// 某节点的全部后代（广度优先，不含自身）。
    #[must_use]
    pub fn descendants_of(&self, node: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut frontier = vec![node];
        while let Some(cur) = frontier.pop() {
            for child in self.children_of(cur) {
                if out.contains(&child) {
                    continue;
                }
                out.push(child);
                frontier.push(child);
            }
        }
        out
    }

    /// 声明本节点的上游（父）节点：把自己从根降为它的孩子。
    ///
    /// agent 连上 admin 后调用；与 [`Self::insert`] 的区别是这里改变的是
    /// **本节点自己**的位置（`insert` 只登记别人）。
    ///
    /// # Errors
    /// 上游节点与本节点相同（[`CoreError::Cycle`]）。
    pub fn attach_upstream(&mut self, parent: NodeId, kind: NodeKind) -> Result<()> {
        if parent == self.me {
            return Err(CoreError::Cycle { node: parent });
        }
        // 上游先作为新的根（深度 0）登记，再把我挂到它下面。
        self.nodes
            .entry(parent)
            .or_insert_with(|| NodeMeta::new(parent, NodeId::UNASSIGNED, 0, kind));
        if let Some(me) = self.nodes.get_mut(&self.me) {
            me.parent = parent;
            me.depth = 1;
        }
        self.children.entry(parent).or_default().insert(self.me);
        self.root = parent;
        self.invalidate();
        Ok(())
    }

    /// 登记一个节点。重复登记要区分「完全一样」与「元数据冲突」。
    ///
    /// # Errors
    /// 已存在且元数据不同（[`CoreError::DuplicateNode`]）、父节点未知
    /// （[`CoreError::UnknownNode`]）、超过 `max_depth`（[`CoreError::MaxDepth`]）、
    /// 自己成为自己的祖先（[`CoreError::Cycle`]）。
    pub fn insert(&mut self, meta: NodeMeta) -> Result<()> {
        if meta.node == self.me {
            return Err(CoreError::DuplicateNode { node: meta.node });
        }
        if meta.parent == NodeId::UNASSIGNED {
            return Err(CoreError::UnknownNode { node: meta.parent });
        }
        let parent_depth = self
            .nodes
            .get(&meta.parent)
            .ok_or(CoreError::UnknownNode { node: meta.parent })?
            .depth;
        let depth = parent_depth.saturating_add(1);
        // 深度由拓扑计算，调用方传什么都不该影响「是否同一条登记」。
        let mut meta = meta;
        meta.depth = depth;
        if let Some(existing) = self.nodes.get(&meta.node) {
            if *existing == meta {
                return Ok(());
            }
            return Err(CoreError::DuplicateNode { node: meta.node });
        }
        if depth > self.max_depth {
            return Err(CoreError::MaxDepth {
                depth,
                max: self.max_depth,
            });
        }
        // 环检测：新节点的后代里不可能已经有自己（刚插入，无子节点），
        // 但父链必须能走到根，否则说明元数据本身是坏的。
        if !self.has_path_to_root(meta.parent) {
            return Err(CoreError::Cycle { node: meta.node });
        }
        self.nodes.insert(meta.node, meta.clone());
        self.children
            .entry(meta.parent)
            .or_default()
            .insert(meta.node);
        Ok(())
    }

    /// 父链是否能走到已登记的根。
    fn has_path_to_root(&self, from: NodeId) -> bool {
        let mut cur = from;
        let mut hops = 0usize;
        loop {
            if cur == self.root {
                return true;
            }
            let Some(meta) = self.nodes.get(&cur) else {
                return false;
            };
            if hops > self.nodes.len() {
                return false;
            }
            hops += 1;
            cur = meta.parent;
            if cur == NodeId::UNASSIGNED {
                return cur == self.root;
            }
        }
    }

    /// 移除一个节点及其全部后代。
    ///
    /// 返回被移除的节点列表（含根被移除的那个）。
    pub fn remove(&mut self, node: NodeId) -> Vec<NodeId> {
        if node == self.me {
            return Vec::new();
        }
        let mut removed = vec![node];
        removed.extend(self.descendants_of(node));
        for id in &removed {
            if let Some(meta) = self.nodes.remove(id)
                && let Some(siblings) = self.children.get_mut(&meta.parent)
            {
                siblings.remove(id);
            }
            self.children.remove(id);
            self.route_cache.remove(id);
        }
        removed
    }

    /// 改父节点（重连/迁移时用）。成功后 epoch 递增。
    ///
    /// # Errors
    /// 节点未知、目标父未知、成环、超深。
    pub fn reparent(&mut self, node: NodeId, parent: NodeId) -> Result<()> {
        if node == self.me {
            return Err(CoreError::DuplicateNode { node });
        }
        let old = self
            .nodes
            .get(&node)
            .cloned()
            .ok_or(CoreError::UnknownNode { node })?;
        if !self.nodes.contains_key(&parent) {
            return Err(CoreError::UnknownNode { node: parent });
        }
        let new_depth = self
            .nodes
            .get(&parent)
            .map_or(0, |p| p.depth.saturating_add(1));
        if new_depth > self.max_depth {
            return Err(CoreError::MaxDepth {
                depth: new_depth,
                max: self.max_depth,
            });
        }
        // 不能把节点挂到自己的后代下面。
        if parent == node || self.descendants_of(node).contains(&parent) {
            return Err(CoreError::Cycle { node });
        }
        if let Some(siblings) = self.children.get_mut(&old.parent) {
            siblings.remove(&node);
        }
        self.children.entry(parent).or_default().insert(node);
        if let Some(meta) = self.nodes.get_mut(&node) {
            meta.parent = parent;
            meta.depth = new_depth;
        }
        // 深度变化会波及整棵子树。
        let subtree = self.descendants_of(node);
        for id in subtree {
            let parent_depth = self
                .nodes
                .get(&id)
                .and_then(|m| self.nodes.get(&m.parent))
                .map_or(0, |p| p.depth);
            if let Some(meta) = self.nodes.get_mut(&id) {
                meta.depth = parent_depth.saturating_add(1);
            }
        }
        self.invalidate();
        Ok(())
    }

    /// 链路集合发生变化：epoch +1 并清空路由缓存。
    ///
    /// 任何「本节点与某个邻居的链路」建立或断开都必须调用它。
    pub fn invalidate(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.route_cache.clear();
    }

    /// 路由缓存条目数（诊断用）。
    #[must_use]
    pub fn cached_routes(&self) -> usize {
        self.route_cache.len()
    }

    /// 计算并缓存到 `dest` 的下一跳。
    ///
    /// 规则（`docs/plan.md` §4.7 第 3 步）：
    /// - `dest == me` → 无下一跳（本地派发，返回 `None`）；
    /// - `dest` 是本节点的后代 → 沿着子节点方向的第一个孩子；
    /// - 否则 → 上行父节点（树形拓扑里「向上再向下」）。
    ///
    /// # Errors
    /// 目标未知（[`CoreError::UnknownNode`]）。
    pub fn next_hop(&mut self, dest: NodeId) -> Result<Option<NodeId>> {
        if dest == self.me {
            return Ok(None);
        }
        if let Some(entry) = self.route_cache.get(&dest) {
            if entry.epoch == self.epoch {
                return Ok(Some(entry.next_hop));
            }
            // 过期条目：即使调用方忘了 invalidate 也不会被误用。
            self.route_cache.remove(&dest);
        }
        let hop = self.compute_next_hop(dest)?;
        self.route_cache.insert(
            dest,
            RouteEntry {
                next_hop: hop,
                epoch: self.epoch,
            },
        );
        Ok(Some(hop))
    }

    fn compute_next_hop(&self, dest: NodeId) -> Result<NodeId> {
        // 目标不在本节点的拓扑视图里 → 不可达（不是编程错误）。
        if !self.nodes.contains_key(&dest) {
            return Err(CoreError::Undeliverable { dest });
        }
        // 先把「我从自己往上到根」的祖先链列出来：目标若在其中，说明它在
        // 我的上方，下一跳就是我的父节点。
        //
        // 注意不能反过来「从 dest 往上找自己」——根节点的 parent 是
        // UNASSIGNED，反向遍历在根处就断了，会把「去根」误判成不在同一棵树。
        let mut upward = BTreeSet::new();
        let mut cur = self.me;
        let mut guard = 0usize;
        while let Some(meta) = self.nodes.get(&cur) {
            if meta.parent == NodeId::UNASSIGNED || guard > self.nodes.len() {
                break;
            }
            guard += 1;
            cur = meta.parent;
            upward.insert(cur);
        }
        if upward.contains(&dest) {
            let me = self
                .nodes
                .get(&self.me)
                .ok_or(CoreError::UnknownNode { node: self.me })?;
            return Ok(me.parent);
        }
        // 目标在我的子树里：找出「我 → 目标」路径上的第一个孩子。
        let mut cursor = dest;
        let mut guard = 0usize;
        loop {
            let Some(meta) = self.nodes.get(&cursor) else {
                return Err(CoreError::Undeliverable { dest });
            };
            if meta.parent == self.me && cursor != self.me {
                return Ok(cursor);
            }
            if cursor == self.me || meta.parent == NodeId::UNASSIGNED || guard > self.nodes.len() {
                break;
            }
            guard += 1;
            cursor = meta.parent;
        }
        // 目标在我的上方：交给我的父节点。
        let me = self
            .nodes
            .get(&self.me)
            .ok_or(CoreError::UnknownNode { node: self.me })?;
        if me.parent == NodeId::UNASSIGNED {
            // 根节点没有上行链路，目标又不在自己的子树里 → 不可达。
            return Err(CoreError::Undeliverable { dest });
        }
        Ok(me.parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> NodeId {
        let mut b = [0u8; 16];
        b[0] = n;
        NodeId(b)
    }

    fn admin() -> Topology {
        Topology::new(NodeId::ADMIN, NodeKind::Admin, 8)
    }

    #[test]
    fn admin_routes_to_descendants_and_up_is_undeliverable() {
        let mut t = admin();
        t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("insert");
        t.insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
            .expect("insert");
        assert_eq!(t.next_hop(id(1)).expect("hop"), Some(id(1)));
        assert_eq!(t.next_hop(id(2)).expect("hop"), Some(id(1)));
        assert!(t.next_hop(NodeId::UNASSIGNED).is_err());
        // 根节点没有上行链路。
        let err = t.next_hop(id(9)).expect_err("unreachable");
        assert!(matches!(err, CoreError::Undeliverable { .. }));
    }

    #[test]
    fn agent_routes_up_and_down() {
        // 真实树：ADMIN 根，1 是它的孩子，2 是 1 的孩子。
        let mut t = admin();
        t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("insert");
        t.insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
            .expect("insert");
        // 站在根上，去 2 必须先下到 1。
        assert_eq!(t.next_hop(id(1)).expect("hop"), Some(id(1)));
        assert_eq!(t.next_hop(id(2)).expect("hop"), Some(id(1)));
        assert_eq!(t.descendants_of(NodeId::ADMIN), vec![id(1), id(2)]);
    }

    #[test]
    fn epoch_bump_invalidates_cached_routes() {
        let mut t = admin();
        t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("insert");
        assert_eq!(t.next_hop(id(1)).expect("hop"), Some(id(1)));
        assert_eq!(t.cached_routes(), 1);
        let epoch_before = t.epoch();
        t.invalidate();
        assert_eq!(t.epoch(), epoch_before + 1);
        assert_eq!(t.cached_routes(), 0);
        // 重新计算仍然正确。
        assert_eq!(t.next_hop(id(1)).expect("hop"), Some(id(1)));
    }

    #[test]
    fn stale_cache_entry_is_never_used_even_without_invalidate() {
        let mut t = admin();
        t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("insert");
        t.insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
            .expect("insert");
        assert_eq!(t.next_hop(id(2)).expect("hop"), Some(id(1)));
        // 手工篡改 epoch（模拟「链路变了但调用方忘了 invalidate」），
        // 再把 2 挂到另一个孩子 3 下面 —— 旧条目必须失效。
        t.epoch = t.epoch.wrapping_add(1);
        t.insert(NodeMeta::new(id(3), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("insert");
        t.reparent(id(2), id(3)).expect("reparent");
        assert_eq!(t.next_hop(id(2)).expect("hop"), Some(id(3)));
    }

    #[test]
    fn duplicate_insert_rejects_conflicting_metadata() {
        let mut t = admin();
        let meta = NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent);
        t.insert(meta.clone()).expect("first insert");
        t.insert(meta).expect("identical insert is idempotent");
        let mut other = NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent);
        other.capabilities = 7;
        let err = t.insert(other).expect_err("conflict");
        assert!(matches!(err, CoreError::DuplicateNode { .. }));
    }

    #[test]
    fn depth_limit_is_enforced() {
        let mut t = Topology::new(NodeId::ADMIN, NodeKind::Admin, 2);
        t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("depth 1");
        t.insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
            .expect("depth 2");
        let err = t
            .insert(NodeMeta::new(id(3), id(2), 0, NodeKind::Agent))
            .expect_err("depth 3 exceeds max 2");
        assert!(matches!(err, CoreError::MaxDepth { depth: 3, max: 2 }));
    }

    #[test]
    fn reparent_rejects_cycles() {
        let mut t = admin();
        t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("insert");
        t.insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
            .expect("insert");
        let err = t.reparent(id(1), id(2)).expect_err("cycle");
        assert!(matches!(err, CoreError::Cycle { .. }));
    }

    #[test]
    fn remove_cascades_to_descendants() {
        let mut t = admin();
        t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("insert");
        t.insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
            .expect("insert");
        let removed = t.remove(id(1));
        assert_eq!(removed.len(), 2);
        assert!(t.get(id(1)).is_none());
        assert!(t.get(id(2)).is_none());
        assert!(t.next_hop(id(2)).is_err());
    }
}
