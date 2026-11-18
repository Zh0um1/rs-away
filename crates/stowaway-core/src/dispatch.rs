//! 本地派发与转发的决策函数（纯函数，便于穷举测试）。
//!
//! 权威：`docs/plan.md` §4.7 的四步派发规则，v1 的
//! `agent/process/process.go` 里 `changeRoute` 只做「吃一段冒号串」，
//! 既不知道下一跳是否还活着，也不会回不可达通知。
//!
//! ```text
//! 收到帧 F：
//!   1. F.dest == me 且 F.via 为空          → Local      （本地派发）
//!   2. F.via 非空                          → Forward(via[0]) + via 左移
//!   3. 否则查 route_cache[dest]            → Forward(下一跳)
//!   4. 查不到                              → Undeliverable（回 NodeStatus）
//! ```
//!
//! 第 2 步优先于第 3 步：显式 source route 是发起方的意志，中间节点无权
//! 改写（plan §4.7「不改 payload」）。只有 `via` 走空后才轮到本地缓存。

use stowaway_protocol::{NodeId, NodeScope, NodeState};

use crate::error::{CoreError, Result};
use crate::topology::Topology;

/// 一帧的去向。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// 交本地的会话/服务处理（中间节点永远拿不到这个结果）。
    Local,
    /// 转发给指定下一跳，`via` 已按需左移。
    Forward {
        /// 下一跳。
        next_hop: NodeId,
        /// 转发时要写回帧头的 `via`（已去掉被消费的一跳）。
        via: Vec<NodeId>,
    },
    /// 不可达，应向来源回 `NodeStatus{Undeliverable}`。
    Undeliverable,
}

/// 决定一帧的去向。
///
/// `dest` 与 `via` 来自帧头；`me` 是本节点编号。纯函数视角的
/// [`Topology::next_hop`] 会被调用（它会写路由缓存），因此需要 `&mut`。
///
/// # Errors
/// 只有在缓存/拓扑内部不一致时才返回错误；「目标不可达」是正常结果
/// （[`Route::Undeliverable`]），不是错误——这样才能把不可达变成一条
/// 可观察的 `NodeStatus` 消息，而不是静默丢弃（缺陷 #11）。
pub fn decide(topology: &mut Topology, me: NodeId, dest: NodeId, via: &[NodeId]) -> Result<Route> {
    // 1. 目标是我，且没有 source route 提示要先绕行。
    if dest == me && via.is_empty() {
        return Ok(Route::Local);
    }
    // 2. 显式 source route：跳到第一跳，剩下的留回去。
    if let Some((first, rest)) = via.split_first() {
        if *first == me {
            // 路由把我自己写成下一跳属于发起方的错误；宁可报不可达，
            // 也不要把帧再绕回自己（v1 在这里会不断自我转发）。
            return Ok(Route::Undeliverable);
        }
        return Ok(Route::Forward {
            next_hop: *first,
            via: rest.to_vec(),
        });
    }
    // 3. 查路由缓存（epoch 由拓扑自己把关）。
    if dest == me {
        // via 为空且 dest 是我，前面已处理；这里只是防御性兜底。
        return Ok(Route::Local);
    }
    match topology.next_hop(dest) {
        Ok(Some(hop)) => Ok(Route::Forward {
            next_hop: hop,
            via: Vec::new(),
        }),
        Ok(None) => Ok(Route::Local),
        Err(CoreError::Undeliverable { .. } | CoreError::UnknownNode { .. }) => {
            Ok(Route::Undeliverable)
        }
        Err(other) => Err(other),
    }
}

/// 不可达时应当发回的 `NodeStatus`。
#[must_use]
pub fn undeliverable_status(dest: NodeId, scope: NodeScope) -> stowaway_protocol::NodeStatus {
    stowaway_protocol::NodeStatus {
        scope,
        state: NodeState::Undeliverable,
        node: dest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{NodeMeta, Topology};
    use stowaway_protocol::NodeKind;

    fn id(n: u8) -> NodeId {
        let mut b = [0u8; 16];
        b[0] = n;
        NodeId(b)
    }

    fn tree() -> Topology {
        let mut t = Topology::new(NodeId::ADMIN, NodeKind::Admin, 8);
        t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("insert");
        t.insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
            .expect("insert");
        t
    }

    #[test]
    fn frame_for_me_is_local() {
        let mut t = tree();
        let route = decide(&mut t, NodeId::ADMIN, NodeId::ADMIN, &[]).expect("decide");
        assert_eq!(route, Route::Local);
    }

    #[test]
    fn explicit_via_wins_over_route_cache() {
        let mut t = tree();
        // 目标 2 的缓存下一跳是 1，但 via 指定先到 2 自己（假设的绕行）。
        let route = decide(&mut t, NodeId::ADMIN, id(2), &[id(2), id(1)]).expect("decide");
        assert_eq!(
            route,
            Route::Forward {
                next_hop: id(2),
                via: vec![id(1)]
            }
        );
    }

    #[test]
    fn via_consumes_one_hop_at_a_time() {
        let mut t = tree();
        let route = decide(&mut t, NodeId::ADMIN, id(2), &[id(1), id(2)]).expect("decide");
        let Route::Forward { next_hop, via } = route else {
            panic!("expected forward");
        };
        assert_eq!(next_hop, id(1));
        assert_eq!(via, vec![id(2)]);
        // 第二跳收到时 via 只剩 [2]，消费后变空，之后按 dest 判定。
        let route2 = decide(&mut t, id(1), id(2), &via).expect("decide");
        assert_eq!(
            route2,
            Route::Forward {
                next_hop: id(2),
                via: Vec::new()
            }
        );
    }

    #[test]
    fn via_pointing_at_me_is_undeliverable_not_a_loop() {
        let mut t = tree();
        let route = decide(&mut t, NodeId::ADMIN, id(2), &[NodeId::ADMIN]).expect("decide");
        assert_eq!(route, Route::Undeliverable);
    }

    #[test]
    fn unknown_dest_is_undeliverable_not_silent_drop() {
        let mut t = tree();
        let route = decide(&mut t, NodeId::ADMIN, id(9), &[]).expect("decide");
        assert_eq!(route, Route::Undeliverable);
        let status = undeliverable_status(id(9), NodeScope::Node);
        assert_eq!(status.state, NodeState::Undeliverable);
        assert_eq!(status.node, id(9));
    }

    #[test]
    fn route_cache_hit_avoids_recompute() {
        let mut t = tree();
        let _ = decide(&mut t, NodeId::ADMIN, id(2), &[]).expect("decide");
        assert_eq!(t.cached_routes(), 1);
        // 第二次走缓存；结果必须一致。
        let route = decide(&mut t, NodeId::ADMIN, id(2), &[]).expect("decide");
        assert_eq!(
            route,
            Route::Forward {
                next_hop: id(1),
                via: Vec::new()
            }
        );
    }

    #[test]
    fn epoch_bump_changes_route_after_topology_shift() {
        let mut t = tree();
        let before = decide(&mut t, NodeId::ADMIN, id(2), &[]).expect("decide");
        assert_eq!(
            before,
            Route::Forward {
                next_hop: id(1),
                via: Vec::new()
            }
        );
        // 2 改挂到新孩子 3 下面：链路变化 → epoch+1 → 缓存整体失效。
        t.insert(NodeMeta::new(id(3), NodeId::ADMIN, 0, NodeKind::Agent))
            .expect("insert");
        t.reparent(id(2), id(3)).expect("reparent");
        let after = decide(&mut t, NodeId::ADMIN, id(2), &[]).expect("decide");
        assert_eq!(
            after,
            Route::Forward {
                next_hop: id(3),
                via: Vec::new()
            }
        );
    }
}
