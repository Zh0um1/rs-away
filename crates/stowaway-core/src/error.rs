//! `stowaway-core` 的错误类型。
//!
//! 与 v1 的关键差别：**任何失败都必须可传播**。v1 在路由为空时静默丢弃
//! （`docs/plan.md` §4.7「不可达不再静默」），并把多处错误吞成空 payload
//! （§3 缺陷 #8/#9）。本模块的错误类型不接受「用零值表示失败」。

use stowaway_protocol::{NodeId, SessionKey};
use stowaway_transport::TransportError;

/// 拓扑、路由、会话与链路 actor 的错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// 帧层/协议层错误。
    #[error("协议错误：{0}")]
    Protocol(#[from] stowaway_protocol::ProtocolError),

    /// 传输层错误。
    #[error("传输错误：{0}")]
    Transport(#[from] TransportError),

    /// 底层 I/O 错误。
    #[error("I/O 错误：{0}")]
    Io(#[from] std::io::Error),

    /// 目标节点不在本节点可见的拓扑里。
    #[error("未知节点：{node}")]
    UnknownNode {
        /// 相关节点。
        node: NodeId,
    },

    /// 重复加入：同一个 `NodeId` 已存在于拓扑中。
    #[error("节点重复加入：{node}")]
    DuplicateNode {
        /// 相关节点。
        node: NodeId,
    },

    /// 声称的父节点不符合既有父子关系。
    #[error("节点 {node} 的父节点不是 {parent}")]
    NotChild {
        /// 声明的父节点。
        parent: NodeId,
        /// 子节点。
        node: NodeId,
    },

    /// 拓扑成环（v1 没有任何防护，靠人工保证）。
    #[error("拓扑成环：{node} 是自身的祖先")]
    Cycle {
        /// 相关节点。
        node: NodeId,
    },

    /// 超出部署上限的树深（`--max-depth`，默认 8）。
    #[error("树深超限：depth={depth}，上限 {max}")]
    MaxDepth {
        /// 实际深度。
        depth: u16,
        /// 配置上限。
        max: u16,
    },

    /// 目标不可达（派发规则第 4 步：回 `NodeStatus{Undeliverable}` 而非丢弃）。
    #[error("目标不可达：{dest}")]
    Undeliverable {
        /// 目标节点。
        dest: NodeId,
    },

    /// 会话键冲突（`SessionKey{origin, id}` 本应唯一）。
    #[error("会话已存在：{key:?}")]
    SessionExists {
        /// 会话键。
        key: SessionKey,
    },

    /// 会话不存在（迟到的 `SessionData`/`SessionClose`）。
    #[error("未知会话：{key:?}")]
    UnknownSession {
        /// 会话键。
        key: SessionKey,
    },

    /// 输出队列已满：调用方必须等待（背压而不是无界缓存）。
    #[error("链路输出队列已满（背压）")]
    Backpressure,

    /// 链路 actor 已退出。
    #[error("链路已关闭")]
    LinkClosed,
}

impl CoreError {
    /// 是否属于「对端断开」这类可预期错误（不应当作 bug 上报）。
    #[must_use]
    pub fn is_disconnect(&self) -> bool {
        match self {
            Self::Transport(e) => e.is_disconnect(),
            Self::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
            ),
            Self::LinkClosed => true,
            _ => false,
        }
    }
}

/// 结果别名。
pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnect_classification_covers_transport_and_io() {
        let eof = CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer closed",
        ));
        assert!(eof.is_disconnect());
        assert!(CoreError::LinkClosed.is_disconnect());
        assert!(
            !CoreError::Undeliverable {
                dest: NodeId::ADMIN
            }
            .is_disconnect()
        );
    }
}
