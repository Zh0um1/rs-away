//! 拓扑、路由、会话与服务实现（SOCKS5 / forward / backward / 文件 / shell / SSH）。
//!
//! 权威文档：
//! - `docs/plan.md` §4.7（派发四步）、§4.8（会话模型）、§4.9（并发与背压）
//! - `docs/design/transport.md` §3（Link 契约）
//!
//! # 分层
//!
//! ```text
//! stowaway-core
//!   topology  ── 节点树、链路 epoch、路由缓存（只持元数据）
//!   dispatch  ── 四步派发决策（纯函数）
//!   session   ── SessionKey 表、序号校验、有界背压
//!   link_actor ── 每链路单写者 + 批量 flush（plan §4.9）
//!   node      ── 上述组件的运行时聚合
//! ```
//!
//! P3 只实现拓扑/路由/会话/链路 actor；服务实现（SOCKS5、forward、文件、
//! shell、SSH）见 P4/P5。
// 库代码禁止直接打印（由二进制/调用方决定输出方式）。
#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod dispatch;
pub mod error;
pub mod link_actor;
pub mod node;
pub mod session;
pub mod topology;

pub use dispatch::{Route, decide, undeliverable_status};
pub use error::{CoreError, Result};
pub use link_actor::{LINK_BATCH_BYTES, LINK_BATCH_MS, LinkActor, LinkCommand};
pub use node::{Node, NodeConfig};
pub use session::{SESSION_QUEUE_DEPTH, SessionMeta, SessionState, SessionTable};
pub use topology::{NodeMeta, RouteEntry, Topology};
