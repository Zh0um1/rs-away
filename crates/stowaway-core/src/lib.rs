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
//!   socks / socks_server ── SOCKS5 线协议与协商（RFC 1928/1929）
//!   session_stream ── 把 SessionData 适配成 AsyncRead + AsyncWrite
//!   forward / backward / file / udp_relay / upstream_proxy ── 具体服务
//! ```
//!
//! P4 已实现 SOCKS5（TCP + UDP ASSOCIATE）、forward、backward、文件传输与
//! 上游代理拨号；shell（PTY）、SSH、SSH 隧道与 `connect` 桥接见 P5。
#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod dispatch;
pub mod error;
pub mod link_actor;
pub mod node;
pub mod session;
pub mod session_stream;
pub mod socks;
pub mod socks_server;
pub mod topology;

pub use dispatch::{Route, decide, undeliverable_status};
pub use error::{CoreError, Result};
pub use link_actor::{LINK_BATCH_BYTES, LINK_BATCH_MS, LinkActor, LinkCommand};
pub use node::{Node, NodeConfig};
pub use session::{SESSION_QUEUE_DEPTH, SessionMeta, SessionState, SessionTable};
pub use session_stream::{SessionOutbound, SessionStream, outbound_message};
pub use socks::{Parsed, SocksError, Target, TargetAddr};
pub use socks_server::{
    Credentials, DIAL_TIMEOUT, Negotiated, READY_TIMEOUT, SocksServerConfig, dial_code,
    dial_target, negotiate, pump, relay, serve_connect, wait_ready,
};
pub use topology::{NodeMeta, RouteEntry, Topology};
