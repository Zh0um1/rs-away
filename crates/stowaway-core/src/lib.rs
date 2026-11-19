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
// 库代码禁止直接打印（由二进制/调用方决定输出方式）。
#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod alloc;
pub mod backward;
pub mod bootstrap;
pub mod bridge;
pub mod dispatch;
pub mod engine;
pub mod error;
pub mod file;
pub mod forward;
pub mod link_actor;
pub mod node;
pub mod service;
pub mod session;
pub mod session_stream;
pub mod shell;
pub mod socks;
pub mod socks_server;
pub mod ssh;
pub mod topology;
pub mod udp_relay;
pub mod upstream_proxy;

pub use alloc::{NODE_ID_MAGIC, NodeIdAllocator, salt_from_secret};
pub use backward::{
    BACKWARD_PROBE_TIMEOUT, BackwardListener, BackwardSpec, dial_remote, next_open, open_message,
    relay_backward,
};
pub use bootstrap::{assign_id, request_id};
pub use dispatch::{Route, decide, undeliverable_status};
pub use engine::{
    Command, ENGINE_QUEUE_DEPTH, Engine, EngineHandle, Event, HeartbeatConfig, LinkStat, NodeInfo,
    SharedHandle, Snapshot, now_ms,
};
pub use error::{CoreError, Result};
pub use file::{FILE_CHUNK, FileError, IncomingFile, safe_join, validate_name};
pub use forward::{
    CommittedForward, Direction, ForwardSpec, PROBE_TIMEOUT, describe, probe, stop_message,
};
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
pub use udp_relay::{
    Datagram, MAX_UDP_DATAGRAM, UDP_IDLE_TIMEOUT_SECS, bind_outlet, needs_resolution,
    ready_message, relay_datagrams,
};
pub use upstream_proxy::{MAX_PROXY_RESPONSE, PROXY_DIAL_TIMEOUT, ProxySpec, dial_via_proxy};

// P5 服务。`open_message` 在 backward / shell / ssh / bridge 各有一份，语义
// 相同（都构造 `ServiceRequest`）但类型不同，故不在 crate 根重导出，调用方
// 按模块路径引用（`shell::open_message` 等），避免命名冲突掩盖了类型差异。
pub use bridge::{
    BridgeError, BridgeKind, BridgeOutcome, BridgeSpec, SshLink, announce_message, bridge_accept,
    bridge_connect, done_message, reply_join_ack, ssh_param_of,
};
pub use shell::{
    Charset, DEFAULT_TERM, PtySession, SHELL_READ_BUF, SHELL_TAG_DATA, SHELL_TAG_RESIZE,
    ShellCodec, ShellError, ShellFrame, ShellSpec, data_message, default_shell, parse_frame,
    resize_message, spawn,
};
pub use ssh::{
    CommandOutput, DEFAULT_SSH_PORT, HostKeyDecision, HostKeyPolicy, HostKeyReject,
    HostKeyVerifier, KnownState, SSH_COMMAND_TIMEOUT, SSH_CONNECT_TIMEOUT, SshConnection, SshError,
    SshShell, SshSpec, connect, decide_host_key, load_known_host_key, open_shell, open_tunnel,
    pump_channel, run_command,
};
