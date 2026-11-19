//! v2 线协议：帧编解码、消息枚举、NodeId、SessionKey。
//!
//! 本 crate 是纯字节层，**不依赖任何 IO 运行时**（见 docs/plan.md §4.1 依赖方向），
//! 因此可被 fuzz 目标直接引用、也可在 no_std 环境下复用编解码部分。
//!
//! 权威定义：`docs/plan.md` §4.4（帧格式）、§4.5（握手）、§4.6（消息集合）、
//! 附录 A（54 → 18 映射）。
//!
//! 分层：
//! - [`node`]：`NodeId`、`SessionKey`、`NodeKind`
//! - [`wire`]：LEB128 varint 与固定布局的读写游标
//! - [`frame`]：`Frame` / `FrameFlags` / `FrameCodec`（纯编码，不含密钥）
//! - [`msg`]：18 种消息的载荷（postcard 编码，**非自描述**，只追加不复用）
//! - [`handshake`]：3-flight 握手报文（未密封帧承载）
#![forbid(unsafe_code)]
// 库代码禁止直接打印（由二进制/调用方决定输出方式）。
#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod error;
pub mod frame;
pub mod handshake;
pub mod msg;
pub mod node;
pub mod transport_kind;
pub mod wire;

pub use error::ProtocolError;
pub use frame::{Frame, FrameCodec, FrameFlags, FrameHeader};
/// 字节容器（`SessionData.data` 等字段的类型），re-export 以免下游直接依赖
/// `serde_bytes`。
pub use serde_bytes::ByteBuf;

pub use msg::{
    AuthConfirm, CloseReason, ConnectParam, FileDirection, FileParam, Heartbeat, Hello, HelloAck,
    Join, JoinAck, Memo, Message, MsgType, NodeScope, NodeState, NodeStatus, OpenSession, Rejoin,
    ServiceData, ServiceExit, ServiceKind, ServiceParam, ServicePhase, ServiceReply,
    ServiceRequest, SessionClose, SessionCode, SessionData, SessionDirection, SessionKind,
    SessionReady, ShellParam, Shutdown, SshAuth, SshParam, SshTunnelParam,
};
pub use node::{NodeId, NodeKind, SessionKey};
pub use transport_kind::TransportKind;

/// 协议魔数（握手首字段，也是传输嗅探的判据，见 transport.md §5）。
pub const MAGIC: [u8; 4] = *b"STW2";

/// 线协议版本。`Frame` 与 `Hello` 双处携带，任一不为 2 即拒绝。
pub const VERSION: u8 = 2;

/// 逻辑帧载荷上限（1 MiB）。超过由帧层分片（见 `FRAGMENT_MAX`）。
pub const MAX_FRAME: usize = 1024 * 1024;

/// 单帧分片上限 64 KiB。
pub const FRAGMENT_MAX: usize = 64 * 1024;

/// 经由跳数上限。
pub const MAX_VIA: usize = 8;

/// 帧头最大字节数：`version(1) + flags(1) + msg_type(2) + dest(16) +
/// via_count(1) + via(8×16) + payload_len(3 varint)`。
pub const MAX_HEADER_LEN: usize = 1 + 1 + 2 + 16 + 1 + MAX_VIA * 16 + 3;
