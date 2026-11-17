//! 连接协议 / 传输抽象层：`Link` / `Listener` / `Dialer` 与传输实现。
//!
//! trait 契约与一致性闸门见 `docs/design/transport.md`。硬约束：新增传输必须在
//! `TransportKind`、`AnyListener`、`AnyDialer` 三处加分支，禁止 `_ =>` 兜底。
//!
//! P0 阶段仅有骨架，实现见 P2。
#![forbid(unsafe_code)]
// 库代码禁止直接打印（由二进制/调用方决定输出方式）。
#![deny(clippy::print_stdout, clippy::print_stderr)]
