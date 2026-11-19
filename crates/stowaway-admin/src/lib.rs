//! `stowaway-admin` 库根：控制台 TUI 的可测部分。
//!
//! 二进制入口仍在 `src/main.rs`（P0 空壳，暂未接入）。把控制台拆成库
//! target 的目的只有一个：让 `history` / `command` / `render` 能在
//! `cargo test -p stowaway-admin` 下跑单测，而不必改动 `main.rs`。
//!
//! 等 `main.rs` 接入控制台编排后，可以直接 `use stowaway_admin::{command, render};`，
//! 也可以把下面三行 `mod` 声明搬进 `main.rs` 并删掉本文件——两种接法等价
//! （`render.rs` 内部用 `crate::command` / `crate::history`，在两种 crate 根下都成立）。
//!
//! 本文件新增于 TUI 交付（P1），未改动 `main.rs`。

/// 命令解析（主面板 5 条 + 节点面板 20 条；不依赖 ratatui）。
pub mod command;
/// 命令历史（三份独立列表，不依赖 ratatui）。
pub mod history;
/// 控制台 TUI 渲染层（只在 `tui` feature 下编译）。
#[cfg(feature = "tui")]
pub mod render;
