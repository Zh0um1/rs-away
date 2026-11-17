//! 拓扑、路由、会话与服务实现（SOCKS5 / forward / backward / 文件 / shell / SSH）。
//!
//! P0 阶段仅有骨架，实现见 P3–P5。
// 库代码禁止直接打印（由二进制/调用方决定输出方式）。
#![deny(clippy::print_stdout, clippy::print_stderr)]
