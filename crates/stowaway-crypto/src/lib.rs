//! 握手、KDF、逐跳密封（LinkSealer）、证书指纹。
//!
//! 权威定义：`docs/plan.md` §4.5。所有密钥材料用 `Zeroizing` 持有。
//!
//! P0 阶段仅有骨架，实现见 P1。
#![forbid(unsafe_code)]
// 库代码禁止直接打印（由二进制/调用方决定输出方式）。
#![deny(clippy::print_stdout, clippy::print_stderr)]
