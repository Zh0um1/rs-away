//! v2 线协议：帧编解码、消息枚举、NodeId、SessionKey。
//!
//! 本 crate 是纯字节层，**不依赖任何 IO 运行时**（见 docs/plan.md §4.1 依赖方向），
//! 因此可被 fuzz 目标直接引用。
//!
//! 权威定义：`docs/plan.md` §4.4（帧格式）、§4.6（消息集合）、附录 A（54 → 18 映射）。
//!
//! P0 阶段仅有骨架，实现见 P1。
#![forbid(unsafe_code)]
// 库代码禁止直接打印（由二进制/调用方决定输出方式）。
#![deny(clippy::print_stdout, clippy::print_stderr)]
