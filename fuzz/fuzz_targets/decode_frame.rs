//! `FrameCodec::decode` / `FrameHeader::parse` 的 fuzz target。
//!
//! 不变量：任意字节输入都必须返回 `Err` 或合法帧，**不得 panic、不得越界、
//! 不得为长度字段做超量分配**（对应 §3 缺陷 #1/#3）。
#![no_main]

use libfuzzer_sys::fuzz_target;
use stowaway_protocol::frame::{FrameCodec, FrameHeader};

fuzz_target!(|data: &[u8]| {
    let _ = FrameHeader::parse(data);
    let _ = FrameCodec::decode(data);
});
