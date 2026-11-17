//! 载荷解码的 fuzz target：任意 `msg_type` × 任意字节。
//!
//! 不变量：`Message::decode` 对每种已知类型都必须返回 `Result`（对应
//! §3 缺陷 #2：v1 在这里对未知类型 `reflect.TypeOf(nil).Elem()` 直接 panic）。
#![no_main]

use libfuzzer_sys::fuzz_target;
use stowaway_protocol::msg::{Message, MsgType};

fuzz_target!(|data: &[u8]| {
    for ty in MsgType::ALL {
        let _ = Message::decode(ty, data);
    }
});
