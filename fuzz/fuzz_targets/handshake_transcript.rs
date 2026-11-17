//! transcript 编码与握手报文解析的 fuzz target。
//!
//! 不变量：`Transcript::encode()` 对任意字段都必须产出**唯一且定长可预测**的
//! 字节序列；`Hello`/`HelloAck`/`AuthConfirm` 的载荷解码不得 panic。
#![no_main]

use libfuzzer_sys::fuzz_target;
use stowaway_protocol::{
    handshake::Transcript,
    msg::{Message, MsgType},
    node::NodeKind,
    transport_kind::TransportKind,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 * 4 + 4 {
        return;
    }
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];
    let mut d = [0u8; 32];
    a.copy_from_slice(&data[0..32]);
    b.copy_from_slice(&data[32..64]);
    c.copy_from_slice(&data[64..96]);
    d.copy_from_slice(&data[96..128]);

    let t = Transcript::new(
        NodeKind::Admin,
        NodeKind::Agent,
        TransportKind::Raw,
        None,
        a,
        b,
        c,
        d,
    );
    let encoded = t.encode();
    // 长度只取决于「是否带 TLS 指纹」，与字段内容无关。
    assert_eq!(encoded.len(), 148);
    // 同一输入必须确定性输出（TH 可复现的前提）。
    assert_eq!(encoded, t.encode());

    for ty in [
        MsgType::Hello,
        MsgType::HelloAck,
        MsgType::AuthConfirm,
    ] {
        let _ = Message::decode(ty, &data[128..]);
    }
});
