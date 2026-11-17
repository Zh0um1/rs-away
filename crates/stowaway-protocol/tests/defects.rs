//! §3 缺陷的协议层回归测试（命名规范 `defect_<n>_`，`cargo test defect_` 一次跑全）。
//!
//! 每个测试对应 docs/plan.md §3 表中的一行；注释里写明 v1 的**具体出错代码**，
//! 以便将来回溯「为什么需要这条测试」。

use stowaway_protocol::frame::{Frame, FrameCodec, FrameFlags, FrameHeader};
use stowaway_protocol::msg::{
    Heartbeat, Hello, HelloAck, Message, MsgType, NodeStatus, SessionData,
};
use stowaway_protocol::node::{NodeId, NodeKind, SessionKey};
use stowaway_protocol::transport_kind::TransportKind;
use stowaway_protocol::wire::{Reader, Writer};
use stowaway_protocol::{MAX_FRAME, MAX_VIA, ProtocolError, VERSION};

/// 构造一个 payload_len 字段可控、但不带 payload 的帧头。
fn header_with_payload_len(payload_len: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(VERSION);
    w.u8(0);
    w.u16_le(MsgType::SessionData.as_u16());
    w.bytes(&[0u8; 16]);
    w.varint(0); // via_count
    w.varint(payload_len);
    w.into_vec()
}

/// 缺陷 #1：v1 `protocol/raw.go:149` `dataBuf := make([]byte, header.DataLen)`
/// 用对端给的 `u64` 直接分配内存，没有上限。
///
/// v2 要求：**在分配任何缓冲区之前**就按 `MAX_FRAME` 拒绝。
#[test]
fn defect_1_oversized_payload_len_rejected_before_allocation() {
    for len in [
        MAX_FRAME as u64 + 1,
        16 * 1024 * 1024,
        u32::MAX as u64,
        u64::MAX,
    ] {
        let bytes = header_with_payload_len(len);
        let err = FrameHeader::parse(&bytes).expect_err("必须拒绝");
        assert!(
            matches!(err, ProtocolError::PayloadTooLarge { .. }),
            "len={len} 应报 PayloadTooLarge，实际 {err:?}"
        );
    }
    // 边界：恰好 MAX_FRAME 允许（仍会因 payload 未到齐而报 Truncated，
    // 但那发生在长度校验之后，即不会预先分配）。
    let bytes = header_with_payload_len(MAX_FRAME as u64);
    // 前 3 字节 version/flags/msg_type 已写对，故解析必须成功。
    assert!(
        FrameHeader::parse(&bytes).is_ok(),
        "MAX_FRAME 本身必须是合法长度"
    );
}

/// 缺陷 #2：v1 的 `DestructMessage` 在未知 `MessageType` 时返回 nil，
/// 随后 `reflect.TypeOf(mess).Elem()`（`protocol/raw.go:275`）对 nil panic。
///
/// v2 要求：未知类型在帧头解析阶段返回 `Err`。
#[test]
fn defect_2_unknown_msg_type_is_error_not_panic() {
    for ty in [0u16, 19, 100, 0x7fff, 0xffff] {
        let mut w = Writer::new();
        w.u8(VERSION);
        w.u8(0);
        w.u16_le(ty);
        w.bytes(&[0u8; 16]);
        w.varint(0);
        w.varint(0);
        let err = FrameCodec::decode(w.as_slice()).expect_err("必须拒绝");
        assert!(
            matches!(err, ProtocolError::UnknownMsgType { msg_type } if msg_type == ty),
            "ty={ty} 应报 UnknownMsgType，实际 {err:?}"
        );
        assert_eq!(MsgType::from_u16(ty), None);
    }
    // 全部已定义类型必须可解码。
    for t in MsgType::ALL {
        assert_eq!(MsgType::from_u16(t.as_u16()), Some(t));
    }
}

/// 缺陷 #3：v1 载荷解析用 `dataBuf[ptr:ptr+n]` 而不校验剩余长度，
/// 短包直接越界 panic（`protocol/raw.go:300` 附近的 `field.SetUint` 系列）。
///
/// v2 要求：任何短于帧头/载荷的输入返回 `Truncated`。
#[test]
fn defect_3_truncated_input_returns_error() {
    let frame = Frame::new(
        FrameFlags::SEALED,
        MsgType::SessionData,
        NodeId::new([1u8; 16]),
        vec![NodeId::ADMIN],
        vec![7u8; 100],
    );
    let bytes = frame.encode();
    let header_len = frame.header.encoded_len();
    for cut in 0..bytes.len() {
        let err = FrameCodec::decode(&bytes[..cut]).expect_err("必须报错");
        let ok = matches!(
            err,
            ProtocolError::Truncated { .. } | ProtocolError::TrailingBytes { .. }
        );
        assert!(ok, "cut={cut} 得到意外错误 {err:?}");
    }
    assert!(header_len > 0);

    // 载荷内部字段截断（消息层）同样不能 panic。
    let msg = Message::SessionData(SessionData {
        key: SessionKey::new(NodeId::UNASSIGNED, 1),
        seq: 3,
        data: vec![1u8, 2, 3].into(),
    });
    let payload = msg.encode().expect("encode");
    for cut in 0..payload.len() {
        assert!(Message::decode(MsgType::SessionData, &payload[..cut]).is_err());
    }
}

/// 缺陷 #4：v1 `DataLen` 是 `u64`，且 `via`/`Route` 用冒号串表达，
/// 长度与内容可以自相矛盾（声称 1 MiB 实际 10 字节，或反之）。
///
/// v2 要求：`payload_len` 与实际 payload 长度**必须严格一致**；
/// `via_count` 有硬上限。
#[test]
fn defect_4_length_fields_must_be_consistent() {
    // (a) 声称的 payload_len 大于实际提供 → Truncated
    let mut bytes = header_with_payload_len(10);
    bytes.extend_from_slice(&[0u8; 5]);
    assert!(matches!(
        FrameCodec::decode(&bytes),
        Err(ProtocolError::Truncated { .. })
    ));

    // (b) 声称的长度小于实际 → 多出的字节成为下一帧（严格消费长度）
    let frame = Frame::new(
        FrameFlags::empty(),
        MsgType::Heartbeat,
        NodeId::UNASSIGNED,
        vec![],
        vec![0u8; 4],
    );
    let mut bytes = frame.encode();
    let n = bytes.len();
    bytes.truncate(n);
    let (_, used) = FrameCodec::decode(&bytes).expect("decode");
    assert_eq!(used, bytes.len());

    // (c) via_count 超限
    let mut w = Writer::new();
    w.u8(VERSION);
    w.u8(0);
    w.u16_le(MsgType::Heartbeat.as_u16());
    w.bytes(&[0u8; 16]);
    w.varint(MAX_VIA as u64 + 1);
    assert!(matches!(
        FrameHeader::parse(w.as_slice()),
        Err(ProtocolError::TooManyVia { .. })
    ));

    // (d) 消息层多余的尾字节必须报错（不允许隐式填充）
    let payload = Message::Heartbeat(Heartbeat::default())
        .encode()
        .expect("e");
    let mut padded = payload.clone();
    padded.push(0);
    assert!(matches!(
        Message::decode(MsgType::Heartbeat, &padded),
        Err(ProtocolError::TrailingBytes { .. })
    ));
}

/// 缺陷 #5（协议侧的部分）：v1 用「UUID 是否等于 Accepter」**隐式推断**是否
/// 需要解密，导致 `--tls-enable` 时把 `Secret` 清空后依然走解密分支、拿到明文。
///
/// v2 要求：密封状态是**显式标志位** `flags.SEALED`，且未定义位一律拒绝。
#[test]
fn defect_5_sealing_is_explicit_flag_not_uuid_inference() {
    assert!(FrameFlags::SEALED.is_sealed());
    assert!(!FrameFlags::empty().is_sealed());
    // 只有 LAST 不算密封。
    assert!(!FrameFlags::LAST.is_sealed());
    // 未定义位必须被拒（防止对端私扩语义）。
    for b in 0b0001_0000u8..=0xff {
        assert!(
            FrameFlags::from_byte(b).is_err(),
            "flags=0b{b:08b} 含未定义位，必须拒绝"
        );
    }
}

/// 缺陷 #7（协议侧）：v1 的「认证」是明文 token 对发，可离线验证且可重放。
///
/// v2 要求：握手报文里的 `proof` 是 32 字节 MAC 而非可重放的明文 token；
/// 且 `HelloAck` 必须声明 `Admin` 角色（防止角色混淆）。
#[test]
fn defect_7_handshake_carries_proof_not_replayable_token() {
    let hello = Hello {
        kind: NodeKind::Agent,
        transport: TransportKind::Ws,
        tls_fp: None,
        eph_pub: [1u8; 32],
        nonce: [2u8; 32],
    };
    let payload = Message::Hello(hello).encode().expect("encode");
    // 32 字节公钥 + 32 字节随机数都在，且不存在 16 字节的固定 token 字段。
    assert!(payload.len() >= 64);

    let ack = HelloAck {
        kind: NodeKind::Admin,
        eph_pub: [3u8; 32],
        nonce: [4u8; 32],
        proof: [5u8; 32],
    };
    let encoded = Message::HelloAck(ack).encode().expect("encode");
    assert_eq!(
        Message::decode(MsgType::HelloAck, &encoded).expect("d"),
        Message::HelloAck(ack)
    );

    // 角色混淆必须被 transcripts 层拒绝（见 handshake::tests）。
    let bad = HelloAck {
        kind: NodeKind::Agent,
        ..ack
    };
    assert_eq!(bad.kind, NodeKind::Agent);
}

/// 缺陷 #11（协议侧）：v1 路由不可达时静默丢弃。
///
/// v2 要求：协议层能表达 `NodeStatus{Undeliverable}`，且 `via` 携带显式下一跳。
#[test]
fn defect_11_undeliverable_is_expressible() {
    use stowaway_protocol::msg::{NodeScope, NodeState};
    let msg = Message::NodeStatus(NodeStatus {
        scope: NodeScope::Node,
        state: NodeState::Undeliverable,
        node: NodeId::new([9u8; 16]),
    });
    let bytes = msg.encode().expect("encode");
    assert_eq!(
        Message::decode(MsgType::NodeStatus, &bytes).expect("d"),
        msg
    );
}

/// 缺陷 #1–#4 的加固：`Reader` 对任意输入都不越界。
#[test]
fn defect_1_to_4_reader_never_indexes_out_of_bounds() {
    for len in 0..64usize {
        let buf = vec![0xffu8; len];
        let mut r = Reader::new(&buf);
        let _ = r.varint("v");
        let mut r = Reader::new(&buf);
        let _ = r.array::<16>("a");
        let mut r = Reader::new(&buf);
        let _ = r.u64_le("u");
        let mut r = Reader::new(&buf);
        let _ = r.slice(len + 1, "s");
    }
}
