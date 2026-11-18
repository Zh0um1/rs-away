//! 属性测试（docs/plan.md §8.1）：帧 round-trip 幂等、任意字节不 panic。
//!
//! 这些不变量是 fuzz 之前的低成本高频闸门；fuzz（§8.2）负责长尾。

use proptest::collection::vec;
use proptest::prelude::*;
use stowaway_protocol::frame::{Frame, FrameCodec, FrameFlags, FrameHeader};
use stowaway_protocol::msg::MsgType;
use stowaway_protocol::node::NodeId;
use stowaway_protocol::{MAX_FRAME, MAX_VIA, VERSION};

fn any_flag_byte() -> impl Strategy<Value = u8> {
    0u8..=0b1_1111u8
}

fn any_msg_type() -> impl Strategy<Value = MsgType> {
    (0u16..18u16).prop_map(|v| MsgType::from_u16(v + 1).expect("1..=18"))
}

fn any_node_id() -> impl Strategy<Value = NodeId> {
    prop::array::uniform16(any::<u8>()).prop_map(NodeId::new)
}

/// 任意合法帧（via ≤ MAX_VIA，payload ≤ 8 KiB 以控制用例耗时）。
fn any_frame() -> impl Strategy<Value = Frame> {
    (
        any_flag_byte(),
        any_msg_type(),
        any_node_id(),
        vec(any_node_id(), 0..=MAX_VIA),
        vec(any::<u8>(), 0..=8192),
    )
        .prop_map(|(flags, msg_type, dest, via, payload)| {
            Frame::new(
                FrameFlags::from_byte(flags).expect("masked"),
                msg_type,
                dest,
                via,
                payload,
            )
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    /// 编码 → 解码 → 再编码，字节必须完全一致（幂等）。
    #[test]
    fn frame_roundtrip_is_idempotent(frame in any_frame()) {
        let bytes = FrameCodec::encode(&frame);
        prop_assert_eq!(bytes.len(), frame.encoded_len());

        let (back, used) = FrameCodec::decode(&bytes).expect("decode");
        prop_assert_eq!(used, bytes.len());
        prop_assert_eq!(back.header.flags.bits(), frame.header.flags.bits());
        prop_assert_eq!(back.header.msg_type, frame.header.msg_type);
        prop_assert_eq!(back.header.dest, frame.header.dest);
        prop_assert_eq!(back.header.via.as_slice(), frame.header.via.as_slice());
        prop_assert_eq!(back.payload.as_ref(), frame.payload.as_ref());

        prop_assert_eq!(FrameCodec::encode(&back), bytes);
    }

    /// AAD 就是帧头前缀，且长度与 `encoded_len` 一致。
    #[test]
    fn header_bytes_are_prefix_of_frame(frame in any_frame()) {
        let full = FrameCodec::encode(&frame);
        let aad = frame.header_bytes();
        prop_assert!(full.starts_with(&aad));
        prop_assert_eq!(aad.len(), frame.header.encoded_len());
    }

    /// 任意字节切片，解码必须返回 Ok 或 Err，**绝不 panic**（缺陷 #1–#4）。
    #[test]
    fn decode_arbitrary_bytes_never_panics(bytes in vec(any::<u8>(), 0..=2048)) {
        // 只要不 panic 即为通过；结果内容不做断言。
        let _ = FrameCodec::decode(&bytes);
        let _ = FrameHeader::parse(&bytes);
    }

    /// 前缀截断：任何比完整帧短的切片都必须报错（不能静默解析出短 payload）。
    #[test]
    fn truncated_frame_always_errors(frame in any_frame()) {
        let bytes = FrameCodec::encode(&frame);
        for cut in 0..bytes.len() {
            prop_assert!(
                FrameCodec::decode(&bytes[..cut]).is_err(),
                "cut={} 必须报错",
                cut
            );
        }
    }

    /// 多帧拼接：必须能逐帧消费到干净结尾。
    #[test]
    fn multiple_frames_decode_sequentially(
        frames in vec(any_frame(), 1..=4),
    ) {
        let mut buf = Vec::new();
        for f in &frames {
            buf.extend_from_slice(&FrameCodec::encode(f));
        }
        let mut rest = &buf[..];
        for f in &frames {
            let (back, used) = FrameCodec::decode(rest).expect("decode");
            prop_assert_eq!(used, f.encoded_len());
            prop_assert_eq!(back.header.msg_type, f.header.msg_type);
            rest = &rest[used..];
        }
        prop_assert!(rest.is_empty());
    }

    /// 版本字段必须是硬门禁：改动 version 字节必须被拒。
    #[test]
    fn wrong_version_always_rejected(frame in any_frame()) {
        let mut bytes = FrameCodec::encode(&frame);
        let wrong = if VERSION == 0 { 1 } else { VERSION - 1 };
        bytes[0] = wrong;
        prop_assert!(FrameCodec::decode(&bytes).is_err());
    }

    /// 超出 MAX_FRAME 的 payload_len 必须在**分配前**被拒。
    #[test]
    fn oversized_payload_len_rejected_before_allocation(
        dest in any_node_id(),
        msg_type in any_msg_type(),
        payload_len in (MAX_FRAME + 1)..=(MAX_FRAME * 4),
    ) {
        let mut header = FrameHeader::new(FrameFlags::empty(), msg_type, dest, Vec::new());
        header.payload_len = payload_len;
        let bytes = header.encode_to_vec();
        let err = FrameHeader::parse(&bytes).expect_err("必须拒绝");
        prop_assert!(
            matches!(
                err,
                stowaway_protocol::ProtocolError::PayloadTooLarge { .. }
            ),
            "{:?}",
            err
        );
    }

    /// via 数量超过上限必须被拒（且不 panic）。
    #[test]
    fn too_many_via_rejected(mut frame in any_frame()) {
        frame.header.via = vec![NodeId::ADMIN; MAX_VIA + 1];
        frame.header.payload_len = frame.payload.len();
        let bytes = frame.encode();
        prop_assert!(FrameHeader::parse(&bytes).is_err());
    }
}
