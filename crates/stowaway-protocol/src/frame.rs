//! v2 帧格式与编解码。
//!
//! 布局见 docs/plan.md §4.4：
//!
//! ```text
//! version u8 | flags u8 | msg_type u16 | dest [16]
//! via_count varint | via[] | payload_len varint | payload
//! ```
//!
//! 定长整数小端，长度用 LEB128 varint。**信封不加任何额外长度前缀**：
//! 上层必须靠 `version` + 定长 `dest` + 逐字段 varint 自行定界，
//! 这也是 `FrameHeader::parse` 能在流式缓冲里判断「还要多少字节」的依据。

use bytes::Bytes;

use crate::error::{ProtocolError, Result};
use crate::msg::MsgType;
use crate::node::NodeId;
use crate::wire::{Reader, Writer};
use crate::{MAX_FRAME, MAX_VIA, VERSION};

/// 帧标志位。
///
/// `SEALED` 用显式位取代 v1「靠 UUID 比较推断是否解密」的隐式规则
/// （缺陷 #5 的根因）；`COMPRESSED` 为预留位，v2 默认关闭。
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// payload 已被 link 层 AEAD 密封。
    pub const SEALED: Self = Self(0b0001);
    /// payload 已压缩（预留，v2 默认关闭）。
    pub const COMPRESSED: Self = Self(0b0010);
    /// 会话数据流尾标记（与 `SessionClose` 语义区分）。
    pub const LAST: Self = Self(0b0100);
    /// payload 内层还有 session 层 E2E 密封。
    pub const E2E: Self = Self(0b1000);
    /// 本帧是逻辑帧的一个分片，**后面还有分片**。
    ///
    /// 逻辑帧载荷超过 `min(MAX_FRAME, link.max_frame)` 时由 [`crate::codec`]
    /// 切片：除最后一片外都置位。因为 [`crate::link::Link`] 承诺「可靠有序」，
    /// 接收方只需「见到 FRAG 就继续累积、见到不带 FRAG 的就结束」，
    /// 不需要片序号。
    pub const FRAG: Self = Self(0b1_0000);

    /// 全部已定义位。
    pub const MASK: u8 = 0b1_1111;

    /// 空标志。
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// 从原始字节构造；含未定义位则报错（拒绝降级/扩展混淆）。
    pub fn from_byte(b: u8) -> Result<Self> {
        if b & !Self::MASK != 0 {
            Err(ProtocolError::BadFlags { value: b })
        } else {
            Ok(Self(b))
        }
    }

    /// 原始字节。
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// 是否置位。
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// 置位。
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// 清除。
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    /// 结合。
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// 是否已密封。
    #[must_use]
    pub const fn is_sealed(self) -> bool {
        self.contains(Self::SEALED)
    }

    /// 是否为流尾。
    #[must_use]
    pub const fn is_last(self) -> bool {
        self.contains(Self::LAST)
    }

    /// 是否还有后续分片。
    #[must_use]
    pub const fn is_fragment(self) -> bool {
        self.contains(Self::FRAG)
    }

    /// 是否双层密封。
    #[must_use]
    pub const fn is_e2e(self) -> bool {
        self.contains(Self::E2E)
    }
}

/// 帧头（不含 payload）。
///
/// 帧头的**全部字节**是 link 层 AEAD 的 AAD（docs/plan.md §4.5），
/// 因此 `encode_into` 与 `parse` 必须严格对称。
#[derive(Clone, Debug)]
pub struct FrameHeader {
    /// 标志位。
    pub flags: FrameFlags,
    /// 消息类型。
    pub msg_type: MsgType,
    /// 目标节点。
    pub dest: NodeId,
    /// 经由跳列表；空表示按 `route_cache` 派发。
    pub via: Vec<NodeId>,
    /// payload 长度。
    pub payload_len: usize,
}

impl FrameHeader {
    /// 构造。
    pub fn new(flags: FrameFlags, msg_type: MsgType, dest: NodeId, via: Vec<NodeId>) -> Self {
        Self {
            flags,
            msg_type,
            dest,
            via,
            payload_len: 0,
        }
    }

    /// 编码后的字节数。
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        1 + 1
            + 2
            + 16
            + varint_len(self.via.len() as u64)
            + self.via.len() * 16
            + varint_len(self.payload_len as u64)
    }

    /// 写入游标（含 `payload_len`）。
    pub fn encode_into(&self, w: &mut Writer) {
        w.u8(VERSION);
        w.u8(self.flags.bits());
        w.u16_le(self.msg_type as u16);
        w.bytes(self.dest.as_bytes());
        w.varint(self.via.len() as u64);
        for hop in &self.via {
            w.bytes(hop.as_bytes());
        }
        w.varint(self.payload_len as u64);
    }

    /// 单独取出帧头字节（用作 AEAD 的 AAD）。
    ///
    /// `Frame::header_bytes` 是同一功能的帧级便捷入口。
    #[must_use]
    pub fn header_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// 单独取出帧头字节（用作 AEAD 的 AAD）。
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.encoded_len());
        self.encode_into(&mut w);
        w.into_vec()
    }

    /// 从缓冲区头部解析。
    ///
    /// 返回 `(header, 帧头字节数)`。**不**校验 payload 是否已到齐，调用方据此
    /// 判断流式缓冲还缺多少字节（`header.encoded_len() + payload_len`）。
    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        let mut r = Reader::new(buf);
        let version = r.u8("version")?;
        if version != VERSION {
            return Err(ProtocolError::BadVersion {
                actual: version,
                expected: VERSION,
            });
        }
        let flags = FrameFlags::from_byte(r.u8("flags")?)?;
        let raw_type = r.u16_le("msg_type")?;
        let msg_type = MsgType::from_u16(raw_type)
            .ok_or(ProtocolError::UnknownMsgType { msg_type: raw_type })?;
        let dest = NodeId::new(r.array::<16>("dest")?);

        let via_count = r.varint("via_count")? as usize;
        if via_count > MAX_VIA {
            return Err(ProtocolError::TooManyVia {
                actual: via_count,
                max: MAX_VIA,
            });
        }
        let mut via = Vec::with_capacity(via_count.min(8));
        for _ in 0..via_count {
            via.push(NodeId::new(r.array::<16>("via")?));
        }

        let payload_len = r.varint("payload_len")? as usize;
        if payload_len > MAX_FRAME {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_FRAME,
            });
        }

        let header_len = r.position();
        Ok((
            Self {
                flags,
                msg_type,
                dest,
                via,
                payload_len,
            },
            header_len,
        ))
    }
}

/// 一帧完整数据：帧头 + payload。
#[derive(Clone, Debug)]
pub struct Frame {
    /// 帧头。
    pub header: FrameHeader,
    /// 载荷（可能已密封/压缩）。
    pub payload: Bytes,
}

impl Frame {
    /// 构造；`payload_len` 由 payload 自动填入。
    pub fn new(
        flags: FrameFlags,
        msg_type: MsgType,
        dest: NodeId,
        via: Vec<NodeId>,
        payload: impl Into<Bytes>,
    ) -> Self {
        let payload = payload.into();
        let mut header = FrameHeader::new(flags, msg_type, dest, via);
        header.payload_len = payload.len();
        Self { header, payload }
    }

    /// 整帧编码后的字节数。
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.header.encoded_len() + self.payload.len()
    }

    /// 编码为完整帧字节。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.encoded_len());
        self.header.encode_into(&mut w);
        w.bytes(&self.payload);
        w.into_vec()
    }

    /// 帧头字节（AEAD 的 AAD）。
    #[must_use]
    pub fn header_bytes(&self) -> Vec<u8> {
        self.header.encode_to_vec()
    }
}

/// 帧编解码入口。
///
/// 无状态：不持密钥、不持计数器，仅做字节层变换（密钥逻辑在
/// `stowaway-crypto::LinkSealer`）。因此可被 fuzz 直接驱动。
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameCodec;

impl FrameCodec {
    /// 从缓冲区解析一帧。
    ///
    /// 返回 `(frame, 消费的字节数)`；缓冲区末尾可以有多余字节（下一个帧），
    /// 但**不允许**帧内部有多余字节（严格长度匹配）。
    pub fn decode(buf: &[u8]) -> Result<(Frame, usize)> {
        let (header, header_len) = FrameHeader::parse(buf)?;
        let total = header_len + header.payload_len;
        if buf.len() < total {
            return Err(ProtocolError::Truncated {
                need: header.payload_len,
                have: buf.len().saturating_sub(header_len),
                field: "payload",
            });
        }
        let payload = Bytes::copy_from_slice(&buf[header_len..total]);
        Ok((Frame { header, payload }, total))
    }

    /// 编码一帧。
    #[must_use]
    pub fn encode(frame: &Frame) -> Vec<u8> {
        frame.encode()
    }
}

/// LEB128 编码所需字节数。
const fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frame() -> Frame {
        Frame::new(
            FrameFlags::SEALED,
            MsgType::SessionData,
            NodeId::new([7u8; 16]),
            vec![NodeId::new([1u8; 16]), NodeId::new([2u8; 16])],
            vec![1u8, 2, 3, 4, 5],
        )
    }

    #[test]
    fn roundtrip() {
        let f = sample_frame();
        let bytes = f.encode();
        assert_eq!(bytes.len(), f.encoded_len());
        let (back, used) = FrameCodec::decode(&bytes).expect("decode");
        assert_eq!(used, bytes.len());
        assert_eq!(back.header.flags, f.header.flags);
        assert_eq!(back.header.msg_type, f.header.msg_type);
        assert_eq!(back.header.dest, f.header.dest);
        assert_eq!(back.header.via, f.header.via);
        assert_eq!(&back.payload[..], &f.payload[..]);
    }

    #[test]
    fn header_bytes_are_aad() {
        let f = sample_frame();
        let full = f.encode();
        let aad = f.header_bytes();
        assert!(full.starts_with(&aad));
        assert_eq!(aad.len(), f.header.encoded_len());
    }

    #[test]
    fn flags_reject_undefined_bits() {
        // bit0..=bit4 已定义（SEALED/COMPRESSED/LAST/E2E/FRAG）。
        assert!(FrameFlags::from_byte(0b1_1111).is_ok());
        assert_eq!(
            FrameFlags::from_byte(0b10_0000),
            Err(ProtocolError::BadFlags { value: 0b10_0000 })
        );
        assert!(FrameFlags::from_byte(0x80).is_err());
    }

    #[test]
    fn bad_version_rejected() {
        let f = sample_frame();
        let mut bytes = f.encode();
        bytes[0] = 1;
        assert!(matches!(
            FrameCodec::decode(&bytes),
            Err(ProtocolError::BadVersion { .. })
        ));
    }

    #[test]
    fn unknown_msg_type_rejected() {
        let f = sample_frame();
        let mut bytes = f.encode();
        // msg_type 在 offset 2..4（小端）；0xffff 不在枚举内。
        bytes[2] = 0xff;
        bytes[3] = 0xff;
        let err = FrameCodec::decode(&bytes).expect_err("must fail");
        assert!(matches!(
            err,
            ProtocolError::UnknownMsgType { msg_type: 0xffff }
        ));
    }

    #[test]
    fn too_many_via_rejected() {
        let mut f = sample_frame();
        f.header.via = vec![NodeId::ADMIN; MAX_VIA + 1];
        f.header.payload_len = f.payload.len();
        let bytes = f.encode();
        assert!(matches!(
            FrameCodec::decode(&bytes),
            Err(ProtocolError::TooManyVia { .. })
        ));
    }

    #[test]
    fn oversized_payload_len_rejected_without_allocation() {
        // 手工构造 payload_len = MAX_FRAME + 1（varint），并且不附带 payload：
        // 必须在分配前就报 PayloadTooLarge 而不是去读 1 MiB。
        let mut w = Writer::new();
        w.u8(VERSION);
        w.u8(0);
        w.u16_le(MsgType::Heartbeat as u16);
        w.bytes(&[0u8; 16]);
        w.varint(0);
        w.varint(MAX_FRAME as u64 + 1);
        let err = FrameCodec::decode(w.as_slice()).expect_err("must fail");
        assert!(matches!(err, ProtocolError::PayloadTooLarge { .. }));
    }

    #[test]
    fn truncated_header_returns_err() {
        let f = sample_frame();
        let bytes = f.encode();
        for cut in 0..bytes.len().min(f.header.encoded_len()) {
            assert!(
                FrameCodec::decode(&bytes[..cut]).is_err(),
                "cut {cut} 必须报错"
            );
        }
    }

    #[test]
    fn truncated_payload_returns_err() {
        let f = sample_frame();
        let bytes = f.encode();
        let header_len = f.header.encoded_len();
        for cut in header_len..bytes.len() {
            assert!(
                FrameCodec::decode(&bytes[..cut]).is_err(),
                "cut {cut} 必须报错"
            );
        }
    }

    #[test]
    fn multiple_frames_in_one_buffer() {
        let a = sample_frame().encode();
        let b = Frame::new(
            FrameFlags::empty(),
            MsgType::Heartbeat,
            NodeId::UNASSIGNED,
            vec![],
            vec![0u8; 0],
        )
        .encode();
        let mut buf = a.clone();
        buf.extend_from_slice(&b);

        let (_, used) = FrameCodec::decode(&buf).expect("first");
        assert_eq!(used, a.len());
        let (second, used2) = FrameCodec::decode(&buf[used..]).expect("second");
        assert_eq!(used2, b.len());
        assert_eq!(second.header.msg_type, MsgType::Heartbeat);
        assert!(second.payload.is_empty());
    }

    #[test]
    fn empty_payload_and_no_via() {
        let f = Frame::new(
            FrameFlags::empty(),
            MsgType::Shutdown,
            NodeId::ADMIN,
            vec![],
            vec![],
        );
        let bytes = f.encode();
        let (back, _) = FrameCodec::decode(&bytes).expect("decode");
        assert!(back.payload.is_empty());
        assert!(back.header.via.is_empty());
        assert_eq!(back.header.dest, NodeId::ADMIN);
    }

    #[test]
    fn header_len_matches_varint_size() {
        // via_count=8 → 1 字节；payload_len 若 > 127 则 2 字节。
        let f = Frame::new(
            FrameFlags::empty(),
            MsgType::SessionData,
            NodeId::UNASSIGNED,
            vec![NodeId::UNASSIGNED; MAX_VIA],
            vec![0u8; 200],
        );
        let bytes = f.encode();
        let (header, header_len) = FrameHeader::parse(&bytes).expect("parse");
        assert_eq!(header_len, header.encoded_len());
        assert_eq!(header.via.len(), MAX_VIA);
        assert_eq!(header.payload_len, 200);
        assert_eq!(header_len, 1 + 1 + 2 + 16 + 1 + MAX_VIA * 16 + 2);
    }
}
