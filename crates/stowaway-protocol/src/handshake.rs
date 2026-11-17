//! 3-flight 握手的报文编组与 transcript 布局。
//!
//! 权威：docs/plan.md §4.5。本模块**只做字节层编组**，不做任何密码学运算
//! （HMAC/ HKDF 在 `stowaway-crypto::handshake`），这样协议 crate 可以保持
//! 零密码学依赖、可被 fuzz 直接驱动。
//!
//! 关键设计（回应 crypto-reviewer 的 C1/C5）：
//!
//! - **transcript hash 由双方各自本地计算**，输入顺序按 role 排序而非按时间，
//!   因此不依赖谁先发；
//! - `transport_kind` 与 `tls_fingerprint` 进入 transcript，篡改即 proof 失配
//!   （防降级）；
//! - 3-flight 让 `auth_key` 依赖双方输入，避免 2-flight 下服务端 proof 早发
//!   导致 MITM 自选 transcript 做离线爆破。

use crate::VERSION;
use crate::error::{ProtocolError, Result};
use crate::msg::{AuthConfirm, Hello, HelloAck};
use crate::node::NodeKind;
use crate::transport_kind::TransportKind;

/// transcript 前缀（域分隔，防止跨协议复用）。
pub const TRANSCRIPT_PREFIX: &[u8] = b"STW2-transcript";

/// 握手阶段。用于拒绝越权跳步（例如在 `HelloAck` 之前收 `AuthConfirm`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flight {
    /// 等待/发送 `Hello`。
    Hello,
    /// 等待/发送 `HelloAck`。
    HelloAck,
    /// 等待/发送 `AuthConfirm`。
    AuthConfirm,
    /// 双方就绪。
    Ready,
    /// 失败或已关闭。
    Failed,
}

impl Flight {
    /// 阶段名（错误信息用）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hello => "Hello",
            Self::HelloAck => "HelloAck",
            Self::AuthConfirm => "AuthConfirm",
            Self::Ready => "Ready",
            Self::Failed => "Failed",
        }
    }

    /// 服务端视角的下一步：收到该 flight 后应推进到哪。
    #[must_use]
    pub const fn server_next(self, got: Self) -> Option<Self> {
        match (self, got) {
            (Self::Hello, Self::Hello) => Some(Self::HelloAck),
            (Self::HelloAck, Self::AuthConfirm) => Some(Self::Ready),
            _ => None,
        }
    }

    /// 客户端视角的下一步。
    #[must_use]
    pub const fn client_next(self, got: Self) -> Option<Self> {
        match (self, got) {
            (Self::Hello, Self::HelloAck) => Some(Self::AuthConfirm),
            (Self::AuthConfirm, Self::Ready) => Some(Self::Ready),
            _ => None,
        }
    }
}

/// transcript 的全部输入。
///
/// 两侧必须填出**完全一致**的字节序列：`role_self`/`role_peer` 由各自视角填，
/// 因此在双方看来顺序相反，但覆盖的集合相同（排序固定为 self→peer）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Transcript {
    /// 本端角色。
    pub role_self: NodeKind,
    /// 对端角色。
    pub role_peer: NodeKind,
    /// 承载类型。
    pub transport: TransportKind,
    /// TLS 证书指纹（无 TLS 时为 `None`）。
    pub tls_fp: Option<[u8; 32]>,
    /// 客户端临时公钥。
    pub client_eph_pub: [u8; 32],
    /// 客户端随机数。
    pub client_nonce: [u8; 32],
    /// 服务端临时公钥。
    pub server_eph_pub: [u8; 32],
    /// 服务端随机数。
    pub server_nonce: [u8; 32],
}

/// `tls_fp` 的线编码长度：`1 + (32 if Some)`。
const fn tls_fp_len(fp: &Option<[u8; 32]>) -> usize {
    match fp {
        Some(_) => 33,
        None => 1,
    }
}

impl Transcript {
    /// 按 `wire_id` 升序返回 `(lo, hi)`，消去「谁先谁后」的视角差异。
    #[must_use]
    pub const fn roles_canonical(a: NodeKind, b: NodeKind) -> (NodeKind, NodeKind) {
        if a.wire_id() <= b.wire_id() {
            (a, b)
        } else {
            (b, a)
        }
    }

    /// 构造：客户端在发送 `Hello` 后即可填齐（它自己的字段已知，
    /// 服务端字段在收 `HelloAck` 后补齐）。
    ///
    /// 8 个参数都是 transcript 的**固定输入**，逐一显式给出比塞进一个临时结构体
    /// 更不容易漏项（漏一项就等于漏进 transcript、让 proof 少绑一个字段）。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        role_self: NodeKind,
        role_peer: NodeKind,
        transport: TransportKind,
        tls_fp: Option<[u8; 32]>,
        client_eph_pub: [u8; 32],
        client_nonce: [u8; 32],
        server_eph_pub: [u8; 32],
        server_nonce: [u8; 32],
    ) -> Self {
        Self {
            role_self,
            role_peer,
            transport,
            tls_fp,
            client_eph_pub,
            client_nonce,
            server_eph_pub,
            server_nonce,
        }
    }

    /// 服务端视角：从 `Hello` 构造（服务端字段尚空）。
    #[must_use]
    pub fn from_hello(h: &Hello) -> Self {
        Self {
            role_self: NodeKind::Admin,
            role_peer: h.kind,
            transport: h.transport,
            tls_fp: h.tls_fp,
            client_eph_pub: h.eph_pub,
            client_nonce: h.nonce,
            server_eph_pub: [0u8; 32],
            server_nonce: [0u8; 32],
        }
    }

    /// 服务端视角：补上自己的字段后得到最终 transcript。
    #[must_use]
    pub fn with_server_fields(&self, eph_pub: [u8; 32], nonce: [u8; 32]) -> Self {
        Self {
            server_eph_pub: eph_pub,
            server_nonce: nonce,
            ..*self
        }
    }

    /// 客户端视角：收到 `HelloAck` 后补齐服务端字段。
    pub fn with_hello_ack(&self, ack: &HelloAck) -> Result<Self> {
        if ack.kind != NodeKind::Admin {
            return Err(ProtocolError::HandshakeField("HelloAck.kind 必须是 Admin"));
        }
        if self.role_peer != NodeKind::Admin {
            return Err(ProtocolError::HandshakeField(
                "本端视角的对端角色必须是 Admin",
            ));
        }
        Ok(Self {
            server_eph_pub: ack.eph_pub,
            server_nonce: ack.nonce,
            ..*self
        })
    }

    /// 编码为 transcript 字节（**SHA-256 的输入**）。
    ///
    /// 布局（全定长，无长度前缀）：
    /// `prefix ‖ role_lo(1) ‖ role_hi(1) ‖ version(1) ‖ transport(1) ‖
    ///  tls_fp_tag(1) [‖ tls_fp(32)] ‖ c_eph(32) ‖ c_nonce(32) ‖ s_eph(32) ‖ s_nonce(32)`
    ///
    /// **角色按 `wire_id` 升序排列**（而不是「本端在前」），因此两侧算出的是
    /// **同一串字节**、同一个 TH —— 这正是 §4.5 要求「两侧入参顺序固定（按 role
    /// 排序而非按时间）」的落地方式；proof 里再拼各自 role 以示区分。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(TRANSCRIPT_PREFIX.len() + 5 + tls_fp_len(&self.tls_fp) + 4 * 32);
        out.extend_from_slice(TRANSCRIPT_PREFIX);
        let (lo, hi) = Self::roles_canonical(self.role_self, self.role_peer);
        out.push(lo.wire_id());
        out.push(hi.wire_id());
        out.push(VERSION);
        out.push(self.transport.wire_id());
        match self.tls_fp {
            Some(fp) => {
                out.push(1);
                out.extend_from_slice(&fp);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.client_eph_pub);
        out.extend_from_slice(&self.client_nonce);
        out.extend_from_slice(&self.server_eph_pub);
        out.extend_from_slice(&self.server_nonce);
        out
    }

    /// 本端是否已填齐（双方临时公钥/随机数均非零）。
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.client_eph_pub != [0u8; 32]
            && self.client_nonce != [0u8; 32]
            && self.server_eph_pub != [0u8; 32]
            && self.server_nonce != [0u8; 32]
    }
}

/// 握手报文的线包装：`msg_type` 由帧头承担，这里只做类型到载荷的路由。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlightMessage<'a> {
    /// flight 1。
    Hello(&'a Hello),
    /// flight 2。
    HelloAck(&'a HelloAck),
    /// flight 3。
    AuthConfirm(&'a AuthConfirm),
}

impl FlightMessage<'_> {
    /// 对应阶段。
    #[must_use]
    pub const fn flight(&self) -> Flight {
        match self {
            Self::Hello(_) => Flight::Hello,
            Self::HelloAck(_) => Flight::HelloAck,
            Self::AuthConfirm(_) => Flight::AuthConfirm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Hello {
        Hello {
            kind: NodeKind::Agent,
            transport: TransportKind::Raw,
            tls_fp: None,
            eph_pub: [0x11; 32],
            nonce: [0x22; 32],
        }
    }

    fn base_transcript() -> Transcript {
        Transcript::new(
            NodeKind::Admin,
            NodeKind::Agent,
            TransportKind::Raw,
            None,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
        )
    }

    #[test]
    fn transcript_length_without_tls() {
        let t = base_transcript();
        // prefix(15) + role_self(1) + role_peer(1) + version(1) + transport(1)
        // + tls_fp_tag(1) + 4×32(128) = 148
        assert_eq!(TRANSCRIPT_PREFIX.len(), 15);
        assert_eq!(t.encode().len(), TRANSCRIPT_PREFIX.len() + 4 + 1 + 128);
    }

    #[test]
    fn transcript_length_with_tls() {
        let t = Transcript {
            tls_fp: Some([0x55; 32]),
            ..base_transcript()
        };
        assert_eq!(t.encode().len(), TRANSCRIPT_PREFIX.len() + 4 + 33 + 128);
    }

    #[test]
    fn both_sides_derive_identical_bytes() {
        // 客户端视角：role_self=Agent、role_peer=Admin；服务端视角相反。
        let client = Transcript::new(
            NodeKind::Agent,
            NodeKind::Admin,
            TransportKind::Raw,
            None,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
        );
        let server = Transcript::new(
            NodeKind::Admin,
            NodeKind::Agent,
            TransportKind::Raw,
            None,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
        );
        // role 按 wire_id 升序排列 → 两侧算出**同一个** TH（§4.5 要求）。
        assert_eq!(client.encode(), server.encode());
        // 同一视角当然也必须确定性。
        assert_eq!(client.encode(), client.encode());
        // 而「谁的视角」由 proof 里的 role 字节区分，不影响 TH。
        assert_eq!(
            Transcript::roles_canonical(NodeKind::Agent, NodeKind::Admin),
            (NodeKind::Admin, NodeKind::Agent)
        );
    }

    #[test]
    fn server_reconstructs_from_hello_then_fills_fields() {
        let h = hello();
        let mut t = Transcript::from_hello(&h);
        assert!(!t.is_complete());
        t = t.with_server_fields([0x33; 32], [0x44; 32]);
        assert!(t.is_complete());
        assert_eq!(t.client_eph_pub, h.eph_pub);
        assert_eq!(t.client_nonce, h.nonce);
        assert_eq!(t.transport, TransportKind::Raw);
    }

    #[test]
    fn client_with_hello_ack_rejects_wrong_role() {
        let t = Transcript::new(
            NodeKind::Agent,
            NodeKind::Admin,
            TransportKind::Raw,
            None,
            [1; 32],
            [2; 32],
            [0; 32],
            [0; 32],
        );
        let bad = HelloAck {
            kind: NodeKind::Agent, // 错：服务端必须声明 Admin
            eph_pub: [3; 32],
            nonce: [4; 32],
            proof: [5; 32],
        };
        assert!(matches!(
            t.with_hello_ack(&bad),
            Err(ProtocolError::HandshakeField(_))
        ));
    }

    #[test]
    fn transport_kind_is_bound_into_transcript() {
        let a = base_transcript();
        let b = Transcript {
            transport: TransportKind::Ws,
            ..base_transcript()
        };
        assert_ne!(a.encode(), b.encode(), "篡改 transport 必须改变 TH");
    }

    #[test]
    fn tls_fp_presence_is_bound_into_transcript() {
        let a = base_transcript();
        let b = Transcript {
            tls_fp: Some([0u8; 32]),
            ..base_transcript()
        };
        assert_ne!(a.encode(), b.encode(), "剥离 TLS 指纹必须改变 TH");
    }

    #[test]
    fn flight_transitions_are_strict() {
        assert_eq!(
            Flight::Hello.server_next(Flight::Hello),
            Some(Flight::HelloAck)
        );
        assert_eq!(
            Flight::HelloAck.server_next(Flight::AuthConfirm),
            Some(Flight::Ready)
        );
        // 越权跳步必须被拒。
        assert_eq!(Flight::Hello.server_next(Flight::AuthConfirm), None);
        assert_eq!(Flight::Ready.server_next(Flight::Hello), None);
        assert_eq!(
            Flight::Hello.client_next(Flight::HelloAck),
            Some(Flight::AuthConfirm)
        );
        assert_eq!(Flight::Hello.client_next(Flight::Hello), None);
    }
}
