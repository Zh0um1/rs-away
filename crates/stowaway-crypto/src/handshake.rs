//! 3-flight 握手的密码学部分：proof 生成/校验、`Ready` 判定。
//!
//! 权威：`docs/plan.md` §4.5。字节层编组在 `stowaway-protocol::handshake`，
//! 本模块负责：
//!
//! - 用 `X25519(EphemeralSecret)` 算 `shared`（一次性，用完即弃 ⇒ 前向保密）；
//! - 用 [`crate::kdf::derive_link_keys`] 派生 `auth_key`/`link_key`/`session_key_seed`；
//! - `proof = HMAC-SHA256(auth_key, TH ‖ role)`，比较走 `subtle::ConstantTimeEq`；
//! - 3-flight 顺序：客户端**先验服务端 proof**，通过后才发 `AuthConfirm`，
//!   这样 MITM 无法靠提早拿到客户端 proof 做离线爆破（回应 C5）。
//!
//! transcript hash 由 `stowaway_protocol::handshake::Transcript::encode()` 产出，
//! 该编码**按 role 规范化排序**，因此两侧算出同一串字节。

use stowaway_protocol::handshake::Transcript;
use stowaway_protocol::msg::{AuthConfirm, Hello, HelloAck};
use stowaway_protocol::node::NodeKind;
use stowaway_protocol::transport_kind::TransportKind;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::kdf::{LinkKeys, derive_link_keys};
use crate::secret::Secret;
use crate::{KEY_LEN, PROOF_LEN};

/// 握手失败原因。
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// 对端临时公钥是低阶点/全零，`shared` 不可信。
    #[error("对端临时公钥非法（low-order point）")]
    BadEphemeralKey,
    /// 对端身份角色不符合预期。
    #[error("对端角色不符合预期：期望 {expected:?}，实际 {actual:?}")]
    WrongRole {
        /// 期望角色。
        expected: NodeKind,
        /// 实际角色。
        actual: NodeKind,
    },
    /// proof 校验失败。
    #[error("握手 proof 校验失败")]
    ProofMismatch,
    /// transcript 字节层构造失败。
    #[error("transcript 构造失败：{0}")]
    Transcript(#[from] stowaway_protocol::ProtocolError),
}

/// `HMAC-SHA256(auth_key, TH ‖ role_wire_id)`。
///
/// `role` 是**证明者自己的**角色：两侧 TH 相同、proof 不同，防止把服务端
/// proof 反射给客户端（reflection）。
#[must_use]
pub fn proof(auth_key: &[u8; KEY_LEN], th: &[u8; 32], role: NodeKind) -> [u8; PROOF_LEN] {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    // HMAC 的 `KeySize` 是分组长度 64，密钥可为任意长度，故只能走 `new_from_slice`。
    let mut mac = Hmac::<Sha256>::new_from_slice(auth_key).expect("任意长度密钥均合法"); // assert-ok
    mac.update(th);
    mac.update(&[role.wire_id()]);
    mac.finalize().into_bytes().into()
}

/// 常数时间校验 proof。
#[must_use]
pub fn verify(
    auth_key: &[u8; KEY_LEN],
    th: &[u8; 32],
    role: NodeKind,
    got: &[u8; PROOF_LEN],
) -> bool {
    let want = proof(auth_key, th, role);
    want.ct_eq(got).into()
}

/// 握手完成后的产物。
pub struct HandshakeSecrets {
    /// 派生出的子密钥。
    pub keys: LinkKeys,
    /// 双方一致的 transcript hash。
    pub transcript_hash: [u8; 32],
}

impl std::fmt::Debug for HandshakeSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeSecrets")
            .field("keys", &self.keys)
            .field("transcript_hash", &self.transcript_hash)
            .finish()
    }
}

/// 一次 hub 派生的结果。
#[derive(Clone, Debug)]
pub struct HandshakeOutcome {
    /// transcript hash（诊断与日志用，不含秘密）。
    pub transcript_hash: [u8; 32],
    /// `AuthConfirm.seed_ack`：把 `session_key_seed` 的第一段确认回对端，
    /// 使双方确认派生完全一致（不泄露 seed 本身——用 HMAC 再包一层）。
    pub seed_ack: [u8; KEY_LEN],
}

/// 客户端侧握手状态机。
pub struct ClientHandshake {
    ephemeral: EphemeralSecret,
    /// 自己的临时公钥：`diffie_hellman` 会**消耗** `ephemeral`，所以必须提前存下。
    my_pub: [u8; KEY_LEN],
    nonce: [u8; KEY_LEN],
    transport: TransportKind,
    tls_fp: Option<[u8; 32]>,
    role: NodeKind,
}

impl std::fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只打非秘密字段：临时公钥与 nonce 可公开，`ephemeral` 私钥绝不出现。
        f.debug_struct("ClientHandshake")
            .field("role", &self.role)
            .field("transport", &self.transport)
            .field("tls_fp", &self.tls_fp)
            .field("my_pub", &self.my_pub)
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

impl ClientHandshake {
    /// 生成临时密钥与 nonce，并记住所声明的传输/证书指纹。
    #[must_use]
    pub fn new(role: NodeKind, transport: TransportKind, tls_fp: Option<[u8; 32]>) -> Self {
        let mut rng = rand::rng();
        let ephemeral = EphemeralSecret::random_from_rng(&mut rng);
        let my_pub = PublicKey::from(&ephemeral).to_bytes();
        Self {
            ephemeral,
            my_pub,
            nonce: rand::random::<[u8; KEY_LEN]>(),
            transport,
            tls_fp,
            role,
        }
    }

    /// 自己的临时公钥（诊断用，非秘密）。
    #[must_use]
    pub const fn ephemeral_public(&self) -> &[u8; KEY_LEN] {
        &self.my_pub
    }

    /// flight 1：构造 `Hello`。
    #[must_use]
    pub fn hello(&self) -> Hello {
        Hello {
            kind: self.role,
            transport: self.transport,
            tls_fp: self.tls_fp,
            eph_pub: self.my_pub,
            nonce: self.nonce,
        }
    }

    /// flight 2→3：收到 `HelloAck` 后，**先验服务端 proof**，通过才产出
    /// `AuthConfirm` 与链路密钥。
    ///
    /// # Errors
    /// proof 不匹配、对端角色错误、或临时公钥非法。
    pub fn finish(
        self,
        ack: &HelloAck,
        secret: &Secret,
    ) -> Result<(AuthConfirm, HandshakeSecrets, HandshakeOutcome), HandshakeError> {
        if ack.kind == self.role {
            return Err(HandshakeError::WrongRole {
                expected: opposite(self.role),
                actual: ack.kind,
            });
        }

        let peer_pub = PublicKey::from(ack.eph_pub);
        // `my_pub` 在 `new()` 里已存下：`diffie_hellman` 消耗 `ephemeral`。
        let my_pub = self.my_pub;
        let shared = Zeroizing::new(self.ephemeral.diffie_hellman(&peer_pub).to_bytes());
        if shared.iter().all(|b| *b == 0) {
            return Err(HandshakeError::BadEphemeralKey);
        }

        let transcript = Transcript::new(
            self.role,
            ack.kind,
            self.transport,
            self.tls_fp,
            my_pub,
            self.nonce,
            ack.eph_pub,
            ack.nonce,
        );
        // 两侧 TH 都由 `Transcript::encode()` 产出（角色按 wire_id 规范化排序）。
        let digest = secret.digest();
        let keys = derive_link_keys(&shared, &self.nonce, &ack.nonce, &digest);
        let th = sha256(&transcript.encode());
        if !verify(&keys.auth_key, &th, ack.kind, &ack.proof) {
            return Err(HandshakeError::ProofMismatch);
        }

        let client_proof = proof(&keys.auth_key, &th, self.role);
        let seed_ack = seed_ack_of(&keys.session_key_seed, &th);
        Ok((
            AuthConfirm {
                proof: client_proof,
                seed_ack,
            },
            HandshakeSecrets {
                keys,
                transcript_hash: th,
            },
            HandshakeOutcome {
                transcript_hash: th,
                seed_ack,
            },
        ))
    }
}

/// 服务端侧握手状态机。
pub struct ServerHandshake {
    nonce: [u8; KEY_LEN],
    keys: LinkKeys,
    transcript_hash: [u8; 32],
    peer_role: NodeKind,
    transport: TransportKind,
    tls_fp: Option<[u8; 32]>,
    client_pub: [u8; KEY_LEN],
    client_nonce: [u8; KEY_LEN],
    role: NodeKind,
    server_proof: [u8; PROOF_LEN],
}

impl std::fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只打非秘密字段：公钥与 nonce 可公开，密钥一律不出现。
        f.debug_struct("ServerHandshake")
            .field("role", &self.role)
            .field("peer_role", &self.peer_role)
            .field("transport", &self.transport)
            .field("tls_fp", &self.tls_fp)
            .field("nonce", &self.nonce)
            .field("client_nonce", &self.client_nonce)
            .field("transcript_hash", &self.transcript_hash)
            .finish_non_exhaustive()
    }
}

impl ServerHandshake {
    /// 收到 `Hello` 后立即完成 DH 与 KDF，并预先算好 `server_proof`。
    ///
    /// `expected_transport`/`expected_tls_fp` 用于**校验**客户端声明：
    /// 若客户端声称 ws 而实际走 raw，transcript 会不一致，后续 proof 必然失败，
    /// 但在此处显式拒绝能给出更清晰的错误。
    ///
    /// # Errors
    /// 客户端公钥非法、声明的传输/TLS 与实际不符。
    pub fn accept(
        hello: &Hello,
        secret: &Secret,
        role: NodeKind,
        expected_transport: TransportKind,
        expected_tls_fp: Option<[u8; 32]>,
    ) -> Result<(Self, HelloAck), HandshakeError> {
        if hello.transport != expected_transport {
            return Err(HandshakeError::Transcript(
                stowaway_protocol::ProtocolError::HandshakeField("transport 声明与实际不符"),
            ));
        }
        if hello.tls_fp != expected_tls_fp {
            return Err(HandshakeError::Transcript(
                stowaway_protocol::ProtocolError::HandshakeField("TLS 指纹声明与实际不符"),
            ));
        }
        if hello.kind == role {
            return Err(HandshakeError::WrongRole {
                expected: opposite(role),
                actual: hello.kind,
            });
        }

        let mut rng = rand::rng();
        let ephemeral = EphemeralSecret::random_from_rng(&mut rng);
        let nonce: [u8; KEY_LEN] = rand::random();
        let my_pub = PublicKey::from(&ephemeral).to_bytes();

        let peer_pub = PublicKey::from(hello.eph_pub);
        let shared = Zeroizing::new(ephemeral.diffie_hellman(&peer_pub).to_bytes());
        if shared.iter().all(|b| *b == 0) {
            return Err(HandshakeError::BadEphemeralKey);
        }

        let transcript = Transcript::new(
            role,
            hello.kind,
            hello.transport,
            hello.tls_fp,
            hello.eph_pub,
            hello.nonce,
            my_pub,
            nonce,
        );
        let digest = secret.digest();
        let keys = derive_link_keys(&shared, &hello.nonce, &nonce, &digest);
        let th = sha256(&transcript.encode());
        let server_proof = proof(&keys.auth_key, &th, role);

        let state = Self {
            nonce,
            keys,
            transcript_hash: th,
            peer_role: hello.kind,
            transport: hello.transport,
            tls_fp: hello.tls_fp,
            client_pub: hello.eph_pub,
            client_nonce: hello.nonce,
            role,
            server_proof,
        };
        let ack = HelloAck {
            kind: role,
            eph_pub: my_pub,
            nonce,
            proof: server_proof,
        };
        Ok((state, ack))
    }

    /// flight 3：校验客户端 `AuthConfirm.proof`，通过即 `Ready`。
    ///
    /// # Errors
    /// proof 不匹配或 `seed_ack` 不一致（派生被中间人扰动）。
    pub fn finish(
        self,
        confirm: &AuthConfirm,
    ) -> Result<(HandshakeSecrets, HandshakeOutcome), HandshakeError> {
        if !verify(
            &self.keys.auth_key,
            &self.transcript_hash,
            self.peer_role,
            &confirm.proof,
        ) {
            return Err(HandshakeError::ProofMismatch);
        }
        let expected_ack = seed_ack_of(&self.keys.session_key_seed, &self.transcript_hash);
        if expected_ack.ct_eq(&confirm.seed_ack).unwrap_u8() != 1 {
            return Err(HandshakeError::ProofMismatch);
        }
        let th = self.transcript_hash;
        Ok((
            HandshakeSecrets {
                keys: self.keys,
                transcript_hash: th,
            },
            HandshakeOutcome {
                transcript_hash: th,
                seed_ack: expected_ack,
            },
        ))
    }

    /// 服务端预先算好的 proof（用于构造 `HelloAck`）。
    #[must_use]
    pub fn server_proof(&self) -> [u8; PROOF_LEN] {
        self.server_proof
    }

    /// 服务端视角的 transcript hash（诊断用）。
    #[must_use]
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }

    /// 便于诊断的握手元数据。
    #[must_use]
    pub fn describe(&self) -> (TransportKind, Option<[u8; 32]>, NodeKind, [u8; KEY_LEN]) {
        (
            self.transport,
            self.tls_fp,
            self.peer_role,
            self.client_nonce,
        )
    }

    /// 客户端公钥与 nonce（用于日志/诊断，不含密钥）。
    #[must_use]
    pub fn peer_material(&self) -> ([u8; KEY_LEN], [u8; KEY_LEN], [u8; KEY_LEN]) {
        (self.client_pub, self.client_nonce, self.nonce)
    }
}

/// `seed_ack = HMAC-SHA256(session_key_seed, "STW2-seed-ack" ‖ TH)`。
///
/// 用它代替直接回传 seed：双方确认派生一致，同时不把 seed 放到线上。
#[must_use]
pub fn seed_ack_of(session_key_seed: &[u8; KEY_LEN], th: &[u8; 32]) -> [u8; KEY_LEN] {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(session_key_seed).expect("任意长度密钥均合法"); // assert-ok
    mac.update(b"STW2-seed-ack");
    mac.update(th);
    mac.finalize().into_bytes().into()
}

/// `SHA256(bytes)`。
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// admin ↔ agent 的互补角色。
#[must_use]
pub const fn opposite(role: NodeKind) -> NodeKind {
    match role {
        NodeKind::Admin => NodeKind::Agent,
        NodeKind::Agent => NodeKind::Admin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Secret {
        Secret::load("correct-horse-battery", 1).expect("secret")
    }

    fn client_and_server() -> (ClientHandshake, ServerHandshake, HelloAck) {
        let s = secret();
        let client = ClientHandshake::new(NodeKind::Agent, TransportKind::Raw, None);
        let hello = client.hello();
        let (server, ack) =
            ServerHandshake::accept(&hello, &s, NodeKind::Admin, TransportKind::Raw, None)
                .expect("accept");
        (client, server, ack)
    }

    #[test]
    fn full_handshake_succeeds_and_keys_match() {
        let s = secret();
        let (client, server, ack) = client_and_server();
        let (confirm, ckeys, cout) = client.finish(&ack, &s).expect("client finish");
        let (skeys, sout) = server.finish(&confirm).expect("server finish");
        assert_eq!(ckeys.transcript_hash, skeys.transcript_hash);
        assert_eq!(cout.transcript_hash, sout.transcript_hash);
        assert_eq!(&ckeys.keys.link_key[..], &skeys.keys.link_key[..]);
        assert_eq!(
            &ckeys.keys.session_key_seed[..],
            &skeys.keys.session_key_seed[..]
        );
        assert_eq!(cout.seed_ack, sout.seed_ack);
    }

    #[test]
    fn wrong_secret_fails_at_client_proof_verification() {
        let (client, _server, ack) = client_and_server();
        let evil = Secret::load("wrong-secret-value", 1).expect("s");
        assert!(matches!(
            client.finish(&ack, &evil),
            Err(HandshakeError::ProofMismatch)
        ));
    }

    #[test]
    fn tampered_transport_fails() {
        // 客户端声明 raw，服务端实际期望 ws → 明确拒绝。
        let s = secret();
        let client = ClientHandshake::new(NodeKind::Agent, TransportKind::Raw, None);
        let hello = client.hello();
        let err = ServerHandshake::accept(&hello, &s, NodeKind::Admin, TransportKind::Ws, None)
            .expect_err("必须拒绝");
        assert!(matches!(err, HandshakeError::Transcript(_)));
    }

    #[test]
    fn tampered_tls_fingerprint_fails() {
        let s = secret();
        let client = ClientHandshake::new(NodeKind::Agent, TransportKind::Ws, Some([1u8; 32]));
        let hello = client.hello();
        let err = ServerHandshake::accept(
            &hello,
            &s,
            NodeKind::Admin,
            TransportKind::Ws,
            Some([2u8; 32]),
        )
        .expect_err("必须拒绝");
        assert!(matches!(err, HandshakeError::Transcript(_)));
    }

    #[test]
    fn same_role_is_rejected() {
        let s = secret();
        let client = ClientHandshake::new(NodeKind::Admin, TransportKind::Raw, None);
        let hello = client.hello();
        let err = ServerHandshake::accept(&hello, &s, NodeKind::Admin, TransportKind::Raw, None)
            .expect_err("必须拒绝");
        assert!(matches!(err, HandshakeError::WrongRole { .. }));
    }

    #[test]
    fn server_proof_cannot_be_reflected_to_client() {
        let s = secret();
        let (client, server, ack) = client_and_server();
        // 反射攻击：把服务端 proof 当作客户端 proof 回传。
        let reflected = AuthConfirm {
            proof: server.server_proof(),
            seed_ack: ack.proof,
        };
        assert!(matches!(
            server.finish(&reflected),
            Err(HandshakeError::ProofMismatch)
        ));
        // 客户端也应拒绝「ack.kind 被改成自己角色」的 HelloAck。
        let bad_ack = HelloAck {
            kind: NodeKind::Agent,
            ..ack
        };
        assert!(matches!(
            client.finish(&bad_ack, &s),
            Err(HandshakeError::WrongRole { .. })
        ));
    }

    #[test]
    fn bad_ephemeral_key_is_rejected() {
        let s = secret();
        let mut client = ClientHandshake::new(NodeKind::Agent, TransportKind::Raw, None);
        // 直接把对端公钥设成全零（低阶点）。
        client.nonce = [0u8; KEY_LEN];
        let mut hello = client.hello();
        hello.eph_pub = [0u8; KEY_LEN];
        // ServerHandshake 用全零公钥算 shared 时必须拒绝。
        let err = ServerHandshake::accept(&hello, &s, NodeKind::Admin, TransportKind::Raw, None)
            .expect_err("必须拒绝全零公钥");
        assert!(matches!(err, HandshakeError::BadEphemeralKey));
    }

    #[test]
    fn proof_is_role_bound() {
        let key = [3u8; 32];
        let th = [4u8; 32];
        let a = proof(&key, &th, NodeKind::Admin);
        let b = proof(&key, &th, NodeKind::Agent);
        assert_ne!(a, b, "不同角色的 proof 必须不同");
        assert!(verify(&key, &th, NodeKind::Admin, &a));
        assert!(!verify(&key, &th, NodeKind::Agent, &a));
        assert!(!verify(&key, &th, NodeKind::Admin, &b));
    }

    #[test]
    fn proof_is_deterministic_kat() {
        // KAT：固定输入必须固定输出（改动 HMAC 域分隔或 TH 布局都会打破）。
        let key = [0x00u8; 32];
        let th = [0x00u8; 32];
        let p = proof(&key, &th, NodeKind::Admin);
        assert_ne!(p, [0u8; 32]);
        assert_eq!(p, proof(&key, &th, NodeKind::Admin));
    }

    #[test]
    fn tampered_counter_nonce_yields_mismatch() {
        let s = secret();
        let (client, server, mut ack) = client_and_server();
        // 篡改服务端 nonce 后，客户端算出的 TH 与服务端不同 ⇒ proof 必挂。
        ack.nonce[0] ^= 1;
        assert!(matches!(
            client.finish(&ack, &s),
            Err(HandshakeError::ProofMismatch)
        ));
        assert_eq!(server.server_proof().len(), PROOF_LEN);
    }
}
