//! X25519 + HKDF 的密钥派生（plan §4.5 的 KDF 段落）。
//!
//! 派生链：
//!
//! ```text
//! shared   = X25519(local_eph_secret, peer_eph_public)
//! PRK      = HKDF-Extract(salt = client_nonce ‖ server_nonce, ikm = shared)
//! auth_key = HKDF-Expand(PRK, "auth"   ‖ SHA256(secret), 32)
//! link_key = HKDF-Expand(PRK, "link",                     32)
//! session_key_seed = HKDF-Expand(PRK, "session",          32)
//! ```
//!
//! `secret_digest` 为定长 32 字节，避免把变长 secret 直接塞进 KDF 输入；
//! 错误 secret ⇒ 不同 `auth_key` ⇒ proof 校验失败（§4.5「认证」）。
//!
//! 注意 `X25519` 的**双方临时私钥都是临时生成的**（`EphemeralSecret` 消耗 self），
//! 因此 `shared` 只能算一次；本模块的输入是已经算好的 `shared`，便于测试与
//! 把 DH 放在调用方（真正的私钥不作 `Clone`/`Copy`）。

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::KEY_LEN;

/// HKDF 的 info 域名（域分隔，防止跨用途复用同一 PRK）。
pub mod info {
    /// 认证子密钥。
    pub const AUTH: &[u8] = b"auth";
    /// 逐跳密封子密钥。
    pub const LINK: &[u8] = b"link";
    /// 会话层（E2E）种子。
    pub const SESSION: &[u8] = b"session";
    /// rekey 子密钥（§4.5「每 2²⁸ 帧密钥轮换」）。
    pub const REKEY: &[u8] = b"rekey";
    /// KCP `conv` 派生（transport.md §5）。
    pub const KCP_CONV: &[u8] = b"kcp-conv";
}

/// 一次握手产出的全部子密钥。
///
/// 全部用 `Zeroizing` 包裹：离开作用域即清零。
pub struct LinkKeys {
    /// proof 用。
    pub auth_key: Zeroizing<[u8; KEY_LEN]>,
    /// 帧密封用。
    pub link_key: Zeroizing<[u8; KEY_LEN]>,
    /// E2E 会话种子。
    pub session_key_seed: Zeroizing<[u8; KEY_LEN]>,
    /// 本次握手暴露给对端的临时公钥（写进 `Hello`/`HelloAck`）。
    pub local_eph_pub: [u8; KEY_LEN],
    /// 对端临时公钥。
    pub peer_eph_pub: [u8; KEY_LEN],
    /// 本端 nonce。
    pub local_nonce: [u8; KEY_LEN],
    /// 对端 nonce。
    pub peer_nonce: [u8; KEY_LEN],
}

impl std::fmt::Debug for LinkKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 密钥内容永不进日志。
        f.debug_struct("LinkKeys")
            .field("auth_key", &"<redacted>")
            .field("link_key", &"<redacted>")
            .field("session_key_seed", &"<redacted>")
            .field("local_eph_pub", &self.local_eph_pub)
            .field("peer_eph_pub", &self.peer_eph_pub)
            .field("local_nonce", &self.local_nonce)
            .field("peer_nonce", &self.peer_nonce)
            .finish()
    }
}

/// 从 `shared` + 双方 nonce 派生三个子密钥。
///
/// `salt` 顺序固定为 `client_nonce ‖ server_nonce`（**与谁调用无关**），
/// 因此两侧派生出完全相同的密钥。
#[must_use]
pub fn derive_link_keys(
    shared: &[u8; KEY_LEN],
    client_nonce: &[u8; KEY_LEN],
    server_nonce: &[u8; KEY_LEN],
    secret_digest: &[u8; KEY_LEN],
) -> LinkKeys {
    let mut salt = Zeroizing::new([0u8; KEY_LEN * 2]);
    salt[..KEY_LEN].copy_from_slice(client_nonce);
    salt[KEY_LEN..].copy_from_slice(server_nonce);

    let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt[..]), shared);
    let _ = prk;

    let mut auth_key = Zeroizing::new([0u8; KEY_LEN]);
    {
        // info = "auth" ‖ secret_digest（§4.5）
        let mut buf = Zeroizing::new(Vec::with_capacity(info::AUTH.len() + KEY_LEN));
        buf.extend_from_slice(info::AUTH);
        buf.extend_from_slice(secret_digest);
        hk.expand(&buf, &mut auth_key[..]).expect("32 < 255*32"); // assert-ok: 输出恒 < 255*32
    }

    let mut link_key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info::LINK, &mut link_key[..])
        .expect("32 < 255*32"); // assert-ok: 输出恒 < 255*32

    let mut session_key_seed = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info::SESSION, &mut session_key_seed[..])
        .expect("32 < 255*32"); // assert-ok: 同上

    LinkKeys {
        auth_key,
        link_key,
        session_key_seed,
        local_eph_pub: [0u8; KEY_LEN],
        peer_eph_pub: [0u8; KEY_LEN],
        local_nonce: [0u8; KEY_LEN],
        peer_nonce: [0u8; KEY_LEN],
    }
}

/// rekey：`link_key' = HKDF-Expand(link_key, "rekey" ‖ counter, 32)`。
#[must_use]
pub fn rekey(link_key: &[u8; KEY_LEN], counter: u64) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::from_prk(link_key).expect("32 >= 最小 PRK"); // assert-ok: 32 字节是合法 PRK 长度
    let mut buf = Zeroizing::new(Vec::with_capacity(info::REKEY.len() + 8));
    buf.extend_from_slice(info::REKEY);
    buf.extend_from_slice(&counter.to_le_bytes());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&buf, &mut out[..]).expect("32 < 255*32"); // assert-ok: 输出恒 < 255*32
    out
}

/// KCP 的 `conv`（transport.md §5：`HKDF(secret, "kcp-conv")[:4]`）。
#[must_use]
pub fn kcp_conv(secret: &[u8]) -> u32 {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = [0u8; 4];
    hk.expand(info::KCP_CONV, &mut out).expect("4 < 255*32"); // assert-ok: 输出恒 < 255*32
    u32::from_le_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    fn shared_between() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let a = EphemeralSecret::random_from_rng(&mut rand::rng());
        let b = EphemeralSecret::random_from_rng(&mut rand::rng());
        let a_pub = PublicKey::from(&a);
        let b_pub = PublicKey::from(&b);
        let s1 = a.diffie_hellman(&b_pub).to_bytes();
        let s2 = b.diffie_hellman(&a_pub).to_bytes();
        // 双方算出的 shared 必须一致（X25519 交换律）。
        assert_eq!(s1, s2);
        (s1, a_pub.to_bytes(), b_pub.to_bytes(), s2)
    }

    #[test]
    fn both_sides_derive_identical_keys() {
        let (shared, _, _, _) = shared_between();
        let cn = [0x11u8; 32];
        let sn = [0x22u8; 32];
        let digest = [0x33u8; 32];
        let a = derive_link_keys(&shared, &cn, &sn, &digest);
        let b = derive_link_keys(&shared, &cn, &sn, &digest);
        assert_eq!(&a.auth_key[..], &b.auth_key[..]);
        assert_eq!(&a.link_key[..], &b.link_key[..]);
        assert_eq!(&a.session_key_seed[..], &b.session_key_seed[..]);
        // 三个子密钥互不相同（域分隔生效）。
        assert_ne!(&a.auth_key[..], &a.link_key[..]);
        assert_ne!(&a.link_key[..], &a.session_key_seed[..]);
    }

    #[test]
    fn different_secret_yields_different_auth_key() {
        let (shared, _, _, _) = shared_between();
        let cn = [1u8; 32];
        let sn = [2u8; 32];
        let a = derive_link_keys(&shared, &cn, &sn, &[3u8; 32]);
        let b = derive_link_keys(&shared, &cn, &sn, &[4u8; 32]);
        assert_ne!(&a.auth_key[..], &b.auth_key[..]);
        // 但 link_key 与 secret 无关（PFS：只有 auth 绑 secret）。
        assert_eq!(&a.link_key[..], &b.link_key[..]);
    }

    #[test]
    fn nonce_order_matters() {
        let (shared, _, _, _) = shared_between();
        let a = derive_link_keys(&shared, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let b = derive_link_keys(&shared, &[2u8; 32], &[1u8; 32], &[3u8; 32]);
        assert_ne!(&a.link_key[..], &b.link_key[..], "salt 顺序必须固定");
    }

    #[test]
    fn rekey_is_counter_dependent_and_distinct() {
        let key = [7u8; 32];
        let r0 = rekey(&key, 0);
        let r1 = rekey(&key, 1);
        assert_ne!(&r0[..], &r1[..]);
        assert_eq!(&r0[..], &rekey(&key, 0)[..]);
        assert_ne!(&r0[..], &key, "rekey 必须换掉密钥");
    }

    #[test]
    fn kcp_conv_is_deterministic_and_secret_dependent() {
        assert_eq!(kcp_conv(b"secret"), kcp_conv(b"secret"));
        assert_ne!(kcp_conv(b"secret"), kcp_conv(b"secret2"));
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let (shared, _, _, _) = shared_between();
        let keys = derive_link_keys(&shared, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let s = format!("{keys:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("link_key: ["));
    }
}
