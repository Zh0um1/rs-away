//! TLS 证书指纹：SHA-256(DER) 的持有、短显示与比较。
//!
//! 权威：`docs/plan.md` §4.5 / §4.8、`docs/design/transport.md` §6。
//!
//! v1 的 TLS 是「每次重启生成 RSA-1024 自签证书 + `InsecureSkipVerify = true`」，
//! 因而没有任何身份约束（缺陷 #6）。v2 的做法：
//!
//! - 服务端证书由 `HKDF(secret, "tls-cert")` **确定性派生**，重启后指纹不变；
//! - 客户端把期望指纹放进 [`CertFingerprint`]，握手时与对端实际证书比对；
//! - 同时该指纹进入 transcript（见 `stowaway_protocol::handshake::Transcript`），
//!   因此任何中间人替换证书都会让 proof 失配（不只是「记录一条告警」）。

use std::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// 32 字节 SHA-256 证书指纹。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CertFingerprint(pub [u8; 32]);

impl CertFingerprint {
    /// 从证书 DER 字节计算指纹。
    #[must_use]
    pub fn of_der(der: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(der);
        Self(h.finalize().into())
    }

    /// 从原始 32 字节构造。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 原始字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 常数时间比较（指纹属秘密派生值，避免时序侧信道）。
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// 人类可读形式：`ab:cd:ef:...`（32 字节 = 32 组，只在需要时用）。
    #[must_use]
    pub fn colon_hex(&self) -> String {
        let mut s = String::with_capacity(32 * 3);
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                s.push(':');
            }
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// 短形式（前 8 字节，16 个十六进制字符），用于 TUI 单行展示。
    ///
    /// **不可用于校验**：只有 [`Self::ct_eq`] 才是权威比较。
    #[must_use]
    pub fn short(&self) -> String {
        let mut s = String::with_capacity(16);
        for b in &self.0[..8] {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl fmt::Debug for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug 只打短形式，避免日志里出现可用于离线比对的完整指纹。
        write!(f, "CertFingerprint({})", self.short())
    }
}

impl fmt::Display for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

impl From<[u8; 32]> for CertFingerprint {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<CertFingerprint> for [u8; 32] {
    fn from(fp: CertFingerprint) -> Self {
        fp.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_of_der_is_deterministic() {
        let der = b"-----BEGIN CERTIFICATE-----fake-----END-----";
        let a = CertFingerprint::of_der(der);
        let b = CertFingerprint::of_der(der);
        assert_eq!(a, b, "同一 DER 必须得到同一指纹");
        assert_ne!(a, CertFingerprint::of_der(b"other"));
    }

    #[test]
    fn ct_eq_matches_equality() {
        let a = CertFingerprint([7u8; 32]);
        assert!(a.ct_eq(&CertFingerprint([7u8; 32])));
        assert!(!a.ct_eq(&CertFingerprint([8u8; 32])));
    }

    #[test]
    fn short_and_colon_hex_shapes() {
        let fp = CertFingerprint([0xab; 32]);
        assert_eq!(fp.short().len(), 16);
        assert_eq!(fp.colon_hex().len(), 32 * 3 - 1);
        assert!(fp.colon_hex().starts_with("ab:ab:"));
        assert_eq!(format!("{fp:?}"), "CertFingerprint(abababababababab)");
    }

    #[test]
    fn debug_does_not_leak_full_fingerprint() {
        let fp = CertFingerprint([0xff; 32]);
        let dbg = format!("{fp:?}");
        assert!(!dbg.contains(&"ff:".repeat(2)));
        assert_eq!(dbg.matches("ff").count(), 8);
    }
}
