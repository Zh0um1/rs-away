//! 握手、KDF、逐跳密封（LinkSealer）、证书指纹。
//!
//! 权威定义：`docs/plan.md` §4.5。所有密钥材料用 `Zeroizing` 持有，
//! 比较一律走 `subtle::ConstantTimeEq`。
//!
//! 模块：
//! - [`secret`]：`secret` 的三种来源（argv / `env:` / `file:` / `stdin:`）、
//!   强度校验、`Zeroizing` 持有、启动即 mlock；
//! - [`kdf`]：X25519 → HKDF-Extract → 三个子密钥（auth/link/session）；
//! - [`handshake`]：3-flight 的密码学部分（proof 生成/校验、`Ready` 判定）；
//! - [`sealer`]：link 层 `AES-256-GCM` 密封、`iv‖counter` nonce、
//!   1024 位滑动窗口、2²⁸ 帧 rekey；
//! - [`fingerprint`]：TLS 证书指纹（SHA-256 DER）与短显示。
#![forbid(unsafe_code)]
// 库代码禁止直接打印（由二进制/调用方决定输出方式）。
#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod fingerprint;
pub mod handshake;
pub mod kdf;
pub mod sealer;
pub mod secret;

pub use fingerprint::CertFingerprint;
pub use handshake::{
    ClientHandshake, HandshakeError, HandshakeOutcome, HandshakeSecrets, ServerHandshake,
    seed_ack_of,
};
pub use kdf::{LinkKeys, derive_link_keys, kcp_conv, rekey};
pub use sealer::{LinkSealer, ReplayWindow, SealerError};
pub use secret::{Secret, SecretError, SecretSource};

/// 密钥长度（AES-256 / HMAC-SHA256 / X25519 公钥均为 32 字节）。
pub const KEY_LEN: usize = 32;

/// 握手 proof 长度。
pub const PROOF_LEN: usize = 32;

/// 帧计数器 rekey 阈值（每 2²⁸ 帧换一次密钥，见 §4.5）。
pub const REKEY_INTERVAL: u64 = 1 << 28;

/// 滑动窗口位宽（见 §4.5「1024 位滑动窗口」）。
pub const REPLAY_WINDOW_BITS: usize = 1024;
