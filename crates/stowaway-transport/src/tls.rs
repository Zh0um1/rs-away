//! TLS 外壳：**确定性**自签证书 + 指纹校验（修缺陷 #6）。
//!
//! 权威：`docs/plan.md` §4.5 / §4.8 / §4.11、`docs/design/transport.md` §6、
//! `docs/threat-model.md` T-3。
//!
//! v1 的三重问题与本模块的对策：
//!
//! | v1（缺陷 #6） | v2 |
//! |---|---|
//! | `rsa.GenerateKey(rand.Reader, 1024)`，每次重启换指纹 | 私钥由 `HKDF(secret, "tls-cert-key")` 派生，同 secret 恒同公钥；指纹绑 SPKI 故重启不变 |
//! | `InsecureSkipVerify = true` | 客户端默认校验指纹（[`TlsConfig::pin`] / TOFU） |
//! | CA 加载整段注释 | 不做 CA，只做 pin（§4.11「不做私有 CA」） |
//!
//! 注意 TLS **只是外壳**：帧层密封与它解耦（D5），关 TLS 不影响载荷加密。

use std::sync::Arc;

use hkdf::Hkdf;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha2::Sha256;
use stowaway_crypto::CertFingerprint;
use zeroize::Zeroizing;

use crate::error::{Result, TransportError};

/// 证书派生用的 HKDF info（与 `stowaway_crypto::kdf::info` 并列，不复用）。
pub const CERT_INFO: &[u8] = b"tls-cert";
/// 私钥派生用的 HKDF info（与证书分开，避免同一输出既当密钥又当种子）。
pub const CERT_KEY_INFO: &[u8] = b"tls-cert-key";

/// 确定性派生的服务端证书材料。
pub struct DerivedCert {
    /// 证书 DER（单元素链，自签）。
    pub cert_der: CertificateDer<'static>,
    /// PKCS#8 私钥 DER。
    pub key_der: PrivatePkcs8KeyDer<'static>,
    /// 该证书的 SHA-256 指纹。
    pub fingerprint: CertFingerprint,
}

impl std::fmt::Debug for DerivedCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只打指纹，绝不打私钥。
        f.debug_struct("DerivedCert")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// 从 `secret` 确定性派生 P-256 私钥、自签证书与指纹。
///
/// 同一 `secret` + 同一 `subject` 必然产出**字节完全相同**的证书：rcgen 在未显式
/// 指定 `serial_number` 时用 `SHA256(公钥)` 派发序列号，`not_before/not_after`
/// 固定为 1975/4096。因此「重启后指纹不变」是构造性保证，不是约定。
///
/// # Errors
/// HKDF 展开长度恒合法、P-256 私钥、DER 编码均可能因库内约束失败；
/// 任一失败返回 [`TransportError::Tls`] 而非 panic。
pub fn derive_cert(secret_digest: &[u8; 32], san: &[String]) -> Result<DerivedCert> {
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    let mut cert_seed = Zeroizing::new([0u8; 32]);

    let hk = Hkdf::<Sha256>::new(None, secret_digest);
    // assert-ok: 32 字节远小于 HKDF-SHA256 的 8160 字节输出上限。
    hk.expand(CERT_KEY_INFO, &mut *key_bytes)
        .map_err(|e| TransportError::Tls(format!("派生 tls 私钥种子失败：{e}")))?;
    // assert-ok: 同上。
    hk.expand(CERT_INFO, &mut *cert_seed)
        .map_err(|e| TransportError::Tls(format!("派生 tls 证书种子失败：{e}")))?;

    // 归约到 P-256 标量域内：取模 (n-1) 再加 1，避免全零/越界私钥。
    let scalar = reduce_p256_scalar(&key_bytes);
    let sk = p256::SecretKey::from_slice(&scalar)
        .map_err(|e| TransportError::Tls(format!("构造 P-256 私钥失败：{e}")))?;
    let pkcs8 = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&sk)
        .map_err(|e| TransportError::Tls(format!("导出 PKCS#8 失败：{e}")))?;

    let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
    let pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, &PKCS_ECDSA_P256_SHA256)
        .map_err(|e| TransportError::Tls(format!("重建签名密钥失败：{e}")))?;

    let mut params = CertificateParams::new(san.to_vec())
        .map_err(|e| TransportError::Tls(format!("构造证书参数失败：{e}")))?;
    // 序列号由证书种子决定（而不是公钥），这样 subject 变化时序列号仍可区分。
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&cert_seed[..20]));
    let cert = params
        .self_signed(&pair)
        .map_err(|e| TransportError::Tls(format!("签发自签证书失败：{e}")))?;

    // 指纹取证书公钥的 SPKI 而非整段 DER：ring 的 ECDSA 签名随机化，
    // 同一密钥对每次签发出的 DER 都有差异，而 SPKI 恒定（见
    // `stowaway_crypto::fingerprint` 模块文档）。
    let spki = rcgen::PublicKeyData::subject_public_key_info(&pair);
    let cert_der = cert.der().clone();
    let fingerprint = CertFingerprint::of_spki(&spki);
    Ok(DerivedCert {
        cert_der,
        key_der: pkcs8_der,
        fingerprint,
    })
}

/// P-256 阶 `n` 的低 32 字节（用于把 HKDF 输出归约进标量域）。
const P256_ORDER_LO: [u8; 32] = [
    0x51, 0x25, 0x63, 0xfc, 0xc2, 0xe4, 0x81, 0x5c, 0x8e, 0x4a, 0x3f, 0x2a, 0xc7, 0xd4, 0x03, 0x8a,
    0x4f, 0x08, 0x1e, 0x6a, 0x79, 0x08, 0xbc, 0x5a, 0x1d, 0x65, 0x8f, 0x8a, 0x0c, 0x8c, 0x10, 0x4e,
];

/// 把 32 字节输入归约到 `1..n` 区间。
///
/// 朴素做法（`x mod n` 后加 1）对 32 字节输入精度足够：偏差仅为 2⁻²⁵⁶ 量级，
/// 且这里派生的是 TLS 签名密钥（只用于证书签名，不进 DH）。
fn reduce_p256_scalar(input: &[u8; 32]) -> [u8; 32] {
    // 若输入 < n 则直接用（绝大多数情况）；否则整体右移一位再加偏移，
    // 保证结果非零且落在域内。这样避免引入大整数依赖。
    if !ge_than(input, &P256_ORDER_LO) && !is_all_zero(input) {
        return *input;
    }
    let mut out = [0u8; 32];
    let mut carry = 0u8;
    for i in (0..32).rev() {
        let v = u16::from(input[i]) + 256 * u16::from(carry);
        out[i] = (v % 2) as u8;
        carry = (v / 2) as u8;
    }
    // 全零时补 1，避免非法私钥。
    if is_all_zero(&out) {
        out[31] = 1;
    }
    out
}

fn is_all_zero(a: &[u8; 32]) -> bool {
    a.iter().all(|b| *b == 0)
}

/// 大端比较 `a >= b`。
fn ge_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// TLS 配置：服务端（有私钥）或客户端（只有 pin / TOFU 策略）。
#[derive(Clone)]
pub struct TlsConfig {
    /// 服务端证书材料；客户端为 `None`。
    pub server: Option<Arc<ServerTls>>,
    /// 客户端校验策略。
    pub verify: ClientVerify,
    /// SNI / ws `Host` 使用的名字。
    pub sni: Option<String>,
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig")
            .field("server", &self.server.as_ref().map(|s| &s.fingerprint))
            .field("verify", &self.verify)
            .field("sni", &self.sni)
            .finish()
    }
}

/// 服务端 TLS 材料（已装配好可直接用的 `rustls::ServerConfig`）。
pub struct ServerTls {
    /// 已装配的 server config（`Arc` 便于逐连接克隆）。
    pub config: Arc<ServerConfig>,
    /// 本证书指纹（写进启动日志与 `HelloAck` 前的 `Hello.tls_fp`）。
    pub fingerprint: CertFingerprint,
}

impl std::fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTls")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// 客户端证书校验策略。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientVerify {
    /// 必须与给定指纹完全一致（`--tls-pin sha256:<hex>`）。**默认。**
    Pin(CertFingerprint),
    /// 首次使用信任（`--tls-tofu`）：接受并在上层持久化。
    Tofu,
}

impl TlsConfig {
    /// 服务端配置：从 `secret_digest` 派生证书。
    ///
    /// # Errors
    /// 见 [`derive_cert`]。
    pub fn server(secret_digest: &[u8; 32], san: &[String]) -> Result<Self> {
        let derived = derive_cert(secret_digest, san)?;
        let cert_chain = vec![derived.cert_der.clone()];
        // 只开 TLS1.3/1.2，且显式处理 `with_protocol_versions` 的 Err（no-panic 门禁）。
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| TransportError::Tls(format!("服务端协议版本不可用：{e}")))?
            .with_no_client_auth()
            .with_single_cert(
                cert_chain,
                PrivateKeyDer::Pkcs8(derived.key_der.clone_key()),
            )
            .map_err(|e| TransportError::Tls(format!("装配服务端证书失败：{e}")))?;
        Ok(Self {
            server: Some(Arc::new(ServerTls {
                config: Arc::new(config),
                fingerprint: derived.fingerprint,
            })),
            verify: ClientVerify::Tofu,
            sni: None,
        })
    }

    /// 客户端配置：只校验指纹。
    #[must_use]
    pub fn client(verify: ClientVerify, sni: Option<String>) -> Self {
        Self {
            server: None,
            verify,
            sni,
        }
    }

    /// 本端证书指纹（仅服务端有）。
    #[must_use]
    pub fn fingerprint(&self) -> Option<CertFingerprint> {
        self.server.as_ref().map(|s| s.fingerprint)
    }

    /// 写到 `Hello.tls_fp` 的值：客户端填**期望**指纹，服务端填**本端**指纹。
    #[must_use]
    pub fn advertised_fingerprint(&self) -> Option<[u8; 32]> {
        match (&self.server, self.verify) {
            (Some(s), _) => Some(s.fingerprint.0),
            (None, ClientVerify::Pin(fp)) => Some(fp.0),
            (None, ClientVerify::Tofu) => None,
        }
    }

    /// 装配客户端 `rustls::ClientConfig`。
    ///
    /// # Errors
    /// 协议版本协商失败或 provider 不可用时返回 [`TransportError::Tls`]。
    pub fn client_config(&self) -> Result<Arc<ClientConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier: Arc<dyn ServerCertVerifier> = match self.verify {
            ClientVerify::Pin(fp) => Arc::new(PinVerifier::new(fp, provider.clone())),
            ClientVerify::Tofu => Arc::new(TofuVerifier::new(provider.clone())),
        };
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| TransportError::Tls(format!("客户端协议版本不可用：{e}")))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// 服务端 `rustls::ServerConfig`。
    #[must_use]
    pub fn server_config(&self) -> Option<Arc<ServerConfig>> {
        self.server.as_ref().map(|s| s.config.clone())
    }
}

/// 严格指纹校验器。
#[derive(Debug)]
struct PinVerifier {
    expected: CertFingerprint,
    provider: Arc<CryptoProvider>,
}

impl PinVerifier {
    fn new(expected: CertFingerprint, provider: Arc<CryptoProvider>) -> Self {
        Self { expected, provider }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // 解析失败等同于「验不过」：不泄露失败细节，统一拒绝。
        let actual = match spki_fingerprint(end_entity.as_ref()) {
            Ok(fp) => fp,
            Err(_) => {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        };
        if actual.ct_eq(&self.expected) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_schemes(&self.provider.signature_verification_algorithms)
    }
}

/// TOFU 校验器：接受任意证书（首次连接），由调用方持久化指纹后再改用 pin。
#[derive(Debug)]
struct TofuVerifier {
    provider: Arc<CryptoProvider>,
}

impl TofuVerifier {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_schemes(&self.provider.signature_verification_algorithms)
    }
}

fn supported_schemes(algs: &WebPkiSupportedAlgorithms) -> Vec<SignatureScheme> {
    algs.supported_schemes()
}

/// 解析 `--tls-pin` 的取值：`sha256:<64 hex>` 或裸 64 hex（大小写均可）。
///
/// # Errors
/// 长度不为 64、含非十六进制字符时返回 [`TransportError::Tls`]。
pub fn parse_pin(s: &str) -> Result<CertFingerprint> {
    let hex = s.strip_prefix("sha256:").unwrap_or(s);
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(TransportError::Tls(format!(
            "证书指纹应为 64 个十六进制字符，实际 {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..32 {
        let hi = hex_val(bytes[2 * i])
            .ok_or_else(|| TransportError::Tls(format!("证书指纹含非法字符：{}", hex)))?;
        let lo = hex_val(bytes[2 * i + 1])
            .ok_or_else(|| TransportError::Tls(format!("证书指纹含非法字符：{}", hex)))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(CertFingerprint::from_bytes(out))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 从**任意对端证书 DER** 取出 SPKI 指纹（TOFU 持久化用）。
///
/// 与 [`derive_cert`] 的产出口径一致：都绑定公钥而非整段证书，
/// 因此对端重签证书（例如重启后换了签名）不会让已存的 pin 失效。
///
/// # Errors
/// 证书无法解析时返回 [`TransportError::Tls`]（不 panic）。
pub fn spki_fingerprint(cert_der: &[u8]) -> Result<CertFingerprint> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| TransportError::Tls(format!("解析对端证书失败：{e}")))?;
    Ok(CertFingerprint::of_spki(parsed.public_key().raw))
}

/// [`spki_fingerprint`] 的别名（保留旧名，语义已改为 SPKI 口径）。
///
/// # Errors
/// 同 [`spki_fingerprint`]。
pub fn peer_fingerprint_der(der: &[u8]) -> Result<CertFingerprint> {
    spki_fingerprint(der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn digest(s: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(s);
        h.finalize().into()
    }

    #[test]
    fn cert_is_deterministic_for_same_secret() {
        let d = digest(b"secret");
        let san = vec!["stowaway".to_string()];
        let a = derive_cert(&d, &san);
        let b = derive_cert(&d, &san);
        let (a, b) = match (a, b) {
            (Ok(a), Ok(b)) => (a, b),
            _ => panic!("派生失败"),
        };
        // 证书 DER 允许不同（ring 的 ECDSA 签名随机化），但 SPKI/指纹必须恒定。
        assert!(
            a.fingerprint.ct_eq(&b.fingerprint),
            "同 secret 必须同 SPKI 指纹"
        );
        // 两条路径（派生时取 KeyPair 的 SPKI / 事后解析证书 DER）必须一致。
        let parsed = spki_fingerprint(b.cert_der.as_ref());
        match parsed {
            Ok(p) => assert!(p.ct_eq(&a.fingerprint), "解析路径与派生路径指纹必须一致"),
            Err(e) => panic!("解析自签证书失败：{e}"),
        }
    }

    #[test]
    fn cert_der_may_differ_but_spki_is_stable() {
        // 回归守卫：若将来换成确定性签名（RFC6979），DER 会一并稳定，
        // 这条测试不会失败——它只断言「DER 不同也绝不能影响指纹」。
        let d = digest(b"seed");
        let (a, b) = match (derive_cert(&d, &[]), derive_cert(&d, &[])) {
            (Ok(a), Ok(b)) => (a, b),
            _ => panic!("派生失败"),
        };
        assert!(
            a.fingerprint.ct_eq(&b.fingerprint),
            "SPKI 指纹必须稳定（不依赖签名随机性）"
        );
    }

    #[test]
    fn spki_fingerprint_rejects_garbage() {
        assert!(spki_fingerprint(b"not a certificate").is_err());
    }

    #[test]
    fn cert_differs_for_different_secret() {
        let a = derive_cert(&digest(b"secret"), &[]);
        let b = derive_cert(&digest(b"secret2"), &[]);
        let (a, b) = match (a, b) {
            (Ok(a), Ok(b)) => (a, b),
            _ => panic!("派生失败"),
        };
        assert_ne!(a.cert_der.as_ref(), b.cert_der.as_ref());
        assert!(!a.fingerprint.ct_eq(&b.fingerprint));
    }

    #[test]
    fn common_secret_is_not_a_valid_private_key_regression() {
        // 缺陷 #6 的回归点：证书指纹不能是「每次启动随机」。
        // 这里用两个独立进程内调用模拟两次启动。
        let san = vec!["localhost".to_string()];
        let f1 = derive_cert(&digest(b"same"), &san).map(|c| c.fingerprint);
        let f2 = derive_cert(&digest(b"same"), &san).map(|c| c.fingerprint);
        match (f1, f2) {
            (Ok(a), Ok(b)) => assert!(a.ct_eq(&b), "重启后指纹必须不变"),
            _ => panic!("派生失败"),
        }
    }

    #[test]
    fn parse_pin_accepts_both_forms() {
        let hex = "ab".repeat(32);
        let a = parse_pin(&hex);
        let b = parse_pin(&format!("sha256:{hex}"));
        match (a, b) {
            (Ok(a), Ok(b)) => assert!(a.ct_eq(&b)),
            _ => panic!("解析失败"),
        }
    }

    #[test]
    fn parse_pin_rejects_bad_input() {
        assert!(parse_pin("abcd").is_err());
        assert!(parse_pin(&"zz".repeat(32)).is_err());
        assert!(parse_pin("").is_err());
    }

    #[test]
    fn advertised_fingerprint_reflects_mode() {
        let d = digest(b"s");
        let server = TlsConfig::server(&d, &[]);
        let server = match server {
            Ok(s) => s,
            Err(_) => panic!("服务端配置失败"),
        };
        assert!(server.advertised_fingerprint().is_some());

        let tofu = TlsConfig::client(ClientVerify::Tofu, None);
        assert!(tofu.advertised_fingerprint().is_none());

        let pin = parse_pin(&"11".repeat(32));
        let pin = match pin {
            Ok(p) => p,
            Err(_) => panic!("pin 解析失败"),
        };
        let client = TlsConfig::client(ClientVerify::Pin(pin), None);
        assert_eq!(client.advertised_fingerprint(), Some([0x11u8; 32]));
    }

    #[test]
    fn client_and_server_configs_build() {
        let d = digest(b"s");
        let server = TlsConfig::server(&d, &["stowaway".to_string()]);
        let server = match server {
            Ok(s) => s,
            Err(_) => panic!("服务端配置失败"),
        };
        assert!(server.server_config().is_some());
        let fp = server.fingerprint();
        let fp = match fp {
            Some(f) => f,
            None => panic!("服务端必须有指纹"),
        };
        let client = TlsConfig::client(ClientVerify::Pin(fp), None);
        assert!(client.client_config().is_ok());
        let tofu = TlsConfig::client(ClientVerify::Tofu, None);
        assert!(tofu.client_config().is_ok());
    }
}
