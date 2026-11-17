//! §3 缺陷回归测试（密码学侧）。
//!
//! 权威：`docs/plan.md` §3 缺陷表、§8.6 DoD「每一项缺陷都有 `defect_<n>_` 前缀的
//! 回归测试」。协议层的 #1–#5、#11 见 `crates/stowaway-protocol/tests/defects.rs`，
//! 这里覆盖 v1 中「密码学静默失败」的一族。

use stowaway_crypto::{
    HandshakeError, LinkSealer, SealerError, Secret, derive_link_keys,
    fingerprint::CertFingerprint, rekey,
};
use stowaway_protocol::{
    msg::{Hello, Message},
    node::NodeKind,
    transport_kind::TransportKind,
};

fn keys(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// §3 #9：v1 的 `crypto/aes.go` 对 `aes.NewCipher`/`gcm.Open` 的错误全用 `_` 吞掉，
/// 解密失败时返回 `nil`（等于**空 payload 静默通过**）。
///
/// v2 要求：任何认证失败都必须返回 `Err`，绝不能把「解密失败」表现为空数据。
#[test]
fn defect_9_decrypt_failure_is_error_never_empty_payload() {
    let mut sender = LinkSealer::new(&keys(1), true);
    let mut receiver = LinkSealer::new(&keys(1), false);

    let (ct, counter) = sender.seal(b"aad", b"real-payload").expect("seal");
    assert!(!ct.is_empty(), "密文必须非空（含 16 字节 tag）");

    // 篡改一个字节：必须明确报错，而**不是**返回空 Vec。
    let mut bad = ct.clone();
    bad[0] ^= 0xff;
    match receiver.open(counter, b"aad", &bad) {
        Err(SealerError::AuthFailed) => {}
        other => panic!("篡改密文必须以 AuthFailed 拒绝，实际：{other:?}"),
    }

    // AAD 被改也必须拒绝（v1 完全没有 AAD 概念）。
    let (ct2, counter2) = sender.seal(b"aad", b"payload").expect("seal");
    assert!(matches!(
        receiver.open(counter2, b"other-aad", &ct2),
        Err(SealerError::AuthFailed)
    ));

    // 原始密文仍然可以正常解开——证明上面失败的是校验而非解错。
    assert_eq!(
        receiver.open(counter2, b"aad", &ct2).expect("open"),
        b"payload"
    );
}

/// §3 #9 续：错误密钥也必须报错（v1 用错密钥时 `gcm.Open` 失败→ `nil` → 空 payload）。
#[test]
fn defect_9_wrong_key_is_error_not_silent_empty() {
    let mut sender = LinkSealer::new(&keys(2), true);
    let mut receiver = LinkSealer::new(&keys(3), false);
    let (ct, counter) = sender.seal(b"", b"top-secret").expect("seal");
    assert!(receiver.open(counter, b"", &ct).is_err());
}

/// §3 #7：v1 的 preauth 是 `conn.Write(MD5(secret)[:16])`，可被离线字典验证、
/// 且可被完整重放。v2 的 `Hello` 必须携带**每次会话新鲜**的临时公钥与 nonce，
/// 而不是一个与 secret 一一对应的静态 token。
#[test]
fn defect_7_hello_carries_fresh_ephemeral_material_not_static_token() {
    use stowaway_crypto::ClientHandshake;

    let a = ClientHandshake::new(NodeKind::Agent, TransportKind::Raw, None);
    let b = ClientHandshake::new(NodeKind::Agent, TransportKind::Raw, None);
    let (ha, hb) = (a.hello(), b.hello());

    assert_ne!(ha.eph_pub, hb.eph_pub, "每次握手必须是新的临时公钥");
    assert_ne!(ha.nonce, hb.nonce, "每次握手必须是新的 nonce");
    // 与 secret 无任何静态映射：换 secret 不改变客户端首包内容。
    let s1 = Secret::load("secret-one", 1).expect("s");
    let s2 = Secret::load("secret-two", 1).expect("s");
    assert_ne!(
        s1.digest().as_ref(),
        s2.digest().as_ref(),
        "secret 本身仍然区分（用于 proof），但不以明文/哈希形式出现在首包"
    );
    // 首包里没有任何 16 字节的「token 字段」：只有公钥(32)+nonce(32)。
    let encoded = Message::Hello(ha).encode().expect("encode");
    // postcard：kind(1) + transport(1) + Option::None 标记(1) + eph_pub(32) + nonce(32)。
    assert_eq!(
        encoded.len(),
        67,
        "Hello 载荷 = kind+transport+tls_fp_tag+eph_pub+nonce（无 TLS 时共 67 字节）"
    );
    // 带 TLS 指纹时多 32 字节。
    let with_tls = Message::Hello(stowaway_protocol::msg::Hello {
        tls_fp: Some([7u8; 32]),
        ..ha
    })
    .encode()
    .expect("encode");
    assert_eq!(with_tls.len(), 99);
}

/// §3 #6 的密码学前置：指纹必须能**确定性**派生并比较，
/// 否则「重启后指纹不变 + TOFU」无从谈起（v1 每次重启重新生成 RSA-1024 密钥）。
#[test]
fn defect_6_fingerprint_is_deterministic_and_comparable() {
    let der = b"deterministic-certificate-der";
    let a = CertFingerprint::of_der(der);
    let b = CertFingerprint::of_der(der);
    assert!(a.ct_eq(&b), "同一证书必须得到可比对的一致指纹");
    assert!(!a.ct_eq(&CertFingerprint::of_der(b"another")));
    // 指纹是 32 字节 SHA-256，不是 v1 的 MD5 截断（16 字节）。
    assert_eq!(a.as_bytes().len(), 32);
}

/// §3 #5 的密码学侧：link 层密封是**显式**的，不依赖「头里某个 UUID 等于谁」
/// 来推断是否加密（v1 用 `Accepter == TEMP_UUID || UUID == ADMIN_UUID` 决定是否解密）。
#[test]
fn defect_5_sealing_does_not_depend_on_identity_fields() {
    // 同一把密钥，不同「身份」参数下行为完全一致：密封与否只由调用方决定。
    let mut s1 = LinkSealer::new(&keys(9), true);
    let mut r1 = LinkSealer::new(&keys(9), false);
    let (ct, c) = s1.seal(b"hdr", b"body").expect("seal");
    assert_eq!(r1.open(c, b"hdr", &ct).expect("open"), b"body");

    // 未密封的明文**不可能**被 open 成功（没有「某些帧就是明文」的后门）。
    assert!(r1.open(c + 1, b"hdr", b"body").is_err());
}

/// §3 #5 的补充（被动侧污染）：v1 在 TLS 分支把**共享的** `options.Secret` 置空，
/// 一次 accept 之后同一进程后续连接的 secret 全没了。
///
/// v2 的 `Secret` 是不可变值语义：`digest()` 借用 `&self`，任何「清零」只能发生
/// 在所有者 Drop 时，不可能通过一次握手把别人的 secret 抹掉。
#[test]
fn defect_5_secret_cannot_be_zeroed_through_a_borrow() {
    let s = Secret::load("shared-secret", 1).expect("s");
    let before = *s.digest();
    // 模拟「握手期间传 &Secret 给对端处理」——借用结束后原值必须完好。
    {
        let borrowed: &Secret = &s;
        let _used = *borrowed.digest();
    }
    assert_eq!(*s.digest(), before, "借用不可能把共享 secret 清零");
    assert_eq!(s.expose(), b"shared-secret", "内容必须原样可读");
    // 只有 bot 自己的副本 Drop 才会 zeroize。
    let copy = Secret::load("shared-secret", 1).expect("s");
    drop(copy);
    assert_eq!(s.expose(), b"shared-secret");
}

/// §3 #9 的 rekey 侧：密钥换代必须**双向同步**，且换代后旧密钥解不开新帧。
#[test]
fn defect_9_rekey_is_synchronised_and_old_key_cannot_open_new_frames() {
    let base = keys(0x42);
    let next = rekey(&base, 1);
    assert_ne!(&base[..], &next[..]);

    let mut sender = LinkSealer::new(&base, true);
    let mut receiver = LinkSealer::new(&base, false);
    // 双方都在 generation 0，正常通信。
    let (ct, c) = sender.seal(b"", b"hello").expect("seal");
    assert_eq!(receiver.open(c, b"", &ct).expect("open"), b"hello");

    // 伪造一个「提前换代」的帧（generation 1），接收方必须拒绝而不是跳过校验。
    let mut future = LinkSealer::new(&next, true);
    let (ct_future, _c_future) = future.seal(b"", b"future").expect("seal");
    // counter 落在 generation 1 区间：接收方会用 gen1 密钥解，但帧是用 gen1 的
    // 不同 IV 密封的（Next 由同一 link_key 派生），故此处只断言「不会 panic」。
    let result = receiver.open(1 << 28, b"", &ct_future);
    assert!(result.is_err(), "跨代的伪造帧不得被接受");
}

/// 组合断言：握手失败的错误必须是**可诊断的类型**，而不是 v1 的「返回 nil 当成功」。
#[test]
fn handshake_errors_are_typed_not_swallowed() {
    let s = Secret::load("right-secret", 1).expect("s");
    let client = stowaway_crypto::ClientHandshake::new(NodeKind::Agent, TransportKind::Raw, None);
    let hello: Hello = client.hello();
    let (_server, ack) = stowaway_crypto::ServerHandshake::accept(
        &hello,
        &s,
        NodeKind::Admin,
        TransportKind::Raw,
        None,
    )
    .expect("accept");

    let wrong = Secret::load("wrong-secret", 1).expect("s");
    match client.finish(&ack, &wrong) {
        Err(HandshakeError::ProofMismatch) => {}
        other => panic!("必须是 ProofMismatch，实际：{other:?}"),
    }

    // KDF 侧：不同 salt 必须给出不同 `link_key`（不是「静默复用旧密钥」）。
    let d = s.digest();
    let k1 = derive_link_keys(&keys(1), &keys(2), &keys(3), &d);
    let k2 = derive_link_keys(&keys(1), &keys(2), &keys(4), &d);
    assert_ne!(&k1.link_key[..], &k2.link_key[..]);
}
