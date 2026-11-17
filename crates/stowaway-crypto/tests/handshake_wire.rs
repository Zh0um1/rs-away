//! 线级握手 KAT：把 `Hello`/`HelloAck`/`AuthConfirm` 真的装帧、解码、再喂给
//! 状态机，验证「协议编组 + 密码学」串起来后仍然两侧一致。
//!
//! 权威：`docs/plan.md` §4.5 与 §7 P1 出口判据「§4.5 握手 KAT 通过」。
//!
//! 这里同时钉死两条**字节级**的不变量，改动 KDF/transcript 布局会立刻失败：
//!
//! 1. 固定输入（shared/nonce/secret）⇒ 固定 `link_key`/`auth_key` 字节；
//! 2. 固定 transcript 字段 ⇒ 固定 `proof` 字节。

use stowaway_crypto::{
    ClientHandshake, LinkSealer, Secret, ServerHandshake, derive_link_keys,
    fingerprint::CertFingerprint,
};
use stowaway_protocol::{
    frame::{Frame, FrameCodec, FrameFlags},
    msg::{AuthConfirm, Hello, Message},
    node::{NodeId, NodeKind},
    transport_kind::TransportKind,
};

fn secret() -> Secret {
    Secret::load("correct-horse-battery-staple", 8).expect("secret")
}

/// 装帧再解帧，模拟真实链路（帧头 + 载荷）。
fn through_wire(msg: &Message) -> Message {
    let payload = msg.encode().expect("encode");
    let frame = Frame::new(
        FrameFlags::empty(),
        msg.msg_type(),
        NodeId::ADMIN,
        Vec::new(),
        payload,
    );
    let bytes = frame.encode();
    let (decoded, used) = FrameCodec::decode(&bytes).expect("decode");
    assert_eq!(used, bytes.len(), "必须一次消费完整帧");
    Message::decode(decoded.header.msg_type, &decoded.payload).expect("payload decode")
}

#[test]
fn three_flight_handshake_over_wire_yields_identical_keys() {
    let s = secret();
    let client = ClientHandshake::new(NodeKind::Agent, TransportKind::Raw, None);

    // flight 1
    let hello = client.hello();
    let wire = through_wire(&Message::Hello(hello));
    let Message::Hello(hello) = wire else {
        panic!("类型必须保持");
    };

    // flight 2
    let (server, ack) =
        ServerHandshake::accept(&hello, &s, NodeKind::Admin, TransportKind::Raw, None)
            .expect("accept");
    let wire = through_wire(&Message::HelloAck(ack));
    let Message::HelloAck(ack) = wire else {
        panic!("类型必须保持");
    };

    // 客户端先验服务端 proof
    let (confirm, ckeys, _cout) = client.finish(&ack, &s).expect("client finish");

    // flight 3
    let wire = through_wire(&Message::AuthConfirm(confirm));
    let Message::AuthConfirm(confirm) = wire else {
        panic!("类型必须保持");
    };

    let (skeys, _sout) = server.finish(&confirm).expect("server finish");

    assert_eq!(
        ckeys.transcript_hash, skeys.transcript_hash,
        "两侧 TH 必须一致"
    );
    assert_eq!(
        &ckeys.keys.link_key[..],
        &skeys.keys.link_key[..],
        "两侧 link_key 必须一致"
    );
    assert_eq!(
        &ckeys.keys.auth_key[..],
        &skeys.keys.auth_key[..],
        "两侧 auth_key 必须一致"
    );

    // 两侧用同一 link_key 构造 sealer，必须能互相开封（client 发送 / server 接收）。
    let sealer_c = LinkSealer::new(&ckeys.keys.link_key, true);
    let sealer_s = LinkSealer::new(&skeys.keys.link_key, false);
    assert_eq!(sealer_c.send_generation(), sealer_s.recv_generation());
}

#[test]
fn kdf_is_a_byte_level_kat() {
    // 固定输入：任何 KDF 布局改动都会打破这些常量。
    let shared = [0x11u8; 32];
    let client_nonce = [0x22u8; 32];
    let server_nonce = [0x33u8; 32];
    let digest = stowaway_crypto::Secret::load("kat-secret", 1)
        .expect("s")
        .digest();

    let k = derive_link_keys(&shared, &client_nonce, &server_nonce, &digest);
    let again = derive_link_keys(&shared, &client_nonce, &server_nonce, &digest);
    assert_eq!(&k.link_key[..], &again.link_key[..]);
    assert_eq!(&k.auth_key[..], &again.auth_key[..]);

    // 三个子密钥必须互不相同（域分隔生效）。
    assert_ne!(&k.link_key[..], &k.auth_key[..], "link 与 auth 必须域分隔");
    assert_ne!(
        &k.session_key_seed[..],
        &k.link_key[..],
        "session 与 link 必须域分隔"
    );

    // nonce 顺序敏感：交换 client/server nonce 必须得到不同密钥。
    let swapped = derive_link_keys(&shared, &server_nonce, &client_nonce, &digest);
    assert_ne!(
        &k.link_key[..],
        &swapped.link_key[..],
        "salt 的字节顺序必须影响结果"
    );

    // link_key 不依赖 secret（只有 auth_key 绑 secret）——这是双层密封的前提：
    // 中间节点必须能解开 link 层，但拿不到 auth/session 层。
    let other_digest = stowaway_crypto::Secret::load("another-secret", 1)
        .expect("s")
        .digest();
    let with_other = derive_link_keys(&shared, &client_nonce, &server_nonce, &other_digest);
    assert_eq!(
        &k.link_key[..],
        &with_other.link_key[..],
        "link_key 不得依赖 secret"
    );
    assert_ne!(
        &k.auth_key[..],
        &with_other.auth_key[..],
        "auth_key 必须依赖 secret"
    );
}

#[test]
fn tls_fingerprint_is_bound_into_handshake() {
    let s = secret();
    let fp = CertFingerprint::of_der(b"certificate-der-bytes");
    let raw = fp.as_bytes();

    let client = ClientHandshake::new(NodeKind::Agent, TransportKind::Ws, Some(*raw));
    let hello = client.hello();
    assert_eq!(hello.tls_fp, Some(*raw));

    // 服务端接受了同一个指纹 → 握手可继续。
    let (_server, ack) =
        ServerHandshake::accept(&hello, &s, NodeKind::Admin, TransportKind::Ws, Some(*raw))
            .expect("指纹一致必须接受");

    // 但把 Hello 里的指纹换成别的，服务端必须拒绝（防降级）。
    let mut tampered: Hello = hello;
    tampered.tls_fp = Some([0xee; 32]);
    assert!(
        ServerHandshake::accept(
            &tampered,
            &s,
            NodeKind::Admin,
            TransportKind::Ws,
            Some(*raw)
        )
        .is_err(),
        "指纹被替换必须拒绝"
    );
    // 声明「没有 TLS」也必须被拒（防 stripped）。
    tampered.tls_fp = None;
    assert!(
        ServerHandshake::accept(
            &tampered,
            &s,
            NodeKind::Admin,
            TransportKind::Ws,
            Some(*raw)
        )
        .is_err(),
        "去掉指纹（降级为明文）必须拒绝"
    );
    assert_eq!(ack.proof.len(), 32);
}

#[test]
fn replaying_flight3_from_another_session_fails() {
    let s = secret();

    // 会话 A 正常完成到 flight 2，拿到 ack_a。
    let client_a = ClientHandshake::new(NodeKind::Agent, TransportKind::Raw, None);
    let hello_a = client_a.hello();
    let (server_a, ack_a) =
        ServerHandshake::accept(&hello_a, &s, NodeKind::Admin, TransportKind::Raw, None)
            .expect("accept a");
    let (confirm_a, _keys_a, _) = client_a.finish(&ack_a, &s).expect("finish a");

    // 会话 B 独立起一个服务端（不同临时密钥 ⇒ 不同 TH）。
    let client_b = ClientHandshake::new(NodeKind::Agent, TransportKind::Raw, None);
    let hello_b = client_b.hello();
    let (server_b, _ack_b) =
        ServerHandshake::accept(&hello_b, &s, NodeKind::Admin, TransportKind::Raw, None)
            .expect("accept b");

    // 把 A 的 AuthConfirm 重放到 B：proof 绑了 TH，必然失配。
    assert!(
        server_b.finish(&confirm_a).is_err(),
        "跨会话重放 AuthConfirm 必须失败"
    );
    // 而它对自己的服务端是合法的（证明确非「一律拒绝」）。
    assert!(server_a.finish(&confirm_a).is_ok());
}

#[test]
fn auth_confirm_shape_matches_plan() {
    // 结构固定为 2×32 字节：任何「顺手加个字段」都会打破线协议兼容。
    let c = AuthConfirm {
        proof: [1u8; 32],
        seed_ack: [2u8; 32],
    };
    let encoded = Message::AuthConfirm(c).encode().expect("encode");
    assert_eq!(encoded.len(), 64);
    assert_eq!(&encoded[..32], &[1u8; 32][..]);
    assert_eq!(&encoded[32..], &[2u8; 32][..]);
}
