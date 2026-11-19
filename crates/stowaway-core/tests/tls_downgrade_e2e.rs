//! plan §8.5 附加判据（二）：**TLS 降级必须失败**。
//!
//! 判据原文：「篡改 `transport_kind` 后握手应失败」。核心保障是握手
//! transcript（TH）把**声明**的传输种类与 TLS 指纹一起摘要进去，服务端在
//! `ServerHandshake::accept` 里先做三件事，任一条不符即整条链路失败：
//!
//! 1. `hello.transport` 与监听侧实际使用的传输实现不符 → 拒；
//! 2. `hello.tls_fp` 与监听侧的证书指纹（或 `None`）不符 → 拒；
//! 3. `hello.kind` 与本端角色相同（树下没有同角色的边）→ 拒。
//!
//! ## 与 `crates/stowaway-crypto/tests/` 的分工
//!
//! `handshake_wire.rs` 与 `defects.rs` 已经覆盖了 crypto 层
//! `ServerHandshake::accept(&Hello, …)` 的直接调用（`Hello` 是内存结构体）。
//! 本文件的价值在**线上路径**：握手帧经 `LinkCodec` 编码成真帧、写进字节流、
//! 再被对端 `recv_expect(MsgType::Hello)` 解出来，因此还额外锁定了四件
//! 只在传输层才存在的事实：
//!
//! * 篡改的 `Hello` 真的能被帧层承载（不会在编码阶段就歪掉）；
//! * 拒绝发生在**写出 `HelloAck` 之前**（服务端一个字节都不回，见
//!   `server_rejects_without_emitting_hello_ack`）；
//! * 错误经 `TransportError::Handshake` 包装后仍然保留可判定的
//!   `ProtocolError::HandshakeField` 文字，从而调用方（agent/admin 的
//!   入站循环）能区分「握手被拒」与「IO 断了」；
//! * 反向对照：同样的代码路径在声明一致时**能成功**并回填
//!   `peer_transport`（见 `matching_declarations_still_complete_the_handshake`），
//!   所以上面的失败不是「一律失败」。

use std::sync::Arc;
use std::time::Duration;

use stowaway_crypto::{HandshakeError, Secret};
use stowaway_protocol::{
    FrameFlags, Message, MsgType, NodeId, NodeKind, ProtocolError, TransportKind,
};
use stowaway_transport::{Link, LinkCodec, LinkMeta, TransportError, boxed};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

// —————————————————————————————————————————————— 测试工具

/// 在 `duplex` 之上包一层 `Link`（与 `topology_e2e.rs`/`services_e2e.rs` 同构）。
#[derive(Debug)]
struct TestLink {
    inner: DuplexStream,
    meta: LinkMeta,
}

impl AsyncRead for TestLink {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TestLink {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Link for TestLink {
    fn meta(&self) -> LinkMeta {
        self.meta.clone()
    }
}

fn link(inner: DuplexStream) -> Box<dyn Link> {
    let meta = LinkMeta::new(TransportKind::Raw, None).with_max_frame(64 * 1024);
    boxed(TestLink { inner, meta })
}

fn secret() -> Arc<Secret> {
    Arc::new(Secret::load("tls-downgrade-e2e-secret", 8).expect("secret"))
}

/// 一对已完成**帧层**准备（尚未握手）的编解码器。
fn codec_pair() -> (LinkCodec, LinkCodec) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    (LinkCodec::new(link(a)), LinkCodec::new(link(b)))
}

/// 客户端把一条手工构造的 `Hello` 写进线上。
///
/// 直接用 `ClientHandshake::new(声明值).hello()` 而非内存结构体，是为了让
/// 篡改的字段带着**合法的 DH 材料**出门 —— 这样被拒的原因只能是声明不符，
/// 而不是「临时公钥非法」（`HandshakeError::BadEphemeralKey`）。
async fn send_tampered_hello(
    client: &mut LinkCodec,
    kind: NodeKind,
    transport: TransportKind,
    tls_fp: Option<[u8; 32]>,
) {
    let hello = stowaway_crypto::ClientHandshake::new(kind, transport, tls_fp).hello();
    let payload = Message::Hello(hello).encode().expect("编码 Hello");
    client
        .send_payload(
            MsgType::Hello,
            NodeId::UNASSIGNED,
            &[],
            FrameFlags::empty(),
            &payload,
        )
        .await
        .expect("写入 Hello 帧");
}

/// 取出 `TransportError::Handshake(Transcript(HandshakeField(..)))` 里的字段文字。
fn handshake_field(err: &TransportError) -> Option<&'static str> {
    match err {
        TransportError::Handshake(HandshakeError::Transcript(ProtocolError::HandshakeField(
            field,
        ))) => Some(*field),
        _ => None,
    }
}

// —————————————————————————————————————————————— 判据用例

/// 篡改 `transport_kind`：客户端声明 `Raw`、服务端实际监听的是 `Ws`。
///
/// 这是最直接的降级攻击面 —— 攻击者用明文 TCP 冒充 ws 连接，服务端必须
/// 在握手阶段就失败，而不是把它当成一条「raw 但自称 ws」的链路接下去。
#[tokio::test]
async fn tls_handshake_rejects_declared_transport_mismatch() {
    let (mut client, mut server) = codec_pair();
    let s = secret();

    // 客户端声明 Raw（它实际也就是裸 TCP）。
    send_tampered_hello(&mut client, NodeKind::Agent, TransportKind::Raw, None).await;

    // 服务端是 ws 监听器：期望 Ws。
    let err = server
        .server_handshake(NodeKind::Admin, TransportKind::Ws, None, &s)
        .await
        .expect_err("声明 Raw 而服务端是 Ws，握手必须失败");
    assert_eq!(
        handshake_field(&err),
        Some("transport 声明与实际不符"),
        "错误必须带可判定的握手字段名，实际：{err}"
    );
    let text = err.to_string();
    assert!(
        text.contains("transport 声明与实际不符"),
        "错误文字必须点明传输声明不符，实际：{text}"
    );
    // 传输层把 crypto 错误包成 `握手失败：<原因>`，调用方据此区分「被拒」与「IO 断了」。
    assert!(
        text.contains("握手失败"),
        "必须走 TransportError::Handshake 分支，实际：{text}"
    );
}

/// 反向方向的篡改同样必须失败：客户端自称 Ws、服务端实际是 raw 监听。
#[tokio::test]
async fn tls_handshake_rejects_declared_transport_mismatch_reverse() {
    let (mut client, mut server) = codec_pair();
    let s = secret();

    send_tampered_hello(&mut client, NodeKind::Agent, TransportKind::Ws, None).await;

    let err = server
        .server_handshake(NodeKind::Admin, TransportKind::Raw, None, &s)
        .await
        .expect_err("声明 Ws 而服务端是 Raw，握手必须失败");
    assert_eq!(
        handshake_field(&err),
        Some("transport 声明与实际不符"),
        "实际：{err}"
    );
}

/// TLS 指纹降级：服务端要求 TLS（且把指纹钉死），对端却声明「我没做 TLS」。
///
/// 这正是 v1 的 TLS 剥离/降级场景：不打 TLS 直接连，或中间人换证书。服务端
/// 用 `expected_tls_fp` 把**期望值**交给握手，声明不符即拒。
#[tokio::test]
async fn tls_handshake_rejects_tls_fingerprint_mismatch() {
    let (mut client, mut server) = codec_pair();
    let s = secret();

    // 传输种类一致（都是 Raw），只有 TLS 声明不同 —— 保证失败原因是指纹。
    send_tampered_hello(&mut client, NodeKind::Agent, TransportKind::Raw, None).await;

    let expected = [0x11u8; 32];
    let err = server
        .server_handshake(NodeKind::Admin, TransportKind::Raw, Some(expected), &s)
        .await
        .expect_err("服务端钉了证书指纹而对端声明没有 TLS，握手必须失败");
    assert_eq!(
        handshake_field(&err),
        Some("TLS 指纹声明与实际不符"),
        "错误必须带可判定的握手字段名，实际：{err}"
    );
    let text = err.to_string();
    assert!(text.contains("TLS 指纹声明与实际不符"), "实际：{text}");
}

/// 指纹「换成另一张证书」也必须失败（不是只拒 `None`）。
#[tokio::test]
async fn tls_handshake_rejects_different_but_present_fingerprint() {
    let (mut client, mut server) = codec_pair();
    let s = secret();

    send_tampered_hello(
        &mut client,
        NodeKind::Agent,
        TransportKind::Raw,
        Some([0x22u8; 32]),
    )
    .await;

    let err = server
        .server_handshake(NodeKind::Admin, TransportKind::Raw, Some([0x11u8; 32]), &s)
        .await
        .expect_err("指纹不同必须失败");
    assert_eq!(
        handshake_field(&err),
        Some("TLS 指纹声明与实际不符"),
        "实际：{err}"
    );
}

/// 两端同角色：树下每条边都必须是 Admin↔Agent，同角色即拒
/// （`HandshakeError::WrongRole { expected: Agent, actual: Admin }`）。
#[tokio::test]
async fn handshake_rejects_same_role_on_both_ends() {
    let (mut client, mut server) = codec_pair();
    let s = secret();

    // 两端都声明 Admin（传输与指纹都一致，唯一的不符是角色）。
    send_tampered_hello(&mut client, NodeKind::Admin, TransportKind::Raw, None).await;

    let err = server
        .server_handshake(NodeKind::Admin, TransportKind::Raw, None, &s)
        .await
        .expect_err("两端都是 Admin，握手必须失败");
    match &err {
        TransportError::Handshake(HandshakeError::WrongRole { expected, actual }) => {
            assert_eq!(
                *expected,
                NodeKind::Agent,
                "服务端期望的对端角色必须是 Agent"
            );
            assert_eq!(*actual, NodeKind::Admin);
        }
        other => panic!("期望 WrongRole，实际：{other}"),
    }
    let text = err.to_string();
    assert!(text.contains("对端角色不符合预期"), "实际：{text}");
}

/// 拒绝必须发生在**回写 `HelloAck` 之前**：服务端一个字节都不发。
///
/// 这条断言的意义：若实现改成「先回 HelloAck 再校验声明」，客户端会误以为
/// 握手进行中（某些客户端随后直接发业务帧），降级窗口就存在了。因此
/// 「对端读不到任何帧」是判据的一部分，而不是实现细节。
#[tokio::test]
async fn server_rejects_without_emitting_hello_ack() {
    let (mut client, mut server) = codec_pair();
    let s = secret();

    send_tampered_hello(&mut client, NodeKind::Agent, TransportKind::Raw, None).await;

    let err = server
        .server_handshake(NodeKind::Admin, TransportKind::Ws, None, &s)
        .await
        .expect_err("声明不符必须失败");
    assert_eq!(
        handshake_field(&err),
        Some("transport 声明与实际不符"),
        "实际：{err}"
    );

    // 服务端没有写任何字节：客户端等不到一帧。
    let waiting = tokio::time::timeout(Duration::from_millis(300), client.recv_message()).await;
    assert!(
        waiting.is_err(),
        "被拒的握手不该向对端写出任何帧（HelloAck 必须在校验之后才发）"
    );
}

/// 反向对照：声明一致时同一段代码路径必须**成功**，并把对端声明的传输
/// 回填进 `HandshakeResult::peer_transport`（证明上面几条失败不是「一律失败」，
/// 也锁定了「传输声明参与 TH、不可事后降级」这一字段的语义）。
#[tokio::test]
async fn matching_declarations_still_complete_the_handshake() {
    let (mut client, mut server) = codec_pair();
    let s = secret();
    let s2 = s.clone();

    let client_task = tokio::spawn(async move {
        client
            .client_handshake(NodeKind::Agent, TransportKind::Ws, None, &s2)
            .await
            .map(|res| (client, res))
    });
    let server_task = tokio::spawn(async move {
        server
            .server_handshake(NodeKind::Admin, TransportKind::Ws, None, &s)
            .await
            .map(|res| (server, res))
    });

    let (client, client_res) = client_task
        .await
        .expect("join")
        .expect("声明一致的客户端握手必须成功");
    let (_server, server_res) = server_task
        .await
        .expect("join")
        .expect("声明一致的服务端握手必须成功");

    assert_eq!(client_res.peer_kind, NodeKind::Admin);
    assert_eq!(server_res.peer_kind, NodeKind::Agent);
    assert_eq!(client_res.peer_transport, TransportKind::Ws);
    assert_eq!(server_res.peer_transport, TransportKind::Ws);
    assert_eq!(
        client_res.secrets.transcript_hash, server_res.secrets.transcript_hash,
        "两侧 TH 必须一致（传输声明被摘要进去了）"
    );
    assert!(client_res.is_client, "发起方必须标记为客户端");
    assert!(!server_res.is_client, "监听方必须标记为服务端");
    assert!(client.is_sealed(), "握手完成后客户端必须装上密封层");
}
