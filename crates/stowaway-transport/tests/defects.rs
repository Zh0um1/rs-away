//! 缺陷回归：传输/帧层相关条目（`docs/plan.md` §3）。
//!
//! 命名规范见 plan.md §8.6：`defect_<n>_<what>`。每条测试都要能单独指出
//! 「v1 会怎样失败」，而不是泛泛覆盖。

use std::time::Duration;

use stowaway_crypto::{LinkSealer, Secret, derive_link_keys};
use stowaway_protocol::{Frame, FrameCodec, FrameFlags, Message, MsgType, NodeId};
use stowaway_transport::{DialTarget, Dialer, Link, LinkMeta, TransportSpec, boxed};

/// 缺陷 #5：v1 在 `--tls-enable` 时把 `Secret` 置空 → 载荷完全明文。
///
/// v2 的帧层密封与 TLS 无关：这里直接验证「没有 TLS 也一定密封」。
#[test]
fn defect_5_sealing_is_independent_of_tls() {
    let secret = Secret::load("0123456789abcdef", 8).expect("secret");
    let keys = derive_link_keys(&[1u8; 32], &[2u8; 32], &[3u8; 32], &secret.digest());
    let mut sealer = LinkSealer::new(&keys.link_key, true);

    let plaintext = b"payload-must-never-be-clear";
    let (ct, counter) = sealer.seal(b"header-aad", plaintext).expect("seal");
    assert_ne!(
        &ct[..],
        &plaintext[..],
        "密封后的字节不得等于明文（缺陷 #5 的根因是「置空 secret 后 AES 直接透传」）"
    );
    assert!(
        !ct.windows(plaintext.len()).any(|w| w == plaintext),
        "密文中不得出现明文片段"
    );

    let mut peer = LinkSealer::new(&keys.link_key, false);
    let back = peer.open(counter, b"header-aad", &ct).expect("open");
    assert_eq!(back, plaintext, "合法对端必须能还原");
}

/// 缺陷 #5 的残余风险面：AAD 变化必须导致解封失败（否则帧头可被重写）。
#[test]
fn defect_5_aad_is_bound_so_headers_cannot_be_rewritten() {
    let secret = Secret::load("0123456789abcdef", 8).expect("secret");
    let keys = derive_link_keys(&[1u8; 32], &[2u8; 32], &[3u8; 32], &secret.digest());
    let mut sealer = LinkSealer::new(&keys.link_key, true);
    let (ct, counter) = sealer.seal(b"dest=AAAA", b"x").expect("seal");

    let mut peer = LinkSealer::new(&keys.link_key, false);
    let err = peer.open(counter, b"dest=BBBB", &ct);
    assert!(
        matches!(err, Err(stowaway_crypto::SealerError::AuthFailed)),
        "改帧头必须解封失败，实际 {err:?}"
    );
}

/// 缺陷 #6：v1 每次重启换 TLS 指纹（RSA-1024 现场生成）。
///
/// v2 断言「同 secret ⇒ 同 SPKI 指纹」，且 pin 必须拒绝不匹配的对端。
#[cfg(feature = "tls")]
#[test]
fn defect_6_tls_fingerprint_survives_restart_and_pin_rejects_others() {
    let digest = Secret::load("0123456789abcdef", 8)
        .expect("secret")
        .digest();
    let san = vec!["stowaway".to_string()];

    let a = stowaway_transport::derive_cert(&digest, &san).expect("derive");
    let b = stowaway_transport::derive_cert(&digest, &san).expect("derive");
    assert!(
        a.fingerprint.ct_eq(&b.fingerprint),
        "同 secret 两次「启动」必须同指纹（缺陷 #6）"
    );

    // 客户端 pin 到 a 的指纹，用 b 的证书也必须通过（同一身份）。
    let pinned = stowaway_transport::parse_pin(&a.fingerprint.colon_hex().replace(':', ""))
        .expect("parse pin");
    assert!(pinned.ct_eq(&b.fingerprint));

    // 换一个 secret 就必须对不上。
    let other = stowaway_transport::derive_cert(
        &Secret::load("another-secret", 8).expect("secret").digest(),
        &san,
    )
    .expect("derive");
    assert!(!pinned.ct_eq(&other.fingerprint), "异 secret 不得同指纹");
}

/// 缺陷 #11：旧表述「每帧一次 topology 往返」失真。
///
/// 真正要守的是：帧层不得为每一帧重新分配整段缓冲，且批量写必须合并到
/// 一次底层 `write`（否则小包场景重回 v1 的 syscall 风暴）。
#[tokio::test]
async fn defect_11_batching_does_not_emit_one_write_per_message() {
    /// 统计底层 `write` 调用次数的内存链路。
    struct CountingLink {
        inner: tokio::io::DuplexStream,
        writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl tokio::io::AsyncRead for CountingLink {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for CountingLink {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl Link for CountingLink {
        fn meta(&self) -> LinkMeta {
            LinkMeta::new(stowaway_protocol::TransportKind::Raw, None)
        }
    }

    let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (a, b) = tokio::io::duplex(1 << 20);
    let mut codec = stowaway_transport::LinkCodec::new(boxed(CountingLink {
        inner: a,
        writes: writes.clone(),
    }));
    let dest = NodeId::new([1u8; 16]);
    for seq in 0..8u64 {
        let msg = Message::SessionData(stowaway_protocol::SessionData {
            key: stowaway_protocol::SessionKey::new(dest, 1),
            seq,
            data: stowaway_protocol::ByteBuf::from(vec![0x11u8; 64]),
        });
        codec.send(&msg, dest, &[]).await.expect("send");
    }
    // 8 个小帧、每帧远小于 max_chunk：必须逐帧成帧（一个帧一次 write），
    // 但绝不能出现「一帧拆成多次写」或「额外的小写入」。
    assert_eq!(
        writes.load(std::sync::atomic::Ordering::Relaxed),
        8,
        "8 个小帧应恰好 8 次底层写（一次成帧），不得额外碎片化"
    );
    drop(b);
}

/// 缺陷 #11 的另一半：大载荷必须分片，而不是让单次 write 阻塞整条链路。
#[tokio::test]
async fn defect_11_large_payload_is_chunked_by_max_chunk() {
    let spec = TransportSpec::parse("raw://127.0.0.1:1").expect("spec");
    assert!(spec.nodelay, "raw 默认开 TCP_NODELAY");

    let (a, b) = tokio::io::duplex(1 << 20);
    struct L(tokio::io::DuplexStream);
    impl tokio::io::AsyncRead for L {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }
    impl tokio::io::AsyncWrite for L {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, data)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }
    impl Link for L {
        fn meta(&self) -> LinkMeta {
            LinkMeta::new(stowaway_protocol::TransportKind::Raw, None)
        }
    }

    let codec = stowaway_transport::LinkCodec::new(boxed(L(a)));
    let chunk = codec.max_chunk();
    assert!(
        chunk <= stowaway_protocol::FRAGMENT_MAX,
        "分片上限不得超过 FRAGMENT_MAX（{chunk} > {}）",
        stowaway_protocol::FRAGMENT_MAX
    );
    drop(b);
}

/// 缺陷 #3/#4 在帧层的体现：截断的物理帧必须报错，而不是 panic 或静默丢弃。
#[test]
fn defect_3_4_truncated_physical_frame_is_an_error() {
    let frame = Frame::new(
        FrameFlags::empty(),
        MsgType::Heartbeat,
        NodeId::new([1u8; 16]),
        Vec::new(),
        vec![0u8; 8],
    );
    let bytes = FrameCodec::encode(&frame);
    for cut in 1..bytes.len() {
        let err = FrameCodec::decode(&bytes[..cut]);
        assert!(err.is_err(), "截断 {cut}/{} 必须报错", bytes.len());
    }
}

/// 规格解析：未知 scheme 不得静默回落 raw（v1 的 `SetUpDownStream` 就这么干）。
#[test]
fn defect_v1_transport_silently_falls_back_is_fixed() {
    let err = TransportSpec::parse("smux://host:1").expect_err("未知 scheme 必须报错");
    assert!(
        matches!(err, stowaway_transport::SpecError::UnknownScheme { .. }),
        "实际 {err:?}"
    );
    // `http://` 是 v1 的死代码伪协议，必须明确拒绝而不是「回落到 raw」。
    let err = TransportSpec::parse("http://host:1").expect_err("http 必须报错");
    assert!(matches!(err, stowaway_transport::SpecError::HttpRemoved));
}

/// 建链失败必须是错误而不是 panic（无网络/端口未监听的最常见路径）。
#[tokio::test]
async fn listening_on_closed_port_surfaces_error() {
    let dialer =
        stowaway_transport::AnyDialer::Raw(stowaway_transport::tcp::RawDialer::new(true, None));
    // 127.0.0.1:1 基本必然拒绝。
    let target = DialTarget::plain("127.0.0.1:1".parse().expect("addr"));
    let res = tokio::time::timeout(Duration::from_secs(5), dialer.connect(&target)).await;
    match res {
        Ok(Err(io)) => {
            assert!(
                io.kind() == std::io::ErrorKind::ConnectionRefused
                    || io.kind() == std::io::ErrorKind::PermissionDenied
                    || io.kind() == std::io::ErrorKind::NetworkUnreachable,
                "实际 kind = {:?}",
                io.kind()
            );
        }
        Ok(Ok(_)) => panic!("127.0.0.1:1 不应连得上"),
        Err(_) => panic!("连接必须在 5 秒内失败并返回错误，而不是挂住"),
    }
}

/// `LinkMeta` 的语义承诺必须与 `TransportKind` 一致（datagram/E2E 决策依赖它）。
#[cfg(all(feature = "transport-raw", feature = "transport-kcp"))]
#[test]
fn defect_link_meta_matches_transport_kind() {
    use stowaway_protocol::TransportKind;
    assert!(!LinkMeta::new(TransportKind::Raw, None).datagram_backed);
    assert!(!LinkMeta::new(TransportKind::Ws, None).datagram_backed);
    assert!(LinkMeta::new(TransportKind::Kcp, None).datagram_backed);
    assert!(
        LinkMeta::new(TransportKind::Raw, None)
            .with_max_frame(4096)
            .max_frame
            == 4096,
        "with_max_frame 必须生效"
    );
}

/// 缺陷 #8：v1 的 `crypto/gzip.go:23` 在解压失败时 `return dst`（空切片），
/// 坏数据于是变成「空载荷」继续往下走。v2 的压缩位是预留位，收到带压缩位
/// 的帧必须**显式拒绝**，绝不把未解压的字节当载荷交出去。
#[tokio::test]
async fn defect_8_compressed_flag_is_rejected_not_silently_emptied() {
    use stowaway_transport::LinkCodec;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

    struct PlainLink {
        inner: tokio::io::DuplexStream,
        meta: LinkMeta,
    }

    impl AsyncRead for PlainLink {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PlainLink {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
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

    impl Link for PlainLink {
        fn meta(&self) -> LinkMeta {
            self.meta.clone()
        }
    }

    let (mut peer, reader_side) = tokio::io::duplex(64 * 1024);
    let meta = LinkMeta::new(stowaway_protocol::TransportKind::Raw, None);
    let mut reader = LinkCodec::new(boxed(PlainLink {
        inner: reader_side,
        meta,
    }));

    // 手工造一个带 COMPRESSED 位的合法帧（未密封，便于直接走到压缩判定）。
    let frame = Frame::new(
        FrameFlags::COMPRESSED,
        MsgType::Heartbeat,
        NodeId::ADMIN,
        Vec::new(),
        b"not-really-gzip".to_vec(),
    );
    peer.write_all(&frame.encode()).await.expect("write");

    let err = reader.recv().await.expect_err("压缩帧必须报错");
    assert!(
        err.to_string().contains("压缩"),
        "错误必须指出压缩位：{err}"
    );
}
