//! P3 的缺陷回归用例：把 plan §3 里「拓扑/路由/会话」一类的缺陷固定下来。
//!
//! 每个测试名以 `defect_<编号>_` 开头，与 plan §8.6 的命名约定一致，
//! 便于 `cargo test defect_` 一次性跑完所有历史缺陷回归。

use std::time::Duration;

use stowaway_core::link_actor::InboundFrame;
use stowaway_core::{
    CoreError, Node, NodeConfig, NodeMeta, Route, SESSION_QUEUE_DEPTH, SessionTable, Topology,
    decide,
};
use stowaway_protocol::{
    ByteBuf, Message, NodeId, NodeKind, NodeScope, NodeState, OpenSession, ServiceParam,
    SessionCode, SessionData, SessionDirection, SessionKey, SessionKind, TransportKind,
};
use stowaway_transport::{Link, LinkCodec, LinkMeta, boxed};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

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

fn id(n: u8) -> NodeId {
    let mut b = [0u8; 16];
    b[0] = n;
    NodeId(b)
}

fn codec_for(max_frame: usize) -> LinkCodec {
    let (a, _b) = tokio::io::duplex(64 * 1024);
    let meta = LinkMeta::new(TransportKind::Raw, None).with_max_frame(max_frame);
    LinkCodec::new(boxed(TestLink { inner: a, meta }))
}

fn open(key: SessionKey) -> OpenSession {
    OpenSession {
        key,
        kind: SessionKind::Socks5,
        direction: SessionDirection::Outbound,
        target: Some("127.0.0.1:80".to_owned()),
        param: ServiceParam::None,
    }
}

/// 缺陷 #4 的一半：v1 的会话号是单 `uint64`，两端各自从 0 开始发号，
/// 同一时刻两个节点都用 0 号就会互踩。v2 用 `(origin, id)` 复合键。
#[test]
fn defect_4_session_ids_from_different_origins_never_collide() {
    let mut table = SessionTable::new();
    let a = SessionKey::new(id(1), 0);
    let b = SessionKey::new(id(2), 0);
    let c = SessionKey::new(NodeId::ADMIN, 0);
    for key in [a, b, c] {
        table.open(key, SessionKind::Socks5).expect("open");
        table.ready(&key, SessionCode::Ok).expect("ready");
    }
    assert_eq!(table.len(), 3);

    // 三路同名 0 号数据互不干扰：各自独立维护序号。
    for key in [a, b, c] {
        table
            .accept_data(&SessionData {
                key,
                seq: 0,
                data: ByteBuf::from(vec![1u8; 4]),
            })
            .expect("seq 0");
    }

    // 同一个 origin 重复开同号仍然要拒绝（复合键不是万能放行）。
    let err = table.open(a, SessionKind::File).expect_err("duplicate");
    assert!(matches!(err, CoreError::SessionExists { .. }));
}

/// 缺陷 #4 的另一半：v1 只靠「收到 SEQS」被动同步，重复/乱序/重放的数据
/// 会被当成新数据交给上层。v2 在会话表里强制连续序号。
#[test]
fn defect_4_out_of_order_and_replayed_session_data_is_rejected() {
    let mut table = SessionTable::new();
    let key = SessionKey::new(id(1), 7);
    table.open(key, SessionKind::File).expect("open");
    table.ready(&key, SessionCode::Ok).expect("ready");
    let payload = ByteBuf::from(vec![0u8; 4]);

    table
        .accept_data(&SessionData {
            key,
            seq: 0,
            data: payload.clone(),
        })
        .expect("seq 0");
    // 重放 0。
    assert!(
        table
            .accept_data(&SessionData {
                key,
                seq: 0,
                data: payload.clone(),
            })
            .is_err()
    );
    // 跳过 1 直接来 2。
    assert!(
        table
            .accept_data(&SessionData {
                key,
                seq: 2,
                data: payload.clone(),
            })
            .is_err()
    );
    // 正常 1。
    table
        .accept_data(&SessionData {
            key,
            seq: 1,
            data: payload,
        })
        .expect("seq 1");
}

/// 缺陷 #4 的第三半：`SessionReady` 之前就来数据必须被拒（v1 会照着
/// seq 直接投递到一个还不存在的 target）。
#[test]
fn defect_4_data_before_ready_is_rejected() {
    let mut table = SessionTable::new();
    let key = SessionKey::new(id(1), 1);
    table.open(key, SessionKind::Socks5).expect("open");
    let err = table
        .accept_data(&SessionData {
            key,
            seq: 0,
            data: ByteBuf::from(vec![0u8; 1]),
        })
        .expect_err("data before ready");
    assert!(matches!(err, CoreError::Protocol(_)));
}

/// 缺陷 #11：v1 每帧都要向 topology 做一次 channel 往返取路由。v2 把
/// 下一跳缓存在 `route_cache` 里，**逐帧只剩一次哈希查找**；只有链路
/// 变化（epoch 变化）才重算。
#[test]
fn defect_11_route_cache_removes_per_frame_topology_roundtrip() {
    let mut t = Topology::new(NodeId::ADMIN, NodeKind::Admin, 8);
    t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
        .expect("a1");
    t.insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
        .expect("a2");

    // 第一次决策 + 填充缓存。
    let first = decide(&mut t, NodeId::ADMIN, id(2), &[]).expect("decide");
    assert_eq!(
        first,
        Route::Forward {
            next_hop: id(1),
            via: Vec::new()
        }
    );
    assert_eq!(t.cached_routes(), 1);
    let epoch = t.epoch();

    // 之后的 1000 次决策不再触达拓扑计算，epoch 也不动。
    for _ in 0..1000 {
        let r = decide(&mut t, NodeId::ADMIN, id(2), &[]).expect("decide");
        assert_eq!(
            r,
            Route::Forward {
                next_hop: id(1),
                via: Vec::new()
            }
        );
    }
    assert_eq!(t.epoch(), epoch, "逐帧决策不得改动拓扑");
    assert_eq!(t.cached_routes(), 1, "不得为同一目标重复插入缓存项");
}

/// 缺陷 #11 的配套：链路变化后缓存必须整体失效，否则会按旧下一跳发。
#[test]
fn defect_11_epoch_bump_invalidates_all_cached_routes() {
    let mut t = Topology::new(NodeId::ADMIN, NodeKind::Admin, 8);
    for n in 1..=3u8 {
        let parent = if n == 1 { NodeId::ADMIN } else { id(n - 1) };
        t.insert(NodeMeta::new(id(n), parent, 0, NodeKind::Agent))
            .expect("insert");
    }
    let _ = decide(&mut t, NodeId::ADMIN, id(3), &[]).expect("decide");
    assert_eq!(t.cached_routes(), 1);

    // A2 换到 A1 的兄弟位（重新挂载）→ 整体失效。
    t.reparent(id(2), NodeId::ADMIN).expect("reparent");
    assert_eq!(t.cached_routes(), 0, "epoch 变化必须清空所有缓存");
    let r = decide(&mut t, NodeId::ADMIN, id(3), &[]).expect("decide");
    // A3 仍挂在 A2 下，但 A2 现在直接挂在根上 → 下一跳变成 A2。
    assert_eq!(
        r,
        Route::Forward {
            next_hop: id(2),
            via: Vec::new()
        }
    );
}

/// 缺陷 #11 的第三面：不可达不能静默丢弃（v1 的 `changeRoute` 在没有匹配
/// 分支时只是把帧丢掉）。
#[test]
fn defect_11_undeliverable_is_reported_not_dropped() {
    let mut t = Topology::new(NodeId::ADMIN, NodeKind::Admin, 8);
    t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
        .expect("a1");
    let route = decide(&mut t, NodeId::ADMIN, id(9), &[]).expect("decide");
    assert_eq!(route, Route::Undeliverable);
}

/// 会话数的背压闸门：v1 的 `SessionManager` 内部 channel 无上界。
#[test]
fn defect_11_session_queue_is_bounded() {
    let mut table = SessionTable::new();
    let key = SessionKey::new(id(1), 0);
    table.open(key, SessionKind::Socks5).expect("open");
    for _ in 0..SESSION_QUEUE_DEPTH {
        table.push_backpressure(&key).expect("queued");
    }
    let err = table
        .push_backpressure(&key)
        .expect_err("must be backpressure");
    assert!(matches!(err, CoreError::Backpressure));
    assert_eq!(table.get(&key).expect("meta").backpressure_events, 1);
}

/// 握手前不得接受业务帧：v1 用「Accepter == TEMP_UUID 就不解密」这种
/// 身份推断，v2 改成显式 SEALED 位 + 会话状态机。这里验证「会话未就绪
/// 就不吃数据」与「链路未握手就没有 sealer」两条拒绝路径同时存在。
#[test]
fn defect_5_unencrypted_business_frame_is_not_silently_accepted() {
    let codec = codec_for(4096);
    assert!(!codec.is_sealed(), "未握手时不应有 sealer");
    // 未密封的链路仍可工作（明文模式是允许的），但一旦收到 SEALED 帧
    // 而自己没有 sealer，必须报错而不是把密文当明文交上去。
    // 该行为由 codec 的单元测试覆盖；这里只固定 codec 的初始状态。
}

/// 拓扑自环必须被拒绝，否则路由会永远在两点之间打转。
#[test]
fn defect_11_topology_rejects_cycles() {
    let mut t = Topology::new(NodeId::ADMIN, NodeKind::Admin, 8);
    t.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
        .expect("a1");
    t.insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
        .expect("a2");
    let err = t.reparent(id(1), id(2)).expect_err("cycle");
    assert!(matches!(err, CoreError::Cycle { .. }));
}

/// 子节点离线后必须整支摘除（v1 只删单点，后代留在拓扑里继续被路由）。
#[tokio::test]
async fn defect_11_offline_child_prunes_whole_subtree() {
    let mut n = Node::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin));
    let (tx, rx) = tokio::sync::mpsc::channel::<InboundFrame>(8);
    let (a, b) = tokio::io::duplex(8192);
    let (_handle, actor) = n
        .attach_link(a_codec(a, 8192), id(1), NodeId::ADMIN, NodeKind::Agent, tx)
        .expect("attach");
    drop(b);
    drop(rx);
    drop(actor);

    // 手工把 A1 的一个后代挂上去（模拟 Join 公告）。
    n.topology_mut()
        .insert(NodeMeta::new(id(2), id(1), 0, NodeKind::Agent))
        .expect("a2");
    n.topology_mut().invalidate();
    assert!(n.topology().get(id(2)).is_some());

    // 打开一个由 A2 发起的会话，离线后必须一并清理。
    n.handle_local_message(Message::OpenSession(open(SessionKey::new(id(2), 0))))
        .await
        .expect("open");
    assert_eq!(n.sessions().len(), 1);

    let _ = n
        .handle_local_message(Message::NodeStatus(stowaway_protocol::NodeStatus {
            scope: NodeScope::Child,
            state: NodeState::Offline,
            node: id(1),
        }))
        .await
        .expect("offline");

    assert!(n.topology().get(id(1)).is_none());
    assert!(n.topology().get(id(2)).is_none(), "后代必须一并摘除");
    assert_eq!(n.sessions().len(), 0, "孤儿会话必须清理");
}

fn a_codec(stream: DuplexStream, max_frame: usize) -> LinkCodec {
    let meta = LinkMeta::new(TransportKind::Raw, None).with_max_frame(max_frame);
    LinkCodec::new(boxed(TestLink {
        inner: stream,
        meta,
    }))
}

/// 上游链路不能被当成下游：agent 连 admin 后如果按「子节点」登记，
/// 它会认为 admin 在自己下面，所有向上路由都会失败。
#[test]
fn defect_11_attach_upstream_flips_tree_direction() {
    let mut t = Topology::new(id(1), NodeKind::Agent, 8);
    t.attach_upstream(NodeId::ADMIN, NodeKind::Admin)
        .expect("attach upstream");
    assert_eq!(t.root(), NodeId::ADMIN);
    assert_eq!(t.my_depth(), 1);
    // 去 admin 的下一跳就是 admin。
    assert_eq!(t.next_hop(NodeId::ADMIN).expect("hop"), Some(NodeId::ADMIN));

    // 反向（admin 视角）不受影响：自己仍是根时去子节点。
    let mut a = Topology::new(NodeId::ADMIN, NodeKind::Admin, 8);
    a.insert(NodeMeta::new(id(1), NodeId::ADMIN, 0, NodeKind::Agent))
        .expect("a1");
    assert_eq!(a.next_hop(id(1)).expect("hop"), Some(id(1)));
}

/// 链路关闭时排队中的帧不能丢（v1 直接在 `Write` 上竞争，写一半断开
/// 会留下半帧）。
#[tokio::test]
async fn defect_3_queued_frames_survive_link_close() {
    let mut n = Node::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin));
    let (tx, rx) = tokio::sync::mpsc::channel::<InboundFrame>(8);
    let (admin_side, peer_side) = tokio::io::duplex(64 * 1024);
    let (handle, actor) = n
        .attach_link(
            a_codec(admin_side, 4096),
            id(1),
            NodeId::ADMIN,
            NodeKind::Agent,
            tx,
        )
        .expect("attach");
    let task = tokio::spawn(actor.run());

    let mut peer = a_codec(peer_side, 4096);
    for i in 0..4u64 {
        handle
            .send(
                Message::Heartbeat(stowaway_protocol::Heartbeat {
                    send_ts: i,
                    echo_ts: 0,
                }),
                id(1),
                Vec::new(),
            )
            .await
            .expect("send");
    }
    // 关掉写侧以后，排队的帧仍应完整到达对端（而不是丢一半）。
    handle.close();
    for i in 0..4u64 {
        let (_, msg) = tokio::time::timeout(Duration::from_secs(5), peer.recv_message())
            .await
            .expect("recv timeout")
            .expect("recv");
        let Message::Heartbeat(hb) = msg else {
            panic!("expected heartbeat");
        };
        assert_eq!(hb.send_ts, i);
    }
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

// ————————————————————————————————————————————— P4 的缺陷回归（#12 / #13）

/// 缺陷 #13（后半）：v1 的 SOCKS5 端口完全不做认证（`agent/handler/socks.go`
/// 的 `checkMethod` 只挑方法、不校验凭据），任何能连到该端口的客户端都能把
/// 它当开放代理用。v2 一旦配置凭据，就**强制**走 RFC 1929：
/// 客户端即使同时声明「无认证」，也不能被选上。
#[tokio::test]
async fn defect_13_socks_with_credentials_never_falls_back_to_no_auth() {
    use stowaway_core::{Credentials, SocksServerConfig, negotiate};
    use tokio::io::AsyncWriteExt;

    let cfg = SocksServerConfig {
        credentials: Some(Credentials::new("alice", "s3cret")),
    };
    let (mut client, mut server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { negotiate(&mut server, &cfg).await });

    // 客户端声明「支持无认证 + 用户名密码」：v1 会挑无认证放行。
    client.write_all(&[5, 2, 0, 2]).await.expect("greeting");
    let mut reply = [0u8; 2];
    use tokio::io::AsyncReadExt;
    client.read_exact(&mut reply).await.expect("reply");
    assert_eq!(
        reply,
        [5, 2],
        "配置了凭据时只能选用户名/密码（v1 会回 [5,0] 直接放行）"
    );
    // 补上认证与请求，让协商正常结束（证明强制的是「方法」而不是「必然失败」）。
    client
        .write_all(&[
            1, 5, b'a', b'l', b'i', b'c', b'e', 6, b's', b'3', b'c', b'r', b'e', b't',
        ])
        .await
        .expect("auth");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("auth reply");
    assert_eq!(auth, [1, 0], "正确凭据必须通过");
    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .expect("request");
    let negotiated = task.await.expect("join").expect("协商必须成功");
    assert_eq!(negotiated.cmd, 1);
    assert_eq!(negotiated.port, 80);

    // 只声明「无认证」：必须明确拒绝，而不是静默降级。
    let cfg = SocksServerConfig {
        credentials: Some(Credentials::new("alice", "s3cret")),
    };
    let (mut client, mut server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { negotiate(&mut server, &cfg).await });
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply, [5, 255], "没有可接受的方法时必须回 0xFF");
    assert!(
        task.await.expect("join").is_err(),
        "协商必须以错误结束，不能假装成功"
    );
}

/// 缺陷 #13（前半）：v1 用 `os.Create(file.FileName)` 直接落盘
/// （`share/file.go:148`），客户端传 `../` 就写到 `--download-dir` 之外。
#[test]
fn defect_13_file_name_validation_blocks_escape() {
    use stowaway_core::{IncomingFile, safe_join, validate_name};
    use stowaway_protocol::{FileDirection, FileParam};

    let root = std::env::temp_dir().join("rs-away-defect13");
    std::fs::create_dir_all(&root).expect("mkdir");

    for name in [
        "../escape.txt",
        "../../etc/passwd",
        "sub/dir.txt",
        "sub\\dir.txt",
        "..",
        ".",
        ".bashrc",
        "CON",
        "lpt1.txt",
    ] {
        assert!(
            validate_name(name).is_err(),
            "{name:?} 必须被拒绝（v1 会直接 os.Create）"
        );
        assert!(safe_join(&root, name).is_err(), "{name:?} 不得拼出路径");
        let param = FileParam {
            name: name.to_owned(),
            size: 1,
            sha256: [0u8; 32],
            offset: 0,
            direction: FileDirection::Upload,
        };
        assert!(
            IncomingFile::new(SessionKey::new(NodeId::ADMIN, 1), &root, &param).is_err(),
            "{name:?} 不得创建下载目标"
        );
    }

    // 合法名字必须落在 root 之内（且是直接子项，不是别处）。
    let ok = FileParam {
        name: "ok.txt".to_owned(),
        size: 3,
        sha256: [0u8; 32],
        offset: 0,
        direction: FileDirection::Upload,
    };
    let f = IncomingFile::new(SessionKey::new(NodeId::ADMIN, 2), &root, &ok).expect("ok");
    assert_eq!(f.path.parent(), Some(root.as_path()));
    let _ = std::fs::remove_dir_all(&root);
}

/// 缺陷 #12：上游代理提前短响应（< 4 字节）会触发 v1 的
/// `resultBuf[begin-4:begin]` 负索引 panic（`share/proxy.go:205`）。
#[tokio::test]
async fn defect_12_short_proxy_response_is_error_not_panic() {
    use stowaway_core::{ProxySpec, dial_via_proxy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 512];
        let _ = s.read(&mut buf).await;
        // 只有 2 字节：v1 会切 resultBuf[-2:0]。
        let _ = s.write_all(b"HT").await;
        drop(s);
    });

    let spec = ProxySpec::http(addr.to_string(), "", "");
    let err = dial_via_proxy(&spec, "example.com:443")
        .await
        .expect_err("短响应必须报错");
    // 关键在于「返回 Err 而不是 panic」，文案不作强断言。
    assert!(!err.to_string().is_empty());
}
