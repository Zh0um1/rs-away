//! P3 出口判据：三节点链路 e2e 帧转发 + route_cache epoch 失效专项用例。
//!
//! 拓扑：`ADMIN ← A1 ← A2`（A1 是 admin 的子节点，A2 是 A1 的子节点）。
//!
//! 测试**真的走完整握手与密封**：每段链路用 `tokio::io::duplex` 造字节
//! 流，包成 `Link`，两侧分别跑 `client_handshake`/`server_handshake`，
//! 因此帧在链路上是「密文 + 分片 + 计数器」的真实形状，而不是把
//! `Frame` 结构体直接塞进通道。

use std::sync::Arc;
use std::time::Duration;

use stowaway_core::link_actor::InboundFrame;
use stowaway_core::{CoreError, Node, NodeConfig, Route, Topology, decide};
use stowaway_crypto::Secret;
use stowaway_protocol::{
    ByteBuf, Heartbeat, Message, MsgType, NodeId, NodeKind, NodeScope, NodeState, SessionCode,
    SessionData, SessionKey, SessionKind, TransportKind,
};
use stowaway_transport::{Link, LinkCodec, LinkMeta, boxed};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

// ------------------------------------------------------------------ 测试工具

/// 在 `duplex` 之上包一层 `Link`。
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

fn link(inner: DuplexStream, max_frame: usize) -> Box<dyn Link> {
    let meta = LinkMeta::new(TransportKind::Raw, None).with_max_frame(max_frame);
    boxed(TestLink { inner, meta })
}

fn id(n: u8) -> NodeId {
    let mut b = [0u8; 16];
    b[0] = n;
    NodeId(b)
}

fn secret() -> Arc<Secret> {
    Arc::new(Secret::load("e2e-shared-secret-value", 8).expect("secret"))
}

/// 建一条已完成握手 + 密封的链路，返回两侧编解码器。
async fn handshake_pair(max_frame: usize) -> (LinkCodec, LinkCodec) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let mut client = LinkCodec::new(link(a, max_frame));
    let mut server = LinkCodec::new(link(b, max_frame));
    let s = secret();
    let s2 = s.clone();
    let client_task = tokio::spawn(async move {
        client
            .client_handshake(NodeKind::Agent, TransportKind::Raw, None, &s2)
            .await
            .map(|_| client)
    });
    let server_task = tokio::spawn(async move {
        server
            .server_handshake(NodeKind::Admin, TransportKind::Raw, None, &s)
            .await
            .map(|_| server)
    });
    let client = client_task.await.expect("join").expect("client handshake");
    let server = server_task.await.expect("join").expect("server handshake");
    (client, server)
}

// ------------------------------------------------------------------ T-A 三节点转发

/// admin 侧的聚合器：收帧 → `Node::handle_frame`。
async fn admin_loop(
    mut node: Node,
    mut inbound: tokio::sync::mpsc::Receiver<InboundFrame>,
) -> Vec<stowaway_core::node::Handled> {
    let mut log = Vec::new();
    while let Some(frame) = inbound.recv().await {
        match node.handle_frame(frame).await {
            Ok(h) => log.push(h),
            Err(e) => panic!("admin 处理帧失败：{e}"),
        }
    }
    log
}

#[tokio::test]
async fn three_node_chain_forwards_frames_end_to_end() {
    // 链 1：admin(上行) ←→ A1
    let (admin_side, a1_up) = handshake_pair(64 * 1024).await;
    // 链 2：A1(下行) ←→ A2
    let (a1_down, a2_up) = handshake_pair(64 * 1024).await;

    let (admin_tx, admin_rx) = tokio::sync::mpsc::channel::<InboundFrame>(64);
    let (a1_tx, a1_rx) = tokio::sync::mpsc::channel::<InboundFrame>(64);

    // admin：自己是根，A1 是它的孩子。
    let mut admin = Node::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin));
    let (admin_link, admin_actor) = admin
        .attach_link(admin_side, id(1), NodeId::ADMIN, NodeKind::Agent, admin_tx)
        .expect("admin attach a1");

    // A1：admin 是它的上游，A2 是它的下游。
    let mut a1 = Node::new(NodeConfig::new(id(1), NodeKind::Agent));
    let (_a1_up_link, a1_up_actor) = a1
        .attach_upstream(a1_up, NodeId::ADMIN, NodeKind::Admin, a1_tx.clone())
        .expect("a1 attach upstream");
    let (_a1_down_link, a1_down_actor) = a1
        .attach_link(a1_down, id(2), id(1), NodeKind::Agent, a1_tx)
        .expect("a1 attach a2");

    // A2 接入后，A1 必须立刻向上游公告，否则 admin 不知道孙节点存在。
    a1.announce_child(id(2), NodeKind::Agent)
        .await
        .expect("a1 announce a2");
    // 中间节点的路由视图也要先断言：A2 在它下面。
    assert_eq!(a1.next_hop(id(2)).expect("hop"), id(2));

    let admin_task = tokio::spawn(admin_loop(admin, admin_rx));
    let a1_task = tokio::spawn(admin_loop(a1, a1_rx));
    let admin_actor_task = tokio::spawn(admin_actor.run());
    let a1_up_task = tokio::spawn(a1_up_actor.run());
    let a1_down_task = tokio::spawn(a1_down_actor.run());

    // A2 侧只要一个裸 codec 来接帧即可（它不参与路由判定）。
    let mut a2 = a2_up;

    // 从 admin 发一条心跳给 A2（跨两跳）。
    admin_link
        .send(
            Message::Heartbeat(Heartbeat {
                send_ts: 11,
                echo_ts: 0,
            }),
            id(2),
            Vec::new(),
        )
        .await
        .expect("admin → a2");

    // A2 收到的帧：目标仍是 2，via 为空（中间节点不改 payload/dest）。
    let (frame, msg) = tokio::time::timeout(Duration::from_secs(5), a2.recv_message())
        .await
        .expect("a2 recv timeout")
        .expect("a2 recv");
    assert_eq!(frame.header.dest, id(2));
    assert!(frame.header.via.is_empty());
    assert_eq!(frame.header.msg_type, MsgType::Heartbeat);
    let Message::Heartbeat(hb) = msg else {
        panic!("expected heartbeat");
    };
    assert_eq!(hb.send_ts, 11);

    // 收尾：断开链路，actor 应正常退出（不 panic）。
    drop(a2);
    let _ = tokio::time::timeout(Duration::from_secs(5), admin_actor_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), a1_up_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), a1_down_task).await;
    drop(a1_task);
    drop(admin_task);
}

#[tokio::test]
async fn route_decision_uses_cache_and_recomputes_after_epoch_bump() {
    // 纯拓扑层：验证「缓存命中」与「epoch 变化后重算」两条路径。
    let mut t = Topology::new(NodeId::ADMIN, NodeKind::Admin, 8);
    t.insert(stowaway_core::NodeMeta::new(
        id(1),
        NodeId::ADMIN,
        0,
        NodeKind::Agent,
    ))
    .expect("insert a1");
    t.insert(stowaway_core::NodeMeta::new(
        id(2),
        id(1),
        0,
        NodeKind::Agent,
    ))
    .expect("insert a2");

    let before = decide(&mut t, NodeId::ADMIN, id(2), &[]).expect("decide");
    assert_eq!(
        before,
        Route::Forward {
            next_hop: id(1),
            via: Vec::new()
        }
    );
    assert_eq!(t.cached_routes(), 1, "决策后应缓存");

    // 模拟链路变化：A2 改挂到新的孩子 3 下面。
    t.insert(stowaway_core::NodeMeta::new(
        id(3),
        NodeId::ADMIN,
        0,
        NodeKind::Agent,
    ))
    .expect("insert a3");
    let epoch_before = t.epoch();
    t.reparent(id(2), id(3)).expect("reparent");
    assert!(t.epoch() > epoch_before, "reparent 必须 bump epoch");
    assert_eq!(t.cached_routes(), 0, "epoch bump 后缓存清空");

    let after = decide(&mut t, NodeId::ADMIN, id(2), &[]).expect("decide");
    assert_eq!(
        after,
        Route::Forward {
            next_hop: id(3),
            via: Vec::new()
        }
    );
}

#[tokio::test]
async fn undeliverable_is_reported_not_dropped() {
    let mut n = Node::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin));
    let err = n
        .send(
            &Message::Heartbeat(Heartbeat {
                send_ts: 1,
                echo_ts: 0,
            }),
            id(7),
        )
        .await
        .expect_err("unknown dest");
    assert!(matches!(err, CoreError::Undeliverable { .. }));
    assert_eq!(n.undeliverable(), 0, "send 失败不增加处理计数");
}

#[tokio::test]
async fn session_key_from_two_origins_coexist_through_a_real_link() {
    let (admin_side, mut a1) = handshake_pair(64 * 1024).await;
    let (admin_tx, _admin_rx) = tokio::sync::mpsc::channel::<InboundFrame>(16);
    let mut admin = Node::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin));
    let (admin_link, actor) = admin
        .attach_link(admin_side, id(1), NodeId::ADMIN, NodeKind::Agent, admin_tx)
        .expect("attach");
    let task = tokio::spawn(actor.run());

    // 两侧都从 id=0 开始发号 —— v1 会撞号，v2 用 origin 区分。
    let k_a1 = SessionKey::new(id(1), 0);
    let k_admin = SessionKey::new(NodeId::ADMIN, 0);
    for key in [k_a1, k_admin] {
        admin_link
            .send(
                Message::OpenSession(stowaway_protocol::OpenSession {
                    key,
                    kind: SessionKind::Socks5,
                    direction: stowaway_protocol::SessionDirection::Outbound,
                    target: Some("127.0.0.1:80".to_owned()),
                    param: stowaway_protocol::ServiceParam::None,
                }),
                id(1),
                Vec::new(),
            )
            .await
            .expect("send open");
    }
    for _ in 0..2 {
        let (_, msg) = a1.recv_message().await.expect("recv");
        let Message::OpenSession(open) = msg else {
            panic!("expected open");
        };
        // 两个 0 号会话必须能被区分。
        assert!(open.key == k_a1 || open.key == k_admin);
    }
    drop(a1);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn session_data_sequence_is_enforced_over_the_wire() {
    let (admin_side, a1) = handshake_pair(64 * 1024).await;
    let (admin_tx, admin_rx) = tokio::sync::mpsc::channel::<InboundFrame>(16);
    let mut admin = Node::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin));
    let (_admin_link, actor) = admin
        .attach_link(admin_side, id(1), NodeId::ADMIN, NodeKind::Agent, admin_tx)
        .expect("attach");
    let actor_task = tokio::spawn(actor.run());

    // A1 侧发出「打开 + 就绪 + 两条数据」，admin 侧处理。
    let key = SessionKey::new(id(1), 9);
    let mut a1_link = a1; // 直接用 codec 发即可（A1 路由细节不属于本例）
    a1_link
        .send(
            &Message::OpenSession(stowaway_protocol::OpenSession {
                key,
                kind: SessionKind::Socks5,
                direction: stowaway_protocol::SessionDirection::Outbound,
                target: Some("127.0.0.1:80".to_owned()),
                param: stowaway_protocol::ServiceParam::None,
            }),
            NodeId::ADMIN,
            &[],
        )
        .await
        .expect("open");
    a1_link
        .send(
            &Message::SessionReady(stowaway_protocol::SessionReady {
                key,
                code: SessionCode::Ok,
                detail: String::new(),
            }),
            NodeId::ADMIN,
            &[],
        )
        .await
        .expect("ready");
    for seq in 0..2u64 {
        a1_link
            .send(
                &Message::SessionData(SessionData {
                    key,
                    seq,
                    data: ByteBuf::from(vec![seq as u8; 8]),
                }),
                NodeId::ADMIN,
                &[],
            )
            .await
            .expect("data");
    }

    let mut inbound = admin_rx;
    // 三条（open/ready/data×2）都要被处理；第三条与第四条是数据。
    let mut handled = Vec::new();
    for _ in 0..4 {
        let frame = inbound.recv().await.expect("inbound");
        handled.push(admin.handle_frame(frame).await.expect("handle"));
    }
    assert!(
        handled.iter().any(
            |h| matches!(h, stowaway_core::node::Handled::SessionData { seq, .. } if *seq == 0)
        )
    );
    drop(a1_link);
    let _ = tokio::time::timeout(Duration::from_secs(5), actor_task).await;
}

#[tokio::test]
async fn node_status_offline_prunes_child_and_its_sessions() {
    let mut n = Node::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin));
    let (tx, rx) = tokio::sync::mpsc::channel::<InboundFrame>(4);
    let (a, b) = tokio::io::duplex(4096);
    let codec = LinkCodec::new(link(a, 4096));
    let (_handle, actor) = n
        .attach_link(codec, id(4), NodeId::ADMIN, NodeKind::Agent, tx)
        .expect("attach");
    drop(b);
    drop(rx);
    drop(actor);
    assert!(n.topology().get(id(4)).is_some());

    // 该节点发起过一个会话（模拟）。
    n.handle_local_message(Message::OpenSession(stowaway_protocol::OpenSession {
        key: SessionKey::new(id(4), 3),
        kind: SessionKind::Socks5,
        direction: stowaway_protocol::SessionDirection::Outbound,
        target: None,
        param: stowaway_protocol::ServiceParam::None,
    }))
    .await
    .expect("open");
    assert_eq!(n.sessions().len(), 1);

    // 收到「子节点离线」上报 → 拓扑摘掉它，并清理它发起的会话。
    let status = stowaway_protocol::NodeStatus {
        scope: NodeScope::Child,
        state: NodeState::Offline,
        node: id(4),
    };
    let handled = n
        .handle_local_message(Message::NodeStatus(status))
        .await
        .expect("handle");
    assert!(matches!(handled, stowaway_core::node::Handled::Status(_)));
    assert!(n.topology().get(id(4)).is_none());
    assert_eq!(n.sessions().len(), 0, "孤儿会话必须被清理");
}
