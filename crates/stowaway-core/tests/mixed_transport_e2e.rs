//! plan §8.5 附加判据（一）：**跨传输混跑** —— 上行 ws、子链路另一套传输实现，
//! 在同一次运行里各自独立握手、独立编号、独立数据面。
//!
//! 拓扑（两段链路都是真实 `TcpListener`/`TcpStream`，不是 `duplex`）：
//!
//! ```text
//! ADMIN  ←── ws ──  A1  ←── raw ──  A2
//!  根/深度 0        深度 1            深度 2
//! ```
//!
//! 与 `topology_e2e.rs`（三段 `duplex` 字节流）的区别有三点，也正是本判据的
//! 内容：
//!
//! 1. **真实 socket**：两段链路都经 `stowaway_core::bind`/`dial`/`accept`，
//!    走 `runtime.rs` 的生产路径（`listener_for` → `AnyListener` /
//!    `dialer_for` → `AnyDialer`），中间不 mock 任何协议层。
//! 2. **两种不同传输同处一棵树**：上行是 WebSocket（真 HTTP Upgrade，
//!    `WsListener`/`WsDialer`），子链路是裸 TCP。两侧的
//!    `HandshakeResult::peer_transport` 是握手 transcript 里绑定的**声明值**
//!    （`docs/design/transport.md` §3：传输声明参与 TH，不可降级），所以
//!    「这条链路说的是哪种传输」可以被独立断言，而不是靠注释声称。
//! 3. **编号只由父节点分配**（plan §4.4）：A1 的编号来自 admin 的 `lead`，
//!    A2 的编号来自 A1 的 `lead`。测试用两个**盐不同**的分配器把这条规则
//!    变成可判定的断言（`admin_alloc.owns(a1)` 为真、`admin_alloc.owns(a2)`
//!    为假）。
//!
//! ## 为什么子链路是 kcp 而不是再开一条 raw
//!
//! 判据原文是「上行 ws、子链路 kcp」。若子链路也用 raw，两条链路的
//! `TransportKind` 就都是 `Raw`，`peer_transport` 的断言只能证明「读到了
//! 一个值」，无法区分「哪一段是哪一段」——那等于把判据做成自证。
//!
//! `transport-kcp` 是 `stowaway-transport` 的非默认 feature，因此本测试
//! 需要 `stowaway-core` 的同名 feature（`crates/stowaway-core/Cargo.toml`
//! 里 `transport-kcp = ["stowaway-transport/transport-kcp"]`）：
//!
//! ```text
//! cargo test -p stowaway-core --features transport-kcp --test mixed_transport_e2e
//! ```
//!
//! 未打开该 feature 时，`listener_for(kcp_spec)` 返回
//! `TransportError::FeatureDisabled`，测试会**响亮地失败**而不是静默降级
//! —— 这正是想要的：判据没跑就应该是红的，而不是绿的。
//!
//! kcp 基于 UDP、`conv` 由 secret 派生（`stowaway_crypto::kcp_conv`），
//! 因此两段链路的 `max_frame` 也不同（kcp = `mtu × 8`，raw = `FRAGMENT_MAX`）
//! —— 这正是「两种传输实现各自独立」的实质，而不只是两个字符串不同。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use stowaway_core::{
    EngineHandle, Event, HeartbeatConfig, NodeConfig, NodeIdAllocator, Runtime, RuntimeConfig,
    Side, Snapshot, accept, announce_message, bind, dial, follow, lead, side_of,
};
use stowaway_crypto::Secret;
use stowaway_protocol::{
    Message, NodeId, NodeKind, OpenSession, ServiceParam, SessionDirection, SessionKey,
    SessionKind, TransportKind,
};
use stowaway_transport::{DialTarget, TransportSpec};

/// 上行（admin ←→ A1）：WebSocket。
const UPSTREAM_SPEC: &str = "ws://127.0.0.1:0?path=/deadbeef";
/// 子链路（A1 ←→ A2）：裸 TCP。理由见文件头「为什么子链路不是 kcp」。
const CHILD_SPEC: &str = "kcp://127.0.0.1:0";

fn secret() -> Arc<Secret> {
    Arc::new(Secret::load("mixed-transport-e2e-secret", 8).expect("secret"))
}

/// ws 拨号需要 path/domain：与 `stowaway-agent`/`bridge` 的构造方式一致
/// （见 `crates/stowaway-agent/src/main.rs` 的 `DialTarget { .. }`）。
fn ws_target(spec: &TransportSpec, addr: SocketAddr) -> DialTarget {
    DialTarget {
        addr,
        domain: spec.effective_domain(),
        path: Some(spec.effective_path().to_owned()),
        tls: None,
    }
}

/// 轮询快照直到条件成立（引擎是异步的，`lead`/公告之后不能假设拓扑立刻可见）。
async fn wait_snapshot(
    handle: &EngineHandle,
    what: &str,
    pred: impl Fn(&Snapshot) -> bool,
) -> Snapshot {
    for _ in 0..1000 {
        let snap = handle.snapshot().await.expect("取快照");
        if pred(&snap) {
            return snap;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let last = handle.snapshot().await.expect("取快照");
    panic!("等待 {what} 超时；最后快照：{last:?}");
}

/// 等到第一条匹配的事件；期间引擎报错/退出立刻失败（不吞掉）。
async fn wait_event(rt: &mut Runtime, what: &str, pred: impl Fn(&Event) -> bool) -> Event {
    let fut = async {
        loop {
            match rt.next_event().await {
                Some(Event::Failed(msg)) => panic!("等待 {what} 期间引擎报错：{msg}"),
                Some(ev) if pred(&ev) => return ev,
                Some(_) => {}
                None => panic!("等待 {what} 期间引擎退出"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .unwrap_or_else(|_| panic!("等待 {what} 超时"))
}

/// 判据主用例：一条 ws 上行 + 一条 kcp 子链路，同一次运行里建成两层树，
/// 并且一条 admin → A2 的消息真的送达 A2 的引擎。
///
/// 未开 `transport-kcp` 时必须**失败**（`FeatureDisabled`），不能跳过：
/// 判据没跑就该是红的。
#[tokio::test]
async fn ws_upstream_and_kcp_child_link_share_one_tree() {
    let shared = secret();

    // —— 1) admin：绑 ws 监听并起引擎（根节点，深度 0）。 ——
    let upstream_spec = TransportSpec::parse(UPSTREAM_SPEC).expect("解析上行规格");
    let (mut ws_listener, upstream_kind, upstream_addr) =
        bind(&upstream_spec, None).await.expect("admin 绑 ws 监听");
    assert_eq!(
        upstream_kind,
        TransportKind::Ws,
        "上行必须落在 ws 传输实现上"
    );

    let admin_cfg = RuntimeConfig::new(
        NodeConfig::new(NodeId::ADMIN, NodeKind::Admin),
        shared.clone(),
    );
    let mut admin = Runtime::start(admin_cfg);
    let admin_handle = admin.handle();
    // 盐刻意与 A1 的分配器不同，便于用 `owns` 判定「编号是谁分配的」。
    let mut admin_alloc = NodeIdAllocator::new([1, 2, 3, 4]);

    // A1 侧：ws 拨号 + `follow` 申领编号。两侧必须并发：admin 在
    // `accept`/`lead` 里等 Join，A1 在 `follow` 里等 JoinAck。
    let a1_cfg = RuntimeConfig::new(
        NodeConfig::new(NodeId::UNASSIGNED, NodeKind::Agent),
        shared.clone(),
    );
    let a1_upstream = ws_target(&upstream_spec, upstream_addr);
    let shared_admin = shared.clone();
    let (admin_side, a1_side) = tokio::join!(
        async {
            let link = accept(
                &mut ws_listener,
                upstream_kind,
                shared_admin.as_ref(),
                NodeKind::Admin,
                None,
            )
            .await
            .expect("admin 接受 ws 入站");
            assert_eq!(link.handshake.peer_kind, NodeKind::Agent);
            // 混跑的正面证据 ①：admin 侧在握手 transcript 里读到对端声明 ws。
            assert_eq!(
                link.handshake.peer_transport,
                TransportKind::Ws,
                "上行链路的对端声明传输必须是 Ws"
            );
            assert_eq!(
                side_of(link.handshake.peer_kind),
                Side::Parent,
                "对端是 Agent ⇒ 本端是父节点 ⇒ 编号由本端分配"
            );
            assert!(
                link.peer.ip().is_loopback() && link.peer.port() != 0,
                "必须是回环上的真实 socket"
            );
            let a1 = lead(
                &admin_handle,
                link.codec,
                &mut admin_alloc,
                NodeId::ADMIN,
                NodeId::ADMIN,
                0,
            )
            .await
            .expect("admin 给 A1 分配编号");
            assert!(admin_alloc.owns(a1), "A1 的编号必须落在 admin 的编号空间");
            (a1, link.peer)
        },
        async {
            let link = dial(
                &upstream_spec,
                &a1_upstream,
                NodeKind::Agent,
                shared.as_ref(),
            )
            .await
            .expect("A1 拨号 ws 上行");
            assert_eq!(link.handshake.peer_kind, NodeKind::Admin);
            // 混跑的正面证据 ②：A1 侧同样读到 ws 声明（客户端回填自己的声明值）。
            assert_eq!(
                link.handshake.peer_transport,
                TransportKind::Ws,
                "上行链路的客户端声明传输必须是 Ws"
            );
            assert_eq!(
                side_of(link.handshake.peer_kind),
                Side::Child,
                "对端是 Admin ⇒ 本端是子节点 ⇒ 编号向对端申领"
            );
            let (rt, ack) = follow(link.codec, a1_cfg, NodeId::ADMIN, NodeKind::Admin)
                .await
                .expect("A1 入网");
            (rt, ack)
        }
    );
    let (a1_id, a1_upstream_peer) = admin_side;
    let (a1_rt, a1_ack) = a1_side;

    assert_eq!(a1_ack.node, a1_id, "A1 拿到的编号必须是 admin 分配的那个");
    assert_eq!(a1_ack.parent, NodeId::ADMIN);
    assert_eq!(a1_ack.root, NodeId::ADMIN);
    assert_eq!(a1_ack.depth, 1);
    assert!(
        a1_upstream_peer.ip().is_loopback(),
        "上行对端必须是回环地址"
    );

    // —— 2) A1 绑 kcp 监听，做 A2 的父节点。 ——
    let child_spec = TransportSpec::parse(CHILD_SPEC).expect("解析子链路规格");
    let (mut raw_listener, child_kind, child_addr) =
        bind(&child_spec, None).await.expect("A1 绑 kcp 监听");
    assert_eq!(
        child_kind,
        TransportKind::Kcp,
        "子链路必须落在 kcp 传输实现上"
    );

    let a1_handle = a1_rt.handle();
    let mut a1_alloc = NodeIdAllocator::new([7, 7, 7, 7]);
    let a1_depth = a1_ack.depth;
    let a2_cfg = RuntimeConfig::new(
        NodeConfig::new(NodeId::UNASSIGNED, NodeKind::Agent),
        shared.clone(),
    );
    let shared_a1 = shared.clone();
    let (a1_downstream, a2_side) = tokio::join!(
        async {
            // A1 相对 A2 是**父节点**：握手时声明 Admin。这里用的是「相对角色」
            // （`runtime.rs` 顶部表：对端 Agent ⇒ 本端父节点），不是节点的绝对种类。
            let link = accept(
                &mut raw_listener,
                child_kind,
                shared_a1.as_ref(),
                NodeKind::Admin,
                None,
            )
            .await
            .expect("A1 接受 kcp 入站");
            assert_eq!(link.handshake.peer_kind, NodeKind::Agent);
            // 混跑的正面证据 ③：子链路的对端声明的是 Raw，不是上行那条 ws。
            assert_eq!(
                link.handshake.peer_transport,
                TransportKind::Kcp,
                "子链路的对端声明传输必须是 Kcp"
            );
            assert_eq!(side_of(link.handshake.peer_kind), Side::Parent);
            let a2 = lead(
                &a1_handle,
                link.codec,
                &mut a1_alloc,
                a1_id,
                NodeId::ADMIN,
                a1_depth,
            )
            .await
            .expect("A1 给 A2 分配编号");
            assert!(a1_alloc.owns(a2), "A2 的编号必须落在 A1 的编号空间");
            a2
        },
        async {
            let link = dial(
                &child_spec,
                &DialTarget::plain(child_addr),
                NodeKind::Agent,
                shared.as_ref(),
            )
            .await
            .expect("A2 拨号 kcp 子链路");
            assert_eq!(link.handshake.peer_kind, NodeKind::Admin);
            // 混跑的正面证据 ④：A2 侧读到 Raw。
            assert_eq!(
                link.handshake.peer_transport,
                TransportKind::Kcp,
                "子链路的客户端声明传输必须是 Kcp"
            );
            assert_eq!(side_of(link.handshake.peer_kind), Side::Child);
            let (rt, ack) = follow(link.codec, a2_cfg, a1_id, NodeKind::Admin)
                .await
                .expect("A2 入网");
            (rt, ack)
        }
    );
    let a2_id = a1_downstream;
    let (mut a2_rt, a2_ack) = a2_side;

    assert_eq!(a2_ack.node, a2_id);
    assert_eq!(a2_ack.parent, a1_id, "A2 的父节点是 A1");
    assert_eq!(a2_ack.root, NodeId::ADMIN, "根仍是 admin");
    assert_eq!(a2_ack.depth, a1_depth + 1, "A2 是第二层");
    assert_ne!(a1_id, a2_id, "两层的编号不得相撞");
    assert!(!admin_alloc.owns(a2_id), "A2 的编号不是 admin 分配的");
    assert!(!a1_alloc.owns(a1_id), "A1 的编号不是 A1 自己分配的");

    // —— 3) 拓扑：admin 必须看到两层，A2 的深度为 2。 ——
    // 引擎不会替中间节点代子公告（`Node::announce_child` 归 Engine 私有，
    // plan §4.7 要求父节点主动公告），所以这里用同一语义的公开函数
    // `announce_message` 让 A1 向上游公告 A2。公告之前 admin 不该知道 A2。
    let before = admin_handle.snapshot().await.expect("admin 快照");
    assert!(
        before.nodes.iter().all(|n| n.node != a2_id),
        "未公告之前 admin 不该知道 A2"
    );
    a1_handle
        .send(announce_message(a2_id, NodeKind::Agent), NodeId::ADMIN)
        .await
        .expect("A1 向上游公告 A2");

    let admin_snap = wait_snapshot(&admin_handle, "admin 拓扑出现第二层 A2", |s| {
        s.nodes.iter().any(|n| n.node == a2_id)
    })
    .await;
    assert_eq!(admin_snap.me, Some(NodeId::ADMIN));
    assert_eq!(admin_snap.depth, 0, "admin 是根，深度 0");
    assert_eq!(admin_snap.root, Some(NodeId::ADMIN));

    let a1_meta = admin_snap
        .nodes
        .iter()
        .find(|n| n.node == a1_id)
        .expect("admin 拓扑里缺 A1");
    assert_eq!(a1_meta.depth, 1);
    assert_eq!(a1_meta.parent, NodeId::ADMIN);
    assert_eq!(a1_meta.kind, NodeKind::Agent);

    let a2_meta = admin_snap
        .nodes
        .iter()
        .find(|n| n.node == a2_id)
        .expect("admin 拓扑里缺 A2");
    assert_eq!(a2_meta.depth, 2, "A2 必须是第二层（深度 2）");
    assert_eq!(a2_meta.parent, a1_id, "A2 挂在 A1 之下");
    assert_eq!(a2_meta.kind, NodeKind::Agent);

    // admin 侧 attach A1 时的事件（`lead` → `attach_link` → `Event::Joined`）。
    let joined = wait_event(
        &mut admin,
        "A1 的 Joined 事件",
        |ev| matches!(ev, Event::Joined { node, .. } if *node == a1_id),
    )
    .await;
    match joined {
        Event::Joined { kind, parent, .. } => {
            assert_eq!(kind, NodeKind::Agent);
            assert_eq!(parent, NodeId::ADMIN);
        }
        other => panic!("期望 Joined，实际 {other:?}"),
    }

    // —— 4) 数据面：admin → A2 的一条消息必须真的送达 A2 的引擎。 ——
    // 选 `OpenSession` 而不是心跳：心跳只证明「对端活着」，而 `OpenSession`
    // 走完整派发（admin 路由 → A1 原样转发 → A2 本地拆包），A2 的引擎会因此
    // 产生 `Event::SessionOpened`，等价于「消息按目标编号真的到达了目的节点」，
    // 是这条链路最强的可观察证据（比 `Event::Rtt` 强：RTT 只经过相邻链路）。
    let key = SessionKey::new(NodeId::ADMIN, 1);
    let open = OpenSession {
        key,
        kind: SessionKind::default(),
        direction: SessionDirection::default(),
        target: None,
        param: ServiceParam::default(),
    };
    admin_handle
        .send(Message::OpenSession(open), a2_id)
        .await
        .expect("admin 发往 A2（需 A1 中继）");

    let delivered = wait_event(
        &mut a2_rt,
        "A2 收到 admin 的 OpenSession",
        |ev| matches!(ev, Event::SessionOpened { open, .. } if open.key == key),
    )
    .await;
    match delivered {
        Event::SessionOpened { open, from } => {
            assert_eq!(from, a1_id, "A2 是从它的父链路收到这一帧的");
            assert_eq!(open.key, key);
            assert_eq!(
                open.key.origin,
                NodeId::ADMIN,
                "会话起源仍是 admin（中继不改 payload）"
            );
            assert!(
                open.target.is_none(),
                "中继必须原样转发 payload（plan §4.7）"
            );
        }
        other => panic!("期望 SessionOpened，实际 {other:?}"),
    }

    // A2 自己的视角：`me` 正确、上游是 A1（相对深度 1）。
    let a2_snap = a2_rt.handle().snapshot().await.expect("A2 快照");
    assert_eq!(a2_snap.me, Some(a2_id));
    assert_eq!(a2_snap.depth, 1, "相对上游 A1，A2 是深度 1");
    assert_eq!(a2_snap.root, Some(a1_id));
    assert!(
        a2_snap.nodes.iter().any(|n| n.node == a1_id),
        "A2 拓扑里必须有它的上游 A1"
    );

    admin.shutdown().await.expect("admin 收摊");
    a1_rt.shutdown().await.expect("A1 收摊");
    a2_rt.shutdown().await.expect("A2 收摊");
}

/// 同一棵混跑树上的心跳往返：ws 上行的探测帧要能被 A1 应答、admin 侧
/// 收到 `Event::Rtt`，证明 ws 这条链路的**双向**数据面（不只是握手）都通。
#[tokio::test]
async fn ws_upstream_carries_heartbeat_round_trip() {
    let shared = secret();
    let upstream_spec = TransportSpec::parse(UPSTREAM_SPEC).expect("解析上行规格");
    let (mut ws_listener, upstream_kind, upstream_addr) =
        bind(&upstream_spec, None).await.expect("admin 绑 ws 监听");
    assert_eq!(upstream_kind, TransportKind::Ws);

    let mut admin_cfg = RuntimeConfig::new(
        NodeConfig::new(NodeId::ADMIN, NodeKind::Admin),
        shared.clone(),
    );
    // 只有配了心跳，`Engine::pulse` 才会真的发探测帧（plan §4.12：默认只应答、不主动探）。
    admin_cfg.heartbeat = Some(HeartbeatConfig {
        interval: Duration::from_millis(20),
        max_missed: 64,
    });
    let mut admin = Runtime::start(admin_cfg);
    let admin_handle = admin.handle();
    let mut admin_alloc = NodeIdAllocator::new([9, 9, 9, 9]);

    let a1_cfg = RuntimeConfig::new(
        NodeConfig::new(NodeId::UNASSIGNED, NodeKind::Agent),
        shared.clone(),
    );
    let a1_upstream = ws_target(&upstream_spec, upstream_addr);
    let shared_admin = shared.clone();
    let (admin_side, a1_side) = tokio::join!(
        async {
            let link = accept(
                &mut ws_listener,
                upstream_kind,
                shared_admin.as_ref(),
                NodeKind::Admin,
                None,
            )
            .await
            .expect("admin 接受 ws 入站");
            assert_eq!(
                link.handshake.peer_transport,
                TransportKind::Ws,
                "上行链路的对端声明传输必须是 Ws"
            );
            lead(
                &admin_handle,
                link.codec,
                &mut admin_alloc,
                NodeId::ADMIN,
                NodeId::ADMIN,
                0,
            )
            .await
            .expect("admin 给 A1 分配编号")
        },
        async {
            let link = dial(
                &upstream_spec,
                &a1_upstream,
                NodeKind::Agent,
                shared.as_ref(),
            )
            .await
            .expect("A1 拨号 ws 上行");
            assert_eq!(
                link.handshake.peer_transport,
                TransportKind::Ws,
                "上行链路的客户端声明传输必须是 Ws"
            );
            let (rt, ack) = follow(link.codec, a1_cfg, NodeId::ADMIN, NodeKind::Admin)
                .await
                .expect("A1 入网");
            (rt, ack)
        }
    );
    let a1_id = admin_side;
    let (a1_rt, a1_ack) = a1_side;
    assert_eq!(a1_ack.node, a1_id);

    let rtt_event = wait_event(
        &mut admin,
        "ws 上行上的心跳往返（Event::Rtt）",
        |ev| matches!(ev, Event::Rtt { peer, .. } if *peer == a1_id),
    )
    .await;
    match rtt_event {
        Event::Rtt { peer, rtt_ms } => {
            assert_eq!(peer, a1_id);
            assert!(rtt_ms < 5_000, "回环上的 RTT 不该是 {rtt_ms} ms");
        }
        other => panic!("期望 Rtt，实际 {other:?}"),
    }

    admin.shutdown().await.expect("admin 收摊");
    a1_rt.shutdown().await.expect("A1 收摊");
}
