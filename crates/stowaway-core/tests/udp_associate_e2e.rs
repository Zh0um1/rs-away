//! 端到端：SOCKS5 UDP ASSOCIATE 的数据面在**两个真引擎**之间跑通。
//!
//! 覆盖整条链路：
//!
//! ```text
//! admin                                            agent
//!   register_session(Socks5Udp)                    Event::SessionOpened
//!   open_stream(Socks5Udp)              ─────────▶ open_stream(Socks5Udp)
//!   send(OpenSession{direction:Inbound})            bind_outlet(127.0.0.1:0)
//!   await_ready                         ◀───────── ready_session(Ok, 出口地址)
//!                                                   outlet_side_on(出口套接字, 会话流)
//!   frame_datagram(会话流, 数据报)       ─────────▶ read_datagram → send_to(目标)
//!   read_datagram(会话流)               ◀───────── recv_from → frame_datagram
//! ```
//!
//! 方向字段写 `Inbound`：`SessionDirection` 是**相对接收方**的语义
//! （`stowaway-protocol/src/msg.rs:264-272`）。`OpenSession` 由 admin 发出、
//! 接收方是 agent，而 agent 才是「提供资源/监听」的一端 —— 正是 `Inbound`。
//! 这与 `docs/plan.md` 附录 A 第 30 行
//! `UDPASSSTART → OpenSession{kind: Socks5Udp, direction: Inbound}` 一致，
//! 也与 `crates/stowaway-core/tests/services_e2e.rs:513-540` 的既有断言一致。
//!
//! 一个容易踩的坑，也是 `udp_session` 存在的理由：会话流是**字节流**，
//! `write_all` 会被拆成任意多次 `poll_write`，接收方也可能一次读到多个数据报。
//! 所以上/下行都必须走 `frame_datagram` / `read_datagram` 的长度前缀分帧；
//! 直接塞裸数据报会被长度头当成 0 长度（SOCKS5 头前两字节恰好是 RSV=0）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use stowaway_core::link_actor::InboundFrame;
use stowaway_core::udp_session::outlet_side_on;
use stowaway_core::{
    Datagram, Engine, EngineHandle, Event, MAX_UDP_DATAGRAM, NodeConfig, SessionStream, Target,
    TargetAddr, bind_outlet, frame_datagram, read_datagram,
};
use stowaway_crypto::Secret;
use stowaway_protocol::{
    CloseReason, Message, NodeId, NodeKind, OpenSession, ServiceParam, SessionCode,
    SessionDirection, SessionKey, SessionKind, TransportKind,
};
use stowaway_transport::{Link, LinkCodec, LinkMeta, boxed};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// ------------------------------------------------------------------ 测试工具
// 脚手架照抄 `crates/stowaway-core/tests/session_ready_e2e.rs`。

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
    Arc::new(Secret::load("udp-associate-shared-secret", 8).expect("secret"))
}

/// 建一条已完成握手 + 密封的链路：`client` 侧扮 agent，`server` 侧扮 admin。
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

type EngineParts = (
    EngineHandle,
    tokio::task::JoinHandle<stowaway_core::Result<()>>,
);

fn spawn_engine(me: NodeId, kind: NodeKind) -> (EngineParts, mpsc::UnboundedReceiver<Event>) {
    let (tx, rx) = mpsc::unbounded_channel::<Event>();
    let (handle, engine, _inbound): (EngineHandle, Engine, mpsc::Sender<InboundFrame>) =
        Engine::new(NodeConfig::new(me, kind), tx);
    let task = tokio::spawn(engine.run());
    ((handle, task), rx)
}

/// 一个把数据报原样回送的回显套接字，返回它的地址。
async fn udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = sock.local_addr().expect("echo addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if sock.send_to(&buf[..n], from).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// 起两个已互连的真引擎，返回 admin / agent 的句柄与 agent 的事件流。
async fn engines() -> (EngineParts, EngineParts, mpsc::UnboundedReceiver<Event>) {
    let (admin_codec, agent_codec) = handshake_pair(64 * 1024).await;
    let (admin, _admin_events) = spawn_engine(NodeId::ADMIN, NodeKind::Admin);
    let (agent, agent_events) = spawn_engine(id(1), NodeKind::Agent);
    admin
        .0
        .attach_link(admin_codec, id(1), NodeId::ADMIN, NodeKind::Agent)
        .await
        .expect("admin attach agent");
    agent
        .0
        .attach_link(agent_codec, NodeId::ADMIN, NodeId::ADMIN, NodeKind::Admin)
        .await
        .expect("agent attach admin");
    (admin, agent, agent_events)
}

/// 等 agent 侧收到 `SessionOpened`（即 admin 的 `OpenSession` 已到达并登记）。
async fn wait_opened(events: &mut mpsc::UnboundedReceiver<Event>) -> OpenSession {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(Event::SessionOpened { open, .. }) => return open,
                Some(_) => {}
                None => panic!("事件通道关闭：agent 引擎已停"),
            }
        }
    })
    .await
    .expect("等 SessionOpened 超时：OpenSession 没有到达 agent")
}

/// admin 侧的完整发起动作：登记 → 绑流 → 发 `OpenSession`，返回会话流。
///
/// `EngineHandle::open_stream` 对同一 key 只能成功一次（第二次撞
/// `SessionExists`），所以流必须在这里取到并交给调用方。
async fn admin_start(admin: &EngineHandle, key: SessionKey) -> SessionStream {
    admin
        .register_session(key, SessionKind::Socks5Udp)
        .await
        .expect("admin register session");
    let stream = admin
        .open_stream(key, id(1), SessionKind::Socks5Udp)
        .await
        .expect("admin open stream");

    admin
        .send(
            Message::OpenSession(OpenSession {
                key,
                kind: SessionKind::Socks5Udp,
                // 相对接收方（agent）而言出口由 agent 提供 —— 所以是 Inbound。
                direction: SessionDirection::Inbound,
                target: None,
                param: ServiceParam::None,
            }),
            id(1),
        )
        .await
        .expect("admin send OpenSession");
    stream
}

/// agent 侧接受会话：绑流 → 绑出口 → 报 Ready（带回出口地址）→ 跑数据面。
async fn agent_accept(
    agent: &EngineHandle,
    key: SessionKey,
    idle: Duration,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<stowaway_core::Result<()>>,
) {
    // 顺序很重要：sink 必须在报 Ready 之前挂好，否则 admin 一收到 Ready
    // 就发数据，那块数据会落在空处。
    let stream = agent
        .open_stream(key, NodeId::ADMIN, SessionKind::Socks5Udp)
        .await
        .expect("agent open stream");
    let outlet = bind_outlet("127.0.0.1:0".parse().expect("bind addr"))
        .await
        .expect("agent bind outlet");
    let outlet_addr = outlet.local_addr().expect("outlet addr");
    agent
        .ready_session(key, NodeId::ADMIN, SessionCode::Ok, outlet_addr.to_string())
        .await
        .expect("agent ready");
    let task = tokio::spawn(outlet_side_on(outlet, stream, MAX_UDP_DATAGRAM, idle));
    (outlet_addr, task)
}

async fn await_ok(admin: &EngineHandle, key: SessionKey) {
    let code = tokio::time::timeout(Duration::from_secs(10), admin.await_ready(key))
        .await
        .expect("await_ready 超时：agent 没有回 SessionReady")
        .expect("await_ready 报错");
    assert_eq!(code, SessionCode::Ok, "出口绑定成功后必须回 Ok");
}

/// 收尾：两侧引擎停掉、任务 join 住。
async fn teardown(admin: EngineParts, agent: EngineParts) {
    admin.0.shutdown().await.expect("shutdown admin");
    agent.0.shutdown().await.expect("shutdown agent");
    let _ = tokio::time::timeout(Duration::from_secs(5), admin.1).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), agent.1).await;
}

// ------------------------------------------------------------------ 正常往返

#[tokio::test]
async fn udp_associate_relays_a_datagram_round_trip() {
    let echo = udp_echo().await;
    let (admin_parts, agent_parts, mut agent_events) = engines().await;
    let admin = admin_parts.0.clone();
    let agent = agent_parts.0.clone();

    let key = SessionKey::new(NodeId::ADMIN, 71);
    let mut admin_stream = admin_start(&admin, key).await;

    let open = wait_opened(&mut agent_events).await;
    assert_eq!(open.key, key, "OpenSession 的键必须与发起侧一致");
    assert_eq!(open.kind, SessionKind::Socks5Udp);
    assert_eq!(
        open.direction,
        SessionDirection::Inbound,
        "UDP ASSOCIATE 由发起方要求对端提供出口，方向写 Inbound"
    );
    assert!(open.target.is_none(), "UDP 会话没有固定目标");

    let (_outlet_addr, outlet_task) = agent_accept(&agent, key, Duration::from_secs(30)).await;
    await_ok(&admin, key).await;

    // 上行：admin 把「发给回显套接字」的数据报分帧写进会话流。
    let up = Datagram {
        target: Target {
            addr: TargetAddr::Ip(echo.ip()),
            port: echo.port(),
        },
        payload: b"udp-hello".to_vec(),
    };
    frame_datagram(&mut admin_stream, &up.encode())
        .await
        .expect("admin frame upstream");
    admin_stream.flush().await.expect("flush");

    // 下行：回包沿会话流回到 admin，解出来应当是原载荷 + 出口看到的来源地址。
    let wire = tokio::time::timeout(Duration::from_secs(10), read_datagram(&mut admin_stream))
        .await
        .expect("读回超时：回包没有沿会话回到 admin")
        .expect("读回失败");
    let reply = Datagram::parse(&wire).expect("回包必须是合法的 SOCKS5 数据报");
    assert_eq!(reply.payload, b"udp-hello", "载荷必须原样回到发起方");
    assert_eq!(
        reply.resolved(),
        Some(echo),
        "回包头里的目标必须是出口侧看到的来源地址（RFC 1928 §7）"
    );

    outlet_task.abort();
    teardown(admin_parts, agent_parts).await;
}

/// 同一会话连发多个数据报：分帧必须让每个数据报各归各的，不能粘连或错位。
#[tokio::test]
async fn udp_associate_keeps_datagram_boundaries_for_a_burst() {
    let echo = udp_echo().await;
    let (admin_parts, agent_parts, mut agent_events) = engines().await;
    let admin = admin_parts.0.clone();
    let agent = agent_parts.0.clone();

    let key = SessionKey::new(NodeId::ADMIN, 73);
    let mut admin_stream = admin_start(&admin, key).await;
    let _ = wait_opened(&mut agent_events).await;
    let (_addr, outlet_task) = agent_accept(&agent, key, Duration::from_secs(30)).await;
    await_ok(&admin, key).await;

    let payloads: [&[u8]; 3] = [b"one", b"two-two", b"three-three-three"];
    for payload in payloads {
        let up = Datagram {
            target: Target {
                addr: TargetAddr::Ip(echo.ip()),
                port: echo.port(),
            },
            payload: payload.to_vec(),
        };
        frame_datagram(&mut admin_stream, &up.encode())
            .await
            .expect("frame upstream");
        admin_stream.flush().await.expect("flush");
    }

    for expected in payloads {
        let wire = tokio::time::timeout(Duration::from_secs(10), read_datagram(&mut admin_stream))
            .await
            .expect("读回超时")
            .expect("读回失败");
        let reply = Datagram::parse(&wire).expect("parse reply");
        assert_eq!(
            reply.payload, expected,
            "回包顺序与载荷必须一一对应，不能粘连"
        );
        assert_eq!(reply.resolved(), Some(echo));
    }

    outlet_task.abort();
    teardown(admin_parts, agent_parts).await;
}

// ------------------------------------------------------------------ 会话关闭

/// 会话关闭后，出口侧应当读到 EOF 并**正常收摊**，而不是 panic 或者挂住。
#[tokio::test]
async fn outlet_side_unwinds_when_the_session_closes() {
    let (admin_parts, agent_parts, mut agent_events) = engines().await;
    let admin = admin_parts.0.clone();
    let agent = agent_parts.0.clone();

    let key = SessionKey::new(NodeId::ADMIN, 72);
    let _admin_stream = admin_start(&admin, key).await;
    let _ = wait_opened(&mut agent_events).await;

    // 空闲超时故意取得很长：本用例要证明的是「会话关闭 → EOF 收摊」这条
    // 路径，而不是空闲计时器顺手把循环结束了。
    let (_addr, outlet_task) = agent_accept(&agent, key, Duration::from_secs(600)).await;
    await_ok(&admin, key).await;

    // 会话关闭 → agent 侧 `session_sinks.remove` → 投递端 drop → 会话流读到 EOF。
    admin
        .close_session(key, CloseReason::Normal)
        .await
        .expect("admin close session");

    let joined = tokio::time::timeout(Duration::from_secs(10), outlet_task)
        .await
        .expect("出口侧没有在会话关闭后收摊（挂住了）")
        .expect("出口侧任务 panic 了");
    assert!(joined.is_ok(), "出口侧收摊必须是正常结束，实际 {joined:?}");

    teardown(admin_parts, agent_parts).await;
}
