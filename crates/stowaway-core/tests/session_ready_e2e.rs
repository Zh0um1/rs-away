//! 回归：`ServiceRequest` 驱动的应答方也要把会话推进到 `Open`。
//!
//! 这条链上曾经有两个连在一起的缺陷（plan §4.14 E18）：
//!
//! 1. 应答方「先回 `SessionReady`、再绑会话流」——发起方一收到 Ready 就
//!    开写，而应答方还没有接收者，第一块数据落在空处；
//! 2. 应答方的会话表**根本没人登记**：`OpenSession` 会自动登记，但
//!    `ServiceRequest` 不会。于是即便调换顺序，`Node::ready_session`
//!    推进状态时也会报 `UnknownSession`，`accept_data` 还会把对端发来的
//!    第一块数据判成「尚未就绪就收到数据」。
//!
//! 这里用两个真引擎（各自持 `Node`、各自跑链路 actor）走一遍
//! 「admin 发 `ServiceRequest{Connect, Run}` → agent 拨号并绑流 → 回
//! Ready → admin 写 → agent 转发 → admin 读回」，证明两侧状态与数据都通。

use std::sync::Arc;

use stowaway_core::link_actor::InboundFrame;
use stowaway_core::{Engine, EngineHandle, Event, NodeConfig, ServiceConfig, Services};
use stowaway_crypto::Secret;
use stowaway_protocol::{
    ConnectParam, Message, NodeId, NodeKind, ServiceKind, ServiceParam, ServicePhase,
    ServiceRequest, SessionKey, SessionKind, TransportKind,
};
use stowaway_transport::{Link, LinkCodec, LinkMeta, boxed};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

// ------------------------------------------------------------------ 测试工具

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
    Arc::new(Secret::load("session-ready-shared-secret", 8).expect("secret"))
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

fn spawn_engine(
    me: NodeId,
    kind: NodeKind,
) -> (EngineParts, tokio::sync::mpsc::UnboundedReceiver<Event>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let (handle, engine, _inbound): (
        EngineHandle,
        Engine,
        tokio::sync::mpsc::Sender<InboundFrame>,
    ) = Engine::new(NodeConfig::new(me, kind), tx);
    let task = tokio::spawn(engine.run());
    ((handle, task), rx)
}

/// 一个把收到的字节原样回送的回显服务。
async fn echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind echo");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

// ------------------------------------------------------ 回归：应答方被 ServiceRequest 驱动

#[tokio::test]
async fn service_request_peer_opens_its_own_session_before_replying_ready() {
    let echo = echo_server().await;
    let (admin_codec, agent_codec) = handshake_pair(64 * 1024).await;

    let ((admin, admin_task), _admin_events) = spawn_engine(NodeId::ADMIN, NodeKind::Admin);
    let ((agent, agent_task), mut agent_events) = spawn_engine(id(1), NodeKind::Agent);

    admin
        .attach_link(admin_codec, id(1), NodeId::ADMIN, NodeKind::Agent)
        .await
        .expect("admin attach agent");
    agent
        .attach_link(agent_codec, NodeId::ADMIN, NodeId::ADMIN, NodeKind::Admin)
        .await
        .expect("agent attach admin");

    // agent 侧：像 `stowaway-agent` 的主循环那样把请求交给服务层。
    let agent_handle = agent.clone();
    let services_task = tokio::spawn(async move {
        let mut tasks = Vec::new();
        while let Some(event) = agent_events.recv().await {
            if let Event::ServiceRequest { req, from } = event {
                let services =
                    Services::new(ServiceConfig::default(), agent_handle.clone()).with_target(None);
                if let Ok(Some(task)) = services.handle(req, from).await {
                    tasks.push(task);
                }
                break;
            }
        }
        tasks
    });

    // admin 侧：先登记、再绑流、再发请求（发起方的既有顺序）。
    let key = SessionKey::new(NodeId::ADMIN, 1);
    admin
        .register_session(key, SessionKind::Socks5)
        .await
        .expect("register");
    let mut stream = admin
        .open_stream(key, id(1), SessionKind::Socks5)
        .await
        .expect("open stream");

    let request = ServiceRequest {
        key,
        kind: ServiceKind::Connect,
        phase: ServicePhase::Run,
        param: ServiceParam::Connect(ConnectParam {
            addr: echo.to_string(),
        }),
    };
    admin
        .send(Message::ServiceRequest(request), id(1))
        .await
        .expect("send service request");

    // 应答方要么把会话状态推到 Open 并回 Ready，要么这里就超时。
    let code = tokio::time::timeout(std::time::Duration::from_secs(10), admin.await_ready(key))
        .await
        .expect("await_ready 超时：应答方没有回 SessionReady")
        .expect("await_ready 报错");
    assert_eq!(
        code,
        stowaway_protocol::SessionCode::Ok,
        "应答方成功拨号后必须回 Ok"
    );

    // 收到 Ready 之后立刻写：这一块数据必须落到应答方已绑好的接收者上。
    let payload = b"ready-before-write";
    stream.write_all(payload).await.expect("write");
    stream.flush().await.expect("flush");

    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_exact(&mut back),
    )
    .await
    .expect("读回超时：应答方没有把数据转发出去")
    .expect("读回失败");
    assert_eq!(back, payload, "回显必须原样回到发起方");

    admin.shutdown().await.expect("shutdown admin");
    agent.shutdown().await.expect("shutdown agent");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), admin_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), agent_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), services_task).await;
}

/// 应答方失败时必须回具体错误码，而不是让发起方等到超时。
#[tokio::test]
async fn rejected_service_request_reports_a_code_not_a_hang() {
    let (admin_codec, agent_codec) = handshake_pair(64 * 1024).await;

    let ((admin, admin_task), _admin_events) = spawn_engine(NodeId::ADMIN, NodeKind::Admin);
    let ((agent, agent_task), mut agent_events) = spawn_engine(id(1), NodeKind::Agent);

    admin
        .attach_link(admin_codec, id(1), NodeId::ADMIN, NodeKind::Agent)
        .await
        .expect("admin attach agent");
    agent
        .attach_link(agent_codec, NodeId::ADMIN, NodeId::ADMIN, NodeKind::Admin)
        .await
        .expect("agent attach admin");

    let agent_handle = agent.clone();
    let services_task = tokio::spawn(async move {
        while let Some(event) = agent_events.recv().await {
            if let Event::ServiceRequest { req, from } = event {
                let services =
                    Services::new(ServiceConfig::default(), agent_handle.clone()).with_target(None);
                let _ = services.handle(req, from).await;
                break;
            }
        }
    });

    // 一个必然连不上的端口（1 号端口通常无人监听，且不应被误连）。
    let key = SessionKey::new(NodeId::ADMIN, 2);
    admin
        .register_session(key, SessionKind::Socks5)
        .await
        .expect("register");
    admin
        .send(
            Message::ServiceRequest(ServiceRequest {
                key,
                kind: ServiceKind::Connect,
                phase: ServicePhase::Run,
                param: ServiceParam::Connect(ConnectParam {
                    addr: "127.0.0.1:1".to_owned(),
                }),
            }),
            id(1),
        )
        .await
        .expect("send");

    let code = tokio::time::timeout(std::time::Duration::from_secs(10), admin.await_ready(key))
        .await
        .expect("await_ready 超时：失败也必须回码")
        .expect("await_ready 报错");
    assert_ne!(
        code,
        stowaway_protocol::SessionCode::Ok,
        "连不上就不能报 Ok"
    );

    admin.shutdown().await.expect("shutdown admin");
    agent.shutdown().await.expect("shutdown agent");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), admin_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), agent_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), services_task).await;
}
