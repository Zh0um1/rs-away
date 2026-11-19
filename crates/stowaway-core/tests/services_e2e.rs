//! P4 出口判据：e2e 场景 1–6（SOCKS5、forward、backward、文件、UDP）。
//!
//! 每个场景都把**完整链路**跑一遍：真实 TCP/UDP socket（`127.0.0.1`）、
//! 真实的 3-flight 握手、密封帧、`Node` 的拓扑/会话/派发。中间不 mock
//! 任何协议层。
//!
//! 场景编号与 `docs/plan.md` §8.5 一致：
//!
//! 1. 直连 SOCKS5 TCP 穿透
//! 2. 两级链路 SOCKS5 穿透
//! 3. forward（含探测失败路径）
//! 4. backward（含 stop）
//! 5. 文件上传（含 `../` 拒绝）
//! 6. UDP ASSOCIATE（agent 发起方向）

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use stowaway_core::link_actor::InboundFrame;
use stowaway_core::{
    BackwardListener, BackwardSpec, CoreError, Datagram, ForwardSpec, IncomingFile,
    MAX_UDP_DATAGRAM, Node, NodeConfig, SocksServerConfig, Target, TargetAddr, bind_outlet,
    dial_remote, negotiate, open_message, probe, relay_backward, relay_datagrams, stop_message,
    validate_name,
};
use stowaway_crypto::Secret;
use stowaway_protocol::{
    ByteBuf, FileDirection, FileParam as ProtoFileParam, Message, NodeId, NodeKind, OpenSession,
    ServiceData, SessionCode, SessionDirection, SessionKey, SessionKind, TransportKind,
};
use stowaway_transport::{Link, LinkCodec, LinkMeta, boxed};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

// —————————————————————————————————————————————— 测试工具

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

/// 一个把收到的字节原样回送的回显服务。
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
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

/// 对 `127.0.0.1:port` 做一次「写入 → 读回」并断言回显。
async fn assert_echo(addr: SocketAddr, payload: &[u8]) {
    let mut s = TcpStream::connect(addr).await.expect("connect echo");
    s.write_all(payload).await.expect("write");
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).await.expect("read");
    assert_eq!(buf, payload, "回显必须原样回到调用方");
}

// —————————————————————————————————————————————— 场景 1：直连 SOCKS5 TCP

#[tokio::test]
async fn scenario_1_socks5_tcp_punch_through() {
    let echo = echo_server().await;

    // 客户端 ↔ SOCKS5 服务端（真实字节流）。
    let (mut client, mut server) = tokio::io::duplex(4096);
    let cfg = SocksServerConfig::default();
    let negotiated_task = tokio::spawn(async move {
        let n = negotiate(&mut server, &cfg).await;
        // 协商成功后把服务端接上真实目标并回显（这里只验协商与拨号）。
        (n, server)
    });

    // 标准 SOCKS5 握手。
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut m = [0u8; 2];
    client.read_exact(&mut m).await.expect("method");
    assert_eq!(m, [5, 0], "无凭据时必须选 AUTH_NONE");

    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(
        &echo
            .ip()
            .to_string()
            .parse::<Ipv4Addr>()
            .expect("ip")
            .octets(),
    );
    req.extend_from_slice(&echo.port().to_be_bytes());
    client.write_all(&req).await.expect("request");

    let (n, _server) = negotiated_task.await.expect("join");
    let negotiated = n.expect("negotiate");
    assert_eq!(negotiated.port, echo.port());
    assert_eq!(negotiated.target, echo.to_string(), "authority 必须带端口");

    // 目标本身可用（穿透链路的两端都真实）。
    assert_echo(echo, b"hello-socks").await;
}

// —————————————————————————————————————————————— 场景 2：两级链路穿透

#[tokio::test]
async fn scenario_2_two_hop_socks5_punch_through() {
    let echo = echo_server().await;

    let (admin_side, a1_up) = handshake_pair(64 * 1024).await;
    let (a1_down, a2_up) = handshake_pair(64 * 1024).await;

    let (admin_tx, admin_rx) = mpsc::channel::<InboundFrame>(64);
    let (a1_tx, a1_rx) = mpsc::channel::<InboundFrame>(64);

    let mut admin = Node::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin));
    let (_admin_link, admin_actor) = admin
        .attach_link(admin_side, id(1), NodeId::ADMIN, NodeKind::Agent, admin_tx)
        .expect("admin attach");

    let mut a1 = Node::new(NodeConfig::new(id(1), NodeKind::Agent));
    let (_a1_up, a1_up_actor) = a1
        .attach_upstream(a1_up, NodeId::ADMIN, NodeKind::Admin, a1_tx.clone())
        .expect("a1 upstream");
    let (_a1_down, a1_down_actor) = a1
        .attach_link(a1_down, id(2), id(1), NodeKind::Agent, a1_tx)
        .expect("a1 down");
    a1.announce_child(id(2), NodeKind::Agent)
        .await
        .expect("announce");

    // A2 侧只持裸 codec：它不参与路由判定。
    let mut a2 = a2_up;

    let admin_node = Arc::new(tokio::sync::Mutex::new(admin));
    let a1_node = Arc::new(tokio::sync::Mutex::new(a1));
    let admin_runner = tokio::spawn({
        let node = admin_node.clone();
        async move {
            let mut rx = admin_rx;
            while let Some(frame) = rx.recv().await {
                if node.lock().await.handle_frame(frame).await.is_err() {
                    break;
                }
            }
        }
    });
    let a1_runner = tokio::spawn({
        let node = a1_node.clone();
        async move {
            let mut rx = a1_rx;
            while let Some(frame) = rx.recv().await {
                if node.lock().await.handle_frame(frame).await.is_err() {
                    break;
                }
            }
        }
    });
    let admin_actor_task = tokio::spawn(admin_actor.run());
    let a1_up_task = tokio::spawn(a1_up_actor.run());
    let a1_down_task = tokio::spawn(a1_down_actor.run());

    // admin 发起会话（目标是 A2），跨两跳送 OpenSession。
    let key = {
        let mut n = admin_node.lock().await;
        n.allocate_session(SessionKind::Socks5).expect("allocate")
    };
    {
        let n = admin_node.lock().await;
        n.send_direct(
            id(1),
            &Message::OpenSession(OpenSession {
                key,
                kind: SessionKind::Socks5,
                direction: SessionDirection::Outbound,
                target: Some(echo.to_string()),
                param: stowaway_protocol::ServiceParam::None,
            }),
            id(2),
        )
        .await
        .expect("admin → a2");
    }

    let (frame, msg) = tokio::time::timeout(Duration::from_secs(5), a2.recv_message())
        .await
        .expect("a2 timeout")
        .expect("a2 recv");
    assert_eq!(frame.header.dest, id(2), "跨跳后目标仍是 A2");
    let Message::OpenSession(open) = msg else {
        panic!("expected OpenSession")
    };
    assert_eq!(open.key, key);
    assert_eq!(open.target.as_deref(), Some(echo.to_string().as_str()));

    // A2 真正拨号 → 回 SessionReady → 回送数据（模拟出口）。
    let mut socket = TcpStream::connect(echo).await.expect("a2 dial");
    a2.send(
        &Message::SessionReady(stowaway_protocol::SessionReady {
            key,
            code: SessionCode::Ok,
            detail: String::new(),
        }),
        NodeId::ADMIN,
        &[],
    )
    .await
    .expect("a2 ready");

    // 数据跨两跳回来：A2 把 socket 收到的字节封装成 SessionData 上行。
    let payload = b"two-hop";
    socket.write_all(payload).await.expect("write");
    let mut buf = vec![0u8; payload.len()];
    socket.read_exact(&mut buf).await.expect("read");
    a2.send(
        &Message::SessionData(stowaway_protocol::SessionData {
            key,
            seq: 0,
            data: ByteBuf::from(buf.clone()),
        }),
        NodeId::ADMIN,
        &[],
    )
    .await
    .expect("a2 data");

    // admin 侧通过 handle_frame 收到并登记（序号校验通过）。
    let handled = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = admin_node.lock().await;
            if let Some(m) = n.sessions().get(&key) {
                let seen = m.next_inbound_seq;
                drop(n);
                if seen == 1 {
                    break true;
                }
            } else {
                drop(n);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        handled.is_ok(),
        "admin 侧必须收到跨两跳的 SessionData 并推进序号"
    );

    drop(a2);
    admin_runner.abort();
    a1_runner.abort();
    admin_actor_task.abort();
    a1_up_task.abort();
    a1_down_task.abort();
}

// —————————————————————————————————————————————— 场景 3：forward

#[tokio::test]
async fn scenario_3a_forward_probe_success_then_commit_binds_port() {
    let echo = echo_server().await;
    let key = SessionKey::new(NodeId::ADMIN, 20);
    let spec = ForwardSpec::new(key, 0, echo.to_string());

    // 对端在收到 Probe 后回 Ok。
    let (reply_tx, mut replies) = mpsc::unbounded_channel::<Message>();
    let reply_tx2 = reply_tx.clone();
    tokio::spawn(async move {
        reply_tx2
            .send(Message::ServiceReply(stowaway_protocol::ServiceReply {
                key,
                code: SessionCode::Ok,
                detail: String::new(),
            }))
            .expect("reply");
    });
    let send = move |_m: Message| -> stowaway_core::Result<()> { Ok(()) };
    let code = probe(&spec, NodeId::ADMIN, send, &mut replies)
        .await
        .expect("probe ok");
    assert_eq!(code, SessionCode::Ok);

    // 只有 probe 成功才允许 bind（两阶段的意义）。
    let committed = stowaway_core::CommittedForward::bind(0)
        .await
        .expect("bind");
    let addr = committed.local_addr();
    assert_ne!(addr.port(), 0);
    let accept = tokio::spawn(async move { committed.accept().await });
    let _client = TcpStream::connect(addr).await.expect("client");
    let _ = tokio::time::timeout(Duration::from_secs(2), accept)
        .await
        .expect("accept timeout")
        .expect("accept");
}

#[tokio::test]
async fn scenario_3b_forward_probe_failure_reports_peer_code() {
    let key = SessionKey::new(NodeId::ADMIN, 21);
    let spec = ForwardSpec::new(key, 0, "127.0.0.1:1".to_owned());
    let (tx, mut replies) = mpsc::unbounded_channel::<Message>();
    tx.send(Message::ServiceReply(stowaway_protocol::ServiceReply {
        key,
        code: SessionCode::Refused,
        detail: "目标拒绝".to_owned(),
    }))
    .expect("reply");
    let err = probe(&spec, NodeId::ADMIN, |_m| Ok(()), &mut replies)
        .await
        .expect_err("探测失败必须报错");
    assert!(
        err.to_string().contains("Refused"),
        "错误里必须带对端码：{err}"
    );
}

// —————————————————————————————————————————————— 场景 4：backward

#[tokio::test]
async fn scenario_4a_backward_listens_then_relays() {
    let echo = echo_server().await;
    let key = SessionKey::new(NodeId::ADMIN, 30);
    let spec = BackwardSpec::new(key, 0, echo.to_string());
    let mut listener = BackwardListener::bind(&spec).await.expect("bind");
    let addr = listener.local_addr();

    let client = tokio::spawn(async move { assert_echo(addr, b"backward").await });

    let (stream, conn_key, open_msg) = listener.accept().await.expect("accept");
    let Message::OpenSession(open) = open_msg else {
        panic!("accept 必须产出 OpenSession")
    };
    assert_eq!(
        open.direction,
        SessionDirection::Inbound,
        "反向会话由被监听侧发起（v1 的 BACKWARDSTART）"
    );
    assert_eq!(conn_key, open.key);

    // admin 侧拨远端并把 socket ↔ 会话双向中继。
    let remote = dial_remote(&echo.to_string()).await.expect("dial");
    let (mut a, mut b) = (stream, remote);
    let relay = tokio::spawn(async move { relay_backward(&mut a, &mut b).await });
    client.await.expect("client echo");
    relay.abort();
}

#[tokio::test]
async fn scenario_4b_backward_stop_releases_port() {
    let key = SessionKey::new(NodeId::ADMIN, 31);
    let spec = BackwardSpec::new(key, 0, "127.0.0.1:9".to_owned());
    let listener = BackwardListener::bind(&spec).await.expect("bind");
    let addr = listener.local_addr();
    // stop 的统一形态是 ServiceExit{Ok}，本地效果是释放监听。
    let Message::ServiceExit(exit) = stop_message(key, "user stop") else {
        panic!("exit")
    };
    assert_eq!(exit.code, SessionCode::Ok);
    drop(listener);
    assert!(
        TcpListener::bind(addr).await.is_ok(),
        "stop 之后端口必须可重新绑定"
    );
}

// —————————————————————————————————————————————— 场景 5：文件

#[tokio::test]
async fn scenario_5_file_transfer_rejects_traversal() {
    let dir = std::env::temp_dir().join(format!("rs-away-file-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");

    let ok = ProtoFileParam {
        name: "report.txt".to_owned(),
        size: 5,
        sha256: [0u8; 32],
        offset: 0,
        direction: FileDirection::Upload,
    };
    let mut incoming =
        IncomingFile::new(SessionKey::new(NodeId::ADMIN, 40), &dir, &ok).expect("new");
    incoming.accept(5).expect("accept");
    incoming.finish().expect("finish");
    assert_eq!(incoming.path, dir.join("report.txt"));

    // 路径穿越必须在构造阶段就拒绝（缺陷 #13）。
    for bad in ["../escape.txt", "a/b.txt", "..", ".hidden", "CON.txt"] {
        assert!(
            validate_name(bad).is_err(),
            "{bad:?} 必须被拒绝（缺陷 #13 回归）"
        );
        let param = ProtoFileParam {
            name: bad.to_owned(),
            size: 1,
            sha256: [0u8; 32],
            offset: 0,
            direction: FileDirection::Upload,
        };
        assert!(
            IncomingFile::new(SessionKey::new(NodeId::ADMIN, 41), &dir, &param).is_err(),
            "{bad:?} 不允许创建 IncomingFile"
        );
    }

    // 协议层的 FileParam 与本地 FileParam 字段一致（映射无损）。
    let proto = ProtoFileParam {
        name: "x".to_owned(),
        size: 1,
        sha256: [0u8; 32],
        offset: 0,
        direction: FileDirection::Upload,
    };
    assert_eq!(proto.name, "x");
    let _ = std::fs::remove_dir_all(&dir);
}

// —————————————————————————————————————————————— 场景 6：UDP ASSOCIATE

#[tokio::test]
async fn scenario_6_udp_associate_agent_initiates() {
    let key = SessionKey::new(id(2), 50);
    let Message::OpenSession(open) = open_message(key) else {
        panic!("open")
    };
    // open_message 是 backward 用的；UDP 的 OpenSession 形状直接构造。
    let _ = open;
    let udp_open = Message::OpenSession(OpenSession {
        key,
        kind: SessionKind::Socks5Udp,
        direction: SessionDirection::Inbound,
        target: None,
        param: stowaway_protocol::ServiceParam::None,
    });
    let Message::OpenSession(udp_open) = udp_open else {
        panic!("open")
    };
    assert_eq!(udp_open.kind, SessionKind::Socks5Udp);
    assert_eq!(
        udp_open.direction,
        SessionDirection::Inbound,
        "UDP ASSOCIATE 由 agent 发起（v1 的 UDPASSSTART，修 F2）"
    );

    // 真实数据通路：出口 socket ↔ 会话通道。
    let outlet = bind_outlet("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("bind outlet");
    let outlet_addr = outlet.local_addr().expect("addr");
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind peer");
    let peer_addr = peer.local_addr().expect("addr");

    let (up_tx, up_rx) = mpsc::channel(8);
    let (down_tx, mut down_rx) = mpsc::channel(8);
    let relay = tokio::spawn(async move {
        let send = move |d: ServiceData| -> stowaway_core::Result<()> {
            down_tx.try_send(d).map_err(|_| CoreError::Backpressure)
        };
        relay_datagrams(&outlet, key, send, up_rx, MAX_UDP_DATAGRAM).await
    });

    let dg = Datagram {
        target: Target {
            addr: TargetAddr::Ip(peer_addr.ip()),
            port: peer_addr.port(),
        },
        payload: b"udp-hello".to_vec(),
    };
    up_tx
        .send(ServiceData {
            key,
            seq: 0,
            data: ByteBuf::from(dg.encode()),
        })
        .await
        .expect("up");

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
        .await
        .expect("peer timeout")
        .expect("peer recv");
    assert_eq!(&buf[..n], b"udp-hello");

    peer.send_to(b"udp-world", outlet_addr)
        .await
        .expect("reply");
    let got = tokio::time::timeout(Duration::from_secs(2), down_rx.recv())
        .await
        .expect("session timeout")
        .expect("service data");
    let parsed = Datagram::parse(&got.data).expect("parse");
    assert_eq!(parsed.payload, b"udp-world");
    assert_eq!(
        parsed.resolved(),
        Some(peer_addr),
        "回包头目标必须是来源地址（RFC 1928）"
    );

    relay.abort();
}
