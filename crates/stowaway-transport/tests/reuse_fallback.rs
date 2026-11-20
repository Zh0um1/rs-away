//! 端口复用回落通道（v1 `agent/initial/method.go` 的 `ProxyStream` / `CopyTraffic`）。
//!
//! 与 `tcp.rs` 的单元测试分工：那里验证 `ReuseFallback` 错误本身，这里验证
//! **配了回落目标之后**的端到端行为——陌生流量真的被原样转走，而本协议/ws
//! 流量绝不会被误转。
//!
//! 注意本文件用 `tokio::spawn` 起后台任务，断言必须留一点时间窗口：
//! 「后端一个连接都没收到」这类断言只能靠「等一小段 + 计数仍为 0」来表达，
//! 因为没有事件可以证明「永远不会发生」。
//!
//! 测试文件不受 `no-panic` 门禁约束，可以直接 `unwrap/expect`。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use stowaway_protocol::{Frame, FrameFlags, MAGIC, MsgType, NodeId};
use stowaway_transport::Listener;
use stowaway_transport::tcp::{FALLBACK_BUF, RawListener, proxy_to_fallback};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 起一个「假后端」：收到什么回什么，可选在**第一段**回包前加一段前缀。
///
/// 返回 `(地址, 已接受的连接数)`。计数用 `AtomicUsize` 而非日志：
/// 「后端有没有被连过」是本文件几个关键断言的核心，必须可观测。
async fn spawn_backend(prefix: Option<&'static [u8]>) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("backend bind");
    let addr = listener.local_addr().expect("backend local_addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);

    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _peer)) = listener.accept().await else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut first = true;
                loop {
                    let n = match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if first {
                        first = false;
                        if let Some(p) = prefix
                            && conn.write_all(p).await.is_err()
                        {
                            break;
                        }
                    }
                    if conn.write_all(&buf[..n]).await.is_err() || conn.flush().await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    (addr, accepted)
}

/// 绑定一个 `RawListener`（可选回落目标），并返回 `(监听地址, listener)`。
async fn bind_listener(fallback: Option<SocketAddr>) -> (SocketAddr, RawListener) {
    let listener = RawListener::bind("127.0.0.1:0".parse().expect("addr"), None, true, None)
        .await
        .expect("bind raw listener")
        .with_fallback(fallback);
    let addr = listener.local_addr().expect("local_addr");
    (addr, listener)
}

/// 回落是旁路：`accept()` 把连接交出去后仍继续等待下一条本协议连接。
///
/// 为了观测「监听器没有被一条陌生连接卡死」，把 `accept()` 放进后台任务，
/// 只在客户端侧断言回落是否真的通。
async fn spawn_accept_loop(mut listener: RawListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // `while let` 而非 `loop`+`match`：本任务唯一的目的就是「一直接、接到出错
        // 为止」，拆成 match 只是把同一个语义写得更长（clippy `while_let_loop`）。
        while let Ok((link, _peer)) = listener.accept().await {
            drop(link);
        }
    })
}

/// 等一小段时间再读计数：回落是 `spawn` 出去的旁路任务，没有同步点可用。
///
/// 300ms 对本地回环足够：后端拨号 + 首字节往返都在微秒级，真要被连早就连上了。
async fn backend_hits_settled(counter: &AtomicUsize) -> usize {
    tokio::time::sleep(Duration::from_millis(300)).await;
    counter.load(Ordering::SeqCst)
}

/// 回落目标可在 `bind` 之后链式设置/读取，且不设置时保持既有语义。
///
/// 这层 API 是 `bind` → `with_fallback` 的接线点，签名变化会直接破坏所有
/// 调用方；因此单独锁住它的形状（`const fn` + `mut self` + 返回 `Self`）。
#[tokio::test]
async fn fallback_target_is_chainable_and_readable() {
    let listener = RawListener::bind("127.0.0.1:0".parse().expect("addr"), None, true, None)
        .await
        .expect("bind");
    assert_eq!(listener.fallback(), None, "bind 默认不得带回落目标");

    let target: SocketAddr = "127.0.0.1:18080".parse().expect("target");
    let listener = listener.with_fallback(Some(target));
    assert_eq!(listener.fallback(), Some(target));

    // `None` 必须能清回去：调用方可能先配了回落、之后又关掉端口复用。
    let listener = listener.with_fallback(None);
    assert_eq!(listener.fallback(), None);
}

/// 陌生流量必须被整条转给回落目标，且**一个字节都不能丢**。
///
/// v1 的 `ProxyStream` 之所以要 `reuseConn.Write(message)`，是因为它先
/// `io.ReadFull` 把字节读走了；v2 用 `MSG_PEEK`，判定所读字节仍在流里，
/// 所以断言的重点是「客户端最初发的那串字节完整地到达了后端」。
///
/// 这里用 SSH 横幅而不是 `GET /`：`sniff::classify` 把 `GET ` 判为
/// `Protocol::Ws`（HTTP 升级），根本不会进回落分支（见最后一个用例）。
#[tokio::test]
async fn foreign_traffic_is_handed_to_the_fallback_target() {
    let (backend_addr, hits) = spawn_backend(Some(b"backend:")).await;
    let (addr, listener) = bind_listener(Some(backend_addr)).await;
    let server = spawn_accept_loop(listener).await;

    let client = tokio::spawn(async move {
        let mut conn = TcpStream::connect(addr).await.expect("client connect");
        conn.write_all(b"SSH-2.0-OpenSSH_9.6\r\n")
            .await
            .expect("client write");

        // 必须读进定长缓冲区：`Vec::new()` 容量为 0，`read` 会直接返回 `Ok(0)`
        // （看起来像 EOF），把「没收到回包」和「连接已关闭」混成同一种现象。
        let mut back = [0u8; 128];
        let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut back))
            .await
            .expect("回落回包必须在 5 秒内到达")
            .expect("client read");
        assert!(n > 0, "回落目标必须把数据回送过来");
        back[..n].to_vec()
    });

    let back = client.await.expect("client join");
    let text = String::from_utf8_lossy(&back).into_owned();
    assert!(
        text.starts_with("backend:"),
        "回包必须来自后端（前缀 `backend:`），实际：{text:?}"
    );
    assert!(
        text.contains("SSH-2.0-OpenSSH_9.6\r\n"),
        "客户端最初的字节必须完整到达后端（peek 不消费 ⇒ 无需补写），实际：{text:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1, "只应有一条连接被转到后端");
    server.abort();
}

/// 不配回落目标时保持既有语义：`accept` 报 `InvalidData`，客户端连接被关闭。
///
/// 服务端侧断言 `Err` 与 kind，客户端侧只断言「读不到任何业务数据」——
/// 关闭可能表现为优雅 FIN（`Ok(0)`）或 RST（`Err`），两者都算「被拒绝」。
#[tokio::test]
async fn without_fallback_foreign_traffic_is_an_error() {
    let (addr, mut listener) = bind_listener(None).await;

    let client = tokio::spawn(async move {
        let mut conn = TcpStream::connect(addr).await.expect("client connect");
        conn.write_all(b"SSH-2.0-OpenSSH_9.6\r\n")
            .await
            .expect("client write");

        let mut back = [0u8; 16];
        match tokio::time::timeout(Duration::from_secs(5), conn.read(&mut back)).await {
            // 对端关闭：要么读到 EOF（0 字节），要么读出错。
            Ok(Ok(n)) => assert_eq!(n, 0, "未配回落时不得回任何数据"),
            Ok(Err(_)) => {}
            Err(_) => panic!("服务端必须关闭连接，而不是挂住"),
        }
    });

    // `(Box<dyn Link>, SocketAddr)` 不是 `Debug`，用 `.err()` 取错误而不 `expect_err`。
    let err = listener.accept().await.err().expect("未配回落必须报错");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "kind 必须是 InvalidData，实际 {err:?}"
    );
    assert!(
        err.to_string().contains("端口复用回落"),
        "错误必须指出这是端口复用回落候选，实际：{err}"
    );
    // `accept` 返回 `Err` 时流已被 drop，客户端必然看到关闭。
    client.await.expect("client join");
}

/// 本协议流量绝不能被回落吞掉：前导被吃掉、帧流原样到达，后端零连接。
#[tokio::test]
async fn fallback_does_not_swallow_protocol_traffic() {
    let (backend_addr, hits) = spawn_backend(Some(b"backend:")).await;
    let (addr, mut listener) = bind_listener(Some(backend_addr)).await;

    let frame_bytes = Frame::new(
        FrameFlags::empty(),
        MsgType::Heartbeat,
        NodeId::ADMIN,
        Vec::new(),
        b"payload".to_vec(),
    )
    .encode();
    let expected = frame_bytes.clone();

    let client = tokio::spawn(async move {
        let mut conn = TcpStream::connect(addr).await.expect("client connect");
        conn.write_all(&MAGIC).await.expect("write preamble");
        conn.write_all(&expected).await.expect("write frame");
        conn.flush().await.expect("flush");
        // 保活到服务端读完，避免对端先看到 EOF 而把「半条流」误判成异常。
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let (mut link, _peer) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("本协议连接不能被回落旁路吞掉")
        .expect("accept 必须返回正常 Link");

    let mut buf = vec![0u8; frame_bytes.len()];
    link.read_exact(&mut buf).await.expect("读回整帧");
    assert_eq!(buf, frame_bytes, "前导必须被消费，帧字节必须原样可见");

    assert_eq!(
        backend_hits_settled(&hits).await,
        0,
        "本协议流量绝不能被转到回落目标"
    );
    client.await.expect("client join");
}

/// ws 流量走 `UnrecognizedPeer`，**不**因配了回落目标而被转走。
///
/// 理由见 `tcp.rs` 的 ws 分支注释：ws 是已知协议、只是走错端口，
/// 秒回一个明确的协议不符，比盲转给后端（再拿一个 400）更利于排障。
#[tokio::test]
async fn ws_traffic_is_not_routed_to_fallback() {
    let (backend_addr, hits) = spawn_backend(Some(b"backend:")).await;
    let (addr, mut listener) = bind_listener(Some(backend_addr)).await;

    let client = tokio::spawn(async move {
        let mut conn = TcpStream::connect(addr).await.expect("client connect");
        conn.write_all(
            b"GET /v2/ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .await
        .expect("write upgrade request");

        let mut back = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(5), conn.read(&mut back)).await {
            Ok(Ok(n)) => {
                let got = String::from_utf8_lossy(&back[..n]).into_owned();
                assert!(
                    !got.starts_with("backend:"),
                    "ws 请求不得被转给回落目标，实际回包：{got:?}"
                );
                assert_eq!(n, 0, "ws 走错端口时应直接断开，不回任何数据");
            }
            Ok(Err(_)) => {}
            Err(_) => panic!("服务端必须关闭 ws 连接，而不是挂住"),
        }
    });

    let err = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("ws 必须立刻报错，不能挂住")
        .err()
        .expect("ws 必须走 UnrecognizedPeer 而不是回落");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "实际 {err:?}");
    let text = err.to_string();
    assert!(
        text.contains("嗅探无法识别") || text.contains("无法识别"),
        "必须是 UnrecognizedPeer 文案（而不是回落文案），实际：{text}"
    );
    assert!(
        !text.contains("端口复用回落"),
        "ws 不得被判为回落候选，实际：{text}"
    );

    assert_eq!(
        backend_hits_settled(&hits).await,
        0,
        "ws 流量绝不能被转到回落目标"
    );
    client.await.expect("client join");
}

/// 直接驱动 `proxy_to_fallback`：拨号超时必须报 `TimedOut` 且文案可读。
///
/// 用一条**不发数据**的本地连接当客户端，回落目标指向一个只丢弃 SYN 的
/// 地址（不可路由），因此会走满 10s 拨号上限；这里用 12s 兜底等待，
/// 断言的重点是「不会无限挂住」+ 超时文案能指认目标与原因。
#[tokio::test]
async fn proxy_to_fallback_times_out_with_timed_out_kind() {
    let client_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("client listener bind");
    let client_addr = client_listener.local_addr().expect("local_addr");

    // 客户端侧保持存活：否则 inbound 会立刻 EOF，语义上就不是「一条真实连接」了。
    let (keepalive_guard, inbound) = tokio::join!(
        async {
            TcpStream::connect(client_addr)
                .await
                .expect("client connect")
        },
        async { client_listener.accept().await.expect("accept inbound").0 }
    );

    let unreachable: SocketAddr = "10.255.255.1:9".parse().expect("addr");
    let res = tokio::time::timeout(
        Duration::from_secs(12),
        proxy_to_fallback(inbound, unreachable),
    )
    .await
    .expect("回落拨号必须在自己的 10s 上限内返回");

    match res {
        // 环境若把不可路由地址改成快速 REJECT，则不会走到超时分支；
        // 两种结果都能证明「不会无限挂住」，但只有超时能验证文案。
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            let text = e.to_string();
            assert!(
                text.contains("端口复用回落") && text.contains("超时"),
                "超时文案必须可读，实际：{text}"
            );
        }
        Err(e) => assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::NetworkUnreachable
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::HostUnreachable
                    | std::io::ErrorKind::PermissionDenied
            ),
            "只允许「不可达」类错误，实际 {e:?}"
        ),
        Ok(_) => panic!("不可路由目标不得连接成功"),
    }
    drop(keepalive_guard);
}

/// `FALLBACK_BUF` 与 v1 `CopyTraffic` 的 `make([]byte, 10240)` 保持同值。
///
/// 这是个「常量必须等于文档承诺」的断言：改成别的值会让回落连接的
/// 常驻内存与 v1 基线不可比（§8.4 行为对照）。
#[test]
fn fallback_buffer_matches_v1_copy_traffic() {
    assert_eq!(FALLBACK_BUF, 10240, "必须与 v1 CopyTraffic 的 10240 一致");
}
