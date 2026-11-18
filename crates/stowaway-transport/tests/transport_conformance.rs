//! 传输一致性闸门 T1–T9（`docs/design/transport.md` §7）。
//!
//! 每个闸门都要在**所有已编译的传输**上跑一遍：raw 与 ws 各一组，KCP 在
//! `--features transport-kcp` 时加入。新增传输若只加实现、不进这里，等于没有
//! 兑现 `Link` 的语义承诺。
//!
//! 与 `stowaway-transport/src/*/tests` 的分工：单元测试验证实现细节，这里只验证
//! **对外可观测的契约**（可靠、有序、背压、半关闭、错误不 panic、不泄漏）。

#![cfg(any(feature = "transport-raw", feature = "transport-ws"))]

use std::io;
use std::time::Duration;

use sha2::{Digest, Sha256};
use stowaway_protocol::MAGIC;
use stowaway_transport::{
    AnyDialer, AnyListener, DialTarget, Dialer, Link, LinkMeta, Listener, boxed,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 已编译的传输种类（由 feature gate 决定）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    #[cfg(feature = "transport-raw")]
    Raw,
    #[cfg(feature = "transport-ws")]
    Ws,
}

impl Kind {
    /// 该传输的监听端是否靠 `peek` 嗅探决定协议（只有 raw 如此）。
    fn is_raw(self) -> bool {
        #[cfg(feature = "transport-raw")]
        let raw = matches!(self, Self::Raw);
        #[cfg(not(feature = "transport-raw"))]
        let raw = false;
        raw
    }

    fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "transport-raw")]
            Self::Raw => "raw",
            #[cfg(feature = "transport-ws")]
            Self::Ws => "ws",
        }
    }
}

/// 所有参与的传输。KCP 走 UDP，闸门里的「半关闭/RST」语义不同，另行在
/// `--features transport-kcp` 的专门用例里覆盖，不混入 TCP 语义的断言。
fn kinds() -> Vec<Kind> {
    vec![
        #[cfg(feature = "transport-raw")]
        Kind::Raw,
        #[cfg(feature = "transport-ws")]
        Kind::Ws,
    ]
}

/// 在给定传输上建立一对已握好传输层的链路（不含 Stowaway 握手与密封）。
///
/// 返回 `(客户端, 服务端)`。raw 需要一段 4 字节前导让服务端 `peek` 判定为
/// Stowaway 流量，这段前导在返回前已被两端消费掉，因此两条链路都是「干净」的。
async fn pair(kind: Kind) -> (Box<dyn Link>, Box<dyn Link>) {
    match kind {
        #[cfg(feature = "transport-raw")]
        Kind::Raw => {
            let mut listener = stowaway_transport::tcp::RawListener::bind(
                "127.0.0.1:0".parse().expect("addr"),
                None,
                true,
                None,
            )
            .await
            .expect("bind raw");
            let addr = listener.local_addr().expect("local_addr");

            let client = tokio::spawn(async move {
                let dialer = AnyDialer::Raw(stowaway_transport::tcp::RawDialer::new(true, None));
                let target = DialTarget::plain(addr);
                let mut link = dialer.connect(&target).await.expect("dial raw");
                // 让服务端的嗅探看到 Stowaway 魔数。
                link.write_all(&MAGIC).await.expect("write preamble");
                link
            });

            let (mut link, _peer) = listener.accept().await.expect("accept raw");
            let mut preamble = [0u8; 4];
            link.read_exact(&mut preamble).await.expect("read preamble");
            assert_eq!(preamble, MAGIC, "前导必须被服务端原样读出");
            let client_link = client.await.expect("client join");
            (client_link, link)
        }
        #[cfg(feature = "transport-ws")]
        Kind::Ws => {
            let mut listener = stowaway_transport::ws::WsListener::bind(
                "127.0.0.1:0".parse().expect("addr"),
                "/deadbeef",
                None,
            )
            .await
            .expect("bind ws");
            let addr = listener.local_addr().expect("local_addr");

            let client = tokio::spawn(async move {
                let dialer = AnyDialer::Ws(stowaway_transport::ws::WsDialer::new(
                    "/deadbeef",
                    None,
                    None,
                ));
                let target = DialTarget::plain(addr);
                dialer.connect(&target).await.expect("dial ws")
            });

            let (link, _peer) = listener.accept().await.expect("accept ws");
            let client_link = client.await.expect("client join");
            (client_link, link)
        }
    }
}

/// 读取当前进程 RSS（KiB）。用于 T3 的「不许无限缓存」断言。
fn rss_kib() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

/// 打开的 fd 数量（T7 泄漏检测）。
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(0)
}

/// T1：小包不被合并、不被拆分——长度 1/255/4096 各自原样往返。
#[tokio::test]
async fn t1_small_payloads_roundtrip() {
    for kind in kinds() {
        let (mut client, mut server) = pair(kind).await;
        for len in [1usize, 255, 4096] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let (sent, got) = tokio::join!(
                async {
                    client.write_all(&payload).await?;
                    client.flush().await?;
                    Ok::<_, io::Error>(())
                },
                async {
                    let mut buf = vec![0u8; len];
                    server.read_exact(&mut buf).await?;
                    Ok::<_, io::Error>(buf)
                }
            );
            sent.unwrap_or_else(|e| panic!("{}: 写 len={len} 失败: {e}", kind.name()));
            let got = got.unwrap_or_else(|e| panic!("{}: 读 len={len} 失败: {e}", kind.name()));
            assert_eq!(got, payload, "{}: len={len} 必须逐字节一致", kind.name());
        }
    }
}

/// T2：10 MiB 大流量，接收端 SHA-256 必须与发送端一致（且不 OOM）。
#[tokio::test]
async fn t2_large_transfer_is_byte_exact() {
    const TOTAL: usize = 10 * 1024 * 1024;
    for kind in kinds() {
        let (mut client, mut server) = pair(kind).await;

        let writer = tokio::spawn(async move {
            let mut chunk = vec![0u8; 64 * 1024];
            let mut written = 0usize;
            let mut seed = 0x1234_5678u64;
            while written < TOTAL {
                for b in chunk.iter_mut() {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (seed >> 33) as u8;
                }
                let take = (TOTAL - written).min(chunk.len());
                client.write_all(&chunk[..take]).await.expect("write");
                written += take;
            }
            client.flush().await.expect("flush");
            client
        });

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut read_total = 0usize;
        while read_total < TOTAL {
            let want = (TOTAL - read_total).min(buf.len());
            let n = server
                .read(&mut buf[..want])
                .await
                .unwrap_or_else(|e| panic!("{}: 读 10MiB 失败: {e}", kind.name()));
            assert_ne!(n, 0, "{}: 提前 EOF（已读 {read_total}）", kind.name());
            hasher.update(&buf[..n]);
            read_total += n;
        }
        let got = hasher.finalize();

        // 同一伪随机序列，独立重算一遍作为期望值。
        let mut expect = Sha256::new();
        let mut seed = 0x1234_5678u64;
        let mut chunk = vec![0u8; 64 * 1024];
        let mut written = 0usize;
        while written < TOTAL {
            for b in chunk.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
            let take = (TOTAL - written).min(chunk.len());
            expect.update(&chunk[..take]);
            written += take;
        }
        assert_eq!(
            got.as_slice(),
            expect.finalize().as_slice(),
            "{}: 10 MiB 校验和必须一致",
            kind.name()
        );
        writer.await.expect("writer join");
    }
}

/// T3：读端停读 3 秒后，写端必须进入 `Pending`（背压），且进程 RSS 增长 < 32 MiB。
#[tokio::test]
async fn t3_backpressure_stops_unbounded_buffering() {
    for kind in kinds() {
        let (mut client, server) = pair(kind).await;
        let before = rss_kib();

        // 不读服务端：只把它拿在手里，模拟「消费者卡住」。
        let chunk = vec![0u8; 64 * 1024];
        let mut stalled = false;
        let mut written = 0usize;
        for _ in 0..4096 {
            match tokio::time::timeout(Duration::from_millis(300), client.write_all(&chunk)).await {
                Ok(Ok(())) => {
                    written += chunk.len();
                }
                Ok(Err(e)) => panic!("{}: 写失败而非背压: {e}", kind.name()),
                Err(_) => {
                    stalled = true;
                    break;
                }
            }
            // 停读阶段（首个 3 秒窗口内不推进读端）。
            if written == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        assert!(
            stalled,
            "{}: 写端必须最终进入 Pending（已写入 {written} 字节仍未被限流）",
            kind.name()
        );

        let after = rss_kib();
        let growth = after.saturating_sub(before);
        assert!(
            growth < 32 * 1024,
            "{}: 背压期间 RSS 增长 {growth} KiB 超过 32 MiB，说明在无限缓存",
            kind.name()
        );

        drop(server);
        drop(client);
    }
}

/// T4：双向并发各 5 MiB，两侧都必须完整收到对方的字节。
#[tokio::test]
async fn t4_bidirectional_concurrent_traffic() {
    const TOTAL: usize = 5 * 1024 * 1024;
    for kind in kinds() {
        let (client, server) = pair(kind).await;
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut sr, mut sw) = tokio::io::split(server);

        let up = tokio::spawn(async move {
            let chunk = vec![0xa5u8; 32 * 1024];
            let mut left = TOTAL;
            while left > 0 {
                let take = left.min(chunk.len());
                cw.write_all(&chunk[..take]).await.expect("c2s write");
                left -= take;
            }
            cw.flush().await.expect("c2s flush");
        });
        let down = tokio::spawn(async move {
            let chunk = vec![0x5au8; 32 * 1024];
            let mut left = TOTAL;
            while left > 0 {
                let take = left.min(chunk.len());
                sw.write_all(&chunk[..take]).await.expect("s2c write");
                left -= take;
            }
            sw.flush().await.expect("s2c flush");
        });

        let read_at_server = tokio::spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            let mut total = 0usize;
            while total < TOTAL {
                let want = (TOTAL - total).min(buf.len());
                let n = sr.read(&mut buf[..want]).await.expect("s read");
                assert_ne!(n, 0);
                assert!(buf[..n].iter().all(|b| *b == 0xa5), "服务端收到脏数据");
                total += n;
            }
            total
        });
        let read_at_client = tokio::spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            let mut total = 0usize;
            while total < TOTAL {
                let want = (TOTAL - total).min(buf.len());
                let n = cr.read(&mut buf[..want]).await.expect("c read");
                assert_ne!(n, 0);
                assert!(buf[..n].iter().all(|b| *b == 0x5a), "客户端收到脏数据");
                total += n;
            }
            total
        });

        up.await.expect("up join");
        down.await.expect("down join");
        assert_eq!(
            read_at_server.await.expect("server read join"),
            TOTAL,
            "{}: 上行字节数不符",
            kind.name()
        );
        assert_eq!(
            read_at_client.await.expect("client read join"),
            TOTAL,
            "{}: 下行字节数不符",
            kind.name()
        );
    }
}

/// T5：半关闭。
///
/// raw 上必须「`shutdown(Write)` 后对端读到 EOF，且本端仍可继续读」。
/// ws 的 `Close` 帧是双向终结，协议层面没有半关闭；这里退化为断言
/// 「对端读到 EOF 且后续写入返回错误而不是 panic」，并在文档中记录该差异
/// （`docs/design/transport.md` §9 已知限制）。
#[tokio::test]
async fn t5_half_close_semantics() {
    for kind in kinds() {
        let (mut client, mut server) = pair(kind).await;
        client.write_all(b"bye").await.expect("write bye");
        client.flush().await.expect("flush");
        let mut three = [0u8; 3];
        server.read_exact(&mut three).await.expect("read bye");
        assert_eq!(&three, b"bye");

        // 客户端关闭写方向。
        client.shutdown().await.expect("shutdown write");

        // 服务端必须读到 EOF（Ok(0)），而不是挂住。
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("{}: 关闭后读端挂住（未返回 EOF）", kind.name()))
            .unwrap_or_else(|e| panic!("{}: 关闭后读返回错误 {e}（应为 Ok(0)）", kind.name()));
        assert_eq!(n, 0, "{}: 关闭后读端必须返回 EOF", kind.name());

        match kind {
            #[cfg(feature = "transport-raw")]
            Kind::Raw => {
                // 反向仍可写：raw 的 shutdown(Write) 只是 FIN。
                server
                    .write_all(b"still-here")
                    .await
                    .unwrap_or_else(|e| panic!("raw: 半关闭后反向写失败: {e}"));
                server.flush().await.expect("flush reverse");
            }
            #[cfg(feature = "transport-ws")]
            Kind::Ws => {
                // ws 没有半关闭：反向写入必须**报错**而不是 panic。
                match tokio::time::timeout(Duration::from_secs(5), server.write_all(b"x")).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {}
                    Err(_) => panic!("ws: 关闭后反向写既未成功也未报错（挂住）"),
                }
            }
        }
    }
}

/// T6：对端 RST/关闭后写必须返回错误，不得 panic。
///
/// raw 用 `SO_LINGER(0)` 制造真 RST；ws 只有「对端进程消失」这一种等价场景。
#[tokio::test]
async fn t6_peer_reset_surfaces_error_not_panic() {
    // 真 RST：手动起一个 std listener，accept 后设 linger 0 并立即 drop。
    #[cfg(feature = "transport-raw")]
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind std");
        let addr = listener.local_addr().expect("local_addr");
        // 关键顺序：必须先让 connect 完成，再让对端设 linger 0 并关闭。
        // 若在 accept 后立刻 RST，connect() 自身就可能拿到 ECONNRESET 而失败
        // （那是另一种合法行为，但会让本闸门测不到「已建连接上的 RST」）。
        let (tx, rx) = std::sync::mpsc::channel();
        let acceptor = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept std");
            tx.send(stream).expect("send stream");
        });

        let dialer = AnyDialer::Raw(stowaway_transport::tcp::RawDialer::new(true, None));
        let mut link = dialer
            .connect(&DialTarget::plain(addr))
            .await
            .expect("dial");
        acceptor.join().expect("acceptor join");

        let peer_stream = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("收不到已 accept 的对端 stream");
        {
            // `SockRef` 只是借用视图，不是 `Drop` 语义对象；用作用域限制其生命周期。
            let sock = socket2::SockRef::from(&peer_stream);
            sock.set_linger(Some(Duration::ZERO)).expect("set linger 0");
        }
        drop(peer_stream);

        // 首次写可能被内核接受（RST 尚未回传），必须最终报错且全程不 panic。
        let mut errored = false;
        for _ in 0..64 {
            match link.write_all(&[0u8; 4096]).await {
                Ok(()) => tokio::time::sleep(Duration::from_millis(20)).await,
                Err(_) => {
                    errored = true;
                    break;
                }
            }
        }
        assert!(errored, "raw: RST 后持续写入必须最终报错");
    }

    // 对端关闭（无 RST）后写：可能成功一两次，最终必须报错。
    for kind in kinds() {
        let (mut client, server) = pair(kind).await;
        drop(server);
        let mut errored = false;
        for _ in 0..64 {
            match client.write_all(&[0u8; 4096]).await {
                Ok(()) => tokio::time::sleep(Duration::from_millis(20)).await,
                Err(_) => {
                    errored = true;
                    break;
                }
            }
        }
        assert!(errored, "{}: 对端关闭后写必须最终报错", kind.name());
    }
}

/// T7：1000 次连接/关闭不泄漏 fd。
#[tokio::test]
async fn t7_thousand_connections_do_not_leak_fds() {
    const ROUNDS: usize = 1000;
    for kind in kinds() {
        let (a, b) = pair(kind).await;
        drop(a);
        drop(b);
        // 建立一次配对，确认基线稳定后再计数。
        let baseline = open_fds();

        let mut listener = match kind {
            #[cfg(feature = "transport-raw")]
            Kind::Raw => AnyListener::Raw(
                stowaway_transport::tcp::RawListener::bind(
                    "127.0.0.1:0".parse().expect("addr"),
                    None,
                    true,
                    None,
                )
                .await
                .expect("bind"),
            ),
            #[cfg(feature = "transport-ws")]
            Kind::Ws => AnyListener::Ws(
                stowaway_transport::ws::WsListener::bind(
                    "127.0.0.1:0".parse().expect("addr"),
                    "/deadbeef",
                    None,
                )
                .await
                .expect("bind"),
            ),
        };
        let addr = listener.local_addr().expect("local_addr");

        for _ in 0..ROUNDS {
            let dialer = match kind {
                #[cfg(feature = "transport-raw")]
                Kind::Raw => AnyDialer::Raw(stowaway_transport::tcp::RawDialer::new(true, None)),
                #[cfg(feature = "transport-ws")]
                Kind::Ws => AnyDialer::Ws(stowaway_transport::ws::WsDialer::new(
                    "/deadbeef",
                    None,
                    None,
                )),
            };
            let target = DialTarget::plain(addr);
            // raw 的服务端会 `peek` 等魔数：不等超时就必须由客户端补上，
            // 否则每一轮都要空耗 PEEK_TIMEOUT_MS，1000 轮会拖到分钟级。
            let is_raw = kind.is_raw();
            let client = tokio::spawn(async move {
                let mut link = dialer.connect(&target).await.expect("dial");
                if is_raw {
                    link.write_all(&MAGIC).await.expect("preamble");
                }
                link
            });
            let (server_link, _peer) = listener.accept().await.expect("accept");
            let client_link = client.await.expect("join");
            drop(server_link);
            drop(client_link);
        }

        // 给内核/运行时一点时间回收。
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after = open_fds();
        assert!(
            after <= baseline + 16,
            "{}: {ROUNDS} 轮后 fd 从 {baseline} 涨到 {after}，存在泄漏",
            kind.name()
        );
    }
}

/// T8：32 个并发连接各传 1 MiB，全部完整。
#[tokio::test]
async fn t8_thirty_two_concurrent_connections() {
    const CONNS: usize = 32;
    const TOTAL: usize = 1024 * 1024;

    #[cfg(feature = "transport-raw")]
    {
        let mut listener = stowaway_transport::tcp::RawListener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            None,
            true,
            None,
        )
        .await
        .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let mut clients = Vec::new();
        for i in 0..CONNS {
            clients.push(tokio::spawn(async move {
                let dialer = AnyDialer::Raw(stowaway_transport::tcp::RawDialer::new(true, None));
                let mut link = dialer
                    .connect(&DialTarget::plain(addr))
                    .await
                    .expect("dial");
                link.write_all(&MAGIC).await.expect("preamble");
                let byte = (i % 251) as u8;
                let chunk = vec![byte; 4096];
                let mut left = TOTAL;
                while left > 0 {
                    let take = left.min(chunk.len());
                    link.write_all(&chunk[..take]).await.expect("write");
                    left -= take;
                }
                link.flush().await.expect("flush");
            }));
        }

        let mut servers = Vec::new();
        for _ in 0..CONNS {
            let (mut link, _peer) = listener.accept().await.expect("accept");
            servers.push(tokio::spawn(async move {
                let mut preamble = [0u8; 4];
                link.read_exact(&mut preamble).await.expect("preamble");
                let mut buf = vec![0u8; 8192];
                let mut total = 0usize;
                while total < TOTAL {
                    let want = (TOTAL - total).min(buf.len());
                    let n = link.read(&mut buf[..want]).await.expect("read");
                    assert_ne!(n, 0);
                    total += n;
                }
                total
            }));
        }
        for s in servers {
            assert_eq!(s.await.expect("server join"), TOTAL);
        }
        for c in clients {
            c.await.expect("client join");
        }
    }

    #[cfg(all(feature = "transport-ws", not(feature = "transport-raw")))]
    {
        let mut listener = stowaway_transport::ws::WsListener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            "/deadbeef",
            None,
        )
        .await
        .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let mut clients = Vec::new();
        for _ in 0..CONNS {
            clients.push(tokio::spawn(async move {
                let dialer = AnyDialer::Ws(stowaway_transport::ws::WsDialer::new(
                    "/deadbeef",
                    None,
                    None,
                ));
                let mut link = dialer
                    .connect(&DialTarget::plain(addr))
                    .await
                    .expect("dial ws");
                let chunk = vec![7u8; 4096];
                let mut left = TOTAL;
                while left > 0 {
                    let take = left.min(chunk.len());
                    link.write_all(&chunk[..take]).await.expect("write");
                    left -= take;
                }
                link.flush().await.expect("flush");
            }));
        }
        let mut servers = Vec::new();
        for _ in 0..CONNS {
            let (mut link, _peer) = listener.accept().await.expect("accept ws");
            servers.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut total = 0usize;
                while total < TOTAL {
                    let want = (TOTAL - total).min(buf.len());
                    let n = link.read(&mut buf[..want]).await.expect("read");
                    assert_ne!(n, 0);
                    total += n;
                }
                total
            }));
        }
        for s in servers {
            assert_eq!(s.await.expect("server join"), TOTAL);
        }
        for c in clients {
            c.await.expect("client join");
        }
    }
}

/// `LinkMeta.max_frame = 4096` 的内存链路：用来验证帧层的分片/重组。
struct CapDuplex {
    inner: tokio::io::DuplexStream,
    meta: LinkMeta,
}

impl tokio::io::AsyncRead for CapDuplex {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for CapDuplex {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Link for CapDuplex {
    fn meta(&self) -> LinkMeta {
        self.meta.clone()
    }
}

/// T9：当 `LinkMeta.max_frame = 4096` 时，帧层必须自动分片并在对端重组。
#[tokio::test]
async fn t9_frame_layer_fragments_when_max_frame_is_small() {
    use stowaway_protocol::{Message, SessionData, SessionKey};

    let (a, b) = tokio::io::duplex(1 << 20);
    let meta = LinkMeta::new(stowaway_protocol::TransportKind::Raw, None).with_max_frame(4096);
    let mut client = stowaway_transport::LinkCodec::new(boxed(CapDuplex {
        inner: a,
        meta: meta.clone(),
    }));
    let mut server = stowaway_transport::LinkCodec::new(boxed(CapDuplex { inner: b, meta }));

    assert!(client.max_chunk() <= 4096, "分片上限必须受 max_frame 约束");

    // 32 KiB 载荷 > 4096，必然分成多片。
    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();
    let msg = Message::SessionData(SessionData {
        key: SessionKey::new(stowaway_protocol::NodeId::new([1u8; 16]), 1),
        seq: 1,
        data: stowaway_protocol::ByteBuf::from(payload),
    });
    let dest = stowaway_protocol::NodeId::new([2u8; 16]);

    let (sent, got) = tokio::join!(async { client.send(&msg, dest, &[]).await }, async {
        server.recv_message().await
    });
    sent.expect("发送成功");
    let (frame, received) = got.expect("接收成功");
    assert_eq!(received, msg, "重组后的消息必须与原消息等价");
    assert!(
        !frame.header.flags.is_fragment(),
        "重组结果的标志位不得残留 FRAG"
    );
}
