//! §8.5 场景 10：端口复用回落。
//!
//! v1 的链路是「iptables 把发往 `--report` 端口的 SYN REDIRECT 到 `--listen`
//! 端口 → 监听器按首字节判定是不是本协议 → 不是就 `ProxyStream` 转给
//! `127.0.0.1:<report>`」（`agent/initial/method.go`）。本文件验证的是**最后一
//! 段**：一个已经配了回落目标的监听器，能否「陌生流量原样转走」而「本协议流量
//! 照旧正常握手」——这两件事必须同时成立，否则端口复用要么吃掉别人的服务，要么
//! 自己被陌生流量卡死。
//!
//! 前一段（`iptables` 装/卸规则、失败回滚）由 `tests/reuse_e2e.rs` 覆盖，这里不重复：
//! 段与段之间的接缝正是 `with_fallback`，所以本文件只走 `stowaway_core::bind`
//! 到 `AnyListener::with_fallback` 这条生产路径。
//!
//! 测试文件不受 `no-panic` 门禁约束，可以直接 `unwrap/expect`。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use stowaway_core::reuse::{self, Fallback, ReuseConfig};
use stowaway_core::{accept, bind, dial};
use stowaway_crypto::Secret;
use stowaway_protocol::NodeKind;
use stowaway_transport::{DialTarget, TransportSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 起一个「假后端」：收到什么就回什么，并在回包前加一段前缀。
///
/// 前缀是必要的：客户端要能确认「我连上的是后端，不是监听器自己」，
/// 而回环上两者的回显长得一模一样。
async fn spawn_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("backend bind");
    let addr = listener.local_addr().expect("backend local_addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut conn, _peer)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = conn.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if conn.write_all(b"backend:").await.is_err()
                        || conn.write_all(&buf[..n]).await.is_err()
                        || conn.flush().await.is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    (addr, accepted)
}

fn spec_for(addr: SocketAddr) -> TransportSpec {
    TransportSpec::parse(&format!("raw://{addr}")).expect("raw spec")
}

fn secret() -> Secret {
    Secret::load("port-reuse-shared-secret", 8).expect("secret")
}

/// 陌生流量必须原样落到后端，而随后的本协议连接必须照旧握手成功。
///
/// 顺序是刻意的：先来一条陌生连接，再来一条本协议连接。若监听器把陌生连接的
/// 字节吞掉（v1 的 `io.ReadFull` 就得手动补发），后端那条断言会失败；若监听器
/// 在陌生连接上直接报错退出，第二条连接的握手就永远等不到 `accept`。
#[tokio::test]
async fn scenario_10_foreign_traffic_is_proxied_and_protocol_traffic_handshakes() {
    let (backend, hits) = spawn_backend().await;
    let (listener, kind, local) = bind(&spec_for("127.0.0.1:0".parse().expect("addr")), None)
        .await
        .expect("listen");
    // 回落是在 `accept()` 内部 `spawn` 出去的旁路，所以监听器必须**一直在跑
    // accept**——否则那条陌生连接根本没人接，也就谈不上转走。这与生产里
    // agent 常驻的入站循环是同一形状。
    let listener = listener.with_fallback(Some(backend));
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut listener = listener;
        let mut tx = Some(tx);
        loop {
            match accept(&mut listener, kind, &secret(), NodeKind::Admin, None).await {
                Ok(link) => {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(link);
                    }
                }
                Err(e) => {
                    // 陌生流量在有回落目标时不会走到这里；真走到了说明回落失效。
                    eprintln!("入站失败：{e}");
                    break;
                }
            }
        }
    });

    // ① 陌生流量：SSH 横幅。`sniff::classify` 把它判成 `Foreign`（不是 `Ws`，
    //    因为 `GET ` 才会被认成 HTTP 升级），于是走回落分支。
    let banner: &[u8] = b"SSH-2.0-OpenSSH_9.6\r\n";
    let mut foreign = TcpStream::connect(local).await.expect("foreign connect");
    foreign.write_all(banner).await.expect("foreign write");
    foreign.flush().await.expect("foreign flush");
    let mut got = vec![0u8; banner.len() + 8];
    let n = tokio::time::timeout(Duration::from_secs(5), foreign.read(&mut got))
        .await
        .expect("回落回包超时：陌生流量没有被转给后端")
        .expect("回落读失败");
    assert_eq!(
        &got[..n],
        b"backend:SSH-2.0-OpenSSH_9.6\r\n",
        "字节必须原样到达后端"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 1, "后端必须恰好收到这一条隧道");
    drop(foreign);

    // ② 本协议流量：同一监听器的下一条连接必须照旧完成 3-flight 握手。
    let target = DialTarget::plain(local);
    let client =
        tokio::spawn(
            async move { dial(&spec_for(local), &target, NodeKind::Agent, &secret()).await },
        );
    let server_link = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .expect("协议流量握手超时：监听器可能被陌生连接卡住了")
        .expect("accept 任务已退出");
    let client_link = client.await.expect("dial task").expect("协议拨号");
    assert_eq!(
        client_link.handshake.secrets.transcript_hash,
        server_link.handshake.secrets.transcript_hash,
        "两侧 transcript 必须一致"
    );
    assert_eq!(server_link.handshake.peer_kind, NodeKind::Agent);
    assert_eq!(client_link.handshake.peer_kind, NodeKind::Admin);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "协议流量绝不能落到回落目标（后端收到第二条就说明嗅探判错了）"
    );
}

/// 没配回落目标时，陌生流量必须报错而不是静默挂住或吞掉。
///
/// 这是回落功能的「关」状态：`reuse::decide_fallback` 返回 `Reject` 时
/// `install_port_reuse` 就是不设 fallback，此时调用方必须看到明确错误
/// （`TransportError::ReuseFallback`），而不是一个永远不返回的 `accept`。
#[tokio::test]
async fn scenario_10_without_fallback_foreign_traffic_is_a_loud_error() {
    let (listener, kind, local) = bind(&spec_for("127.0.0.1:0".parse().expect("addr")), None)
        .await
        .expect("listen");
    let listener = listener.with_fallback(None);
    assert_eq!(listener.kind(), kind, "with_fallback 不得改变传输种类");
    let mut listener = listener;

    let client = tokio::spawn(async move {
        let mut conn = TcpStream::connect(local).await.expect("connect");
        conn.write_all(b"SSH-2.0-OpenSSH_9.6\r\n")
            .await
            .expect("write");
        conn.flush().await.expect("flush");
        // 连接会立刻被对端关掉；读一次只为让握手失败发生。
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf).await;
    });

    let err = accept(&mut listener, kind, &secret(), NodeKind::Admin, None)
        .await
        .expect_err("没有回落目标时陌生流量必须是错误");
    let text = err.to_string();
    assert!(
        text.contains("回落") || text.contains("认不出") || text.contains("未知"),
        "错误要说明「这条连接不是本协议」而不是泛泛的 IO 失败，实际是：{text}"
    );
    client.await.expect("client task");
}

/// `decide_fallback` 的判定表（§8.5 场景 10 的决策面）。
///
/// 三个分支对应三种运维现实：给了 `--report` 就转走；两边都没给就没有去处；
/// `--report 0` 是「以为给了但其实没有」——必须拒绝而不是悄悄当成 `:0`。
#[test]
fn decide_fallback_covers_the_three_operational_cases() {
    let cfg = ReuseConfig::new("0123456789abcdef", 9000, 8080).expect("cfg");
    assert!(matches!(
        reuse::decide_fallback(&cfg, Some(9001)),
        Fallback::Report(9001)
    ));
    assert!(
        matches!(reuse::decide_fallback(&cfg, None), Fallback::Reject(_)),
        "既没装规则也没给 --report 时必须拒绝"
    );
    assert!(
        matches!(reuse::decide_fallback(&cfg, Some(0)), Fallback::Reject(_)),
        "--report 0 不是可用目标"
    );
}
