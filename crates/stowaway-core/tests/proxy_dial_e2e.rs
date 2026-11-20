//! §5.2 第 5 项 + 修 #12：上游 SOCKS5 代理拨号链。
//!
//! v1 的代理路径（`share/proxy.go`）有两个 bug：HTTP 回包解析里
//! `resultBuf[begin-4:begin]` 在 `begin < 4` 时负索引 panic；HTTP `CONNECT`
//! 从不带 `Proxy-Authorization` —后者已在 `upstream_proxy` 的单测里锁住，
//! 本文件验证 **SOCKS5 这一侧接进真实链路之后仍然成立**：
//!
//! ```text
//! admin（监听） ← 真实 TCP ← [假 SOCKS5 代理] ← agent（经代理解析出的流）
//! ```
//!
//! 判据是两侧 `transcript_hash` 相同——它把传输种类、DH 公钥、nonce、
//! 双方角色全部算进去，任何一步「以为连上了其实连错地方」都会失败。
//!
//! 测试文件不受 `no-panic` 门禁约束，可以直接 `unwrap/expect`。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use stowaway_core::upstream_proxy::ProxySpec;
use stowaway_core::{accept, bind, dial_through_proxy};
use stowaway_crypto::Secret;
use stowaway_protocol::NodeKind;
use stowaway_transport::{DialTarget, TransportSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn spec_for(addr: SocketAddr) -> TransportSpec {
    TransportSpec::parse(&format!("raw://{addr}")).expect("raw spec")
}

fn secret() -> Secret {
    Secret::load("proxy-dial-shared-secret", 8).expect("secret")
}

/// 一个**只做 CONNECT** 的迷你 SOCKS5 代理：把每条请求透给真实目标。
///
/// 记下 `CONNECT` 的目标地址，测试据此断言「代理收到的确实是上行的
/// `host:port`」而不是别的什么东西（例如被 `authority` 的格式化弄坏的地址）。
async fn spawn_socks5_proxy() -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy bind");
    let addr = listener.local_addr().expect("proxy local_addr");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let record = Arc::clone(&record);
            tokio::spawn(async move {
                // ① 方法协商：只接受「无认证」。
                let mut head = [0u8; 2];
                if client.read_exact(&mut head).await.is_err() || head[0] != 5 {
                    return;
                }
                let n = usize::from(head[1]);
                let mut methods = vec![0u8; n];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if client.write_all(&[5, 0]).await.is_err() {
                    return;
                }
                // ② 请求：VER CMD RSV ATYP ...
                let mut fixed = [0u8; 4];
                if client.read_exact(&mut fixed).await.is_err() || fixed[1] != 1 {
                    return;
                }
                let host = match fixed[3] {
                    // IPv4
                    1 => {
                        let mut a = [0u8; 4];
                        if client.read_exact(&mut a).await.is_err() {
                            return;
                        }
                        std::net::Ipv4Addr::from(a).to_string()
                    }
                    // 域名
                    3 => {
                        let mut len = [0u8; 1];
                        if client.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut name = vec![0u8; usize::from(len[0])];
                        if client.read_exact(&mut name).await.is_err() {
                            return;
                        }
                        String::from_utf8(name).expect("域名必须是 UTF-8")
                    }
                    _ => return,
                };
                let mut port = [0u8; 2];
                if client.read_exact(&mut port).await.is_err() {
                    return;
                }
                let port = u16::from_be_bytes(port);
                record
                    .lock()
                    .expect("proxy record")
                    .push(format!("{host}:{port}"));
                // ③ 回「成功 + 绑定地址 0.0.0.0:0」，然后透字节。
                if client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }
                let Ok(mut upstream) = TcpStream::connect(format!("{host}:{port}")).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (addr, seen)
}

/// 经 SOCKS5 代理拨号，两侧必须派生出同一份密钥材料。
///
/// 这条断言的分量在于：`client_handshake` 的 transcript 把**传输种类**、
/// DH 公钥、双方 nonce、双方角色都算进去。代理路径若要自己拼一条「差不多」
/// 的链路（漏掉 TLS、漏掉前导、或者拨错目标），hash 就对不上。
#[tokio::test]
async fn dial_through_a_socks5_proxy_completes_the_real_handshake() {
    let (proxy_addr, seen) = spawn_socks5_proxy().await;
    let (mut listener, kind, local) = bind(&spec_for("127.0.0.1:0".parse().expect("addr")), None)
        .await
        .expect("listen");

    let proxy = ProxySpec::socks5(proxy_addr.to_string(), "", "");
    let target = DialTarget::plain(local);
    let client = tokio::spawn(async move {
        dial_through_proxy(
            &spec_for(local),
            &target,
            &proxy,
            NodeKind::Agent,
            &secret(),
        )
        .await
    });

    let server_link = tokio::time::timeout(
        Duration::from_secs(10),
        accept(&mut listener, kind, &secret(), NodeKind::Admin, None),
    )
    .await
    .expect("经代理的上行握手超时")
    .expect("服务端握手失败");

    let client_link = client.await.expect("dial task").expect("经代理拨号失败");

    assert_eq!(
        client_link.handshake.secrets.transcript_hash,
        server_link.handshake.secrets.transcript_hash,
        "代理路径与直连路径必须得到同一份 transcript"
    );
    assert_eq!(server_link.handshake.peer_kind, NodeKind::Agent);
    assert_eq!(client_link.handshake.peer_kind, NodeKind::Admin);
    assert_eq!(
        client_link.handshake.peer_transport,
        stowaway_protocol::TransportKind::Raw
    );

    // 代理收到的目标必须是上行的地址本身。
    let seen = seen.lock().expect("proxy record").clone();
    assert_eq!(seen, vec![local.to_string()], "代理应被要求连到 {local}");
}

/// 代理拒绝连接时，错误要带着代理的回复码**从拨号层**冒出来。
///
/// 这条和上面那条是一对：上面证明「连得上就用它」，这里证明「连不上不会
/// 静默变成直连」——后者比前者更容易写错，因为直连分支就在旁边。
#[tokio::test]
async fn proxy_rejection_does_not_silently_fall_back_to_direct() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("reject bind");
    let proxy_addr = listener.local_addr().expect("local_addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if client.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; usize::from(head[1])];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if client.write_all(&[5, 0]).await.is_err() {
                    return;
                }
                let mut rest = [0u8; 10];
                let _ = client.read_exact(&mut rest).await;
                // REP = 0x05（连接被拒）
                let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            });
        }
    });

    let proxy = ProxySpec::socks5(proxy_addr.to_string(), "", "");
    let target = DialTarget::plain("127.0.0.1:9".parse().expect("addr"));
    let err = dial_through_proxy(
        &spec_for("127.0.0.1:9".parse().expect("addr")),
        &target,
        &proxy,
        NodeKind::Agent,
        &secret(),
    )
    .await
    .expect_err("代理拒绝时拨号必须失败");
    let text = err.to_string();
    assert!(
        text.contains("代理"),
        "错误要说明是代理拒绝的，实际是：{text}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "只能向代理拨一次，绝不能自己直连目标"
    );
}

/// 非 `raw` 传输必须直接拒绝，而不是「先连上代理再发现不对」。
///
/// `ws` 的 `Host`/路径与 `kcp` 的 UDP 语义都与「代理一条 TCP」不兼容；
/// 而且握手 transcript 会把传输种类算进去，硬塞只会得到难解释的校验失败。
#[tokio::test]
async fn proxy_dial_rejects_non_raw_transports_before_connecting() {
    let proxy = ProxySpec::socks5("127.0.0.1:1", "", "");
    let target = DialTarget::plain("127.0.0.1:2".parse().expect("addr"));
    for spec in ["ws://127.0.0.1:2/deadbeef", "kcp://127.0.0.1:2"] {
        let spec = TransportSpec::parse(spec).expect("spec");
        let err = dial_through_proxy(&spec, &target, &proxy, NodeKind::Agent, &secret())
            .await
            .expect_err("{spec} 不该被代理接受");
        let text = err.to_string();
        assert!(text.contains("raw"), "错误要指出只支持 raw，实际是：{text}");
    }
}

/// 断言代理路径**没有**把上行地址拼错（`domain` 存在时用 `domain:port`）。
///
/// 这条只跑拨号前的格式化，不真连：用 `/1` 端口让拨号必然失败，但失败
/// 文案里会带上代理地址，从而间接证明控制流确实进了代理分支。
#[tokio::test]
async fn proxy_dial_uses_domain_authority_when_present() {
    let (proxy_addr, seen) = spawn_socks5_proxy().await;
    let proxy = ProxySpec::socks5(proxy_addr.to_string(), "", "");
    let mut target = DialTarget::plain("127.0.0.1:1".parse().expect("addr"));
    target.domain = Some("example.test".to_owned());
    let spec = spec_for("127.0.0.1:1".parse().expect("addr"));
    let _ = dial_through_proxy(&spec, &target, &proxy, NodeKind::Agent, &secret()).await;
    // 代理一定会被拨到（否则这条断言就没有意义了）。
    let seen = seen.lock().expect("proxy record").clone();
    assert_eq!(
        seen,
        vec!["example.test:1".to_owned()],
        "有 domain 时必须用域名作为代理的目标，否则虚拟主机路由不到"
    );
}
