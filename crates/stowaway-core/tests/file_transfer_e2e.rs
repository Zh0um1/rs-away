//! 两个方向的文件传输各自走一遍完整线上路径。
//!
//! v1 上传走 `FILESTATREQ` + `FILEDOWNRES`、下载走 `FILEDOWNREQ`，两套包头都在
//! `share/file.go` 里，方向靠消息类型区分。v2 把两个方向压进了同一个
//! `ServiceParam::File(FileParam)`，方向随 `FileParam.direction` 一起给
//! （plan §4.14 E25）——所以「同一族消息能否承载两个方向」必须被证明，
//! 不能只靠单元测试里的函数调用。
//!
//! 这里用两个真引擎（各自持 `Node`、各自跑链路 actor）：
//!
//! - 上传：admin 逐块写会话流 → agent 落盘 → 回 `ServiceExit`；
//! - 下载：admin 发请求 → agent 先写 40 字节清单头（`size ‖ sha256`）→ 再写
//!   分片 → admin 按清单校验后落盘。
//!
//! 两条都要覆盖「多块」（正文大于一个 `FILE_CHUNK`），否则分片逻辑只走一遍
//! 就过，等于没测。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use stowaway_core::link_actor::InboundFrame;
use stowaway_core::{Engine, EngineHandle, Event, NodeConfig, ServiceConfig, Services};
use stowaway_crypto::Secret;
use stowaway_protocol::{
    FileDirection, FileParam, Message, NodeId, NodeKind, ServiceKind, ServiceParam, ServicePhase,
    ServiceRequest, SessionCode, SessionKey, SessionKind, TransportKind,
};
use stowaway_transport::{Link, LinkCodec, LinkMeta, boxed};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

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
    Arc::new(Secret::load("file-transfer-shared-secret", 8).expect("secret"))
}

async fn handshake_pair(max_frame: usize) -> (LinkCodec, LinkCodec) {
    let (a, b) = tokio::io::duplex(512 * 1024);
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

/// 一次性的临时目录（测试进程内有效；结束时由调用方清理）。
fn temp_dir(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "stw-file-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&base).expect("mkdir");
    base
}

/// 一段可复算的正文（大于一个 `FILE_CHUNK`，让分片真的分成多块）。
fn payload() -> Vec<u8> {
    let len = stowaway_core::file::FILE_CHUNK * 2 + 997;
    let mut out = Vec::with_capacity(len);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((x >> 16) as u8);
    }
    out
}

fn digest_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// 在 agent 侧起一个只服务「第一次请求」的循环。
///
/// `ServiceExit` 是**发给发起方**的（`Services::spawn` 结束时经引擎路由回去），
/// 所以它出现在 admin 的事件流里，不在 agent 侧——这里只管接请求。
fn services_loop(
    handle: EngineHandle,
    cfg: ServiceConfig,
    mut events: tokio::sync::mpsc::UnboundedReceiver<Event>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tasks = Vec::new();
        while let Some(event) = events.recv().await {
            if let Event::ServiceRequest { req, from } = event {
                let services = Services::new(cfg.clone(), handle.clone()).with_target(None);
                match services.handle(req, from).await {
                    Ok(Some(task)) => tasks.push(task.handle),
                    Ok(None) => {}
                    Err(e) => eprintln!("服务请求处理失败：{e}"),
                }
            }
        }
        for task in tasks {
            task.abort();
        }
    })
}

/// 等某个会话的 `ServiceExit`。
async fn wait_exit(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    key: SessionKey,
    deadline: Duration,
) -> stowaway_protocol::ServiceExit {
    loop {
        let ev = tokio::time::timeout(deadline, rx.recv())
            .await
            .expect("等 ServiceExit 超时：应答方没有回报结果")
            .expect("事件通道关闭");
        if let Event::ServiceExit { exit, .. } = ev
            && exit.key == key
        {
            return exit;
        }
    }
}

// ------------------------------------------------------------------ 上传方向

#[tokio::test]
async fn upload_direction_moves_bytes_and_the_receiver_verifies_the_digest() {
    let dir = temp_dir("up");
    let body = payload();
    let want = digest_of(&body);

    let (admin_side, agent_side) = linked_engines().await;
    let ((admin, admin_task), mut admin_events) = admin_side;
    let ((agent, agent_task), agent_events) = agent_side;

    let cfg = ServiceConfig {
        download_dir: dir.clone(),
        ..ServiceConfig::default()
    };
    let _services_task = services_loop(agent.clone(), cfg, agent_events);

    let key = SessionKey::new(NodeId::ADMIN, 1);
    admin
        .register_session(key, SessionKind::File)
        .await
        .expect("register");
    let mut stream = admin
        .open_stream(key, id(1), SessionKind::File)
        .await
        .expect("open stream");

    let param = FileParam {
        name: "uploaded.bin".to_owned(),
        size: body.len() as u64,
        sha256: want,
        offset: 0,
        direction: FileDirection::Upload,
    };
    admin
        .send(
            Message::ServiceRequest(ServiceRequest {
                key,
                kind: ServiceKind::File,
                phase: ServicePhase::Run,
                param: ServiceParam::File(param),
            }),
            id(1),
        )
        .await
        .expect("send request");

    let code = tokio::time::timeout(Duration::from_secs(10), admin.await_ready(key))
        .await
        .expect("await_ready 超时：应答方没有回 SessionReady")
        .expect("await_ready 报错");
    assert_eq!(code, SessionCode::Ok, "可写目录里应当接受上传");

    // 逐块写（步长比 `FILE_CHUNK` 小，逼 `SessionStream` 自己拼块）。
    for piece in body.chunks(16 * 1024) {
        stream.write_all(piece).await.expect("write");
    }
    stream.shutdown().await.expect("shutdown stream");

    let exit = wait_exit(&mut admin_events, key, Duration::from_secs(30)).await;
    assert_eq!(
        exit.code,
        SessionCode::Ok,
        "校验通过才算成功：{}",
        exit.detail
    );

    let landed = dir.join("uploaded.bin");
    let got = std::fs::read(&landed).expect("落盘文件必须存在");
    assert_eq!(got.len(), body.len(), "长度必须与声明一致");
    assert_eq!(got, body, "内容必须逐字节相同");
    assert_eq!(digest_of(&got), want, "落盘内容的摘要必须等于声明值");

    admin.shutdown().await.expect("shutdown admin");
    agent.shutdown().await.expect("shutdown agent");
    let _ = tokio::time::timeout(Duration::from_secs(5), admin_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), agent_task).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ 下载方向

#[tokio::test]
async fn download_direction_sends_a_manifest_then_the_bytes() {
    let dir = temp_dir("down");
    let body = payload();
    let want = digest_of(&body);
    std::fs::write(dir.join("remote.bin"), &body).expect("seed");

    let (admin_side, agent_side) = linked_engines().await;
    let ((admin, admin_task), _admin_events) = admin_side;
    let ((agent, agent_task), agent_events) = agent_side;

    let cfg = ServiceConfig {
        download_dir: dir.clone(),
        ..ServiceConfig::default()
    };
    let _services_task = services_loop(agent.clone(), cfg, agent_events);

    let key = SessionKey::new(NodeId::ADMIN, 2);
    admin
        .register_session(key, SessionKind::File)
        .await
        .expect("register");
    let mut stream = admin
        .open_stream(key, id(1), SessionKind::File)
        .await
        .expect("open stream");

    let param = FileParam {
        name: "remote.bin".to_owned(),
        // 下载方向的长度与摘要由发送方在清单头里声明，这里刻意填错，
        // 证明接收方**不**相信本地猜测。
        size: 1,
        sha256: [0xffu8; 32],
        offset: 0,
        direction: FileDirection::Download,
    };
    admin
        .send(
            Message::ServiceRequest(ServiceRequest {
                key,
                kind: ServiceKind::File,
                phase: ServicePhase::Run,
                param: ServiceParam::File(param),
            }),
            id(1),
        )
        .await
        .expect("send request");

    let code = tokio::time::timeout(Duration::from_secs(10), admin.await_ready(key))
        .await
        .expect("await_ready 超时")
        .expect("await_ready 报错");
    assert_eq!(code, SessionCode::Ok, "文件存在就应当开始发送");

    // 先读清单头，再按声明长度收正文。
    let mut head = [0u8; stowaway_core::file::MANIFEST_LEN];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut head))
        .await
        .expect("读清单头超时")
        .expect("读清单头失败");
    let (size, want_remote) = stowaway_core::file::parse_manifest(&head);
    assert_eq!(size, body.len() as u64, "清单声明的长度必须是真的");
    assert_eq!(want_remote, want, "清单声明的摘要必须是真的");

    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut got))
        .await
        .expect("读正文超时")
        .expect("读正文失败");
    assert_eq!(got, body, "下载正文必须逐字节相同");

    admin.shutdown().await.expect("shutdown admin");
    agent.shutdown().await.expect("shutdown agent");
    let _ = tokio::time::timeout(Duration::from_secs(5), admin_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), agent_task).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ 互连的两条引擎

/// 建一对已握手的引擎（这是唯一的建链入口：链路两端必须来自同一对 codec）。
async fn linked_engines() -> (
    (EngineParts, tokio::sync::mpsc::UnboundedReceiver<Event>),
    (EngineParts, tokio::sync::mpsc::UnboundedReceiver<Event>),
) {
    let (admin_codec, agent_codec) = handshake_pair(64 * 1024).await;
    let admin = spawn_engine(NodeId::ADMIN, NodeKind::Admin);
    let agent = spawn_engine(id(1), NodeKind::Agent);
    admin
        .0
        .0
        .attach_link(admin_codec, id(1), NodeId::ADMIN, NodeKind::Agent)
        .await
        .expect("admin attach agent");
    agent
        .0
        .0
        .attach_link(agent_codec, NodeId::ADMIN, NodeId::ADMIN, NodeKind::Admin)
        .await
        .expect("agent attach admin");
    (admin, agent)
}
