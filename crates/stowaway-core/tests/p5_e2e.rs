//! P5 出口判据：e2e 场景 7–9（PTY Shell、SSH、connect 桥接）。
//!
//! 场景编号与 `docs/plan.md` §8.5 一致：
//!
//! 7. shell 交互 + PTY resize
//! 8. SSH 命令执行 + 隧道（真 sshd，可配 known_hosts）
//! 9. `connect` 跨 admin 桥接
//!
//! 与 `services_e2e.rs` 同样的纪律：中间不 mock 协议层。场景 7 跑真 PTY
//! （`/dev/ptmx`），场景 8 跑 `/usr/sbin/sshd`，场景 9 跑真 TCP socket +
//! 真 3-flight 握手（这条路径同时验证 raw 前导约定：`STW2` 由传输层自己收发）。

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use stowaway_core::link_actor::InboundFrame;
use stowaway_core::{
    BridgeSpec, Charset, HostKeyPolicy, Node, NodeConfig, PtySession, SHELL_TAG_DATA,
    SHELL_TAG_RESIZE, ShellCodec, ShellFrame, ShellSpec, SshSpec, bridge_connect, data_message,
    parse_frame, resize_message, spawn,
};
use stowaway_crypto::Secret;
use stowaway_protocol::{
    Message, NodeId, NodeKind, SessionKey, ShellParam, SshAuth, SshParam as ProtoSshParam,
    TransportKind,
};
use stowaway_transport::LinkCodec;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// —————————————————————————————————————————————— 测试工具

fn id(n: u8) -> NodeId {
    let mut b = [0u8; 16];
    b[0] = n;
    NodeId(b)
}

/// 从 PTY 输出里累积到包含 `needle` 为止（带超时）。
async fn read_until(session: &mut PtySession, needle: &[u8]) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut acc = Vec::new();
    loop {
        if acc.windows(needle.len()).any(|w| w == needle) {
            return acc;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            panic!(
                "15 秒内没有读到 {:?}，已收到: {:?}",
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(&acc)
            );
        }
        match tokio::time::timeout(left, session.next_output()).await {
            Ok(Ok(Some(chunk))) => acc.extend_from_slice(&chunk),
            Ok(Ok(None)) => panic!("PTY 提前 EOF，已收到: {:?}", String::from_utf8_lossy(&acc)),
            Ok(Err(e)) => panic!("读 PTY 失败: {e}"),
            Err(_) => panic!("读 PTY 超时，已收到: {:?}", String::from_utf8_lossy(&acc)),
        }
    }
}

// —————————————————————————————————————————————— 场景 7：PTY shell + resize

/// 场景 7a：真 PTY 上跑一条命令并拿回输出。
#[tokio::test]
async fn scenario_7a_shell_interactive_output() {
    let key = SessionKey::new(NodeId::ADMIN, 7);
    let param = ShellParam {
        cols: 80,
        rows: 24,
        term: "xterm".to_owned(),
    };
    let spec = ShellSpec::new(key, &param);
    let mut session = spawn(&spec).expect("spawn pty");

    // 先确认拿到的是真终端（`test -t 0` 在 PTY 下为真、在管道下为假）。
    session.write(b"test -t 0 && echo IS-TTY\r").expect("write");
    let out = read_until(&mut session, b"IS-TTY").await;
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("IS-TTY"),
        "PTY 必须是真终端，实际输出: {text}"
    );

    session.write(b"echo stowaway-pty-ok\r").expect("write");
    let out = read_until(&mut session, b"stowaway-pty-ok").await;
    assert!(String::from_utf8_lossy(&out).contains("stowaway-pty-ok"));
}

/// 场景 7b：`resize` 必须真的到达子进程（用 `stty size` 读回）。
///
/// v1 完全没有 resize 能力（`agent/handler/shell.go` 只有 4096 字节读循环），
/// 所以这条断言是 P5 把 shell 升级为 PTY 的核心证据。
#[tokio::test]
async fn scenario_7b_resize_reaches_the_child() {
    let key = SessionKey::new(NodeId::ADMIN, 8);
    let param = ShellParam {
        cols: 100,
        rows: 40,
        term: "xterm".to_owned(),
    };
    let spec = ShellSpec::new(key, &param);
    let mut session = spawn(&spec).expect("spawn pty");

    // `stty size` 输出「行 列」。
    session.write(b"stty size\r").expect("write");
    let out = read_until(&mut session, b"40 100").await;
    assert!(
        String::from_utf8_lossy(&out).contains("40 100"),
        "初始尺寸应为 40x100，实际: {}",
        String::from_utf8_lossy(&out)
    );

    session.resize(132, 50).expect("resize");
    session.write(b"stty size\r").expect("write");
    let out = read_until(&mut session, b"50 132").await;
    assert!(
        String::from_utf8_lossy(&out).contains("50 132"),
        "resize 后应为 50x132，实际: {}",
        String::from_utf8_lossy(&out)
    );
}

/// 场景 7c：shell 帧的类型标签与 resize 帧能在线路上往返。
#[test]
fn scenario_7c_shell_frames_round_trip_on_the_wire() {
    let key = SessionKey::new(NodeId::ADMIN, 9);

    // 数据帧：首字节 0x00，其后原样。
    let msg = data_message(key, 1, b"hello");
    match msg {
        Message::ServiceData(data) => {
            assert_eq!(data.seq, 1);
            assert_eq!(data.data[0], SHELL_TAG_DATA);
            match parse_frame(&data.data).expect("parse") {
                ShellFrame::Data(bytes) => assert_eq!(bytes, b"hello"),
                other => panic!("期望 Data，得到 {other:?}"),
            }
        }
        other => panic!("期望 ServiceData，得到 {:?}", other.msg_type()),
    }

    // resize 帧：首字节 0x01 + cols/rows。
    let msg = resize_message(key, 2, 132, 50).expect("resize message");
    match msg {
        Message::ServiceData(data) => {
            assert_eq!(data.data[0], SHELL_TAG_RESIZE);
            match parse_frame(&data.data).expect("parse") {
                ShellFrame::Resize { cols, rows } => {
                    assert_eq!((cols, rows), (132, 50));
                }
                other => panic!("期望 Resize，得到 {other:?}"),
            }
        }
        other => panic!("期望 ServiceData，得到 {:?}", other.msg_type()),
    }
}

/// 场景 7d：GBK 双向转换必须真的转换（v1 的 `-cs gbk` 保留项）。
#[test]
fn scenario_7d_gbk_charset_round_trips() {
    let mut codec = ShellCodec::new(Charset::Gbk);
    // 「你好」的 GBK 编码是 4 字节；UTF-8 是 6 字节。
    let gbk = codec.encode_input("你好".as_bytes()).expect("encode");
    assert_eq!(
        gbk,
        vec![196, 227, 186, 195],
        "「你好」的 GBK 必须是 4 字节"
    );
    let back = codec.decode_output(&gbk).expect("decode");
    assert_eq!(back, "你好".as_bytes());
}

// —————————————————————————————————————————————— 场景 8：SSH 命令 + 隧道

/// 一个最小的本地 sshd（工作区内的临时目录，用完即杀）。
///
/// 注意 `/` 是只读的，`/run/sshd` 建不出来，所以 `PidFile`/`HostKey` 必须
/// 落在工作区；`/tmp` 跨进程不持久，所以也不能用。
struct LocalSshd {
    child: Child,
    port: u16,
    dir: PathBuf,
    user_key: PathBuf,
    user: String,
}

impl LocalSshd {
    fn start() -> Option<Self> {
        if !Path::new("/usr/sbin/sshd").exists() || !Path::new("/usr/bin/ssh-keygen").exists() {
            return None;
        }
        let dir = std::env::temp_dir().join(format!(
            "stw-p5-sshd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).ok()?;

        let host = dir.join("hostkey");
        let user_key_path = dir.join("userkey");
        let make_key = |path: &Path| {
            Command::new("/usr/bin/ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        };
        if !make_key(&host).ok()?.success() || !make_key(&user_key_path).ok()?.success() {
            return None;
        }

        let authorized = dir.join("authorized_keys");
        std::fs::copy(dir.join("userkey.pub"), &authorized).ok()?;

        // 用运行测试的那个账号登录，不假设是 root：CI runner 上是 `runner`，
        // 本地开发机上通常是 `root`。写死任一个都会在另一侧失败在
        // `Auth("用户 X 的凭据未被接受")`——`p5_e2e` 曾在 GitHub runner 上正是如此。
        let user = current_user().unwrap_or_else(|| "root".to_owned());
        let port = pick_free_port()?;
        let config = dir.join("sshd_config");
        std::fs::write(
            &config,
            format!(
                "Port {port}\n\
                 ListenAddress 127.0.0.1\n\
                 HostKey {}\n\
                 PidFile {}\n\
                 AuthorizedKeysFile {}\n\
                 PasswordAuthentication no\n\
                 PermitRootLogin prohibit-password\n\
                 UsePAM no\n\
                 StrictModes no\n\
                 AllowUsers {user}\n\
                 LogLevel VERBOSE\n",
                host.display(),
                dir.join("sshd.pid").display(),
                authorized.display()
            ),
        )
        .ok()?;

        let child = Command::new("/usr/sbin/sshd")
            .arg("-f")
            .arg(&config)
            .arg("-E")
            .arg(dir.join("sshd.log"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        // 等端口起来（sshd 是异步 listen 的）。
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(Self {
                    child,
                    port,
                    dir,
                    user_key: user_key_path,
                    user,
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    fn ssh_param(&self) -> ProtoSshParam {
        let pem = std::fs::read_to_string(&self.user_key).expect("user key pem");
        ProtoSshParam {
            user: self.user.clone(),
            auth: SshAuth::PrivateKey(pem),
            command: String::new(),
        }
    }

    fn known_hosts(&self) -> PathBuf {
        // 每次用新文件：走 `AcceptAndLearn` 观察「首次即信任并落盘」。
        self.dir.join("known_hosts")
    }
}

impl Drop for LocalSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn pick_free_port() -> Option<u16> {
    let s = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
    let port = s.local_addr().ok()?.port();
    drop(s);
    Some(port)
}

/// 当前进程所属账号名。测试用 `sshd` 只允许这个账号登录：CI runner 上是
/// `runner`，开发机上通常是 `root`。取不到就返回 `None`（调用方回落到
/// `root`，那是本地开发的常态）。
fn current_user() -> Option<String> {
    let uid = {
        let out = Command::new("id").arg("-u").output().ok()?;
        String::from_utf8(out.stdout).ok()?.trim().to_owned()
    };
    let out = Command::new("getent")
        .arg("passwd")
        .arg(&uid)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8(out.stdout).ok()?;
    let name = line.split(':').next()?.trim().to_owned();
    if name.is_empty() { None } else { Some(name) }
}

/// 场景 8a：SSH 命令执行（真 sshd + 公钥认证 + known_hosts 首访学习）。
#[tokio::test]
async fn scenario_8a_ssh_command_execution() {
    let Some(sshd) = LocalSshd::start() else {
        eprintln!("跳过：本机没有 /usr/sbin/sshd 或 ssh-keygen");
        return;
    };

    let key = SessionKey::new(NodeId::ADMIN, 11);
    let addr = format!("127.0.0.1:{}", sshd.port);
    let spec = SshSpec::new(key, &addr, &sshd.ssh_param())
        .with_policy(HostKeyPolicy::AcceptAndLearn)
        .with_known_hosts(sshd.known_hosts());

    let out = stowaway_core::run_command(&spec, "echo ssh-hello")
        .await
        .expect("run command");
    let text = String::from_utf8_lossy(&out.output);
    assert!(text.contains("ssh-hello"), "SSH 输出: {text}");
    assert_eq!(out.exit_status, Some(0));

    // `AcceptAndLearn` 必须**真的把 key 落盘**，第二次才能 Strict 通过。
    let known = sshd.known_hosts();
    assert!(known.exists(), "known_hosts 必须被创建");
    let content = std::fs::read_to_string(&known).expect("read known_hosts");
    assert!(
        content.contains("ssh-ed25519"),
        "known_hosts 内容: {content}"
    );
}

/// 场景 8b：SSH 隧道（`direct-tcpip`）把远端端口引到本端。
#[tokio::test]
async fn scenario_8b_ssh_tunnel_carries_tcp() {
    let Some(sshd) = LocalSshd::start() else {
        eprintln!("跳过：本机没有 /usr/sbin/sshd");
        return;
    };
    // 隧道另一头必须是 sshd 所在主机能访问的地址；127.0.0.1 正好。
    let echo = echo_server().await;

    let key = SessionKey::new(NodeId::ADMIN, 12);
    let addr = format!("127.0.0.1:{}", sshd.port);
    let spec = SshSpec::new(key, &addr, &sshd.ssh_param())
        .with_policy(HostKeyPolicy::AcceptAndLearn)
        .with_known_hosts(sshd.known_hosts());

    let (conn, channel) = stowaway_core::open_tunnel(&spec, &echo.ip().to_string(), echo.port())
        .await
        .expect("open tunnel");
    assert!(!conn.is_closed());

    // 通过隧道写一段、再读回显。
    let payload = b"ssh-tunnel-payload";
    channel
        .data_bytes(Bytes::copy_from_slice(payload))
        .await
        .expect("write tunnel");
    channel.eof().await.expect("eof");

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let pump = tokio::spawn(async move { stowaway_core::pump_channel(channel, tx).await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut acc = Vec::new();
    loop {
        if acc.windows(payload.len()).any(|w| w == payload) {
            break;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            panic!("隧道回显超时，已收到: {:?}", String::from_utf8_lossy(&acc));
        }
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(chunk)) => acc.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(_) => panic!("隧道回显超时，已收到: {:?}", String::from_utf8_lossy(&acc)),
        }
    }
    assert!(
        acc.windows(payload.len()).any(|w| w == payload),
        "隧道必须原样承载字节，实际: {:?}",
        String::from_utf8_lossy(&acc)
    );
    pump.abort();
}

/// 场景 8c：host key 变更必须被拒绝（v1 的 `InsecureIgnoreHostKey` 缺陷回归）。
#[test]
fn scenario_8c_changed_host_key_is_rejected() {
    use stowaway_core::{HostKeyDecision, HostKeyReject, KnownState, decide_host_key};

    // 每个「会检查」的策略都必须拒绝变更后的 key。
    for policy in [HostKeyPolicy::Strict, HostKeyPolicy::AcceptAndLearn] {
        assert_eq!(
            decide_host_key(policy, KnownState::Changed),
            HostKeyDecision::Reject(HostKeyReject::Changed),
            "{policy:?} 必须拒绝变更的主机密钥"
        );
    }
    // 首次见到（Absent）在 Strict 下必须拒绝，否则 TOFU 没有意义。
    assert_eq!(
        decide_host_key(HostKeyPolicy::Strict, KnownState::Absent),
        HostKeyDecision::Reject(HostKeyReject::Unknown)
    );
    // 默认策略必须是 Strict（不能悄悄降级）。
    assert_eq!(HostKeyPolicy::default(), HostKeyPolicy::Strict);
}

// —————————————————————————————————————————————— 场景 9：connect 跨 admin 桥接

/// 场景 9：`connect` 把对端当作子节点接入，并真实跑通握手与登记。
///
/// 这条路径与 v1 的 `CONNECTSTART → CONNECTDONE` 语义一致：发起方扮 admin，
/// 对端（被桥接的 agent）接受后完成 3-flight 握手与编号交换。
/// 同时它是 raw 前导约定的端到端验证：整条链路走真 TCP socket。
#[tokio::test]
async fn scenario_9_connect_bridge_registers_peer() {
    use stowaway_transport::{Listener, listener_for};

    let secret = Secret::load("p5-e2e-shared-secret", 8).expect("secret");
    let mut listener = listener_for(
        &stowaway_transport::TransportSpec::parse("raw://127.0.0.1:0").expect("spec"),
        None,
    )
    .expect("ctor")
    .await
    .expect("bind");
    let addr = listener.local_addr().expect("addr");

    // 对端：接受连接 → 服务端握手（扮 agent）→ 回 JoinAck。
    let server_secret = Secret::load("p5-e2e-shared-secret", 8).expect("secret2");
    let server = tokio::spawn(async move {
        let (link, _peer) = listener.accept().await.expect("accept");
        let mut codec = LinkCodec::new(link);
        let res = codec
            .server_handshake(NodeKind::Agent, TransportKind::Raw, None, &server_secret)
            .await
            .expect("server handshake");
        assert_eq!(res.peer_kind, NodeKind::Admin);

        // 等桥接方发来的 Join（它自报 admin 身份）。
        let (_, join_msg) = codec.recv_message().await.expect("recv join");
        let Message::Join(join) = join_msg else {
            panic!("期望 Join，得到 {:?}", join_msg.msg_type());
        };
        assert_eq!(join.kind, NodeKind::Admin);
        let parent = join.node;
        assert!(parent.is_assigned(), "桥接方必须自报具体编号");

        // 回 `JoinAck`：`node` 必须是**申请方自己**的编号（协议里就是 `from`），
        // 不是响应方的编号——把它填成自己的会让发起方以为对端认错了人。
        let my_id = id(0x42);
        stowaway_core::reply_join_ack(
            &mut codec,
            stowaway_protocol::JoinAck {
                node: parent,
                parent,
                root: parent,
                depth: 1,
            },
        )
        .await
        .expect("join ack");
        codec
            .send(
                &stowaway_core::announce_message(my_id, NodeKind::Agent),
                NodeId::UNASSIGNED,
                &[],
            )
            .await
            .expect("announce");
        my_id
    });

    // 桥接方：扮 admin 拨号并完成登记。
    let self_id = id(0x01);
    let spec = BridgeSpec::connect(SessionKey::new(self_id, 1), addr.to_string());
    let outcome = bridge_connect(&spec, &secret, self_id)
        .await
        .expect("bridge connect");

    assert_eq!(outcome.peer, id(0x42), "必须学到对端编号");
    assert_eq!(outcome.peer_kind, NodeKind::Agent);
    assert!(outcome.codec.is_sealed(), "桥接链路必须已密封");
    assert_eq!(server.await.expect("server join"), id(0x42));

    // 把桥接出来的链路真正挂到 Node 上，确认它能作为子节点工作。
    let mut admin = Node::new(NodeConfig::new(self_id, NodeKind::Admin));
    let (tx, _rx) = mpsc::channel::<InboundFrame>(64);
    let codec = outcome.codec;
    let (_handle, actor) = admin
        .attach_link(codec, outcome.peer, self_id, outcome.peer_kind, tx)
        .expect("attach bridged link");
    tokio::spawn(actor.run());

    assert!(
        admin.topology().get(outcome.peer).is_some(),
        "桥接对端必须出现在 admin 的拓扑里"
    );
}

// —————————————————————————————————————————————— 公共小工具

/// 一个把收到的字节原样回送的回显服务。
async fn echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
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

use bytes::Bytes;
