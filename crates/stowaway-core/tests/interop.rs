//! plan.md §8.4「Go 黑盒行为对照」（`tests/interop`）。
//!
//! v2 与 v1 的线协议**不兼容**（plan.md §0 的 D1），所以这里**不对照线格式**，
//! 只对照**行为**：SOCKS5 语义、文件切分、shell 输出编码（GBK）、
//! forward/backward 的探测时序。
//!
//! # 基线二进制从哪来
//!
//! `cargo xtask fetch-go-baseline`（`xtask/src/interop.rs`）用 Go 1.18 构建 v1 的
//! `./agent` 与 `./admin` 两个包，产物落在 `target/interop-baseline/stowaway-{agent,admin}-go`。
//! 本文件读 `STOWAWAY_INTEROP_BASELINE`（默认 `target/interop-baseline`）找
//! `stowaway-agent-go`。
//!
//! **没有 Go 基线就跳过**（plan.md §9 风险表的口径）：二进制缺失、或存在但无法
//! 执行（权限不足、架构不符、缺动态库），每条测试都 `eprintln!` 说明原因后
//! `return`，**不失败**。这样「本机没装 Go」不会把 `cargo test` 变成红灯。
//!
//! # 本机实测结论（为什么有的对照只能做到这个程度）
//!
//! 实测环境：`/opt/go/bin/go` = go1.18.1 linux/amd64，基线二进制可构建、可运行。
//!
//! 1. **SOCKS5 端到端对照不了**：v1 的 SOCKS5 **TCP 监听器由 admin 侧创建**
//!    （`admin/handler/socks.go` 的 `LetSocks` 里 `net.Listen("tcp", addr)`），
//!    agent 只负责跑状态机（`agent/handler/socks.go:130` 的 `checkMethod` /
//!    `auth` / `buildConn`），且状态机是靠 v1 私有消息 `SOCKSTCPDATA` 驱动的。
//!    单独一个 `stowaway-agent-go` 进程的 TCP 端口是**v1 协议端口**，不是
//!    SOCKS5 端口：实测往该端口发 SOCKS5 方法协商字节（`05 02 00 02`）得不到
//!    任何 SOCKS5 回复，对端随后报 `unexpected EOF` 退出。因为 v2 说不了 v1 的
//!    线协议（D1），「让 Rust 客户端与 Go agent 完成 SOCKS5 握手」在本机上
//!    **不可能**，只能：(a) 黑盒断言 Go 二进制不是 SOCKS5 监听器（
//!    [`interop_socks5_go_agent_is_not_a_socks_listener`]），(b) 断言我们的
//!    `socks_server::negotiate` 在方法选择上与 v1 `checkMethod` 的判定表**同构**
//!    （[`interop_socks5_auth_is_not_downgraded`]）。不伪造握手。
//! 2. **文件分片、GBK、探测时序是纯行为/常量对照**：v1 的分片大小
//!    （`share/file.go:194` 的 `make([]byte, 30720)`）、GBK 编码（
//!    `utils/utils.go:219` 的 `ConvertStr2GBK` → `simplifiedchinese.GBK`）、
//!    `FORWARDTEST`/`BACKWARDTEST` 两阶段（`admin/handler/forward.go:22`、
//!    `admin/handler/backward.go:26`）都是源码里的确定性事实。GBK 的基准字节
//!    已用 Go 的 `simplifiedchinese.GBK.NewEncoder().Bytes([]byte("你好"))` 实测为
//!    `[196 227 186 195]`，与下面断言的期望值一致。
//! 3. **CLI 规约可以用预编译二进制真对照**：退出码与 stderr 文案是 v1 的对外
//!    行为（Go `flag` 包与 `agent/initial/parser.go`/`utils.CheckIPPort` 决定），
//!    [`interop_go_agent_cli_contract`] 直接跑二进制比对，这是本套件里唯一
//!    真正「跑起来」的对照。
//!
//! 运行：
//! ```text
//! cargo run -q --offline -p xtask -- fetch-go-baseline
//! cargo test -p stowaway-core --test interop -- --test-threads=1
//! ```

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use stowaway_core::socks::{AUTH_NONE, AUTH_UNACCEPTABLE, AUTH_USERPASS};
use stowaway_core::{
    BACKWARD_PROBE_TIMEOUT, BackwardSpec, Charset, Credentials, FILE_CHUNK, ForwardSpec,
    PROBE_TIMEOUT, ShellCodec, SocksServerConfig, negotiate,
};
use stowaway_protocol::{
    MAX_FRAME, Message, NodeId, ServiceKind, ServiceParam, ServicePhase, SessionKey,
};

// —————————————————————————————————————————————— 基线定位

/// 基线目录下的 agent 产物名（与 `xtask/src/interop.rs` 的 `SIDES` 一致）。
const AGENT_BIN: &str = "stowaway-agent-go";

/// 基线目录：`$STOWAWAY_INTEROP_BASELINE`，默认 `<workspace>/target/interop-baseline`。
///
/// 相对路径按**仓库根**解析（`cargo test` 的 cwd 是 `crates/stowaway-core`，
/// 直接按 cwd 解析会指到 `crates/stowaway-core/target/...`）。
fn baseline_dir() -> PathBuf {
    match std::env::var("STOWAWAY_INTEROP_BASELINE") {
        Ok(dir) => {
            let p = PathBuf::from(&dir);
            if p.is_absolute() {
                p
            } else {
                workspace_root().join(p)
            }
        }
        Err(_) => workspace_root().join("target").join("interop-baseline"),
    }
}

fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| manifest.to_path_buf(), Path::to_path_buf)
}

/// 取基线 agent 二进制；不可用则**打印跳过原因并返回 `None`**。
///
/// 判定顺序：文件存在 → 能真正被执行。后者用一个不会产生副作用的调用
/// （`--zzz`，Go `flag` 包必定以退出码 2 拒绝）试探；`Err` 只可能来自
/// 「权限不足 / 架构不符 / 缺解释器」，正是 plan.md §9 说的「无 Go 基线」。
fn baseline_agent(test: &str) -> Option<PathBuf> {
    let dir = baseline_dir();
    let bin = dir.join(AGENT_BIN);
    let skip = |reason: String| {
        eprintln!(
            "interop: 跳过 {test}：{reason}（先跑 `cargo xtask fetch-go-baseline`，或用 STOWAWAY_INTEROP_BASELINE 指定目录）"
        );
    };
    if !bin.is_file() {
        skip(format!("基线二进制 {} 不存在", bin.display()));
        return None;
    }
    match Command::new(&bin).arg("--zzz").output() {
        Ok(_) => Some(bin),
        Err(e) => {
            skip(format!(
                "基线二进制 {} 无法执行：{e}（权限不足或架构不符？）",
                bin.display()
            ));
            None
        }
    }
}

// —————————————————————————————————————————————— 进程/端口小工具

/// 让内核分配一个空闲端口（bind 后立刻释放，供随后的 Go agent 复用）。
fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

fn wait_listening(port: u16, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

/// 起一个**被动模式**的 v1 agent（`-l <ip:port> -s <secret>`）。
///
/// 失败返回原因字符串（端口被占、二进制起不来），由调用方决定跳过。
fn spawn_passive_agent(bin: &Path) -> Result<AgentGuard, String> {
    let mut last = String::new();
    for _ in 0..3 {
        let port = free_port();
        let mut child = Command::new(bin)
            .args(["-l", &format!("127.0.0.1:{port}"), "-s", "interop-secret"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("无法启动 {}：{e}", bin.display()))?;
        if wait_listening(port, Duration::from_secs(3)) {
            return Ok(AgentGuard {
                child: Some(child),
                port,
            });
        }
        let _ = child.kill();
        let _ = child.wait();
        last = format!("端口 {port} 在 3s 内没有进入监听状态");
    }
    Err(last)
}

/// v1 agent 子进程的守卫：无论断言结果如何都杀掉，避免残留进程/端口。
///
/// `child` 是 `Option`：`Drop` 里要把 `Child` 移出来才能 `wait_with_output`，
/// 而实现 `Drop` 的类型不允许整体移出字段，故用 `take()` 显式取走。
///
/// `Debug` 手写：`Child` 的格式化输出对断言无用，只保留 port 更有信息量。
struct AgentGuard {
    child: Option<Child>,
    port: u16,
}

impl std::fmt::Debug for AgentGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentGuard")
            .field("port", &self.port)
            .field("pid", &self.child.as_ref().map(Child::id))
            .finish()
    }
}

impl AgentGuard {
    /// 杀掉并回收，返回（退出码, stderr 全文）。
    fn shutdown(mut self) -> (Option<i32>, String) {
        let Some(mut child) = self.child.take() else {
            return (None, String::new());
        };
        let _ = child.kill();
        match child.wait_with_output() {
            Ok(o) => (
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            ),
            Err(_) => (None, String::new()),
        }
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn key() -> SessionKey {
    SessionKey::new(NodeId::new([0x11; 16]), 1)
}

/// 取出 `ServiceRequest`（断言失败时把实际消息打出来）。
fn service_request(msg: Message) -> stowaway_protocol::ServiceRequest {
    match msg {
        Message::ServiceRequest(req) => req,
        other => panic!("应为 ServiceRequest，实际 {other:?}"),
    }
}

// —————————————————————————————————————————————— 1. CLI 规约（真跑 Go 二进制）

/// v1 agent 的**对外行为**：退出码 + stderr 文案。
///
/// 全部来自实测（go1.18.1 构建的 `/root/workspace/coding/Stowaway`）：
///
/// | 调用 | 退出码 | stderr |
/// |---|---|---|
/// | 无参数 | 1 | （空；`agent/initial/parser.go` 的模式判定不通过 → `os.Exit(1)`） |
/// | `-l abc` | 1 | `Starting agent node passively…` + `Error occurred: please input either port(1~65535) or ip:port(1-65535)`（`utils/utils.go:95` 的 `CheckIPPort`） |
/// | `--zzz` | 2 | `flag provided but not defined: -zzz`（Go `flag` 包） |
/// | `-l <ip:port> -s <secret>` | 持续运行 | `Starting agent node passively.Now listening on port <ip:port>`，且该端口进入监听 |
///
/// 这几条是「行为对照」里唯一真正跑起 Go 二进制的部分（plan.md §8.4 的
/// 「场景脚本对比退出码与输出规约」）。我们 v2 的 agent 由 `clap` 解析，
/// 文案不同但**同类语义必须存在**：无模式即失败、非法端口即失败、未知参数
/// 即失败。本测试只固定 v1 侧基线，供 v2 的 CLI 改动回归时对照。
#[test]
fn interop_go_agent_cli_contract() {
    let Some(bin) = baseline_agent("interop_go_agent_cli_contract") else {
        return;
    };

    // 无参数：v1 的模式判定失败 → os.Exit(1)，且**不打印**任何东西。
    let bare = Command::new(&bin).output().expect("跑 stowaway-agent-go");
    assert_eq!(
        bare.status.code(),
        Some(1),
        "v1 agent 无参数应以退出码 1 结束，实际 {:?}，stderr={}",
        bare.status.code(),
        String::from_utf8_lossy(&bare.stderr)
    );
    assert!(
        bare.stdout.is_empty() && bare.stderr.is_empty(),
        "v1 agent 无参数应静默退出，实际 stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&bare.stdout),
        String::from_utf8_lossy(&bare.stderr)
    );

    // 非法端口：先打「被动模式启动」横幅，再由 CheckIPPort 报错，退出码 1。
    let bad = Command::new(&bin)
        .args(["-l", "abc"])
        .output()
        .expect("跑 stowaway-agent-go -l abc");
    let bad_err = String::from_utf8_lossy(&bad.stderr);
    assert_eq!(bad.status.code(), Some(1), "非法端口应以 1 退出：{bad_err}");
    assert!(
        bad_err.contains("please input either port(1~65535) or ip:port(1-65535)"),
        "非法端口的错误文案应含 CheckIPPort 的提示，实际 stderr={bad_err}"
    );

    // 未定义 flag：Go flag 包以退出码 2 结束。
    let unknown = Command::new(&bin)
        .arg("--zzz")
        .output()
        .expect("跑 stowaway-agent-go --zzz");
    let unknown_err = String::from_utf8_lossy(&unknown.stderr);
    assert_eq!(
        unknown.status.code(),
        Some(2),
        "未定义 flag 应以 2 退出：{unknown_err}"
    );
    assert!(
        unknown_err.contains("flag provided but not defined"),
        "未定义 flag 的文案应来自 Go flag 包，实际 stderr={unknown_err}"
    );

    // 被动模式：横幅 + 端口真的进入监听。
    let guard = match spawn_passive_agent(&bin) {
        Ok(g) => g,
        Err(reason) => {
            eprintln!(
                "interop: interop_go_agent_cli_contract 的监听子项跳过：{reason}（前三条退出码断言已通过）"
            );
            return;
        }
    };
    let port = guard.port;
    let (_code, stderr) = guard.shutdown();
    assert!(
        stderr.contains("Starting agent node passively.Now listening on port"),
        "被动模式应打印监听横幅，实际 stderr={stderr}"
    );
    assert!(
        stderr.contains(&port.to_string()),
        "监听横幅应含端口 {port}，实际 stderr={stderr}"
    );
}

// —————————————————————————————————————————————— 2. SOCKS5：Go 二进制不是 SOCKS5 端口

/// v1 的 SOCKS5 **监听器在 admin 侧**，agent 侧只有状态机（由 v1 私有消息驱动）。
///
/// 因此单独一个 `stowaway-agent-go` 的 TCP 端口**不会**回 SOCKS5 方法协商。
/// 本测试把这个「结构性事实」变成可机械复核的断言：往 agent 端口发
/// `05 02 00 02`（VER=5、NMETHODS=2、NONE+USERPASS）后，在 1s 内**收不到**
/// 形如 `[0x05, method]` 的方法选择回复（超时或 EOF 都算「不是 SOCKS5 服务端」）。
///
/// 如果哪天这里**收到**了 `05 xx`，说明 v1 的拓扑与 plan.md §0/F2 的描述不符，
/// 那时才需要重写这条对照（而不是继续跳过）。
#[test]
fn interop_socks5_go_agent_is_not_a_socks_listener() {
    let Some(bin) = baseline_agent("interop_socks5_go_agent_is_not_a_socks_listener") else {
        return;
    };
    let guard = match spawn_passive_agent(&bin) {
        Ok(g) => g,
        Err(reason) => {
            eprintln!(
                "interop: 跳过 interop_socks5_go_agent_is_not_a_socks_listener：v1 agent 起不来（{reason}）"
            );
            return;
        }
    };
    let port = guard.port;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("连 v1 agent 端口");
    stream
        .set_read_timeout(Some(Duration::from_millis(800)))
        .expect("set_read_timeout");
    // 写入本身也可能立刻被拒（对端可能在读到首字节前就关闭）：那同样说明
    // 「这个端口不是 SOCKS5 服务端」，与读取阶段的判定合并处理。
    let write = stream
        .write_all(&[0x05, 0x02, AUTH_NONE, AUTH_USERPASS])
        .and_then(|()| stream.flush());
    if let Err(e) = write {
        eprintln!(
            "interop: 写 SOCKS5 协商到 v1 agent 端口即被拒（{:?}：{e}），符合「监听器在 admin 侧」的结论",
            e.kind()
        );
        let (_code, stderr) = guard.shutdown();
        eprintln!("interop: v1 agent 收尾 stderr（诊断用）={stderr}");
        return;
    }

    let mut buf = [0u8; 8];
    match stream.read(&mut buf) {
        // 读到 `05 xx` 就是「v1 agent 自己会说 SOCKS5」，与 plan §0/F2 矛盾。
        Ok(n) if n >= 2 && buf[0] == 0x05 => panic!(
            "v1 agent 端口回了 SOCKS5 方法选择 {:?}：说明 SOCKS5 监听器在 agent 侧，\
             plan.md §0（D1）/ §4.6（F2）的描述需要复核",
            &buf[..n]
        ),
        // 超时 / EOF / 其他字节：都不是 SOCKS5 方法选择回复，符合预期。
        Ok(n) => eprintln!(
            "interop: v1 agent 端口回的不是 SOCKS5 方法选择（{n} 字节: {:?}），符合「监听器在 admin 侧」的结论",
            &buf[..n]
        ),
        Err(e) => match e.kind() {
            // 超时：对端既不回 SOCKS5 回复、也不立刻断开——符合预期。
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => eprintln!(
                "interop: v1 agent 端口对 SOCKS5 协商无回复（{:?}），符合「监听器在 admin 侧」的结论",
                e.kind()
            ),
            // 对端把这几字节当非法 v1 报文、直接关闭/重置连接：同样符合预期
            // （实测 v1 agent 收到 `05 02 00 02` 后报 `unexpected EOF` 并退出）。
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof => eprintln!(
                "interop: v1 agent 端口拒绝了 SOCKS5 协商并关闭连接（{:?}），符合「监听器在 admin 侧」的结论",
                e.kind()
            ),
            other => panic!("读 v1 agent 端口失败（非预期错误）：{other:?}（{e}）"),
        },
    }
    let (_code, stderr) = guard.shutdown();
    // agent 收到非法 v1 报文后会报错退出；这条只在诊断时有用，不断言具体文案。
    eprintln!("interop: v1 agent 收尾 stderr（诊断用）={stderr}");
}

// —————————————————————————————————————————————— 3. SOCKS5：认证不可降级
/// 方法协商的「不可降级」语义，与 v1 的 `checkMethod` 判定表同构。
///
/// v1 的判定表（`agent/handler/socks.go:130-208`，实测口径）：
///
/// | 客户端声明 | 服务端配了用户名/密码 | 结果 |
/// |---|---|---|
/// | 含 `0x00` | 否 | 选 `0x00`（NONE），免认证 |
/// | 含 `0x02` | 是 | 选 `0x02`（USERPASS） |
/// | 含 `0x00` 但**不含** `0x02` | 是 | 回 `05 ff`（ILLEGAL）——**绝不降级到 NONE** |
/// | 含 `0x02` 但**不含** `0x00` | 否 | 回 `05 ff` |
/// | 一个都不含 | 任意 | 回 `05 ff` |
///
/// v2 的 `socks_server::negotiate` 必须给出同样的选择（plan.md §5.1 第 13 项：
/// v1 的 `checkMethod` 只挑方法不校验凭据，任何能连到端口的客户端都能把 agent
/// 当开放代理用；v2 强制要求 USERPASS）。这里用 `tokio::io::duplex` 走真实的
/// 协商代码路径，逐条对表。
#[tokio::test]
async fn interop_socks5_auth_is_not_downgraded() {
    let Some(_bin) = baseline_agent("interop_socks5_auth_is_not_downgraded") else {
        return;
    };

    // 请求体（VER|CMD|RSV|ATYP| addr | port）：CONNECT 127.0.0.1:9（discard 端口）。
    let connect_request = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 9];

    // (客户端声明的方法, 服务端是否配凭据, 期望的 2 字节方法回复)
    let cases: [(Vec<u8>, bool, [u8; 2]); 5] = [
        (vec![AUTH_NONE], false, [0x05, AUTH_NONE]),
        (vec![AUTH_NONE, AUTH_USERPASS], false, [0x05, AUTH_NONE]),
        (vec![AUTH_NONE, AUTH_USERPASS], true, [0x05, AUTH_USERPASS]),
        // 关键一条：配了凭据时只报 NONE → 必须回 `05 ff`，不得降级。
        (vec![AUTH_NONE], true, [0x05, AUTH_UNACCEPTABLE]),
        // 未配凭据时只报 USERPASS → 同样回 `05 ff`。
        (vec![AUTH_USERPASS], false, [0x05, AUTH_UNACCEPTABLE]),
    ];

    for (methods, with_credentials, expected) in cases {
        let cfg = if with_credentials {
            SocksServerConfig::with_credentials(Credentials::new("user", "pass"))
        } else {
            SocksServerConfig::open()
        };
        let (mut client, mut server) = tokio::io::duplex(64);
        let server_cfg = cfg.clone();
        let task = tokio::spawn(async move {
            // 协商在 `05 ff`/认证失败/读到一半就断开时会返回 Err；本测试只关心
            // 服务端**写出的方法回复**，返回值不参与断言。
            let _ = negotiate(&mut server, &server_cfg).await;
        });

        let mut greeting = vec![0x05, u8::try_from(methods.len()).expect("方法数 <= 255")];
        greeting.extend_from_slice(&methods);
        // 先写协商头，再写请求：认证通过的分支需要后续请求才能走到结尾，
        // 但方法回复在这之前就已经发出。
        tokio::io::AsyncWriteExt::write_all(&mut client, &greeting)
            .await
            .expect("写方法协商");
        tokio::io::AsyncWriteExt::write_all(&mut client, &connect_request)
            .await
            .expect("写请求头");

        let mut reply = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut reply)
            .await
            .expect("读方法选择回复");
        assert_eq!(
            reply, expected,
            "方法声明 {methods:?} / 配凭据 {with_credentials}：应选 {:?}，实际 {reply:?}",
            expected[1]
        );
        drop(client);
        let _ = task.await;
    }
}

// —————————————————————————————————————————————— 4. 文件分片语义

/// v1 的 shard 是 30720 字节（`share/file.go:194` 的 `make([]byte, 30720)`），
/// v2 是 65536（[`FILE_CHUNK`]，对齐 `FRAGMENT_MAX`）。分块语义按
/// `ceil(len / chunk)` 计算，两种大小下 100 KiB 的块数不同（2 vs 4）——
/// 这正是「不对照线格式、只对照行为」的边界：片数不同不是回归。
#[test]
fn interop_file_chunk_is_ceil_of_100kib() {
    let Some(_bin) = baseline_agent("interop_file_chunk_is_ceil_of_100kib") else {
        return;
    };

    /// v1 的分片大小（`share/file.go:194`）。
    const V1_FILE_CHUNK: usize = 30720;
    /// 100 KiB。
    const DATA_LEN: usize = 100 * 1024;

    assert_eq!(FILE_CHUNK, 64 * 1024, "v2 的 FILE_CHUNK 应为 65536");
    assert_ne!(
        FILE_CHUNK, V1_FILE_CHUNK,
        "v1 用 30720 字节分片；v2 若与之相同，plan.md §4.6 的说明需要更新"
    );

    let data = vec![0xA5u8; DATA_LEN];
    let frames = stowaway_core::file::chunk(key(), &data);

    // ceil(100KiB / 64KiB) = 2。
    assert_eq!(frames.len(), 2, "100 KiB 应按 65536 分成 2 块");
    // ceil(100KiB / 30720) = 4（v1 的块数，作为对照记录）。
    assert_eq!(
        DATA_LEN.div_ceil(V1_FILE_CHUNK),
        4,
        "v1 的 30720 分片下 100 KiB 应为 4 块（仅用于说明差异，不是回归）"
    );

    let mut total = 0usize;
    for (expected_seq, frame) in frames.iter().enumerate() {
        let Message::ServiceData(part) = frame else {
            panic!("文件数据帧应为 ServiceData，实际 {frame:?}");
        };
        assert_eq!(part.seq, expected_seq as u64, "seq 必须从 0 开始连续");
        assert_eq!(part.key, key(), "会话键必须原样带出");
        assert!(
            part.data.len() <= FILE_CHUNK,
            "第 {expected_seq} 块 {} 字节超过 FILE_CHUNK",
            part.data.len()
        );
        assert!(
            part.data.len() <= MAX_FRAME,
            "第 {expected_seq} 块 {} 字节超过 MAX_FRAME({MAX_FRAME})",
            part.data.len()
        );
        total += part.data.len();
    }
    // 块长分别是 65536 与 36864，拼起来正好等于原始长度（分块不丢字节）。
    assert_eq!(total, DATA_LEN, "分块后总长必须等于原始长度");
    assert_eq!(
        frames
            .iter()
            .filter_map(|f| match f {
                Message::ServiceData(p) => Some(p.data.len()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![64 * 1024, DATA_LEN - 64 * 1024],
        "块长应为 [65536, 36864]"
    );

    // 空输入也要产出一帧（否则对端无法区分「空文件」与「没有文件」）。
    let empty = stowaway_core::file::chunk(key(), &[]);
    assert_eq!(empty.len(), 1, "空数据应产出一帧空帧");
    let Message::ServiceData(part) = &empty[0] else {
        panic!("空帧也应是 ServiceData，实际 {:?}", empty[0]);
    };
    assert_eq!(part.seq, 0);
    assert!(part.data.is_empty());
}

// —————————————————————————————————————————————— 5. shell 的 GBK 编码

/// `-cs gbk` 的字节级一致：`你好` → `[196, 227, 186, 195]`。
///
/// 基准来自 v1 `utils/utils.go:219` 的 `ConvertStr2GBK`
/// （`simplifiedchinese.GBK.NewEncoder().String(str)`），本机用同一 API 实测
/// `Bytes([]byte("你好"))` = `[196 227 186 195]`。我们的
/// `ShellCodec::new(Charset::Gbk).encode_input` 必须逐字节相同，`decode_output`
/// 必须能反向还原（`agent/handler/shell.go:122` 的 `ConvertGBK2Str`）。
#[test]
fn interop_shell_gbk_matches_go_encoder() {
    let Some(_bin) = baseline_agent("interop_shell_gbk_matches_go_encoder") else {
        return;
    };

    // 命令行标签也对照：v1 `-cs` 接受 `gbk`（`agent/initial/parser.go`）。
    assert_eq!(Charset::from_tag("gbk"), Some(Charset::Gbk));
    assert_eq!(Charset::Gbk.as_tag(), "gbk");

    let utf8 = "你好".as_bytes();
    let expected = [196u8, 227, 186, 195];
    let mut codec = ShellCodec::new(Charset::Gbk);
    let encoded = codec.encode_input(utf8).expect("GBK 编码 你好");
    assert_eq!(
        encoded,
        expected.to_vec(),
        "GBK 编码应与 Go 的 ConvertStr2GBK 一致：期望 {expected:?}，实际 {encoded:?}"
    );
    assert_eq!(
        encoded.len(),
        4,
        "「你好」在 GBK 下是 4 字节（2 汉字 × 2 字节）"
    );

    let mut decoder = ShellCodec::new(Charset::Gbk);
    let decoded = decoder.decode_output(&expected).expect("GBK 解码");
    assert_eq!(
        decoded,
        utf8.to_vec(),
        "GBK 解码必须还原 UTF-8 的「你好」，实际 {decoded:?}"
    );

    // UTF-8 模式下同样是「原样透传」（v1 的默认 `-cs utf-8`）。
    let mut plain = ShellCodec::new(Charset::Utf8);
    assert_eq!(plain.encode_input(utf8).expect("UTF-8 透传"), utf8.to_vec());
    assert_eq!(
        plain.decode_output(utf8).expect("UTF-8 透传"),
        utf8.to_vec()
    );

    // 不可映射字符在 GBK 下必须**报错**而不是静默替换（v1 会吞掉）；这条是
    // 我们有意强化的行为，记录在此以免被误当成「与 v1 不一致」。
    let mut strict = ShellCodec::new(Charset::Gbk);
    assert!(
        strict.encode_input("😀".as_bytes()).is_err(),
        "GBK 无法表示 emoji，应报错而不是静默替换"
    );
}

// —————————————————————————————————————————————— 6. forward/backward 的探测时序

/// 两阶段（Probe → Run）与 backward 的 `listen:<port>` 探测载荷。
///
/// v1 的两个探测消息语义不同（`docs/plan.md` 附录 A）：
/// - `FORWARDTEST` 携带**要拨的目标**（`admin/handler/forward.go:22` 的
///   `ForwardTest{Addr: forward.Addr}`）；
/// - `BACKWARDTEST` 携带**要监听的端口**（`admin/handler/backward.go:26` 的
///   `BackwardTest{LPort, RPort}`），即「你打算在哪个端口服务我」。
///
/// v2 把「探测」与「执行」写成显式阶段（`ServicePhase::Probe` / `Run`），
/// 消除 v1 `admin/handler/forward.go:124-132` 那段 DEAD LOCK 注释里的顺序耦合：
/// 端口监听器只在 Probe 返回 `Ok` 之后才创建。
#[test]
fn interop_forward_backward_probe_precedes_run() {
    let Some(_bin) = baseline_agent("interop_forward_backward_probe_precedes_run") else {
        return;
    };

    // 探测超时与 v1 的 `FORWARDTEST`/`BACKWARDTEST` 等待窗口同量级（10s）。
    assert_eq!(PROBE_TIMEOUT, Duration::from_secs(10));
    assert_eq!(BACKWARD_PROBE_TIMEOUT, Duration::from_secs(10));

    let forward = ForwardSpec::new(key(), 0, "127.0.0.1:22");
    // 探测：Probe 阶段，载荷是「要拨的目标」。
    let req = service_request(forward.probe());
    assert_eq!(req.phase, ServicePhase::Probe, "probe() 必须是 Probe 阶段");
    assert_eq!(req.kind, ServiceKind::Connect);
    assert_eq!(
        req.param,
        ServiceParam::Connect(stowaway_protocol::ConnectParam {
            addr: "127.0.0.1:22".to_string(),
        }),
        "forward 的探测载荷应是远端目标地址（v1 FORWARDTEST 语义）"
    );
    // 执行：Run 阶段，载荷不变（同一目标）。
    let req = service_request(forward.run());
    assert_eq!(req.phase, ServicePhase::Run, "run() 必须是 Run 阶段");
    assert_eq!(req.kind, ServiceKind::Connect);

    // backward：探测载荷是 `listen:<port>`，而不是目标地址。
    let backward = BackwardSpec::new(key(), 9000, "127.0.0.1:22");
    let req = service_request(backward.probe());
    assert_eq!(req.phase, ServicePhase::Probe);
    assert_eq!(
        req.kind,
        ServiceKind::Backward,
        "backward 用独立的 ServiceKind：它要在对端 bind，与 Connect 是相反动作（附录 A 第 39 行）"
    );
    assert_eq!(
        req.param,
        ServiceParam::Connect(stowaway_protocol::ConnectParam {
            addr: "listen:9000".to_string(),
        }),
        "backward 的探测载荷应是 listen:<port>（v1 BACKWARDTEST 语义）"
    );
    let req = service_request(backward.run());
    assert_eq!(req.phase, ServicePhase::Run);
    assert_eq!(
        req.param,
        ServiceParam::Connect(stowaway_protocol::ConnectParam {
            addr: "listen:9000".to_string(),
        }),
        "backward 的执行阶段沿用同一监听端口"
    );

    // 两个阶段的消息必须**不相等**：否则「先探测再执行」在协议层无从区分，
    // 又会退化成 v1 那种靠人为顺序规避死锁的形态。
    assert_ne!(backward.probe(), backward.run());
}
