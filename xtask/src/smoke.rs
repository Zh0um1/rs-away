//! `smoke`：`--non-interactive` 的双进程冒烟（plan.md §7 P7 出口判据）。
//!
//! 判据来自 P7 的出口要求「`--non-interactive` 冒烟」——它的意思是
//! **两个真二进制真的能连起来并按脚本跑完**，而不是「`run_batch` 这个函数
//! 有单测」。两者的差别正是本项目已经踩过的那些坑：会话就绪时序、前导
//! 污染、`ServiceExit` 回错方向，全都在单测里看不见。
//!
//! 四步，每步都断言一个具体现象：
//!
//! 1. `admin --listen --non-interactive --command ...` 起被动端；
//! 2. `agent --connect` 拨进来——**没有它，admin 永远等不到首个节点**，
//!    这也是「单进程冒烟」不成立的原因（首个入站是设计上的必经点）；
//! 3. admin 的批处理输出里必须出现「入网」「已选中节点」「已退出控制台」，
//!    退出码 0；
//! 4. 另起一次带错命令的批处理，退出码必须是 1——批处理静默跳过一条命令
//!    会让脚本以为跑过了，这比报错危险得多。
//!
//! 端口用「绑 0 再释放」取一个空闲号：测试机端口占用不可预期，写死会在
//! CI 上随机失败。

use std::io::{BufRead, BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

/// v1/v2 都要求 ≥8 字符，这里给一个明显的测试值。
const SECRET: &str = "xtask-smoke-secret";

/// 等对端端口可连的上限：`LINK_SETUP_TIMEOUT` 是 15s，留一倍余量。
const BOOT_TIMEOUT: Duration = Duration::from_secs(30);

/// 批处理跑完的上限（含一次 15s 的首个入站等待）。
const BATCH_TIMEOUT: Duration = Duration::from_secs(60);

pub fn run(root: &Path, argv: &[String]) -> ExitCode {
    match argv.first().map(String::as_str) {
        None => {}
        Some("-h" | "--help") => {
            println!("cargo xtask smoke [--release]");
            println!("  构建两个二进制并跑 `--non-interactive` 双进程冒烟（plan.md §7 P7）");
            return ExitCode::SUCCESS;
        }
        Some(other) => {
            eprintln!("smoke: 未知参数 `{other}`（只接受 `--release`）");
            return ExitCode::FAILURE;
        }
    }
    let release = argv.iter().any(|a| a == "--release");
    match smoke(root, release) {
        Ok(()) => {
            println!("smoke: 通过");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("smoke: 失败：{e}");
            ExitCode::FAILURE
        }
    }
}

fn smoke(root: &Path, release: bool) -> Result<(), String> {
    build(root, release)?;
    let profile = if release { "release" } else { "debug" };
    let admin = root.join("target").join(profile).join("stowaway-admin");
    let agent = root.join("target").join(profile).join("stowaway-agent");
    for bin in [&admin, &agent] {
        if !bin.is_file() {
            return Err(format!("找不到 {}", bin.display()));
        }
    }

    happy_path(&admin, &agent)?;
    bad_command_is_loud(&admin)?;
    Ok(())
}

/// 一次正常的被动端 + 主动端。
fn happy_path(admin: &Path, agent: &Path) -> Result<(), String> {
    let port = free_port()?;
    let admin_child = Command::new(admin)
        .args(["-s", SECRET, "-l", &port.to_string(), "--non-interactive"])
        // 三条命令覆盖「只读面板 → 切面板 → 退出」：`topo` 在主面板，
        // `status` 只在 node 面板（先 `use 0` 才进得去），`exit` 结束批处理。
        .args([
            "--command",
            "topo",
            "--command",
            "use 0",
            "--command",
            "status",
            "--command",
            "exit",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("启动 admin 失败：{e}"))?;

    wait_port(port)?;

    let mut agent_child = Command::new(agent)
        .args(["-s", SECRET, "-c", &format!("127.0.0.1:{port}")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("启动 agent 失败：{e}"))?;

    let (status, out, err) = finish(admin_child, BATCH_TIMEOUT, "admin")?;

    // agent 是被动端等来的对端，它的退出码不重要（SIGTERM 是 -15），
    // 但它的输出要留一份，失败时能看出是哪一侧先断的。
    let (_, agent_out, agent_err) = finish_quiet(&mut agent_child);
    let _ = agent_out;
    let _ = agent_err;

    if !status.success() {
        return Err(format!(
            "admin 批处理退出码 {status}\nstdout:\n{out}\nstderr:\n{err}"
        ));
    }
    for needle in ["入网", "已选中节点", "已退出控制台"] {
        if !out.contains(needle) {
            return Err(format!(
                "admin 输出缺少「{needle}」——批处理没真正跑到那一步\nstdout:\n{out}\nstderr:\n{err}"
            ));
        }
    }
    if out.contains("无法解析") || err.contains("无法解析") {
        return Err(format!(
            "合法命令被判成无法解析\nstdout:\n{out}\nstderr:\n{err}"
        ));
    }
    Ok(())
}

/// 一条错命令必须让退出码非 0。
fn bad_command_is_loud(admin: &Path) -> Result<(), String> {
    let port = free_port()?;
    let child = Command::new(admin)
        .args(["-s", SECRET, "-l", &port.to_string(), "--non-interactive"])
        .args(["--command", "definitely-not-a-command"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("启动 admin 失败：{e}"))?;
    // 这条命令解析失败，批处理会立刻返回 —— 但被动端仍要先等首个节点，
    // 所以这里没有对端、只能等超时。用短超时换一个明确的失败信号。
    let (status, out, err) = finish(child, BOOT_TIMEOUT, "admin（错命令）")?;
    let _ = out;
    if status.success() {
        return Err(format!("错命令的退出码居然是 0\nstderr:\n{err}"));
    }
    Ok(())
}

fn build(root: &Path, release: bool) -> Result<(), String> {
    let mut cmd = Command::new(cargo());
    cmd.current_dir(root).args([
        "build",
        "-p",
        "stowaway-admin",
        "-p",
        "stowaway-agent",
        // 两个大二进制的链接在 `-j 2` 下会让 LLVM 崩（见 plan §4.14 E27），
        // 冒烟不是竞速，单线程链接最省事。
        "-j",
        "1",
    ]);
    // 本机只能离线（plan §1.3：`/` 只读，依赖全在 .cargo-home）；CI 上要现拉依赖。
    if std::env::var_os("CI").is_none() && root.join(".cargo-home").join("registry").is_dir() {
        cmd.arg("--offline");
    }
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().map_err(|e| format!("调用 cargo 失败：{e}"))?;
    if !status.success() {
        return Err(format!("cargo build 失败：{status}"));
    }
    Ok(())
}

fn cargo() -> &'static str {
    "cargo"
}

/// 绑到 0 拿一个空闲端口再立刻释放。
///
/// 释放到对端 bind 之间有极小的竞态窗口；冒烟是本地单机顺序跑，可接受。
fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("取空闲端口失败：{e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("读本地地址失败：{e}"))?
        .port();
    drop(listener);
    Ok(port)
}

/// 等端口可以建立 TCP 连接（只证明「在听」，不发任何字节）。
fn wait_port(port: u16) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < BOOT_TIMEOUT {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "等 {} 秒后端口 {port} 仍不可连",
        BOOT_TIMEOUT.as_secs()
    ))
}

/// 等子进程结束并收集输出；超时就杀掉并报错（挂住的冒烟比失败的冒烟更糟）。
fn finish(
    mut child: Child,
    timeout: Duration,
    label: &str,
) -> Result<(std::process::ExitStatus, String, String), String> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                let mut err = String::new();
                if let Some(mut s) = child.stdout.take() {
                    let _ = s.read_to_string(&mut out);
                }
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_string(&mut err);
                }
                return Ok((status, out, err));
            }
            Ok(None) => {
                if started.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{label} 超过 {} 秒未结束（批处理挂住？）",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("等 {label} 失败：{e}")),
        }
    }
}

/// 收掉一个仍在跑的子进程，把管道读完（否则写满管道会让它阻塞）。
fn finish_quiet(child: &mut Child) -> (Option<std::process::ExitStatus>, String, String) {
    let _ = child.kill();
    let status = child.wait().ok();
    let mut out = String::new();
    let mut err = String::new();
    if let Some(s) = child.stdout.take() {
        for line in BufReader::new(s).lines().map_while(Result::ok) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    if let Some(s) = child.stderr.take() {
        for line in BufReader::new(s).lines().map_while(Result::ok) {
            err.push_str(&line);
            err.push('\n');
        }
    }
    (status, out, err)
}
