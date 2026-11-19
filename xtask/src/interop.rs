//! `fetch-go-baseline`：为 plan.md §8.4 的「Go 黑盒行为对照」预构建 v1 基线二进制。
//!
//! v2 与 v1 的线协议**不兼容**（plan.md §0 的 D1），因此 `tests/interop` 只能
//! 拿**预编译好的 Go 二进制**做行为对照（退出码、输出规约、分片大小、编码），
//! 而不是让 Rust 节点去跟 Go 节点握手。本子命令负责那一步预构建：
//!
//! ```text
//! cargo xtask fetch-go-baseline
//!   -> target/interop-baseline/stowaway-agent-go
//!   -> target/interop-baseline/stowaway-admin-go
//! ```
//!
//! 两个产物都从 v1 源码（默认 `/root/workspace/coding/Stowaway`）的 `./agent`
//! 与 `./admin` 两个包构建，编译期不依赖本仓库的任何 crate。
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// 默认 v1 源码目录。与 `doccheck` 的 `STOWAWAY_GO_BASELINE` 同一口径，
/// 但用独立变量名：一个是「文档引用核对」，一个是「基线二进制构建」。
const DEFAULT_SOURCE: &str = "/root/workspace/coding/Stowaway";

/// 兜底 Go 工具链路径（plan.md §1.3：`/opt/go/bin` 不一定在 `PATH` 里）。
const FALLBACK_GO: &str = "/opt/go/bin/go";

/// 需要构建的两个包：`(包路径, 产物名)`。
///
/// 产物名与 `docs/plan.md` §8.4 的约定一致（`stowaway-<side>-go`），刻意**不**
/// 沿用 v1 `Makefile` 的 `release/<plat>_<side>`：这里是「对照用的基线」，不是
/// 发布物，放在 `target/` 下与构建缓存同生命周期。
const SIDES: [(&str, &str); 2] = [
    ("./agent", "stowaway-agent-go"),
    ("./admin", "stowaway-admin-go"),
];

/// 子命令帮助（`cargo xtask fetch-go-baseline --help`）。
pub fn print_help() {
    println!(
        r#"fetch-go-baseline 用法：
  cargo xtask fetch-go-baseline [选项]

为 plan.md §8.4 的 Go 黑盒行为对照预构建 v1 基线二进制。v2 与 v1 线协议不兼容
（§0 的 D1），所以 `crates/stowaway-core/tests/interop.rs` 不能与 Go 节点握手，
只能拿预编译产物对照**行为**（退出码 / 输出规约 / 分片大小 / 编码）。

构建内容（在 <source> 下执行，`GOFLAGS=-mod=mod`、`CGO_ENABLED=0`）：
  ./agent  ->  <out>/stowaway-agent-go
  ./admin  ->  <out>/stowaway-admin-go

选项：
  --source <dir>  v1 源码目录，默认取环境变量 STOWAWAY_GO_SOURCE，
                  再默认 /root/workspace/coding/Stowaway
  --out <dir>     产物目录，默认 target/interop-baseline（相对仓库根）
  --force         产物已存在时仍然重建（默认跳过并打一行说明）
  -h, --help      显示本帮助

工具链：优先用 PATH 里的 `go`，否则用 /opt/go/bin/go；都没有则报
「需要 Go 工具链（v1 基线是 Go 项目）」并以失败退出。

测试侧读取环境变量 STOWAWAY_INTEROP_BASELINE（默认 target/interop-baseline）；
二进制缺失或无法执行时，`tests/interop.rs` 的每条测试都跳过并打印原因
（plan.md §9 风险表的口径），不把「本机没有 Go」变成红灯。"#
    );
}

/// 解析后的配置。私有：只在本模块内流转。
#[derive(Debug)]
struct Config {
    source: PathBuf,
    out: PathBuf,
    force: bool,
}

#[derive(Debug)]
enum Parsed {
    Help,
    Run(Config),
}

/// 子命令入口（`main.rs` 的 `match task` 调用）。
pub fn fetch(root: &Path, args: &[String]) -> ExitCode {
    let cfg = match parse(root, args) {
        Ok(Parsed::Help) => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Ok(Parsed::Run(cfg)) => cfg,
        Err(e) => {
            eprintln!(
                "fetch-go-baseline: {e}（用 `cargo xtask fetch-go-baseline --help` 查看用法）"
            );
            return ExitCode::FAILURE;
        }
    };
    run(root, &cfg)
}

fn parse(root: &Path, args: &[String]) -> Result<Parsed, String> {
    let mut source: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut force = false;
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--force" => force = true,
            "--source" => {
                let v = args
                    .get(i + 1)
                    .ok_or("`--source` 需要一个目录参数".to_string())?;
                source = Some(resolve(root, v));
                i += 1;
            }
            "--out" => {
                let v = args
                    .get(i + 1)
                    .ok_or("`--out` 需要一个目录参数".to_string())?;
                out = Some(resolve(root, v));
                i += 1;
            }
            other if other.starts_with("--source=") => {
                source = Some(resolve(root, &other["--source=".len()..]));
            }
            other if other.starts_with("--out=") => {
                out = Some(resolve(root, &other["--out=".len()..]));
            }
            other => return Err(format!("未知参数 `{other}`")),
        }
        i += 1;
    }
    let source = source.unwrap_or_else(|| {
        std::env::var_os("STOWAWAY_GO_SOURCE")
            .map_or_else(|| PathBuf::from(DEFAULT_SOURCE), PathBuf::from)
    });
    // 默认产物目录与测试侧的 `target/interop-baseline` 默认值必须一致。
    let out = out.unwrap_or_else(|| root.join("target").join("interop-baseline"));
    Ok(Parsed::Run(Config { source, out, force }))
}

/// 相对路径一律相对**仓库根**解析（调用方可能在任意 `cwd` 下跑 xtask）。
fn resolve(root: &Path, value: &str) -> PathBuf {
    let p = PathBuf::from(value);
    if p.is_absolute() { p } else { root.join(p) }
}

fn run(root: &Path, cfg: &Config) -> ExitCode {
    if !cfg.source.is_dir() {
        eprintln!(
            "fetch-go-baseline: Go 基线源码目录不存在：{}（用 `--source <dir>` 或环境变量 STOWAWAY_GO_SOURCE 指定）",
            cfg.source.display()
        );
        return ExitCode::FAILURE;
    }
    let (go, go_version) = match find_go() {
        Ok(found) => found,
        Err(e) => {
            eprintln!("fetch-go-baseline: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "fetch-go-baseline: go = {go}（{go_version}），source = {}",
        cfg.source.display()
    );
    if let Err(e) = std::fs::create_dir_all(&cfg.out) {
        eprintln!(
            "fetch-go-baseline: 无法创建产物目录 {}：{e}",
            cfg.out.display()
        );
        return ExitCode::FAILURE;
    }

    let mut built: Vec<PathBuf> = Vec::new();
    for (pkg, name) in SIDES {
        let dest = cfg.out.join(name);
        if dest.is_file() && !cfg.force {
            println!(
                "fetch-go-baseline: 跳过 {name}（{} 已存在，用 --force 重建）",
                display(root, &dest)
            );
            built.push(dest);
            continue;
        }
        println!(
            "fetch-go-baseline: $ {go} build -o {} {pkg}（cwd={}）",
            display(root, &dest),
            cfg.source.display()
        );
        let output = Command::new(&go)
            .arg("build")
            .arg("-o")
            .arg(&dest)
            .arg(pkg)
            .current_dir(&cfg.source)
            .env("GOFLAGS", "-mod=mod")
            .env("CGO_ENABLED", "0")
            .output();
        let output = match output {
            Ok(o) => o,
            Err(e) => {
                eprintln!("fetch-go-baseline: 无法执行 `{go}`：{e}");
                return ExitCode::FAILURE;
            }
        };
        if !output.status.success() {
            eprintln!(
                "fetch-go-baseline: `go build {pkg}` 失败（退出码 {}）",
                output
                    .status
                    .code()
                    .map_or_else(|| "信号".to_string(), |c| c.to_string())
            );
            for line in tail(&output.stderr, 20) {
                eprintln!("  | {line}");
            }
            return ExitCode::FAILURE;
        }
        // `go build -o <file> <pkg>` 在包是 main 时必定落盘；仍显式核对一次，
        // 避免「go 成功但产物在别处」被误当成功。
        if !dest.is_file() {
            eprintln!(
                "fetch-go-baseline: `go build {pkg}` 成功但找不到产物 {}",
                display(root, &dest)
            );
            return ExitCode::FAILURE;
        }
        built.push(dest);
    }

    let paths: Vec<String> = built.iter().map(|p| display(root, p)).collect();
    println!("fetch-go-baseline: ok {}", paths.join(" "));
    ExitCode::SUCCESS
}

/// 找 Go 工具链：`PATH` 里的 `go` 优先，其次 `/opt/go/bin/go`。
///
/// 两者都不行时**不是**「跳过」而是**失败**：本子命令的语义就是「把基线构建
/// 出来」，缺工具链属于环境问题，应当让调用方看见。
fn find_go() -> Result<(String, String), String> {
    for candidate in ["go", FALLBACK_GO] {
        if let Ok(o) = Command::new(candidate).arg("version").output()
            && o.status.success()
        {
            let version = String::from_utf8_lossy(&o.stdout).trim().to_string();
            return Ok((candidate.to_string(), version));
        }
    }
    Err(format!(
        "需要 Go 工具链（v1 基线是 Go 项目）：`PATH` 里没有可用的 `go`，{FALLBACK_GO} 也不可用"
    ))
}

/// stderr 末尾若干行（Go 的编译错误摘要就在末尾）。
fn tail(stderr: &[u8], n: usize) -> Vec<String> {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .map(|l| (*l).to_string())
        .collect()
}

fn display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}
