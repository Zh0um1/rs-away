//! 仓库自带任务运行器（plan.md §4.13 / §10 G5）。
//!
//! 用法：`cargo xtask <任务>`，任务定义见 `docs/plan.md` §8.6。
//! 这是一个**无第三方依赖**的最小实现，避免 `xtask` 拖慢 workspace 构建。
use std::process::{Command, ExitCode};

/// `fetch-go-baseline`：为 plan.md §8.4 的 Go 黑盒行为对照预构建 v1 基线二进制。
mod interop;

/// `smoke`：`--non-interactive` 的双进程冒烟（plan.md §7 P7 出口判据）。
mod smoke;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let task = args.first().map(String::as_str).unwrap_or("help");
    match task {
        "check" => run_check(),
        "fmt" => sh_status("cargo", &["fmt", "--all", "--check"]),
        "clippy" => sh_status(
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        "test" => test(),
        "doccheck" => run_doccheck(),
        "no-panic" => run_no_panic(),
        "no-unsafe" => run_no_unsafe(),
        "build-matrix" => run_build_matrix(&args[1..]),
        "fetch-go-baseline" => interop::fetch(&repo_root(), &args[1..]),
        "smoke" => smoke::run(&repo_root(), &args[1..]),
        "help" | "-h" | "--help" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("xtask: 未知任务 `{other}`（用 `cargo xtask help` 查看）");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        r#"xtask 任务：
  check       fmt --check + clippy + test + no-panic（提交前必跑，plan.md §10 G5.4）
  fmt         cargo fmt --all --check
  clippy      cargo clippy --workspace --all-targets --all-features -- -D warnings
  test        cargo test --workspace --all-features
  doccheck    校验 docs/**.md 内所有 `path/to/file.go:LINE` 引用有效
  no-panic    校验 crates/*/src 的非测试代码里没有 panic 类构造
  no-unsafe   校验 protocol/crypto/transport 三 crate 的 unsafe 计数为 0（§8.6 第六条）
  build-matrix 按 plan.md §4.13 的 11 个 blocking 组合交叉编译出包（`cargo xtask build-matrix --help`）
  fetch-go-baseline  预构建 Go v1 基线二进制（§8.4 行为对照用，`cargo xtask fetch-go-baseline --help`）
  smoke       两个真二进制的 `--non-interactive` 冒烟（§7 P7 出口判据，`cargo xtask smoke --help`）
  help        显示本帮助"#
    );
}

fn run_check() -> ExitCode {
    for (label, argv) in [
        ("fmt", vec!["fmt", "--all", "--check"]),
        (
            "clippy",
            vec![
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("test", vec!["test", "--workspace", "--all-features"]),
    ] {
        eprintln!("==> {label}");
        if sh_status("cargo", &argv) != ExitCode::SUCCESS {
            eprintln!("xtask check: {label} 失败");
            return ExitCode::FAILURE;
        }
    }
    eprintln!("==> no-panic");
    if run_no_panic() != ExitCode::SUCCESS {
        eprintln!("xtask check: no-panic 失败");
        return ExitCode::FAILURE;
    }
    eprintln!("==> no-unsafe");
    if run_no_unsafe() != ExitCode::SUCCESS {
        eprintln!("xtask check: no-unsafe 失败");
        return ExitCode::FAILURE;
    }
    eprintln!("xtask check: 全部通过");
    ExitCode::SUCCESS
}

fn test() -> ExitCode {
    sh_status("cargo", &["test", "--workspace", "--all-features"])
}

fn sh_status(prog: &str, argv: &[&str]) -> ExitCode {
    match Command::new(prog).args(argv).status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => {
            eprintln!("命令 `{prog} {}` 失败：{s}", argv.join(" "));
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("无法执行 `{prog}`：{e}");
            ExitCode::FAILURE
        }
    }
}

/// `doccheck`：把 `docs/**.md` 里每个 `path/to/file.go:LINE` 形式的源码引用拿到
/// Go 基线仓库核对「文件存在且该行非空」。P0 起取代 `scripts/doccheck.sh`，
/// 行为与退出码保持一致（plan.md §10 G8）。
fn run_doccheck() -> ExitCode {
    let baseline = std::env::var("STOWAWAY_GO_BASELINE")
        .unwrap_or_else(|_| "/root/workspace/coding/Stowaway".to_string());
    let root = repo_root();
    match doccheck::run(&root.join("docs"), std::path::Path::new(&baseline)) {
        Ok((total, bad)) => {
            println!("doccheck: 共检查 {total} 个引用，失效 {bad} 个");
            if bad == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("doccheck: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `no-panic`：plan.md §8.6 的 DoD 条款。生产代码（`crates/*/src` 中
/// `#[cfg(test)]` 之前的部分）不得出现 `unwrap()` / `expect(` / `panic!` /
/// `todo!` / `unimplemented!` / `unreachable!`，除非该行带 `// assert-ok` 注释
/// 说明「恒不成立」。集成测试（`tests/`）不受此限。
fn run_no_panic() -> ExitCode {
    let root = repo_root();
    let mut files = Vec::new();
    for name in ["protocol", "crypto", "transport", "core", "admin", "agent"] {
        let src = root
            .join("crates")
            .join(format!("stowaway-{name}"))
            .join("src");
        collect_rs(&src, &mut files);
    }
    files.sort();

    // `expect(` 必须带前导点：否则 `fn recv_expect(` 这类**名字里含 expect** 的
    // 正常函数定义会被误报（P2 实际踩到）。
    const PATTERNS: [&str; 6] = [
        "unwrap()",
        ".expect(",
        "panic!(",
        "todo!(",
        "unimplemented!(",
        "unreachable!(",
    ];
    let mut violations = 0usize;
    for file in &files {
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("no-panic: 读取 {} 失败：{e}", file.display());
                return ExitCode::FAILURE;
            }
        };
        for (idx, line) in text.lines().enumerate() {
            // `#[cfg(test)]` 之后全是测试模块，不在 DoD 范围内。
            if line.trim() == "#[cfg(test)]" {
                break;
            }
            if line.contains("// assert-ok") {
                continue;
            }
            if PATTERNS.iter().any(|p| line.contains(p)) {
                let rel = file.strip_prefix(&root).unwrap_or(file);
                println!(
                    "NO-PANIC      {}:{}  {}",
                    rel.display(),
                    idx + 1,
                    line.trim()
                );
                violations += 1;
            }
        }
    }
    if violations == 0 {
        println!("no-panic: {} 个源文件，0 处命中", files.len());
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "no-panic: {violations} 处违规（加 `// assert-ok` 说明为何恒不成立，或改用 Result）"
        );
        ExitCode::FAILURE
    }
}

/// `no-unsafe`：plan.md §8.6 第六条 DoD。
///
/// 判据本身是**`cargo geiger`**。本命令优先直接调用它：对三个受门禁的 crate 分别
/// 跑 `cargo geiger --output-format Json`，解析 `packages[].unsafety.used`，要求
/// ① `forbids_unsafe == true`（`#![forbid(unsafe_code)]` 真的在生效）且
/// ② 五类 unsafe 计数（functions / exprs / item_impls / item_traits / methods）全为 0。
///
/// 注意**不能看 `cargo geiger` 的退出码**：本仓库的 manifest 里 `lints.cargo` 是
///  nightly 才支持的表键，稳定版 cargo 会报 8 条 `unused manifest key` 警告，geiger
/// 因此以 1 退出——而这三行警告与被检查对象无关。因此这里只信 JSON 里的计数。
///
/// **回退**：`cargo-geiger` 不可用（CI 上没装、或用户改用最小工具链）时，退到自建
/// 扫描器：对每个 crate 的 `src/` 逐行统计**真正构成 unsafe 作用域**的构造 ——
/// `unsafe {`、`unsafe fn`、`unsafe impl`、`unsafe trait`、`extern "C"`。两条路径
/// 的判据一致（都是「受门禁的三个 crate 计数为 0」），只是精度不同：geiger 走的是
/// 编译器 HIR，扫描器走的是文本。
///
/// 与 `no-panic` 的两点差异，都是**有意**的：
/// 1. 扫**全部**行，遇到 `#[cfg(test)]` 不提前退出 —— `unsafe` 不能用「在测试里」豁免，
///    测试代码里的 unsafe 同样进产物；
/// 2. 注释里提到 unsafe（例如 `// 本 crate 禁 unsafe`）不算命中，因为判据是「去掉注释
///    与文档后还剩什么」：行首或空白之后紧跟 `//`、`///`、`//!` 的行直接跳过。
///
/// `#![forbid(unsafe_code)]` / `unsafe_op_in_unsafe_fn` 是**禁用声明**，不是使用，
/// 出现它们本身应被跳过（否则每个 crate 都会永远报 1 处）。
fn run_no_unsafe() -> ExitCode {
    if let Some(code) = run_no_unsafe_via_geiger() {
        return code;
    }
    println!("no-unsafe: 未找到 `cargo-geiger`，回退到内置扫描器（判据相同，精度不同）");
    run_no_unsafe_scan()
}

/// plan.md §8.6：protocol / crypto / transport 三个 crate 的 unsafe 计数必须为 0。
/// core 及以上允许出现平台相关 unsafe（目前也确为 0），单独统计但不作为门禁。
const NO_UNSAFE_GATED: [&str; 3] = ["protocol", "crypto", "transport"];
const NO_UNSAFE_REPORTED: [&str; 3] = ["core", "admin", "agent"];

/// 用 `cargo geiger` 做门禁。返回 `None` 表示 geiger 不可用（交给扫描器兜底）。
fn run_no_unsafe_via_geiger() -> Option<ExitCode> {
    let root = repo_root();
    // geiger 0.14 不接受 virtual manifest（workspace 根），必须进到各 crate 目录里跑。
    let mut gated_violations = 0usize;
    let mut reported_violations = 0usize;
    for name in NO_UNSAFE_GATED.into_iter().chain(NO_UNSAFE_REPORTED) {
        let crate_dir = root.join("crates").join(format!("stowaway-{name}"));
        let gated = NO_UNSAFE_GATED.contains(&name);
        let out = match Command::new("cargo")
            .args(["geiger", "--offline", "--output-format", "Json"])
            .current_dir(&crate_dir)
            .output()
        {
            Ok(o) => o,
            // 命令本身跑不起来（没装 geiger）：交给扫描器。
            Err(_) => return None,
        };
        // `cargo geiger` 在「子命令不存在」时以 101 退出并在 stderr 里说明；
        // 这里只把「完全解析不出 JSON」当作不可用，其余照常解析。
        let stdout = String::from_utf8_lossy(&out.stdout);
        let metrics = parse_geiger_crate(&stdout, &format!("stowaway-{name}"))?;
        let (forbids, total) = metrics;
        let count = total as usize;
        if gated {
            gated_violations += count;
            if !forbids {
                eprintln!(
                    "no-unsafe: stowaway-{name} 的 `#![forbid(unsafe_code)]` 未生效（cargo geiger 报告 forbids_unsafe=false）"
                );
                gated_violations += 1;
            }
        } else {
            reported_violations += count;
        }
        println!(
            "no-unsafe: stowaway-{name}: {count} 处 unsafe（forbids_unsafe={forbids}）{} [cargo geiger]",
            if gated {
                "（门禁）"
            } else {
                "（仅统计）"
            }
        );
    }
    if gated_violations == 0 {
        println!(
            "no-unsafe: cargo geiger 判定 —— 受门禁的三个 crate 0 处 unsafe 且 forbid 生效（其余 crate 共 {reported_violations} 处）"
        );
        Some(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "no-unsafe: 受门禁的 crate 有 {gated_violations} 处问题（plan.md §8.6 要求为 0）"
        );
        Some(ExitCode::FAILURE)
    }
}

/// 从 `cargo geiger --output-format Json` 的 stdout 里取出目标 crate 的
/// `(forbids_unsafe, unsafe 总数)`。解析不出（JSON 结构变了、crate 不在结果里）返回
/// `None`，让调用方退回扫描器 —— **宁可换实现，也不要静默当成 0**。
fn parse_geiger_crate(stdout: &str, crate_name: &str) -> Option<(bool, u64)> {
    // geiger 会把别的东西混进 stdout 吗？目前不会，但 cargo 的 warning 走 stderr，
    // 这里仍然从第一个 `{` 开始截，避免前置杂讯让解析整体失败。
    let start = stdout.find('{')?;
    let value: serde_json::Value = serde_json::from_str(&stdout[start..]).ok()?;
    let packages = value.get("packages")?.as_array()?;
    let entry = packages.iter().find(|p| {
        p.pointer("/package/id/name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name == crate_name)
    })?;
    let forbids = entry
        .pointer("/unsafety/forbids_unsafe")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    // 五类计数各自是 `{"safe": n, "unsafe_": n}`。
    let used = entry.pointer("/unsafety/used")?;
    let mut total = 0u64;
    for key in ["functions", "exprs", "item_impls", "item_traits", "methods"] {
        total += used.pointer(&format!("/{key}/unsafe_"))?.as_u64()?;
    }
    Some((forbids, total))
}

/// `no-unsafe`：plan.md §8.6 第六条的**回退**实现（`cargo-geiger` 不可用时）。
fn run_no_unsafe_scan() -> ExitCode {
    let root = repo_root();
    let mut total_files = 0usize;
    let mut gated_violations = 0usize;
    let mut reported_violations = 0usize;
    for name in NO_UNSAFE_GATED.into_iter().chain(NO_UNSAFE_REPORTED) {
        let src = root
            .join("crates")
            .join(format!("stowaway-{name}"))
            .join("src");
        let mut files = Vec::new();
        collect_rs(&src, &mut files);
        files.sort();
        total_files += files.len();
        let gated = NO_UNSAFE_GATED.contains(&name);
        let mut count = 0usize;
        for file in &files {
            let text = match std::fs::read_to_string(file) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("no-unsafe: 读取 {} 失败：{e}", file.display());
                    return ExitCode::FAILURE;
                }
            };
            for (idx, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                // 注释与文档不构成 unsafe 作用域。
                if trimmed.starts_with("//")
                    || trimmed.starts_with("/*")
                    || trimmed.starts_with('*')
                {
                    continue;
                }
                // `#![forbid(unsafe_code)]` 之类是禁用声明，不是使用。
                if trimmed.contains("forbid(unsafe_code)")
                    || trimmed.contains("deny(unsafe_op_in_unsafe_fn")
                    || trimmed.contains("unsafe_op_in_unsafe_fn")
                {
                    continue;
                }
                if UNSAFE_FORMS.iter().any(|p| trimmed.contains(p)) {
                    let rel = file.strip_prefix(&root).unwrap_or(file);
                    println!("NO-UNSAFE     {}:{}  {}", rel.display(), idx + 1, trimmed);
                    count += 1;
                }
            }
        }
        if gated {
            gated_violations += count;
        } else {
            reported_violations += count;
        }
        println!(
            "no-unsafe: stowaway-{name}: {count} 处{}",
            if gated {
                "（门禁）"
            } else {
                "（仅统计）"
            }
        );
    }
    if gated_violations == 0 {
        println!(
            "no-unsafe: {total_files} 个源文件，受门禁的三个 crate 0 处 unsafe（其余 crate 共 {reported_violations} 处）"
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "no-unsafe: 受门禁的 crate 有 {gated_violations} 处 unsafe（plan.md §8.6 要求为 0）"
        );
        ExitCode::FAILURE
    }
}

/// 真正构成 unsafe 作用域的语法形态（不含注释里提到的 `unsafe`）。
const UNSAFE_FORMS: [&str; 5] = [
    "unsafe {",
    "unsafe fn ",
    "unsafe impl",
    "unsafe trait",
    "extern \"C\"",
];

fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

/// `build-matrix`：按 plan.md §4.13 的 11 个 blocking 组合交叉编译出包。
fn run_build_matrix(args: &[String]) -> ExitCode {
    let cfg = match build_matrix::parse(args) {
        Ok(build_matrix::Parsed::Help) => {
            build_matrix::print_help();
            return ExitCode::SUCCESS;
        }
        Ok(build_matrix::Parsed::Run(cfg)) => cfg,
        Err(e) => {
            eprintln!("build-matrix: {e}（用 `cargo xtask build-matrix --help` 查看用法）");
            return ExitCode::FAILURE;
        }
    };
    build_matrix::run(&repo_root(), &cfg)
}

fn repo_root() -> std::path::PathBuf {
    // xtask 由 workspace 根目录调用；`CARGO_MANIFEST_DIR` 指向 xtask/ 本身。
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap_or(manifest).to_path_buf()
}

mod doccheck {
    use std::collections::BTreeSet;
    use std::path::Path;

    /// 收集 `path/to/x.go:123` 形式的引用并逐条校验，返回（总数，失效数）。
    pub fn run(docs: &Path, baseline: &Path) -> std::io::Result<(usize, usize)> {
        if !baseline.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Go 基线目录不存在：{}", baseline.display()),
            ));
        }
        let mut refs: BTreeSet<String> = BTreeSet::new();
        for path in walk_md(docs)? {
            let text = std::fs::read_to_string(&path)?;
            for r in extract_refs(&text) {
                refs.insert(r);
            }
        }
        let mut bad = 0usize;
        for r in &refs {
            let (file, line) = r.split_once(':').expect("已由正则保证含冒号");
            let line: usize = line
                .split('-')
                .next()
                .and_then(|s| s.parse().ok())
                .expect("已由正则保证是数字");
            let target = baseline.join(file);
            if !target.is_file() {
                println!("MISSING-FILE  {r}  (无此文件: {file})");
                bad += 1;
                continue;
            }
            let content = std::fs::read_to_string(&target)?;
            let hit = content.lines().nth(line - 1).unwrap_or("").trim();
            if hit.is_empty() {
                println!("EMPTY-LINE    {r}  (该行为空或超出文件末尾)");
                bad += 1;
            }
        }
        Ok((refs.len(), bad))
    }

    fn walk_md(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            if !d.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(&d)? {
                let p = entry?.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|e| e.to_str()) == Some("md") {
                    out.push(p);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// 无正则依赖的最小提取器：匹配 `IDENT/...` 段后跟 `.go:` 与十进制行号。
    fn extract_refs(text: &str) -> Vec<String> {
        let bytes: Vec<char> = text.chars().collect();
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            if !is_path_char(bytes[i]) || is_upper_start(&bytes, i) {
                i += 1;
                continue;
            }
            let start = i;
            let mut j = i;
            while j < bytes.len() && is_path_char(bytes[j]) {
                j += 1;
            }
            if j >= bytes.len() || bytes[j] != ':' {
                i = start + 1;
                continue;
            }
            let candidate: String = bytes[start..j].iter().collect();
            if candidate.contains('/') && candidate.ends_with(".go") {
                let mut k = j + 1;
                let line_start = k;
                while k < bytes.len() && (bytes[k].is_ascii_digit() || bytes[k] == '-') {
                    k += 1;
                }
                if k > line_start {
                    let line: String = bytes[line_start..k].iter().collect();
                    if line.ends_with('-') {
                        k -= 1;
                    }
                    out.push(format!(
                        "{candidate}:{}",
                        &line[..line.trim_end_matches('-').len()]
                    ));
                    i = k;
                    continue;
                }
            }
            i = start + 1;
        }
        out
    }

    fn is_path_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '/' || c == '_' || c == '.' || c == '-'
    }

    /// 排除 `See/Foo.go:12` 这类大写开头的词法噪声（本仓库引用全是小写路径）。
    fn is_upper_start(chars: &[char], i: usize) -> bool {
        !chars[i].is_ascii_lowercase()
    }
}

/// `build-matrix`：plan.md §4.13 的 11 个 blocking OS-ARCH 组合。
///
/// 产物命名以 **Go 原版 Makefile** 为准（`release/linux_x64_agent`、
/// `release/windows_x64_admin.exe`、`release/arm_eabi5_agent`、`release/mipsel_agent`、
/// `release/freebsd_x86_agent`、`release/freebsd_arm_agent` …），即
/// `release/<plat>_<side>`；`docs/plan.md` §4.13 文中的 `agent_linux_x64` 是同一名字的
/// 反序写法，本任务额外建一个硬链接别名，避免文档与实际产物对不上。
mod build_matrix {
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode};

    /// 11 个 blocking 组合。`plat` 段逐条对照 Go 版 `Makefile` 的 `-o` 参数。
    static MATRIX: [Combo; 11] = [
        Combo {
            os: "linux",
            arch: "x86_64",
            triple: "x86_64-unknown-linux-gnu",
            plat: "linux_x64",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "linux",
            arch: "i686",
            triple: "i686-unknown-linux-gnu",
            plat: "linux_x86",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "linux",
            arch: "aarch64",
            triple: "aarch64-unknown-linux-gnu",
            plat: "linux_arm64",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "linux",
            arch: "arm",
            triple: "armv5te-unknown-linux-musleabi",
            plat: "arm_eabi5",
            agent: true,
            admin: false,
            tier3: true,
            builder: Builder::Cross,
        },
        Combo {
            os: "linux",
            arch: "mipsle",
            triple: "mipsel-unknown-linux-musl",
            plat: "mipsel",
            agent: true,
            admin: false,
            tier3: true,
            builder: Builder::Zigbuild,
        },
        Combo {
            os: "darwin",
            arch: "x86_64",
            triple: "x86_64-apple-darwin",
            plat: "macos_x64",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "darwin",
            arch: "aarch64",
            triple: "aarch64-apple-darwin",
            plat: "macos_arm64",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "windows",
            arch: "x86_64",
            triple: "x86_64-pc-windows-gnu",
            plat: "windows_x64",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "windows",
            arch: "i686",
            triple: "i686-pc-windows-gnu",
            plat: "windows_x86",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "freebsd",
            arch: "i686",
            triple: "i686-unknown-freebsd",
            plat: "freebsd_x86",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            // Go 版是 `GOOS=freebsd GOARCH=arm GOARM=5`；Rust 侧最低可选目标是 armv6。
            os: "freebsd",
            arch: "arm",
            triple: "armv6-unknown-freebsd",
            plat: "freebsd_arm",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
    ];

    /// 宿主 musl 组合（plan §4.13 的 best-effort 档，**不进 blocking 清单**）。
    ///
    /// 本地验证只跑这一档：11 个 blocking 组合交给 CI 证明——本机 `/` 只读
    /// （plan §1.3），连 `rustup target add` 都会失败，本地重复交叉编译既装不上
    /// target，也不可能比 CI 更有说服力。musl 静态链接是本地唯一能真实验证的形态。
    static MUSL_MATRIX: [Combo; 4] = [
        Combo {
            os: "linux",
            arch: "x86_64-musl",
            triple: "x86_64-unknown-linux-musl",
            plat: "linux_x64_musl",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "linux",
            arch: "i686-musl",
            triple: "i686-unknown-linux-musl",
            plat: "linux_x86_musl",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "linux",
            arch: "aarch64-musl",
            triple: "aarch64-unknown-linux-musl",
            plat: "linux_arm64_musl",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
        Combo {
            os: "linux",
            arch: "arm-musleabihf",
            triple: "armv7-unknown-linux-musleabihf",
            plat: "linux_armv7_musl",
            agent: true,
            admin: true,
            tier3: false,
            builder: Builder::Cargo,
        },
    ];

    /// 谁来执行交叉编译。这三者不是「哪个更好」，而是实测出来的分工
    /// （plan §4.14 E34）：同一套 `RUSTFLAGS` 在不同 sysroot 上方向相反，
    /// 所以按目标各自选一个能出静态发布形态的驱动器，比统一硬凑一套配方可靠。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Builder {
        /// 宿主/官方 target 直接 `cargo build`（CI 里由 job 预先 `rustup target add`）。
        Cargo,
        /// `cross`（容器内 crosstool-ng sysroot）。armv5te 裸跑即静态 EXEC。
        Cross,
        /// `cargo-zigbuild`（zig 自带 libc）。mipsel 裸跑即 static-pie、无 INTERP。
        Zigbuild,
    }

    impl Builder {
        /// 产物目录里用的名字（也是 `--dry-run` 打印的命令名）。
        const fn label(self) -> &'static str {
            match self {
                Self::Cargo => "cargo",
                Self::Cross => "cross",
                Self::Zigbuild => "zigbuild",
            }
        }

        /// 需要通过 `PATH` 找的可执行文件；`Cargo` 用 rustup 装的 `cargo`，不查。
        const fn command(self) -> Option<&'static str> {
            match self {
                Self::Cargo => None,
                Self::Cross => Some("cross"),
                Self::Zigbuild => Some("cargo-zigbuild"),
            }
        }
    }

    #[derive(Debug)]
    struct Combo {
        os: &'static str,
        arch: &'static str,
        triple: &'static str,
        /// Go 版产物名的平台段（`release/<plat>_<side>`）。
        plat: &'static str,
        agent: bool,
        admin: bool,
        /// tier-3：std 无预编译产物，需 nightly + `-Z build-std`。
        tier3: bool,
        /// 这个组合由哪个驱动器编译（见 [`Builder`]）。
        builder: Builder,
    }

    impl Combo {
        fn artifact(&self, side: Side) -> String {
            let ext = if self.os == "windows" { ".exe" } else { "" };
            format!("{}_{}{}", self.plat, side.label(), ext)
        }

        fn supports(&self, side: Side) -> bool {
            match side {
                Side::Agent => self.agent,
                Side::Admin => self.admin,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Side {
        Agent,
        Admin,
    }

    impl Side {
        fn label(self) -> &'static str {
            match self {
                Side::Agent => "agent",
                Side::Admin => "admin",
            }
        }

        fn pkg(self) -> &'static str {
            match self {
                Side::Agent => "stowaway-agent",
                Side::Admin => "stowaway-admin",
            }
        }
    }

    #[derive(Debug)]
    pub struct Config {
        target: Option<String>,
        agent: bool,
        admin: bool,
        list: bool,
        dry_run: bool,
        out: Option<PathBuf>,
        /// `--local`：只跑「本地能验证」的那一档（宿主 musl），11 个 blocking
        /// 组合交给 CI。见 `MUSL_MATRIX` 的说明。
        local: bool,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                target: None,
                agent: true,
                admin: true,
                list: false,
                dry_run: false,
                out: None,
                local: false,
            }
        }
    }

    #[derive(Debug)]
    pub enum Parsed {
        Help,
        Run(Config),
    }

    pub fn parse(args: &[String]) -> Result<Parsed, String> {
        let mut cfg = Config::default();
        let mut only: Option<Side> = None;
        let mut i = 0usize;
        while i < args.len() {
            let a = args[i].as_str();
            match a {
                "-h" | "--help" => return Ok(Parsed::Help),
                "--list" => cfg.list = true,
                "--dry-run" => cfg.dry_run = true,
                "--local" => cfg.local = true,
                "--agent-only" | "--admin-only" => {
                    let side = if a == "--agent-only" {
                        Side::Agent
                    } else {
                        Side::Admin
                    };
                    if let Some(prev) = only
                        && prev != side
                    {
                        return Err("`--agent-only` 与 `--admin-only` 互斥".to_string());
                    }
                    only = Some(side);
                }
                "--target" => {
                    let v = args.get(i + 1).ok_or("`--target` 需要一个 triple")?;
                    cfg.target = Some(v.clone());
                    i += 1;
                }
                "--out" => {
                    let v = args.get(i + 1).ok_or("`--out` 需要一个目录")?;
                    cfg.out = Some(PathBuf::from(v));
                    i += 1;
                }
                other if other.starts_with("--target=") => {
                    cfg.target = Some(other["--target=".len()..].to_string());
                }
                other if other.starts_with("--out=") => {
                    cfg.out = Some(PathBuf::from(&other["--out=".len()..]));
                }
                other => return Err(format!("未知参数 `{other}`")),
            }
            i += 1;
        }
        match only {
            Some(Side::Agent) => {
                cfg.admin = false;
            }
            Some(Side::Admin) => {
                cfg.agent = false;
            }
            None => {}
        }
        Ok(Parsed::Run(cfg))
    }

    pub fn print_help() {
        println!(
            r#"build-matrix 用法：
  cargo xtask build-matrix [选项]

按 docs/plan.md §4.13 的 11 个 blocking OS-ARCH 组合交叉编译 agent / admin，
产物命名与 Go 原版 Makefile 对齐（release/linux_x64_agent、release/windows_x64_admin.exe、
release/arm_eabi5_agent、release/mipsel_agent、release/freebsd_x86_agent …）。

选项：
  --local             只跑宿主 musl 档（本地能真实验证的那几行），
                      blocking 的 11 个组合交给 CI；与 --target 互斥
  --target <triple>   只构建指定 target triple（不在矩阵里则报错）
  --agent-only        只构建 agent 侧
  --admin-only        只构建 admin 侧
  --list              只打印矩阵表（OS/ARCH/agent/admin/是否可用），不构建
  --dry-run           打印将要执行的命令，不执行
  --out <dir>         产物目录，默认 release/（相对仓库根）
  -h, --help          显示本帮助

本地与 CI 的分工（plan §4.13）：本机 `/` 只读，`rustup target add` 会失败，因此除了
已有的 x86_64-unknown-linux-gnu 与 -musl 之外一个 target 都装不上。`--local` 只跑
`MUSL_MATRIX`（宿主 musl 静态链接），11 个 blocking 组合由 CI 的 build-matrix job
在各自 runner 上交叉编译——那才是发布矩阵的证明地。

每个组合按 target 是否安装（`rustup target list --installed`）报三种状态：
  ok       构建成功，产物落在 --out 目录
  skipped  该 triple 未安装，或 tier-3 目标缺 nightly（**不算失败**）
  failed   构建失败，附最后的错误行；只要有一个「本应可用却失败」的组合，退出码非 0

tier-3（armv5te / mipsel）需 nightly + `-Z build-std`，并关掉 tls / ws / kcp（plan §4.13、
§9.1）。非 nightly 工具链上这两行直接报 skipped。"#
        );
    }

    #[derive(Debug)]
    struct Toolchain {
        installed: Vec<String>,
        installed_err: Option<String>,
        release: String,
        nightly: bool,
    }

    impl Toolchain {
        fn detect() -> Self {
            let mut installed_err = None;
            let installed = match Command::new("rustup")
                .args(["target", "list", "--installed"])
                .output()
            {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect(),
                Ok(o) => {
                    installed_err = Some(format!(
                        "rustup target list --installed 失败（{})",
                        o.status
                    ));
                    Vec::new()
                }
                Err(e) => {
                    installed_err = Some(format!("无法执行 rustup：{e}"));
                    Vec::new()
                }
            };
            // `rustc -vV` 的 `release:` 行是判断 nightly 的唯一依据（rustup 缺失时也不崩）。
            let rustc_vv = Command::new("rustc")
                .arg("-vV")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            let release = rustc_vv
                .lines()
                .find_map(|l| l.strip_prefix("release: "))
                .unwrap_or("unknown")
                .to_string();
            let nightly = release.contains("nightly");
            Self {
                installed,
                installed_err,
                release,
                nightly,
            }
        }

        fn has_target(&self, triple: &str) -> bool {
            self.installed.iter().any(|t| t == triple)
        }
    }

    /// 返回 `None` 表示可用；`Some(原因)` 表示按矩阵定义**本机不可用**（skipped）。
    fn unavailable(row: &Combo, tc: &Toolchain) -> Option<String> {
        let mut reasons = Vec::new();
        // tier-3 走 `-Z build-std`：std 由 nightly 从 rust-src **现场编译**，
        // 本来就不需要 `rustup target add`（也没有预编译件可装）。
        // 早期版本这里无条件要求已装 target，于是 CI 上「nightly 已就位、
        // rust-src 已装」的 tier-3 job 仍被判 skipped——判据被自己的前置条件挡死。
        if !row.tier3 && !tc.has_target(row.triple) {
            reasons.push(match &tc.installed_err {
                Some(e) => format!("该 triple 不可用（{e}）"),
                None => "`rustup target list --installed` 里没有该 triple".to_string(),
            });
        }
        if row.tier3 && !tc.nightly {
            reasons.push(format!(
                "tier-3 目标需 nightly + `-Z build-std`（当前工具链 {}）",
                tc.release
            ));
        }
        // 非 `Cargo` 驱动器要独立安装的可执行文件（cross / cargo-zigbuild）。
        // 缺了就跳过并说清缺失的是哪个命令，而不是让它走到 build_one 里报
        // `无法执行 \`cross\`` 那种「看起来像构建失败」的形态。
        if let Some(cmd) = row.builder.command().filter(|c| !have_command(c)) {
            reasons.push(format!(
                "缺少 `{cmd}` 命令（{}）",
                match row.builder {
                    Builder::Cross => "装 cross-rs 后才有，见 plan §4.13",
                    Builder::Zigbuild => "`pip install cargo-zigbuild` 后才有，见 plan §4.13",
                    Builder::Cargo => unreachable!(),
                }
            ));
        }
        if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("；"))
        }
    }

    /// `PATH` 里有没有这个可执行文件（不真的运行它——`cross --version` 要 1 秒起步）。
    fn have_command(name: &str) -> bool {
        let Some(paths) = std::env::var_os("PATH") else {
            return false;
        };
        std::env::split_paths(&paths).any(|dir| {
            let p = dir.join(name);
            p.is_file()
        })
    }

    pub fn run(root: &Path, cfg: &Config) -> ExitCode {
        // `--local` 换成宿主 musl 那一档；它与 `--target` 互斥（两个都在指定「跑哪几行」）。
        if cfg.local && cfg.target.is_some() {
            eprintln!("build-matrix: `--local` 与 `--target` 互斥");
            return ExitCode::FAILURE;
        }
        let table: &[Combo] = if cfg.local { &MUSL_MATRIX } else { &MATRIX };
        let combos: Vec<&'static Combo> = table
            .iter()
            .filter(|c| cfg.target.as_deref().is_none_or(|t| c.triple == t))
            .collect();
        if combos.is_empty() {
            let t = cfg.target.as_deref().unwrap_or("");
            let scope = if cfg.local {
                "本地 musl 档"
            } else {
                "plan §4.13 的 11 个 blocking 组合"
            };
            eprintln!("build-matrix: triple `{t}` 不在{scope}里（用 `--list` 查看）");
            return ExitCode::FAILURE;
        }

        let tc = Toolchain::detect();
        if cfg.list {
            print_list(&combos, &tc, cfg.local);
            return ExitCode::SUCCESS;
        }

        let out_dir = cfg.out.clone().unwrap_or_else(|| PathBuf::from("release"));
        let out_dir = if out_dir.is_absolute() {
            out_dir
        } else {
            root.join(&out_dir)
        };
        let target_dir = target_dir(root);
        let mut jobs: Vec<(&'static Combo, Side)> = Vec::new();
        for row in combos.iter().copied() {
            for side in [Side::Agent, Side::Admin] {
                if !row.supports(side) {
                    continue;
                }
                if (side == Side::Agent && !cfg.agent) || (side == Side::Admin && !cfg.admin) {
                    continue;
                }
                jobs.push((row, side));
            }
        }

        if jobs.is_empty() {
            println!("build-matrix: 所选组合经 `--agent-only` / `--admin-only` 过滤后没有产物");
            return ExitCode::SUCCESS;
        }
        if cfg.local {
            println!(
                "build-matrix（--local）：只验证宿主 musl 档（{} 行）；11 个 blocking 组合由 CI 的 build-matrix job 证明（plan §4.13）",
                combos.len()
            );
        }
        println!(
            "build-matrix: {} 个组合 / {} 个产物，out={}，target_dir={}",
            combos.len(),
            jobs.len(),
            display_rel(root, &out_dir),
            display_rel(root, &target_dir)
        );
        println!(
            "build-matrix: toolchain {}（nightly={}），已装 target {} 个",
            tc.release,
            tc.nightly,
            tc.installed.len()
        );

        let mut results: Vec<Outcome> = Vec::new();
        for (idx, (row, side)) in jobs.iter().copied().enumerate() {
            let artifact = row.artifact(side);
            println!(
                "\n==> [{}/{}] {}/{} {} -> {}",
                idx + 1,
                jobs.len(),
                row.os,
                row.arch,
                side.label(),
                artifact
            );
            let status = build_one(root, &out_dir, &target_dir, row, side, &tc, cfg);
            results.push(Outcome {
                row,
                side,
                artifact,
                status,
            });
        }

        // CI 上「该编的组合被跳过」等于没验证，必须红；本地跑 `--local` 时目标
        // 架构本来就装不上，跳过是常态（plan §4.14 E22）。
        print_results(root, &out_dir, &results, skipped_is_failure(cfg.local))
    }

    /// 跳过是否算失败。
    ///
    /// 首次 CI 的教训：`build linux/(arm,mipsle)` 两个 tier-3 job 显示成功，
    /// 实际输出是 `skipped`——`rust-toolchain.toml` 把 channel 钉在 stable，
    /// `rustup default nightly` 对它无效，于是 `-Z build-std` 从没跑起来，而
    /// `skipped` 不置非 0 退出码。判据没跑就该是红的（plan §4.14 E30）。
    ///
    /// 本地用 `--local` 验证宿主 musl 档时，`i686`/`aarch64`/`armv7` 三条本机
    /// 装不上 target，跳过是预期结果，不能判失败。
    const fn skipped_is_failure(local: bool) -> bool {
        !local
    }

    #[derive(Debug)]
    struct Outcome {
        row: &'static Combo,
        side: Side,
        artifact: String,
        status: Status,
    }

    #[derive(Debug)]
    enum Status {
        Ok { bytes: u64, alias: Option<String> },
        Skipped(String),
        Failed(String),
        DryRun,
    }

    fn build_one(
        root: &Path,
        out_dir: &Path,
        target_dir: &Path,
        row: &Combo,
        side: Side,
        tc: &Toolchain,
        cfg: &Config,
    ) -> Status {
        if let Some(reason) = unavailable(row, tc) {
            println!("    skipped：{reason}");
            return Status::Skipped(reason);
        }
        let argv = build_argv(root, row, side);
        let bin = host_bin(target_dir, row, side);
        let artifact_path = out_dir.join(row.artifact(side));

        if cfg.dry_run {
            println!("    $ {}", argv.join(" "));
            println!(
                "      cp {} {}",
                display_rel(root, &bin),
                display_rel(root, &artifact_path)
            );
            return Status::DryRun;
        }

        println!("    $ {}", argv.join(" "));
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]).current_dir(root);
        // 本机 `/` 只读（plan §1.3）：调用方没显式设 CARGO_HOME 时回落到仓库内的 `.cargo-home`。
        if std::env::var_os("CARGO_HOME").is_none() {
            let home = root.join(".cargo-home");
            if home.is_dir() {
                cmd.env("CARGO_HOME", &home);
            }
        }
        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                let msg = format!("无法执行 `cargo`：{e}");
                println!("    failed：{msg}");
                return Status::Failed(msg);
            }
        };
        if !output.status.success() {
            let msg = last_error_line(&output);
            for line in tail(&output, 15) {
                eprintln!("    | {line}");
            }
            println!("    failed：{msg}");
            return Status::Failed(msg);
        }

        if let Err(e) = std::fs::create_dir_all(out_dir) {
            let msg = format!("无法创建产物目录 {}：{e}", out_dir.display());
            println!("    failed：{msg}");
            return Status::Failed(msg);
        }
        if !bin.is_file() {
            let msg = format!(
                "cargo 成功但找不到产物 {}（target-dir 是否为 {}？）",
                display_rel(root, &bin),
                display_rel(root, target_dir)
            );
            println!("    failed：{msg}");
            return Status::Failed(msg);
        }
        if let Err(e) = std::fs::copy(&bin, &artifact_path) {
            let msg = format!("复制产物到 {} 失败：{e}", display_rel(root, &artifact_path));
            println!("    failed：{msg}");
            return Status::Failed(msg);
        }
        let bytes = std::fs::metadata(&artifact_path)
            .map(|m| m.len())
            .unwrap_or(0);

        // docs/plan.md §4.13 用反序写法（agent_linux_x64）指代同一产物，建硬链接别名，
        // 失败只告警（不影响构建结论）。
        let alias = row.artifact(side);
        let plan_name = plan_alias(&alias);
        let alias = if plan_name == alias {
            None
        } else {
            let path = out_dir.join(&plan_name);
            // 重复执行时别名已存在（硬链接不会覆盖），先删掉再重建，保证幂等。
            if path.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&path);
            }
            match std::fs::hard_link(&artifact_path, &path) {
                Ok(()) => {
                    println!("    别名 {}", display_rel(root, &path));
                    Some(plan_name)
                }
                Err(e) => {
                    eprintln!(
                        "    注意：无法建立 plan §4.13 别名 {}：{e}",
                        display_rel(root, &path)
                    );
                    None
                }
            }
        };

        // 判据不能只是「用了哪个 builder」自证：cross 会对没有 subcommand 的调用
        // 回落宿主 cargo，zigbuild 也可能退化成动态链接。tier-3 的交付形态是
        // 「无 PT_INTERP」，直接从产物里读，而不是相信调用链（plan §4.14 E34）。
        if row.tier3
            && let Err(why) = verify_static(&artifact_path)
        {
            let msg = format!(
                "tier-3 产物 {} 不是静态链接（{why}），交付形态应为无 PT_INTERP",
                display_rel(root, &artifact_path)
            );
            println!("    failed：{msg}");
            return Status::Failed(msg);
        }

        println!(
            "    ok：{} {}",
            display_rel(root, &artifact_path),
            human_bytes(bytes)
        );
        Status::Ok { bytes, alias }
    }

    /// 确认 tier-3 产物是静态的（无 `PT_INTERP`）。
    ///
    /// 这里刻意把「读不出文件」「不是 ELF」都当成失败，而不是「跳过检查」：
    /// 对 tier-3 的 Linux 目标来说，产物本来就是 ELF，读不出来或不是 ELF 是
    /// 判据没跑成，不能当成「验过了」。这与 plan §4.14 E30（前置步骤静默没
    /// 做事、错误延后到链接期）是同一类问题——**做不到要说出来**。
    ///
    /// 只查 `PT_INTERP` 而不查 `DT_NEEDED`：`static-pie`（zigbuild 的 mipsel
    /// 产物）没有解释器但保留动态段，那是合法的静态形态；有解释器就一定不是。
    fn verify_static(path: &Path) -> std::result::Result<(), String> {
        let bytes = std::fs::read(path).map_err(|e| format!("怀疑没验成——读取产物失败：{e}"))?;
        if bytes.len() < 64 {
            return Err(format!(
                "怀疑没验成——产物只有 {} 字节，不是 ELF",
                bytes.len()
            ));
        }
        if &bytes[..4] != b"\x7fELF" {
            return Err("怀疑没验成——产物不是 ELF".to_string());
        }
        let is_64 = match bytes[4] {
            2 => true,
            1 => false,
            other => return Err(format!("怀疑没验成——未知的 ELF 类别 {other}")),
        };
        // 本机与 CI 的 tier-3 runner 都是小端；大端 ELF 不在支持范围内。
        if bytes[5] != 1 {
            return Err(format!("怀疑没验成——未知的 ELF 字节序 {}", bytes[5]));
        }
        let u16_at = |off: usize| -> Option<u16> {
            let b = bytes.get(off..off + 2)?;
            Some(u16::from_le_bytes([b[0], b[1]]))
        };
        let u32_at = |off: usize| -> Option<u32> {
            let b = bytes.get(off..off + 4)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        let u64_at = |off: usize| -> Option<u64> {
            let b = bytes.get(off..off + 8)?;
            Some(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
        };
        let (phoff, phentsize, phnum) = if is_64 {
            (u64_at(32), u16_at(54), u16_at(56))
        } else {
            (u32_at(28).map(u64::from), u16_at(42), u16_at(44))
        };
        let (Some(phoff), Some(phentsize), Some(phnum)) = (phoff, phentsize, phnum) else {
            return Err("怀疑没验成——ELF 头被截断，读不到程序头表".to_string());
        };
        if phentsize < 32 || phnum == 0 {
            return Err(format!(
                "怀疑没验成——程序头表异常（{} 条，每条 {} 字节）",
                phnum, phentsize
            ));
        }
        const PT_INTERP: u32 = 3;
        for i in 0..usize::from(phnum) {
            let base = phoff as usize + i * usize::from(phentsize);
            let Some(ptype) = u32_at(base) else {
                return Err(format!("怀疑没验成——第 {i} 条程序头越界"));
            };
            if ptype == PT_INTERP {
                return Err("存在 PT_INTERP".to_string());
            }
        }
        Ok(())
    }

    /// 内部 `cargo` 调用要不要加 `--offline`。
    ///
    /// 本机（plan §1.3：`/` 只读）只能吃 `.cargo-home` 里的缓存，必须离线；CI 上
    /// 依赖要现拉，加 `--offline` 会让第一次构建直接失败。判据是「有没有走网络的条件」：
    /// CI 环境变量在场就联网，否则只看仓库内缓存目录是否存在。
    fn use_offline(root: &Path) -> bool {
        if std::env::var_os("CI").is_some() {
            return false;
        }
        // 显式覆盖：`STOWAWAY_OFFLINE=0` 可在联网机器上关掉。
        match std::env::var("STOWAWAY_OFFLINE").ok().as_deref() {
            Some("0") | Some("false") => return false,
            Some(_) => return true,
            None => {}
        }
        root.join(".cargo-home").join("registry").is_dir()
    }

    fn build_argv(root: &Path, row: &Combo, side: Side) -> Vec<String> {
        // 链接 **release** 时两个 ~90MB 二进制并行会让 LLVM 自己崩（plan §4.14 E27），
        // 因此这里固定 `-j 1` —— 每次调用只产出一个二进制，串行链接是唯一稳的形态。
        let mut v: Vec<String> = match row.builder {
            // `cross` 与 `cargo-zigbuild` 都是 cargo 的子命令（独立安装的可执行文件），
            // 参数形态与 `cargo build` 同形，只是多了容器/zig 包装。
            Builder::Cargo => ["cargo", "build", "--release", "-j", "1"],
            Builder::Cross => ["cross", "build", "--release", "-j", "1"],
            Builder::Zigbuild => ["cargo", "zigbuild", "--release", "-j", "1"],
        }
        .map(String::from)
        .to_vec();
        if use_offline(root) && allows_offline(row) {
            v.push("--offline".to_string());
        }
        if row.tier3 {
            // tier-3 无预编译 std，只能现场编：`-Z build-std` 需要 nightly。
            // `unavailable()` 已经把「非 nightly」判成 skipped，所以走到这里必然有
            // nightly（CI 用 RUSTUP_TOOLCHAIN=nightly 压过 rust-toolchain.toml）。
            v.push("-Z".to_string());
            v.push("build-std=std,panic_abort".to_string());
        }
        v.extend([
            "--target".to_string(),
            row.triple.to_string(),
            "-p".to_string(),
            side.pkg().to_string(),
        ]);
        v
    }

    /// tier-3 的 `-Z build-std` 必须能联网拉 std 的依赖（`wasip1` 等）。
    ///
    /// 本机没有 nightly 的 registry 缓存，`--offline` 会直接报
    /// `no matching package named \`wasip1\` found`；CI 则本来就要现拉依赖。
    /// 所以只在「非 tier-3」时允许 `use_offline()` 生效。
    fn allows_offline(row: &Combo) -> bool {
        !row.tier3
    }

    fn host_bin(target_dir: &Path, row: &Combo, side: Side) -> PathBuf {
        let mut name = side.pkg().to_string();
        if row.os == "windows" {
            name.push_str(".exe");
        }
        target_dir.join(row.triple).join("release").join(name)
    }

    fn target_dir(root: &Path) -> PathBuf {
        match std::env::var_os("CARGO_TARGET_DIR") {
            Some(dir) => {
                let p = PathBuf::from(dir);
                if p.is_absolute() { p } else { root.join(p) }
            }
            None => root.join("target"),
        }
    }

    /// `linux_x64_agent` -> `agent_linux_x64`（Go 名字与 plan §4.13 写法的唯一差异）。
    fn plan_alias(go: &str) -> String {
        let (stem, ext) = match go.strip_suffix(".exe") {
            Some(s) => (s, ".exe"),
            None => (go, ""),
        };
        match stem.rsplit_once('_') {
            Some((plat, side)) => format!("{side}_{plat}{ext}"),
            None => go.to_string(),
        }
    }

    fn last_error_line(o: &std::process::Output) -> String {
        // cargo 的 stderr 末尾全是 `= note:`/`= help:` 续行；直接取最后一行会把
        // 「帮助文本」当成错误摘要，因此优先挑真正的 `error…` 行（跳过 `could not
        // compile` 这类汇总行，它不含根因），再退化为第一条非缩进续行。
        let mut fallback = String::new();
        for stream in [&o.stderr, &o.stdout] {
            let text = String::from_utf8_lossy(stream);
            for raw in text.lines().rev() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('=') || line.starts_with('|') {
                    continue;
                }
                if line.starts_with("error") {
                    if line.starts_with("error: could not compile")
                        || line.starts_with("error: aborting")
                    {
                        continue;
                    }
                    return line.to_string();
                }
                if fallback.is_empty() {
                    fallback = line.to_string();
                }
            }
        }
        if fallback.is_empty() {
            format!(
                "cargo build 失败（退出码 {}）",
                o.status.code().unwrap_or(-1)
            )
        } else {
            fallback
        }
    }

    fn tail(o: &std::process::Output, n: usize) -> Vec<String> {
        let text = String::from_utf8_lossy(&o.stderr);
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(n)..]
            .iter()
            .map(|l| l.to_string())
            .collect()
    }

    fn print_list(combos: &[&'static Combo], tc: &Toolchain, local: bool) {
        if local {
            println!(
                "本地 musl 档：{} 个组合（plan §4.13 的 best-effort 档；blocking 的 11 个组合由 CI 证明）",
                combos.len()
            );
        } else {
            println!(
                "plan §4.13 blocking 矩阵：{} 个 OS-ARCH 组合（产物名对齐 Go 版 Makefile：release/<plat>_<side>）",
                combos.len()
            );
        }
        println!(
            "{:<10} {:<9} {:<22} {:<24} {:<34} {:<9} AVAIL",
            "OS", "ARCH", "AGENT", "ADMIN", "TRIPLE", "BUILDER"
        );
        let mut usable = 0usize;
        for row in combos {
            let agent = row.agent.then(|| row.artifact(Side::Agent));
            let admin = row.admin.then(|| row.artifact(Side::Admin));
            let avail = unavailable(row, tc).is_none();
            if avail {
                usable += 1;
            }
            let mut agent = agent.unwrap_or_else(|| "-".to_string());
            if row.tier3 {
                agent.push_str(" (t3)");
            }
            println!(
                "{:<10} {:<9} {:<22} {:<24} {:<34} {:<9} {}",
                row.os,
                row.arch,
                agent,
                admin.unwrap_or_else(|| "-".to_string()),
                row.triple,
                row.builder.label(),
                if avail { "yes" } else { "no" }
            );
        }
        println!("\n(t3) = tier-3 目标：std 无预编译件，需 nightly + `-Z build-std`（plan §4.13）");
        println!(
            "BUILDER = 谁来编译：cargo（宿主/预装 target）· cross（crosstool-ng 容器）\n          · zigbuild（zig 自带 libc）。选择依据见 plan §4.14 E34。"
        );
        println!(
            "可用 {usable}/{}（toolchain {}，已装 target {} 个）",
            combos.len(),
            tc.release,
            tc.installed.len()
        );
        if let Some(err) = &tc.installed_err {
            println!("注意：{err}，因此全部组合按不可用处理");
        }
        for row in combos {
            if let Some(reason) = unavailable(row, tc) {
                println!("no -> {}/{}：{reason}", row.os, row.arch);
            }
        }
    }

    fn print_results(
        root: &Path,
        out_dir: &Path,
        results: &[Outcome],
        skipped_fails: bool,
    ) -> ExitCode {
        println!("\n汇总：");
        println!(
            "{:<10} {:<9} {:<6} {:<24} {:<8} DETAIL",
            "OS", "ARCH", "SIDE", "ARTIFACT", "STATUS"
        );
        let (mut ok, mut skipped, mut failed, mut dry) = (0usize, 0usize, 0usize, 0usize);
        for r in results {
            let (status, detail) = match &r.status {
                Status::Ok { bytes, alias } => {
                    ok += 1;
                    let mut detail = human_bytes(*bytes);
                    if let Some(a) = alias {
                        detail.push_str(&format!("（别名 {a}）"));
                    }
                    ("ok", detail)
                }
                Status::Skipped(reason) => {
                    skipped += 1;
                    ("skipped", reason.clone())
                }
                Status::Failed(msg) => {
                    failed += 1;
                    ("failed", msg.clone())
                }
                Status::DryRun => {
                    dry += 1;
                    ("dry-run", "未执行".to_string())
                }
            };
            println!(
                "{:<10} {:<9} {:<6} {:<24} {:<8} {}",
                r.row.os,
                r.row.arch,
                r.side.label(),
                r.artifact,
                status,
                detail
            );
        }
        let out = display_rel(root, out_dir);
        println!(
            "\nok {ok} / skipped {skipped} / failed {failed}{}（产物目录 {out}）",
            if dry > 0 {
                format!(" / dry-run {dry}")
            } else {
                String::new()
            }
        );
        if skipped > 0 {
            if skipped_fails {
                eprintln!(
                    "build-matrix: {skipped} 个组合被跳过，而这里必须真正编译（本地验证请用 --local）"
                );
            } else {
                println!("skipped 不影响退出码（--local：宿主之外的组合本机装不上 target）");
            }
        }
        if failed > 0 {
            eprintln!("build-matrix: {failed} 个组合本应可用却构建失败");
            return ExitCode::FAILURE;
        }
        if skipped > 0 && skipped_fails {
            return ExitCode::FAILURE;
        }
        ExitCode::SUCCESS
    }

    fn display_rel(root: &Path, path: &Path) -> String {
        path.strip_prefix(root)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.display().to_string())
    }

    fn human_bytes(n: u64) -> String {
        const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
        let mut v = n as f64;
        let mut i = 0usize;
        while v >= 1024.0 && i + 1 < UNITS.len() {
            v /= 1024.0;
            i += 1;
        }
        if i == 0 {
            format!("{n} B")
        } else {
            format!("{v:.1} {}", UNITS[i])
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// 构造一个可控的工具链快照（不碰真实 rustup 状态）。
        fn tc(installed: &[&str], nightly: bool) -> Toolchain {
            Toolchain {
                installed: installed.iter().map(|s| (*s).to_string()).collect(),
                installed_err: None,
                release: if nightly {
                    "1.102.0-nightly".to_string()
                } else {
                    "1.100.0".to_string()
                },
                nightly,
            }
        }

        fn row(triple: &'static str, tier3: bool) -> Combo {
            Combo {
                os: "linux",
                arch: "x",
                triple,
                plat: "linux_x",
                agent: true,
                admin: true,
                tier3,
                builder: Builder::Cargo,
            }
        }

        #[test]
        fn skipped_fails_everywhere_except_local() {
            // 判据没跑就不能是绿的（plan §4.14 E30）。本地 `--local` 是唯一的例外：
            // 宿主之外的组合本机装不上 target，跳过是预期。
            assert!(skipped_is_failure(false), "非 --local：跳过必须判失败");
            assert!(!skipped_is_failure(true), "--local：跳过不算失败");
        }

        #[test]
        fn tier3_does_not_require_an_installed_target() {
            // `-Z build-std` 由 nightly 从 rust-src 现场编译 std，没有预编译件可装。
            // 早期版本无条件要求已装 target，把「nightly + rust-src 都就位」的
            // tier-3 job 判成 skipped——判据被自己的前置条件挡死（首次 CI 现象）。
            let t = tc(&["x86_64-unknown-linux-gnu"], true);
            assert!(
                unavailable(&row("armv5te-unknown-linux-musleabi", true), &t).is_none(),
                "nightly 就位时 tier-3 不该被判 skipped"
            );
        }

        #[test]
        fn tier3_still_requires_nightly() {
            let t = tc(&["x86_64-unknown-linux-gnu"], false);
            let reason = unavailable(&row("mipsel-unknown-linux-musl", true), &t)
                .expect("stable 下 tier-3 必须给出原因");
            assert!(
                reason.contains("nightly") && reason.contains("build-std"),
                "原因要说清缺什么：{reason}"
            );
        }

        #[test]
        fn non_tier3_still_requires_the_target() {
            let t = tc(&["x86_64-unknown-linux-gnu"], false);
            let reason = unavailable(&row("aarch64-unknown-linux-gnu", false), &t)
                .expect("没装 target 的普通组合必须给出原因");
            assert!(
                reason.contains("rustup target list"),
                "原因指向具体缺口：{reason}"
            );
        }

        #[test]
        fn available_targets_are_available() {
            let t = tc(&["x86_64-unknown-linux-gnu"], false);
            assert!(unavailable(&row("x86_64-unknown-linux-gnu", false), &t).is_none());
        }

        fn row_with(triple: &'static str, tier3: bool, builder: Builder) -> Combo {
            let mut c = row(triple, tier3);
            c.builder = builder;
            c
        }

        /// 造一个最小 ELF64 头 + `phnum` 条程序头，`ptype` 决定第一条的类型。
        fn synth_elf(ptype: u32, phnum: u16) -> Vec<u8> {
            let mut b = vec![0u8; 64];
            b[..4].copy_from_slice(b"\x7fELF");
            b[4] = 2; // ELFCLASS64
            b[5] = 1; // 小端
            b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
            b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
            b[56..58].copy_from_slice(&phnum.to_le_bytes()); // e_phnum
            for i in 0..usize::from(phnum) {
                let mut ph = vec![0u8; 56];
                // 只有第一条用 ptype，其余填 PT_LOAD(1)，避免误判成「多段解释器」。
                let t = if i == 0 { ptype } else { 1 };
                ph[..4].copy_from_slice(&t.to_le_bytes());
                b.extend_from_slice(&ph);
            }
            b
        }

        #[test]
        fn interp_segment_is_what_makes_a_tier3_artifact_dynamic() {
            let dir = std::env::temp_dir().join(format!("stw-xtask-elf-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("mkdir");

            let dynamic = dir.join("dynamic");
            std::fs::write(&dynamic, synth_elf(3, 1)).expect("write");
            let err = verify_static(&dynamic).expect_err("PT_INTERP 必须被判成动态");
            assert!(err.contains("PT_INTERP"), "错误要指出根因，实际是：{err}");

            let statik = dir.join("static");
            std::fs::write(&statik, synth_elf(1, 2)).expect("write");
            assert_eq!(
                verify_static(&statik),
                Ok(()),
                "static-pie 没有解释器，必须放过（zigbuild 的 mipsel 就是这种形态）"
            );

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn a_failed_check_is_a_failure_not_a_pass() {
            let dir = std::env::temp_dir().join(format!("stw-xtask-bad-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("mkdir");

            let missing = dir.join("nope");
            assert!(
                verify_static(&missing).is_err(),
                "读不到文件不能被当成验过了"
            );

            let pe = dir.join("pe");
            std::fs::write(&pe, b"MZ\x90\x00").expect("write");
            assert!(verify_static(&pe).is_err(), "非 ELF 不能被当成验过了");

            let truncated = dir.join("trunc");
            std::fs::write(&truncated, b"\x7fELF\x02\x01").expect("write");
            assert!(
                verify_static(&truncated).is_err(),
                "截断的 ELF 不能被当成验过了"
            );

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn tier3_rows_are_built_by_their_own_driver() {
            // 分工是实测结论（plan §4.14 E34），不是偏好：两个驱动器各自只在一个
            // 目标上能出静态发布形态。这条锁住「别在重构时把两档都改回 cargo」。
            let arm = MATRIX
                .iter()
                .find(|c| c.triple == "armv5te-unknown-linux-musleabi")
                .expect("armv5te 必须在 blocking 矩阵里");
            let mips = MATRIX
                .iter()
                .find(|c| c.triple == "mipsel-unknown-linux-musl")
                .expect("mipsel 必须在 blocking 矩阵里");
            assert_eq!(arm.builder, Builder::Cross);
            assert_eq!(mips.builder, Builder::Zigbuild);
            // 其余组合一律走 cargo：多引入一个驱动器就多一份失败面。
            for c in MATRIX.iter().filter(|c| !c.tier3) {
                assert_eq!(c.builder, Builder::Cargo, "{} 应该走 cargo", c.triple);
            }
        }

        #[test]
        fn build_argv_dispatches_on_the_driver() {
            let root = Path::new(".");
            let arm = row_with("armv5te-unknown-linux-musleabi", true, Builder::Cross);
            let argv = build_argv(root, &arm, Side::Agent);
            assert_eq!(argv[0], "cross", "cross 自己的命令名：{argv:?}");
            assert!(argv.iter().any(|a| a == "build-std=std,panic_abort"));

            let mips = row_with("mipsel-unknown-linux-musl", true, Builder::Zigbuild);
            let argv = build_argv(root, &mips, Side::Agent);
            assert_eq!(
                &argv[..2],
                ["cargo", "zigbuild"],
                "zigbuild 是 cargo 子命令：{argv:?}"
            );

            let plain = row("x86_64-unknown-linux-gnu", false);
            let argv = build_argv(root, &plain, Side::Agent);
            assert_eq!(&argv[..2], ["cargo", "build"]);
            assert!(
                !argv.iter().any(|a| a.starts_with("build-std")),
                "非 tier-3 不带 build-std：{argv:?}"
            );
        }

        #[test]
        fn missing_driver_is_skipped_with_a_specific_reason() {
            // 驱动器没装时要说清缺哪条命令，而不是走到 build_one 里报
            // 「无法执行 `cross`」——那看起来像构建失败，实际是环境没准备好。
            // 结论取决于本机装没装 cross，所以两条分支都要写死断言，
            // 免得这条测试在开发机与 CI 上给出相反的「通过」。
            let t = tc(&[], true);
            let r = unavailable(
                &row_with("armv5te-unknown-linux-musleabi", true, Builder::Cross),
                &t,
            );
            if have_command("cross") {
                assert!(r.is_none(), "装了 cross 就不该因驱动器被判跳过：{r:?}");
            } else {
                let reason = r.expect("缺 cross 时必须给出原因");
                assert!(reason.contains("cross"), "原因要点名缺失的命令：{reason}");
            }
        }
    }
}
