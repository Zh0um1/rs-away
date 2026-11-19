//! 仓库自带任务运行器（plan.md §4.13 / §10 G5）。
//!
//! 用法：`cargo xtask <任务>`，任务定义见 `docs/plan.md` §8.6。
//! 这是一个**无第三方依赖**的最小实现，避免 `xtask` 拖慢 workspace 构建。
use std::process::{Command, ExitCode};

/// `fetch-go-baseline`：为 plan.md §8.4 的 Go 黑盒行为对照预构建 v1 基线二进制。
mod interop;

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

/// `no-unsafe`：plan.md §8.6 第六条 DoD（原口径 `cargo geiger`）的等价实现。
///
/// `cargo-geiger` 无法在本仓库环境安装（离线缓存里没有该 crate，联网安装也失败），
/// 因此改为自建扫描器：对每个 crate 的 `src/` 逐行统计**真正构成 unsafe 作用域**的
/// 构造 —— `unsafe {`、`unsafe fn`、`unsafe impl`、`unsafe trait`、`extern "C"`。
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
    let root = repo_root();
    // plan.md §8.6：protocol / crypto / transport 三个 crate 的 unsafe 计数必须为 0。
    // core 及以上允许出现平台相关 unsafe（目前也确为 0），单独统计但不作为门禁。
    const GATED: [&str; 3] = ["protocol", "crypto", "transport"];
    const REPORTED: [&str; 3] = ["core", "admin", "agent"];
    let mut total_files = 0usize;
    let mut gated_violations = 0usize;
    let mut reported_violations = 0usize;
    for name in GATED.into_iter().chain(REPORTED) {
        let src = root
            .join("crates")
            .join(format!("stowaway-{name}"))
            .join("src");
        let mut files = Vec::new();
        collect_rs(&src, &mut files);
        files.sort();
        total_files += files.len();
        let gated = GATED.contains(&name);
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
        },
        Combo {
            os: "linux",
            arch: "i686",
            triple: "i686-unknown-linux-gnu",
            plat: "linux_x86",
            agent: true,
            admin: true,
            tier3: false,
        },
        Combo {
            os: "linux",
            arch: "aarch64",
            triple: "aarch64-unknown-linux-gnu",
            plat: "linux_arm64",
            agent: true,
            admin: true,
            tier3: false,
        },
        Combo {
            os: "linux",
            arch: "arm",
            triple: "armv5te-unknown-linux-musleabi",
            plat: "arm_eabi5",
            agent: true,
            admin: false,
            tier3: true,
        },
        Combo {
            os: "linux",
            arch: "mipsle",
            triple: "mipsel-unknown-linux-musl",
            plat: "mipsel",
            agent: true,
            admin: false,
            tier3: true,
        },
        Combo {
            os: "darwin",
            arch: "x86_64",
            triple: "x86_64-apple-darwin",
            plat: "macos_x64",
            agent: true,
            admin: true,
            tier3: false,
        },
        Combo {
            os: "darwin",
            arch: "aarch64",
            triple: "aarch64-apple-darwin",
            plat: "macos_arm64",
            agent: true,
            admin: true,
            tier3: false,
        },
        Combo {
            os: "windows",
            arch: "x86_64",
            triple: "x86_64-pc-windows-gnu",
            plat: "windows_x64",
            agent: true,
            admin: true,
            tier3: false,
        },
        Combo {
            os: "windows",
            arch: "i686",
            triple: "i686-pc-windows-gnu",
            plat: "windows_x86",
            agent: true,
            admin: true,
            tier3: false,
        },
        Combo {
            os: "freebsd",
            arch: "i686",
            triple: "i686-unknown-freebsd",
            plat: "freebsd_x86",
            agent: true,
            admin: true,
            tier3: false,
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
        },
    ];

    #[derive(Debug)]
    struct Combo {
        os: &'static str,
        arch: &'static str,
        triple: &'static str,
        /// Go 版产物名的平台段（`release/<plat>_<side>`）。
        plat: &'static str,
        agent: bool,
        admin: bool,
        /// tier-3：std 无预编译产物，需 nightly + `-Z build-std`，且要关 TLS/ws/kcp。
        tier3: bool,
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
  --target <triple>   只构建指定 target triple（不在矩阵里则报错）
  --agent-only        只构建 agent 侧
  --admin-only        只构建 admin 侧
  --list              只打印矩阵表（OS/ARCH/agent/admin/是否可用），不构建
  --dry-run           打印将要执行的命令，不执行
  --out <dir>         产物目录，默认 release/（相对仓库根）
  -h, --help          显示本帮助

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
        if !tc.has_target(row.triple) {
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
        if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("；"))
        }
    }

    pub fn run(root: &Path, cfg: &Config) -> ExitCode {
        let combos: Vec<&'static Combo> = MATRIX
            .iter()
            .filter(|c| cfg.target.as_deref().is_none_or(|t| c.triple == t))
            .collect();
        if combos.is_empty() {
            let t = cfg.target.as_deref().unwrap_or("");
            eprintln!(
                "build-matrix: triple `{t}` 不在 plan §4.13 的 11 个 blocking 组合里（用 `--list` 查看）"
            );
            return ExitCode::FAILURE;
        }

        let tc = Toolchain::detect();
        if cfg.list {
            print_list(&combos, &tc);
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

        print_results(root, &out_dir, &results)
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
        let argv = build_argv(row, side);
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

        println!(
            "    ok：{} {}",
            display_rel(root, &artifact_path),
            human_bytes(bytes)
        );
        Status::Ok { bytes, alias }
    }

    fn build_argv(row: &Combo, side: Side) -> Vec<String> {
        // 资源受限（plan §1.3）与可复现：一律 `--offline -j 2`。
        let mut v: Vec<String> = ["cargo", "build", "--release", "--offline", "-j", "2"]
            .map(String::from)
            .to_vec();
        if row.tier3 {
            // tier-3 无预编译 std；feature 门控（关 tls/ws/kcp）需 crate 侧配合，
            // 见 plan §4.13 / §9.1。本机非 nightly 时早已在 unavailable() 里跳过。
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

    fn print_list(combos: &[&'static Combo], tc: &Toolchain) {
        println!(
            "plan §4.13 blocking 矩阵：{} 个 OS-ARCH 组合（产物名对齐 Go 版 Makefile：release/<plat>_<side>）",
            combos.len()
        );
        println!(
            "{:<10} {:<9} {:<22} {:<24} {:<34} AVAIL",
            "OS", "ARCH", "AGENT", "ADMIN", "TRIPLE"
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
                "{:<10} {:<9} {:<22} {:<24} {:<34} {}",
                row.os,
                row.arch,
                agent,
                admin.unwrap_or_else(|| "-".to_string()),
                row.triple,
                if avail { "yes" } else { "no" }
            );
        }
        println!(
            "\n(t3) = tier-3 目标：需 nightly + `-Z build-std`，并关 TLS/ws/kcp（plan §4.13）"
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

    fn print_results(root: &Path, out_dir: &Path, results: &[Outcome]) -> ExitCode {
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
            println!("skipped 不影响退出码（CI 上可据此看出本机与发布矩阵的差异）");
        }
        if failed > 0 {
            eprintln!("build-matrix: {failed} 个组合本应可用却构建失败");
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
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
}
