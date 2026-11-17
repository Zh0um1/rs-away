//! 仓库自带任务运行器（plan.md §4.13 / §10 G5）。
//!
//! 用法：`cargo xtask <任务>`，任务定义见 `docs/plan.md` §8.6。
//! 这是一个**无第三方依赖**的最小实现，避免 `xtask` 拖慢 workspace 构建。
use std::process::{Command, ExitCode};

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
  check       fmt --check + clippy + test（提交前必跑，plan.md §10 G5.4）
  fmt         cargo fmt --all --check
  clippy      cargo clippy --workspace --all-targets --all-features -- -D warnings
  test        cargo test --workspace --all-features
  doccheck    校验 docs/**.md 内所有 `path/to/file.go:LINE` 引用有效
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
