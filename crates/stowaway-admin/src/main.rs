//! admin 二进制：薄 main + 启动编排（业务在 `stowaway-core`）。
use clap::Parser;

/// admin 命令行参数。字段与 Go v1 的 11 个 flag 一一对应，另加 plan.md §6 的新增项。
#[derive(Debug, Parser)]
#[command(
    name = "stowaway-admin",
    version,
    about = "Stowaway admin (Rust, v2 protocol)"
)]
struct Args {
    /// 共享密钥。支持 `env:NAME` / `file:/path` / `stdin:` 前缀。
    #[arg(short = 's', long)]
    secret: Option<String>,

    /// 监听端口（等价 `--up raw://0.0.0.0:<port>`）。
    #[arg(short = 'l', long)]
    listen: Option<u16>,

    /// 上行传输规格，如 `ws://host:port?domain=x`。
    #[arg(long)]
    up: Option<String>,

    /// 下行（子节点）传输规格。
    #[arg(long)]
    down: Option<String>,

    /// 非交互模式（CI / 无 TTY）。
    #[arg(long)]
    non_interactive: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!(
        listen = ?args.listen,
        up = ?args.up,
        non_interactive = args.non_interactive,
        "stowaway-admin 启动（P0 骨架：尚无运行时）"
    );
    if args.secret.is_some() {
        tracing::warn!("`--secret` 已解析但尚未消费（P0 骨架）");
    }
    Ok(())
}
