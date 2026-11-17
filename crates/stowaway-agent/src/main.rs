//! agent 二进制：薄 main + 启动编排。
use clap::Parser;

/// agent 命令行参数。对应 Go v1 的 15 个 flag。
#[derive(Debug, Parser)]
#[command(
    name = "stowaway-agent",
    version,
    about = "Stowaway agent (Rust, v2 protocol)"
)]
struct Args {
    /// 共享密钥。支持 `env:NAME` / `file:/path` / `stdin:` 前缀。
    #[arg(short = 's', long)]
    secret: Option<String>,

    /// 本地监听端口（被动模式）。
    #[arg(short = 'l', long)]
    listen: Option<u16>,

    /// 上行 admin 地址（主动模式）。
    #[arg(short = 'c', long)]
    connect: Option<String>,

    /// 上行传输规格。
    #[arg(long)]
    up: Option<String>,

    /// 下行传输规格。
    #[arg(long)]
    down: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!(
        listen = ?args.listen,
        connect = ?args.connect,
        "stowaway-agent 启动（P0 骨架：尚无运行时）"
    );
    if args.secret.is_some() {
        tracing::warn!("`--secret` 已解析但尚未消费（P0 骨架）");
    }
    Ok(())
}
