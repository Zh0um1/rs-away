//! admin 二进制：薄 main + 启动编排（业务在 `stowaway-core`）。
//!
//! 职责边界（plan §4.9）：本文件只做三件事——建引擎、拿到第一条链路、
//! 把按键与命令喂给 `console`/`render`。**没有任何网络 I/O 在这里**，
//! 一律走 [`stowaway_core::EngineHandle`]。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Parser;
#[cfg(feature = "tui")]
use stowaway_admin::render;
use stowaway_admin::{cli, command, console};
use stowaway_core::{
    Engine, Event, HeartbeatConfig, Link, NodeConfig, NodeIdAllocator, bind, dial,
    dial_through_proxy, lead, salt_from_secret,
};
use stowaway_crypto::{CertFingerprint, Secret};
use stowaway_protocol::{NodeId, NodeKind};
use stowaway_transport::{ClientVerify, DialTarget, TlsConfig, TransportSpec};
use tokio::sync::mpsc;

/// 建立第一条链路的超时（握手 + 引导，plan §4.12 的失败语义）。
const LINK_SETUP_TIMEOUT: Duration = Duration::from_secs(15);

/// 弱密钥下限（plan §4.14 E10）。
const MIN_SECRET_LEN: usize = 8;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // 参数先全部校验完再动手：v1 是「跑到一半才发现参数不对」。
    let mode = args.mode().context("启动模式无法确定")?;
    args.check_proxy_credentials()
        .context("上游代理凭据不完整")?;
    let pin = args.tls_pin().context("TLS 指纹非法")?;
    let upstream = args.upstream_spec().context("上行传输规格非法")?;
    let secret = Arc::new(load_secret(&args)?);

    tracing::info!(
        ?mode,
        up = %upstream,
        tls = args.tls,
        heartbeat = args.heartbeat,
        non_interactive = args.non_interactive,
        "stowaway-admin 启动"
    );
    if args.tls && pin.is_none() && !args.tls_tofu {
        tracing::warn!("TLS 未给 `--tls-pin` 也未开 `--tls-tofu`：将按 TOFU 首次信任");
    }

    let digest = secret.digest();

    // 引擎：本端固定是 Admin（编号 `NodeId::ADMIN`，plan §4.2）。
    let mut node = NodeConfig::new(NodeId::ADMIN, NodeKind::Admin);
    node.max_depth = args.max_depth;
    let (events_tx, events) = mpsc::unbounded_channel::<Event>();
    let (handle, engine, _inbound) = Engine::new(node, events_tx);
    let engine = if args.heartbeat {
        engine.with_heartbeat(HeartbeatConfig {
            interval: Duration::from_secs(args.heartbeat_interval.max(1)),
            max_missed: 3,
        })
    } else {
        engine
    };
    tokio::spawn(async move {
        if let Err(e) = engine.run().await {
            tracing::warn!("引擎退出：{e}");
        }
    });

    let mut alloc = NodeIdAllocator::new(salt_from_secret(&digest));
    let server_tls = server_tls(&args, &digest)?;

    // 第一条链路：主动拨出、或被动监听并接受首个入站。
    match &mode {
        cli::Mode::Active { addr } => {
            let target = DialTarget {
                addr: upstream.resolve_addr().context("上行地址无法解析")?,
                domain: upstream.effective_domain(),
                path: Some(upstream.effective_path().to_owned()),
                tls: client_tls(&args, pin),
            };
            tracing::info!(%addr, "主动拨号");
            let proxy = args.proxy_spec();
            let dial_fut = async {
                match &proxy {
                    Some(proxy) => {
                        tracing::info!(%proxy, "经上游代理拨号");
                        dial_through_proxy(&upstream, &target, proxy, NodeKind::Admin, &secret)
                            .await
                    }
                    None => dial(&upstream, &target, NodeKind::Admin, &secret).await,
                }
            };
            let link = tokio::time::timeout(LINK_SETUP_TIMEOUT, dial_fut)
                .await
                .context("拨号超时（15 秒）")?
                .context("拨号失败")?;
            establish(&handle, link, &mut alloc).await?;
        }
        cli::Mode::Passive { port } => {
            let mut spec = upstream.clone();
            spec.host = "0.0.0.0".to_owned();
            spec.port = *port;
            let (mut listener, kind, local) = bind(&spec, server_tls.clone())
                .await
                .context("监听失败（端口被占用或权限不足）")?;
            tracing::info!(%local, ?kind, "被动监听，等待节点拨入");
            let expected = server_tls
                .as_ref()
                .and_then(stowaway_transport::TlsConfig::advertised_fingerprint);
            // 首个入站就绪后才进控制台，避免界面已起而拓扑还是空的。
            let link = tokio::time::timeout(
                LINK_SETUP_TIMEOUT,
                stowaway_core::accept(&mut listener, kind, &secret, NodeKind::Admin, expected),
            )
            .await
            .context("等待首个节点拨入超时（15 秒）")?
            .context("首个节点握手失败")?;
            establish(&handle, link, &mut alloc).await?;

            // 后续入站交给后台任务：它独占分配器，串行分配编号。
            let accept_handle = handle.clone();
            let accept_secret = secret.clone();
            tokio::spawn(async move {
                loop {
                    match stowaway_core::accept(
                        &mut listener,
                        kind,
                        &accept_secret,
                        NodeKind::Admin,
                        expected,
                    )
                    .await
                    {
                        Ok(link) => {
                            if let Err(e) = establish(&accept_handle, link, &mut alloc).await {
                                tracing::warn!("入站节点引导失败：{e}");
                            }
                        }
                        Err(e) => tracing::warn!("入站握手失败，继续监听：{e}"),
                    }
                }
            });
        }
    }

    let mut console = console::Console::new(
        handle.clone(),
        NodeId::ADMIN,
        NodeIdAllocator::new(salt_from_secret(&digest)),
        events,
    );

    if args.non_interactive {
        run_batch(&mut console, &args).await?;
        let _ = handle.shutdown().await;
        return Ok(());
    }

    with_tui(&mut console, &handle).await
}

/// 握手完成后把链路挂成本端子节点（admin 永远是父节点）。
async fn establish(
    handle: &stowaway_core::EngineHandle,
    link: Link,
    alloc: &mut NodeIdAllocator,
) -> anyhow::Result<NodeId> {
    let child = tokio::time::timeout(
        LINK_SETUP_TIMEOUT,
        lead(handle, link.codec, alloc, NodeId::ADMIN, NodeId::ADMIN, 0),
    )
    .await
    .context("引导超时（15 秒）")?
    .context("引导失败（对端没有按 Join 流程申领编号）")?;
    tracing::info!(%child, "节点已接入");
    Ok(child)
}

/// 读密钥（支持 `env:` / `file:` / `stdin:` 前缀）。
fn load_secret(args: &cli::Args) -> anyhow::Result<Secret> {
    let Some(raw) = args.secret.as_deref() else {
        bail!("必须给出 `--secret`（支持 env:NAME / file:/path / stdin: 前缀）");
    };
    let min = if args.allow_weak_secret {
        1
    } else {
        MIN_SECRET_LEN
    };
    if args.allow_weak_secret {
        tracing::warn!("`--allow-weak-secret` 已开启：仅用于调试，生产环境必须关闭");
    }
    Secret::load(raw, min).context("密钥加载失败")
}

/// 客户端 TLS 配置；`--tls` 未开时为 `None`。
fn client_tls(args: &cli::Args, pin: Option<[u8; 32]>) -> Option<TlsConfig> {
    if !args.tls {
        return None;
    }
    let verify = match pin {
        Some(bytes) => ClientVerify::Pin(CertFingerprint::from_bytes(bytes)),
        None => ClientVerify::Tofu,
    };
    Some(TlsConfig::client(verify, args.domain.clone()))
}

/// 服务端 TLS 配置；`--tls` 未开时为 `None`。
///
/// # Errors
/// `--tls` 已开启但证书装配失败。**必须拒绝启动**：静默降级成明文等于
/// 让用户以为自己在加密信道上（缺陷 #5 的反面），而 `--tls` 是显式承诺。
fn server_tls(args: &cli::Args, digest: &[u8; 32]) -> anyhow::Result<Option<TlsConfig>> {
    if !args.tls {
        return Ok(None);
    }
    let san = vec![args.domain.clone().unwrap_or_else(|| "stowaway".to_owned())];
    let tls = TlsConfig::server(digest, &san)
        .context("TLS 服务端配置失败（--tls 已开启，拒绝以明文启动）")?;
    Ok(Some(tls))
}

/// 非交互模式：逐条执行 `--command`，或（未给命令时）常驻服务。
async fn run_batch(console: &mut console::Console, args: &cli::Args) -> anyhow::Result<()> {
    if args.command.is_empty() {
        // 常驻：只服务、不交互，Ctrl-C 退出（e2e 里当 daemon 用）。
        println!("{}", console.execute(command::Command::Status).await);
        tokio::signal::ctrl_c().await.ok();
        return Ok(());
    }

    let mut panel = command::Panel::Main;
    let mut failed = 0_usize;
    for line in &args.command {
        let cmd = match command::parse(panel, line) {
            Ok(cmd) => cmd,
            Err(e) => {
                // 批处理里「静默跳过一条命令」比报错更危险：脚本会以为跑过了。
                eprintln!("{line}: {e}");
                failed += 1;
                continue;
            }
        };
        let out = console.execute(cmd).await;
        for l in &out.lines {
            println!("{l}");
        }
        panel = console.panel();
        if !out.keep_running {
            break;
        }
    }
    if failed > 0 {
        bail!("{failed} 条命令未能解析（见上）");
    }
    Ok(())
}

/// 画 TUI。只在 `tui` feature 下存在。
#[cfg(feature = "tui")]
async fn with_tui(
    console: &mut console::Console,
    handle: &stowaway_core::EngineHandle,
) -> anyhow::Result<()> {
    use crossterm::event::KeyEvent;
    use ratatui::style::Style;

    let mut terminal = ratatui::init();
    let mut app = render::App::new();
    if let Ok(snap) = handle.snapshot().await {
        app.set_snapshot(snap);
    }

    // 按键在独立线程里阻塞读，转进 tokio 通道（crossterm 的 `read` 是阻塞的）。
    let (key_tx, mut key_rx) = mpsc::unbounded_channel::<KeyEvent>();
    std::thread::Builder::new()
        .name("stw-admin-keys".to_owned())
        .spawn(move || {
            loop {
                match crossterm::event::read() {
                    Ok(crossterm::event::Event::Key(k)) => {
                        if key_tx.send(k).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        })
        .context("无法启动按键读取线程")?;

    let mut ticker = tokio::time::interval(Duration::from_millis(150));
    let mut quitting = false;
    while !quitting {
        if let Some(lines) = console.tick() {
            for line in lines {
                app.push_log(line);
            }
        }
        if let Ok(snap) = handle.snapshot().await {
            app.set_snapshot(snap);
        }
        let panel = console.panel();
        if app.panel != panel {
            if panel == command::Panel::Main {
                app.back_to_main();
            } else {
                app.focus_node(console.focus());
            }
        }
        terminal
            .draw(|frame| {
                let _ = Style::default();
                render::draw(frame, &app);
            })
            .context("绘制失败")?;

        tokio::select! {
            key = key_rx.recv() => {
                let Some(key) = key else { break };
                match app.on_key(key) {
                    render::Action::None => {}
                    render::Action::Quit => quitting = true,
                    render::Action::Submit(cmd) => {
                        app.push_log(format!("> {cmd}"));
                        let out = console.execute(cmd).await;
                        for line in out.lines {
                            app.push_log(line);
                        }
                        if !out.keep_running {
                            quitting = true;
                        }
                        if let Ok(snap) = handle.snapshot().await {
                            app.set_snapshot(snap);
                        }
                    }
                }
            }
            _ = ticker.tick() => {}
        }
    }

    ratatui::restore();
    let _ = handle.shutdown().await;
    Ok(())
}

/// 没有 `tui` feature 时给出明确错误，而不是静默什么都不做。
#[cfg(not(feature = "tui"))]
async fn with_tui(
    _console: &mut console::Console,
    _handle: &stowaway_core::EngineHandle,
) -> anyhow::Result<()> {
    bail!("本二进制编译时未启用 `tui` feature，请用 `--non-interactive --command <cmd>` 运行");
}

/// 未使用的导入在此保留可见（`TransportSpec` 用于类型标注的上行推导）。
const _: fn() = || {
    let _: Option<TransportSpec> = None;
    let _: Option<PathBuf> = None;
};
