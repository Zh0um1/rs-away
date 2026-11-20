//! agent 二进制：薄 main + 启动编排（业务在 `stowaway-core`）。
//!
//! 职责边界：本文件只做「读参数 → 建链路 → 跑事件循环」，协议、加密、
//! 路由、服务执行全部在 core 里。v1 的 `agent/agent.go` 之所以难读，
//! 就是因为 9 种 `Mode` 的分支与协议细节混在一个函数里（见 plan §6）。

mod cli;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use stowaway_core::{
    EngineHandle, Event, HeartbeatConfig, ListenContext, MAX_UDP_DATAGRAM, NodeConfig, Runtime,
    RuntimeConfig, ServiceConfig, ServiceTask, Services, UDP_IDLE_TIMEOUT_SECS, bind_outlet,
    outlet_side_on,
};
use stowaway_core::{NodeIdAllocator, salt_from_secret};
use stowaway_crypto::{CertFingerprint, KEY_LEN, Secret};
use stowaway_protocol::{
    JoinAck, Message, NodeId, NodeKind, ServiceKind, SessionCode, SessionDirection, SessionKey,
    SessionKind, TransportKind,
};
use stowaway_transport::{ClientVerify, DialTarget, TlsConfig, TransportSpec};
use tracing::{info, warn};

/// 密钥长度下限（plan §5.1：secret 短于 8 字节视为配置错误，`--allow-weak-secret` 放宽）。
const MIN_SECRET_LEN: usize = 8;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // 参数校验一律在起链路之前做完：v1 是「跑起来才发现参数组合不对」，
    // 那时已经 bind 过端口、发过握手（plan §6「解析期报冲突项」）。
    let mode = args.mode()?;
    args.check_proxy_credentials()?;
    let pin = args.tls_pin()?;
    let upstream = args.upstream_spec()?;
    let upstream_kind = args.upstream_kind()?;
    // 下行规格（子节点链路）在 P6 只解析不建链路：被动 `listen` 服务要共享运行时
    // 的编号分配器，那是 P7 联调项；先打印出来，便于确认参数被正确理解。
    let downstream = args.downstream_spec()?;

    info!(
        mode = ?mode,
        up = %upstream,
        up_kind = ?upstream_kind,
        down = %downstream,
        accepts_children = args.accepts_children(),
        tls = args.tls,
        "stowaway-agent 启动"
    );
    if args.socks5_proxy.is_some() || args.http_proxy.is_some() {
        // 上游代理尚未接进链路建立路径（P7 项），显式告知而不是静默忽略。
        warn!(
            socks5 = ?args.socks5_proxy,
            http = ?args.http_proxy,
            "上游代理已解析但尚未接入拨号路径（P7 联调项）"
        );
    }
    if args.reuse_magic.is_some() {
        warn!(
            magic = ?args.reuse_magic,
            "端口复用魔法串已解析，但复用监听属 P7 项（plan §4.11）"
        );
    }

    let reconnect = args.reconnect;
    loop {
        let outcome = match mode {
            cli::Mode::Active { .. } => run_active(&args, &upstream, upstream_kind, pin).await,
            cli::Mode::Passive { port } => run_passive(&args, &upstream, port).await,
        };
        match outcome {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!(error = %e, "上行链路结束");
                let Some(delay) = reconnect.filter(|d| *d > 0) else {
                    return Err(e);
                };
                info!(secs = delay, "按固定间隔重连");
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
        }
    }
}

/// 主动模式：拨号到 admin，然后作为子节点接入。
async fn run_active(
    args: &cli::Args,
    upstream: &TransportSpec,
    kind: TransportKind,
    pin: Option<[u8; 32]>,
) -> anyhow::Result<()> {
    let target = DialTarget {
        addr: upstream.resolve_addr()?,
        domain: upstream.effective_domain(),
        path: Some(upstream.effective_path().to_owned()),
        tls: client_tls(args, pin),
    };
    let secret = load_secret(args)?;
    let link = stowaway_core::dial(upstream, &target, NodeKind::Agent, &secret).await?;
    let peer_kind = link.handshake.peer_kind;
    let peer = link.peer;
    info!(peer = %peer, peer_kind = ?peer_kind, kind = ?kind, "上行已建立");

    let (runtime, ack) = stowaway_core::follow(
        link.codec,
        runtime_config(args, &secret)?,
        peer_id_of(peer_kind),
        peer_kind,
    )
    .await?;
    info!(
        me = ?ack.node,
        parent = ?ack.parent,
        root = ?ack.root,
        depth = ack.depth,
        "已入网"
    );
    serve(runtime, args, &ack).await
}

/// 被动模式：监听端口，等 admin 拨入（v1 的 `NORMAL_PASSIVE`）。
async fn run_passive(args: &cli::Args, upstream: &TransportSpec, port: u16) -> anyhow::Result<()> {
    // `-l` 只给端口，监听地址固定为 `0.0.0.0`；要指定地址用 `--up`/`--down`
    // 的完整规格（v1 的 `-l` 同样只收端口）。
    let mut spec = upstream.clone();
    spec.host = "0.0.0.0".to_owned();
    spec.port = port;
    let tls = server_tls(args)?;
    let (mut listener, kind, addr) = stowaway_core::bind(&spec, tls.clone()).await?;
    info!(%addr, kind = ?kind, "被动监听中");

    let expected_fp = tls.as_ref().and_then(|t| t.fingerprint()).map(|f| f.0);
    loop {
        let secret = load_secret(args)?;
        let link =
            match stowaway_core::accept(&mut listener, kind, &secret, NodeKind::Agent, expected_fp)
                .await
            {
                Ok(l) => l,
                Err(e) => {
                    // 单个连接握手失败不该拖垮监听（v1 在 `Accept` 里直接 `continue`，
                    // 但连 TLS 错误都不区分）。这里记日志后继续等下一个。
                    warn!(error = %e, "入站握手失败，继续监听");
                    continue;
                }
            };
        let peer_kind = link.handshake.peer_kind;
        let peer = link.peer;
        if peer_kind != NodeKind::Admin {
            // 被动 agent 只等上游 admin；别的 agent 拨进来是「子节点」，
            // 那条路径要共享已有运行时的编号分配器，属 `listen` 服务（P7）。
            warn!(peer = %peer, peer_kind = ?peer_kind, "非 admin 入站，忽略");
            continue;
        }
        info!(peer = %peer, "上游 admin 已接入");
        let (runtime, ack) = stowaway_core::follow(
            link.codec,
            runtime_config(args, &secret)?,
            peer_id_of(peer_kind),
            peer_kind,
        )
        .await?;
        info!(me = ?ack.node, depth = ack.depth, "已入网");
        return serve(runtime, args, &ack).await;
    }
}

/// 事件循环：把引擎事件翻译成服务执行。
async fn serve(runtime: Runtime, args: &cli::Args, ack: &JoinAck) -> anyhow::Result<()> {
    let listen_ctx = listen_context(args, ack)?;
    let handle = runtime.handle();
    let service_config = service_config(args);
    // `ServiceRequest` 不带目标地址（地址在 `OpenSession.target` 里随开会话下发），
    // 所以要按会话键记住它。
    let mut targets: HashMap<SessionKey, Option<String>> = HashMap::new();
    let mut tasks = Vec::new();
    let mut runtime = Some(runtime);

    while let Some(rt) = runtime.as_mut() {
        let Some(event) = rt.next_event().await else {
            break;
        };
        match event {
            Event::SessionOpened { open, from } => {
                info!(key = ?open.key, kind = ?open.kind, target = ?open.target, from = %from, "会话开启");
                // UDP ASSOCIATE 的出口在这一侧（`SessionDirection::Inbound`：
                // 接收方提供资源）。会话被接受之后立刻起出口，再回 Ready 告诉
                // 发起方往哪发数据报（plan §4.14 E18、附录 A 第 30 行）。
                if open.kind == SessionKind::Socks5Udp
                    && open.direction == SessionDirection::Inbound
                {
                    let outlet_handle = handle.clone();
                    if let Some(task) = spawn_udp_outlet(outlet_handle, open.key, from).await {
                        tasks.push(task);
                    }
                }
                targets.insert(open.key, open.target.clone());
            }
            Event::ServiceRequest { req, from } => {
                let target = targets.get(&req.key).cloned().flatten();
                let mut services =
                    Services::new(service_config.clone(), handle.clone()).with_target(target);
                if let Some(ctx) = listen_ctx.clone() {
                    services = services.with_listen_context_shared(ctx);
                }
                match services.handle(req, from).await {
                    Ok(Some(task)) => tasks.push(task),
                    Ok(None) => {}
                    Err(e) => warn!(error = %e, "服务请求无法处理"),
                }
            }
            Event::ServiceExit { exit, from } => {
                info!(key = ?exit.key, code = ?exit.code, detail = %exit.detail, from = %from, "服务结束");
                targets.remove(&exit.key);
            }
            Event::SessionClosed { key } => {
                targets.remove(&key);
            }
            Event::Joined { node, kind, parent } => {
                info!(node = ?node, kind = ?kind, parent = ?parent, "链路已登记");
            }
            Event::Offline { node, removed } => {
                warn!(node = ?node, removed = removed.len(), "子节点离线");
            }
            Event::LinkLost { peer } => {
                warn!(peer = %peer, "链路断开");
                // 上游断开 = 本节点失联。`--reconnect` 由外层决定要不要重来，
                // 这里只把运行时收掉，让 `serve` 返回（plan §4.12：默认不重连）。
                if let Some(rt) = runtime.take() {
                    rt.shutdown().await.ok();
                }
                break;
            }
            Event::PeerDead { peer, misses } => {
                warn!(peer = %peer, misses, "心跳判定对端已死");
            }
            Event::Undeliverable { dest } => warn!(dest = ?dest, "帧不可达"),
            Event::Failed(msg) => warn!(%msg, "引擎报告错误"),
            Event::Shutdown => {
                info!("收到 shutdown，收尾");
                break;
            }
            Event::Rtt { peer, rtt_ms } => {
                tracing::debug!(peer = %peer, rtt_ms, "心跳回显");
            }
            Event::SessionReady { key, code } => {
                tracing::debug!(key = ?key, code = ?code, "会话就绪");
            }
            Event::ServiceReply { reply, from } => {
                tracing::debug!(key = ?reply.key, code = ?reply.code, from = %from, "服务答复");
            }
            Event::ServiceData { data, from } => {
                tracing::debug!(key = ?data.key, seq = data.seq, len = data.data.len(), from = %from, "服务数据");
            }
        }
    }

    for task in tasks {
        task.handle.abort();
    }
    if let Some(rt) = runtime {
        rt.shutdown().await.ok();
    }
    Ok(())
}

/// 运行时配置（节点编号留空：被动/主动都靠 `follow` 从父节点领取）。
fn runtime_config(args: &cli::Args, secret: &Secret) -> anyhow::Result<RuntimeConfig> {
    let mut node = NodeConfig::new(NodeId::UNASSIGNED, NodeKind::Agent);
    node.max_depth = args.max_depth;
    let mut cfg = RuntimeConfig::new(node, std::sync::Arc::new(load_secret(args)?));
    cfg.services = service_config(args);
    cfg.heartbeat = Some(HeartbeatConfig::default());
    let _ = secret;
    Ok(cfg)
}

/// 为一条 UDP ASSOCIATE 会话起出口套接字，并把它的地址回报给发起方。
///
/// 出口绑在 `0.0.0.0:0`：目标地址由每个数据报自带的 SOCKS5 头决定，出口不
/// 绑定固定对端。`ServiceTask` 的 `kind` 借用 `ServiceKind::Connect` —— 它只是
/// 让任务列表有个标签，不参与线上语义（这条会话不是 `ServiceRequest` 驱动的）。
async fn spawn_udp_outlet(
    handle: EngineHandle,
    key: SessionKey,
    from: NodeId,
) -> Option<ServiceTask> {
    let socket = match bind_outlet("0.0.0.0:0".parse().expect("回环地址是常量")).await {
        Ok(s) => s,
        Err(e) => {
            warn!(key = ?key, error = %e, "UDP 出口无法绑定");
            handle
                .ready_session(key, from, SessionCode::Denied, "UDP 出口无法绑定")
                .await
                .ok();
            return None;
        }
    };
    let Ok(bind) = socket.local_addr() else {
        return None;
    };
    let session = match handle.open_stream(key, from, SessionKind::Socks5Udp).await {
        Ok(s) => s,
        Err(e) => {
            warn!(key = ?key, error = %e, "UDP 会话流无法建立");
            return None;
        }
    };
    // 先把出口地址告诉发起方（`SessionReady.detail` 在 SOCKS5 UDP 这条路上
    // 就是「出口绑定地址」，见 `udp_relay::ready_message` 的文档）。
    let ready = stowaway_core::ready_message(key, bind);
    if let Message::SessionReady(ready) = &ready {
        handle
            .ready_session(key, from, ready.code, ready.detail.clone())
            .await
            .ok();
    }
    let task = tokio::spawn(async move {
        let idle = Duration::from_secs(UDP_IDLE_TIMEOUT_SECS);
        let _ = outlet_side_on(socket, session, MAX_UDP_DATAGRAM, idle).await;
    });
    Some(ServiceTask {
        key,
        kind: ServiceKind::Connect,
        handle: task,
    })
}

/// 服务配置：下载目录、shell 编解码、SSH host key 策略。
/// `listen` 服务要用的上下文：新建链路的监听规格、编号分配器、本端在树里的位置。
///
/// 被控端替别人起监听时**由本端扮父节点**（v1 `agent/handler/listen.go` 的
/// `normalListen` 就是发伪 admin 的 `HI`），所以这里必须带上 `me`/`root`/
/// `depth` 与分配器；上游编号取 `JoinAck.parent`，好让新子节点被上游看见
/// （缺了它，admin 看不到孙节点，见 plan §4.14 E6）。
fn listen_context(args: &cli::Args, ack: &JoinAck) -> anyhow::Result<Option<Arc<ListenContext>>> {
    // `--down` 决定 listen 用什么传输：没有显式 `--down` 就沿用上行。
    let spec = args.downstream_spec()?;
    let secret = Arc::new(load_secret(args)?);
    let alloc = NodeIdAllocator::new(salt_from_secret(&secret.digest()));
    Ok(Some(Arc::new(
        ListenContext::new(secret.clone(), spec, alloc, ack.node, ack.root, ack.depth)
            .with_upstream(Some(ack.parent)),
    )))
}

fn service_config(args: &cli::Args) -> ServiceConfig {
    ServiceConfig {
        download_dir: args.download_dir.as_ref().map_or_else(
            || std::env::temp_dir().join("stowaway-downloads"),
            std::path::PathBuf::from,
        ),
        charset: args.cs.charset(),
        host_key_policy: args.host_key_policy.policy(),
        known_hosts: args.known_hosts.as_ref().map(std::path::PathBuf::from),
    }
}

/// 客户端 TLS（`--tls` 时启用）：有 pin 就严格校验，否则 TOFU。
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

/// 服务端 TLS（`--tls` 时启用）：证书从共享密钥派生（plan §4.7 D6）。
///
/// # Errors
/// `--tls` 已开启但证书装配失败。**必须拒绝启动**：静默降级成明文会让
/// 用户以为自己在加密信道上（缺陷 #5 的反面），而 `--tls` 是显式承诺。
fn server_tls(args: &cli::Args) -> anyhow::Result<Option<TlsConfig>> {
    if !args.tls {
        return Ok(None);
    }
    let secret = load_secret(args)?;
    let san: Vec<String> = args.domain.iter().cloned().collect();
    let cfg = TlsConfig::server(&secret.digest(), &san)
        .map_err(|e| anyhow::anyhow!("TLS 服务端配置失败（--tls 已开启，拒绝以明文启动）：{e}"))?;
    Ok(Some(cfg))
}

/// 读共享密钥。长度下限按 `--allow-weak-secret` 决定（plan §5.1 / E10）。
fn load_secret(args: &cli::Args) -> anyhow::Result<Secret> {
    let raw = args.secret.as_deref().ok_or_else(|| {
        anyhow::anyhow!("缺少 `--secret`（共享密钥，可用 env:/file:/stdin: 前缀）")
    })?;
    let min = if args.allow_weak_secret {
        1
    } else {
        MIN_SECRET_LEN
    };
    if args.allow_weak_secret && min < MIN_SECRET_LEN {
        warn!("`--allow-weak-secret` 已启用：密钥短于 {MIN_SECRET_LEN} 字节，仅限调试");
    }
    Ok(Secret::load(raw, min)?)
}

/// 上游对端的保留编号：admin 恒为 [`NodeId::ADMIN`]。
fn peer_id_of(kind: NodeKind) -> NodeId {
    match kind {
        NodeKind::Admin => NodeId::ADMIN,
        // agent 拨进来当父节点是非法拓扑（agent 不能充当别人的上游），
        // 用 `UNASSIGNED` 让 `follow` 的登记路径报错而不是静默接受。
        NodeKind::Agent => NodeId::UNASSIGNED,
    }
}

/// 让 `KEY_LEN` 的引用保持可见（测试与文档引用都指向它）。
const _: usize = KEY_LEN;
