//! 端口复用（`docs/plan.md` §4.11）。
//!
//! 权威：`docs/plan.md` §4.11（后端只保留 iptables、magic 安装期随机、检查退出码
//! 并回滚、Windows 不支持、非本协议流量回落 `127.0.0.1:<report>`）、
//! §8.5 场景 10（端口复用回落，外部服务共存）。
//! v1 参考实现：`Stowaway/agent/initial/method.go:249-281`
//! （`SetPortReuseRules` / `DeletePortReuseRules`）。
//!
//! # 修的 v1 缺陷 #10（§3）
//!
//! v1 把 5 条 `iptables` 命令交给 `exec.Command(...).Run()` 并**丢掉返回错误**：
//! 规则装失败照样往下跑，之后 `NormalPassive` 在复用端口上等一条永远不会被
//! REDIRECT 过来的连接，表现是「端口复用静默失效」。v2 逐条**检查退出码**，
//! 任一步失败就把本次已成功的步骤按逆序撤销（[`install`] 的返回值就是「本次
//! 真正装上了哪几步」），并把 iptables 的原始 stderr 一起带回调用方。
//!
//! # 与 v1 的其它差异
//!
//! - **magic**：v1 由 secret 派生（`setReuseSecret`，`method.go:241`）——派生值是
//!   secret 的函数，泄露 magic 等于给离线爆破一个已知明文。v2 改为安装期随机的
//!   16 字符（`--reuse-magic`，plan §4.11 / 附录 E11），由调用方传入本模块，
//!   **本模块不生成、不持久化 secret**。
//! - **链名**：v1 用固定 `STOWAWAY`，同一台机器上多份配置会互相踩。v2 由
//!   magic + 两个端口派生（`STWR` + sha256 前 10 字节的大写十六进制 = 24 字符），
//!   字符集与长度都在 iptables 限制内（≤28 字符，字母/数字/下划线/横线）。
//! - **两个 magic**：v1 需要「开始转发」与「停止转发」两个不同字符串。本模块只
//!   拿到一个 16 字符 magic，故 stop = 反转(magic)（见 [`ReuseConfig::magic_stop`]）。
//!
//! # 不做的事
//!
//! 本层**不碰任何 socket**：它只负责把规则装上/卸下，以及给出「一条不受复用规则
//! 照顾的入站连接该去哪」的判定（[`decide_fallback`]）。**嗅探不在这里做**——
//! 按首字节判协议已经是 `stowaway_transport::sniff::classify` 的职责（plan §4.11
//! 「TLS 下嗅探」一行），在回落层再嗅一遍会得到两个可能不一致的判定。

use std::process::Command;

use sha2::{Digest, Sha256};

/// magic 的长度（字符数）。plan §4.11：`--reuse-magic <16 字符>`。
pub const REUSE_MAGIC_LEN: usize = 16;

/// recent 表的保鲜期（秒）。v1 硬编码 3600（`method.go:252`、`:273`）。
pub const REUSE_SAME_SECONDS: u32 = 3600;

/// 第 1 步：新建 nat 表自定义链。
pub const STEP_NEW_CHAIN: &str = "新建 nat 自定义链";
/// 第 2 步：自定义链内的流量重定向到本地监听端口。
pub const STEP_REDIRECT: &str = "自定义链重定向到本地端口";
/// 第 3 步：INPUT 上「开始转发」标记（把来源地址加入 recent 表）。
pub const STEP_MARK_START: &str = "INPUT 设置开始转发标记";
/// 第 4 步：INPUT 上「停止转发」标记（把来源地址移出 recent 表）。
pub const STEP_MARK_STOP: &str = "INPUT 清除开始转发标记";
/// 第 5 步：PREROUTING 上按 recent 表跳转自定义链。
pub const STEP_PREROUTING: &str = "PREROUTING 按 recent 表跳转自定义链";
/// [`probe`] 里 `iptables -V` 这一步（不属于装机 5 步）。
pub const STEP_PROBE_VERSION: &str = "探测 iptables 版本";
/// [`probe`] 里试建探针链这一步。
pub const STEP_PROBE_CHAIN: &str = "试建探针链";
/// [`probe`] 里往探针链加规则这一步。
pub const STEP_PROBE_RULE: &str = "探针链加规则";
/// [`probe`] 里清理探针链这一步。
pub const STEP_PROBE_CLEAN: &str = "清理探针链";

/// 端口复用配置。
///
/// 通过 [`ReuseConfig::new`] 构造（它校验 magic 长度与端口，并派生链名），
/// 再用 [`ReuseConfig::with_same_seconds`] 改写保鲜期。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReuseConfig {
    /// 安装期随机的 16 字符 magic（**不是** secret 的派生值）。
    pub magic: String,
    /// 对外的复用端口（客户端连这个端口）。
    pub reused_port: u16,
    /// 本模块真正监听的本地端口（REDIRECT 的目标）。
    pub local_port: u16,
    /// recent 表的保鲜期（秒，1..=4294967295）。
    pub same_seconds: u32,
    /// 由 magic + 两个端口派生的 iptables 链名（24 字符，字符集安全）。
    pub chain: String,
}

impl ReuseConfig {
    /// 构造配置并派生链名。
    ///
    /// 校验：magic 必须**正好** [`REUSE_MAGIC_LEN`] 个字符；两个端口都不能是 0
    /// （iptables 接受 `--to-port 0`、`--dport 0`，但那不是「一个端口」，装机成功
    /// 也毫无意义，所以在入口就拒绝）。
    ///
    /// # Errors
    ///
    /// magic 长度不符返回 [`ReuseError::BadMagic`]；端口为 0 返回
    /// [`ReuseError::BadPort`]。
    pub fn new(
        magic: &str,
        reused_port: u16,
        local_port: u16,
    ) -> std::result::Result<Self, ReuseError> {
        let actual = magic.chars().count();
        if actual != REUSE_MAGIC_LEN {
            return Err(ReuseError::BadMagic {
                actual,
                need: REUSE_MAGIC_LEN,
            });
        }
        if reused_port == 0 || local_port == 0 {
            return Err(ReuseError::BadPort);
        }
        Ok(Self {
            magic: magic.to_string(),
            reused_port,
            local_port,
            same_seconds: REUSE_SAME_SECONDS,
            chain: derive_chain(magic, reused_port, local_port),
        })
    }

    /// 改写 recent 保鲜期。缺省 [`REUSE_SAME_SECONDS`]。
    ///
    /// 这里不做范围校验：iptables 自己对 `--seconds 0` 报
    /// `bad value for option "--seconds", or out of range (1-4294967295)`，
    /// 让第 5 步如实失败并触发回滚，比在本地猜一个上界更诚实。
    #[must_use]
    pub fn with_same_seconds(mut self, secs: u32) -> Self {
        self.same_seconds = secs;
        self
    }

    /// 「停止转发」用的 magic = 反转(magic)。
    ///
    /// v1 有 `START_FORWARDING` / `STOP_FORWARDING` **两个**独立字符串
    /// （`method.go:241` 从 md5 链里各切 16 字节），本模块只拿到一个 16 字符
    /// magic，于是把 stop 定义成它的反序：长度相同、必然不同、且仍只由这一个
    /// 入参决定（不需要额外的 CLI 参数）。它和 v1 的差异是**派生方式**，语义
    /// （一个字符串入表、另一个出表）完全一致。
    ///
    /// 反序对回文 magic 会得到与 start 相同的串——那样两条 INPUT 规则会互相
    /// 抵消（`--set` 后立刻 `--remove`），复用彻底失效。因此回文时改掉首字符。
    #[must_use]
    pub fn magic_stop(&self) -> String {
        let reversed: String = self.magic.chars().rev().collect();
        if reversed != self.magic {
            return reversed;
        }
        const CANDIDATES: [char; 5] = ['A', 'B', '0', '1', '_'];
        let mut chars: Vec<char> = reversed.chars().collect();
        if let Some(first) = chars.first().copied()
            && let Some(repl) = CANDIDATES.iter().copied().find(|c| *c != first)
            && let Some(slot) = chars.first_mut()
        {
            *slot = repl;
        }
        chars.into_iter().collect()
    }

    /// 第 1 步：`iptables -t nat -N <chain>`。
    fn argv_new_chain(&self) -> Vec<String> {
        vec!["-t".into(), "nat".into(), "-N".into(), self.chain.clone()]
    }

    /// 第 2 步：`-t nat -A <chain> -p tcp -j REDIRECT --to-port <local_port>`。
    fn argv_redirect(&self) -> Vec<String> {
        vec![
            "-t".into(),
            "nat".into(),
            "-A".into(),
            self.chain.clone(),
            "-p".into(),
            "tcp".into(),
            "-j".into(),
            "REDIRECT".into(),
            "--to-port".into(),
            self.local_port.to_string(),
        ]
    }

    /// 第 3 步：INPUT 上的「开始转发」标记。
    ///
    /// 与 v1 的唯一差异：recent 表名用派生链名原样（v1 用 `strings.ToLower`），
    /// 本机 iptables 1.8.7 对大小写都接受，少一次变换就少一处不一致。
    fn argv_mark_start(&self) -> Vec<String> {
        vec![
            "-A".into(),
            "INPUT".into(),
            "-p".into(),
            "tcp".into(),
            "-m".into(),
            "string".into(),
            "--string".into(),
            self.magic.clone(),
            "--algo".into(),
            "bm".into(),
            "-m".into(),
            "recent".into(),
            "--set".into(),
            "--name".into(),
            self.chain.clone(),
            "--rsource".into(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    }

    /// 第 4 步：INPUT 上的「停止转发」标记（v1 这条也不带 `--rsource`）。
    fn argv_mark_stop(&self) -> Vec<String> {
        vec![
            "-A".into(),
            "INPUT".into(),
            "-p".into(),
            "tcp".into(),
            "-m".into(),
            "string".into(),
            "--string".into(),
            self.magic_stop(),
            "--algo".into(),
            "bm".into(),
            "-m".into(),
            "recent".into(),
            "--name".into(),
            self.chain.clone(),
            "--remove".into(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    }

    /// 第 5 步：PREROUTING 上检查 recent 表并跳自定义链。
    fn argv_prerouting(&self) -> Vec<String> {
        vec![
            "-t".into(),
            "nat".into(),
            "-A".into(),
            "PREROUTING".into(),
            "-p".into(),
            "tcp".into(),
            "--dport".into(),
            self.reused_port.to_string(),
            "--syn".into(),
            "-m".into(),
            "recent".into(),
            "--rcheck".into(),
            "--seconds".into(),
            self.same_seconds.to_string(),
            "--name".into(),
            self.chain.clone(),
            "--rsource".into(),
            "-j".into(),
            self.chain.clone(),
        ]
    }
}

/// 一条 iptables 命令的失败详情（`code == None` 表示根本没跑起来）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdFailure {
    /// 退出码；进程 spawn 失败时为 `None`。
    pub code: Option<i32>,
    /// iptables 的原始 stderr（已 trim）。
    pub stderr: String,
}

/// 命令执行器抽象：生产用 [`system_run`]，测试可注入记录/失败注入的闭包。
///
/// 抽出来是为了让「第 N 步失败 → 回滚序列」这条路径可以在**不碰真实 iptables**
/// 的前提下断言（详见本文件 `mod tests` 与
/// `crates/stowaway-core/tests/reuse_e2e.rs`）。
pub type Runner<'a> = dyn Fn(&[&str]) -> std::result::Result<(), CmdFailure> + 'a;

/// 端口复用的错误。所有 iptables 失败都带上**原始 stderr**，不吞。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReuseError {
    /// magic 长度不符。
    #[error("reuse magic 必须正好 {need} 个字符，实际 {actual} 个")]
    BadMagic {
        /// 实际字符数。
        actual: usize,
        /// 期望字符数。
        need: usize,
    },

    /// 端口为 0（不是一个可用端口）。
    #[error("端口不能为 0：复用端口与本地端口都必须是 1-65535")]
    BadPort,

    /// 平台不支持。
    #[error("平台不支持端口复用：{0}")]
    Unsupported(&'static str),

    /// 某一 步 iptables 命令失败。
    #[error("iptables 第「{step}」步失败（退出码 {code:?}）：{stderr}")]
    CommandFailed {
        /// 失败的步骤（`STEP_*` 之一）。
        step: &'static str,
        /// 退出码。
        code: Option<i32>,
        /// iptables 的原始 stderr。
        stderr: String,
    },

    /// 回滚本身失败：机器上可能残留规则，必须让调用方看见。
    #[error("第「{step}」步回滚失败，iptables 可能残留规则：{detail}")]
    RollbackFailed {
        /// 回滚失败的步骤。
        step: &'static str,
        /// 细节（同时包含最初那步的失败原因）。
        detail: String,
    },

    /// 需要 root / `CAP_NET_ADMIN`。
    #[error("需要 root（CAP_NET_ADMIN）才能安装 iptables 端口复用规则")]
    NotRoot,
}

/// 默认执行器：真的去跑 `iptables`。
///
/// 失败时保留退出码与**原始 stderr**（trim 过，保留换行），供上层原样打印。
pub fn system_run(argv: &[&str]) -> std::result::Result<(), CmdFailure> {
    match Command::new("iptables").args(argv).output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(CmdFailure {
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        }),
        Err(e) => Err(CmdFailure {
            code: None,
            stderr: e.to_string(),
        }),
    }
}

/// 平台适配（plan §4.11 平台行）。
///
/// Linux 之外没有等价实现：
/// - Windows 的 `SO_REUSEADDR` 语义与 BSD 不同，遇到 `SO_EXCLUSIVEADDRUSE` 时
///   `bind` **直接失败**，装规则也无处可落；
/// - macOS/BSD 的 `pf` 不能等价表达 `-m string` / `-m recent`（plan §4.11 已删掉
///   「nftables/pf 优先」的旧方案），只剩 `SO_REUSEPORT`。
///
/// # Errors
///
/// 非 Linux 返回 [`ReuseError::Unsupported`]。
pub fn platform_supported() -> std::result::Result<(), ReuseError> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(ReuseError::Unsupported(
            "只有 Linux 支持 iptables 端口复用；Windows 的 SO_EXCLUSIVEADDRUSE 下 bind 直接失败，macOS/BSD 只有 SO_REUSEPORT",
        ))
    }
}

/// 探测本机是否支持端口复用：`iptables -V` + 试建一个探针链（含
/// `-m string` / `-m recent` / `REDIRECT` / `--syn` / `--seconds` 的真实解析），
/// 然后删掉。
///
/// 探针链名带进程号，避免与真实配置链或其他进程的探针撞名；无论成功失败都尽力清理。
///
/// # Errors
///
/// 平台不支持 → [`ReuseError::Unsupported`]；非 root → [`ReuseError::NotRoot`]；
/// `iptables` 不存在或某一步失败 → [`ReuseError::CommandFailed`]（带原始 stderr）。
pub fn probe() -> std::result::Result<(), ReuseError> {
    platform_supported()?;
    require_root()?;

    let version = match Command::new("iptables").arg("-V").output() {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            return Err(ReuseError::CommandFailed {
                step: STEP_PROBE_VERSION,
                code: out.status.code(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReuseError::Unsupported("未找到 iptables 可执行文件"));
        }
        Err(e) => {
            return Err(ReuseError::CommandFailed {
                step: STEP_PROBE_VERSION,
                code: None,
                stderr: e.to_string(),
            });
        }
    };
    let _ = version; // 只需要「能跑」这个结论；版本串不进错误信息。

    let chain = probe_chain_name();
    // 上一轮崩溃可能留下同名探针链：先尽力清掉，清不掉就让后面的 -N 如实失败。
    let _ = run_raw(&["-t", "nat", "-F", &chain]);
    let _ = run_raw(&["-t", "nat", "-X", &chain]);

    run_raw(&["-t", "nat", "-N", &chain]).map_err(|f| ReuseError::CommandFailed {
        step: STEP_PROBE_CHAIN,
        code: f.code,
        stderr: f.stderr,
    })?;

    let magic = "STWPROBE0123ABCD";
    let recent = chain.to_ascii_lowercase();
    let rule_ok = run_raw(&[
        "-t",
        "nat",
        "-A",
        &chain,
        "-p",
        "tcp",
        "-j",
        "REDIRECT",
        "--to-port",
        "1",
    ])
    .and_then(|()| {
        run_raw(&[
            "-t",
            "nat",
            "-A",
            &chain,
            "-p",
            "tcp",
            "--dport",
            "1",
            "--syn",
            "-m",
            "recent",
            "--rcheck",
            "--seconds",
            &REUSE_SAME_SECONDS.to_string(),
            "--name",
            &recent,
            "--rsource",
            "-j",
            "RETURN",
        ])
    })
    .and_then(|()| {
        run_raw(&[
            "-t",
            "nat",
            "-A",
            &chain,
            "-p",
            "tcp",
            "-m",
            "string",
            "--string",
            magic,
            "--algo",
            "bm",
            "-m",
            "recent",
            "--set",
            "--name",
            &recent,
            "--rsource",
            "-j",
            "RETURN",
        ])
    });

    // 无论探针规则是否成功，都要清掉链，否则本机残留一条无人引用的探针链。
    let _ = run_raw(&["-t", "nat", "-F", &chain]);
    let cleanup = run_raw(&["-t", "nat", "-X", &chain]);

    rule_ok.map_err(|f| ReuseError::CommandFailed {
        step: STEP_PROBE_RULE,
        code: f.code,
        stderr: f.stderr,
    })?;
    cleanup.map_err(|f| ReuseError::CommandFailed {
        step: STEP_PROBE_CLEAN,
        code: f.code,
        stderr: f.stderr,
    })?;
    Ok(())
}

/// 安装复用规则（幂等）。
///
/// 幂等性：先尽力清掉上一次留下的同类规则与链（清理失败不报错——真正的问题会在
/// 下面 5 步里暴露出来），然后依次装 5 条规则。
///
/// **任一步失败 → 把本次已成功的步骤按逆序撤销 → 返回 [`ReuseError::CommandFailed`]**；
/// 若撤销本身也失败，返回 [`ReuseError::RollbackFailed`]（信息里同时带上最初的失败
/// 原因），因为「机器上可能残留规则」比「装机失败」更需要调用方看见。
///
/// # Errors
///
/// 见 [`ReuseError`]；iptables 的原始 stderr 一律保留。
pub fn install(cfg: &ReuseConfig) -> std::result::Result<Vec<&'static str>, ReuseError> {
    platform_supported()?;
    require_root()?;
    install_with(cfg, &system_run)
}

/// 同 [`install`]，但命令由 `run` 执行（测试可注入；生产入口见 [`install`]）。
///
/// # Errors
///
/// 同 [`install`]。
pub fn install_with(
    cfg: &ReuseConfig,
    run: &Runner<'_>,
) -> std::result::Result<Vec<&'static str>, ReuseError> {
    // 幂等：第二次装同一条配置必须得到「仍然只有一份规则」，而不是叠加一份。
    let _ = uninstall_with(cfg, run);

    let plan: [(&'static str, Vec<String>); 5] = [
        (STEP_NEW_CHAIN, cfg.argv_new_chain()),
        (STEP_REDIRECT, cfg.argv_redirect()),
        (STEP_MARK_START, cfg.argv_mark_start()),
        (STEP_MARK_STOP, cfg.argv_mark_stop()),
        (STEP_PREROUTING, cfg.argv_prerouting()),
    ];

    let mut applied: Vec<&'static str> = Vec::with_capacity(plan.len());
    for (step, argv) in plan {
        if let Err(f) = exec(run, &argv) {
            let first = failed(step, f);
            return Err(match rollback(cfg, run, &applied, &first) {
                Some(rb) => rb,
                None => first,
            });
        }
        applied.push(step);
    }
    Ok(applied)
}

/// 卸载复用规则（逆序；「本来就不存在」不算错误）。
///
/// 顺序与装机严格相反：先摘 PREROUTING 的跳转（否则链还被引用，
/// `-X` 会以 `CHAIN_USER_DEL failed (Device or resource busy)` 失败），
/// 再摘两条 INPUT 标记，最后 `-F` + `-X`。
///
/// # Errors
///
/// 除「规则/链不存在」以外的失败都返回 [`ReuseError::CommandFailed`]。
pub fn uninstall(cfg: &ReuseConfig) -> std::result::Result<(), ReuseError> {
    platform_supported()?;
    require_root()?;
    uninstall_with(cfg, &system_run)
}

/// 同 [`uninstall`]，但命令由 `run` 执行（测试可注入）。
///
/// # Errors
///
/// 同 [`uninstall`]。
pub fn uninstall_with(cfg: &ReuseConfig, run: &Runner<'_>) -> std::result::Result<(), ReuseError> {
    let plan: [(&'static str, Vec<String>); 5] = [
        (STEP_PREROUTING, cfg.argv_prerouting_delete()),
        (STEP_MARK_STOP, cfg.argv_mark_stop_delete()),
        (STEP_MARK_START, cfg.argv_mark_start_delete()),
        (STEP_NEW_CHAIN, cfg.argv_flush_chain()),
        (STEP_NEW_CHAIN, cfg.argv_delete_chain()),
    ];
    for (step, argv) in plan {
        if let Err(f) = exec(run, &argv) {
            if is_absent(step, f.code) {
                continue;
            }
            return Err(failed(step, f));
        }
    }
    Ok(())
}

/// 一条不受复用规则照顾的入站连接该去哪（plan §4.11 的「回落」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fallback {
    /// 仍由复用监听器自己处理。
    ///
    /// 目前的 [`decide_fallback`] **不会**返回它：判定「这条连接属于复用监听器」
    /// 是 netfilter 的事（规则命中与否），而本函数只拿得到配置与 `--report`，
    /// 不足以判断归属。保留该变体是为了让调用方在**已确知**连接被复用规则
    /// 认领时能表达「不回落」，避免用 `Option` 在调用点二次编码。
    Reuse,
    /// 转投 `127.0.0.1:<report>`（v1 `ProxyStream`，`method.go:390-403`）。
    Report(u16),
    /// 送不走，只能拒绝（带原因）。
    Reject(&'static str),
}

/// 决定一条不受复用规则照顾的入站连接该去哪。
///
/// 语义（plan §4.11「非本协议流量回落 `127.0.0.1:<report>`」）：
/// - 有 `report` → [`Fallback::Report`]，由回落代理把它写进 `127.0.0.1:<report>`；
/// - 没有 `report` → [`Fallback::Reject`]（v1 在这种情况下会去拨 `127.0.0.1:` 这个
///   空地址，得到一个毫无信息量的拨号失败）。
///
/// **本函数不做 sniff**：按首字节判协议是 `stowaway_transport::sniff::classify`
/// 的职责（plan §4.11「TLS 下嗅探」一行，只用 8 字节 + `MSG_PEEK`）。回落层再嗅
/// 一次会得到两个可能不一致的判定，而且会把「已经读掉的字节由谁负责重放」变成
/// 一个跨层约定。这里只做**纯决策**，不碰 socket、不读字节。
#[must_use]
pub fn decide_fallback(_cfg: &ReuseConfig, report: Option<u16>) -> Fallback {
    match report {
        Some(0) => Fallback::Reject("--report 0 不是可用端口（127.0.0.1:0 等于没有目标）"),
        Some(port) => Fallback::Report(port),
        None => Fallback::Reject("既没有 --report 也没装规则，无法把陌生流量送走"),
    }
}

/// 派生链名：`STWR` + sha256(magic ‖ reused_port ‖ local_port) 前 10 字节的大写
/// 十六进制 = 24 字符。
///
/// 用哈希而不是直接拼 magic：magic 是任意 16 字符（可能含空格、引号、非 ASCII），
/// 直接拼会踩 iptables 链名字符集（字母/数字/下划线/横线）与长度（≤28）两条限制；
/// 同时把两个端口纳入哈希，避免「同 magic 不同端口」两份配置共用一个链。
fn derive_chain(magic: &str, reused_port: u16, local_port: u16) -> String {
    let mut hasher = Sha256::new();
    hasher.update(magic.as_bytes());
    hasher.update(reused_port.to_be_bytes());
    hasher.update(local_port.to_be_bytes());
    let digest = hasher.finalize();
    const HEX: [u8; 16] = *b"0123456789ABCDEF";
    let mut chain = String::with_capacity(24);
    chain.push_str("STWR");
    for byte in digest.iter().take(10) {
        chain.push(char::from(HEX[usize::from(byte >> 4)]));
        chain.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    chain
}

/// 探针链名（带进程号，≤28 字符、字符集安全）。
fn probe_chain_name() -> String {
    format!("STWPROBE{}", std::process::id())
}

/// 当前有效 uid（探测不到时返回 `None`，此时不拦，交给 iptables 自己报错）。
fn current_uid() -> Option<u32> {
    let out = Command::new("id").arg("-u").output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// 非 root 时提前失败：让「权限不足」有一个明确错误，而不是一句 iptables stderr。
fn require_root() -> std::result::Result<(), ReuseError> {
    match current_uid() {
        Some(0) | None => Ok(()),
        Some(_) => Err(ReuseError::NotRoot),
    }
}

/// 直接跑一条 iptables 命令（[`probe`] 用；不经过 [`Runner`]）。
fn run_raw(argv: &[&str]) -> std::result::Result<(), CmdFailure> {
    system_run(argv)
}

/// 把 `Vec<String>` 命令交给执行器；失败详情原样返回（由调用方决定包成哪种错误）。
fn exec(run: &Runner<'_>, argv: &[String]) -> std::result::Result<(), CmdFailure> {
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    run(&refs)
}

/// 把一条命令的失败包成 [`ReuseError::CommandFailed`]。
fn failed(step: &'static str, f: CmdFailure) -> ReuseError {
    ReuseError::CommandFailed {
        step,
        code: f.code,
        stderr: f.stderr,
    }
}

/// 已成功步骤的逆序撤销。返回**第一个**回滚失败（若全部成功则为 `None`）。
fn rollback(
    cfg: &ReuseConfig,
    run: &Runner<'_>,
    applied: &[&'static str],
    first: &ReuseError,
) -> Option<ReuseError> {
    let mut failure: Option<ReuseError> = None;
    for step in applied.iter().rev() {
        // 一个步骤可能对应多条撤销命令（新建链 = -F + -X）。
        let undo: Vec<(&'static str, Vec<String>)> = match *step {
            STEP_PREROUTING => vec![(*step, cfg.argv_prerouting_delete())],
            STEP_MARK_STOP => vec![(*step, cfg.argv_mark_stop_delete())],
            STEP_MARK_START => vec![(*step, cfg.argv_mark_start_delete())],
            STEP_REDIRECT => vec![(*step, cfg.argv_redirect_delete())],
            STEP_NEW_CHAIN => vec![
                (*step, cfg.argv_flush_chain()),
                (*step, cfg.argv_delete_chain()),
            ],
            _ => Vec::new(),
        };
        for (name, argv) in undo {
            if let Err(f) = exec(run, &argv)
                && failure.is_none()
            {
                failure = Some(ReuseError::RollbackFailed {
                    step: name,
                    detail: format!(
                        "最初失败：{first}；回滚「{name}」也失败（退出码 {:?}）：{}",
                        f.code, f.stderr
                    ),
                });
            }
        }
    }
    failure
}

/// 卸载时「本来就不存在」的退出码。
///
/// - 删规则（`-D`）：1 = `Bad rule`，2 = `Bad rule` / 目标链不存在；
/// - 删链（`-F` / `-X`）：1 = `No chain/target/match by that name`。
///
/// `-X` 的 4（`Device or resource busy`，链仍被引用）**不**算缺失，必须报错。
fn is_absent(step: &'static str, code: Option<i32>) -> bool {
    let codes: &[i32] = if step == STEP_NEW_CHAIN {
        &[1]
    } else {
        &[1, 2]
    };
    match code {
        Some(c) => codes.contains(&c),
        None => false,
    }
}

impl ReuseConfig {
    /// 第 5 步的删除式（与原 argv 逐字一致，否则 iptables 报 `Bad rule`）。
    fn argv_prerouting_delete(&self) -> Vec<String> {
        replace_flag(self.argv_prerouting(), "-A", "-D")
    }

    /// 第 4 步的删除式。
    fn argv_mark_stop_delete(&self) -> Vec<String> {
        replace_flag(self.argv_mark_stop(), "-A", "-D")
    }

    /// 第 3 步的删除式。
    fn argv_mark_start_delete(&self) -> Vec<String> {
        replace_flag(self.argv_mark_start(), "-A", "-D")
    }

    /// 第 2 步的删除式。
    fn argv_redirect_delete(&self) -> Vec<String> {
        replace_flag(self.argv_redirect(), "-A", "-D")
    }

    /// 第 1 步的撤销之一：`-t nat -F <chain>`。
    fn argv_flush_chain(&self) -> Vec<String> {
        vec!["-t".into(), "nat".into(), "-F".into(), self.chain.clone()]
    }

    /// 第 1 步的撤销之二：`-t nat -X <chain>`。
    fn argv_delete_chain(&self) -> Vec<String> {
        vec!["-t".into(), "nat".into(), "-X".into(), self.chain.clone()]
    }
}

/// 把 argv 里的 `-A` 换成 `-D`（只换第一处）。
fn replace_flag(mut argv: Vec<String>, from: &str, to: &str) -> Vec<String> {
    if let Some(slot) = argv.iter_mut().find(|a| a.as_str() == from) {
        *slot = to.to_string();
    }
    argv
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const MAGIC: &str = "0123456789abcdef";

    fn cfg() -> ReuseConfig {
        ReuseConfig::new(MAGIC, 41000, 41001).expect("测试配置应当合法")
    }

    #[test]
    fn magic_length_is_enforced_in_chars() {
        assert!(ReuseConfig::new(MAGIC, 1, 2).is_ok());
        assert_eq!(
            ReuseConfig::new("0123456789abcde", 1, 2),
            Err(ReuseError::BadMagic {
                actual: 15,
                need: 16
            })
        );
        assert_eq!(
            ReuseConfig::new("0123456789abcdefg", 1, 2),
            Err(ReuseError::BadMagic {
                actual: 17,
                need: 16
            })
        );
        // 多字节字符按「字符」计数，不是按字节。
        let wide = "端口复用0123456789ab";
        assert_eq!(wide.chars().count(), 16);
        assert!(wide.len() > 16, "多字节字符的字节长度应当大于字符数");
        assert!(ReuseConfig::new(wide, 1, 2).is_ok());
    }

    #[test]
    fn zero_ports_are_rejected() {
        assert_eq!(ReuseConfig::new(MAGIC, 0, 1), Err(ReuseError::BadPort));
        assert_eq!(ReuseConfig::new(MAGIC, 1, 0), Err(ReuseError::BadPort));
        assert_eq!(ReuseConfig::new(MAGIC, 0, 0), Err(ReuseError::BadPort));
    }

    #[test]
    fn chain_name_is_short_and_charset_safe() {
        let wide = "端口复用0123456789ab";
        for c in [
            cfg(),
            ReuseConfig::new(wide, 1, 65535).expect("合法"),
            ReuseConfig::new("   spaces test  ", 1, 2).expect("合法"),
        ] {
            assert!(c.chain.len() <= 28, "链名过长：{}", c.chain);
            assert!(c.chain.starts_with("STWR"));
            assert!(
                c.chain
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'),
                "链名含非法字符：{}",
                c.chain
            );
        }
    }

    #[test]
    fn chain_name_separates_ports_and_magics() {
        let a = ReuseConfig::new(MAGIC, 41000, 41001).expect("合法");
        let b = ReuseConfig::new(MAGIC, 41000, 41002).expect("合法");
        let c = ReuseConfig::new("fedcba9876543210", 41000, 41001).expect("合法");
        assert_ne!(a.chain, b.chain);
        assert_ne!(a.chain, c.chain);
        // 同一输入必须稳定（幂等装机依赖这一点）。
        assert_eq!(a.chain, cfg().chain);
    }

    #[test]
    fn stop_magic_is_reverse_and_differs_from_start() {
        let c = cfg();
        assert_eq!(c.magic_stop(), "fedcba9876543210");
        assert_ne!(c.magic_stop(), c.magic);
    }

    #[test]
    fn palindromic_magic_still_yields_distinct_stop_magic() {
        let palindrome = "aaaaaaaaaaaaaaaa";
        let c = ReuseConfig::new(palindrome, 1, 2).expect("合法");
        assert_eq!(c.magic.chars().count(), REUSE_MAGIC_LEN);
        let stop = c.magic_stop();
        assert_ne!(stop, c.magic, "回文 magic 的 stop 必须与 start 不同");
        assert_eq!(stop.chars().count(), REUSE_MAGIC_LEN);
    }

    #[test]
    fn install_builds_five_rules_in_v1_order() {
        let log: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
        let run = |argv: &[&str]| {
            log.borrow_mut()
                .push(argv.iter().map(|s| (*s).to_string()).collect());
            Ok(())
        };
        let applied = install_with(&cfg(), &run).expect("注入 runner 应当成功");
        assert_eq!(
            applied,
            vec![
                STEP_NEW_CHAIN,
                STEP_REDIRECT,
                STEP_MARK_START,
                STEP_MARK_STOP,
                STEP_PREROUTING
            ]
        );
        let calls = log.borrow();
        // 前 5 条是幂等清理（全失败也无所谓，注入 runner 一律 Ok），后 5 条是装机。
        let install = &calls[calls.len() - 5..];
        assert_eq!(install[0][..3], ["-t", "nat", "-N"]);
        assert_eq!(install[0][3], cfg().chain);
        assert_eq!(install[1][2], "-A");
        assert_eq!(install[1][3], cfg().chain);
        assert_eq!(install[1][7], "REDIRECT");
        assert_eq!(install[1][9], "41001");
        // 第 3 步：["-A","INPUT","-p","tcp","-m","string","--string",<magic>,
        //           "--algo","bm","-m","recent","--set","--name",<chain>,"--rsource","-j","ACCEPT"]
        assert_eq!(install[2][..2], ["-A", "INPUT"]);
        assert_eq!(install[2][7], cfg().magic);
        assert_eq!(install[2][12], "--set");
        assert_eq!(install[2][14], cfg().chain);
        assert_eq!(install[2][15], "--rsource");
        // 第 4 步同形，只是 magic 换成反序、`--set` 换成 `--remove`（且不带 --rsource）。
        assert_eq!(install[3][..2], ["-A", "INPUT"]);
        assert_eq!(install[3][7], cfg().magic_stop());
        assert_eq!(install[3][12], "--name");
        assert_eq!(install[3][14], "--remove");
        assert!(!install[3].contains(&"--rsource".to_string()));
        // 第 5 步：["-t","nat","-A","PREROUTING","-p","tcp","--dport",<reused>,
        //           "--syn","-m","recent","--rcheck","--seconds",<secs>,"--name",<chain>,
        //           "--rsource","-j",<chain>]
        assert_eq!(install[4][..2], ["-t", "nat"]);
        assert_eq!(install[4][3], "PREROUTING");
        assert_eq!(install[4][7], "41000");
        assert_eq!(install[4][11], "--rcheck");
        assert_eq!(install[4][13], "3600");
        assert_eq!(install[4][18], cfg().chain);
        assert_eq!(install[4].first().map(String::as_str), Some("-t"));
        assert_eq!(install[4].last().map(String::as_str), Some(&*cfg().chain));
    }

    #[test]
    fn failure_at_step_three_rolls_back_the_two_applied_steps() {
        let log: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
        let run = |argv: &[&str]| {
            log.borrow_mut()
                .push(argv.iter().map(|s| (*s).to_string()).collect());
            if argv.contains(&"--set") {
                return Err(CmdFailure {
                    code: Some(1),
                    stderr: "注入失败".to_string(),
                });
            }
            Ok(())
        };
        let err = install_with(&cfg(), &run).expect_err("第 3 步失败应当整体失败");
        match &err {
            ReuseError::CommandFailed { step, code, .. } => {
                assert_eq!(*step, STEP_MARK_START);
                assert_eq!(*code, Some(1));
            }
            other => panic!("错误类型不对：{other:?}"),
        }
        let calls = log.borrow();
        // 失败点之后只允许出现回滚：撤 REDIRECT、-F 链、-X 链（逆序）。
        // 只认**装机**的第 3 步（`-A INPUT ... --set`）：幂等清理的 `-D INPUT ... --set`
        // 不是失败点，不能把它当锚。
        let failed_at = calls
            .iter()
            .rposition(|c| c[0] == "-A" && c[1] == "INPUT")
            .expect("应当有失败调用");
        let undo = &calls[failed_at + 1..];
        assert_eq!(undo.len(), 3, "回滚命令数不对：{undo:?}");
        assert_eq!(undo[0][..3], ["-t", "nat", "-D"]);
        assert_eq!(undo[0][3], cfg().chain);
        assert_eq!(undo[0].last().map(String::as_str), Some("41001"));
        assert_eq!(undo[1][..3], ["-t", "nat", "-F"]);
        assert_eq!(undo[2][..3], ["-t", "nat", "-X"]);
        assert_eq!(undo[2][3], cfg().chain);
    }

    #[test]
    fn failure_at_first_step_rolls_back_nothing() {
        let log: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
        let run = |argv: &[&str]| {
            log.borrow_mut()
                .push(argv.iter().map(|s| (*s).to_string()).collect());
            if argv.contains(&"-N") {
                return Err(CmdFailure {
                    code: Some(1),
                    stderr: "Chain already exists.".to_string(),
                });
            }
            Ok(())
        };
        let err = install_with(&cfg(), &run).expect_err("第 1 步失败应当整体失败");
        match &err {
            ReuseError::CommandFailed { step, .. } => assert_eq!(*step, STEP_NEW_CHAIN),
            other => panic!("错误类型不对：{other:?}"),
        }
        let calls = log.borrow();
        let failed_at = calls
            .iter()
            .rposition(|c| c.contains(&"-N".to_string()))
            .expect("应当有失败调用");
        assert_eq!(calls.len(), failed_at + 1, "没有已成功步骤时不该有回滚");
    }

    #[test]
    fn rollback_failure_is_reported_not_swallowed() {
        let run = |argv: &[&str]| {
            if argv.contains(&"--set") {
                return Err(CmdFailure {
                    code: Some(1),
                    stderr: "规则装不上".to_string(),
                });
            }
            if argv.contains(&"-D") || argv.contains(&"-F") || argv.contains(&"-X") {
                return Err(CmdFailure {
                    code: Some(4),
                    stderr: "Device or resource busy".to_string(),
                });
            }
            Ok(())
        };
        let err = install_with(&cfg(), &run).expect_err("应当失败");
        match &err {
            ReuseError::RollbackFailed { detail, .. } => {
                assert!(
                    detail.contains("最初失败"),
                    "detail 丢了原失败原因：{detail}"
                );
                assert!(detail.contains("busy"), "detail 丢了回滚 stderr：{detail}");
            }
            other => panic!("错误类型不对：{other:?}"),
        }
    }

    #[test]
    fn uninstall_is_reverse_order_and_tolerates_absence() {
        let log: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
        let run = |argv: &[&str]| {
            log.borrow_mut()
                .push(argv.iter().map(|s| (*s).to_string()).collect());
            // 全部「本来就不存在」。
            Err(CmdFailure {
                code: Some(1),
                stderr: "No chain/target/match by that name.".to_string(),
            })
        };
        uninstall_with(&cfg(), &run).expect("缺失不算错");
        let calls = log.borrow();
        assert_eq!(calls.len(), 5);
        // 逆序：PREROUTING 跳转 → 停止标记 → 开始标记 → -F → -X
        assert_eq!(calls[0][..4], ["-t", "nat", "-D", "PREROUTING"]);
        assert_eq!(calls[1][0], "-D");
        assert_eq!(calls[1][1], "INPUT");
        assert!(calls[1].contains(&"--remove".to_string()));
        assert_eq!(calls[2][0], "-D");
        assert_eq!(calls[2][1], "INPUT");
        assert_eq!(calls[2][7], cfg().magic);
        assert!(calls[2].contains(&"--set".to_string()));
        assert_eq!(calls[3][..3], ["-t", "nat", "-F"]);
        assert_eq!(calls[4][..3], ["-t", "nat", "-X"]);
    }

    #[test]
    fn uninstall_reports_busy_chain_as_error() {
        let run = |argv: &[&str]| {
            if argv.contains(&"-X") {
                return Err(CmdFailure {
                    code: Some(4),
                    stderr: "CHAIN_USER_DEL failed (Device or resource busy)".to_string(),
                });
            }
            Ok(())
        };
        match uninstall_with(&cfg(), &run) {
            Err(ReuseError::CommandFailed { step, code, stderr }) => {
                assert_eq!(step, STEP_NEW_CHAIN);
                assert_eq!(code, Some(4));
                assert!(stderr.contains("busy"));
            }
            other => panic!("应当报错，实际：{other:?}"),
        }
    }

    #[test]
    fn fallback_prefers_report_then_rejects() {
        let c = cfg();
        assert_eq!(decide_fallback(&c, Some(41002)), Fallback::Report(41002));
        assert_eq!(decide_fallback(&c, Some(65535)), Fallback::Report(65535));
        assert_eq!(
            decide_fallback(&c, Some(0)),
            Fallback::Reject("--report 0 不是可用端口（127.0.0.1:0 等于没有目标）")
        );
        match decide_fallback(&c, None) {
            Fallback::Reject(reason) => {
                assert!(reason.contains("--report"), "原因应当提到缺什么：{reason}");
            }
            other => panic!("没有 report 时应当 Reject，实际：{other:?}"),
        }
    }

    #[test]
    fn platform_gate_matches_target_os() {
        if cfg!(target_os = "linux") {
            assert!(platform_supported().is_ok());
        } else {
            match platform_supported() {
                Err(ReuseError::Unsupported(msg)) => {
                    assert!(msg.contains("Linux"));
                }
                other => panic!("非 Linux 平台应当 Unsupported，实际：{other:?}"),
            }
        }
    }

    #[test]
    fn same_seconds_setter_only_changes_that_field() {
        let c = cfg().with_same_seconds(60);
        assert_eq!(c.same_seconds, 60);
        assert_eq!(c.chain, cfg().chain);
        assert_eq!(cfg().same_seconds, REUSE_SAME_SECONDS);
    }
}
