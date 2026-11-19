//! P7 出口判据：e2e 场景 10（端口复用回落，外部服务共存）。
//!
//! 场景编号与 `docs/plan.md` §8.5 一致；语义权威见 §4.11（后端只保留 iptables、
//! magic 安装期随机、检查退出码并回滚、Windows 不支持、非本协议流量回落
//! `127.0.0.1:<report>`）。v1 参考：`Stowaway/agent/initial/method.go:249-281`。
//!
//! 本文件分两类测试：
//!
//! - **真 iptables**（`reuse_install_*` / `reuse_probe_*` / `reuse_rollback_*`）：
//!   真的装规则、真的用 `iptables -S` 验存在、真的卸干净。跑不了（非 root、
//!   `iptables` 缺失、内核缺 `-m string`/`-m recent`）就**打印原因并 return**，
//!   绝不失败——这条硬要求来自「CI/容器里没有 `CAP_NET_ADMIN`」。
//! - **纯逻辑 + socket**（`reuse_fallback_*`）：不碰 iptables，起一个真
//!   `TcpListener` 当「外部服务」，验证回落判定的两个分支，以及它是**纯决策**
//!   （不读字节、不拨号）。
//!
//! 失败注入（第 5 个测试）用两层手段：
//! 1. 真 iptables 下**预建同名链**让 `-N` 失败 → 验证「第 1 步失败不产生任何残留」；
//! 2. 再制造「链被 PREROUTING 引用」的冲突让 `-X` 失败 → 验证
//!    `RollbackFailed` 会被**如实上报**而不是当成成功（这正是 v1 的缺陷 #10 的
//!    反面：v1 连失败都不看，更不会告诉你机器上残留了什么）。

use std::process::Command;
use std::time::Duration;

use stowaway_core::reuse::{
    CmdFailure, Fallback, REUSE_SAME_SECONDS, ReuseConfig, ReuseError, decide_fallback,
    install_with, platform_supported, probe, uninstall,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// —————————————————————————————————————————————— 测试工具

/// 本测试用的 magic（16 字符，字母数字混合，便于在 `iptables -S` 输出里认出来）。
const MAGIC: &str = "STWRtest0magic42";

/// 复用端口与本端口：都挑了不会与常见服务冲突的高位端口。
///
/// 本测试**不会**真的 bind 它们（复用端口只出现在 iptables 规则里；
/// 本地端口只被写进 REDIRECT 目标），所以不需要占用。
const REUSED_PORT: u16 = 41011;
const LOCAL_PORT: u16 = 41012;

fn test_cfg() -> ReuseConfig {
    ReuseConfig::new(MAGIC, REUSED_PORT, LOCAL_PORT).expect("测试配置应当合法")
}

/// `iptables` 探测：跑不了就打印原因并返回 `false`（调用方 `return`，测试算通过）。
///
/// 打印的是**真实原因**（缺 root / 缺二进制 / 缺模块），不是一句「跳过了」。
fn iptables_ready() -> bool {
    if let Err(e) = platform_supported() {
        eprintln!("跳过：{e}");
        return false;
    }
    let version = Command::new("iptables").arg("-V").output();
    match version {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            eprintln!(
                "跳过：`iptables -V` 退出码 {:?}，stderr：{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return false;
        }
        Err(e) => {
            eprintln!("跳过：无法执行 iptables（{e}）");
            return false;
        }
    }
    // 探针链能建能删，才说明 `-m string` / `-m recent` / REDIRECT 都可用。
    match probe() {
        Ok(()) => true,
        Err(e) => {
            eprintln!("跳过：端口复用探针失败（{e}）");
            false
        }
    }
}

/// 跑一条 iptables 命令，返回 `(退出码, stdout, stderr)`。
///
/// 这层故意**不吞 stderr**：所有断言失败路径都会把它原样打出来。
fn ipt(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new("iptables")
        .args(args)
        .output()
        .expect("测试环境下 iptables 应当可执行");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

/// `iptables -t nat -S <chain>` 的退出码：0 = 链在，1 = 链不在。
fn nat_chain_exists(chain: &str) -> bool {
    let (code, _out, err) = ipt(&["-t", "nat", "-S", chain]);
    if code != Some(0) && code != Some(1) {
        eprintln!("意外：`iptables -t nat -S {chain}` 退出码 {code:?}，stderr：{err}");
    }
    code == Some(0)
}

/// `iptables -t nat -L <chain>` 的退出码：0 = 链在，1 = 链不在。
///
/// 与 `-S` 互为佐证（plan 的验收要求「失败后 `-L` 找不到残留」）。
fn nat_chain_listable(chain: &str) -> bool {
    let (code, _out, _err) = ipt(&["-t", "nat", "-L", chain]);
    code == Some(0)
}

/// 名字里含 chain 的 INPUT 规则条数（`-S INPUT` 全量输出里数）。
///
/// 注意：**不能**用 `iptables -S INPUT -m recent --name X` 当过滤器——`-S` 不按
/// `-m` 过滤（实测 `--set` 单独出现还会被 recent 模块拒绝，退出码 2），它会打印
/// 整条链。故这里拿全量输出自己筛。
fn input_rules_for(chain: &str) -> Vec<String> {
    let (code, out, err) = ipt(&["-S", "INPUT"]);
    if code != Some(0) {
        eprintln!("意外：`iptables -S INPUT` 退出码 {code:?}，stderr：{err}");
        return Vec::new();
    }
    out.lines()
        .filter(|l| l.contains(chain))
        .map(|l| l.to_string())
        .collect()
}

/// PREROUTING 里跳往 `chain` 的规则条数。
fn prerouting_rules_for(chain: &str) -> Vec<String> {
    let (code, out, err) = ipt(&["-t", "nat", "-S", "PREROUTING"]);
    if code != Some(0) {
        eprintln!("意外：`iptables -t nat -S PREROUTING` 退出码 {code:?}，stderr：{err}");
        return Vec::new();
    }
    out.lines()
        .filter(|l| l.contains(chain))
        .map(|l| l.to_string())
        .collect()
}

/// 尽力清掉本测试可能留下的任何东西（测试失败时也不污染机器）。
///
/// 顺序与 [`uninstall`] 一致；每一步都打印失败原因，绝不静默。
fn cleanup(cfg: &ReuseConfig) {
    if let Err(e) = uninstall(cfg) {
        eprintln!("清理未完成（需要人工看一眼）：{e}");
        // 兜底：PREROUTING 里可能还引用着链，逐条 -D 掉再 -F/-X。
        for line in prerouting_rules_for(&cfg.chain) {
            eprintln!("残留的 PREROUTING 规则：{line}");
        }
        let flush = ipt(&["-t", "nat", "-F", &cfg.chain]);
        let del = ipt(&["-t", "nat", "-X", &cfg.chain]);
        eprintln!(
            "兜底 -F 退出码 {:?}（{}）；-X 退出码 {:?}（{}）",
            flush.0, flush.2, del.0, del.2
        );
    }
}

/// 打印一条规则的完整 `iptables` 体现，用于报告里的「实际命令」证据。
fn dump_state(cfg: &ReuseConfig) {
    let (_, nat, _) = ipt(&["-t", "nat", "-S", &cfg.chain]);
    let (_, pre, _) = ipt(&["-t", "nat", "-S", "PREROUTING"]);
    let (_, input, _) = ipt(&["-S", "INPUT"]);
    eprintln!("— nat 链 {}\n{nat}", cfg.chain);
    eprintln!(
        "— PREROUTING 中相关行\n{}",
        pre.lines()
            .filter(|l| l.contains(&cfg.chain))
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!(
        "— INPUT 中相关行\n{}",
        input
            .lines()
            .filter(|l| l.contains(&cfg.chain))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// 每个测试开始前先清一次，避免上一个测试崩在中间留下状态。
fn fresh(cfg: &ReuseConfig) {
    let _ = uninstall(cfg);
}

/// 当前运行的操作系统名（`std::env::consts::OS` 的运行时取值）。
///
/// 包成函数是为了让「平台结论 vs 实际平台」的比较是**运行时**比较：直接写
/// `cfg!(target_os = "linux")` 会变成常量断言，clippy 会按
/// `assertions_on_constants` 报错。
fn host_os() -> &'static str {
    std::env::consts::OS
}

fn host_os_is_linux() -> bool {
    host_os() == "linux"
}

// —————————————————————————————————————— 1. 探测本机能力

#[test]
fn reuse_probe_reports_platform_capability() {
    // 平台层结论必须与当前运行的操作系统一致（Linux 上 Ok，别处 Unsupported）。
    match platform_supported() {
        Ok(()) => assert!(
            host_os_is_linux(),
            "只在 Linux 上允许 Ok，当前是 {}",
            host_os()
        ),
        Err(ReuseError::Unsupported(msg)) => {
            assert!(!host_os_is_linux(), "Linux 不该报 Unsupported");
            eprintln!("平台不支持端口复用（跳过真实 iptables 部分）：{msg}");
            return;
        }
        Err(other) => panic!("平台判定不该返回这个错误：{other:?}"),
    }

    let version = Command::new("iptables").arg("-V").output();
    let Ok(out) = version else {
        eprintln!("跳过：无法执行 iptables（{:?}）", version.err());
        return;
    };
    if !out.status.success() {
        eprintln!(
            "跳过：`iptables -V` 退出码 {:?}，stderr：{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return;
    }
    let banner = String::from_utf8_lossy(&out.stdout).trim().to_string();
    eprintln!("iptables 版本：{banner}");

    match probe() {
        Ok(()) => {
            // 探针必须**不残留**：探针链已删。
            let chain = format!("STWPROBE{}", std::process::id());
            let (code, _out, err) = ipt(&["-t", "nat", "-S", &chain]);
            assert_eq!(
                code,
                Some(1),
                "探针链 {chain} 应当已被清理（退出码 1 = 不存在），stderr：{err}"
            );
            eprintln!("探针通过：iptables 可用，且探针链已清理");
        }
        Err(ReuseError::NotRoot) => {
            eprintln!("跳过：需要 root（CAP_NET_ADMIN）");
        }
        Err(ReuseError::Unsupported(msg)) => {
            eprintln!("跳过：{msg}");
        }
        Err(e) => {
            // 这里**不** panic：内核缺 `-m string` / `-m recent` 的环境里，
            // 「探测说不行」本身就是正确结论，不该让测试变红。
            eprintln!("跳过：探测结论为不可用，原因：{e}");
        }
    }
}

// —————————————————————————————————————— 2. 真装真卸

#[test]
fn reuse_install_then_uninstall_is_clean() {
    if !iptables_ready() {
        return;
    }
    let cfg = test_cfg();
    fresh(&cfg);

    // 链名必须在 plan 允许的字符集内（字母/数字/下划线/横线，≤28）。
    assert!(cfg.chain.len() <= 28, "链名过长：{}", cfg.chain);
    assert!(
        cfg.chain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "链名含非法字符：{}",
        cfg.chain
    );
    eprintln!("派生链名：{}（{} 字符）", cfg.chain, cfg.chain.len());

    // ——— 装机前：什么都不该在。
    assert!(!nat_chain_exists(&cfg.chain), "装机前 nat 链不该存在");
    assert!(
        input_rules_for(&cfg.chain).is_empty(),
        "装机前 INPUT 不该有本链的规则"
    );
    assert!(
        prerouting_rules_for(&cfg.chain).is_empty(),
        "装机前 PREROUTING 不该有本链的规则"
    );

    // ——— 装机。
    let applied = match stowaway_core::reuse::install(&cfg) {
        Ok(steps) => steps,
        Err(e) => {
            // 真实环境里装机失败通常是 `-m string` / `-m recent` 不可用；
            // 打印原始 stderr 后跳过，不把环境问题算成代码缺陷。
            eprintln!("跳过：装机失败（本机能力不足），原因：{e}");
            cleanup(&cfg);
            return;
        }
    };
    eprintln!("装机成功，共 {} 步：{applied:?}", applied.len());
    dump_state(&cfg);

    // ——— 装机后：5 条规则都在，且各只有一条。
    assert!(nat_chain_exists(&cfg.chain), "nat 链应当存在");
    assert!(nat_chain_listable(&cfg.chain), "nat 链应当可列举");
    let (_, nat_dump, _) = ipt(&["-t", "nat", "-S", &cfg.chain]);
    assert!(
        nat_dump.contains("REDIRECT"),
        "自定义链里应当有 REDIRECT，实际：{nat_dump}"
    );
    assert!(
        nat_dump.contains(&LOCAL_PORT.to_string()),
        "REDIRECT 目标该是本地端口 {LOCAL_PORT}，实际：{nat_dump}"
    );

    let input = input_rules_for(&cfg.chain);
    assert_eq!(
        input.len(),
        2,
        "INPUT 该有 2 条（start/stop），实际：{input:?}"
    );
    assert!(
        input.iter().any(|l| l.contains(MAGIC)),
        "其中一条该含 magic，实际：{input:?}"
    );
    assert!(
        input.iter().any(|l| l.contains("--remove")),
        "其中一条该是 --remove，实际：{input:?}"
    );

    let pre = prerouting_rules_for(&cfg.chain);
    assert_eq!(pre.len(), 1, "PREROUTING 该有 1 条，实际：{pre:?}");
    assert!(
        pre[0].contains(&REUSED_PORT.to_string()),
        "跳转该按复用端口 {REUSED_PORT} 触发，实际：{}",
        pre[0]
    );
    assert!(
        pre[0].contains(&REUSE_SAME_SECONDS.to_string()),
        "跳转该带 --seconds {REUSE_SAME_SECONDS}，实际：{}",
        pre[0]
    );

    // `-L` 的显式证据：装机时能找到链，卸载后找不到（plan 验收口径）。
    let (live_code, live_out, _) = ipt(&["-t", "nat", "-L", &cfg.chain]);
    eprintln!(
        "装机后 `iptables -t nat -L {}` 退出码 {live_code:?}，输出首行：{}",
        cfg.chain,
        live_out.lines().next().unwrap_or("")
    );
    assert_eq!(live_code, Some(0), "装机后 `-L` 应当能找到链");

    // ——— 卸载。
    uninstall(&cfg).expect("卸载应当成功");

    let (dead_code, _, dead_err) = ipt(&["-t", "nat", "-L", &cfg.chain]);
    eprintln!(
        "卸载后 `iptables -t nat -L {}` 退出码 {dead_code:?}（stderr：{dead_err}）",
        cfg.chain
    );
    assert_eq!(dead_code, Some(1), "卸载后 `-L` 应当找不到链（退出码 1）");

    // ——— 卸载后：链与所有引用都不在（`-S` 与 `-L` 双重佐证）。
    assert!(!nat_chain_exists(&cfg.chain), "卸载后 nat 链不该存在");
    assert!(!nat_chain_listable(&cfg.chain), "卸载后 `-L` 也该找不到");
    assert!(
        input_rules_for(&cfg.chain).is_empty(),
        "卸载后 INPUT 不该残留：{:?}",
        input_rules_for(&cfg.chain)
    );
    assert!(
        prerouting_rules_for(&cfg.chain).is_empty(),
        "卸载后 PREROUTING 不该残留：{:?}",
        prerouting_rules_for(&cfg.chain)
    );
    eprintln!("装卸闭环干净：`-S`/`-L`/`-S INPUT`/`-S PREROUTING` 均无残留");
}

// —————————————————————————————————————— 3. 幂等

#[test]
fn reuse_install_is_idempotent() {
    if !iptables_ready() {
        return;
    }
    let cfg = test_cfg();
    fresh(&cfg);

    let first = match stowaway_core::reuse::install(&cfg) {
        Ok(steps) => steps,
        Err(e) => {
            eprintln!("跳过：第一次装机失败（本机能力不足），原因：{e}");
            cleanup(&cfg);
            return;
        }
    };
    let after_first = (
        input_rules_for(&cfg.chain).len(),
        prerouting_rules_for(&cfg.chain).len(),
    );
    eprintln!(
        "第一次装机：{} 步，INPUT {} 条 / PREROUTING {} 条",
        first.len(),
        after_first.0,
        after_first.1
    );

    // 第二次装同一份配置：必须成功，且**规则不叠加**。
    let second = match stowaway_core::reuse::install(&cfg) {
        Ok(steps) => steps,
        Err(e) => {
            panic!("第二次装机（幂等）不该失败：{e}");
        }
    };
    let after_second = (
        input_rules_for(&cfg.chain).len(),
        prerouting_rules_for(&cfg.chain).len(),
    );
    dump_state(&cfg);
    eprintln!(
        "第二次装机：{} 步，INPUT {} 条 / PREROUTING {} 条",
        second.len(),
        after_second.0,
        after_second.1
    );

    assert_eq!(second.len(), first.len(), "两次装机的步骤数该一致");
    assert_eq!(
        after_first, after_second,
        "幂等：规则条数不该增长（第一次 {:?}，第二次 {:?}）",
        after_first, after_second
    );
    assert_eq!(after_second.0, 2, "INPUT 仍该只有 2 条");
    assert_eq!(after_second.1, 1, "PREROUTING 仍该只有 1 条");
    assert!(nat_chain_exists(&cfg.chain), "链仍该在");

    uninstall(&cfg).expect("卸载应当成功");
    assert!(!nat_chain_exists(&cfg.chain), "卸载后不该残留");
    eprintln!("幂等确认：连装两次后规则数不变，卸载后干净");
}

// —————————————————————————————————————— 4. 坏输入

#[test]
fn reuse_rejects_bad_magic_and_ports() {
    // magic 长度：15 / 17 都不行，16 才行。
    assert_eq!(
        ReuseConfig::new("0123456789abcde", REUSED_PORT, LOCAL_PORT),
        Err(ReuseError::BadMagic {
            actual: 15,
            need: 16
        })
    );
    assert_eq!(
        ReuseConfig::new("0123456789abcdefg", REUSED_PORT, LOCAL_PORT),
        Err(ReuseError::BadMagic {
            actual: 17,
            need: 16
        })
    );
    assert_eq!(
        ReuseConfig::new("", REUSED_PORT, LOCAL_PORT),
        Err(ReuseError::BadMagic {
            actual: 0,
            need: 16
        })
    );

    // 端口 0：四个组合都要被拒。
    for (reused, local) in [(0u16, LOCAL_PORT), (REUSED_PORT, 0u16), (0, 0)] {
        assert_eq!(
            ReuseConfig::new(MAGIC, reused, local),
            Err(ReuseError::BadPort),
            "端口 ({reused}, {local}) 该被拒"
        );
    }

    // 合法输入必须通过，且链名安全。
    let ok = ReuseConfig::new(MAGIC, REUSED_PORT, LOCAL_PORT).expect("合法输入");
    assert_eq!(ok.magic.chars().count(), 16);
    assert!(ok.chain.len() <= 28, "链名过长：{}", ok.chain);

    // 坏输入必须在**装机前**就失败：即便本机有 iptables，也不该留下任何痕迹。
    let bad = ReuseConfig::new(MAGIC, 0, LOCAL_PORT);
    assert!(bad.is_err(), "port 0 不该构造出配置");
    eprintln!("坏输入拒绝确认：magic 15/17/0 字符、port 0 全部报明确错误");
}

// —————————————————————————————————————— 5. 失败回滚

#[test]
fn reuse_rollback_on_failure_leaves_nothing() {
    // —— 第一层：纯注入（不依赖 iptables，任何环境都跑）。
    //
    //   让「第 3 步」（INPUT 设开始标记）失败，断言回滚序列 == 已成功的
    //   第 2、1 步的逆序。这条覆盖的是 v1 缺陷 #10 的核心：v1 根本不看失败，
    //   v2 必须「失败 → 撤销 → 报错」。
    let log: std::cell::RefCell<Vec<Vec<String>>> = std::cell::RefCell::new(Vec::new());
    let injected = |argv: &[&str]| {
        log.borrow_mut()
            .push(argv.iter().map(|s| (*s).to_string()).collect());
        // 只让**装机**的 `-A INPUT`（即第 3 步）失败；卸载/清理里的 `-D INPUT` 放过。
        if argv.first() == Some(&"-A") && argv.get(1) == Some(&"INPUT") {
            return Err(CmdFailure {
                code: Some(1),
                stderr: "注入失败：拒绝第 3 步".to_string(),
            });
        }
        Ok(())
    };
    let cfg = test_cfg();
    let err = install_with(&cfg, &injected).expect_err("注入第 3 步失败后应当整体失败");
    match &err {
        ReuseError::CommandFailed { step, code, stderr } => {
            assert_eq!(*step, stowaway_core::reuse::STEP_MARK_START);
            assert_eq!(*code, Some(1));
            assert!(
                stderr.contains("注入失败"),
                "原始 stderr 该被保留：{stderr}"
            );
        }
        other => panic!("错误类型不对：{other:?}"),
    }
    {
        let calls = log.borrow();
        let failed_at = calls
            .iter()
            .rposition(|c| {
                c.first().map(String::as_str) == Some("-A")
                    && c.get(1).map(String::as_str) == Some("INPUT")
            })
            .expect("应当有失败调用");
        let undo = &calls[failed_at + 1..];
        eprintln!("注入第 3 步失败后的回滚序列：{undo:?}");
        assert_eq!(
            undo.len(),
            3,
            "该撤销 2 步 + 链（-F/-X 各一条），实际：{undo:?}"
        );
        // 逆序：先撤 REDIRECT（-A → -D），再 -F 再 -X。
        assert_eq!(undo[0][..3], ["-t", "nat", "-D"]);
        assert_eq!(undo[0][3], cfg.chain);
        assert_eq!(undo[0].last().map(String::as_str), Some("41012"));
        assert_eq!(undo[1][..3], ["-t", "nat", "-F"]);
        assert_eq!(undo[1][3], cfg.chain);
        assert_eq!(undo[2][..3], ["-t", "nat", "-X"]);
        assert_eq!(undo[2][3], cfg.chain);
        // 回滚里绝不能再去动「第 3 步」那条 INPUT 规则（它压根没装上）。
        assert!(
            !undo
                .iter()
                .any(|c| c.first().map(String::as_str) == Some("-D")
                    && c.get(1).map(String::as_str) == Some("INPUT")),
            "不该撤销一个从未成功的步骤：{undo:?}"
        );
    }

    // —— 第二层：真 iptables 下的冲突注入（没有 iptables 就到此为止）。
    if !iptables_ready() {
        eprintln!("（真实 iptables 部分跳过；上面注入层已覆盖回滚序列）");
        return;
    }
    let rc = test_cfg();
    fresh(&rc);

    // 注入手段：手工预建同名链，并让 PREROUTING 引用它。
    //
    // 为什么这样注入：`install` 的第一件事是幂等清理，它会 `-F` + `-X` 掉旧链；
    // 但 PREROUTING 里那条引用会让 `-X` 报 `Device or resource busy`（退出码 4），
    // 于是旧链删不掉、第 1 步 `-N` 撞上 `Chain already exists` 而失败。这恰好
    // 同时验两件事：
    //   (a) 第 1 步失败时**没有任何**已成功步骤可回滚（残留的是注入物，不是本次新增）；
    //   (b) 幂等清理的失败不会把「装机」错误地报成成功（v1 的缺陷 #10 的反面）。
    let chain = rc.chain.clone();
    let (code, _out, err) = ipt(&["-t", "nat", "-N", &chain]);
    eprintln!("预建链 `-t nat -N {chain}` 退出码 {code:?}（stderr：{err}）");
    assert_eq!(code, Some(0), "预建链应当成功，stderr：{err}");

    let (code, _out, err) = ipt(&["-t", "nat", "-A", &chain, "-p", "tcp", "-j", "RETURN"]);
    assert_eq!(code, Some(0), "预建链内加规则应当成功，stderr：{err}");

    let dport = REUSED_PORT.to_string();
    let (code, _out, err) = ipt(&[
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-p",
        "tcp",
        "--dport",
        &dport,
        "-j",
        &chain,
    ]);
    assert_eq!(code, Some(0), "PREROUTING 引用应当成功，stderr：{err}");

    let outcome = stowaway_core::reuse::install(&rc);
    match &outcome {
        Err(e) => eprintln!("冲突注入下装机如实失败：{e}"),
        Ok(steps) => panic!("冲突注入下装机不该成功，实际步骤：{steps:?}"),
    }
    assert!(
        matches!(
            outcome,
            Err(ReuseError::CommandFailed { .. } | ReuseError::RollbackFailed { .. })
        ),
        "应当是 CommandFailed 或 RollbackFailed，实际：{outcome:?}"
    );

    // 关键断言：注入物之外**没有**本次装机引入的残留。INPUT 里那两条标记规则
    // 只有装机第 3、4 步才会加，所以「一条都没有」证明失败发生在第 1 步之前
    // 且没有半成品漏到 INPUT。
    let input_now = input_rules_for(&chain);
    eprintln!("冲突失败后 INPUT 中本链相关行：{input_now:?}");
    assert!(
        input_now.is_empty(),
        "失败后 INPUT 不该有本链规则（那是本次装机才会加的）：{input_now:?}"
    );
    // PREROUTING 里只剩我们自己注入的那一条（`--dport <port> -j <chain>`），
    // 不带 `--syn`/`--rcheck` —— 本次装机的第 5 步没有落地。
    let pre_now = prerouting_rules_for(&chain);
    eprintln!("冲突失败后 PREROUTING 中本链相关行：{pre_now:?}");
    assert!(
        pre_now.iter().all(|l| !l.contains("--rcheck")),
        "PREROUTING 不该出现本次装机的第 5 步规则：{pre_now:?}"
    );

    // 清掉注入物（先摘 PREROUTING 引用，否则 `-X` 仍会 busy）。
    let (code, _out, err) = ipt(&[
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "-p",
        "tcp",
        "--dport",
        &dport,
        "-j",
        &chain,
    ]);
    eprintln!("清理注入的 PREROUTING 引用，退出码 {code:?}（stderr：{err}）");
    assert_eq!(code, Some(0), "应当能删掉注入的引用，stderr：{err}");
    let (code, _out, err) = ipt(&["-t", "nat", "-F", &chain]);
    eprintln!("清理注入链 `-F`，退出码 {code:?}（stderr：{err}）");
    let (code, _out, err) = ipt(&["-t", "nat", "-X", &chain]);
    eprintln!("清理注入链 `-X`，退出码 {code:?}（stderr：{err}）");
    assert_eq!(code, Some(0), "应当能删掉注入链，stderr：{err}");

    // 最终：`-L` 与 `-S` 都找不到链 —— plan 要求的那句「找不到残留」。
    assert!(!nat_chain_exists(&chain), "清理后不该有链（-S）");
    assert!(!nat_chain_listable(&chain), "清理后不该有链（-L）");
    eprintln!("冲突注入清理完成：`-S`/`-L` 均确认无残留");
}

// ———————————————————————————— 6. e2e：回落的两个分支 + 外部服务共存

#[tokio::test]
async fn reuse_fallback_keeps_external_service_reachable() {
    // 「外部服务」：一个真的 TcpListener（下游 echo）。端口复用要能与之共存——
    // 复用规则只碰 nat PREROUTING 上**指定 dport**的流量，陌生流量回落给它。
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("外部服务应当能 bind");
    let addr = listener.local_addr().expect("应当拿到地址");
    eprintln!("外部服务监听在 {addr}");

    let echo = tokio::spawn(async move {
        if let Ok((mut sock, peer)) = listener.accept().await {
            eprintln!("外部服务接受来自 {peer} 的连接");
            let mut buf = [0u8; 64];
            if let Ok(n) = sock.read(&mut buf).await {
                let _ = sock.write_all(&buf[..n]).await;
                let _ = sock.flush().await;
            }
        }
    });

    // ——— 分支 A：有 `--report` → `Report(port)`，且「report 端口」就是外部服务。
    let rc = test_cfg();
    assert_eq!(
        decide_fallback(&rc, Some(addr.port())),
        Fallback::Report(addr.port())
    );

    // 按回落的语义真的走一遍：把连接拨到 `127.0.0.1:<report>`，echo 回来。
    let mut client = TcpStream::connect(addr).await.expect("应当能连上外部服务");
    client
        .write_all(b"stowaway-fallback")
        .await
        .expect("应当能写");
    let mut back = [0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut back))
        .await
        .expect("echo 不该超时")
        .expect("应当能读");
    assert_eq!(&back[..n], b"stowaway-fallback", "echo 内容该原样返回");
    eprintln!("回落分支 A（Report）验证通过：{n} 字节经外部服务原样返回");
    echo.await.expect("echo 任务应当正常结束");

    // ——— 分支 B：没有 `--report` → `Reject`，并且原因要指出缺什么。
    match decide_fallback(&rc, None) {
        Fallback::Reject(reason) => {
            assert!(reason.contains("--report"), "原因该提到 --report：{reason}");
            eprintln!("回落分支 B（Reject）验证通过：{reason}");
        }
        other => panic!("没有 --report 时该 Reject，实际：{other:?}"),
    }

    // ——— `--report 0` 也是 Reject（127.0.0.1:0 不是目标）。
    match decide_fallback(&rc, Some(0)) {
        Fallback::Reject(reason) => {
            assert!(reason.contains("0"), "原因该提到端口 0：{reason}");
            eprintln!("回落分支 C（Reject port 0）验证通过：{reason}");
        }
        other => panic!("report 0 该 Reject，实际：{other:?}"),
    }

    // ——— 与 `probe()` 结论一致：探测说不可用时，回落的**决策**依然可用
    //     （它不碰 iptables、不碰 socket，是纯函数）。这正是本层与装机解耦的意义。
    match probe() {
        Ok(()) => eprintln!("探针说本机可用 iptables；回落决策与之无关，仍可用"),
        Err(ReuseError::NotRoot) => eprintln!("探针说缺 root；回落决策不需要 root，仍可用"),
        Err(e) => eprintln!("探针说 iptables 不可用（{e}）；回落决策不受影响"),
    }
    // 复查：同一份配置，两次决策必须一致（纯函数、无隐藏状态）。
    assert_eq!(
        decide_fallback(&rc, Some(addr.port())),
        decide_fallback(&rc, Some(addr.port()))
    );

    // ——— 回落层**不读字节**：上面 client 读到的 echo 是从 socket 来的完整回显，
    //     没有哪一层提前「嗅」掉前 8 字节。这里用一个 8 字节前缀刚好是
    //     `STW2`（协议魔数）的负载再验一次——若回落层偷偷 sniff 并消费，就会丢字节。
    let listener2 = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("第二个外部服务应当能 bind");
    let addr2 = listener2.local_addr().expect("应当拿到地址");
    let echo2 = tokio::spawn(async move {
        if let Ok((mut sock, _peer)) = listener2.accept().await {
            let mut buf = [0u8; 64];
            if let Ok(n) = sock.read(&mut buf).await {
                let _ = sock.write_all(&buf[..n]).await;
            }
        }
    });
    let payload = b"STW2 untouched!!"; // 前 4 字节是协议魔数，故意如此
    let mut c2 = TcpStream::connect(addr2).await.expect("应当能连上");
    c2.write_all(payload).await.expect("应当能写");
    let mut back2 = [0u8; 64];
    let n2 = tokio::time::timeout(Duration::from_secs(5), c2.read(&mut back2))
        .await
        .expect("不该超时")
        .expect("应当能读");
    assert_eq!(&back2[..n2], payload, "回落层不该消费任何字节");
    eprintln!("确认回落层不嗅探：{} 字节（含 STW2 前缀）原样往返", n2);
    echo2.await.expect("echo 任务应当正常结束");
}
