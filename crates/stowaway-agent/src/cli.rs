//! agent 命令行参数与「运行模式」判定。
//!
//! 对应 plan §6 的 CLI 映射表。v1 用「参数组合穷举式 if/else 链」得出 9 个
//! `Mode` 常量，任何不匹配组合直接 `os.Exit(1)`（`agent/initial/method.go`），
//! 失败既不说明原因也无法测试。这里改成**声明式约束**：
//!
//! - `--connect` 与 `--listen` 互斥（一个主动、一个被动）；
//! - 至少给一个，否则无从接入（plan §4.13：不存在「只跑着等」的模式）；
//! - 代理只在主动模式下有意义（被动模式没有拨号动作）；
//! - `--up` / `--down` 只是传输选择，不参与模式判定。
//!
//! 判定结果是一个可枚举的 [`Mode`]，可以被单测直接覆盖 —— 这正是 v1 那
//! 串 `os.Exit(1)` 做不到的。

use clap::Parser;
use stowaway_core::{Charset, HostKeyPolicy};
use stowaway_protocol::TransportKind;
use stowaway_transport::TransportSpec;

/// `--cs` 的取值（agent 侧 shell 的编解码，plan §4.10 F6）。
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum CsArg {
    /// UTF-8（默认）。
    #[default]
    #[value(name = "utf-8", alias = "utf8")]
    Utf8,
    /// GBK（Windows 中文环境常见）。
    #[value(name = "gbk")]
    Gbk,
}

impl CsArg {
    /// 转成 core 的字符集枚举。
    #[must_use]
    pub const fn charset(self) -> Charset {
        match self {
            Self::Utf8 => Charset::Utf8,
            Self::Gbk => Charset::Gbk,
        }
    }
}

/// agent 命令行参数。
#[derive(Debug, Parser)]
#[command(
    name = "stowaway-agent",
    version,
    about = "Stowaway agent (Rust, v2 protocol)",
    long_about = None,
)]
pub struct Args {
    /// 共享密钥。支持 `env:NAME` / `file:/path` / `stdin:` 前缀。
    #[arg(short = 's', long)]
    pub secret: Option<String>,

    /// 本地监听端口（被动模式）：等待 Admin 拨入。
    #[arg(short = 'l', long, conflicts_with = "connect")]
    pub listen: Option<u16>,

    /// 上行 Admin 地址 `host:port`（主动模式）。
    #[arg(short = 'c', long, conflicts_with = "listen")]
    pub connect: Option<String>,

    /// 上行传输规格（默认 `raw`）。
    #[arg(long)]
    pub up: Option<String>,

    /// 下行（子节点）传输规格（默认与 `--up` 相同）。
    #[arg(long)]
    pub down: Option<String>,

    /// 断开后的重连间隔（秒）；不给则不重连（plan §4.12）。
    #[arg(long)]
    pub reconnect: Option<u64>,

    /// agent 侧 shell 的编解码。
    #[arg(long, value_enum, default_value = "utf-8")]
    pub cs: CsArg,

    /// WS 的 Host 头 / TLS SNI。
    #[arg(long)]
    pub domain: Option<String>,

    /// 启用 TLS。
    #[arg(long)]
    pub tls: bool,

    /// TLS 指纹（32 字节 hex，可带冒号分隔或 `sha256:` 前缀）。
    #[arg(long)]
    pub tls_pin: Option<String>,

    /// 首次连接时信任并记录对端指纹。
    #[arg(long)]
    pub tls_tofu: bool,

    /// 上游 SOCKS5 代理地址（仅主动模式）。
    #[arg(long)]
    pub socks5_proxy: Option<String>,

    /// 上游 SOCKS5 代理用户名。
    #[arg(long, requires = "socks5_proxy")]
    pub socks5_proxy_user: Option<String>,

    /// 上游 SOCKS5 代理密码。
    #[arg(long, requires = "socks5_proxy")]
    pub socks5_proxy_pass: Option<String>,

    /// 上游 HTTP 代理地址（仅主动模式）。
    #[arg(long, conflicts_with = "socks5_proxy")]
    pub http_proxy: Option<String>,

    /// 树深上限（plan §4.7）。
    #[arg(long, default_value_t = 8)]
    pub max_depth: u16,

    /// 文件落盘目录（plan §5.2 修 #13）。
    #[arg(long)]
    pub download_dir: Option<String>,

    /// SSH host key 策略。
    #[arg(long, value_enum, default_value = "strict")]
    pub host_key_policy: HostKeyArg,

    /// known_hosts 文件路径。
    #[arg(long)]
    pub known_hosts: Option<String>,

    /// 放宽密钥长度下限（8 → 1），仅用于兼容旧部署。
    #[arg(long)]
    pub allow_weak_secret: bool,

    /// 端口复用 magic（16 字符，plan §4.11）；仅记录，复用逻辑见 `--reuse-host`。
    #[arg(long)]
    pub reuse_magic: Option<String>,

    /// 端口复用回落时的上报端口。
    #[arg(long)]
    pub report: Option<u16>,

    /// 允许降级运行（复用规则装不上时继续，plan §4.11）。
    #[arg(long)]
    pub allow_degraded: bool,
}

/// `--host-key-policy` 的取值。
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum HostKeyArg {
    /// 必须已记录且匹配（默认）。
    #[default]
    #[value(name = "strict")]
    Strict,
    /// 首次信任并记录，之后必须匹配。
    #[value(name = "accept-and-learn")]
    AcceptAndLearn,
    /// 不校验（仅调试；plan §5.1#10 明确反对）。
    #[value(name = "insecure")]
    Insecure,
}

impl HostKeyArg {
    /// 转成 core 的策略枚举。
    #[must_use]
    pub const fn policy(self) -> HostKeyPolicy {
        match self {
            Self::Strict => HostKeyPolicy::Strict,
            Self::AcceptAndLearn => HostKeyPolicy::AcceptAndLearn,
            Self::Insecure => HostKeyPolicy::Insecure,
        }
    }
}

/// 运行模式。v1 的 9 个 `Mode` 收敛成 4 个：代理与重连不再是独立模式，
/// 而是正交选项（`proxy` / `reconnect`）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// 主动：拨 Admin。
    Active {
        /// Admin 地址 `host:port`。
        addr: String,
        /// 是否经上游代理拨号。
        via_proxy: bool,
    },
    /// 被动：监听等 Admin 拨入。
    Passive {
        /// 监听端口。
        port: u16,
    },
}

/// 参数互相矛盾时的错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArgsError {
    /// 既没给 `--connect` 也没给 `--listen`。
    #[error("必须给 `--connect <addr>`（主动）或 `--listen <port>`（被动）之一")]
    NoEndpoint,
    /// 代理只在主动模式下有意义。
    #[error("`--socks5-proxy` / `--http-proxy` 只在主动模式（`--connect`）下有意义")]
    ProxyWithoutConnect,
    /// 传输规格非法。
    #[error("传输规格 `{spec}` 不可用：{reason}")]
    BadSpec {
        /// 原始规格。
        spec: String,
        /// 原因。
        reason: String,
    },
    /// 指纹格式非法。
    #[error("`--tls-pin` 需要 32 字节 hex（可带冒号分隔）")]
    BadTlsPin,
    /// 只给了一个代理凭据。
    #[error("`--socks5-proxy-user` 与 `--socks5-proxy-pass` 必须成对使用")]
    HalfProxyCredentials,
}

impl Args {
    /// 判定运行模式。
    ///
    /// # Errors
    /// 见 [`ArgsError`]。
    pub fn mode(&self) -> Result<Mode, ArgsError> {
        let via_proxy = self.socks5_proxy.is_some() || self.http_proxy.is_some();
        match (&self.connect, self.listen) {
            (Some(addr), _) => Ok(Mode::Active {
                addr: addr.clone(),
                via_proxy,
            }),
            (None, Some(port)) => {
                if via_proxy {
                    return Err(ArgsError::ProxyWithoutConnect);
                }
                Ok(Mode::Passive { port })
            }
            (None, None) => Err(ArgsError::NoEndpoint),
        }
    }

    /// 上行传输规格：`--up` 有则用，否则按 `--connect` 的地址合成 `raw://`。
    ///
    /// # Errors
    /// 规格语法非法。
    pub fn upstream_spec(&self) -> Result<TransportSpec, ArgsError> {
        let raw = match &self.up {
            Some(s) if !s.trim().is_empty() => s.clone(),
            _ => {
                let addr = self
                    .connect
                    .clone()
                    .or_else(|| self.listen.map(|p| format!("127.0.0.1:{p}")))
                    .unwrap_or_else(|| "127.0.0.1:0".to_owned());
                if addr.contains("://") {
                    addr
                } else {
                    format!("raw://{addr}")
                }
            }
        };
        let mut spec = TransportSpec::parse(&raw).map_err(|e| ArgsError::BadSpec {
            spec: raw.clone(),
            reason: e.to_string(),
        })?;
        if spec.domain.is_none() {
            spec.domain = self.domain.clone();
        }
        Ok(spec)
    }

    /// 下行传输规格：`--down` 有则用，否则与上行同 kind（plan §4.13：两条链
    /// 路可独立选传输，缺省沿用）。
    ///
    /// # Errors
    /// 规格语法非法。
    pub fn downstream_spec(&self) -> Result<TransportSpec, ArgsError> {
        match &self.down {
            Some(s) if !s.trim().is_empty() => {
                let mut spec = TransportSpec::parse(s).map_err(|e| ArgsError::BadSpec {
                    spec: s.clone(),
                    reason: e.to_string(),
                })?;
                if spec.domain.is_none() {
                    spec.domain = self.domain.clone();
                }
                Ok(spec)
            }
            _ => self.upstream_spec(),
        }
    }

    /// 是否校验 TLS 指纹。
    ///
    /// # Errors
    /// 给了 `--tls-pin` 但格式不对。
    pub fn tls_pin(&self) -> Result<Option<[u8; 32]>, ArgsError> {
        match &self.tls_pin {
            None => Ok(None),
            Some(raw) => {
                // `parse_pin` 只认连续 hex 与 `sha256:` 前缀，冒号分隔（常见于
                // 指纹展示形式）在这里先剥掉，免得用户为了粘贴再去手工改。
                let cleaned: String = raw
                    .chars()
                    .filter(|c| *c != ':' && !c.is_whitespace())
                    .collect();
                stowaway_transport::parse_pin(&cleaned)
                    .map(|fp| Some(fp.0))
                    .map_err(|_| ArgsError::BadTlsPin)
            }
        }
    }

    /// 代理凭据是否成对。
    ///
    /// # Errors
    /// 只给了一个。
    pub fn check_proxy_credentials(&self) -> Result<(), ArgsError> {
        if self.socks5_proxy_user.is_some() != self.socks5_proxy_pass.is_some() {
            return Err(ArgsError::HalfProxyCredentials);
        }
        Ok(())
    }

    /// 下行是否可能承载子节点（被动模式恒可）。
    #[must_use]
    pub fn accepts_children(&self) -> bool {
        true
    }

    /// 传输种类（日志用）。
    ///
    /// # Errors
    /// 规格非法。
    pub fn upstream_kind(&self) -> Result<TransportKind, ArgsError> {
        Ok(self.upstream_spec()?.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::{Args, ArgsError, CsArg, HostKeyArg, Mode};
    use clap::Parser;
    use stowaway_core::{Charset, HostKeyPolicy};
    use stowaway_protocol::TransportKind;

    fn parse(argv: &[&str]) -> Args {
        Args::try_parse_from(argv).expect("clap 应接受这组参数")
    }

    #[test]
    fn connect_means_active_and_listen_means_passive() {
        assert_eq!(
            parse(&["agent", "-c", "10.0.0.1:8080"]).mode().expect("ok"),
            Mode::Active {
                addr: "10.0.0.1:8080".to_owned(),
                via_proxy: false
            }
        );
        assert_eq!(
            parse(&["agent", "-l", "9001"]).mode().expect("ok"),
            Mode::Passive { port: 9001 }
        );
    }

    #[test]
    fn neither_endpoint_is_an_error_not_a_default() {
        let args = parse(&["agent"]);
        assert_eq!(args.mode(), Err(ArgsError::NoEndpoint));
    }

    #[test]
    fn connect_and_listen_conflict_at_parse_time() {
        let err = Args::try_parse_from(["agent", "-c", "h:1", "-l", "1"]).expect_err("应冲突");
        let text = err.to_string();
        assert!(
            text.contains("cannot be used with") || text.contains("不能同时使用"),
            "clap 应报互斥，实际：{text}"
        );
    }

    #[test]
    fn proxy_requires_active_mode() {
        let args = parse(&["agent", "-l", "9001", "--socks5-proxy", "127.0.0.1:1080"]);
        assert_eq!(args.mode(), Err(ArgsError::ProxyWithoutConnect));
    }

    #[test]
    fn proxy_marks_active_mode_via_proxy() {
        let args = parse(&[
            "agent",
            "-c",
            "10.1.1.1:9000",
            "--socks5-proxy",
            "127.0.0.1:1080",
        ]);
        assert_eq!(
            args.mode().expect("ok"),
            Mode::Active {
                addr: "10.1.1.1:9000".to_owned(),
                via_proxy: true
            }
        );
    }

    #[test]
    fn upstream_spec_defaults_to_raw_from_connect_addr() {
        let args = parse(&["agent", "-c", "10.0.0.1:8080"]);
        let spec = args.upstream_spec().expect("ok");
        assert_eq!(spec.kind, TransportKind::Raw);
        assert_eq!(spec.host, "10.0.0.1");
        assert_eq!(spec.port, 8080);
        assert_eq!(args.upstream_kind().expect("ok"), TransportKind::Raw);
    }

    #[test]
    fn explicit_up_spec_wins_and_carries_domain() {
        let args = parse(&[
            "agent",
            "-c",
            "10.0.0.1:8080",
            "--up",
            "ws://example.test:8443",
            "--domain",
            "cdn.example.test",
        ]);
        let spec = args.upstream_spec().expect("ok");
        assert_eq!(spec.kind, TransportKind::Ws);
        assert_eq!(spec.port, 8443);
        assert_eq!(spec.domain.as_deref(), Some("cdn.example.test"));
    }

    #[test]
    fn downstream_defaults_to_upstream_kind_but_can_differ() {
        let args = parse(&["agent", "-c", "h:1", "--up", "ws://h:8443"]);
        assert_eq!(
            args.downstream_spec().expect("ok").kind,
            TransportKind::Ws,
            "缺省与上行同种类"
        );

        let args = parse(&[
            "agent",
            "-c",
            "h:1",
            "--up",
            "ws://h:8443",
            "--down",
            "raw://h:9",
        ]);
        assert_eq!(args.downstream_spec().expect("ok").kind, TransportKind::Raw);
        assert_eq!(args.downstream_spec().expect("ok").port, 9);
    }

    #[test]
    fn unknown_scheme_is_an_error_not_a_silent_raw() {
        let args = parse(&["agent", "-c", "h:1", "--up", "http://h:1"]);
        match args.upstream_spec() {
            Err(ArgsError::BadSpec { spec, .. }) => assert!(spec.contains("http")),
            other => panic!("http 必须报错，实际 {other:?}"),
        }
    }

    #[test]
    fn charset_and_host_key_policy_map_to_core_enums() {
        assert_eq!(CsArg::default().charset(), Charset::Utf8);
        assert_eq!(CsArg::Gbk.charset(), Charset::Gbk);
        assert_eq!(HostKeyArg::default().policy(), HostKeyPolicy::Strict);
        assert_eq!(HostKeyArg::Insecure.policy(), HostKeyPolicy::Insecure);
        assert_eq!(
            HostKeyArg::AcceptAndLearn.policy(),
            HostKeyPolicy::AcceptAndLearn
        );
    }

    #[test]
    fn cs_flag_accepts_both_spellings() {
        assert_eq!(parse(&["agent", "--cs", "utf-8"]).cs, CsArg::Utf8);
        assert_eq!(parse(&["agent", "--cs", "utf8"]).cs, CsArg::Utf8);
        assert_eq!(parse(&["agent", "--cs", "gbk"]).cs, CsArg::Gbk);
    }

    #[test]
    fn tls_pin_is_validated_eagerly() {
        let good = "0".repeat(64);
        assert!(
            parse(&["agent", "--tls", "--tls-pin", &good])
                .tls_pin()
                .expect("ok")
                .is_some()
        );
        // 展示形式（冒号分隔）应被接受：用户复制粘贴不该失败。
        let colon: Vec<String> = (0..32).map(|_| "ab".to_owned()).collect();
        let colon = colon.join(":");
        assert_eq!(
            parse(&["agent", "--tls", "--tls-pin", &colon])
                .tls_pin()
                .expect("冒号分隔应被接受"),
            Some([0xab; 32])
        );
        let bad = parse(&["agent", "--tls", "--tls-pin", "zz"]);
        assert_eq!(bad.tls_pin(), Err(ArgsError::BadTlsPin));
    }

    #[test]
    fn half_proxy_credentials_are_rejected() {
        let args = parse(&[
            "agent",
            "-c",
            "h:1",
            "--socks5-proxy",
            "p:1",
            "--socks5-proxy-user",
            "u",
        ]);
        assert_eq!(
            args.check_proxy_credentials(),
            Err(ArgsError::HalfProxyCredentials)
        );
    }
}
