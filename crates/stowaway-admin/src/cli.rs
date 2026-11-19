//! admin 命令行参数：v1 的 11 个 flag + plan §6 的新增项。
//!
//! v1 用「参数组合穷举 if/else」得到 9 种 `Mode`（`admin/initial/parser.go`），
//! 不匹配就 `flag.Usage(); os.Exit(0)`。这里改成：`clap` 在解析期就拒绝冲突
//! 组合，语义上只剩两个正交问题——「本端是等对端拨入还是主动拨出」与
//! 「上行用什么传输」。

use stowaway_protocol::TransportKind;
use stowaway_transport::TransportSpec;

/// admin 的启动模式。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// 主动：拨 `--connect` 给的地址（对端是 agent 的监听端口）。
    Active { addr: String },
    /// 被动：自己监听，等 agent 拨入。
    Passive { port: u16 },
}

/// 参数校验错误。
#[derive(Debug, thiserror::Error)]
pub enum ArgsError {
    /// 既没 `--listen` 也没 `--connect`。
    #[error("必须给出 `--listen <port>` 或 `--connect <host:port>` 之一")]
    NoEndpoint,

    /// 两者同时给出。
    #[error("`--listen` 与 `--connect` 不能同时使用")]
    BothEndpoints,

    /// 传输规格语法非法。
    #[error("传输规格 `{spec}` 非法：{reason}")]
    BadSpec {
        /// 原始规格串。
        spec: String,
        /// 解析器给出的原因。
        reason: String,
    },

    /// TLS 指纹非法。
    #[error("`--tls-pin` 必须是 32 字节 hex（可带冒号分隔或 `sha256:` 前缀）")]
    BadTlsPin,

    /// 上游代理不支持被动模式。
    #[error("上游代理只用于主动模式；被动监听不能经代理")]
    ProxyWithoutConnect,

    /// 代理凭据只给了一半。
    #[error("`--socks5-proxy-user` 与 `--socks5-proxy-pass` 必须同时给出")]
    HalfProxyCredentials,
}

/// 命令行参数。
#[derive(Debug, Clone, clap::Parser)]
#[command(
    name = "stowaway-admin",
    version,
    about = "Stowaway admin (Rust, v2 protocol)"
)]
pub struct Args {
    /// 共享密钥。支持 `env:NAME` / `file:/path` / `stdin:` 前缀。
    #[arg(short = 's', long)]
    pub secret: Option<String>,

    /// 监听端口（被动模式）：等 agent 拨入。
    #[arg(short = 'l', long, conflicts_with = "connect")]
    pub listen: Option<u16>,

    /// 主动连接地址 `host:port`（agent 的监听端口）。
    #[arg(short = 'c', long, conflicts_with = "listen")]
    pub connect: Option<String>,

    /// 上行传输规格（默认由 `--listen`/`--connect` 合成 `raw://...`）。
    #[arg(long)]
    pub up: Option<String>,

    /// 下行（子节点）传输规格（默认与上行同 kind）。
    #[arg(long)]
    pub down: Option<String>,

    /// WS 的 Host 头 / TLS SNI。
    #[arg(long)]
    pub domain: Option<String>,

    /// 启用 TLS。
    #[arg(long)]
    pub tls: bool,

    /// TLS 指纹（32 字节 hex，可带冒号分隔或 `sha256:` 前缀）。
    #[arg(long)]
    pub tls_pin: Option<String>,

    /// 首次使用信任（TOFU）：不校验指纹但记录下来。
    #[arg(long, conflicts_with = "tls_pin")]
    pub tls_tofu: bool,

    /// 启用心跳（双向 + RTT + 连续 3 周期无回显判死，plan §4.12）。
    #[arg(long)]
    pub heartbeat: bool,

    /// 心跳周期（秒，默认 5）。
    #[arg(long, default_value_t = 5)]
    pub heartbeat_interval: u64,

    /// 非交互模式（无 TTY / CI）：不画 TUI，逐行输出。
    #[arg(long)]
    pub non_interactive: bool,

    /// 非交互模式下要执行的命令（可重复）。
    #[arg(long)]
    pub command: Vec<String>,

    /// 下载目录（agent 侧文件落到这里的对应位置）。
    #[arg(long)]
    pub download_dir: Option<String>,

    /// 树的最大深度。
    #[arg(long, default_value_t = 8)]
    pub max_depth: u16,

    /// 上游 SOCKS5 代理（只用于主动模式）。
    #[arg(long)]
    pub socks5_proxy: Option<String>,

    /// 上游 SOCKS5 代理用户名。
    #[arg(long, requires = "socks5_proxy")]
    pub socks5_proxy_user: Option<String>,

    /// 上游 SOCKS5 代理密码。
    #[arg(long, requires = "socks5_proxy")]
    pub socks5_proxy_pass: Option<String>,

    /// 上游 HTTP 代理（只用于主动模式）。
    #[arg(long, conflicts_with = "socks5_proxy")]
    pub http_proxy: Option<String>,

    /// 端口复用的魔法串。
    #[arg(long)]
    pub reuse_magic: Option<String>,

    /// 端口复用回落端口。
    #[arg(long)]
    pub report: Option<u16>,

    /// 允许长度不足 8 字节的弱密钥（仅调试）。
    #[arg(long)]
    pub allow_weak_secret: bool,
}

impl Args {
    /// 判定启动模式。
    ///
    /// # Errors
    /// 端点缺失或冲突。
    pub fn mode(&self) -> Result<Mode, ArgsError> {
        match (&self.connect, self.listen) {
            (Some(addr), None) => Ok(Mode::Active { addr: addr.clone() }),
            (None, Some(port)) => Ok(Mode::Passive { port }),
            (None, None) => Err(ArgsError::NoEndpoint),
            (Some(_), Some(_)) => Err(ArgsError::BothEndpoints),
        }
    }

    /// 上行传输规格：`--up` 优先，否则由端点合成 `raw://...`。
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

    /// 下行传输规格（子节点链路）。
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
            _ => {
                let mut spec = self.upstream_spec()?;
                // 下行只关心 kind；地址由 `listen` 服务决定，这里清掉免得误用。
                spec.host = "0.0.0.0".to_owned();
                spec.port = 0;
                Ok(spec)
            }
        }
    }

    /// 上行传输种类。
    ///
    /// # Errors
    /// 规格语法非法。
    pub fn upstream_kind(&self) -> Result<TransportKind, ArgsError> {
        Ok(self.upstream_spec()?.kind)
    }

    /// TLS 指纹：先把冒号与空白剥掉再解析（用户粘贴的展示形式常带冒号）。
    ///
    /// # Errors
    /// 指纹不是 32 字节 hex。
    pub fn tls_pin(&self) -> Result<Option<[u8; 32]>, ArgsError> {
        let Some(raw) = &self.tls_pin else {
            return Ok(None);
        };
        let cleaned: String = raw
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':')
            .collect();
        let fp = stowaway_transport::parse_pin(&cleaned).map_err(|_| ArgsError::BadTlsPin)?;
        Ok(Some(fp.0))
    }

    /// 代理凭据必须成对。
    ///
    /// # Errors
    /// 只给了用户名或只给了密码。
    pub fn check_proxy_credentials(&self) -> Result<(), ArgsError> {
        if self.socks5_proxy_user.is_some() != self.socks5_proxy_pass.is_some() {
            return Err(ArgsError::HalfProxyCredentials);
        }
        Ok(())
    }

    /// 是否启用了上游代理。
    #[must_use]
    pub const fn via_proxy(&self) -> bool {
        self.socks5_proxy.is_some() || self.http_proxy.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(argv: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(argv)
    }

    #[test]
    fn listen_means_passive_and_connect_means_active() {
        let a = parse(&["admin", "-l", "8080"]).expect("ok");
        assert_eq!(a.mode().expect("mode"), Mode::Passive { port: 8080 });
        let b = parse(&["admin", "-c", "10.0.0.9:8080"]).expect("ok");
        assert_eq!(
            b.mode().expect("mode"),
            Mode::Active {
                addr: "10.0.0.9:8080".to_owned()
            }
        );
    }

    #[test]
    fn neither_endpoint_is_an_error_not_a_default() {
        let a = parse(&["admin"]).expect("ok");
        assert!(matches!(a.mode(), Err(ArgsError::NoEndpoint)));
    }

    #[test]
    fn both_endpoints_conflict_at_parse_time() {
        let err = parse(&["admin", "-l", "1", "-c", "h:1"]).expect_err("冲突");
        let text = err.to_string();
        assert!(
            text.contains("cannot be used with") || text.contains("不能同时使用"),
            "clap 文案应说明冲突：{text}"
        );
    }

    #[test]
    fn upstream_spec_defaults_to_raw_from_listen_port() {
        let a = parse(&["admin", "-l", "9000"]).expect("ok");
        let spec = a.upstream_spec().expect("spec");
        assert_eq!(spec.kind, TransportKind::Raw);
        assert_eq!(spec.host, "127.0.0.1");
        assert_eq!(spec.port, 9000);
    }

    #[test]
    fn explicit_up_spec_wins_and_carries_domain() {
        let a = parse(&[
            "admin",
            "-l",
            "9000",
            "--up",
            "ws://example.test:8443",
            "--domain",
            "cdn.example.test",
        ])
        .expect("ok");
        let spec = a.upstream_spec().expect("spec");
        assert_eq!(spec.kind, TransportKind::Ws);
        assert_eq!(spec.port, 8443);
        assert_eq!(spec.domain.as_deref(), Some("cdn.example.test"));
    }

    #[test]
    fn unknown_scheme_is_an_error_not_a_silent_raw() {
        let a = parse(&["admin", "-l", "9000", "--up", "http://h:80"]).expect("ok");
        assert!(matches!(a.upstream_spec(), Err(ArgsError::BadSpec { .. })));
    }

    #[test]
    fn tls_pin_accepts_colon_separated_hex() {
        let hex = "ab".repeat(32);
        let colon = hex
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(":");
        let a = parse(&["admin", "-l", "1", "--tls", "--tls-pin", &colon]).expect("ok");
        assert_eq!(a.tls_pin().expect("pin"), Some([0xab; 32]));
    }

    #[test]
    fn bad_tls_pin_is_rejected_eagerly() {
        let a = parse(&["admin", "-l", "1", "--tls-pin", "zz"]).expect("ok");
        assert!(matches!(a.tls_pin(), Err(ArgsError::BadTlsPin)));
    }

    #[test]
    fn half_proxy_credentials_are_rejected() {
        let a = parse(&[
            "admin",
            "-c",
            "h:1",
            "--socks5-proxy",
            "p:1",
            "--socks5-proxy-user",
            "u",
        ])
        .expect("ok");
        assert!(matches!(
            a.check_proxy_credentials(),
            Err(ArgsError::HalfProxyCredentials)
        ));
    }

    #[test]
    fn proxy_reporting_is_consistent() {
        let a = parse(&["admin", "-c", "h:1", "--http-proxy", "p:1"]).expect("ok");
        assert!(a.via_proxy());
        let b = parse(&["admin", "-l", "1"]).expect("ok");
        assert!(!b.via_proxy());
    }
}
