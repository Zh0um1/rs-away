//! `TransportSpec`：把 `-up` / `-down` 的裸字符串升级为带参数的 URI。
//!
//! 语法与语义见 `docs/design/transport.md` §4.1。解析是**纯函数**（不碰网络），
//! 因此可以在 CLI 解析期就报错，而不是等监听/拨号失败。

use std::collections::BTreeMap;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};

use stowaway_protocol::transport_kind::TransportKind;

/// 解析错误。
#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    /// 空字符串。
    #[error("传输规格为空：需要 <scheme>://<host>:<port> 或 <host>:<port>")]
    Empty,
    /// Go v1 的 `http` 伪协议已删除。
    #[error("`http://` 传输已在 v2 删除（v1 的 http 伪协议只是伪装，无实际语义）")]
    HttpRemoved,
    /// 未知 scheme：不静默回落 raw。
    #[error("未知传输 scheme `{scheme}`（可用：raw、ws、kcp、quic）")]
    UnknownScheme {
        /// 用户写的 scheme。
        scheme: String,
    },
    /// 缺少 host。
    #[error("传输规格缺少 host：{spec}")]
    MissingHost {
        /// 原始规格。
        spec: String,
    },
    /// 缺少端口（v2 不允许省略端口，避免依赖默认端口）。
    #[error("传输规格缺少端口：{spec}")]
    MissingPort {
        /// 原始规格。
        spec: String,
    },
    /// 端口不是合法 u16。
    #[error("传输规格端口非法 `{port}`（需 0..=65535）")]
    BadPort {
        /// 原始端口文本。
        port: String,
    },
    /// 未知查询参数。
    #[error("传输 `{scheme}` 不认识参数 `{key}`（可用：{allowed}）")]
    UnknownParam {
        /// scheme。
        scheme: &'static str,
        /// 参数名。
        key: String,
        /// 允许的参数列表。
        allowed: &'static str,
    },
    /// 参数值非法。
    #[error("传输 `{scheme}` 的参数 `{key}={value}` 非法：{reason}")]
    BadParam {
        /// scheme。
        scheme: &'static str,
        /// 参数名。
        key: String,
        /// 参数值。
        value: String,
        /// 原因。
        reason: &'static str,
    },
    /// 查询串语法错误。
    #[error("传输查询串非法：{0}")]
    BadQuery(String),
    /// quic 尚未实现。
    #[error("`quic://` 在 v2 未实现（占位：枚举扩展点已就绪）")]
    QuicUnimplemented,
    /// 该传输不支持某个 feature。
    #[error("传输 `{kind}` 需要 feature `{feature}`，本次构建未启用")]
    FeatureDisabled {
        /// 传输种类。
        kind: &'static str,
        /// 需要的 feature。
        feature: &'static str,
    },
    /// host 无法解析成地址。
    #[error("传输 host `{host}` 无法解析：{source}")]
    Resolve {
        /// host。
        host: String,
        /// 底层错误。
        source: std::io::Error,
    },
    /// 与端口复用互斥。
    #[error("端口复用（--reuse-magic / -rehost / -report）只能与 `raw` 组合，当前是 `{kind}`")]
    ReuseNeedsRaw {
        /// 实际传输种类。
        kind: &'static str,
    },
}

/// 传输规格。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportSpec {
    /// 传输种类。
    pub kind: TransportKind,
    /// 主机名或 IP 字面量（保留原文，拨号时才解析）。
    pub host: String,
    /// 端口。
    pub port: u16,
    /// 参数（已知参数已解析成明确字段，此处仅保留原始键值便于诊断）。
    pub raw_query: BTreeMap<String, String>,
    /// TCP_NODELAY（raw/ws）。
    pub nodelay: bool,
    /// SO_KEEPALIVE 秒数（raw/ws）。
    pub keepalive_secs: Option<u64>,
    /// ws 的 Host/SNI；缺省由 CLI `-domain` 或 `-c` 的 host 补齐。
    pub domain: Option<String>,
    /// ws 的路径。
    pub path: Option<String>,
    /// kcp 的 conv（`None` = 由 secret 派生）。
    pub conv: Option<u32>,
    /// kcp 的 mtu。
    pub mtu: Option<u16>,
    /// kcp 的收发窗口。
    pub wnd: Option<(u16, u16)>,
}

impl TransportSpec {
    /// 解析一个规格字符串。
    ///
    /// 无 `://` 的 `host:port` 一律按 `raw`（兼容 Go v1 的 `-l 8080`）。
    pub fn parse(input: &str) -> Result<Self, SpecError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SpecError::Empty);
        }

        let (scheme, rest) = match trimmed.split_once("://") {
            Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
            None => ("raw".to_owned(), trimmed),
        };

        let kind = match scheme.as_str() {
            "raw" | "tcp" => TransportKind::Raw,
            "ws" | "websocket" => TransportKind::Ws,
            "kcp" => TransportKind::Kcp,
            "quic" => return Err(SpecError::QuicUnimplemented),
            "http" | "https" => return Err(SpecError::HttpRemoved),
            other => {
                return Err(SpecError::UnknownScheme {
                    scheme: other.to_owned(),
                });
            }
        };

        let (authority, query) = match rest.split_once('?') {
            Some((authority, query)) => (authority, Some(query)),
            None => (rest, None),
        };
        // 去掉 path 部分：raw/kcp 忽略 path，ws 的 path 由 `path=` 参数给出，
        // 这样 `ws://h:1/xxx` 里的 `/xxx` 不会被静默丢弃。
        let (authority, inline_path) = match authority.find('/') {
            Some(idx) => (&authority[..idx], Some(authority[idx..].to_owned())),
            None => (authority, None),
        };

        let (host, port) = split_host_port(authority, trimmed)?;

        let mut spec = Self {
            kind,
            host,
            port,
            raw_query: BTreeMap::new(),
            nodelay: true,
            keepalive_secs: None,
            domain: None,
            path: inline_path,
            conv: None,
            mtu: None,
            wnd: None,
        };

        // raw / kcp 不认路径：内联路径只对 ws 有意义，否则报错而非静默丢弃。
        if kind != TransportKind::Ws && spec.path.is_some() {
            return Err(SpecError::UnknownParam {
                scheme: kind.as_str(),
                key: "path".to_owned(),
                allowed: "无（该传输不支持路径）",
            });
        }

        if let Some(query) = query {
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (key, value) = match pair.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => (pair, ""),
                };
                spec.apply_param(key, value)?;
            }
        }

        Ok(spec)
    }

    /// 解析并用 `secret` 补齐 kcp 的 conv。
    pub fn resolve(self, secret: &[u8]) -> Self {
        let mut spec = self;
        if spec.kind == TransportKind::Kcp && spec.conv.is_none() {
            spec.conv = Some(stowaway_crypto::kcp_conv(secret));
        }
        spec
    }

    fn apply_param(&mut self, key: &str, value: &str) -> Result<(), SpecError> {
        let scheme = self.kind.as_str();
        let allowed = match self.kind {
            TransportKind::Raw => "nodelay、keepalive",
            TransportKind::Ws => "domain、path、nodelay、keepalive",
            TransportKind::Kcp => "conv、nodelay、mtu、wnd",
            TransportKind::Quic => "",
        };

        // 记录原始键值，未知参数也留下痕迹便于报错信息稳定。
        self.raw_query.insert(key.to_owned(), value.to_owned());

        match (self.kind, key) {
            (TransportKind::Raw | TransportKind::Ws, "nodelay") => {
                self.nodelay = parse_bool(scheme, key, value)?;
            }
            (TransportKind::Raw | TransportKind::Ws, "keepalive") => {
                let secs: u64 = parse_u64(scheme, key, value)?;
                if secs == 0 {
                    return Err(SpecError::BadParam {
                        scheme,
                        key: key.to_owned(),
                        value: value.to_owned(),
                        reason: "keepalive 必须 > 0 秒",
                    });
                }
                self.keepalive_secs = Some(secs);
            }
            (TransportKind::Ws, "domain") => {
                if value.is_empty() {
                    return Err(SpecError::BadParam {
                        scheme,
                        key: key.to_owned(),
                        value: value.to_owned(),
                        reason: "domain 不能为空",
                    });
                }
                self.domain = Some(value.to_owned());
            }
            (TransportKind::Ws, "path") => {
                if !value.starts_with('/') {
                    return Err(SpecError::BadParam {
                        scheme,
                        key: key.to_owned(),
                        value: value.to_owned(),
                        reason: "path 必须以 / 开头",
                    });
                }
                self.path = Some(value.to_owned());
            }
            (TransportKind::Kcp, "conv") => {
                let conv: u32 = parse_u64(scheme, key, value).and_then(|v| {
                    u32::try_from(v).map_err(|_| SpecError::BadParam {
                        scheme,
                        key: key.to_owned(),
                        value: value.to_owned(),
                        reason: "conv 必须是 u32",
                    })
                })?;
                // Go v1 的 KCP 服务端约定 conv 不得为 0（0 表示未设置）。
                if conv == 0 {
                    return Err(SpecError::BadParam {
                        scheme,
                        key: key.to_owned(),
                        value: value.to_owned(),
                        reason: "conv 不得为 0",
                    });
                }
                self.conv = Some(conv);
            }
            (TransportKind::Kcp, "mtu") => {
                let mtu: u64 = parse_u64(scheme, key, value)?;
                if !(576..=1400).contains(&mtu) {
                    return Err(SpecError::BadParam {
                        scheme,
                        key: key.to_owned(),
                        value: value.to_owned(),
                        reason: "mtu 必须在 576..=1400",
                    });
                }
                self.mtu = Some(u16::try_from(mtu).map_err(|_| SpecError::BadParam {
                    scheme,
                    key: key.to_owned(),
                    value: value.to_owned(),
                    reason: "mtu 溢出 u16",
                })?);
            }
            (TransportKind::Kcp, "wnd") => {
                let (recv, send) = value.split_once(',').ok_or(SpecError::BadParam {
                    scheme,
                    key: key.to_owned(),
                    value: value.to_owned(),
                    reason: "wnd 形如 recv,send",
                })?;
                let recv: u16 = parse_u64(scheme, key, recv).and_then(|v| {
                    u16::try_from(v).map_err(|_| SpecError::BadParam {
                        scheme,
                        key: key.to_owned(),
                        value: value.to_owned(),
                        reason: "wnd 分量必须是 u16",
                    })
                })?;
                let send: u16 = parse_u64(scheme, key, send).and_then(|v| {
                    u16::try_from(v).map_err(|_| SpecError::BadParam {
                        scheme,
                        key: key.to_owned(),
                        value: value.to_owned(),
                        reason: "wnd 分量必须是 u16",
                    })
                })?;
                if recv == 0 || send == 0 {
                    return Err(SpecError::BadParam {
                        scheme,
                        key: key.to_owned(),
                        value: value.to_owned(),
                        reason: "wnd 分量不得为 0",
                    });
                }
                self.wnd = Some((recv, send));
            }
            (_, "nodelay") if self.kind == TransportKind::Kcp => {
                self.nodelay = parse_bool(scheme, key, value)?;
            }
            _ => {
                return Err(SpecError::UnknownParam {
                    scheme,
                    key: key.to_owned(),
                    allowed,
                });
            }
        }

        Ok(())
    }

    /// 解析 `host:port` 为 `SocketAddr`（只在拨号期调用）。
    pub fn resolve_addr(&self) -> Result<SocketAddr, SpecError> {
        let mut addrs = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|source| SpecError::Resolve {
                host: self.host.clone(),
                source,
            })?;
        addrs.next().ok_or_else(|| SpecError::Resolve {
            host: self.host.clone(),
            source: std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "解析结果为空"),
        })
    }

    /// ws 的 Host 头 / TLS SNI：显式 `domain=` 优先，否则用 host。
    #[must_use]
    pub fn effective_domain(&self) -> Option<String> {
        self.domain.clone().or_else(|| {
            if self.host.parse::<std::net::IpAddr>().is_ok() {
                None
            } else {
                Some(self.host.clone())
            }
        })
    }

    /// ws 的请求路径，默认 `/deadbeef`（与 Go v1 的 `websocketPath` 一致）。
    #[must_use]
    pub fn effective_path(&self) -> &str {
        self.path.as_deref().unwrap_or("/deadbeef")
    }
}

fn split_host_port(authority: &str, spec: &str) -> Result<(String, u16), SpecError> {
    if authority.is_empty() {
        return Err(SpecError::MissingHost {
            spec: spec.to_owned(),
        });
    }

    // IPv6 字面量：[::1]:8080
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(|| SpecError::MissingHost {
            spec: spec.to_owned(),
        })?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| SpecError::MissingPort {
                spec: spec.to_owned(),
            })?;
        return Ok((format!("[{host}]"), parse_port(port)?));
    }

    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| SpecError::MissingPort {
            spec: spec.to_owned(),
        })?;
    if host.is_empty() {
        return Err(SpecError::MissingHost {
            spec: spec.to_owned(),
        });
    }
    Ok((host.to_owned(), parse_port(port)?))
}

fn parse_port(text: &str) -> Result<u16, SpecError> {
    text.parse::<u16>().map_err(|_| SpecError::BadPort {
        port: text.to_owned(),
    })
}

fn parse_bool(scheme: &'static str, key: &str, value: &str) -> Result<bool, SpecError> {
    match value {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(SpecError::BadParam {
            scheme,
            key: key.to_owned(),
            value: value.to_owned(),
            reason: "布尔值只能是 0/1、true/false、yes/no、on/off",
        }),
    }
}

fn parse_u64(scheme: &'static str, key: &str, value: &str) -> Result<u64, SpecError> {
    value.parse::<u64>().map_err(|_| SpecError::BadParam {
        scheme,
        key: key.to_owned(),
        value: value.to_owned(),
        reason: "必须是十进制非负整数",
    })
}

impl fmt::Display for TransportSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}", self.kind.as_str(), self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_port_is_raw() {
        let spec = TransportSpec::parse("127.0.0.1:8080").expect("parse");
        assert_eq!(spec.kind, TransportKind::Raw);
        assert_eq!(spec.host, "127.0.0.1");
        assert_eq!(spec.port, 8080);
        assert!(spec.nodelay, "raw 默认开 nodelay");
    }

    #[test]
    fn ws_with_all_params() {
        let spec =
            TransportSpec::parse("ws://example.com:443?domain=cdn.example&path=/x&nodelay=0")
                .expect("parse");
        assert_eq!(spec.kind, TransportKind::Ws);
        assert_eq!(spec.domain.as_deref(), Some("cdn.example"));
        assert_eq!(spec.effective_path(), "/x");
        assert!(!spec.nodelay);
    }

    #[test]
    fn inline_path_is_kept_for_ws() {
        let spec = TransportSpec::parse("ws://h:80/abc").expect("parse");
        assert_eq!(spec.effective_path(), "/abc");
    }

    #[test]
    fn http_is_rejected_explicitly() {
        assert!(matches!(
            TransportSpec::parse("http://h:80"),
            Err(SpecError::HttpRemoved)
        ));
    }

    #[test]
    fn unknown_scheme_is_not_silently_raw() {
        assert!(matches!(
            TransportSpec::parse("fancy://h:1"),
            Err(SpecError::UnknownScheme { .. })
        ));
    }

    #[test]
    fn quic_parses_to_unimplemented() {
        assert!(matches!(
            TransportSpec::parse("quic://h:1"),
            Err(SpecError::QuicUnimplemented)
        ));
    }

    #[test]
    fn kcp_conv_defaults_from_secret() {
        let spec = TransportSpec::parse("kcp://h:9000")
            .expect("parse")
            .resolve(b"hunter2");
        assert!(spec.conv.is_some());
        assert_eq!(spec.conv, Some(stowaway_crypto::kcp_conv(b"hunter2")));
    }

    #[test]
    fn kcp_mtu_range_enforced() {
        assert!(TransportSpec::parse("kcp://h:9?mtu=100").is_err());
        assert!(TransportSpec::parse("kcp://h:9?mtu=1400").is_ok());
    }

    #[test]
    fn kcp_zero_conv_rejected() {
        assert!(TransportSpec::parse("kcp://h:9?conv=0").is_err());
    }

    #[test]
    fn unknown_param_is_error_not_ignored() {
        assert!(matches!(
            TransportSpec::parse("raw://h:1?bogus=1"),
            Err(SpecError::UnknownParam { .. })
        ));
    }

    #[test]
    fn ipv6_literal_is_supported() {
        let spec = TransportSpec::parse("[::1]:8080").expect("parse");
        assert_eq!(spec.host, "[::1]");
        assert_eq!(spec.port, 8080);
    }

    #[test]
    fn missing_port_is_error() {
        assert!(matches!(
            TransportSpec::parse("raw://h"),
            Err(SpecError::MissingPort { .. })
        ));
    }
}
