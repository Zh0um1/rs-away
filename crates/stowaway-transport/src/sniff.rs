//! 首字节嗅探：在**同一 TCP 端口**上区分 raw / ws / 非本协议流量。
//!
//! 权威：`docs/design/transport.md` §5。
//!
//! 为什么必须嗅探：v1 在 `--tls-enable` 时**先** `WrapTLSServerConn` 再读 16 字节 token
//! （`agent/initial/method.go:330` → `:344-345`），所以非 Stowaway 流量会在 TLS 握手处
//! 失败，端口复用回落逻辑失效（F10）。v2 用 `MSG_PEEK` 先判种类，再决定是否包 TLS。
//!
//! 判定表：
//!
//! | 首字节/前缀 | 结论 |
//! |---|---|
//! | `0x16` + 本端启用 TLS | [`Protocol::Tls`] |
//! | `"STW2"` | [`Protocol::Raw`] |
//! | `"GET "` / `"POST "` / `"HEAD"` / `"PUT "` | [`Protocol::Ws`]（HTTP 升级） |
//! | 其它 | [`Protocol::Foreign`] → 端口复用回落或关闭 |

use stowaway_protocol::MAGIC;

/// 嗅探判定所需的字节数上限。
pub const SNIFF_LEN: usize = 8;

/// TLS 记录层 `handshake` 内容类型的首字节。
pub const TLS_HANDSHAKE_RECORD: u8 = 0x16;

/// 嗅探结论。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    /// 明文 Stowaway 帧流。
    Raw,
    /// TLS 外壳（TLS 握手完成后仍是 raw 帧流）。
    Tls,
    /// WebSocket 升级请求（HTTP/1.1）。
    Ws,
    /// 非本协议流量（端口复用回落候选）。
    Foreign,
}

impl Protocol {
    /// 日志/错误信息用的名字。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Tls => "tls",
            Self::Ws => "ws",
            Self::Foreign => "foreign",
        }
    }
}

/// 对已 peek 到的首若干字节分类。
///
/// `tls_expected` 是本端是否启用了 TLS：未启用时 `0x16` 也按 [`Protocol::Foreign`]
/// 处理（否则会把「随便一个 TLS 客户端」误当成本协议，破坏端口复用）。
///
/// 输入不足时返回 `None`——调用方应继续 peek，而不是猜测。
#[must_use]
pub fn classify(peeked: &[u8], tls_expected: bool) -> Option<Protocol> {
    let first = *peeked.first()?;

    if first == TLS_HANDSHAKE_RECORD {
        return Some(if tls_expected {
            Protocol::Tls
        } else {
            Protocol::Foreign
        });
    }

    // "STW2" 需要 4 字节才可判定。
    if peeked.len() >= MAGIC.len() {
        if peeked.starts_with(&MAGIC) {
            return Some(Protocol::Raw);
        }
        if is_http_method(peeked) {
            return Some(Protocol::Ws);
        }
        return Some(Protocol::Foreign);
    }

    // 不足 4 字节：先按已知前缀排除，无法排除时返回 None 让调用方继续 peek。
    if MAGIC.starts_with(&peeked[..peeked.len().min(MAGIC.len())]) {
        return None;
    }
    if is_http_prefix(peeked) {
        return None;
    }
    Some(Protocol::Foreign)
}

fn is_http_method(peeked: &[u8]) -> bool {
    const METHODS: [&[u8]; 5] = [b"GET ", b"POST ", b"HEAD", b"PUT ", b"OPTI"];
    METHODS.iter().any(|m| peeked.starts_with(m))
}

fn is_http_prefix(peeked: &[u8]) -> bool {
    const METHODS: [&[u8]; 5] = [b"GET ", b"POST ", b"HEAD", b"PUT ", b"OPTI"];
    METHODS
        .iter()
        .any(|m| m.starts_with(&peeked[..peeked.len().min(m.len())]))
}

/// 十六进制预览（最多 8 字节）。
#[must_use]
pub fn hex_preview(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes.iter().take(8) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_is_raw() {
        assert_eq!(classify(b"STW2", false), Some(Protocol::Raw));
        assert_eq!(classify(b"STW2\x02\x01\x00", false), Some(Protocol::Raw));
    }

    #[test]
    fn tls_only_when_expected() {
        assert_eq!(classify(&[0x16, 0x03, 0x01], true), Some(Protocol::Tls));
        assert_eq!(
            classify(&[0x16, 0x03, 0x01], false),
            Some(Protocol::Foreign),
            "未启用 TLS 时不得把任意 TLS 客户端当本协议"
        );
    }

    #[test]
    fn http_is_ws() {
        assert_eq!(
            classify(b"GET /deadbeef HTTP/1.1", false),
            Some(Protocol::Ws)
        );
        assert_eq!(classify(b"POST /x HTTP/1.1", false), Some(Protocol::Ws));
        assert_eq!(classify(b"HEAD /x", false), Some(Protocol::Ws));
    }

    #[test]
    fn ssh_is_foreign() {
        assert_eq!(
            classify(b"SSH-2.0-OpenSSH_9.6", false),
            Some(Protocol::Foreign)
        );
    }

    #[test]
    fn partial_prefix_waits() {
        assert_eq!(classify(b"S", false), None);
        assert_eq!(classify(b"ST", false), None);
        assert_eq!(classify(b"STW", false), None);
        assert_eq!(classify(b"G", false), None);
        assert_eq!(classify(b"GE", false), None);
        // 与任何已知前缀都不匹配时立即判定为 foreign。
        assert_eq!(classify(b"X", false), Some(Protocol::Foreign));
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(classify(b"", false), None);
    }

    #[test]
    fn hex_preview_truncates() {
        assert_eq!(hex_preview(&[0x53, 0x54]), "5354");
        assert_eq!(hex_preview(&[0xffu8; 32]).len(), 16);
    }
}
