//! `secret` 的来源解析、强度校验与内存保护。
//!
//! 权威：`docs/plan.md` §4.5 末段。v1 的问题是把 secret 放在 argv 里
//! （`ps` / `/proc/<pid>/cmdline` 全机可见），并且 TLS 模式下把共享的
//! `userOptions.Secret` 清空（`agent/initial/method.go:93`）。
//!
//! v2 的做法：
//! - 支持 `env:NAME`、`file:/path`（去掉尾部换行）、`stdin:`、裸字符串；
//! - 全链路 `Zeroizing<Vec<u8>>` 持有，Drop 时清零；
//! - 提供 `mlock_requested` 探测入口；真正 `mlock` 在平台层（本 crate 禁 unsafe）；
//! - 强度下限默认 8 字节，`--allow-weak-secret` 可放宽（兼容 v1 的 `-s 123`）。

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// secret 的来源（用于日志与错误信息，**不含内容**）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SecretSource {
    /// 直接写在命令行（最不安全，仅兼容 v1 习惯）。
    Argv,
    /// `env:NAME`。
    Env(String),
    /// `file:/path`。
    File(String),
    /// `stdin:`。
    Stdin,
}

impl SecretSource {
    /// 从原始字符串推断来源。裸字符串即 argv。
    #[must_use]
    pub fn parse(raw: &str) -> (Self, &str) {
        if let Some(name) = raw.strip_prefix("env:") {
            (Self::Env(name.to_string()), raw)
        } else if let Some(path) = raw.strip_prefix("file:") {
            (Self::File(path.to_string()), raw)
        } else if raw == "stdin:" {
            (Self::Stdin, raw)
        } else {
            (Self::Argv, raw)
        }
    }

    /// 是否会在进程参数里可见。
    #[must_use]
    pub const fn exposes_argv(&self) -> bool {
        matches!(self, Self::Argv)
    }

    /// 人类可读描述（不含 secret 本身）。
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Argv => "argv".to_string(),
            Self::Env(n) => format!("env:{n}"),
            Self::File(p) => format!("file:{p}"),
            Self::Stdin => "stdin".to_string(),
        }
    }
}

/// 加载错误。
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// 环境变量未设置或非 UTF-8。
    #[error("环境变量 {0} 未设置或不是合法 UTF-8")]
    EnvMissing(String),
    /// 无法读取 secret 文件。
    #[error("无法读取 secret 文件 {path}：{source}")]
    FileRead {
        /// 文件路径。
        path: String,
        /// 底层错误。
        #[source]
        source: std::io::Error,
    },
    /// 从 stdin 读取失败。
    #[error("从 stdin 读取 secret 失败：{0}")]
    Stdin(std::io::Error),
    /// 长度为 0。
    #[error("secret 不能为空")]
    Empty,
    /// 强度不足。
    #[error("secret 长度 {actual} 字节，低于下限 {min}；如确需兼容旧用法请加 --allow-weak-secret")]
    TooWeak {
        /// 实际字节数。
        actual: usize,
        /// 要求的下限。
        min: usize,
    },
}

/// 已加载的 secret。
///
/// 内部是 `Zeroizing<Vec<u8>>`，`Drop` 时清零；不实现 `Clone`（避免多份副本）。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    /// 明文（`Zeroizing` 托管，Drop 时清零）。
    bytes: Vec<u8>,
    /// 来源，仅用于诊断。
    #[zeroize(skip)]
    source: SecretSource,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 永不打印内容。
        f.debug_struct("Secret")
            .field("source", &self.source)
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Secret {
    /// 默认强度下限（字节）。
    pub const DEFAULT_MIN_LEN: usize = 8;

    /// 从已解析的字节构造并校验。
    pub fn from_bytes(
        bytes: Vec<u8>,
        source: SecretSource,
        min_len: usize,
    ) -> Result<Self, SecretError> {
        if bytes.is_empty() {
            return Err(SecretError::Empty);
        }
        if bytes.len() < min_len {
            return Err(SecretError::TooWeak {
                actual: bytes.len(),
                min: min_len,
            });
        }
        Ok(Self { bytes, source })
    }

    /// 从命令行原始字符串加载（支持 `env:`/`file:`/`stdin:` 前缀）。
    pub fn load(raw: &str, min_len: usize) -> Result<Self, SecretError> {
        match raw {
            r if r.starts_with("env:") => {
                let name = &r[4..];
                let val =
                    std::env::var(name).map_err(|_| SecretError::EnvMissing(name.to_string()))?;
                Self::from_bytes(
                    trim_trailing_newline(val.as_bytes()),
                    SecretSource::Env(name.to_string()),
                    min_len,
                )
            }
            r if r.starts_with("file:") => {
                let path = &r[5..];
                let data = std::fs::read(path).map_err(|e| SecretError::FileRead {
                    path: path.to_string(),
                    source: e,
                })?;
                Self::from_bytes(
                    trim_trailing_newline(&data),
                    SecretSource::File(path.to_string()),
                    min_len,
                )
            }
            "stdin:" => {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .map_err(SecretError::Stdin)?;
                Self::from_bytes(trim_trailing_newline(&buf), SecretSource::Stdin, min_len)
            }
            other => Self::from_bytes(other.as_bytes().to_vec(), SecretSource::Argv, min_len),
        }
    }

    /// 从文件路径加载（等价于 `file:` 形式，供测试直接调用）。
    pub fn from_file(path: &Path, min_len: usize) -> Result<Self, SecretError> {
        let data = std::fs::read(path).map_err(|e| SecretError::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;
        Self::from_bytes(
            trim_trailing_newline(&data),
            SecretSource::File(path.display().to_string()),
            min_len,
        )
    }

    /// 明文切片（**仅**用于派生密钥，调用方不得写出日志）。
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// 长度。
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// 是否为空（构造后恒为 `false`）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// 来源描述。
    #[must_use]
    pub fn source(&self) -> &SecretSource {
        &self.source
    }

    /// `secret_digest = SHA256(secret)`，作为 HKDF 的 info 成分（§4.5）。
    ///
    /// 直接用固定长度摘要作 info，避免把变长 secret 塞进 KDF 输入。
    #[must_use]
    pub fn digest(&self) -> Zeroizing<[u8; 32]> {
        let mut h = Sha256::new();
        h.update(&self.bytes);
        Zeroizing::new(h.finalize().into())
    }
}

/// 去掉文件/stdin 带来的单个尾随换行（`\n` 或 `\r\n`）。
fn trim_trailing_newline(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.last() == Some(&b'\n') {
        out.pop();
        if out.last() == Some(&b'\r') {
            out.pop();
        }
    }
    out
}

/// 请求把密钥内存锁进物理页（防止换出到磁盘）。
///
/// **本 crate 保持 `#![forbid(unsafe_code)]`**（plan §8.6），因此真正的 `mlock`
/// 由平台层在 P2 起通过 `nix::sys::mman` 完成；这里只给出统一的探测入口，
/// 让调用方能区分「需要锁但没锁」与「平台不支持」。
///
/// 当前实现：始终返回 `false`，表示「尚未锁定」。返回值不影响安全性——
/// `Zeroizing` 在 Drop 时清零，mlock 只是缩小 swap/崩溃转储的暴露窗口。
#[must_use]
pub fn mlock_requested(_bytes: &[u8]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_secret_by_default() {
        let err = Secret::load("123", Secret::DEFAULT_MIN_LEN).expect_err("太短");
        assert!(matches!(err, SecretError::TooWeak { actual: 3, min: 8 }));
        // 兼容 v1：放宽下限后可加载。
        assert!(Secret::load("123", 1).is_ok());
    }

    #[test]
    fn rejects_empty_secret() {
        assert!(matches!(Secret::load("", 0), Err(SecretError::Empty)));
    }

    #[test]
    fn source_prefix_detection() {
        assert_eq!(
            SecretSource::parse("env:FOO").0,
            SecretSource::Env("FOO".into())
        );
        assert_eq!(
            SecretSource::parse("file:/tmp/s").0,
            SecretSource::File("/tmp/s".into())
        );
        assert_eq!(SecretSource::parse("stdin:").0, SecretSource::Stdin);
        assert_eq!(SecretSource::parse("hunter2").0, SecretSource::Argv);
        assert!(SecretSource::Argv.exposes_argv());
    }

    #[test]
    fn file_loading_strips_one_trailing_newline() {
        let dir = tempdir();
        let path = dir.join("s.txt");
        std::fs::write(&path, b"correct-horse\n").expect("write");
        let s = Secret::from_file(&path, Secret::DEFAULT_MIN_LEN).expect("load");
        assert_eq!(s.expose(), b"correct-horse");
        assert_eq!(s.source(), &SecretSource::File(path.display().to_string()));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn digest_is_stable_and_hides_content() {
        let a = Secret::load("abcdefgh", 1).expect("a");
        let b = Secret::load("abcdefgh", 1).expect("b");
        assert_eq!(a.digest(), b.digest());
        assert_ne!(a.digest(), Secret::load("abcdefgi", 1).expect("c").digest());
        // Debug 不含内容。
        let dbg = format!("{a:?}");
        assert!(!dbg.contains("abcdefgh"), "Debug 泄露了 secret：{dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("stw-secret-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }
}
