//! 文件传输：分片、落盘与路径穿越防护。
//!
//! 权威：`docs/plan.md` §4.6（`ServiceKind::File` + `FileParam`）、
//! 附录 A（`FILESTATREQ`/`FILEDATA`/`FILEERR` 的映射）、§5.1 第 13 项。
//!
//! # 修的缺陷 #13
//!
//! v1 直接用客户端给的文件名落盘（`share/file.go:148` 的
//! `os.Create(file.FileName)`），客户端传 `../../etc/cron.d/x` 就能写到
//! `--download-dir` 之外。v2 的规则是**先校验再拼接**：
//!
//! - 文件名必须是单段：不含 `/`、`\`；
//! - 不是 `.`、`..`，不以 `.` 开头（避免 `.bashrc`/`.ssh` 这类）；
//! - 不含控制字符；
//! - 不是 Windows 保留名（`con`/`prn`/`aux`/`nul`/`com1`…/`lpt1`…）；
//! - 拼接后仍须落在给定根目录之内（`safe_join` 双重保险）。

use std::path::{Path, PathBuf};

use stowaway_protocol::{
    FileParam, Message, ServiceKind, ServiceParam, ServicePhase, ServiceRequest, SessionKey,
};

use crate::error::CoreError;

/// 单片载荷上限（v1 是 30720，见 `share/file.go:194`；v2 对齐帧层分片粒度）。
pub const FILE_CHUNK: usize = 64 * 1024;

/// 文件名长度上限。
pub const MAX_NAME_LEN: usize = 255;

/// 下载方向的清单头长度：8 字节长度（LE）+ 32 字节 sha256。
///
/// 接收方在下载时**不知道**远端文件多大、摘要是什么，所以发送方必须在
/// 任何分片之前先声明：`size ‖ sha256` 是会话流里的第一段 40 字节。
/// 这与 v1 的 `FILEDOWNRES`（先包头、再 `FILEDATA`，见
/// `share/file.go:262` 的 `Ask4Download`）同构，只是把「包头」压成了定长。
pub const MANIFEST_LEN: usize = 8 + 32;

/// 造清单头。
#[must_use]
pub fn manifest(size: u64, sha256: &[u8; 32]) -> [u8; MANIFEST_LEN] {
    let mut out = [0u8; MANIFEST_LEN];
    out[..8].copy_from_slice(&size.to_le_bytes());
    out[8..].copy_from_slice(sha256);
    out
}

/// 解清单头。
#[must_use]
pub fn parse_manifest(head: &[u8; MANIFEST_LEN]) -> (u64, [u8; 32]) {
    let mut len = [0u8; 8];
    len.copy_from_slice(&head[..8]);
    let mut sha = [0u8; 32];
    sha.copy_from_slice(&head[8..]);
    (u64::from_le_bytes(len), sha)
}

/// 流式计算一个文件的 sha256（不把整文件读进内存）。
///
/// # Errors
/// 打不开或读不动时把底层 `io::Error` 原样带回。
pub async fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; FILE_CHUNK];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// 文件名/落盘错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileError {
    /// 空文件名。
    #[error("文件名为空")]
    EmptyName,

    /// 文件名过长。
    #[error("文件名过长：{actual} 字节，上限 {max}")]
    NameTooLong {
        /// 实际长度。
        actual: usize,
        /// 上限。
        max: usize,
    },

    /// 含路径分隔符。
    #[error("文件名不得含路径分隔符：{name:?}")]
    Separator {
        /// 文件名。
        name: String,
    },

    /// 相对路径穿越（`.` / `..`）。
    #[error("文件名不得是相对路径片段：{name:?}")]
    ParentTraversal {
        /// 文件名。
        name: String,
    },

    /// 隐藏文件（以 `.` 开头）。
    #[error("不允许以点开头：{name:?}")]
    Hidden {
        /// 文件名。
        name: String,
    },

    /// Windows 保留设备名。
    #[error("不允许使用系统保留名：{name:?}")]
    Reserved {
        /// 文件名。
        name: String,
    },

    /// 含控制字符。
    #[error("文件名含控制字符")]
    ControlChar,

    /// 收到的字节数超过声明的长度。
    #[error("收到的数据超出声明长度：已收 {actual} 字节，声明 {declared}")]
    Oversize {
        /// 已收。
        actual: u64,
        /// 声明。
        declared: u64,
    },

    /// 结束时收到的字节数不足声明的长度。
    #[error("文件不完整：收到 {actual} 字节，声明 {declared}")]
    Incomplete {
        /// 实收。
        actual: u64,
        /// 声明。
        declared: u64,
    },

    /// 起始偏移超过声明长度。
    #[error("起始偏移 {offset} 超过声明长度 {size}")]
    BadOffset {
        /// 偏移。
        offset: u64,
        /// 声明长度。
        size: u64,
    },
}

/// 校验文件名并返回它（成功时原样返回）。
///
/// # Errors
/// 见 [`FileError`] 的各个变体。
pub fn validate_name(name: &str) -> std::result::Result<&str, FileError> {
    if name.is_empty() {
        return Err(FileError::EmptyName);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(FileError::NameTooLong {
            actual: name.len(),
            max: MAX_NAME_LEN,
        });
    }
    if name.contains('/') || name.contains('\\') {
        return Err(FileError::Separator {
            name: name.to_owned(),
        });
    }
    if name == "." || name == ".." {
        return Err(FileError::ParentTraversal {
            name: name.to_owned(),
        });
    }
    if name.starts_with('.') {
        return Err(FileError::Hidden {
            name: name.to_owned(),
        });
    }
    if name.chars().any(char::is_control) {
        return Err(FileError::ControlChar);
    }
    // Windows 保留名：取第一个 `.` 之前的部分，大小写无关。
    let stem = name.split('.').next().unwrap_or(name).to_ascii_lowercase();
    let reserved = matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || ((stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0');
    if reserved {
        return Err(FileError::Reserved {
            name: name.to_owned(),
        });
    }
    Ok(name)
}

/// 在 `root` 之下安全地拼出目标路径。
///
/// # Errors
/// 名字非法（同 [`validate_name`]），或拼接结果逃出了 `root`。
pub fn safe_join(root: &Path, name: &str) -> std::result::Result<PathBuf, FileError> {
    validate_name(name)?;
    let path = root.join(name);
    // 双重保险：即使 validate_name 有漏，拼接结果也必须仍在 root 之下。
    if !path.starts_with(root) {
        return Err(FileError::Separator {
            name: name.to_owned(),
        });
    }
    Ok(path)
}

/// 一次下载（接收方视角）的落盘状态。
#[derive(Debug)]
pub struct IncomingFile {
    /// 会话键。
    pub key: SessionKey,
    /// 最终落盘路径（已通过 [`safe_join`] 校验）。
    pub path: PathBuf,
    /// 声明的总字节数。
    pub declared: u64,
    /// 已收字节数。
    pub received: u64,
}

impl IncomingFile {
    /// 按 `FileParam` 建一个下载目标。
    ///
    /// # Errors
    /// 名字非法、`offset > size`、父目录不存在或不可写。
    pub fn new(
        key: SessionKey,
        root: &Path,
        param: &FileParam,
    ) -> std::result::Result<Self, FileError> {
        let path = safe_join(root, &param.name)?;
        if param.offset > param.size {
            return Err(FileError::BadOffset {
                offset: param.offset,
                size: param.size,
            });
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| FileError::Separator {
                name: param.name.clone(),
            })?;
        }
        Ok(Self {
            key,
            path,
            declared: param.size,
            received: 0,
        })
    }

    /// 记录一片数据，返回累计字节数。
    ///
    /// # Errors
    /// 累计超过声明长度（[`FileError::Oversize`]）。
    pub fn accept(&mut self, len: usize) -> std::result::Result<u64, FileError> {
        let len = len as u64;
        let total = self.received.saturating_add(len);
        if total > self.declared {
            return Err(FileError::Oversize {
                actual: total,
                declared: self.declared,
            });
        }
        self.received = total;
        Ok(total)
    }

    /// 收尾校验：实收必须等于声明。
    ///
    /// # Errors
    /// 数量不符（[`FileError::Incomplete`]）。
    pub fn finish(&self) -> std::result::Result<(), FileError> {
        if self.received != self.declared {
            return Err(FileError::Incomplete {
                actual: self.received,
                declared: self.declared,
            });
        }
        Ok(())
    }
}

/// 把一段字节切成 `ServiceData` 分片（seq 从 0 严格递增）。
///
/// 空输入也发一个空帧：接收方靠它推进序号，而不是靠「没有数据」猜结束。
#[must_use]
pub fn chunk(key: SessionKey, data: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    if data.is_empty() {
        out.push(data_message(key, 0, Vec::new()));
        return out;
    }
    for (seq, piece) in data.chunks(FILE_CHUNK).enumerate() {
        out.push(data_message(key, seq as u64, piece.to_vec()));
    }
    out
}

fn data_message(key: SessionKey, seq: u64, data: Vec<u8>) -> Message {
    Message::ServiceData(stowaway_protocol::ServiceData {
        key,
        seq,
        data: stowaway_protocol::ByteBuf::from(data),
    })
}

/// 文件传输的探测请求（v1 的 `FILESTATREQ`）。
#[must_use]
pub fn request(key: SessionKey, param: &FileParam) -> Message {
    Message::ServiceRequest(ServiceRequest {
        key,
        kind: ServiceKind::File,
        phase: ServicePhase::Probe,
        param: ServiceParam::File(param.clone()),
    })
}

/// 文件传输的执行请求（探测通过后开始传数据）。
#[must_use]
pub fn run(key: SessionKey, param: &FileParam) -> Message {
    Message::ServiceRequest(ServiceRequest {
        key,
        kind: ServiceKind::File,
        phase: ServicePhase::Run,
        param: ServiceParam::File(param.clone()),
    })
}

/// 失败时的终止消息（v1 的 `FILEERR`）。
#[must_use]
pub fn failure(key: SessionKey, detail: impl Into<String>) -> Message {
    Message::ServiceExit(stowaway_protocol::ServiceExit {
        key,
        code: stowaway_protocol::SessionCode::Refused,
        detail: detail.into(),
    })
}

/// 为「本节点发起的第 `id` 个文件会话」造键。
#[must_use]
pub fn key_for(origin: stowaway_protocol::NodeId, id: u64) -> SessionKey {
    SessionKey::new(origin, id)
}

/// 把 [`FileError`] 提升为 [`CoreError`]。
#[must_use]
pub fn as_core(err: &FileError) -> CoreError {
    CoreError::Protocol(stowaway_protocol::ProtocolError::Payload(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_protocol::NodeId;

    fn param(name: &str, size: u64) -> FileParam {
        FileParam {
            name: name.to_owned(),
            size,
            sha256: [0u8; 32],
            offset: 0,
            direction: stowaway_protocol::FileDirection::Upload,
        }
    }

    fn key() -> SessionKey {
        SessionKey::new(NodeId::ADMIN, 3)
    }

    #[test]
    fn accepts_a_plain_single_segment_name() {
        assert_eq!(validate_name("report.txt").expect("ok"), "report.txt");
        assert_eq!(validate_name("a-b_c.tar.gz").expect("ok"), "a-b_c.tar.gz");
    }

    #[test]
    fn rejects_path_traversal_attempts() {
        for bad in [
            "../escape.txt",
            "../../etc/passwd",
            "sub/dir.txt",
            "sub\\dir.txt",
            "..",
            ".",
            ".hidden",
            "con",
            "CON.txt",
            "lpt1",
            "nul.log",
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?} 必须被拒绝");
        }
    }

    #[test]
    fn rejects_empty_and_overlong_names() {
        assert_eq!(validate_name(""), Err(FileError::EmptyName));
        let long = "a".repeat(MAX_NAME_LEN + 1);
        assert!(matches!(
            validate_name(&long),
            Err(FileError::NameTooLong { .. })
        ));
    }

    #[test]
    fn rejects_control_characters() {
        assert_eq!(validate_name("a\u{0007}b"), Err(FileError::ControlChar));
    }

    #[test]
    fn safe_join_stays_inside_the_root() {
        let root = std::env::temp_dir().join("rs-away-safe-join");
        std::fs::create_dir_all(&root).expect("mkdir");
        let path = safe_join(&root, "ok.txt").expect("ok");
        assert_eq!(path, root.join("ok.txt"));
        assert!(path.starts_with(&root));
        assert!(safe_join(&root, "../x").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn incoming_rejects_offset_beyond_size() {
        let root = std::env::temp_dir().join("rs-away-offset");
        std::fs::create_dir_all(&root).expect("mkdir");
        let mut p = param("a.txt", 4);
        p.offset = 5;
        assert!(matches!(
            IncomingFile::new(key(), &root, &p),
            Err(FileError::BadOffset { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn incoming_tracks_bytes_and_validates_totals() {
        let root = std::env::temp_dir().join("rs-away-incoming");
        std::fs::create_dir_all(&root).expect("mkdir");
        let mut f = IncomingFile::new(key(), &root, &param("a.bin", 5)).expect("new");
        assert_eq!(f.accept(2).expect("2"), 2);
        assert_eq!(f.accept(3).expect("3"), 5);
        assert!(f.finish().is_ok());
        // 超出声明。
        let mut g = IncomingFile::new(key(), &root, &param("b.bin", 1)).expect("new");
        assert!(matches!(g.accept(2), Err(FileError::Oversize { .. })));
        // 不足声明。
        let h = IncomingFile::new(key(), &root, &param("c.bin", 9)).expect("new");
        assert!(matches!(h.finish(), Err(FileError::Incomplete { .. })));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn chunk_splits_at_the_boundary() {
        let data = vec![7u8; FILE_CHUNK * 2 + 1];
        let msgs = chunk(key(), &data);
        assert_eq!(msgs.len(), 3, "两整片 + 1 字节余量");
        let mut seqs = Vec::new();
        for m in &msgs {
            let Message::ServiceData(d) = m else {
                panic!("必须是 ServiceData")
            };
            seqs.push(d.seq);
            assert_eq!(
                d.data.len(),
                FILE_CHUNK.min(data.len() - (d.seq as usize) * FILE_CHUNK)
            );
        }
        assert_eq!(seqs, vec![0, 1, 2], "序号必须从 0 严格递增");
    }

    #[test]
    fn chunk_of_empty_data_emits_one_empty_frame() {
        let msgs = chunk(key(), &[]);
        assert_eq!(msgs.len(), 1);
        let Message::ServiceData(d) = &msgs[0] else {
            panic!("必须是 ServiceData")
        };
        assert_eq!(d.seq, 0);
        assert!(d.data.is_empty());
    }

    #[test]
    fn requests_and_failures_carry_the_right_kind() {
        let p = param("f.txt", 1);
        let Message::ServiceRequest(probe) = request(key(), &p) else {
            panic!("probe")
        };
        assert_eq!(probe.kind, ServiceKind::File);
        assert_eq!(probe.phase, ServicePhase::Probe);

        let Message::ServiceRequest(run_msg) = run(key(), &p) else {
            panic!("run")
        };
        assert_eq!(run_msg.phase, ServicePhase::Run);

        let Message::ServiceExit(exit) = failure(key(), "磁盘满") else {
            panic!("exit")
        };
        assert_eq!(exit.code, stowaway_protocol::SessionCode::Refused);
        assert_eq!(exit.detail, "磁盘满");
    }

    #[test]
    fn errors_promote_to_core_errors() {
        let e = as_core(&FileError::EmptyName);
        assert!(e.to_string().contains("文件名为空"), "{e}");
    }
}
