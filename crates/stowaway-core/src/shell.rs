//! 交互式 Shell：**PTY** + 编码转换 + resize。
//!
//! 权威：`docs/plan.md` §4.6（`ServiceKind::Shell` + `ShellParam`）、
//! §5.1 第 9 项（交互式 shell **升级为 PTY**）、附录 A（`SHELLREQ`/`SHELLRES`/
//! `SHELLCOMMAND`/`SHELLRESULT`/`SHELLEXIT` 的映射）、§8.5 场景 7。
//!
//! # 与 v1 的三处差别
//!
//! 1. **有 PTY**。v1 用 `exec.Command("/bin/sh","-i")` + `StdoutPipe`/`StdinPipe`
//!    （`agent/handler/shell.go:76-90`），子进程看到的是管道而不是终端：
//!    `isatty()` 为假、`ls` 不彩色、`vim`/`top` 这类全屏程序直接报错、
//!    `stty size` 返回 `0 0`。v2 用 `portable-pty` 开一对真正的 PTY，
//!    并把 `cols`/`rows` 一路带到 `TIOCSWINSZ`。
//! 2. **有 resize**。v1 没有任何 resize 消息——窗口大小在启动那一刻定死。
//!    v2 用一字节**类型前缀**承载控制帧（见下）。
//! 3. **编码转换不再静默替换**。`-cs gbk`（`agent/handler/shell.go:122/:138`）
//!    的 `ConvertGBK2Str`/`ConvertStr2GBK` 遇到映射不了的字符会直接吞掉；
//!    v2 的 `encode_input` 检测到替换就报错，把「用户输入被悄悄改掉」
//!    变成可传播的失败。
//!
//! # 数据帧带类型前缀
//!
//! `ServiceData` 没有「类型」字段，而 `seq` 是流序不是帧类型。为了在不改动
//! 消息集的前提下表达 resize，`payload` 的第一个字节是**类型标签**：
//!
//! | 首字节 | 含义 | 其余字节 |
//! |---|---|---|
//! | `0x00` | 终端数据 | 原样（GBK 或 UTF-8，取决于 `charset`） |
//! | `0x01` | resize | `cols u16 LE ‖ rows u16 LE`，共 4 字节 |
//!
//! **所有** shell 数据帧都带前缀（不是「只有控制帧带」），否则首字节为
//! `0x01` 的普通输出会被误判成 resize。这一字节的代价换来的是无歧义。

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use stowaway_protocol::{
    ByteBuf, Message, ServiceData, ServiceKind, ServiceParam, ServicePhase, ServiceRequest,
    SessionKey,
};
use tokio::sync::mpsc;

use crate::error::CoreError;

/// 读缓冲大小，与 v1 一致（`agent/handler/shell.go:96`）。
pub const SHELL_READ_BUF: usize = 4096;

/// 终端数据帧的类型标签。
pub const SHELL_TAG_DATA: u8 = 0x00;

/// resize 控制帧的类型标签。
pub const SHELL_TAG_RESIZE: u8 = 0x01;

/// 默认终端类型。
pub const DEFAULT_TERM: &str = "xterm";

/// 编码方案。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Charset {
    /// UTF-8（v2 默认）。
    #[default]
    Utf8,
    /// GBK（v1 的 `-cs gbk`）。
    Gbk,
}

impl Charset {
    /// 从命令行标签解析（大小写不敏感）。
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        if tag.eq_ignore_ascii_case("utf8") || tag.eq_ignore_ascii_case("utf-8") {
            Some(Self::Utf8)
        } else if tag.eq_ignore_ascii_case("gbk") {
            Some(Self::Gbk)
        } else {
            None
        }
    }

    /// 命令行标签。
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Gbk => "gbk",
        }
    }

    /// 对应的 `encoding_rs` 编码。
    #[must_use]
    const fn encoding(self) -> &'static encoding_rs::Encoding {
        match self {
            Self::Utf8 => encoding_rs::UTF_8,
            Self::Gbk => encoding_rs::GBK,
        }
    }
}

/// Shell 会话的错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShellError {
    /// PTY 子系统报错（`portable-pty` 的统一错误类型是 `anyhow::Error`）。
    #[error("PTY 错误：{0}")]
    Pty(String),

    /// 输入无法用目标编码表示（例如 GBK 下输入 emoji）。
    #[error("输入无法编码为 {charset}：第 {offset} 字节起")]
    Encode {
        /// 编码名。
        charset: &'static str,
        /// 出问题的输入偏移（UTF-8 字节）。
        offset: usize,
    },

    /// 输出解码出现非法字节序列。
    #[error("输出无法按 {charset} 解码")]
    Decode {
        /// 编码名。
        charset: &'static str,
    },

    /// 控制帧长度不对。
    #[error("shell 数据帧格式错误：{0}")]
    Frame(String),

    /// 会话已关闭。
    #[error("shell 会话已关闭")]
    Closed,
}

impl ShellError {
    /// 提升为 [`CoreError`]。
    #[must_use]
    pub fn as_core(&self) -> CoreError {
        CoreError::Protocol(stowaway_protocol::ProtocolError::Payload(self.to_string()))
    }
}

/// 一次 shell 服务的规格。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShellSpec {
    /// 会话键。
    pub key: SessionKey,
    /// 初始列数。
    pub cols: u16,
    /// 初始行数。
    pub rows: u16,
    /// 终端类型（`TERM`）。
    pub term: String,
    /// 编码。
    pub charset: Charset,
}

impl ShellSpec {
    /// 由请求参数构造；`cols`/`rows` 为 0 时回落到 80×24。
    #[must_use]
    pub fn new(key: SessionKey, param: &stowaway_protocol::ShellParam) -> Self {
        Self {
            key,
            cols: if param.cols == 0 { 80 } else { param.cols },
            rows: if param.rows == 0 { 24 } else { param.rows },
            term: if param.term.is_empty() {
                DEFAULT_TERM.to_owned()
            } else {
                param.term.clone()
            },
            charset: Charset::Utf8,
        }
    }

    /// 换编码。
    #[must_use]
    pub fn with_charset(mut self, charset: Charset) -> Self {
        self.charset = charset;
        self
    }

    /// 上线用的请求参数。
    #[must_use]
    pub fn param(&self) -> stowaway_protocol::ShellParam {
        stowaway_protocol::ShellParam {
            cols: self.cols,
            rows: self.rows,
            term: self.term.clone(),
        }
    }
}

/// 打开 shell 的请求（v1 的 `SHELLREQ`，`docs/plan.md` 附录 A 第 7 行）。
#[must_use]
pub fn open_message(key: SessionKey, param: &stowaway_protocol::ShellParam) -> Message {
    Message::ServiceRequest(ServiceRequest {
        key,
        kind: ServiceKind::Shell,
        phase: ServicePhase::Run,
        param: ServiceParam::Shell(param.clone()),
    })
}

/// 终端数据帧（带上限定的类型标签）。
#[must_use]
pub fn data_message(key: SessionKey, seq: u64, data: &[u8]) -> Message {
    let mut payload = Vec::with_capacity(data.len() + 1);
    payload.push(SHELL_TAG_DATA);
    payload.extend_from_slice(data);
    Message::ServiceData(ServiceData {
        key,
        seq,
        data: ByteBuf::from(payload),
    })
}

/// resize 控制帧。
///
/// # Errors
/// `cols`/`rows` 为 0 时报 [`ShellError::Frame`]：`TIOCSWINSZ` 接受 0，但
/// 0 列的终端在 `ncurses` 里会整除出错，不让它上线。
pub fn resize_message(
    key: SessionKey,
    seq: u64,
    cols: u16,
    rows: u16,
) -> std::result::Result<Message, ShellError> {
    if cols == 0 || rows == 0 {
        return Err(ShellError::Frame(format!(
            "resize 不接受 0 尺寸：cols={cols}, rows={rows}"
        )));
    }
    let mut payload = Vec::with_capacity(5);
    payload.push(SHELL_TAG_RESIZE);
    payload.extend_from_slice(&cols.to_le_bytes());
    payload.extend_from_slice(&rows.to_le_bytes());
    Ok(Message::ServiceData(ServiceData {
        key,
        seq,
        data: ByteBuf::from(payload),
    }))
}

/// 一个 shell 数据帧的语义。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ShellFrame {
    /// 终端数据（已去掉类型标签，仍是线上编码）。
    Data(Vec<u8>),
    /// 调整窗口大小。
    Resize {
        /// 列。
        cols: u16,
        /// 行。
        rows: u16,
    },
}

/// 解析 shell 数据帧。
///
/// # Errors
/// 空帧、未知标签、resize 帧长度不是 4、零尺寸。
pub fn parse_frame(data: &[u8]) -> std::result::Result<ShellFrame, ShellError> {
    let (tag, rest) = data
        .split_first()
        .ok_or_else(|| ShellError::Frame("空帧没有类型标签".to_owned()))?;
    match *tag {
        SHELL_TAG_DATA => Ok(ShellFrame::Data(rest.to_vec())),
        SHELL_TAG_RESIZE => {
            if rest.len() != 4 {
                return Err(ShellError::Frame(format!(
                    "resize 帧必须是 4 字节，实际 {}",
                    rest.len()
                )));
            }
            let cols = u16::from_le_bytes([rest[0], rest[1]]);
            let rows = u16::from_le_bytes([rest[2], rest[3]]);
            if cols == 0 || rows == 0 {
                return Err(ShellError::Frame(format!(
                    "resize 不接受 0 尺寸：cols={cols}, rows={rows}"
                )));
            }
            Ok(ShellFrame::Resize { cols, rows })
        }
        other => Err(ShellError::Frame(format!(
            "未知的 shell 帧标签 {other:#04x}"
        ))),
    }
}

/// PTY 侧的内部事件。
#[derive(Debug)]
enum PtyEvent {
    Data(Vec<u8>),
    Eof,
    Failed(String),
}

/// 编解码状态机：把 UTF-8 和线上编码互相转换，**不静默替换**。
///
/// 单独成一个类型有两个原因：
/// 1. 编解码需要跨多次读保持状态（一个 GBK 双字节可能被切在两次读之间），
///    所以不能写成纯函数；
/// 2. 它不含任何 PTY 资源，可以脱离 PTY 单独测（见 `mod tests` 里那几条
///    编码用例），也不必为「测编码」而去起一个子进程。
#[derive(Debug)]
pub struct ShellCodec {
    charset: Charset,
    encoder: Option<encoding_rs::Encoder>,
    decoder: Option<encoding_rs::Decoder>,
}

impl ShellCodec {
    /// 按编码方案构造。
    #[must_use]
    pub fn new(charset: Charset) -> Self {
        Self {
            charset,
            encoder: match charset {
                Charset::Utf8 => None,
                Charset::Gbk => Some(charset.encoding().new_encoder()),
            },
            decoder: match charset {
                Charset::Utf8 => None,
                Charset::Gbk => Some(charset.encoding().new_decoder()),
            },
        }
    }

    /// 当前编码方案。
    #[must_use]
    pub const fn charset(&self) -> Charset {
        self.charset
    }

    /// 把 UTF-8 输入转成线上编码。
    ///
    /// **不静默替换**：`encoding_rs` 的带替换版本会把无法映射的字符换成
    /// `&#NNNNN;` 并置 `replaced=true`，那等于把「用户输入被改掉」这件事
    /// 藏起来。这里走 `_without_replacement` 系列，`Unmappable` 直接报错。
    ///
    /// 容量必须按 `max_buffer_length_from_utf8_without_replacement` 预留：
    /// `encoding_rs` 在输出缓冲不足时**返回 `OutputFull` 且一个字节都不写**，
    /// 不会自动扩容（实测 capacity 9 处理 6 字节 UTF-8 仍 `OutputFull`）。
    ///
    /// # Errors
    /// 输入不是合法 UTF-8，或目标编码里没有对应字符（[`ShellError::Encode`]）。
    pub fn encode_input(&mut self, data: &[u8]) -> std::result::Result<Vec<u8>, ShellError> {
        let Some(encoder) = self.encoder.as_mut() else {
            return Ok(data.to_vec());
        };
        let text = std::str::from_utf8(data).map_err(|e| ShellError::Encode {
            charset: self.charset.as_tag(),
            offset: e.valid_up_to(),
        })?;
        let mut out: Vec<u8> = Vec::with_capacity(text.len() + 8);
        let mut rest = text;
        let mut consumed = 0usize;
        loop {
            let need = encoder
                .max_buffer_length_from_utf8_without_replacement(rest.len())
                .unwrap_or(rest.len() * 4 + 8);
            out.reserve(need.max(16));
            let (result, read) =
                encoder.encode_from_utf8_to_vec_without_replacement(rest, &mut out, true);
            consumed += read;
            rest = &rest[read..];
            match result {
                encoding_rs::EncoderResult::InputEmpty => return Ok(out),
                encoding_rs::EncoderResult::Unmappable(_) => {
                    return Err(ShellError::Encode {
                        charset: self.charset.as_tag(),
                        offset: consumed,
                    });
                }
                encoding_rs::EncoderResult::OutputFull => continue,
            }
        }
    }

    /// 把线上字节转成 UTF-8。
    ///
    /// 与 [`ShellCodec::encode_input`] 同理：走 `_without_replacement`，
    /// 非法字节序列报错而不是替换成 U+FFFD。
    ///
    /// # Errors
    /// 出现非法字节序列（[`ShellError::Decode`]）。
    pub fn decode_output(&mut self, data: &[u8]) -> std::result::Result<Vec<u8>, ShellError> {
        let Some(decoder) = self.decoder.as_mut() else {
            return Ok(data.to_vec());
        };
        // 用 `decode_to_string_without_replacement` 而不是 `decode_to_utf8_*`：
        // 后者收 `&mut [u8]`，传 `&mut Vec` 只会借到「已初始化长度」的空切片，
        // 永远 OutputFull。前者内部用 `spare_capacity_mut`，能真正扩容。
        let mut out = String::with_capacity(data.len() + 8);
        let mut rest = data;
        loop {
            let need = decoder
                .max_utf8_buffer_length_without_replacement(rest.len())
                .unwrap_or(rest.len() * 4 + 8);
            out.reserve(need.max(16));
            let (result, read) = decoder.decode_to_string_without_replacement(rest, &mut out, true);
            rest = &rest[read..];
            match result {
                encoding_rs::DecoderResult::InputEmpty => return Ok(out.into_bytes()),
                encoding_rs::DecoderResult::Malformed(_, _) => {
                    return Err(ShellError::Decode {
                        charset: self.charset.as_tag(),
                    });
                }
                encoding_rs::DecoderResult::OutputFull => continue,
            }
        }
    }
}

/// 一个已启动的 PTY 会话。
///
/// `Debug` 手写：`portable-pty` 的 `MasterPty`/`Child` 都没有 `Debug`。
pub struct PtySession {
    spec: ShellSpec,
    master: Box<dyn portable_pty::MasterPty + Send>,
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
    writer: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    out: mpsc::UnboundedReceiver<PtyEvent>,
    codec: ShellCodec,
    exited: bool,
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtySession")
            .field("spec", &self.spec)
            .field("exited", &self.exited)
            .finish_non_exhaustive()
    }
}

/// 选择要起的 shell 程序，对齐 v1 `agent/handler/shell.go:64-74` 的选择逻辑。
#[must_use]
pub fn default_shell() -> (&'static str, &'static [&'static str]) {
    if cfg!(windows) {
        ("cmd.exe", &[] as &[&str])
    } else if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
        ("/bin/bash", &["-i"] as &[&str])
    } else {
        ("/bin/sh", &["-i"] as &[&str])
    }
}

/// 起一个 PTY + 子进程。
///
/// # Errors
/// PTY 打不开、子进程起不来。两者都把 `anyhow::Error` 的 `Display` 装进
/// [`ShellError::Pty`]（`portable-pty` 没有更细的错误类型）。
pub fn spawn(spec: &ShellSpec) -> std::result::Result<PtySession, ShellError> {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};

    let size = PtySize {
        rows: spec.rows,
        cols: spec.cols,
        pixel_width: 0,
        pixel_height: 0,
    };
    let pair = native_pty_system()
        .openpty(size)
        .map_err(|e| ShellError::Pty(format!("打开 PTY 失败：{e}")))?;

    let (prog, args) = default_shell();
    let mut cmd = CommandBuilder::new(prog);
    cmd.args(args);
    cmd.env("TERM", spec.term.as_str());

    let child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| ShellError::Pty(format!("启动 {prog} 失败：{e}")))?;
    // slave 必须立刻丢掉：只要还有进程持有 slave 端，master 读端在子进程
    // 退出后就永远等不到 EOF/EIO，读取线程会挂死。
    drop(pair.slave);

    let master = pair.master;
    let reader = master
        .try_clone_reader()
        .map_err(|e| ShellError::Pty(format!("克隆 PTY 读端失败：{e}")))?;
    let writer = master
        .take_writer()
        .map_err(|e| ShellError::Pty(format!("取 PTY 写端失败：{e}")))?;

    let (out_tx, out_rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("stw-pty-read".to_owned())
        .spawn(move || read_loop(reader, out_tx))
        .map_err(|e| ShellError::Pty(format!("启动读取线程失败：{e}")))?;

    let (in_tx, in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::Builder::new()
        .name("stw-pty-write".to_owned())
        .spawn(move || write_loop(writer, in_rx))
        .map_err(|e| ShellError::Pty(format!("启动写入线程失败：{e}")))?;

    let charset = spec.charset;
    Ok(PtySession {
        spec: spec.clone(),
        master,
        child: Arc::new(Mutex::new(child)),
        writer: Some(in_tx),
        out: out_rx,
        codec: ShellCodec::new(charset),
        exited: false,
    })
}

fn read_loop(mut reader: Box<dyn Read + Send>, tx: mpsc::UnboundedSender<PtyEvent>) {
    let mut buf = vec![0u8; SHELL_READ_BUF];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                let _ = tx.send(PtyEvent::Eof);
                return;
            }
            Ok(n) => {
                if tx.send(PtyEvent::Data(buf[..n].to_vec())).is_err() {
                    return; // 会话已 drop
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // 子进程退出后读 PTY master 得到 EIO（Linux/macOS 都是 5），
            // 这不是错误而是「终端那头没了」。
            Err(e) if e.raw_os_error() == Some(5) => {
                let _ = tx.send(PtyEvent::Eof);
                return;
            }
            Err(e) => {
                let _ = tx.send(PtyEvent::Failed(e.to_string()));
                return;
            }
        }
    }
}

fn write_loop(mut writer: Box<dyn Write + Send>, rx: std::sync::mpsc::Receiver<Vec<u8>>) {
    while let Ok(chunk) = rx.recv() {
        if writer.write_all(&chunk).is_err() {
            return;
        }
        let _ = writer.flush();
    }
}

impl PtySession {
    /// 规格。
    #[must_use]
    pub const fn spec(&self) -> &ShellSpec {
        &self.spec
    }

    /// 会话键。
    #[must_use]
    pub const fn key(&self) -> SessionKey {
        self.spec.key
    }

    /// 子进程是否已经退出（读到 EOF 后为真）。
    #[must_use]
    pub const fn exited(&self) -> bool {
        self.exited
    }

    /// 把控制器发来的输入转成 PTY 需要的编码（委托 [`ShellCodec`]）。
    ///
    /// # Errors
    /// GBK 下有映射不了的字符——**不静默替换**。
    pub fn encode_input(&mut self, data: &[u8]) -> std::result::Result<Vec<u8>, ShellError> {
        self.codec.encode_input(data)
    }

    /// 把 PTY 输出转成 UTF-8 字节。
    ///
    /// # Errors
    /// GBK 解码出现非法序列。
    pub fn decode_output(&mut self, data: &[u8]) -> std::result::Result<Vec<u8>, ShellError> {
        self.codec.decode_output(data)
    }

    /// 写终端输入（已按 `charset` 编码）。
    ///
    /// # Errors
    /// 编码失败、写入线程已退出。
    pub fn write(&mut self, data: &[u8]) -> std::result::Result<(), ShellError> {
        let encoded = self.encode_input(data)?;
        match self.writer.as_ref() {
            Some(tx) => tx.send(encoded).map_err(|_| ShellError::Closed),
            None => Err(ShellError::Closed),
        }
    }

    /// 等下一段输出；`None` 表示终端已关闭（子进程退出）。
    ///
    /// 返回的字节已经按 `charset` 转成 UTF-8。
    ///
    /// # Errors
    /// 解码失败、PTY 读失败。
    pub async fn next_output(&mut self) -> std::result::Result<Option<Vec<u8>>, ShellError> {
        loop {
            match self.out.recv().await {
                Some(PtyEvent::Data(raw)) => {
                    let decoded = self.decode_output(&raw)?;
                    if decoded.is_empty() {
                        continue; // 半个多字节序列：等后续字节
                    }
                    return Ok(Some(decoded));
                }
                Some(PtyEvent::Eof) | None => {
                    self.exited = true;
                    return Ok(None);
                }
                Some(PtyEvent::Failed(msg)) => return Err(ShellError::Pty(msg)),
            }
        }
    }

    /// 调整窗口大小（`TIOCSWINSZ`）。
    ///
    /// # Errors
    /// 0 尺寸、`ioctl` 失败。
    pub fn resize(&self, cols: u16, rows: u16) -> std::result::Result<(), ShellError> {
        if cols == 0 || rows == 0 {
            return Err(ShellError::Frame(format!(
                "resize 不接受 0 尺寸：cols={cols}, rows={rows}"
            )));
        }
        self.master
            .resize(portable_pty::PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| ShellError::Pty(format!("resize 到 {cols}x{rows} 失败：{e}")))
    }

    /// 杀掉子进程。
    ///
    /// # Errors
    /// `kill(2)` 失败（通常意味着进程已经退出）。
    pub fn kill(&mut self) -> std::result::Result<(), ShellError> {
        let mut child = self
            .child
            .lock()
            .map_err(|_| ShellError::Pty("子进程句柄被毒化".to_owned()))?;
        child
            .kill()
            .map_err(|e| ShellError::Pty(format!("kill 失败：{e}")))?;
        self.exited = true;
        Ok(())
    }

    /// 等子进程退出并返回退出码（`wait(2)` 是阻塞调用，这里挪到阻塞线程池）。
    ///
    /// # Errors
    /// `wait(2)` 失败。
    pub async fn wait_exit(&self) -> std::result::Result<u32, ShellError> {
        let child = Arc::clone(&self.child);
        tokio::task::spawn_blocking(move || {
            let mut guard = child
                .lock()
                .map_err(|_| ShellError::Pty("子进程句柄被毒化".to_owned()))?;
            guard
                .wait()
                .map(|s| s.exit_code())
                .map_err(|e| ShellError::Pty(format!("wait 失败：{e}")))
        })
        .await
        .map_err(|e| ShellError::Pty(format!("join 失败：{e}")))?
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // 先关写端，让写入线程收尾；再杀子进程，读取线程随之读到 EIO。
        self.writer = None;
        if !self.exited {
            if let Ok(mut child) = self.child.lock() {
                let _ = child.kill();
            }
            self.exited = true;
        }
    }
}

/// 把 [`ShellError`] 提升为 [`CoreError`]。
#[must_use]
pub fn as_core(err: &ShellError) -> CoreError {
    err.as_core()
}

/// 结果别名，便于服务层直接 `?`。
pub type ShellResult<T> = std::result::Result<T, ShellError>;

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_protocol::{NodeId, ShellParam};

    fn key() -> SessionKey {
        SessionKey::new(NodeId::ADMIN, 7)
    }

    fn spec(charset: Charset) -> ShellSpec {
        ShellSpec::new(
            key(),
            &ShellParam {
                cols: 0,
                rows: 0,
                term: String::new(),
            },
        )
        .with_charset(charset)
    }

    #[test]
    fn spec_falls_back_to_80x24_and_xterm() {
        let s = spec(Charset::Utf8);
        assert_eq!((s.cols, s.rows), (80, 24));
        assert_eq!(s.term, "xterm");
    }

    #[test]
    fn spec_keeps_explicit_size() {
        let s = ShellSpec::new(
            key(),
            &ShellParam {
                cols: 132,
                rows: 43,
                term: "linux".to_owned(),
            },
        );
        assert_eq!((s.cols, s.rows), (132, 43));
        assert_eq!(s.param().term, "linux");
    }

    #[test]
    fn charset_tags_round_trip() {
        assert_eq!(Charset::from_tag("GBK"), Some(Charset::Gbk));
        assert_eq!(Charset::from_tag("utf-8"), Some(Charset::Utf8));
        assert_eq!(Charset::from_tag("gb18030"), None);
        assert_eq!(Charset::Gbk.as_tag(), "gbk");
    }

    #[test]
    fn open_message_is_a_run_phase_shell_request() {
        let param = ShellParam {
            cols: 100,
            rows: 40,
            term: "xterm".to_owned(),
        };
        match open_message(key(), &param) {
            Message::ServiceRequest(req) => {
                assert_eq!(req.kind, ServiceKind::Shell);
                assert_eq!(req.phase, ServicePhase::Run);
                match req.param {
                    ServiceParam::Shell(p) => assert_eq!(p.cols, 100),
                    other => panic!("参数种类不对：{other:?}"),
                }
            }
            other => panic!("消息种类不对：{other:?}"),
        }
    }

    #[test]
    fn data_frames_carry_a_type_tag() {
        let msg = data_message(key(), 3, b"hello");
        match msg {
            Message::ServiceData(d) => {
                assert_eq!(d.seq, 3);
                assert_eq!(&d.data[..], b"\x00hello");
            }
            other => panic!("消息种类不对：{other:?}"),
        }
    }

    #[test]
    fn resize_frames_round_trip() {
        let msg = resize_message(key(), 4, 120, 40).expect("resize");
        let Message::ServiceData(d) = msg else {
            panic!("不是数据帧");
        };
        assert_eq!(d.data.len(), 5);
        match parse_frame(&d.data).expect("parse") {
            ShellFrame::Resize { cols, rows } => {
                assert_eq!((cols, rows), (120, 40));
            }
            other => panic!("解析结果不对：{other:?}"),
        }
    }

    #[test]
    fn zero_size_resize_is_rejected() {
        assert!(resize_message(key(), 0, 0, 24).is_err());
        assert!(resize_message(key(), 0, 80, 0).is_err());
        // 线上来的畸形帧也要拒。
        let mut bad = vec![SHELL_TAG_RESIZE];
        bad.extend_from_slice(&0u16.to_le_bytes());
        bad.extend_from_slice(&24u16.to_le_bytes());
        assert!(parse_frame(&bad).is_err());
    }

    #[test]
    fn malformed_frames_are_errors_not_guesses() {
        assert!(parse_frame(&[]).is_err());
        assert!(parse_frame(&[0x09, 1, 2, 3]).is_err());
        // resize 长度不对
        assert!(parse_frame(&[SHELL_TAG_RESIZE, 1, 2]).is_err());
        // 数据帧可以是空内容
        assert_eq!(
            parse_frame(&[SHELL_TAG_DATA]).expect("空数据"),
            ShellFrame::Data(Vec::new())
        );
    }

    #[test]
    fn utf8_charset_is_identity() {
        let mut s = ShellCodec::new(Charset::Utf8);
        assert_eq!(
            s.encode_input("你好".as_bytes()).expect("编码"),
            "你好".as_bytes()
        );
        assert_eq!(
            s.decode_output("你好".as_bytes()).expect("解码"),
            "你好".as_bytes()
        );
    }

    #[test]
    fn gbk_round_trips_chinese() {
        let mut s = ShellCodec::new(Charset::Gbk);
        let gbk = s.encode_input("你好".as_bytes()).expect("编码");
        // GBK 下「你好」= 4 字节，且不是 UTF-8。
        assert_eq!(gbk.len(), 4);
        assert_ne!(gbk, "你好".as_bytes());
        let back = s.decode_output(&gbk).expect("解码");
        assert_eq!(back, "你好".as_bytes());
    }

    #[test]
    fn gbk_unmappable_input_is_an_error_not_silent_replacement() {
        let mut s = ShellCodec::new(Charset::Gbk);
        // emoji 不在 GBK 里：v1 会替换成 `&#128512;`，v2 必须报错。
        let err = s.encode_input("😀".as_bytes()).expect_err("必须报错");
        match err {
            ShellError::Encode { charset, .. } => assert_eq!(charset, "gbk"),
            other => panic!("错误种类不对：{other:?}"),
        }
    }

    #[test]
    fn gbk_invalid_bytes_are_a_decode_error() {
        let mut s = ShellCodec::new(Charset::Gbk);
        // GBK 首字节 0x81..=0xFE 后接 0x20 是非法组合。
        assert!(s.decode_output(&[0x81, 0x20]).is_err());
    }

    #[test]
    fn spawn_and_echo_through_a_real_pty() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let mut s = spawn(&spec(Charset::Utf8)).expect("起 PTY");
            s.write(b"echo stowaway-pty\r").expect("写");
            let mut seen = Vec::new();
            for _ in 0..64 {
                let Some(chunk) = s.next_output().await.expect("读") else {
                    break;
                };
                seen.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&seen).contains("stowaway-pty") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&seen).to_string();
            assert!(text.contains("stowaway-pty"), "没看到回显：{text:?}");
            s.kill().expect("kill");
        });
    }

    #[test]
    fn resize_reaches_the_child_through_stty() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let mut s = spawn(&spec(Charset::Utf8)).expect("起 PTY");
            s.resize(101, 37).expect("resize");
            s.write(b"stty size\r").expect("写");
            let mut seen = Vec::new();
            for _ in 0..64 {
                let Some(chunk) = s.next_output().await.expect("读") else {
                    break;
                };
                seen.extend_from_slice(&chunk);
                let text = String::from_utf8_lossy(&seen).to_string();
                if text.contains("37 101") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&seen).to_string();
            assert!(text.contains("37 101"), "stty size 没反映 resize：{text:?}");
            s.kill().expect("kill");
        });
    }

    #[test]
    fn pty_means_isatty_is_true() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let mut s = spawn(&spec(Charset::Utf8)).expect("起 PTY");
            s.write(b"test -t 0 && echo TTY-OK || echo TTY-NO\r")
                .expect("写");
            let mut seen = Vec::new();
            for _ in 0..64 {
                let Some(chunk) = s.next_output().await.expect("读") else {
                    break;
                };
                seen.extend_from_slice(&chunk);
                let text = String::from_utf8_lossy(&seen).to_string();
                if text.contains("TTY-OK") || text.contains("TTY-NO") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&seen).to_string();
            assert!(text.contains("TTY-OK"), "PTY 下 stdin 应当是 tty：{text:?}");
            s.kill().expect("kill");
        });
    }
}
