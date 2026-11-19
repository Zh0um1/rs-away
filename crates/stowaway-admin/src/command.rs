//! 控制台命令解析：主面板 5 条 + 节点面板 20 条。
//!
//! 权威清单见 docs/plan.md §4.10，与 v1 `admin/cli/cli.go` 的帮助文本一致：
//!
//! - 主面板：`use <node>` / `detail` / `topo` / `help` / `exit`
//! - 节点面板：`status` / `addmemo <note>` / `delmemo <idx>` / `shell` /
//!   `listen [ip:]<port>` / `connect <addr>` /
//!   `ssh <user@host:port | host:port> [command]` /
//!   `sshtunnel <ip:sshport> <agent port>` /
//!   `socks <lport> [username] [pass]` / `stopsocks` /
//!   `forward <lport> <ip:port>` / `stopforward [idx]` /
//!   `backward <rport> <lport>` / `stopbackward [idx]` /
//!   `upload <local> <remote>` / `download <remote> [local]` /
//!   `shutdown` / `help` / `back` / `exit`
//!
//! 本模块**不依赖 ratatui**，`--no-default-features` 下也可编译。

use core::fmt;

use thiserror::Error;

/// 当前所在面板。
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum Panel {
    /// 主面板（admin 视角：节点列表 + 拓扑）。
    #[default]
    Main,
    /// 节点面板（单节点视角）。
    Node,
}

impl Panel {
    /// 面板名（日志 / 提示用）。
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Node => "node",
        }
    }

    /// 输入行提示符前缀。主面板 `>> `，节点面板由调用方拼上 `(node <id>) `。
    #[must_use]
    pub const fn prompt_prefix(self) -> &'static str {
        match self {
            Self::Main => "(admin) >> ",
            Self::Node => ">> ",
        }
    }
}

/// 解析后的一条命令。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `use <node>`：进入节点面板。参数是用户敲的节点编号（v1 的 UUIDNum）。
    Use(String),
    /// `detail`：打印全部节点详情。
    Detail,
    /// `topo`：打印拓扑。
    Topo,
    /// `help`：打印当前面板帮助。
    Help,
    /// `exit`：退出控制台（二次确认）。
    Exit,
    /// `status`：当前节点状态（socks / forward / backward 的 refcount）。
    Status,
    /// `addmemo <note>`：给当前节点加备注（参数是整行剩余内容）。
    AddMemo(String),
    /// `delmemo <idx>`：删备注。
    DelMemo(u32),
    /// `shell`：在 agent 上开交互 shell。
    Shell,
    /// `listen [ip:]<port>`：在 agent 上监听。
    Listen(String),
    /// `connect <addr>`：让 agent 主动连一个新节点。
    Connect(String),
    /// `ssh <user@host:port | host:port> [command]`：经 agent 起 ssh。
    Ssh {
        /// `host:port` 或 `user@host:port`。
        target: String,
        /// 非交互式 ssh 时直接执行的命令。
        command: Option<String>,
    },
    /// `sshtunnel <ip:sshport> <agent port>`：经 ssh 隧道把节点挂进拓扑。
    SshTunnel {
        /// ssh 侧的 `host:port`。
        ssh: String,
        /// agent 侧端口。
        agent_port: u16,
    },
    /// `socks <lport> [username] [pass]`：起 socks5，可选用户名口令。
    Socks {
        /// 本地监听端口。
        port: u16,
        /// 用户名。
        user: Option<String>,
        /// 口令。
        pass: Option<String>,
    },
    /// `stopsocks`：停掉全部 socks 服务。
    StopSocks,
    /// `forward <lport> <ip:port>`：本地端口转发到远端的 `ip:port`。
    Forward {
        /// 本地监听端口。
        local_port: u16,
        /// 远端目标 `ip:port`。
        target: String,
    },
    /// `stopforward [idx]`：停转发，可只停一条。
    StopForward(Option<u32>),
    /// `backward <rport> <lport>`：agent 侧远端口回流到 admin 本地端口。
    Backward {
        /// agent 侧（远端）端口。
        remote_port: u16,
        /// admin 侧（本地）端口。
        local_port: u16,
    },
    /// `stopbackward [idx]`：停回流，可只停一条。
    StopBackward(Option<u32>),
    /// `upload <local> <remote>`：传文件到 agent。
    Upload {
        /// 本地路径。
        local: String,
        /// 远端路径。
        remote: String,
    },
    /// `download <remote> [local]`：从 agent 取文件。
    Download {
        /// 远端路径。
        remote: String,
        /// 本地路径（缺省用远端文件的 base name）。
        local: Option<String>,
    },
    /// `shutdown`：关掉当前节点（二次确认）。
    Shutdown,
    /// `back`：回到主面板。
    Back,
}

impl Command {
    /// 是否必须在节点面板执行（即需要先 `use <node>` 选中一个节点）。
    ///
    /// 主面板那 5 条命令返回 `false`，其余返回 `true`。
    #[must_use]
    pub const fn requires_node(&self) -> bool {
        !matches!(
            self,
            Self::Use(_) | Self::Detail | Self::Topo | Self::Help | Self::Exit
        )
    }

    /// 是否需要二次确认（v1 里这些命令都先问 y/n）。
    #[must_use]
    pub const fn is_destructive(&self) -> bool {
        matches!(
            self,
            Self::StopSocks
                | Self::StopForward(_)
                | Self::StopBackward(_)
                | Self::Shutdown
                | Self::Exit
        )
    }

    /// 命令名（日志 / 历史用）。
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Use(_) => "use",
            Self::Detail => "detail",
            Self::Topo => "topo",
            Self::Help => "help",
            Self::Exit => "exit",
            Self::Status => "status",
            Self::AddMemo(_) => "addmemo",
            Self::DelMemo(_) => "delmemo",
            Self::Shell => "shell",
            Self::Listen(_) => "listen",
            Self::Connect(_) => "connect",
            Self::Ssh { .. } => "ssh",
            Self::SshTunnel { .. } => "sshtunnel",
            Self::Socks { .. } => "socks",
            Self::StopSocks => "stopsocks",
            Self::Forward { .. } => "forward",
            Self::StopForward(_) => "stopforward",
            Self::Backward { .. } => "backward",
            Self::StopBackward(_) => "stopbackward",
            Self::Upload { .. } => "upload",
            Self::Download { .. } => "download",
            Self::Shutdown => "shutdown",
            Self::Back => "back",
        }
    }

    /// 二次确认提示里展示的动作描述。
    #[must_use]
    pub const fn confirm_prompt(&self) -> &'static str {
        match self {
            Self::StopSocks => "Stop all socks services",
            Self::StopForward(_) => "Stop port forwarding",
            Self::StopBackward(_) => "Stop backward forwarding",
            Self::Shutdown => "Terminate current node",
            Self::Exit => "Exit Stowaway",
            _ => "",
        }
    }
}

/// 解析错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// 空白行（无任何 token）。
    #[error("空命令：请输入命令，或键入 help 查看帮助")]
    Empty,

    /// 未知命令。
    #[error("未知命令 `{name}`（{panel} 面板），键入 help 查看帮助")]
    UnknownCommand {
        /// 用户敲的第一个 token。
        name: String,
        /// 当前面板名。
        panel: &'static str,
    },

    /// 参数个数不对。
    #[error("命令 `{cmd}` 参数个数不对：需要 {expected}，实际 {got}。用法：{usage}")]
    WrongArgCount {
        /// 命令名。
        cmd: &'static str,
        /// 期望的参数个数（不含命令名本身）。
        expected: &'static str,
        /// 实际给的参数个数。
        got: usize,
        /// 该命令的用法串。
        usage: &'static str,
    },

    /// 端口写了非数字。
    #[error("参数 `{arg}` 不是合法端口：`{value}`（应为 0-65535 的整数）")]
    PortNotANumber {
        /// 出错的位置，如 `lport` / `port` / `agent port`。
        arg: &'static str,
        /// 用户原样输入的串。
        value: String,
    },

    /// 端口超出 0-65535。
    #[error("参数 `{arg}` 超出端口范围：`{value}`（应为 0-65535）")]
    PortOutOfRange {
        /// 出错的位置。
        arg: &'static str,
        /// 用户原样输入的串。
        value: String,
    },

    /// 编号（备注下标 / 条目下标）不是数字。
    #[error("参数 `{arg}` 不是合法编号：`{value}`（应为非负整数）")]
    NotANumber {
        /// 出错的位置，如 `idx`。
        arg: &'static str,
        /// 用户原样输入的串。
        value: String,
    },

    /// 地址不是 `host:port` 形式。
    #[error("参数 `{arg}` 地址格式不对：`{value}`（应为 {expected}）")]
    BadAddress {
        /// 出错的位置，如 `addr` / `target`。
        arg: &'static str,
        /// 用户原样输入的串。
        value: String,
        /// 期望的形式。
        expected: &'static str,
    },
}

/// 每类命令的用法串（错误信息与 `help` 复用）。
const USAGE_USE: &str = "use <node>";
const USAGE_DETAIL: &str = "detail";
const USAGE_TOPO: &str = "topo";
const USAGE_HELP: &str = "help";
const USAGE_EXIT: &str = "exit";
const USAGE_STATUS: &str = "status";
const USAGE_ADDMEMO: &str = "addmemo <note>";
const USAGE_DELMEMO: &str = "delmemo <idx>";
const USAGE_SHELL: &str = "shell";
const USAGE_LISTEN: &str = "listen [ip:]<port>";
const USAGE_CONNECT: &str = "connect <ip:port>";
const USAGE_SSH: &str = "ssh <user@host:port | host:port> [command]";
const USAGE_SSHTUNNEL: &str = "sshtunnel <ip:sshport> <agent port>";
const USAGE_SOCKS: &str = "socks <lport> [username] [pass]";
const USAGE_STOPSOCKS: &str = "stopsocks";
const USAGE_FORWARD: &str = "forward <lport> <ip:port>";
const USAGE_STOPFORWARD: &str = "stopforward [idx]";
const USAGE_BACKWARD: &str = "backward <rport> <lport>";
const USAGE_STOPBACKWARD: &str = "stopbackward [idx]";
const USAGE_UPLOAD: &str = "upload <local filename> <remote filename>";
const USAGE_DOWNLOAD: &str = "download <remote filename> [local filename]";
const USAGE_SHUTDOWN: &str = "shutdown";
const USAGE_BACK: &str = "back";

/// 主面板命令名（顺序即帮助里的顺序）。
const MAIN_COMMANDS: [&str; 5] = ["use", "detail", "topo", "help", "exit"];

/// 节点面板命令名（顺序即帮助里的顺序）。
const NODE_COMMANDS: [&str; 20] = [
    "status",
    "addmemo",
    "delmemo",
    "shell",
    "listen",
    "connect",
    "ssh",
    "sshtunnel",
    "socks",
    "stopsocks",
    "forward",
    "stopforward",
    "backward",
    "stopbackward",
    "upload",
    "download",
    "shutdown",
    "help",
    "back",
    "exit",
];

/// 某面板可用的命令名全集（Tab 补全 / 帮助用）。
#[must_use]
pub const fn command_names(panel: Panel) -> &'static [&'static str] {
    match panel {
        Panel::Main => &MAIN_COMMANDS,
        Panel::Node => &NODE_COMMANDS,
    }
}

/// 逐行帮助文本。
#[must_use]
pub const fn help_lines(panel: Panel) -> &'static [&'static str] {
    match panel {
        Panel::Main => &[
            "use <node>      Enter the node panel",
            "detail          Display connected nodes' detail",
            "topo            Display the topology",
            "help            Show this help",
            "exit            Exit Stowaway",
        ],
        Panel::Node => &[
            "status                                  Show node status,including socks/forward/backward",
            "addmemo <note>                          Add a memo to current node",
            "delmemo <idx>                           Delete a memo of current node",
            "shell                                   Start a shell on current node",
            "listen [ip:]<port>                      Start port listening on current node",
            "connect <ip:port>                       Connect to a new node",
            "ssh <user@host:port | host:port> [cmd]  Start SSH through current node",
            "sshtunnel <ip:sshport> <agent port>     Use sshtunnel to add the node into our topology",
            "socks <lport> [username] [pass]         Start a socks5 server",
            "stopsocks                               Shut down socks services",
            "forward <lport> <ip:port>               Forward local port to specific remote ip:port",
            "stopforward [idx]                       Shut down forward services",
            "backward <rport> <lport>                Backward remote port(agent) to local port(admin)",
            "stopbackward [idx]                      Shut down backward services",
            "upload <local filename> <remote filename>   Upload file to current node",
            "download <remote filename> [local filename] Download file from current node",
            "shutdown                                Terminate current node",
            "help                                    Show this help",
            "back                                    Back to main panel",
            "exit                                    Exit Stowaway",
        ],
    }
}

/// 解析一行输入。
///
/// - 空行 → [`ParseError::Empty`]
/// - 命令不属于当前面板 → [`ParseError::UnknownCommand`]
/// - 参数个数 / 端口 / 地址不合法 → 对应的 [`ParseError`] 变体
pub fn parse(panel: Panel, line: &str) -> Result<Command, ParseError> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let Some((cmd, args)) = tokens.split_first() else {
        return Err(ParseError::Empty);
    };
    let cmd = *cmd;

    match panel {
        Panel::Main => parse_main(cmd, args),
        Panel::Node => parse_node(cmd, args),
    }
}

fn parse_main(cmd: &str, args: &[&str]) -> Result<Command, ParseError> {
    match cmd {
        "use" => {
            expect(USAGE_USE, "use", args, 1, 1)?;
            Ok(Command::Use(args[0].to_owned()))
        }
        "detail" => {
            expect(USAGE_DETAIL, "detail", args, 0, 0)?;
            Ok(Command::Detail)
        }
        "topo" => {
            expect(USAGE_TOPO, "topo", args, 0, 0)?;
            Ok(Command::Topo)
        }
        "help" => {
            expect(USAGE_HELP, "help", args, 0, 0)?;
            Ok(Command::Help)
        }
        "exit" => {
            expect(USAGE_EXIT, "exit", args, 0, 0)?;
            Ok(Command::Exit)
        }
        other => Err(ParseError::UnknownCommand {
            name: other.to_owned(),
            panel: Panel::Main.label(),
        }),
    }
}

fn parse_node(cmd: &str, args: &[&str]) -> Result<Command, ParseError> {
    match cmd {
        "status" => {
            expect(USAGE_STATUS, "status", args, 0, 0)?;
            Ok(Command::Status)
        }
        "addmemo" => {
            expect(USAGE_ADDMEMO, "addmemo", args, 1, usize::MAX)?;
            Ok(Command::AddMemo(args.join(" ")))
        }
        "delmemo" => {
            expect(USAGE_DELMEMO, "delmemo", args, 1, 1)?;
            Ok(Command::DelMemo(parse_index("idx", args[0])?))
        }
        "shell" => {
            expect(USAGE_SHELL, "shell", args, 0, 0)?;
            Ok(Command::Shell)
        }
        "listen" => {
            expect(USAGE_LISTEN, "listen", args, 1, 1)?;
            // `listen [ip:]<port>`：允许只给端口，或 ip:port。
            validate_listen_addr(args[0])?;
            Ok(Command::Listen(args[0].to_owned()))
        }
        "connect" => {
            expect(USAGE_CONNECT, "connect", args, 1, 1)?;
            validate_host_port("addr", args[0])?;
            Ok(Command::Connect(args[0].to_owned()))
        }
        "ssh" => {
            expect(USAGE_SSH, "ssh", args, 1, usize::MAX)?;
            validate_ssh_target("target", args[0])?;
            let command = if args.len() > 1 {
                Some(args[1..].join(" "))
            } else {
                None
            };
            Ok(Command::Ssh {
                target: args[0].to_owned(),
                command,
            })
        }
        "sshtunnel" => {
            expect(USAGE_SSHTUNNEL, "sshtunnel", args, 2, 2)?;
            validate_host_port("ip:sshport", args[0])?;
            Ok(Command::SshTunnel {
                ssh: args[0].to_owned(),
                agent_port: parse_port("agent port", args[1])?,
            })
        }
        "socks" => {
            // 2 参（只给端口）或 4 参（端口 + 用户名 + 口令）。
            if args.len() != 1 && args.len() != 3 {
                return Err(ParseError::WrongArgCount {
                    cmd: "socks",
                    expected: "1 或 3",
                    got: args.len(),
                    usage: USAGE_SOCKS,
                });
            }
            let port = parse_port("lport", args[0])?;
            let (user, pass) = if args.len() == 3 {
                (Some(args[1].to_owned()), Some(args[2].to_owned()))
            } else {
                (None, None)
            };
            Ok(Command::Socks { port, user, pass })
        }
        "stopsocks" => {
            expect(USAGE_STOPSOCKS, "stopsocks", args, 0, 0)?;
            Ok(Command::StopSocks)
        }
        "forward" => {
            expect(USAGE_FORWARD, "forward", args, 2, 2)?;
            let local_port = parse_port("lport", args[0])?;
            validate_host_port("ip:port", args[1])?;
            Ok(Command::Forward {
                local_port,
                target: args[1].to_owned(),
            })
        }
        "stopforward" => {
            expect(USAGE_STOPFORWARD, "stopforward", args, 0, 1)?;
            let idx = match args.first() {
                Some(raw) => Some(parse_index("idx", raw)?),
                None => None,
            };
            Ok(Command::StopForward(idx))
        }
        "backward" => {
            expect(USAGE_BACKWARD, "backward", args, 2, 2)?;
            let remote_port = parse_port("rport", args[0])?;
            let local_port = parse_port("lport", args[1])?;
            Ok(Command::Backward {
                remote_port,
                local_port,
            })
        }
        "stopbackward" => {
            expect(USAGE_STOPBACKWARD, "stopbackward", args, 0, 1)?;
            let idx = match args.first() {
                Some(raw) => Some(parse_index("idx", raw)?),
                None => None,
            };
            Ok(Command::StopBackward(idx))
        }
        "upload" => {
            expect(USAGE_UPLOAD, "upload", args, 2, 2)?;
            Ok(Command::Upload {
                local: args[0].to_owned(),
                remote: args[1].to_owned(),
            })
        }
        "download" => {
            expect(USAGE_DOWNLOAD, "download", args, 1, 2)?;
            Ok(Command::Download {
                remote: args[0].to_owned(),
                local: args.get(1).map(|s| (*s).to_owned()),
            })
        }
        "shutdown" => {
            expect(USAGE_SHUTDOWN, "shutdown", args, 0, 0)?;
            Ok(Command::Shutdown)
        }
        "help" => {
            expect(USAGE_HELP, "help", args, 0, 0)?;
            Ok(Command::Help)
        }
        "back" => {
            expect(USAGE_BACK, "back", args, 0, 0)?;
            Ok(Command::Back)
        }
        "exit" => {
            expect(USAGE_EXIT, "exit", args, 0, 0)?;
            Ok(Command::Exit)
        }
        other => Err(ParseError::UnknownCommand {
            name: other.to_owned(),
            panel: Panel::Node.label(),
        }),
    }
}

/// 参数个数校验。`max` 取 [`usize::MAX`] 表示「至少 `min` 个」。
fn expect(
    usage: &'static str,
    cmd: &'static str,
    args: &[&str],
    min: usize,
    max: usize,
) -> Result<(), ParseError> {
    let got = args.len();
    let ok = got >= min && got <= max;
    if ok {
        return Ok(());
    }
    let expected: &'static str = match (min, max) {
        (a, b) if a == b && a == 0 => "0",
        (a, b) if a == b && a == 1 => "1",
        (a, b) if a == b && a == 2 => "2",
        (a, b) if a == b && a == 3 => "3",
        (_, usize::MAX) => "至少 1",
        (0, 1) => "0 或 1",
        (1, 2) => "1 或 2",
        _ => "至少 1",
    };
    Err(ParseError::WrongArgCount {
        cmd,
        expected,
        got,
        usage,
    })
}

/// 端口解析：0-65535。非数字与越界分别报不同错误。
fn parse_port(arg: &'static str, value: &str) -> Result<u16, ParseError> {
    match value.parse::<u16>() {
        Ok(port) => Ok(port),
        Err(_) if value.bytes().all(|b| b.is_ascii_digit()) && !value.is_empty() => {
            Err(ParseError::PortOutOfRange {
                arg,
                value: value.to_owned(),
            })
        }
        Err(_) => Err(ParseError::PortNotANumber {
            arg,
            value: value.to_owned(),
        }),
    }
}

/// 编号解析（备注下标 / 条目下标）。
fn parse_index(arg: &'static str, value: &str) -> Result<u32, ParseError> {
    value.parse::<u32>().map_err(|_| ParseError::NotANumber {
        arg,
        value: value.to_owned(),
    })
}

/// 校验 `host:port`。`host` 非空、端口 0-65535。
fn validate_host_port(arg: &'static str, value: &str) -> Result<(), ParseError> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(ParseError::BadAddress {
            arg,
            value: value.to_owned(),
            expected: "host:port",
        });
    };
    if host.is_empty() {
        return Err(ParseError::BadAddress {
            arg,
            value: value.to_owned(),
            expected: "host:port",
        });
    }
    // 端口不合法时优先报端口错误，信息更具体。
    parse_port(arg, port)?;
    Ok(())
}

/// 校验 ssh 目标：`host:port` 或 `user@host:port`。
fn validate_ssh_target(arg: &'static str, value: &str) -> Result<(), ParseError> {
    let host_port = match value.rsplit_once('@') {
        Some((user, rest)) => {
            if user.is_empty() {
                return Err(ParseError::BadAddress {
                    arg,
                    value: value.to_owned(),
                    expected: "user@host:port 或 host:port",
                });
            }
            rest
        }
        None => value,
    };
    validate_host_port(arg, host_port)
}

/// 校验 `listen` 的 `[ip:]<port>`。
fn validate_listen_addr(value: &str) -> Result<(), ParseError> {
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.is_empty() {
            return Err(ParseError::BadAddress {
                arg: "addr",
                value: value.to_owned(),
                expected: "[ip:]<port>",
            });
        }
        parse_port("addr", port)?;
        return Ok(());
    }
    parse_port("addr", value)?;
    Ok(())
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn main_ok(line: &str) -> Command {
        parse(Panel::Main, line).expect("主面板命令应能解析")
    }

    fn node_ok(line: &str) -> Command {
        parse(Panel::Node, line).expect("节点面板命令应能解析")
    }

    #[test]
    fn parse_all_five_main_panel_commands() {
        assert_eq!(main_ok("use 3"), Command::Use("3".to_owned()));
        assert_eq!(main_ok("detail"), Command::Detail);
        assert_eq!(main_ok("topo"), Command::Topo);
        assert_eq!(main_ok("help"), Command::Help);
        assert_eq!(main_ok("exit"), Command::Exit);
        // 多余空白不影响解析。
        assert_eq!(main_ok("  use   42  "), Command::Use("42".to_owned()));
    }

    #[test]
    fn parse_all_twenty_node_panel_commands() {
        assert_eq!(node_ok("status"), Command::Status);
        assert_eq!(
            node_ok("addmemo hello world"),
            Command::AddMemo("hello world".to_owned())
        );
        assert_eq!(node_ok("delmemo 7"), Command::DelMemo(7));
        assert_eq!(node_ok("shell"), Command::Shell);
        assert_eq!(node_ok("listen 8080"), Command::Listen("8080".to_owned()));
        assert_eq!(
            node_ok("connect 10.0.0.1:1080"),
            Command::Connect("10.0.0.1:1080".to_owned())
        );
        assert_eq!(
            node_ok("ssh root@10.0.0.1:22"),
            Command::Ssh {
                target: "root@10.0.0.1:22".to_owned(),
                command: None,
            }
        );
        assert_eq!(
            node_ok("sshtunnel 10.0.0.1:22 9000"),
            Command::SshTunnel {
                ssh: "10.0.0.1:22".to_owned(),
                agent_port: 9000,
            }
        );
        assert_eq!(
            node_ok("socks 1080"),
            Command::Socks {
                port: 1080,
                user: None,
                pass: None,
            }
        );
        assert_eq!(node_ok("stopsocks"), Command::StopSocks);
        assert_eq!(
            node_ok("forward 8080 10.0.0.1:80"),
            Command::Forward {
                local_port: 8080,
                target: "10.0.0.1:80".to_owned(),
            }
        );
        assert_eq!(node_ok("stopforward"), Command::StopForward(None));
        assert_eq!(
            node_ok("backward 9000 8080"),
            Command::Backward {
                remote_port: 9000,
                local_port: 8080,
            }
        );
        assert_eq!(node_ok("stopbackward"), Command::StopBackward(None));
        assert_eq!(
            node_ok("upload /tmp/a.bin /root/a.bin"),
            Command::Upload {
                local: "/tmp/a.bin".to_owned(),
                remote: "/root/a.bin".to_owned(),
            }
        );
        assert_eq!(
            node_ok("download /root/a.bin"),
            Command::Download {
                remote: "/root/a.bin".to_owned(),
                local: None,
            }
        );
        assert_eq!(node_ok("download /root/a.bin ./a.bin"), {
            Command::Download {
                remote: "/root/a.bin".to_owned(),
                local: Some("./a.bin".to_owned()),
            }
        });
        assert_eq!(node_ok("shutdown"), Command::Shutdown);
        assert_eq!(node_ok("help"), Command::Help);
        assert_eq!(node_ok("back"), Command::Back);
        assert_eq!(node_ok("exit"), Command::Exit);
    }

    #[test]
    fn missing_arguments_are_rejected_with_usage() {
        for line in ["use", "connect", "listen", "ssh", "delmemo", "upload"] {
            let err = parse(Panel::Main, line).unwrap_err();
            // 主面板对节点命令报「未知命令」，因此这里逐面板取正确的错误。
            if matches!(err, ParseError::UnknownCommand { .. }) {
                let err_node = parse(Panel::Node, line).unwrap_err();
                assert!(
                    matches!(err_node, ParseError::WrongArgCount { .. }),
                    "{line} 应报参数个数错误，实际 {err_node:?}"
                );
            } else {
                assert!(
                    matches!(err, ParseError::WrongArgCount { .. }),
                    "{line} 应报参数个数错误，实际 {err:?}"
                );
            }
        }
        // 具体字段：usage 串要带上，便于直接提示用户。
        match parse(Panel::Node, "connect").unwrap_err() {
            ParseError::WrongArgCount {
                cmd, got, usage, ..
            } => {
                assert_eq!(cmd, "connect");
                assert_eq!(got, 0);
                assert!(usage.contains("connect"));
            }
            other => panic!("期望 WrongArgCount，实际 {other:?}"),
        }
    }

    #[test]
    fn extra_arguments_are_rejected_for_no_arg_commands() {
        for line in [
            "detail",
            "topo",
            "help",
            "exit",
            "status",
            "shell",
            "stopsocks",
        ] {
            let panel = if matches!(line, "status" | "shell" | "stopsocks") {
                Panel::Node
            } else {
                Panel::Main
            };
            let err = parse(panel, &format!("{line} extra")).unwrap_err();
            assert!(
                matches!(err, ParseError::WrongArgCount { .. }),
                "{line} extra 应报参数个数错误，实际 {err:?}"
            );
        }
        // shutdown 也是零参数。
        assert!(matches!(
            parse(Panel::Node, "shutdown now").unwrap_err(),
            ParseError::WrongArgCount { .. }
        ));
    }

    #[test]
    fn port_out_of_range_is_rejected() {
        for (line, arg) in [
            ("socks 70000", "lport"),
            ("forward 70000 10.0.0.1:80", "lport"),
            ("backward 70000 80", "rport"),
            ("backward 80 70000", "lport"),
            ("sshtunnel 10.0.0.1:22 70000", "agent port"),
            ("listen 99999", "addr"),
        ] {
            match parse(Panel::Node, line).unwrap_err() {
                ParseError::PortOutOfRange { arg: got, value } => {
                    assert_eq!(got, arg, "{line} 的出错参数名");
                    assert!(!value.is_empty());
                }
                other => panic!("{line} 应报端口越界，实际 {other:?}"),
            }
        }
    }

    #[test]
    fn port_not_a_number_is_rejected() {
        match parse(Panel::Node, "socks abc").unwrap_err() {
            ParseError::PortNotANumber { arg, value } => {
                assert_eq!(arg, "lport");
                assert_eq!(value, "abc");
            }
            other => panic!("期望 PortNotANumber，实际 {other:?}"),
        }
        assert!(matches!(
            parse(Panel::Node, "forward -1 10.0.0.1:80").unwrap_err(),
            ParseError::PortNotANumber { .. }
        ));
    }

    #[test]
    fn bad_address_is_rejected() {
        for line in [
            "connect 10.0.0.1",
            "connect :80",
            "connect 10.0.0.1:abc",
            "forward 8080 10.0.0.1",
            "listen 1.2.3.4:",
            "ssh host-without-port",
        ] {
            let err = parse(Panel::Node, line).unwrap_err();
            assert!(
                matches!(
                    err,
                    ParseError::BadAddress { .. } | ParseError::PortNotANumber { .. }
                ),
                "{line} 应报地址/端口格式错误，实际 {err:?}"
            );
        }
        // 地址格式错误要指出是哪个参数。
        match parse(Panel::Node, "forward 8080 nope").unwrap_err() {
            ParseError::BadAddress { arg, expected, .. } => {
                assert_eq!(arg, "ip:port");
                assert_eq!(expected, "host:port");
            }
            other => panic!("期望 BadAddress，实际 {other:?}"),
        }
        // user 为空的 ssh 目标也算格式错误。
        assert!(matches!(
            parse(Panel::Node, "ssh @10.0.0.1:22").unwrap_err(),
            ParseError::BadAddress { .. }
        ));
    }

    #[test]
    fn unknown_command_is_rejected() {
        match parse(Panel::Main, "frobnicate").unwrap_err() {
            ParseError::UnknownCommand { name, panel } => {
                assert_eq!(name, "frobnicate");
                assert_eq!(panel, "main");
            }
            other => panic!("期望 UnknownCommand，实际 {other:?}"),
        }
        // 节点命令在主面板不合法（反之亦然）。
        assert!(matches!(
            parse(Panel::Main, "socks").unwrap_err(),
            ParseError::UnknownCommand { .. }
        ));
        assert!(matches!(
            parse(Panel::Node, "topo").unwrap_err(),
            ParseError::UnknownCommand { .. }
        ));
        // 大小写敏感，与 v1 一致。
        assert!(matches!(
            parse(Panel::Main, "Use 1").unwrap_err(),
            ParseError::UnknownCommand { .. }
        ));
    }

    #[test]
    fn blank_line_is_rejected() {
        for line in ["", "   ", "\t", " \t \n"] {
            assert_eq!(parse(Panel::Main, line).unwrap_err(), ParseError::Empty);
            assert_eq!(parse(Panel::Node, line).unwrap_err(), ParseError::Empty);
        }
    }

    #[test]
    fn socks_accepts_two_and_four_tokens() {
        // 2 token：`socks <lport>`
        assert_eq!(
            node_ok("socks 1080"),
            Command::Socks {
                port: 1080,
                user: None,
                pass: None,
            }
        );
        // 4 token：`socks <lport> <username> <pass>`
        assert_eq!(
            node_ok("socks 1080 alice s3cret"),
            Command::Socks {
                port: 1080,
                user: Some("alice".to_owned()),
                pass: Some("s3cret".to_owned()),
            }
        );
        // 3 token（只给用户名）非法，与 v1 的 `[username] [pass]` 一致。
        assert!(matches!(
            parse(Panel::Node, "socks 1080 alice").unwrap_err(),
            ParseError::WrongArgCount { .. }
        ));
        // 5 token 也非法。
        assert!(matches!(
            parse(Panel::Node, "socks 1080 a b c").unwrap_err(),
            ParseError::WrongArgCount { .. }
        ));
    }

    #[test]
    fn ssh_with_and_without_command() {
        assert_eq!(
            node_ok("ssh 10.0.0.1:22"),
            Command::Ssh {
                target: "10.0.0.1:22".to_owned(),
                command: None,
            }
        );
        assert_eq!(
            node_ok("ssh alice@10.0.0.1:2222 uptime -p"),
            Command::Ssh {
                target: "alice@10.0.0.1:2222".to_owned(),
                command: Some("uptime -p".to_owned()),
            }
        );
        assert_eq!(
            node_ok("ssh root@10.0.0.1:22 ls"),
            Command::Ssh {
                target: "root@10.0.0.1:22".to_owned(),
                command: Some("ls".to_owned()),
            }
        );
    }

    #[test]
    fn forward_and_backward_keep_there_directions() {
        // forward：本地端口在前，远端 ip:port 在后。
        assert_eq!(
            node_ok("forward 8080 10.0.0.5:80"),
            Command::Forward {
                local_port: 8080,
                target: "10.0.0.5:80".to_owned(),
            }
        );
        // backward：远端（agent）端口在前，本地（admin）端口在后。
        assert_eq!(
            node_ok("backward 9000 8080"),
            Command::Backward {
                remote_port: 9000,
                local_port: 8080,
            }
        );
        // 两者不能混淆：forward 的第二个参数必须是 ip:port。
        assert!(matches!(
            parse(Panel::Node, "forward 8080 9090").unwrap_err(),
            ParseError::BadAddress { .. }
        ));
        // backward 两个参数都必须是端口。
        assert!(matches!(
            parse(Panel::Node, "backward 10.0.0.1:9000 8080").unwrap_err(),
            ParseError::PortNotANumber { .. }
        ));
    }

    #[test]
    fn stop_commands_take_optional_index() {
        assert_eq!(node_ok("stopforward 2"), Command::StopForward(Some(2)));
        assert_eq!(node_ok("stopbackward 0"), Command::StopBackward(Some(0)));
        // 下标必须是数字。
        assert!(matches!(
            parse(Panel::Node, "stopforward x").unwrap_err(),
            ParseError::NotANumber { .. }
        ));
        assert!(matches!(
            parse(Panel::Node, "stopbackward -1").unwrap_err(),
            ParseError::NotANumber { .. }
        ));
    }

    #[test]
    fn requires_node_flags() {
        for cmd in [
            Command::Use("1".to_owned()),
            Command::Detail,
            Command::Topo,
            Command::Help,
            Command::Exit,
        ] {
            assert!(!cmd.requires_node(), "{cmd:?} 不应要求节点");
        }
        for cmd in [
            Command::Status,
            Command::AddMemo("m".to_owned()),
            Command::DelMemo(0),
            Command::Shell,
            Command::Listen("8080".to_owned()),
            Command::Connect("1.2.3.4:5".to_owned()),
            Command::Ssh {
                target: "h:1".to_owned(),
                command: None,
            },
            Command::SshTunnel {
                ssh: "h:1".to_owned(),
                agent_port: 1,
            },
            Command::Socks {
                port: 1,
                user: None,
                pass: None,
            },
            Command::StopSocks,
            Command::Forward {
                local_port: 1,
                target: "h:1".to_owned(),
            },
            Command::StopForward(None),
            Command::Backward {
                remote_port: 1,
                local_port: 2,
            },
            Command::StopBackward(None),
            Command::Upload {
                local: "a".to_owned(),
                remote: "b".to_owned(),
            },
            Command::Download {
                remote: "a".to_owned(),
                local: None,
            },
            Command::Shutdown,
            Command::Back,
        ] {
            assert!(cmd.requires_node(), "{cmd:?} 应要求节点");
        }
    }

    #[test]
    fn destructive_commands_need_confirmation() {
        for cmd in [
            Command::StopSocks,
            Command::StopForward(None),
            Command::StopForward(Some(1)),
            Command::StopBackward(None),
            Command::Shutdown,
            Command::Exit,
        ] {
            assert!(cmd.is_destructive(), "{cmd:?} 应需要二次确认");
            assert!(!cmd.confirm_prompt().is_empty());
        }
        for cmd in [
            Command::Detail,
            Command::Status,
            Command::Shell,
            Command::Back,
            Command::Topo,
        ] {
            assert!(!cmd.is_destructive(), "{cmd:?} 不应需要二次确认");
        }
    }

    #[test]
    fn command_names_cover_help_lines() {
        assert_eq!(command_names(Panel::Main).len(), 5);
        assert_eq!(command_names(Panel::Node).len(), 20);
        // 23 个不同的命令 token（help/exit 两个面板共用）。
        let mut all: Vec<&str> = command_names(Panel::Main)
            .iter()
            .chain(command_names(Panel::Node).iter())
            .copied()
            .collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 23);
        // 每条帮助行都以可用命令名开头。
        for line in help_lines(Panel::Node) {
            let name = line.split_whitespace().next().unwrap_or_default();
            assert!(
                command_names(Panel::Node).contains(&name),
                "帮助行 `{line}` 的命令名 `{name}` 不在命令表里"
            );
        }
        for line in help_lines(Panel::Main) {
            let name = line.split_whitespace().next().unwrap_or_default();
            assert!(command_names(Panel::Main).contains(&name));
        }
    }

    #[test]
    fn panel_helpers() {
        assert_eq!(Panel::default(), Panel::Main);
        assert_eq!(Panel::Main.label(), "main");
        assert_eq!(Panel::Node.label(), "node");
        assert_eq!(Panel::Main.prompt_prefix(), "(admin) >> ");
        assert_eq!(Panel::Node.prompt_prefix(), ">> ");
    }
}
