//! 控制台命令执行层：把 [`Command`] 变成真实的网络动作。
//!
//! 权威：`docs/plan.md` §4.10（命令面）、§4.14 E17–E21（服务种类与「探测」和
//! 「执行」的差别）。
//!
//! # 这一层负责什么
//!
//! 解析层（[`crate::command`]）只把字符串变成枚举，渲染层（[`crate::render`]）
//! 只管画。**真发包**的地方只有这里：快照、备注、会话、服务请求、本地监听。
//! 因此本模块不依赖 ratatui，`--no-default-features` 下同样可用。
//!
//! # 三条硬约定
//!
//! 1. **不静默成功**。尚未接通的命令（`listen`、`backward` 的远端侧、
//!    文件上传/下载）必须回一行明确的「没做，因为什么」，而不是打一条
//!    「ok」。探测说「可以」而执行说「没做」必须让调用方看得见
//!    （plan §4.14 E20）。
//! 2. **等对端答复一律带超时**。引擎事件流由 [`Console`] 独占，需要
//!    `SessionReady` / `ServiceReply` 时先 `try_recv` 排空，再 `recv`，
//!    并且整段包在 `tokio::time::timeout` 里——控制台不会因为对端不回
//!    而挂死。
//! 3. **本地监听统一可停**。`socks` / `forward` / `backward` 起的后台任务
//!    都登记在 `HashMap` 里，`stop*` 时 `abort` 并回一行说明；没有在跑的
//!    服务时回「没有在跑」，**不是**错误。
//!
//! # 与引擎的边界
//!
//! 引擎（[`stowaway_core::Engine`]）是唯一的网络出口：[`Console`] 只持有
//! [`EngineHandle`] 与事件接收端。[`Console::new`] 要接收 `events`
//! （引擎事件流的接收端），因为「等答复」的本质是等事件——把接收端留在
//! 外面，控制台就没法既画界面又等网络。
//!
//! 未在此模块实现的命令都会在 [`Console::execute`] 里落到 `_` 分支，
//! 返回 `Outcome::fail` 的一行说明。

#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use sha2::{Digest, Sha256};
use stowaway_core::{EngineHandle, Event, NodeIdAllocator, Snapshot, forward, socks, socks_server};
use stowaway_protocol::{
    ConnectParam, Memo, Message, NodeId, OpenSession, ServiceKind, ServiceParam, ServicePhase,
    ServiceRequest, SessionCode, SessionDirection, SessionKey, SessionKind, ShellParam, Shutdown,
    SshAuth, SshParam, SshTunnelParam,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::command::{Command, Panel};

/// 一次执行的产出。
///
/// `lines` 是给渲染层/非交互输出用的纯文本（一行一条），`keep_running`
/// 为 `false` 表示「请调用方收摊」——`exit` 与 `shutdown` 都是这个语义。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// 输出行（按顺序）。
    pub lines: Vec<String>,
    /// 是否继续跑控制台；`false` = 请求退出/关机。
    pub keep_running: bool,
}

impl Outcome {
    /// 一行输出，继续跑。
    #[must_use]
    pub fn ok(line: impl Into<String>) -> Self {
        Self {
            lines: vec![line.into()],
            keep_running: true,
        }
    }

    /// 多行输出，继续跑。
    #[must_use]
    pub fn lines(lines: Vec<String>) -> Self {
        Self {
            lines,
            keep_running: true,
        }
    }

    /// 一行输出并请求退出。
    #[must_use]
    pub fn quit(line: impl Into<String>) -> Self {
        Self {
            lines: vec![line.into()],
            keep_running: false,
        }
    }

    /// 失败提示：仍然继续跑（控制台不因一条命令失败而退出）。
    #[must_use]
    pub fn fail(line: impl Into<String>) -> Self {
        Self::ok(format!("错误：{}", line.into()))
    }

    /// 明确未实现：一行说明「没做」以及为什么。
    #[must_use]
    pub fn unimplemented(what: &str, why: &str) -> Self {
        Self::ok(format!("{what}：执行尚未接通（{why}）"))
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.lines.join("\n"))
    }
}

/// 等待对端答复的统一超时。
///
/// 与 `socks_server::READY_TIMEOUT`（15s）保持同一量级：控制台可以容忍
/// 慢网络，但不能无上限地挂着。
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// 固定端口 `0` 之外默认用的本地监听端口（v1 的默认 SOCKS5 端口）。
const DEFAULT_SOCKS_PORT: u16 = 1080;

/// 挂在本地监听上的后台任务登记表。
#[derive(Default)]
struct Running {
    /// `socks` 起的监听（按本地端口索引）。
    socks: HashMap<u16, JoinHandle<()>>,
    /// `forward` 起的监听（按本地端口索引）。
    forwards: HashMap<u16, JoinHandle<()>>,
    /// `backward` 的远端监听（按**远端**端口索引）：每条 accept 出来的
    /// 连接一个中继任务，停一条映射就 abort 这一组。
    backwards: HashMap<u16, Vec<JoinHandle<()>>>,
}

impl Running {
    /// 三个登记表都是空的（没有本地监听在跑）。
    fn is_empty(&self) -> bool {
        self.socks.is_empty() && self.forwards.is_empty() && self.backwards.is_empty()
    }
}

/// 命令执行器：一条引擎句柄 + 一份事件流 + 本地监听登记表。
///
/// 一个控制台会话只有一个 [`Console`]；它独占事件接收端，因此
/// 「画界面」和「等网络」必须经过同一个 `execute`（plan §4.10）。
pub struct Console {
    /// 引擎句柄（唯一的网络出口）。
    handle: EngineHandle,
    /// 本端编号。
    me: NodeId,
    /// 编号分配器（`listen`/`backward` 场景由本端扮父节点时用得上）。
    alloc: NodeIdAllocator,
    /// 引擎事件流：等答复时在这里取。
    events: mpsc::UnboundedReceiver<Event>,
    /// 会话序号（`EngineHandle` 没有 `allocate_session`，本层自增）。
    seq: u64,
    /// 当前选中的节点（`use` 的结果）。
    focus: Option<NodeId>,
    /// 当前面板。
    panel: Panel,
    /// 在跑的本地监听。
    running: Running,
    /// 反向映射登记表：`(请求时的会话键, 远端端口, 本端拨号目标)`。
    ///
    /// 后台任务不能碰事件流（[`Console`] 是唯一消费者），所以入站
    /// `OpenSession{Backward, Inbound}` 必须由本层的 [`Self::drain_events`]
    /// 就地转交。对端为每条 accept 出来的连接分配的键是
    /// `SessionKey::new(请求键.origin, 请求键.id + n)`，所以按「同 origin 且
    /// 请求键 id 不大于入站键 id 的最近一条」就能唯一确定属于哪条映射。
    backwards: Vec<(SessionKey, u16, String)>,
}

impl fmt::Debug for Console {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Console")
            .field("me", &self.me)
            .field("focus", &self.focus)
            .field("panel", &self.panel)
            .field("seq", &self.seq)
            .field("socks", &self.running.socks.len())
            .field("forwards", &self.running.forwards.len())
            .field("backwards", &self.running.backwards.len())
            .finish_non_exhaustive()
    }
}

impl Console {
    /// 新建执行器。
    ///
    /// `events` 必须是 [`stowaway_core::Engine`] 创建时拿到的那个接收端：
    /// 等 `SessionReady` / `ServiceReply` 只能从这里来。
    #[must_use]
    pub fn new(
        handle: EngineHandle,
        me: NodeId,
        alloc: NodeIdAllocator,
        events: mpsc::UnboundedReceiver<Event>,
    ) -> Self {
        Self {
            handle,
            me,
            alloc,
            events,
            seq: 0,
            focus: None,
            panel: Panel::Main,
            running: Running::default(),
            backwards: Vec::new(),
        }
    }

    /// 本端编号。
    #[must_use]
    pub const fn me(&self) -> NodeId {
        self.me
    }

    /// 当前面板。
    #[must_use]
    pub const fn panel(&self) -> Panel {
        self.panel
    }

    /// 当前选中的节点（未 `use` 时为 `None`）。
    #[must_use]
    pub const fn focus(&self) -> Option<NodeId> {
        self.focus
    }

    /// 在跑的本地监听数量：`(socks, forward, backward)`。
    #[must_use]
    pub fn running_counts(&self) -> (usize, usize, usize) {
        (
            self.running.socks.len(),
            self.running.forwards.len(),
            self.running.backwards.len(),
        )
    }

    /// 下一个会话键。
    ///
    /// `SessionKey::new(origin, id)` 的 `id` 从 1 起（0 保留），因此先自增。
    fn next_key(&mut self) -> SessionKey {
        self.seq = self.seq.saturating_add(1);
        SessionKey::new(self.me, self.seq)
    }

    /// 排掉当前已到达的事件，返回其中的应答类事件。
    ///
    /// 非应答事件（`Joined` / `Rtt` / `Failed` …）对命令执行没有直接用处，
    /// 但**不能丢**它们的语义（`Failed` 要变成一行提示），所以顺手筛一层。
    fn drain_events(&mut self) -> Vec<String> {
        let mut notes = Vec::new();
        while let Ok(ev) = self.events.try_recv() {
            if let Some(note) = self.route_event(&ev) {
                notes.push(note);
            }
        }
        notes
    }

    /// 非阻塞地排掉已到达事件，把每条事件的语义翻成一行可显示文本。
    ///
    /// TUI 每帧调用一次；返回 `None` 表示这一轮没有新事件（不必重画）。
    /// 与 [`Self::execute`] 共用同一个事件接收端，因此**两者不能并发**——
    /// 编排层应当在同一条 `select!` 里交替使用（plan §4.9 的 ConsoleActor）。
    pub fn tick(&mut self) -> Option<Vec<String>> {
        let notes = self.drain_events();
        if notes.is_empty() { None } else { Some(notes) }
    }

    /// 把一条事件转成提示行；需要本端动手的（反向映射入站会话）先动手。
    ///
    /// `OpenSession{Backward, Inbound}` 不能像其它事件那样只打一行了事：
    /// 对端已经 bind 好远端端口并接受了连进来的客户端，正在等本端拨本地
    /// 目标。本端不接，对端那条连接就永远挂在 `await_ready` 上。
    fn route_event(&mut self, ev: &Event) -> Option<String> {
        if let Event::SessionOpened { open, .. } = ev
            && open.kind == SessionKind::Backward
            && open.direction == SessionDirection::Inbound
        {
            return Some(self.spawn_backward_relay(open.key));
        }
        event_note(ev)
    }

    /// 为一条反向映射的入站会话起中继任务。
    ///
    /// 返回需要显示的一行。找不到对应映射时不中继——宁可让那条连接
    /// 超时关闭，也不猜一个本地端口把数据灌进去。
    fn spawn_backward_relay(&mut self, key: SessionKey) -> String {
        let target = self
            .backwards
            .iter()
            .filter(|(base, _, _)| base.origin == key.origin && base.id <= key.id)
            .max_by_key(|(base, _, _)| base.id)
            .map(|(_, port, target)| (*port, target.clone()));
        let Some((port, target)) = target else {
            return format!(
                "警告：收到反向映射会话 {}（{}），但本端没有登记远端端口",
                key.id,
                key.origin.short()
            );
        };
        let handle = self.handle.clone();
        let dial_to = target.clone();
        let task = tokio::spawn(async move {
            relay_backward_session(handle, key, dial_to).await;
        });
        self.running.backwards.entry(port).or_default().push(task);
        format!("反向映射：远端 {port} 的会话 {} 已拨 {target}", key.id)
    }

    /// 等到一个满足 `want` 的引擎事件，或超时。
    ///
    /// 期间到达的其它事件用 `event_note` 转成提示行，一起带回。
    async fn wait_event<F>(
        &mut self,
        label: &str,
        deadline: Duration,
        mut want: F,
    ) -> (Option<Event>, Vec<String>)
    where
        F: FnMut(&Event) -> bool,
    {
        let mut notes = self.drain_events();
        let fut = async {
            loop {
                match self.events.recv().await {
                    None => return None,
                    Some(ev) => {
                        if want(&ev) {
                            return Some(ev);
                        }
                        if let Some(note) = event_note(&ev) {
                            notes.push(note);
                        }
                    }
                }
            }
        };
        match timeout(deadline, fut).await {
            Ok(got) => (got, notes),
            Err(_) => {
                notes.push(format!(
                    "{label}：等待对端答复超时（{}s）",
                    deadline.as_secs()
                ));
                (None, notes)
            }
        }
    }

    /// 目标节点：优先 `focus`，否则用 `me`（单节点自测/无拓扑时）。
    fn target(&self) -> NodeId {
        self.focus.unwrap_or(self.me)
    }

    /// 执行一条命令。
    ///
    /// 任何分支都不会 panic，也不会静默成功：说不出「做了什么」时，至少
    /// 说清「没做什么、为什么」。
    ///
    /// 面板（[`Panel`]）与 `focus` 的迁移在这里维护，调用方不必再管。
    pub async fn execute(&mut self, cmd: Command) -> Outcome {
        match cmd {
            Command::Status => self.status().await,
            Command::Detail => self.detail().await,
            Command::Topo => self.topo().await,
            Command::Help => self.help(),
            Command::Use(node) => self.use_node(&node).await,
            Command::Back => self.back(),
            Command::Exit => Outcome::quit("已退出控制台"),
            Command::AddMemo(note) => self.add_memo(&note).await,
            Command::DelMemo(idx) => self.del_memo(idx).await,
            Command::Shell => self.shell().await,
            Command::Socks { port, user, pass } => self.socks(port, user, pass).await,
            Command::StopSocks => self.stop_socks(),
            Command::Forward { local_port, target } => {
                self.start_forward(local_port, &target).await
            }
            Command::StopForward(idx) => self.stop_forward(idx),
            Command::Backward {
                remote_port,
                local_port,
            } => self.backward(remote_port, local_port).await,
            Command::StopBackward(idx) => self.stop_backward(idx),
            Command::Ssh { target, command } => self.ssh(&target, command.as_deref()).await,
            Command::SshTunnel { ssh, agent_port } => self.ssh_tunnel(&ssh, agent_port).await,
            Command::Connect(addr) => self.connect(&addr).await,
            Command::Listen(spec) => self.listen(&spec).await,
            Command::Upload { local, remote } => self.upload(&local, &remote).await,
            Command::Download { remote, local } => self.download(&remote, local.as_deref()).await,
            Command::Shutdown => self.shutdown().await,
        }
    }

    // —————————————————————————————————————————————— 只读：快照与面板

    /// `status`：当前节点与其服务摘要（单节点时就是零拓扑摘要）。
    async fn status(&mut self) -> Outcome {
        let snap = match self.handle.snapshot().await {
            Ok(s) => s,
            Err(e) => return Outcome::fail(format!("取快照失败：{e}")),
        };
        let mut lines = vec![self.summary_line(&snap)];
        if snap.nodes.len() > 1 {
            lines.push(format!(
                "拓扑：{} 个节点、{} 条链路、最大深度 {}",
                snap.nodes.len(),
                snap.links.len(),
                snap.depth
            ));
        }
        let (socks, fwd, back) = self.running_counts();
        if socks + fwd + back > 0 {
            lines.push(format!(
                "本端服务：socks {socks}、forward {fwd}、backward {back}"
            ));
        }
        lines.extend(self.drain_events());
        Outcome::lines(lines)
    }

    /// 一行式的节点摘要。
    fn summary_line(&self, snap: &Snapshot) -> String {
        let me = snap.me.map_or_else(|| self.me.short(), |id| id.short());
        let root = snap.root.map_or_else(|| "-".to_owned(), |id| id.short());
        let focus = self.focus.map_or_else(|| "-".to_owned(), |id| id.short());
        format!(
            "本机 {me}｜根 {root}｜深度 {}｜节点 {}｜链路 {}｜会话 {}｜不可达 {}｜选中 {focus}",
            snap.depth,
            snap.nodes.len(),
            snap.links.len(),
            snap.sessions,
            snap.undeliverable
        )
    }

    /// `detail`：全部节点的明细。
    async fn detail(&mut self) -> Outcome {
        let snap = match self.handle.snapshot().await {
            Ok(s) => s,
            Err(e) => return Outcome::fail(format!("取快照失败：{e}")),
        };
        let mut lines = vec![format!("快照（epoch {}）：", snap.epoch)];
        if snap.nodes.is_empty() {
            lines.push("  （没有节点）".to_owned());
        }
        for info in &snap.nodes {
            lines.push(format!("  {}", node_line(info)));
        }
        lines.extend(self.drain_events());
        Outcome::lines(lines)
    }

    /// `topo`：拓扑与链路（RTT/丢包）。
    async fn topo(&mut self) -> Outcome {
        let snap = match self.handle.snapshot().await {
            Ok(s) => s,
            Err(e) => return Outcome::fail(format!("取快照失败：{e}")),
        };
        let mut lines = vec![format!("本机 {}", snap.me.unwrap_or(self.me).short())];
        for info in &snap.nodes {
            let indent = "  ".repeat(usize::from(info.depth));
            lines.push(format!("{indent}{}", node_line(info)));
        }
        if snap.links.is_empty() {
            lines.push("链路：无".to_owned());
        } else {
            lines.push(format!("链路 {} 条：", snap.links.len()));
            for link in &snap.links {
                let rtt = link
                    .rtt_ms
                    .map_or_else(|| "-".to_owned(), |ms| format!("{ms}ms"));
                lines.push(format!(
                    "  {} 类型 {:?} 父 {} 深度 {} rtt {} 丢 {}",
                    link.peer.short(),
                    link.kind,
                    link.parent.short(),
                    link.depth,
                    rtt,
                    link.missed
                ));
            }
        }
        lines.extend(self.drain_events());
        Outcome::lines(lines)
    }

    /// `help`：当前面板的帮助文本。
    fn help(&mut self) -> Outcome {
        let mut lines = vec![format!("帮助（{} 面板）：", self.panel.label())];
        lines.extend(
            crate::command::help_lines(self.panel)
                .iter()
                .map(|l| (*l).to_owned()),
        );
        self.drain_events();
        Outcome::lines(lines)
    }

    /// `use <node>`：进入节点面板。只改本地选中态，不发包。
    ///
    /// 节点编号接受 `short()` 形状（前 4 字节 hex，8 个字符）与
    /// `nodes` 里的序号（`0` 起）。两种都失败时给出候选数量，便于用户改。
    async fn use_node(&mut self, node: &str) -> Outcome {
        let snap = match self.handle.snapshot().await {
            Ok(s) => s,
            Err(e) => return Outcome::fail(format!("取快照失败：{e}")),
        };
        let needle = node.trim();
        if needle.is_empty() {
            return Outcome::fail("use 需要一个节点编号");
        }
        // 先按序号，再按编号前缀匹配。
        let by_index = needle
            .parse::<usize>()
            .ok()
            .and_then(|idx| snap.nodes.get(idx))
            .map(|info| info.node);
        let by_short = snap
            .nodes
            .iter()
            .find(|info| info.node.short().eq_ignore_ascii_case(needle))
            .map(|info| info.node);
        let Some(target) = by_index.or(by_short) else {
            return Outcome::fail(format!(
                "找不到节点 {needle}（快照里 {} 个节点，可用 use <序号> 或 use <编号>）",
                snap.nodes.len()
            ));
        };
        self.focus = Some(target);
        self.panel = Panel::Node;
        Outcome::ok(format!(
            "已选中节点 {}（{} 面板）",
            target.short(),
            self.panel.label()
        ))
    }

    /// `back`：回到主面板。不改网络，也不清 `focus`（`detail` 还要用）。
    fn back(&mut self) -> Outcome {
        self.panel = Panel::Main;
        Outcome::ok(format!("回到 {} 面板", self.panel.label()))
    }

    // —————————————————————————————————————————————— 备注

    /// `addmemo <note>`：给选中节点写备注。
    ///
    /// 备注由对端节点登记（`Message::Memo` 的 `text` 为空串表示清除）。
    /// 选中的是本机时不发消息——引擎对 `Route::Local` 一律判
    /// `Undeliverable`，发给自己只会换来一条「不可达」提示，没有意义。
    async fn add_memo(&mut self, note: &str) -> Outcome {
        let target = self.target();
        let mut notes = self.drain_events();
        if target == self.me {
            notes.push(format!(
                "备注只对远端节点生效；本机不需要登记（收到：{note}）"
            ));
            return Outcome::lines(notes);
        }
        match self
            .handle
            .send(
                Message::Memo(Memo {
                    node: target,
                    text: note.to_owned(),
                }),
                target,
            )
            .await
        {
            Ok(()) => notes.push(format!("已给 {} 写备注：{note}", target.short())),
            Err(e) => notes.push(format!("错误：备注未发出：{e}")),
        }
        Outcome::lines(notes)
    }

    /// `delmemo <idx>`：清空选中节点的备注（空串 = 清除）。
    ///
    /// `idx` 是命令层保留的备注下标；引擎侧不保留备注列表，因此这里按
    /// 「清除该节点的备注」处理，并把序号回显给用户，避免假装按序号删。
    async fn del_memo(&mut self, idx: u32) -> Outcome {
        let target = self.target();
        let mut notes = self.drain_events();
        if target == self.me {
            notes.push(format!(
                "本机没有可清除的备注（序号 {idx}；备注只对远端节点生效）"
            ));
            return Outcome::lines(notes);
        }
        match self
            .handle
            .send(
                Message::Memo(Memo {
                    node: target,
                    text: String::new(),
                }),
                target,
            )
            .await
        {
            Ok(()) => notes.push(format!(
                "已清除 {} 的备注（序号 {idx}；引擎不保留备注索引，故按「清除」处理）",
                target.short()
            )),
            Err(e) => notes.push(format!("错误：清除备注失败：{e}")),
        }
        Outcome::lines(notes)
    }

    // —————————————————————————————————————————————— 会话类

    /// `shell`：在远端 agent 上开 PTY 会话。
    ///
    /// 发 `OpenSession{kind: ShellPty, direction: Outbound}`，然后建会话流
    /// 让调用方接管读写。流本身交给 `SessionStream`，本层只保证「会话已
    /// 开启」这件事可见。
    async fn shell(&mut self) -> Outcome {
        let key = self.next_key();
        let target = self.target();
        let param = ShellParam {
            cols: 0,
            rows: 0,
            term: String::new(),
        };
        let open = OpenSession {
            key,
            kind: SessionKind::ShellPty,
            direction: SessionDirection::Outbound,
            target: None,
            param: ServiceParam::Shell(param),
        };
        let mut notes = self.drain_events();
        // 先在本端登记，再发 `OpenSession`：对端的 `SessionReady` 要靠会话表
        // 落账（plan §4.14 E18）。
        if let Err(e) = self
            .handle
            .register_session(key, SessionKind::ShellPty)
            .await
        {
            notes.push(format!("错误：shell 会话无法登记：{e}"));
            return Outcome::lines(notes);
        }
        if let Err(e) = self.handle.send(Message::OpenSession(open), target).await {
            notes.push(format!("错误：shell 未开启：{e}"));
            return Outcome::lines(notes);
        }
        match self
            .handle
            .open_stream(key, target, SessionKind::ShellPty)
            .await
        {
            Ok(stream) => {
                let k = stream.key();
                notes.push(format!(
                    "已在 {} 开启 shell（会话 {}）",
                    target.short(),
                    k.id
                ));
            }
            Err(e) => notes.push(format!("错误：会话流建立失败：{e}")),
        }
        Outcome::lines(notes)
    }

    /// `ssh <target> [command]`：让 agent 侧执行 ssh。
    ///
    /// 本端只发 `ServiceRequest{kind: Ssh, phase: Run}`：SSH 客户端跑在
    /// agent 上（v1 语义），凭据/交互都在那边。跨 admin 桥接时端到端密封
    /// 退化到链路级（plan.md §「已知限制」），因此附一行提示。
    async fn ssh(&mut self, target: &str, command: Option<&str>) -> Outcome {
        let (user, addr) = split_user_host(target);
        let param = SshParam {
            user: user.unwrap_or_default(),
            auth: SshAuth::Agent,
            command: command.unwrap_or_default().to_owned(),
        };
        let msg = stowaway_core::ssh::open_message(self.next_key(), &param);
        self.send_service(msg, format!("ssh 请求已发往 {addr}（远端执行）"))
            .await
    }

    /// `sshtunnel <host:sshport> <agent_port>`：用 ssh 把远端节点挂进拓扑。
    ///
    /// 发 `ServiceRequest{kind: SshTunnel, phase: Run}`；真正的桥接
    /// （`bridge_connect`）需要共享密钥，属于 admin 编排层的工作，因此
    /// 这里只发请求并说明由谁完成。
    async fn ssh_tunnel(&mut self, ssh: &str, agent_port: u16) -> Outcome {
        let param = SshTunnelParam {
            ssh: SshParam {
                user: String::new(),
                auth: SshAuth::Agent,
                command: String::new(),
            },
            local_port: agent_port,
            remote_target: ssh.to_owned(),
        };
        let key = self.next_key();
        let request = ServiceRequest {
            key,
            kind: ServiceKind::SshTunnel,
            phase: ServicePhase::Run,
            param: ServiceParam::SshTunnel(param),
        };
        self.send_service(
            Message::ServiceRequest(request),
            format!(
                "sshtunnel 请求已发往 {}（agent 端口 {agent_port}）",
                self.target().short()
            ),
        )
        .await
    }

    /// `connect <addr>`：让 agent 主动连一个新节点。
    async fn connect(&mut self, addr: &str) -> Outcome {
        let key = self.next_key();
        let request = ServiceRequest {
            key,
            kind: ServiceKind::Connect,
            phase: ServicePhase::Run,
            param: ServiceParam::Connect(ConnectParam {
                addr: addr.to_owned(),
            }),
        };
        self.send_service(
            Message::ServiceRequest(request),
            format!("connect 请求已发往 {}：{addr}", self.target().short()),
        )
        .await
    }

    /// 发一条服务请求，并等到 `ServiceReply` / `ServiceExit`（带超时）。
    async fn send_service(&mut self, msg: Message, done: String) -> Outcome {
        let target = self.target();
        let key = message_key(&msg);
        let mut notes = self.drain_events();
        if let Err(e) = self.handle.send(msg, target).await {
            notes.push(format!("错误：请求未发出：{e}"));
            return Outcome::lines(notes);
        }
        notes.push(done);
        // 调用方只把 `Service*` 消息交给本函数；拿不到 key 说明传错了消息种类，
        // 与其 panic 不如把它当成一次失败的命令（缺陷 #2：v1 在这里直接 panic）。
        let Some(key) = key else {
            notes.push("错误：内部消息种类不对（缺少会话键）".to_owned());
            return Outcome::lines(notes);
        };
        let (ev, more) = self
            .wait_event("服务应答", REPLY_TIMEOUT, |ev| {
                matches!(
                    ev,
                    Event::ServiceReply { reply, .. } if reply.key == key
                ) || matches!(
                    ev,
                    Event::ServiceExit { exit, .. } if exit.key == key
                )
            })
            .await;
        notes.extend(more);
        match ev {
            None => notes.push("提示：未收到应答，请求可能仍在远端排队".to_owned()),
            Some(Event::ServiceReply { reply, .. }) => {
                notes.push(format!("对端答复：{:?}（{}）", reply.code, reply.detail));
            }
            Some(Event::ServiceExit { exit, .. }) => {
                notes.push(format!("对端结束：{:?}（{}）", exit.code, exit.detail));
            }
            Some(other) => notes.push(format!("对端事件：{other:?}")),
        }
        Outcome::lines(notes)
    }

    /// 发一条 Probe 并等对端答复（带超时）。
    ///
    /// 与 [`stowaway_core::forward::probe`] 同一语义（只认本会话键的
    /// `ServiceReply` / `ServiceExit`），区别在于事件源是引擎的全量事件流，
    /// 因此期间到达的其它事件也顺手转成提示行。
    async fn probe_service(
        &mut self,
        msg: Message,
        key: SessionKey,
        label: &str,
    ) -> (Result<SessionCode, String>, Vec<String>) {
        let target = self.target();
        let mut notes = self.drain_events();
        if let Err(e) = self.handle.send(msg, target).await {
            return (Err(format!("请求未发出：{e}")), notes);
        }
        let (ev, more) = self
            .wait_event(label, REPLY_TIMEOUT, |ev| match ev {
                Event::ServiceReply { reply, .. } => reply.key == key,
                Event::ServiceExit { exit, .. } => exit.key == key,
                _ => false,
            })
            .await;
        notes.extend(more);
        let got = match ev {
            None => Err("等待对端答复超时".to_owned()),
            Some(Event::ServiceReply { reply, .. }) => {
                if reply.code == SessionCode::Ok {
                    Ok(reply.code)
                } else {
                    Err(format!("远端拒绝：{:?}（{}）", reply.code, reply.detail))
                }
            }
            Some(Event::ServiceExit { exit, .. }) => {
                Err(format!("远端结束：{:?}（{}）", exit.code, exit.detail))
            }
            Some(_) => Err("收到意外事件".to_owned()),
        };
        (got, notes)
    }

    // —————————————————————————————————————————————— 本地监听：socks

    /// `socks <lport> [user] [pass]`：本端起 SOCKS5 监听。
    ///
    /// 每条客户端连接分配一个会话键、发 `OpenSession{kind: Socks5}` 给
    /// 选中节点（默认本机），然后交给
    /// [`stowaway_core::socks_server::serve_connect`] 走「等就绪 → 回真实
    /// REP → 中继」的硬顺序。
    async fn socks(&mut self, port: u16, user: Option<String>, pass: Option<String>) -> Outcome {
        if self.running.socks.contains_key(&port) {
            return Outcome::fail(format!("端口 {port} 上已有 socks 服务在跑（先 stopsocks）"));
        }
        let bind_port = if port == 0 { DEFAULT_SOCKS_PORT } else { port };
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", bind_port)).await {
            Ok(l) => l,
            Err(e) => return Outcome::fail(format!("监听 {bind_port} 失败：{e}")),
        };
        let addr = match listener.local_addr() {
            Ok(a) => a,
            Err(e) => return Outcome::fail(format!("取本地地址失败：{e}")),
        };
        let cfg = match (user, pass) {
            (Some(u), p) => socks_server::SocksServerConfig::with_credentials(
                socks_server::Credentials::new(u, p.unwrap_or_default()),
            ),
            (None, _) => socks_server::SocksServerConfig::open(),
        };
        let handle = self.handle.clone();
        let me = self.me;
        let peer = self.target();
        let task = tokio::spawn(async move {
            run_socks(listener, cfg, handle, me, peer).await;
        });
        self.running.socks.insert(bind_port, task);
        let mut notes = self.drain_events();
        notes.push(format!("socks5 已监听 {addr}（出站经 {}）", peer.short()));
        notes.push(
            "提示：客户端回包用「先连后回」——严格的「先 SessionReady 再回 REP」需要事件泵接线（P7）"
                .to_owned(),
        );
        Outcome::lines(notes)
    }

    /// `stopsocks`：停掉全部 socks 监听。
    fn stop_socks(&mut self) -> Outcome {
        if self.running.socks.is_empty() {
            return Outcome::ok("没有在跑的 socks 服务（stopsocks 无事可做）");
        }
        let mut lines = Vec::new();
        for (port, task) in self.running.socks.drain() {
            task.abort();
            lines.push(format!("已停止 socks（端口 {port}）"));
        }
        lines.extend(self.drain_events());
        Outcome::lines(lines)
    }

    // —————————————————————————————————————————————— 本地监听：forward

    /// `forward <lport> <ip:port>`：本地端口转发到远端目标。
    ///
    /// 先发 Probe，拿到 `Ok` 才真正 bind 本地端口，免得「探测说不行，
    /// 本地却已经占了端口」。
    async fn start_forward(&mut self, local_port: u16, target: &str) -> Outcome {
        if self.running.forwards.contains_key(&local_port) {
            return Outcome::fail(format!(
                "端口 {local_port} 上已有 forward 在跑（先 stopforward）"
            ));
        }
        let peer = self.target();
        let key = self.next_key();
        let spec = forward::ForwardSpec::new(key, local_port, target);
        let (probed, mut notes) = self.probe_service(spec.probe(), key, "forward").await;
        if let Err(e) = probed {
            notes.push(format!("错误：forward 探测失败（{target}）：{e}"));
            return Outcome::lines(notes);
        }
        let committed = match forward::CommittedForward::bind(local_port).await {
            Ok(c) => c,
            Err(e) => {
                notes.push(format!("错误：绑定本地端口 {local_port} 失败：{e}"));
                return Outcome::lines(notes);
            }
        };
        let addr = committed.local_addr();
        let handle = self.handle.clone();
        let run = spec.run();
        let origin = spec.key.origin;
        let base = spec.key.id;
        let task = tokio::spawn(async move {
            run_forward(committed, run, origin, base, handle, peer).await;
        });
        self.running.forwards.insert(local_port, task);
        notes.push(format!(
            "forward 已就绪 {addr} → {target}（经 {}）",
            peer.short()
        ));
        Outcome::lines(notes)
    }

    /// `stopforward [idx]`：停转发；无参停全部。
    fn stop_forward(&mut self, idx: Option<u32>) -> Outcome {
        stop_listener(&mut self.running.forwards, idx, "forward", &mut self.events)
    }

    // —————————————————————————————————————————————— 本地监听：backward

    /// `backward <rport> <lport>`：agent 侧监听 `rport`，admin 侧拨 `lport`。
    ///
    /// v1 语义（`admin/handler/backward.go:129` 是 `DialTimeout(LPort)`、
    /// `agent/handler/backward.go:187` 是 `net.Listen("tcp", "0.0.0.0:"+RPort)`）：
    /// **被监听的一侧是 agent 的 `rport`，拨号的一侧是 admin 的 `lport`**。
    /// 命令名里的 remote/local 说的是「谁的端口在哪一边」，不是「谁监听」。
    ///
    /// 顺序（plan §4.14 E20 的 P7 收尾）：Probe（问对端能否监听 `rport`）→
    /// Run（让对端真的 bind）→ 等 `ServiceReply` 拿到实际监听地址 → 登记
    /// `running.backwards`，由后台任务承接对端发来的 `OpenSession{Backward,
    /// Inbound}` 并逐条拨本地 `lport` 中继。
    async fn backward(&mut self, remote_port: u16, local_port: u16) -> Outcome {
        if self.running.backwards.contains_key(&remote_port) {
            return Outcome::fail(format!(
                "远端端口 {remote_port} 上已有 backward 在跑（先 stopbackward）"
            ));
        }
        let key = self.next_key();
        let spec = stowaway_core::backward::BackwardSpec::new(
            key,
            remote_port,
            format!("127.0.0.1:{local_port}"),
        );
        let (probed, mut notes) = self.probe_service(spec.probe(), key, "backward").await;
        if let Err(e) = probed {
            notes.push(format!(
                "错误：backward 探测失败（远端 {remote_port}）：{e}"
            ));
            return Outcome::lines(notes);
        }
        // 探测通过之后再发 Run：真正的监听在对端，本端只是发起请求。
        let peer = self.target();
        if let Err(e) = self.handle.send(spec.run(), peer).await {
            notes.push(format!("错误：backward 请求未发出：{e}"));
            return Outcome::lines(notes);
        }
        let (ev, more) = self
            .wait_event("backward", REPLY_TIMEOUT, |ev| {
                matches!(ev, Event::ServiceReply { reply, .. } if reply.key == key)
                    || matches!(ev, Event::ServiceExit { exit, .. } if exit.key == key)
            })
            .await;
        notes.extend(more);
        match ev {
            Some(Event::ServiceReply { reply, .. }) if reply.code == SessionCode::Ok => {
                notes.push(format!(
                    "backward 已就绪：远端 {remote_port} → 本地 {local_port}（{}）",
                    reply.detail
                ));
                // 只登记意图：对端已 bind，本端等它发来的
                // `OpenSession{Backward, Inbound}`（由 `route_event` 转交）。
                self.running.backwards.entry(remote_port).or_default();
                self.backwards
                    .push((key, remote_port, spec.remote_target.clone()));
            }
            Some(Event::ServiceReply { reply, .. }) => notes.push(format!(
                "错误：backward 未就绪：{:?}（{}）",
                reply.code, reply.detail
            )),
            Some(Event::ServiceExit { exit, .. }) => notes.push(format!(
                "错误：backward 结束：{:?}（{}）",
                exit.code, exit.detail
            )),
            _ => notes.push("提示：未收到 backward 应答，请求可能仍在远端排队".to_owned()),
        }
        Outcome::lines(notes)
    }

    /// `stopbackward [idx]`：停回流。
    ///
    /// 远端端口停不掉（监听在对端），本端能做的是**不再拨号中继**：
    /// 摘掉登记项并 abort 这组任务。对端那条监听会在下一次 accept 时因为
    /// 等不到 `SessionReady` 而关掉该连接。
    fn stop_backward(&mut self, idx: Option<u32>) -> Outcome {
        let mut lines = self.drain_events();
        if self.running.backwards.is_empty() {
            lines.push("没有在跑的 backward 服务（backward 停止命令无事可做）".to_owned());
            return Outcome::lines(lines);
        }
        let mut ports: Vec<u16> = self.running.backwards.keys().copied().collect();
        ports.sort_unstable();
        let chosen: Vec<u16> = match idx {
            None => ports,
            Some(i) => match ports.get(usize::try_from(i).unwrap_or(usize::MAX)).copied() {
                Some(port) => vec![port],
                None => {
                    lines.push(format!("没有第 {i} 条 backward（当前 {} 条）", ports.len()));
                    return Outcome::lines(lines);
                }
            },
        };
        for port in chosen {
            if let Some(tasks) = self.running.backwards.remove(&port) {
                for task in tasks {
                    task.abort();
                }
            }
            self.backwards.retain(|(_, p, _)| *p != port);
            lines.push(format!("已停止 backward（远端端口 {port}）"));
        }
        Outcome::lines(lines)
    }

    // —————————————————————————————————————————————— 文件

    /// `upload <local> <remote>`：把本地文件推到当前节点。
    ///
    /// 顺序：本地算 `size`/`sha256`（**没有摘要就不传**，plan §4.14 E17 的
    /// 原话是「本端无法算 sha256 就不传」，现在能算了）→ 探测
    /// （`ServiceRequest{File, Probe}`）→ 登记会话 → 开流 → 发 Run →
    /// 等 `SessionReady` → 分片写流。
    ///
    /// 摘要与长度都先在本地算好再发给对端，对端才有可校验的期望值；
    /// 反过来（先传再算）等于事后补票，写坏的文件也已经落盘了。
    async fn upload(&mut self, local: &str, remote: &str) -> Outcome {
        let path = std::path::Path::new(local);
        let size = match tokio::fs::metadata(path).await {
            Ok(m) if m.is_file() => m.len(),
            Ok(_) => return Outcome::fail(format!("{local} 不是普通文件")),
            Err(e) => return Outcome::fail(format!("打不开 {local}：{e}")),
        };
        let remote_name = remote_name_of(remote);
        if let Err(e) = stowaway_core::file::validate_name(&remote_name) {
            return Outcome::fail(format!("远端文件名不可用：{e}"));
        }
        let digest = match stowaway_core::file::sha256_file(path).await {
            Ok(d) => d,
            Err(e) => return Outcome::fail(format!("计算 sha256 失败：{e}")),
        };
        let key = self.next_key();
        let param = stowaway_protocol::FileParam {
            name: remote_name,
            size,
            sha256: digest,
            offset: 0,
            direction: stowaway_protocol::FileDirection::Upload,
        };
        let mut notes = self.drain_events();
        notes.push(format!(
            "上传 {local} → {}（{size} 字节，sha256 {}）",
            self.target().short(),
            hex8(&digest)
        ));
        let (probe, more) = self
            .probe_service(stowaway_core::file::request(key, &param), key, "文件探测")
            .await;
        notes.extend(more);
        if let Err(e) = probe {
            notes.push(format!("错误：{e}"));
            return Outcome::lines(notes);
        }
        let target = self.target();
        if let Err(e) = self.handle.register_session(key, SessionKind::File).await {
            notes.push(format!("错误：会话无法登记：{e}"));
            return Outcome::lines(notes);
        }
        let mut session = match self
            .handle
            .open_stream(key, target, SessionKind::File)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                notes.push(format!("错误：开流失败：{e}"));
                return Outcome::lines(notes);
            }
        };
        if let Err(e) = self
            .handle
            .send(stowaway_core::file::run(key, &param), target)
            .await
        {
            notes.push(format!("错误：请求未发出：{e}"));
            return Outcome::lines(notes);
        }
        match self.handle.await_ready(key).await {
            Ok(SessionCode::Ok) => {}
            Ok(other) => {
                notes.push(format!("错误：对端拒绝上传：{other:?}"));
                return Outcome::lines(notes);
            }
            Err(e) => {
                notes.push(format!("错误：等就绪失败：{e}"));
                return Outcome::lines(notes);
            }
        }
        let mut file = match tokio::fs::File::open(path).await {
            Ok(f) => f,
            Err(e) => {
                notes.push(format!("错误：打开 {local} 失败：{e}"));
                return Outcome::lines(notes);
            }
        };
        let mut buf = vec![0u8; stowaway_core::file::FILE_CHUNK];
        let mut sent = 0u64;
        loop {
            let n = match file.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    notes.push(format!("错误：读 {local} 失败：{e}"));
                    return Outcome::lines(notes);
                }
            };
            if let Err(e) = session.write_all(&buf[..n]).await {
                notes.push(format!("错误：写会话失败：{e}"));
                return Outcome::lines(notes);
            }
            sent = sent.saturating_add(n as u64);
        }
        if let Err(e) = session.shutdown().await {
            notes.push(format!("错误：收尾失败：{e}"));
            return Outcome::lines(notes);
        }
        notes.push(format!("已发送 {sent} 字节，等待对端校验"));
        // 校验在远端做，结果通过 `ServiceExit` 回来；等不到也要说清。
        let (ev, more) = self
            .wait_event("文件传输", FILE_TIMEOUT, |ev| match ev {
                Event::ServiceExit { exit, .. } => exit.key == key,
                Event::ServiceReply { reply, .. } => reply.key == key,
                _ => false,
            })
            .await;
        notes.extend(more);
        match ev {
            Some(Event::ServiceExit { exit, .. }) => notes.push(match exit.code {
                SessionCode::Ok => format!("对端确认：{}", exit.detail),
                other => format!("对端失败：{other:?}（{}）", exit.detail),
            }),
            Some(Event::ServiceReply { reply, .. }) => {
                notes.push(format!("对端答复：{:?}（{}）", reply.code, reply.detail));
            }
            _ => notes.push("提示：未收到对端校验结果，传输可能仍在远端处理".to_owned()),
        }
        Outcome::lines(notes)
    }

    /// `download <remote> [local]`：把当前节点上的文件取回本地。
    ///
    /// 接收方不知道远端大小与摘要，所以由发送方在流首写 40 字节清单
    /// （`size ‖ sha256`，[`stowaway_core::file::MANIFEST_LEN`]）。本端按
    /// 清单校验：长度不符或摘要不符都不落成好文件（落到 `<name>.part`
    /// 后删除），这样「传坏一个文件」不会静默成功。
    async fn download(&mut self, remote: &str, local: Option<&str>) -> Outcome {
        let remote_name = remote_name_of(remote);
        if let Err(e) = stowaway_core::file::validate_name(&remote_name) {
            return Outcome::fail(format!("远端文件名不可用：{e}"));
        }
        let out_path = match local {
            Some(p) => std::path::PathBuf::from(p),
            None => std::path::PathBuf::from(remote_name.as_str()),
        };
        let key = self.next_key();
        // 下载方向的 size/sha256 由发送方在清单头里给，这里先填占位。
        let param = stowaway_protocol::FileParam {
            name: remote_name,
            size: 0,
            sha256: [0u8; 32],
            offset: 0,
            direction: stowaway_protocol::FileDirection::Download,
        };
        let mut notes = self.drain_events();
        notes.push(format!(
            "下载 {}:{} → {}",
            self.target().short(),
            remote,
            out_path.display()
        ));
        let (probe, more) = self
            .probe_service(stowaway_core::file::request(key, &param), key, "文件探测")
            .await;
        notes.extend(more);
        if let Err(e) = probe {
            notes.push(format!("错误：{e}"));
            return Outcome::lines(notes);
        }
        let target = self.target();
        if let Err(e) = self.handle.register_session(key, SessionKind::File).await {
            notes.push(format!("错误：会话无法登记：{e}"));
            return Outcome::lines(notes);
        }
        let mut session = match self
            .handle
            .open_stream(key, target, SessionKind::File)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                notes.push(format!("错误：开流失败：{e}"));
                return Outcome::lines(notes);
            }
        };
        if let Err(e) = self
            .handle
            .send(stowaway_core::file::run(key, &param), target)
            .await
        {
            notes.push(format!("错误：请求未发出：{e}"));
            return Outcome::lines(notes);
        }
        match self.handle.await_ready(key).await {
            Ok(SessionCode::Ok) => {}
            Ok(other) => {
                notes.push(format!("错误：对端拒绝发送：{other:?}"));
                return Outcome::lines(notes);
            }
            Err(e) => {
                notes.push(format!("错误：等就绪失败：{e}"));
                return Outcome::lines(notes);
            }
        }
        let mut head = [0u8; stowaway_core::file::MANIFEST_LEN];
        if let Err(e) = session.read_exact(&mut head).await {
            notes.push(format!("错误：读清单失败：{e}"));
            return Outcome::lines(notes);
        }
        let (size, want) = stowaway_core::file::parse_manifest(&head);
        notes.push(format!("远端声明 {size} 字节，sha256 {}", hex8(&want)));
        let part = out_path.with_extension("part");
        let mut sink = match tokio::fs::File::create(&part).await {
            Ok(f) => f,
            Err(e) => {
                notes.push(format!("错误：创建 {} 失败：{e}", part.display()));
                return Outcome::lines(notes);
            }
        };
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; stowaway_core::file::FILE_CHUNK];
        let mut got = 0u64;
        loop {
            let n = match session.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    notes.push(format!("错误：读会话失败：{e}"));
                    let _ = tokio::fs::remove_file(&part).await;
                    return Outcome::lines(notes);
                }
            };
            hasher.update(&buf[..n]);
            if let Err(e) = sink.write_all(&buf[..n]).await {
                notes.push(format!("错误：写盘失败：{e}"));
                let _ = tokio::fs::remove_file(&part).await;
                return Outcome::lines(notes);
            }
            got = got.saturating_add(n as u64);
        }
        if let Err(e) = sink.flush().await {
            notes.push(format!("错误：落盘失败：{e}"));
            let _ = tokio::fs::remove_file(&part).await;
            return Outcome::lines(notes);
        }
        drop(sink);
        let actual: [u8; 32] = hasher.finalize().into();
        if got != size {
            let _ = tokio::fs::remove_file(&part).await;
            notes.push(format!("错误：长度不符（收到 {got}，声明 {size}），已丢弃"));
            return Outcome::lines(notes);
        }
        if actual != want {
            let _ = tokio::fs::remove_file(&part).await;
            notes.push(format!(
                "错误：sha256 不符（{} ≠ {}），已丢弃",
                hex8(&actual),
                hex8(&want)
            ));
            return Outcome::lines(notes);
        }
        match tokio::fs::rename(&part, &out_path).await {
            Ok(()) => notes.push(format!(
                "已保存 {}（{got} 字节，校验通过）",
                out_path.display()
            )),
            Err(e) => {
                let _ = tokio::fs::remove_file(&part).await;
                notes.push(format!("错误：改名失败：{e}"));
            }
        }
        Outcome::lines(notes)
    }

    // —————————————————————————————————————————————— 其它

    /// `listen [ip:]<port>`：在 agent 上被动监听（P7 联调项）。
    /// `listen <addr>`：请**对端**在 `addr` 上监听，把拨进来的节点当它的子节点。
    ///
    /// 监听必须发生在被控端：本端替对端起监听器既无意义（防火墙在后面），
    /// 也违背「谁能 bind 谁负责」的分工。所以这里只发一条
    /// `ServiceRequest{kind: Listen, phase: Run}`，地址放在 `ConnectParam.addr`
    /// （`ServiceRequest` 没有 target 字段，见 plan §4.14 E19），真正的
    /// `bind` + 伪 admin 握手 + 编号分配都发生在对端（`Services::run_listen`）。
    async fn listen(&mut self, spec: &str) -> Outcome {
        let mut notes = self.drain_events();
        let key = self.next_key();
        let msg = Message::ServiceRequest(ServiceRequest {
            key,
            kind: ServiceKind::Listen,
            phase: ServicePhase::Run,
            param: ServiceParam::Connect(ConnectParam {
                addr: spec.to_owned(),
            }),
        });
        notes.push(format!("请求 {} 在 {spec} 上监听", self.target().short()));
        let outcome = self.send_service(msg, "listen 请求已发出".to_owned()).await;
        notes.extend(outcome.lines);
        Outcome::lines(notes)
    }

    /// `shutdown`：广播 `Shutdown` 给拓扑里的每个远端节点，再请控制台退出。
    ///
    /// 本机不给自己发：`Route::Local` 会被引擎判 `Undeliverable`，那条
    /// 「不可达」提示只会误导用户。
    async fn shutdown(&mut self) -> Outcome {
        let mut notes = self.drain_events();
        let msg = Message::Shutdown(Shutdown {
            grace_ms: 1_000,
            reason: "控制台 shutdown".to_owned(),
        });
        let peers: Vec<NodeId> = match self.handle.snapshot().await {
            Ok(snap) => snap
                .nodes
                .iter()
                .map(|info| info.node)
                .filter(|id| *id != self.me)
                .collect(),
            Err(e) => {
                notes.push(format!("错误：取快照失败，shutdown 只能停本端：{e}"));
                Vec::new()
            }
        };
        if peers.is_empty() {
            notes.push("拓扑里没有其它节点，shutdown 只停本端".to_owned());
        }
        for peer in peers {
            match self.handle.send(msg.clone(), peer).await {
                Ok(()) => notes.push(format!("已向 {} 发送 shutdown", peer.short())),
                Err(e) => notes.push(format!("错误：向 {} 发送 shutdown 失败：{e}", peer.short())),
            }
        }
        notes.push("控制台退出（shutdown）".to_owned());
        for (port, task) in self.running.socks.drain() {
            task.abort();
            notes.push(format!("已停止 socks（端口 {port}）"));
        }
        for (port, task) in self.running.forwards.drain() {
            task.abort();
            notes.push(format!("已停止 forward（端口 {port}）"));
        }
        for (port, tasks) in self.running.backwards.drain() {
            for task in tasks {
                task.abort();
            }
            notes.push(format!("已停止 backward（远端端口 {port}）"));
        }
        self.backwards.clear();
        let _ = self.handle.shutdown().await;
        Outcome {
            lines: notes,
            keep_running: false,
        }
    }
}

/// 把一条非应答事件转成给人看的提示行；不需要提示的返回 `None`。
fn event_note(ev: &Event) -> Option<String> {
    match ev {
        Event::Failed(detail) => Some(format!("引擎提示：{detail}")),
        Event::Undeliverable { dest } => Some(format!("目标 {} 不可达", dest.short())),
        Event::LinkLost { peer } => Some(format!("链路 {} 断开", peer.short())),
        Event::PeerDead { peer, misses } => Some(format!(
            "链路 {} 判定已死（{misses} 次心跳无回显）",
            peer.short()
        )),
        Event::Offline { node, .. } => Some(format!("节点 {} 离线", node.short())),
        Event::Shutdown => Some("对端请求 shutdown".to_owned()),
        Event::Joined { node, .. } => Some(format!("节点 {} 入网", node.short())),
        Event::SessionOpened { open, from } => Some(format!(
            "{} 发起会话 {}（{:?}）",
            from.short(),
            open.key.id,
            open.kind
        )),
        Event::SessionClosed { key } => Some(format!("会话 {} 关闭", key.id)),
        Event::SessionReady { .. }
        | Event::ServiceRequest { .. }
        | Event::ServiceReply { .. }
        | Event::ServiceData { .. }
        | Event::ServiceExit { .. }
        | Event::Rtt { .. } => None,
    }
}

/// 文件传输的整体超时：分片 + 对端校验都在里面。
const FILE_TIMEOUT: Duration = Duration::from_secs(300);

/// 远端路径的 base name（`upload`/`download` 都只认单段文件名）。
fn remote_name_of(path: &str) -> String {
    let trimmed = path.trim_end_matches(['/', '\\']);
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(trimmed)
        .to_owned()
}

/// 摘要前 8 字节的 hex（只用于提示行，不是安全边界）。
fn hex8(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(16);
    for b in &bytes[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 取出消息带的会话键（服务请求/会话相关消息才有）。
fn message_key(msg: &Message) -> Option<SessionKey> {
    match msg {
        Message::ServiceRequest(req) => Some(req.key),
        Message::OpenSession(open) => Some(open.key),
        _ => None,
    }
}

/// 一行节点描述。
fn node_line(info: &stowaway_core::NodeInfo) -> String {
    let listen = info.listen.as_deref().unwrap_or("-");
    format!(
        "{} 类型 {:?} 父 {} 深度 {} 监听 {listen}",
        info.node.short(),
        info.kind,
        info.parent.short(),
        info.depth
    )
}

/// `ssh` 的目标：`user@host:port` 或 `host:port`。
fn split_user_host(target: &str) -> (Option<String>, String) {
    match target.split_once('@') {
        Some((user, host)) if !user.is_empty() && !host.is_empty() => {
            (Some(user.to_owned()), host.to_owned())
        }
        _ => (None, target.to_owned()),
    }
}

/// 停一组本地监听：给 `idx` 时只停第 idx 条（按端口升序），否则全停。
fn stop_listener(
    map: &mut HashMap<u16, JoinHandle<()>>,
    idx: Option<u32>,
    name: &str,
    events: &mut mpsc::UnboundedReceiver<Event>,
) -> Outcome {
    let mut lines = Vec::new();
    while let Ok(ev) = events.try_recv() {
        if let Some(note) = event_note(&ev) {
            lines.push(note);
        }
    }
    if map.is_empty() {
        lines.push(format!("没有在跑的 {name} 服务（{name} 停止命令无事可做）"));
        return Outcome::lines(lines);
    }
    match idx {
        None => {
            let mut ports: Vec<u16> = map.keys().copied().collect();
            ports.sort_unstable();
            for port in ports {
                if let Some(task) = map.remove(&port) {
                    task.abort();
                    lines.push(format!("已停止 {name}（端口 {port}）"));
                }
            }
        }
        Some(i) => {
            let mut ports: Vec<u16> = map.keys().copied().collect();
            ports.sort_unstable();
            let Some(port) = ports.get(usize::try_from(i).unwrap_or(usize::MAX)).copied() else {
                lines.push(format!("没有第 {i} 条 {name}（当前 {} 条）", ports.len()));
                return Outcome::lines(lines);
            };
            if let Some(task) = map.remove(&port) {
                task.abort();
                lines.push(format!("已停止 {name}（端口 {port}）"));
            }
        }
    }
    Outcome::lines(lines)
}

/// 把会话码翻成 SOCKS5 回包码。
///
/// `SessionCode` 只有 Ok/Refused/Timeout/NotFound/Denied 五种，SOCKS5 的
/// 回包码更细（网络不可达/主机不可达分开）；这里只做保守映射：能让客户端
/// 区分「被拒」与「超时」就够了，其余一律 `REP_GENERAL_FAILURE`。
const fn reply_of(code: SessionCode) -> u8 {
    match code {
        SessionCode::Ok => socks::REP_SUCCEEDED,
        SessionCode::Refused => socks::REP_CONNECTION_REFUSED,
        SessionCode::Timeout => socks::REP_TTL_EXPIRED,
        SessionCode::NotFound => socks::REP_HOST_UNREACHABLE,
        SessionCode::Denied => socks::REP_NOT_ALLOWED,
    }
}

// —————————————————————————————————————————————— 后台监听任务

/// SOCKS5 监听循环：每条连接一个会话键，交给 `serve_connect`。
async fn run_socks(
    listener: tokio::net::TcpListener,
    cfg: socks_server::SocksServerConfig,
    handle: EngineHandle,
    me: NodeId,
    peer: NodeId,
) {
    let mut seq: u64 = 0;
    loop {
        let Ok((mut client, _)) = listener.accept().await else {
            return;
        };
        seq = seq.saturating_add(1);
        let key = SessionKey::new(me, seq);
        let cfg = cfg.clone();
        let handle = handle.clone();
        tokio::spawn(async move {
            let Ok(neg) = socks_server::negotiate(&mut client, &cfg).await else {
                return;
            };
            // UDP ASSOCIATE 不在本层实现：明确回「命令不支持」而不是装作成功。
            if socks_server::is_udp_associate(&neg) {
                let _ = client
                    .write_all(&socks::Reply::new(socks::REP_COMMAND_NOT_SUPPORTED).encode())
                    .await;
                let _ = client.flush().await;
                return;
            }
            // 发起方也要登记会话：对端回的 `SessionReady` 要靠会话表落账，
            // 而 `await_ready` 也是靠它区分「还没就绪」与「没这条会话」
            // （plan §4.14 E18；缺这一步会在等就绪时立刻被判未知会话）。
            if handle
                .register_session(key, SessionKind::Socks5)
                .await
                .is_err()
            {
                return;
            }
            let mut session = match handle.open_stream(key, peer, SessionKind::Socks5).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = handle
                .send(
                    Message::OpenSession(OpenSession {
                        key,
                        kind: SessionKind::Socks5,
                        direction: SessionDirection::Outbound,
                        target: Some(neg.target.clone()),
                        param: ServiceParam::None,
                    }),
                    peer,
                )
                .await;
            // 对端确认「出口已经建起来了」之后才回 REP（plan §4.14 E18）：
            // 先回成功再拨号正是 v1 `admin/handler/socks.go:204` 的缺陷。
            let code = match handle.await_ready(key).await {
                Ok(code) => code,
                Err(_) => {
                    let reply = socks::Reply::new(socks::REP_GENERAL_FAILURE);
                    let _ = client.write_all(&reply.encode()).await;
                    let _ = client.flush().await;
                    return;
                }
            };
            let reply = match code {
                SessionCode::Ok => {
                    socks::Reply::succeeded(std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
                }
                other => socks::Reply::new(reply_of(other)),
            };
            if client.write_all(&reply.encode()).await.is_err() {
                return;
            }
            if client.flush().await.is_err() {
                return;
            }
            if code != SessionCode::Ok {
                return;
            }
            let (out, _inbound) = mpsc::channel(64);
            let _ = socks_server::pump(&mut session, &mut client, &out, key, peer).await;
        });
    }
}

/// forward 监听循环：每条连接开一条 Forward 会话并中继。
/// 反向映射的一条连接：开流 → 拨本地目标 → 回 Ready → 双向中继。
///
/// 顺序按 plan §4.14 E18：**先开流、再回 Ready**。反过来对端一收到
/// `Ok` 就会把客户端数据推过来，而本端还没拨到本地目标。
async fn relay_backward_session(handle: EngineHandle, key: SessionKey, target: String) {
    let peer = key.origin;
    let mut session = match handle.open_stream(key, peer, SessionKind::Backward).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(?key, error = %e, "反向映射：建流失败");
            return;
        }
    };
    let mut remote = match stowaway_core::backward::dial_remote(&target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target = %target, error = %e, "反向映射：拨本地目标失败");
            let _ = handle
                .close_session(key, stowaway_protocol::CloseReason::Refused)
                .await;
            return;
        }
    };
    if handle
        .ready_session(key, peer, SessionCode::Ok, format!("已连到 {target}"))
        .await
        .is_err()
    {
        return;
    }
    match stowaway_core::relay_stream(&mut session, &mut remote).await {
        Ok((up, down)) => tracing::debug!(?key, up, down, "反向映射会话结束"),
        Err(e) => tracing::debug!(?key, error = %e, "反向映射会话中断"),
    }
    let _ = handle
        .close_session(key, stowaway_protocol::CloseReason::Normal)
        .await;
}

async fn run_forward(
    committed: forward::CommittedForward,
    run: Message,
    origin: NodeId,
    base: u64,
    handle: EngineHandle,
    peer: NodeId,
) {
    let mut seq: u64 = 0;
    loop {
        let Ok(client) = committed.accept().await else {
            return;
        };
        seq = seq.saturating_add(1);
        let key = SessionKey::new(origin, base.wrapping_add(seq));
        let handle = handle.clone();
        let run = run.clone();
        tokio::spawn(async move {
            // forward 的发起方同样要先登记会话（同上一条注释）。
            if handle
                .register_session(key, SessionKind::Forward)
                .await
                .is_err()
            {
                return;
            }
            let mut session = match handle.open_stream(key, peer, SessionKind::Forward).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = handle.send(run, peer).await;
            // forward 也要等对端确认出口可达（plan §4.14 E18），
            // 否则本地连接会已经开始灌数据而远端还没开始拨。
            if !matches!(handle.await_ready(key).await, Ok(SessionCode::Ok)) {
                return;
            }
            let (out, _inbound) = mpsc::channel(64);
            let mut client = client;
            let _ = socks_server::pump(&mut session, &mut client, &out, key, peer).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{Console, Outcome};
    use crate::command::{Command, Panel};
    use stowaway_core::{Engine, EngineHandle, Event, NodeConfig, NodeIdAllocator};
    use stowaway_protocol::{NodeId, NodeKind};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    /// 起一个真实引擎（无链路），返回执行器与关停句柄。
    async fn console() -> (Console, EngineHandle, JoinHandle<stowaway_core::Result<()>>) {
        let (etx, erx) = mpsc::unbounded_channel::<Event>();
        let (handle, engine, _inbound) =
            Engine::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin), etx);
        let task = tokio::spawn(engine.run());
        let console = Console::new(
            handle.clone(),
            NodeId::ADMIN,
            NodeIdAllocator::new([0; 4]),
            erx,
        );
        (console, handle, task)
    }

    /// 收尾：关引擎并等它退出。
    async fn shutdown(handle: &EngineHandle, task: JoinHandle<stowaway_core::Result<()>>) {
        handle.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("engine ok");
    }

    #[test]
    fn outcome_display_joins_lines() {
        let out = Outcome::lines(vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(out.to_string(), "a\nb");
        assert!(out.keep_running);
    }

    #[tokio::test]
    async fn status_without_nodes_reports_zero_topology() {
        let (mut c, handle, task) = console().await;
        let out = c.execute(Command::Status).await;
        assert!(out.keep_running, "status 不该退出");
        let text = out.to_string();
        assert!(text.contains("节点 1"), "至少报出自己：{text}");
        assert!(text.contains("链路 0"), "无链路：{text}");
        assert!(text.contains("会话 0"), "无会话：{text}");
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn detail_and_topo_are_non_empty() {
        let (mut c, handle, task) = console().await;
        let detail = c.execute(Command::Detail).await;
        assert!(detail.to_string().contains("快照"));
        let topo = c.execute(Command::Topo).await;
        assert!(topo.to_string().contains("链路"));
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn listen_asks_the_peer_and_reports_the_timeout() {
        // 本端没有链路：请求发不出去也不该静默成功，必须留下「没收到应答」。
        let (mut c, handle, task) = console().await;
        let out = c
            .execute(Command::Listen("127.0.0.1:1080".to_owned()))
            .await;
        let text = out.to_string();
        assert!(text.contains("127.0.0.1:1080"), "必须回显地址：{text}");
        assert!(
            text.contains("超时") || text.contains("未发出") || text.contains("不可达"),
            "必须说明没打通：{text}"
        );
        assert!(out.keep_running);
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn backward_probe_without_peer_is_an_error_not_a_silent_success() {
        let (mut c, handle, task) = console().await;
        let out = c
            .execute(Command::Backward {
                remote_port: 9001,
                local_port: 22,
            })
            .await;
        let text = out.to_string();
        assert!(text.contains("9001"), "必须回显远端端口：{text}");
        assert!(text.contains("错误"), "探测不到就必须报错：{text}");
        assert!(c.running_counts().2 == 0, "失败时不该留下登记：{text}");
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn stop_commands_without_services_are_hints() {
        let (mut c, handle, task) = console().await;
        for cmd in [
            Command::StopSocks,
            Command::StopForward(None),
            Command::StopBackward(None),
        ] {
            let out = c.execute(cmd).await;
            let text = out.to_string();
            assert!(text.contains("没有在跑"), "应是提示而非报错：{text}");
            assert!(!text.contains("错误"), "不该出现错误字样：{text}");
            assert!(out.keep_running);
        }
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn use_and_back_do_not_touch_network() {
        let (mut c, handle, task) = console().await;
        let before = handle.snapshot().await.expect("snapshot");
        let out = c.execute(Command::Use("0".to_owned())).await;
        assert!(out.keep_running);
        assert_eq!(c.focus(), Some(NodeId::ADMIN), "按序号 0 选中自己");
        assert_eq!(c.panel(), Panel::Node);
        let back = c.execute(Command::Back).await;
        assert!(back.keep_running);
        assert_eq!(c.panel(), Panel::Main);
        let after = handle.snapshot().await.expect("snapshot");
        assert_eq!(before.nodes.len(), after.nodes.len());
        assert_eq!(before.sessions, after.sessions);
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn use_with_unknown_node_reports_instead_of_erroring() {
        let (mut c, handle, task) = console().await;
        let out = c.execute(Command::Use("deadbeef".to_owned())).await;
        assert!(out.to_string().contains("找不到节点"));
        assert!(out.keep_running);
        assert_eq!(c.focus(), None);
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn shutdown_stops_the_console() {
        let (mut c, handle, task) = console().await;
        let out = c.execute(Command::Shutdown).await;
        assert!(!out.keep_running, "shutdown 必须请求退出");
        let text = out.to_string();
        assert!(text.contains("shutdown"), "{text}");
        assert!(
            text.contains("没有其它节点"),
            "单节点要说清只停本端：{text}"
        );
        assert!(!text.contains("错误"), "单节点 shutdown 不该报错：{text}");
        task.await.expect("join").expect("engine ok");
        // 引擎已经停了：再有命令会拿到 LinkClosed，而不是静默挂起。
        assert!(handle.snapshot().await.is_err(), "关机后引擎不应再应答");
    }

    #[tokio::test]
    async fn exit_requests_quit_without_network() {
        let (mut c, handle, task) = console().await;
        let out = c.execute(Command::Exit).await;
        assert!(!out.keep_running);
        assert!(out.to_string().contains("退出"));
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn parse_then_execute_help_end_to_end() {
        let (mut c, handle, task) = console().await;
        let cmd = crate::command::parse(Panel::Main, "help").expect("parse");
        let out = c.execute(cmd).await;
        assert!(out.to_string().contains("帮助"));
        assert!(out.keep_running);
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn parse_then_execute_shell_opens_a_session() {
        let (mut c, handle, task) = console().await;
        let cmd = crate::command::parse(Panel::Node, "shell").expect("parse");
        let out = c.execute(cmd).await;
        assert!(out.to_string().contains("shell"), "{}", out);
        let snap = handle.snapshot().await.expect("snapshot");
        assert_eq!(snap.sessions, 1, "会话应已登记");
        shutdown(&handle, task).await;
    }

    #[tokio::test]
    async fn memo_commands_are_accepted() {
        let (mut c, handle, task) = console().await;
        let add = c.execute(Command::AddMemo("注意这台".to_owned())).await;
        assert!(add.to_string().contains("备注"));
        assert!(!add.to_string().contains("错误"), "本机备注不该报错：{add}");
        let del = c.execute(Command::DelMemo(0)).await;
        assert!(del.to_string().contains("清除"));
        assert!(!del.to_string().contains("错误"), "本机清除不该报错：{del}");
        shutdown(&handle, task).await;
    }
}
