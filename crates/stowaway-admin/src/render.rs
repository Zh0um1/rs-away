//! 控制台 TUI 渲染层：两级面板（主面板 / 节点面板）+ 输入行。
//!
//! 只在 `tui` feature（默认开启）下接入 `main.rs`：
//!
//! ```ignore
//! #[cfg(feature = "tui")]
//! mod render;
//! ```
//!
//! 本模块只负责「把状态画到终端」和「把按键翻译成高层动作」：
//! 命令解析在 `command.rs`、历史在 `history.rs`，这里不重复实现语义。
//! 真正的命令执行由编排层（`main.rs` / 将来的 console 状态机）根据
//! [`Action::Submit`] 决定，`render.rs` 自己不动网络。

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph, Row, Table};
use stowaway_core::{LinkStat, NodeInfo, Snapshot};
use stowaway_protocol::{NodeId, NodeKind};

use crate::command::{self, Command, Panel};
use crate::history::{History, HistoryKind};

/// 滚动日志最多保留的行数（v1 也是软上限，只留最近的输出）。
pub const MAX_LOG_LINES: usize = 500;

/// 输入行提交后交给编排层的高层动作。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Action {
    /// 什么都不用做（继续等输入）。
    #[default]
    None,
    /// 解析成功、且不需要二次确认：请编排层执行这条命令。
    Submit(Command),
    /// 退出 TUI（`exit` 经 y/n 确认，或 Ctrl-C）。
    Quit,
}

/// TUI 的全部可变状态。
#[derive(Debug, Clone)]
pub struct App {
    /// 当前面板。
    pub panel: Panel,
    /// 节点面板聚焦的节点（主面板用于高亮某一行）。
    pub focus: Option<NodeId>,
    /// 当前输入行内容。
    pub input: String,
    /// 输入行的光标位置（**字节**偏移，且始终落在字符边界上）。
    pub cursor: usize,
    /// 命令历史（三份独立列表）。
    pub history: History,
    /// 滚动日志（只保留最近 [`MAX_LOG_LINES`] 行）。
    pub log: Vec<String>,
    /// 最近一次拓扑快照。
    pub snapshot: Snapshot,
    /// peer 断链时的降级 banner 文案；`None` 表示链路正常。
    pub degraded: Option<String>,
    /// 状态行（错误提示 / 候选命令 / 确认提示）。
    pub status_line: String,
    /// 历史浏览期间固定的前缀（`None` = 当前不在浏览历史）。
    search_prefix: Option<String>,
    /// 等待 y/n 二次确认的命令。
    pending: Option<Command>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// 全空起始状态。
    #[must_use]
    pub fn new() -> Self {
        Self {
            panel: Panel::Main,
            focus: None,
            input: String::new(),
            cursor: 0,
            history: History::new(),
            log: Vec::new(),
            snapshot: Snapshot::default(),
            degraded: None,
            status_line: String::new(),
            search_prefix: None,
            pending: None,
        }
    }

    /// 用一帧快照初始化（编排层 poll 到新状态时也可直接赋值 `app.snapshot`）。
    #[must_use]
    pub fn with_snapshot(snapshot: Snapshot) -> Self {
        Self {
            snapshot,
            ..Self::new()
        }
    }

    /// 追加一行日志；超过 [`MAX_LOG_LINES`] 时丢掉最旧的行。
    pub fn push_log(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > MAX_LOG_LINES {
            let excess = self.log.len() - MAX_LOG_LINES;
            self.log.drain(..excess);
        }
    }

    /// 清空日志。
    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// 替换快照。
    pub fn set_snapshot(&mut self, snapshot: Snapshot) {
        self.snapshot = snapshot;
    }

    /// 设置降级 banner 文案（`None` 恢复正常）。
    pub fn set_degraded(&mut self, message: Option<String>) {
        self.degraded = message;
    }

    /// 设置聚焦节点；同时把面板切到与之匹配的一侧。
    pub fn focus_node(&mut self, node: Option<NodeId>) {
        self.focus = node;
        if node.is_some() {
            self.panel = Panel::Node;
        }
    }

    /// 回到主面板。
    pub fn back_to_main(&mut self) {
        self.panel = Panel::Main;
    }

    /// 等待二次确认的命令（供编排层观察）。
    #[must_use]
    pub fn pending_confirm(&self) -> Option<&Command> {
        self.pending.as_ref()
    }

    /// 输入行提示符：主面板 `>> `，节点面板 `(node <id>) >> `。
    #[must_use]
    pub fn prompt(&self) -> String {
        match self.panel {
            Panel::Main => ">> ".to_string(),
            Panel::Node => match self.focus {
                Some(id) => format!("(node {id}) >> "),
                None => "(node) >> ".to_string(),
            },
        }
    }

    /// 当前输入行使用的历史列表（普通命令都进 `NORMAL`）。
    #[must_use]
    const fn history_kind(&self) -> HistoryKind {
        HistoryKind::Normal
    }

    /// 清空输入行与历史浏览状态。
    fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
        self.search_prefix = None;
    }

    /// 处理一次按键，返回编排层要执行的动作。
    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        // 终端（尤其 Windows）会同时上报 Release/Repeat，只处理按下。
        if key.kind == KeyEventKind::Release {
            return Action::None;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('c') => return Action::Quit,
                KeyCode::Char('u') => {
                    self.clear_input();
                    return Action::None;
                }
                KeyCode::Char('l') => {
                    self.clear_log();
                    return Action::None;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Char(c) => {
                self.insert_char(c);
                Action::None
            }
            KeyCode::Backspace => {
                self.backspace();
                Action::None
            }
            KeyCode::Delete => {
                self.delete_forward();
                Action::None
            }
            KeyCode::Left => {
                self.move_left();
                Action::None
            }
            KeyCode::Right => {
                self.move_right();
                Action::None
            }
            KeyCode::Home => {
                self.cursor = 0;
                Action::None
            }
            KeyCode::End => {
                self.cursor = self.input.len();
                Action::None
            }
            KeyCode::Up => {
                self.history_prev();
                Action::None
            }
            KeyCode::Down => {
                self.history_next();
                Action::None
            }
            KeyCode::Tab => {
                self.complete_command();
                Action::None
            }
            KeyCode::Esc => {
                // 先取消待确认，再清空输入。
                if self.pending.take().is_some() {
                    self.status_line = "已取消".to_string();
                } else {
                    self.clear_input();
                    self.status_line.clear();
                }
                Action::None
            }
            KeyCode::Enter => self.on_enter(),
            _ => Action::None,
        }
    }

    /// 插入一个字符到光标处。
    fn insert_char(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        self.input.insert(self.cursor, c);
        self.cursor += c.len_utf8();
        self.status_line.clear();
    }

    /// 删除光标前一个字符。
    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let Some((index, _)) = self.input[..self.cursor].char_indices().next_back() else {
            self.cursor = 0;
            return;
        };
        self.input.remove(index);
        self.cursor = index;
    }

    /// 删除光标处一个字符（Delete 键）。
    fn delete_forward(&mut self) {
        if self.cursor >= self.input.len() {
            return;
        }
        self.input.remove(self.cursor);
    }

    /// 光标左移一个字符。
    fn move_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        if let Some((index, _)) = self.input[..self.cursor].char_indices().next_back() {
            self.cursor = index;
        }
    }

    /// 光标右移一个字符。
    fn move_right(&mut self) {
        if self.cursor >= self.input.len() {
            return;
        }
        if let Some((offset, c)) = self.input[self.cursor..].char_indices().next() {
            self.cursor += offset + c.len_utf8();
        }
    }

    /// `↑`：进入/继续历史搜索。首次按下时把当前输入固定为前缀。
    fn history_prev(&mut self) {
        let kind = self.history_kind();
        let prefix = match self.search_prefix.take() {
            Some(prefix) => prefix,
            None => self.input.clone(),
        };
        let entry = self.history.prev(kind, &prefix);
        if entry.is_empty() && self.input.is_empty() && self.history.is_empty(kind) {
            self.search_prefix = None;
            return;
        }
        self.search_prefix = Some(prefix);
        self.input = entry;
        self.cursor = self.input.len();
    }

    /// `↓`：回到更新的一条；走到底回到空输入行。
    fn history_next(&mut self) {
        let kind = self.history_kind();
        let entry = self.history.next(kind);
        if entry.is_empty() {
            self.search_prefix = None;
        }
        self.input = entry;
        self.cursor = self.input.len();
    }

    /// `Tab`：补全命令名。
    fn complete_command(&mut self) {
        let names = command::command_names(self.panel);
        let head: String = self
            .input
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        if head.is_empty() {
            self.status_line = names.join(" ");
            return;
        }
        let matches: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| name.starts_with(head.as_str()))
            .collect();
        match matches.as_slice() {
            [] => self.status_line = format!("没有以 \"{head}\" 开头的命令"),
            [single] => {
                self.input = format!("{single} ");
                self.cursor = self.input.len();
                self.status_line.clear();
            }
            many => self.status_line = many.join(" "),
        }
    }

    /// `Enter`：二次确认优先，否则记录历史并解析。
    fn on_enter(&mut self) -> Action {
        if self.pending.is_some() {
            return self.resolve_confirm();
        }
        let line = self.input.trim().to_string();
        self.clear_input();
        if line.is_empty() {
            return Action::None;
        }
        self.history.record(self.history_kind(), &line);
        match command::parse(self.panel, &line) {
            Err(err) => {
                self.status_line = err.to_string();
                self.push_log(format!("[命令错误] {err}"));
                Action::None
            }
            Ok(cmd) => {
                if cmd.is_destructive() {
                    self.status_line = format!("{} — 确认执行？(y/n)", cmd.confirm_prompt());
                    self.pending = Some(cmd);
                    Action::None
                } else {
                    self.status_line.clear();
                    self.push_log(format!("[命令] {line}"));
                    Action::Submit(cmd)
                }
            }
        }
    }

    /// 把输入当作 y/n 回答，结算待确认命令。
    fn resolve_confirm(&mut self) -> Action {
        let answer = self.input.trim().to_ascii_lowercase();
        self.clear_input();
        let Some(cmd) = self.pending.take() else {
            return Action::None;
        };
        if matches!(answer.as_str(), "y" | "yes") {
            self.status_line.clear();
            self.push_log(format!("[命令] {} (已确认)", cmd.name()));
            if matches!(cmd, Command::Exit) {
                Action::Quit
            } else {
                Action::Submit(cmd)
            }
        } else {
            self.status_line = format!("已取消 {}", cmd.name());
            Action::None
        }
    }
}

/// 节点角色文案。
#[must_use]
const fn role_label(kind: NodeKind) -> &'static str {
    if kind.is_admin() { "admin" } else { "agent" }
}

/// 查某节点的链路统计。
#[must_use]
fn link_for(snapshot: &Snapshot, node: NodeId) -> Option<&LinkStat> {
    snapshot.links.iter().find(|link| link.peer == node)
}

/// RTT 文案。
#[must_use]
fn rtt_label(link: Option<&LinkStat>) -> String {
    match link.and_then(|l| l.rtt_ms) {
        Some(ms) => format!("{ms}ms"),
        None => "-".to_string(),
    }
}

/// 状态列文案。
#[must_use]
fn status_label(link: Option<&LinkStat>) -> String {
    match link {
        None => "?".to_string(),
        Some(l) if l.missed == 0 => "ok".to_string(),
        Some(l) => format!("missed {}", l.missed),
    }
}

/// 构造主面板表格的一行。
#[must_use]
fn node_row(index: usize, app: &App, info: &NodeInfo) -> Row<'static> {
    let link = link_for(&app.snapshot, info.node);
    let focused = app.focus == Some(info.node);
    let row = Row::new(vec![
        index.to_string(),
        info.node.to_string(),
        role_label(info.kind).to_string(),
        info.parent.to_string(),
        info.depth.to_string(),
        rtt_label(link),
        status_label(link),
    ]);
    if focused {
        row.style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        row
    }
}

/// 顶部 banner：正常是一行版本串，降级时红底高亮。
fn draw_banner(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let (style, text) = if let Some(message) = &app.degraded {
        (
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
            format!(" [!] DEGRADED: {message}"),
        )
    } else {
        (
            Style::default().add_modifier(Modifier::REVERSED),
            format!(
                " stowaway-admin v{} | nodes:{} | epoch:{} | sessions:{} | undeliverable:{}",
                env!("CARGO_PKG_VERSION"),
                app.snapshot.nodes.len(),
                app.snapshot.epoch,
                app.snapshot.sessions,
                app.snapshot.undeliverable,
            ),
        )
    };
    frame.render_widget(Paragraph::new(text).style(style), area);
}

/// 主面板：节点列表（`Table`）。
fn draw_main_panel(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let title = match app.snapshot.root {
        Some(root) => format!(
            " Nodes ({})  root {}  depth {} ",
            app.snapshot.nodes.len(),
            root,
            app.snapshot.depth,
        ),
        None => format!(
            " Nodes ({})  root -  depth {} ",
            app.snapshot.nodes.len(),
            app.snapshot.depth,
        ),
    };
    let block = Block::bordered().title(title);

    if app.snapshot.nodes.is_empty() {
        let text = Text::from(vec![
            Line::from(""),
            Line::from(" (no nodes connected yet) "),
            Line::from(""),
            Line::from(" 用 `help` 查看命令，节点上线后 `use <node>` 进入其面板。"),
        ]);
        frame.render_widget(Paragraph::new(text).block(block), area);
        return;
    }

    let header = Row::new(vec![
        "#", "NodeId", "role", "parent", "depth", "rtt", "status",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row<'static>> = app
        .snapshot
        .nodes
        .iter()
        .enumerate()
        .map(|(index, info)| node_row(index, app, info))
        .collect();
    let widths = [
        Constraint::Length(3),
        Constraint::Length(21),
        Constraint::Length(7),
        Constraint::Length(21),
        Constraint::Length(5),
        Constraint::Length(9),
        Constraint::Min(10),
    ];
    let table = Table::new(rows, widths).header(header).block(block);
    frame.render_widget(table, area);
}

/// 节点详情（上半区）的文本行。
#[must_use]
fn detail_lines(app: &App) -> Vec<Line<'static>> {
    let Some(id) = app.focus else {
        return vec![
            Line::from(""),
            Line::from(" (no node selected) "),
            Line::from(""),
            Line::from(" 回主面板用 `back`，选节点需要先 `use <node>`。"),
        ];
    };
    let Some(info) = app.snapshot.nodes.iter().find(|info| info.node == id) else {
        return vec![
            Line::from(format!(" node     : {id}")),
            Line::from(" (该节点已不在当前快照里)"),
        ];
    };
    let link = link_for(&app.snapshot, info.node);
    let missed = link.map_or_else(|| "-".to_string(), |l| l.missed.to_string());
    vec![
        Line::from(format!(" node     : {}", info.node)),
        Line::from(format!(" parent   : {}", info.parent)),
        Line::from(format!(
            " depth    : {}    role: {}",
            info.depth,
            role_label(info.kind),
        )),
        Line::from(format!(
            " link     : rtt {}    missed {}",
            rtt_label(link),
            missed,
        )),
        Line::from(format!(" sessions : {}", app.snapshot.sessions)),
        Line::from(format!(
            " listen   : {}",
            info.listen.as_deref().unwrap_or("-"),
        )),
        Line::from(format!(
            " degraded : {}",
            app.degraded.as_deref().unwrap_or("no"),
        )),
    ]
}

/// 节点面板：上半详情 `Paragraph`，下半滚动日志。
fn draw_node_panel(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [detail_area, log_area] =
        Layout::vertical([Constraint::Length(9), Constraint::Min(3)]).areas(area);

    let detail_title = match app.focus {
        Some(id) => format!(" Node {id} "),
        None => " Node ".to_string(),
    };
    let detail = Paragraph::new(detail_lines(app)).block(Block::bordered().title(detail_title));
    frame.render_widget(detail, detail_area);

    let inner_height = usize::from(log_area.height.saturating_sub(2));
    let lines: Vec<Line<'static>> = if app.log.is_empty() {
        vec![Line::from(" (no log yet) ")]
    } else {
        let skip = app.log.len().saturating_sub(inner_height);
        app.log[skip..]
            .iter()
            .map(|line| Line::from(line.clone()))
            .collect()
    };
    let log_block = Block::bordered().title(format!(" Log ({}) ", app.log.len()));
    frame.render_widget(Paragraph::new(lines).block(log_block), log_area);
}

/// 底部：输入行 + 状态行，并把终端光标放到输入位置。
fn draw_input(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let [input_area, status_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);

    let prompt = app.prompt();
    let input_line = Line::from(vec![
        Span::styled(
            prompt.clone(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(app.input.clone()),
    ]);
    frame.render_widget(Paragraph::new(input_line), input_area);

    frame.render_widget(
        Paragraph::new(Line::from(app.status_line.clone()))
            .style(Style::default().fg(Color::Yellow)),
        status_area,
    );

    let typed = &app.input[..app.cursor];
    let offset = u16::try_from(Span::raw(prompt.as_str()).width() + Span::raw(typed).width())
        .unwrap_or(u16::MAX);
    let max_x = input_area.right().saturating_sub(1);
    let x = input_area.x.saturating_add(offset).min(max_x);
    frame.set_cursor_position(Position::new(x, input_area.y));
}

/// 画一帧。布局：banner(1) / 内容(≥3) / 输入行+状态行(2)。
pub fn draw(frame: &mut Frame<'_>, app: &App) {
    let [banner_area, body_area, input_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .areas(frame.area());

    draw_banner(frame, app, banner_area);
    match app.panel {
        Panel::Main => draw_main_panel(frame, app, body_area),
        Panel::Node => draw_node_panel(frame, app, body_area),
    }
    draw_input(frame, app, input_area);
}

#[cfg(test)]
mod tests {
    use super::*;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// 造一个稳定的测试节点 ID。
    fn nid(first: u8, second: u8) -> NodeId {
        let mut bytes = [0u8; 16];
        bytes[0] = first;
        bytes[1] = second;
        NodeId::new(bytes)
    }

    /// 根 admin + 两个 agent 的快照。
    fn sample_snapshot() -> Snapshot {
        let root = NodeId::ADMIN;
        let alpha = nid(0x00, 0x11);
        let beta = nid(0x00, 0x22);
        Snapshot {
            me: Some(root),
            root: Some(root),
            depth: 2,
            epoch: 7,
            nodes: vec![
                NodeInfo {
                    node: root,
                    parent: NodeId::UNASSIGNED,
                    depth: 0,
                    kind: NodeKind::Admin,
                    listen: None,
                },
                NodeInfo {
                    node: alpha,
                    parent: root,
                    depth: 1,
                    kind: NodeKind::Agent,
                    listen: Some("10.0.0.1:8080".to_string()),
                },
                NodeInfo {
                    node: beta,
                    parent: alpha,
                    depth: 2,
                    kind: NodeKind::Agent,
                    listen: None,
                },
            ],
            links: vec![
                LinkStat {
                    peer: alpha,
                    kind: NodeKind::Agent,
                    parent: root,
                    depth: 1,
                    rtt_ms: Some(12),
                    missed: 0,
                },
                LinkStat {
                    peer: beta,
                    kind: NodeKind::Agent,
                    parent: alpha,
                    depth: 2,
                    rtt_ms: Some(240),
                    missed: 2,
                },
            ],
            sessions: 3,
            undeliverable: 1,
        }
    }

    /// 渲染到 `TestBackend`，返回整屏文本 + 终端（用于再查光标）。
    fn render(app: &App, width: u16, height: u16) -> (String, Terminal<TestBackend>) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("TestBackend 初始化不该失败");
        terminal
            .draw(|frame| draw(frame, app))
            .expect("draw 不该失败");
        let text = terminal.backend().to_string();
        (text, terminal)
    }

    const WIDTH: u16 = 90;
    const HEIGHT: u16 = 24;

    #[test]
    fn main_panel_shows_empty_topology_placeholder() {
        let app = App::new();
        let (text, _terminal) = render(&app, WIDTH, HEIGHT);
        assert!(text.contains("Nodes (0)"), "空拓扑也要显示节点数: {text}");
        assert!(
            text.contains("no nodes connected yet"),
            "空拓扑要有占位提示: {text}"
        );
        assert!(
            text.contains("stowaway-admin v"),
            "banner 要有版本串: {text}"
        );
        assert!(text.contains(">> "), "输入行要有提示符: {text}");
    }

    #[test]
    fn main_panel_lists_three_nodes() {
        let mut app = App::with_snapshot(sample_snapshot());
        app.focus = Some(nid(0x00, 0x11));
        let (text, _terminal) = render(&app, WIDTH, HEIGHT);
        assert!(text.contains("Nodes (3)"), "节点数: {text}");
        assert!(text.contains("NodeId(ADMIN)"), "root 行: {text}");
        assert!(text.contains("NodeId(00110000)"), "alpha 行: {text}");
        assert!(text.contains("NodeId(00220000)"), "beta 行: {text}");
        assert!(text.contains("12ms"), "RTT 列: {text}");
        assert!(text.contains("240ms"), "RTT 列: {text}");
        assert!(text.contains("missed 2"), "missed 列: {text}");
        assert!(text.contains("depth"), "表头: {text}");
    }

    #[test]
    fn node_panel_shows_detail_and_log() {
        let mut app = App::with_snapshot(sample_snapshot());
        app.focus_node(Some(nid(0x00, 0x11)));
        app.push_log("[test] first");
        app.push_log("[test] second");
        let (text, _terminal) = render(&app, WIDTH, HEIGHT);
        assert!(
            text.contains("(node NodeId(00110000)) >> "),
            "提示符: {text}"
        );
        assert!(text.contains("sessions : 3"), "详情要有 sessions: {text}");
        assert!(text.contains("link     : rtt 12ms"), "详情要有 RTT: {text}");
        assert!(text.contains("role: agent"), "详情要有角色: {text}");
        assert!(text.contains("Log (2)"), "日志块标题: {text}");
        assert!(text.contains("[test] second"), "日志内容: {text}");
    }

    #[test]
    fn degraded_banner_is_red_and_visible() {
        let mut app = App::new();
        app.set_degraded(Some("transport closed by peer".to_string()));
        let (text, terminal) = render(&app, WIDTH, HEIGHT);
        assert!(text.contains("DEGRADED"), "降级文案: {text}");
        assert!(
            text.contains("transport closed by peer"),
            "降级文案要带原因: {text}"
        );
        let background = terminal.backend().buffer()[(0, 0)].bg;
        assert_eq!(background, Color::Red, "降级 banner 必须红底");
    }

    #[test]
    fn log_keeps_only_tail_and_trims_to_capacity() {
        let mut app = App::with_snapshot(sample_snapshot());
        app.focus_node(Some(nid(0x00, 0x11)));
        for index in 0..600 {
            app.push_log(format!("log-line-{index:03}"));
        }
        assert_eq!(app.log.len(), MAX_LOG_LINES, "日志要裁剪到上限");
        let (text, _terminal) = render(&app, WIDTH, HEIGHT);
        assert!(text.contains("log-line-599"), "要显示最新一条: {text}");
        assert!(
            !text.contains("log-line-000"),
            "最旧的日志应已被裁掉: {text}"
        );
    }

    #[test]
    fn input_line_shows_prompt_and_places_cursor() {
        let mut app = App::new();
        app.input = "use 1".to_string();
        app.cursor = app.input.len();
        let (text, terminal) = render(&app, WIDTH, HEIGHT);
        assert!(text.contains(">> use 1"), "输入行内容: {text}");
        let position = terminal.backend().cursor_position();
        assert_eq!(position.y, HEIGHT - 2, "光标应在输入行");
        assert_eq!(position.x, 3 + 5, "光标应在输入末尾: {position:?}");
        assert!(terminal.backend().cursor_visible(), "光标必须可见");
    }

    #[test]
    fn layout_uses_three_vertical_bands() {
        let mut app = App::with_snapshot(sample_snapshot());
        app.focus_node(Some(nid(0x00, 0x11)));
        let (_text, terminal) = render(&app, WIDTH, HEIGHT);
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer.area.height, HEIGHT);
        // 三块竖直带：第 0 行是 banner，最后一行是状态行，中间是内容。
        let row_text = |y: u16| -> String {
            (0..WIDTH)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        };
        assert!(
            row_text(0).contains("stowaway-admin"),
            "第 0 行应是 banner：{:?}",
            row_text(0)
        );
        assert!(
            row_text(HEIGHT - 1).trim().is_empty(),
            "最后一行是状态行（此处为空）"
        );
        assert!(
            row_text(HEIGHT - 2).contains(">>"),
            "倒数第 2 行应是输入行：{:?}",
            row_text(HEIGHT - 2)
        );
        assert!(row_text(2).contains('│'), "中部内容区应从第 1 行开始画边框");
    }

    // ---- 按键行为 ----

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_str(app: &mut App, text: &str) {
        for c in text.chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
    }

    #[test]
    fn typing_moves_cursor_and_escape_clears() {
        let mut app = App::new();
        type_str(&mut app, "use");
        assert_eq!(app.input, "use");
        assert_eq!(app.cursor, 3);
        let action = app.on_key(key(KeyCode::Esc));
        assert_eq!(action, Action::None);
        assert!(app.input.is_empty());
        assert_eq!(app.cursor, 0);
    }

    #[test]
    fn backspace_deletes_previous_character_only() {
        let mut app = App::new();
        type_str(&mut app, "topo");
        app.on_key(key(KeyCode::Left));
        app.on_key(key(KeyCode::Backspace));
        assert_eq!(app.input, "too", "删的是光标前那个字符（'p'）");
        assert_eq!(app.cursor, 2);
        app.on_key(key(KeyCode::Backspace));
        assert_eq!(app.input, "to");
        assert_eq!(app.cursor, 1);
        app.on_key(key(KeyCode::Backspace));
        assert_eq!(app.input, "o");
        assert_eq!(app.cursor, 0);
        // 光标已在行首，再退格应无副作用且不 panic。
        app.on_key(key(KeyCode::Backspace));
        assert_eq!(app.input, "o", "行首退格不该 panic");
        assert_eq!(app.cursor, 0);
    }

    #[test]
    fn enter_submits_parsed_command() {
        let mut app = App::new();
        type_str(&mut app, "topo");
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(action, Action::Submit(Command::Topo));
        assert!(app.input.is_empty(), "提交后清空输入行");
        assert_eq!(app.history.len(HistoryKind::Normal), 1, "提交要入历史");
    }

    #[test]
    fn enter_on_bad_command_reports_error_without_submit() {
        let mut app = App::new();
        type_str(&mut app, "bogus");
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(action, Action::None);
        assert!(
            app.status_line.contains("bogus") || app.status_line.contains("未知命令"),
            "状态行要报错: {}",
            app.status_line
        );
        assert!(!app.log.is_empty(), "错误也要进日志");
    }

    #[test]
    fn up_and_down_walk_history() {
        let mut app = App::new();
        app.history.record(HistoryKind::Normal, "topo");
        app.history.record(HistoryKind::Normal, "help");
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.input, "help", "↑ 先回最新一条");
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.input, "topo", "再 ↑ 回更旧一条");
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.input, "topo", "到顶停住，不 wrap");
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.input, "help");
        app.on_key(key(KeyCode::Down));
        assert!(app.input.is_empty(), "到底回到空输入行");
        assert_eq!(app.cursor, 0);
    }

    #[test]
    fn up_on_empty_history_does_not_panic() {
        let mut app = App::new();
        app.on_key(key(KeyCode::Up));
        assert!(app.input.is_empty());
        app.on_key(key(KeyCode::Down));
        assert!(app.input.is_empty());
    }

    #[test]
    fn tab_completes_unique_command_prefix() {
        let mut app = App::new();
        type_str(&mut app, "top");
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.input, "topo ", "唯一前缀要补全并加空格");
        assert_eq!(app.cursor, app.input.len());
    }

    #[test]
    fn destructive_command_waits_for_confirmation() {
        let mut app = App::with_snapshot(sample_snapshot());
        app.focus_node(Some(nid(0x00, 0x11)));
        type_str(&mut app, "shutdown");
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(action, Action::None, "shutdown 不能直接执行");
        assert_eq!(app.pending_confirm(), Some(&Command::Shutdown));
        assert!(app.status_line.contains("(y/n)"), "要有 y/n 提示");
        type_str(&mut app, "y");
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(action, Action::Submit(Command::Shutdown));
        assert!(app.pending_confirm().is_none());
    }

    #[test]
    fn destructive_command_can_be_cancelled() {
        let mut app = App::with_snapshot(sample_snapshot());
        app.focus_node(Some(nid(0x00, 0x11)));
        type_str(&mut app, "stopsocks");
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::None);
        type_str(&mut app, "n");
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::None);
        assert!(app.pending_confirm().is_none());
        assert!(app.status_line.contains("已取消"), "{}", app.status_line);
    }

    #[test]
    fn confirmed_exit_quits() {
        let mut app = App::new();
        type_str(&mut app, "exit");
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::None, "exit 要确认");
        type_str(&mut app, "y");
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::Quit);
    }

    #[test]
    fn ctrl_c_quits_immediately() {
        let mut app = App::new();
        let action = app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert_eq!(action, Action::Quit);
    }

    #[test]
    fn key_release_events_are_ignored() {
        let mut app = App::new();
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('x'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert_eq!(app.on_key(release), Action::None);
        assert!(app.input.is_empty());
    }

    #[test]
    fn prompt_depends_on_panel_and_focus() {
        let mut app = App::new();
        assert_eq!(app.prompt(), ">> ");
        app.focus_node(Some(nid(0x00, 0x11)));
        assert_eq!(app.prompt(), "(node NodeId(00110000)) >> ");
        app.back_to_main();
        assert_eq!(app.panel, Panel::Main);
        assert_eq!(app.prompt(), ">> ");
    }
}
