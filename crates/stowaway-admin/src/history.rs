//! 命令历史：三份独立的环形历史 + 前缀搜索。
//!
//! 对应 Go v1 `admin/cli/history.go`（189 行）：v1 用 `container/list` 维护
//! `normal` / `shell` / `ssh` 三份历史，每份 `capacity = 100`，超过
//! `capacity * 2` 才裁剪回 `capacity`（避免每条命令都裁剪）。搜索用
//! `BEGIN` / `PREV` / `NEXT` 三态移动指针，并按前缀过滤。
//!
//! 与 v1 的两处有意差异：
//!
//! 1. v1 靠 `chan` + goroutine 串行化，读取结果时若列表为空会阻塞；v1 后来
//!    专门打补丁「列表为空时立刻回 `""`」。Rust 侧是同步方法，天然不会阻塞，
//!    但仍然保证空历史返回空串（`prev` / `next` 都不会 panic）。
//! 2. v1 的 `now` 指针在裁剪后可能悬空，Rust 侧用索引 + 裁剪时重置指针规避。
//!
//! 本模块**不依赖 ratatui**，`--no-default-features` 下也可编译。

/// 历史类别：普通控制台 / shell 子模式 / ssh 子模式。
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum HistoryKind {
    /// 控制台命令（主面板 + 节点面板共用）。
    #[default]
    Normal,
    /// shell 子模式里敲的原始命令。
    Shell,
    /// ssh 子模式里敲的原始命令。
    Ssh,
}

impl HistoryKind {
    /// 三份历史的固定顺序，便于遍历与测试。
    pub const ALL: [Self; 3] = [Self::Normal, Self::Shell, Self::Ssh];

    /// 稳定短名（日志 / 调试用）。
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Shell => "shell",
            Self::Ssh => "ssh",
        }
    }
}

/// 单份历史。`entries` 按时间顺序存放（`entries[0]` 最旧，末尾最新）。
#[derive(Clone, Debug)]
struct HistoryList {
    /// 旧 → 新。
    entries: Vec<String>,
    /// 搜索游标：`Some(i)` 表示当前停在 `entries[i]`，`None` 表示在输入行上。
    cursor: Option<usize>,
    /// 容量上限（裁剪目标）。
    capacity: usize,
}

impl HistoryList {
    fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            cursor: None,
            capacity: capacity.max(1),
        }
    }

    /// 记一条。空白忽略；与最新一条完全相同时去重（连续重复不入库）。
    fn record(&mut self, cmd: &str) {
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return;
        }
        if self.entries.last().is_some_and(|last| last == cmd) {
            return;
        }
        self.entries.push(cmd.to_owned());
        // v1 语义：超过 capacity*2 才裁剪回 capacity，避免每条命令都裁剪。
        if self.entries.len() > self.capacity * 2 {
            let excess = self.entries.len() - self.capacity;
            self.entries.drain(..excess);
        }
        // 裁剪会移动下标，游标一律重置，避免指向错位/越界。
        self.cursor = None;
    }

    fn reset_search(&mut self) {
        self.cursor = None;
    }

    /// 向更旧方向找第一个以 `prefix` 开头的条目。
    ///
    /// - 未在搜索态时从最新一条往旧扫；
    /// - 已在搜索态时从当前条目往旧扫；
    /// - 到顶（再无更旧匹配）时停在当前条目（不 wrap）。
    fn prev(&mut self, prefix: &str) -> String {
        if self.entries.is_empty() {
            self.cursor = None;
            return String::new();
        }
        let Some(cur) = self.cursor else {
            for idx in (0..self.entries.len()).rev() {
                if self.entries[idx].starts_with(prefix) {
                    self.cursor = Some(idx);
                    return self.entries[idx].clone();
                }
            }
            return String::new();
        };
        for idx in (0..cur).rev() {
            if self.entries[idx].starts_with(prefix) {
                self.cursor = Some(idx);
                return self.entries[idx].clone();
            }
        }
        // 到顶：停在最旧那条，不 wrap。
        self.entries[cur].clone()
    }

    /// 向更新方向走一格；越过最新一条后回到输入行并返回空串。
    fn next(&mut self) -> String {
        let Some(cur) = self.cursor else {
            return String::new();
        };
        let next = cur + 1;
        if next >= self.entries.len() {
            self.cursor = None;
            return String::new();
        }
        self.cursor = Some(next);
        self.entries[next].clone()
    }
}

/// 三份独立历史。
#[derive(Clone, Debug)]
pub struct History {
    normal: HistoryList,
    shell: HistoryList,
    ssh: HistoryList,
}

impl History {
    /// 每份历史的容量（v1 同样取 100）。
    pub const CAPACITY: usize = 100;

    /// 新建三份空历史。
    #[must_use]
    pub fn new() -> Self {
        Self {
            normal: HistoryList::new(Self::CAPACITY),
            shell: HistoryList::new(Self::CAPACITY),
            ssh: HistoryList::new(Self::CAPACITY),
        }
    }

    const fn list(&self, kind: HistoryKind) -> &HistoryList {
        match kind {
            HistoryKind::Normal => &self.normal,
            HistoryKind::Shell => &self.shell,
            HistoryKind::Ssh => &self.ssh,
        }
    }

    const fn list_mut(&mut self, kind: HistoryKind) -> &mut HistoryList {
        match kind {
            HistoryKind::Normal => &mut self.normal,
            HistoryKind::Shell => &mut self.shell,
            HistoryKind::Ssh => &mut self.ssh,
        }
    }

    /// 记一条命令。空白命令忽略；与最新一条相同则去重。
    pub fn record(&mut self, kind: HistoryKind, cmd: &str) {
        self.list_mut(kind).record(cmd);
    }

    /// 重置搜索游标（每次从输入行重新进入历史搜索时调用）。
    pub fn reset_search(&mut self, kind: HistoryKind) {
        self.list_mut(kind).reset_search();
    }

    /// 向更旧方向找第一条以 `prefix` 开头的命令；历史为空或无匹配时返回空串。
    pub fn prev(&mut self, kind: HistoryKind, prefix: &str) -> String {
        self.list_mut(kind).prev(prefix)
    }

    /// 向更新方向走一格；走到底返回空串（代表当前输入行）。
    pub fn next(&mut self, kind: HistoryKind) -> String {
        self.list_mut(kind).next()
    }

    /// 某份历史的内容，按时间顺序（旧 → 新）。
    #[must_use]
    pub fn entries(&self, kind: HistoryKind) -> Vec<&str> {
        self.list(kind).entries.iter().map(String::as_str).collect()
    }

    /// 某份历史的条目数。
    #[must_use]
    pub fn len(&self, kind: HistoryKind) -> usize {
        self.list(kind).entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self, kind: HistoryKind) -> bool {
        self.list(kind).entries.is_empty()
    }

    /// 某份历史的容量上限。
    #[must_use]
    pub const fn capacity(&self, kind: HistoryKind) -> usize {
        self.list(kind).capacity
    }
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: HistoryKind = HistoryKind::Normal;
    const S: HistoryKind = HistoryKind::Shell;
    const H: HistoryKind = HistoryKind::Ssh;

    #[test]
    fn new_history_is_empty_for_all_kinds() {
        let mut hist = History::new();
        for kind in HistoryKind::ALL {
            assert_eq!(hist.len(kind), 0);
            assert!(hist.is_empty(kind));
            assert_eq!(hist.capacity(kind), History::CAPACITY);
            assert!(hist.entries(kind).is_empty());
            // 空历史必须返回空串而不是阻塞 / panic。
            assert_eq!(hist.prev(kind, ""), "");
            assert_eq!(hist.next(kind), "");
        }
        // 再确认一次：空历史的 prev 带具体前缀也不 panic。
        assert_eq!(hist.prev(N, "anything"), "");
    }

    #[test]
    fn prev_on_empty_history_returns_empty_string() {
        let mut hist = History::new();
        assert_eq!(hist.prev(N, ""), "");
        assert_eq!(hist.prev(N, "u"), "");
        assert_eq!(hist.next(N), "");
        // 空历史多次按键依旧不 panic。
        for _ in 0..5 {
            assert_eq!(hist.prev(N, ""), "");
            assert_eq!(hist.next(N), "");
        }
    }

    #[test]
    fn record_ignores_blank_commands() {
        let mut hist = History::new();
        hist.record(N, "");
        hist.record(N, "   ");
        hist.record(N, "\t\t");
        assert_eq!(hist.len(N), 0);
        assert!(hist.is_empty(N));
    }

    #[test]
    fn record_dedupes_consecutive_duplicates() {
        let mut hist = History::new();
        hist.record(N, "detail");
        hist.record(N, "detail");
        hist.record(N, "detail");
        assert_eq!(hist.len(N), 1);
        hist.record(N, "topo");
        hist.record(N, "topo");
        assert_eq!(hist.entries(N), vec!["detail", "topo"]);
        // 非连续重复仍要入库。
        hist.record(N, "detail");
        assert_eq!(hist.entries(N), vec!["detail", "topo", "detail"]);
    }

    #[test]
    fn entries_are_in_chronological_order() {
        let mut hist = History::new();
        for cmd in ["topo", "detail", "help"] {
            hist.record(N, cmd);
        }
        assert_eq!(hist.entries(N), vec!["topo", "detail", "help"]);
        assert_eq!(hist.len(N), 3);
    }

    #[test]
    fn prev_walks_from_newest_to_oldest() {
        let mut hist = History::new();
        for cmd in ["a1", "a2", "a3"] {
            hist.record(N, cmd);
        }
        assert_eq!(hist.prev(N, ""), "a3");
        assert_eq!(hist.prev(N, ""), "a2");
        assert_eq!(hist.prev(N, ""), "a1");
    }

    #[test]
    fn prev_stops_at_oldest_without_wrapping() {
        let mut hist = History::new();
        for cmd in ["x1", "x2"] {
            hist.record(N, cmd);
        }
        assert_eq!(hist.prev(N, ""), "x2");
        assert_eq!(hist.prev(N, ""), "x1");
        // 到顶：停在最旧那条，不 wrap 回最新的 x2。
        assert_eq!(hist.prev(N, ""), "x1");
        assert_eq!(hist.prev(N, ""), "x1");
    }

    #[test]
    fn prev_filters_by_prefix() {
        let mut hist = History::new();
        for cmd in ["use 1", "detail", "use 3", "topo", "use 5"] {
            hist.record(N, cmd);
        }
        assert_eq!(hist.prev(N, "use"), "use 5");
        assert_eq!(hist.prev(N, "use"), "use 3");
        assert_eq!(hist.prev(N, "use"), "use 1");
        // 到顶后仍停在最旧的匹配项。
        assert_eq!(hist.prev(N, "use"), "use 1");
    }

    #[test]
    fn prev_returns_empty_when_prefix_never_matches() {
        let mut hist = History::new();
        hist.record(N, "detail");
        hist.record(N, "topo");
        assert_eq!(hist.prev(N, "zzz"), "");
        // 无匹配时不应把游标推进到某个条目上。
        assert_eq!(hist.prev(N, ""), "topo");
    }

    #[test]
    fn next_walks_back_to_current_line() {
        let mut hist = History::new();
        for cmd in ["b1", "b2", "b3"] {
            hist.record(N, cmd);
        }
        assert_eq!(hist.prev(N, ""), "b3");
        assert_eq!(hist.prev(N, ""), "b2");
        assert_eq!(hist.prev(N, ""), "b1");
        assert_eq!(hist.next(N), "b2");
        assert_eq!(hist.next(N), "b3");
        // 走到底：回到输入行（空串）。
        assert_eq!(hist.next(N), "");
        assert_eq!(hist.next(N), "");
        // 回到输入行后再 Up，应从最新一条重新开始。
        assert_eq!(hist.prev(N, ""), "b3");
    }

    #[test]
    fn three_histories_are_independent() {
        let mut hist = History::new();
        hist.record(N, "normal-a");
        hist.record(S, "shell-a");
        hist.record(H, "ssh-a");
        assert_eq!(hist.entries(N), vec!["normal-a"]);
        assert_eq!(hist.entries(S), vec!["shell-a"]);
        assert_eq!(hist.entries(H), vec!["ssh-a"]);
        // 一份历史里的搜索游标不影响另外两份。
        assert_eq!(hist.prev(S, ""), "shell-a");
        assert_eq!(hist.prev(S, ""), "shell-a");
        assert_eq!(hist.prev(N, ""), "normal-a");
        assert_eq!(hist.prev(H, ""), "ssh-a");
        assert_eq!(hist.next(N), "");
        assert_eq!(hist.next(S), "");
    }

    #[test]
    fn reset_search_restarts_from_newest() {
        let mut hist = History::new();
        for cmd in ["c1", "c2", "c3"] {
            hist.record(N, cmd);
        }
        assert_eq!(hist.prev(N, ""), "c3");
        assert_eq!(hist.prev(N, ""), "c2");
        hist.reset_search(N);
        assert_eq!(hist.prev(N, ""), "c3");
    }

    #[test]
    fn trimming_keeps_capacity_and_search_still_works() {
        let mut hist = History::new();
        // 塞满 2*capacity 条：触发一次裁剪回 capacity。
        for i in 0..History::CAPACITY * 2 {
            hist.record(N, &format!("cmd-{i:03}"));
        }
        // 恰好 2*capacity 条时还没裁剪（v1 用 `>` 而不是 `>=`）。
        assert_eq!(hist.len(N), History::CAPACITY * 2);
        hist.record(N, "overflow");
        assert_eq!(hist.len(N), History::CAPACITY);
        // 裁剪掉的是最旧的一批：最新的 "overflow" 仍在，最旧的 cmd-000 没了。
        let entries = hist.entries(N);
        assert_eq!(entries.last().copied(), Some("overflow"));
        assert!(entries.contains(&"cmd-199"));
        assert!(!entries.contains(&"cmd-000"));
        assert_eq!(hist.entries(N).len(), History::CAPACITY);
        // 裁剪后仍可正常搜索，游标不会越界。
        assert_eq!(hist.prev(N, ""), "overflow");
        assert_eq!(hist.prev(N, ""), "cmd-199");
        hist.reset_search(N);
        assert_eq!(hist.prev(N, "cmd-1"), "cmd-199");
        assert_eq!(hist.prev(N, "cmd-1"), "cmd-198");
        // 最旧的一批已被裁掉，往回走到底不会越界。
        for _ in 0..History::CAPACITY * 2 {
            let got = hist.prev(N, "");
            assert!(!got.is_empty());
        }
    }

    #[test]
    fn capacity_is_one_hundred_like_v1() {
        assert_eq!(History::CAPACITY, 100);
        let hist = History::new();
        assert_eq!(hist.capacity(N), 100);
        assert_eq!(hist.capacity(S), 100);
        assert_eq!(hist.capacity(H), 100);
    }

    #[test]
    fn record_after_search_resets_cursor() {
        let mut hist = History::new();
        hist.record(N, "e1");
        hist.record(N, "e2");
        assert_eq!(hist.prev(N, ""), "e2");
        hist.record(N, "e3");
        // 游标已重置，next 直接回到输入行；prev 从最新开始。
        assert_eq!(hist.next(N), "");
        assert_eq!(hist.prev(N, ""), "e3");
    }

    #[test]
    fn kind_labels_and_default() {
        assert_eq!(HistoryKind::default(), HistoryKind::Normal);
        assert_eq!(HistoryKind::Normal.label(), "normal");
        assert_eq!(HistoryKind::Shell.label(), "shell");
        assert_eq!(HistoryKind::Ssh.label(), "ssh");
        assert_eq!(HistoryKind::ALL.len(), 3);
    }
}
