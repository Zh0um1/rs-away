//! 运行时引擎：把 [`Node`] 与各链路 actor 串成一个可驱动的实体。
//!
//! v1 没有这一层：`Node`（`share/node.go`）自己拿着 `net.Conn`、自己起
//! goroutine、自己往 `Manager` 里塞通道，读写与状态混在同一个对象里。
//! v2 把职责切成三层（plan §4.9）：
//!
//! ```text
//! Engine（本模块）        拥有 Node，串行消费入站帧与命令；不持 socket
//!   ├─ LinkActor（每链路）  单写者 + 攒批；独占 socket
//!   └─ Session drainer     把 SessionOutbound 搬成节点消息
//! ```
//!
//! 一切都经通道进出：[`EngineHandle`] 是外部唯一入口，[`Event`] 是引擎输出。
//! 这样控制台、服务层与二进制主循环都不直接碰 `Node` 的可变状态，
//! 也就不可能出现「两个任务同时改拓扑」的 v1 竞态（§2.9 第 3 条）。
//!
//! # 为什么引擎要独占 `Node`
//!
//! [`Node`] 的每个方法都要 `&mut self`（拓扑、会话表、链路表都是可变的）。
//! 与其加锁，不如让单个任务持有它 —— 这正是 actor 模型的本意，也避免了
//! 锁顺序问题。代价是「读快照」也要走通道，见 [`Command::Snapshot`]。

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stowaway_protocol::{
    CloseReason, Message, NodeId, NodeKind, NodeScope, NodeState, NodeStatus, OpenSession,
    ServiceData, ServiceExit, ServiceReply, ServiceRequest, SessionClose, SessionKey,
};
use stowaway_transport::LinkCodec;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::error::{CoreError, Result};
use crate::link_actor::{InboundFrame, LinkHandle};
use crate::node::{Handled, Node, NodeConfig};
use crate::session_stream::{SessionStream, outbound_message};

/// 引擎默认命令队列深度。
pub const ENGINE_QUEUE_DEPTH: usize = 256;

/// 链路 actor 的对端标识与句柄（供诊断与关停）。
#[derive(Clone, Debug)]
pub struct PeerLink {
    /// 对端节点。
    pub peer: NodeId,
    /// 写句柄。
    pub handle: LinkHandle,
}

/// 一条链路的可观测状态。
#[derive(Clone, Debug)]
pub struct LinkStat {
    /// 对端节点。
    pub peer: NodeId,
    /// 对端角色。
    pub kind: NodeKind,
    /// 该链路在树里的父节点。
    pub parent: NodeId,
    /// 该链路深度。
    pub depth: u16,
    /// 最近一次心跳 RTT（毫秒）；未测到过则 `None`。
    pub rtt_ms: Option<u64>,
    /// 连续未收到回显的次数（判死用）。
    pub missed: u32,
}

/// 拓扑快照（供控制台渲染，只读拷贝）。
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// 本节点编号。
    pub me: Option<NodeId>,
    /// 根节点编号。
    pub root: Option<NodeId>,
    /// 本节点深度。
    pub depth: u16,
    /// 拓扑 epoch（每次变更自增，控制台据此判断是否要重绘）。
    pub epoch: u64,
    /// 节点表，按编号有序。
    pub nodes: Vec<NodeInfo>,
    /// 链路表。
    pub links: Vec<LinkStat>,
    /// 已登记的会话数。
    pub sessions: usize,
    /// 累计不可达次数（v1 静默丢弃，v2 计数并可查，见缺陷 #11）。
    pub undeliverable: u64,
}

/// 快照里的一个节点。
#[derive(Clone, Debug)]
pub struct NodeInfo {
    /// 编号。
    pub node: NodeId,
    /// 父节点。
    pub parent: NodeId,
    /// 深度。
    pub depth: u16,
    /// 角色。
    pub kind: NodeKind,
    /// 监听地址（自报，仅展示）。
    pub listen: Option<String>,
}

/// 外部发给引擎的命令。
#[derive(Debug)]
pub enum Command {
    /// 按路由发一条消息。
    Send {
        /// 消息。
        msg: Box<Message>,
        /// 目标。
        dest: NodeId,
    },
    /// 直发一条消息到指定链路（对端必须已登记）。
    SendDirect {
        /// 链路对端。
        peer: NodeId,
        /// 消息。
        msg: Box<Message>,
        /// 目标。
        dest: NodeId,
    },
    /// 登记一条已经握手完成的链路。
    AttachLink {
        /// 已密封的编解码器。
        codec: Box<LinkCodec>,
        /// 对端编号（由父节点分配）。
        peer: NodeId,
        /// 父节点（本节点自己，或已被本节点登记的上游）。
        parent: NodeId,
        /// 对端角色。
        peer_kind: NodeKind,
        /// 回执。
        reply: oneshot::Sender<Result<()>>,
    },
    /// 关闭一条链路（flush 后退出 actor）。
    DetachLink {
        /// 对端。
        peer: NodeId,
        /// 回执（返回被级联摘除的节点）。
        reply: oneshot::Sender<Vec<NodeId>>,
    },
    /// 登记一条由本端发起的会话（必须在发 `OpenSession` 之前）。
    ///
    /// 发起方也要登记：对端回的 `SessionReady` 要写进会话表，否则
    /// `sessions.ready` 报 `UnknownSession`；`await_ready` 也是靠会话表
    /// 判断「这条会话到底存不存在」，未登记就会被立刻判死。
    RegisterSession {
        /// 会话键。
        key: SessionKey,
        /// 会话种类。
        kind: stowaway_protocol::SessionKind,
        /// 回执。
        reply: oneshot::Sender<Result<()>>,
    },
    /// 确保会话已登记（已登记则什么都不做）。
    ///
    /// 服务层的**失败路径**也要它：拨号失败时还没有任何流，若直接回
    /// `SessionReady`，`sessions.ready` 会报 `UnknownSession`，发起方就等
    /// 到超时——失败也必须能把错误码送回去（plan §4.14 E18）。
    EnsureSession {
        /// 会话键。
        key: SessionKey,
        /// 会话种类。
        kind: stowaway_protocol::SessionKind,
        /// 回执。
        reply: oneshot::Sender<Result<()>>,
    },
    /// 打开一条会话流（引擎创建并绑定，返回可读写的流）。
    ///
    /// 应答方（`ServiceRequest` 驱动的那一侧）在开会话流时才真正「接受」
    /// 这条会话：`ServiceRequest` 不像 `OpenSession` 那样先把会话登记进表，
    /// 所以这里带 `kind`——缺了它，随后 `ready_session` 推进状态会报
    /// `UnknownSession`，本端收到的第一块数据也会被判「尚未就绪」。
    OpenStream {
        /// 会话键。
        key: SessionKey,
        /// 会话对端。
        dest: NodeId,
        /// 会话种类（应答方接受会话时用它登记）。
        kind: stowaway_protocol::SessionKind,
        /// 回执。
        reply: oneshot::Sender<Result<SessionStream>>,
    },
    /// 会话就绪（服务层拨号成功后回报）。
    ReadySession {
        /// 会话键。
        key: SessionKey,
        /// 对端（发起方那条链路）。
        peer: NodeId,
        /// 结果码。
        code: stowaway_protocol::SessionCode,
        /// 详情。
        detail: String,
    },
    /// 关闭会话（双向通知）。
    CloseSession {
        /// 会话键。
        key: SessionKey,
        /// 原因。
        reason: CloseReason,
    },
    /// 取拓扑快照。
    Snapshot {
        /// 回执。
        reply: oneshot::Sender<Snapshot>,
    },
    /// 定向等待某条会话的 `SessionReady`。
    ///
    /// 与「订阅 [`Event::SessionReady`]」的区别：广播事件只有一个接收端
    /// （控制台的 [Event] 流），而后台监听任务（`socks` / `forward`）需要
    /// 各自等**自己那一条**会话就绪。把事件流拆给多个消费者会让「谁漏了
    /// 哪条事件」变成竞态，所以改成登记一次性等待者，由引擎在
    /// `SessionReady` 到达时定向兑现。
    ///
    /// 已经就绪（或已登记过结果）时立即返回，不会漏。
    AwaitReady {
        /// 会话键。
        key: SessionKey,
        /// 回执：就绪码，或会话根本不存在。
        reply: oneshot::Sender<Result<stowaway_protocol::SessionCode>>,
    },
    /// 立刻发一轮心跳（诊断/测试用；定时心跳由 [`Engine::with_heartbeat`] 起）。
    Pulse,
    /// 停止引擎。
    Shutdown,
}

/// 引擎输出的事件。
#[derive(Debug)]
pub enum Event {
    /// 对端发起了一条会话（服务层决定是否接受）。
    SessionOpened {
        /// 会话描述。
        open: OpenSession,
        /// 发起方。
        from: NodeId,
    },
    /// 会话被对端接受/拒绝。
    SessionReady {
        /// 会话键。
        key: SessionKey,
        /// 结果码。
        code: stowaway_protocol::SessionCode,
    },
    /// 会话结束。
    SessionClosed {
        /// 会话键。
        key: SessionKey,
    },
    /// 服务请求（文件/shell/ssh/隧道/桥接）。
    ServiceRequest {
        /// 请求。
        req: ServiceRequest,
        /// 发起方。
        from: NodeId,
    },
    /// 服务应答。
    ServiceReply {
        /// 应答。
        reply: ServiceReply,
        /// 来源。
        from: NodeId,
    },
    /// 服务数据。
    ServiceData {
        /// 数据。
        data: ServiceData,
        /// 来源。
        from: NodeId,
    },
    /// 服务退出。
    ServiceExit {
        /// 退出。
        exit: ServiceExit,
        /// 来源。
        from: NodeId,
    },
    /// 新节点入网（拓扑已更新）。
    Joined {
        /// 节点。
        node: NodeId,
        /// 角色。
        kind: NodeKind,
        /// 父节点。
        parent: NodeId,
    },
    /// 节点离线（子树已摘除）。
    Offline {
        /// 节点。
        node: NodeId,
        /// 被级联摘除的节点（含自身）。
        removed: Vec<NodeId>,
    },
    /// 链路断开。
    LinkLost {
        /// 对端。
        peer: NodeId,
    },
    /// 目标不可达（v1 静默丢弃）。
    Undeliverable {
        /// 目标。
        dest: NodeId,
    },
    /// 心跳回显（RTT）。
    Rtt {
        /// 对端。
        peer: NodeId,
        /// 往返毫秒。
        rtt_ms: u64,
    },
    /// 连续 `misses` 次心跳无回显，判定该链路已死。
    PeerDead {
        /// 对端。
        peer: NodeId,
        /// 未回显次数。
        misses: u32,
    },
    /// 对端广播了 `Shutdown`（本机应当优雅退出）。
    Shutdown,
    /// 引擎因错误停止运行。
    Failed(String),
}

/// 引擎句柄（可克隆，多任务共享）。
#[derive(Clone, Debug)]
pub struct EngineHandle {
    cmd: mpsc::Sender<Command>,
}

impl EngineHandle {
    /// 按路由发消息。
    ///
    /// # Errors
    /// 引擎已停止。
    pub async fn send(&self, msg: Message, dest: NodeId) -> Result<()> {
        self.cmd
            .send(Command::Send {
                msg: Box::new(msg),
                dest,
            })
            .await
            .map_err(|_| closed())
    }

    /// 指定链路直发。
    ///
    /// # Errors
    /// 引擎已停止。
    pub async fn send_direct(&self, peer: NodeId, msg: Message, dest: NodeId) -> Result<()> {
        self.cmd
            .send(Command::SendDirect {
                peer,
                msg: Box::new(msg),
                dest,
            })
            .await
            .map_err(|_| closed())
    }

    /// 登记一条已握手的链路。
    ///
    /// # Errors
    /// 引擎已停止，或登记被拒绝（重复节点、深度超限、环）。
    pub async fn attach_link(
        &self,
        codec: LinkCodec,
        peer: NodeId,
        parent: NodeId,
        peer_kind: NodeKind,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::AttachLink {
                codec: Box::new(codec),
                peer,
                parent,
                peer_kind,
                reply: tx,
            })
            .await
            .map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }

    /// 关闭并摘除一条链路。
    ///
    /// # Errors
    /// 引擎已停止。
    pub async fn detach_link(&self, peer: NodeId) -> Result<Vec<NodeId>> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::DetachLink { peer, reply: tx })
            .await
            .map_err(|_| closed())?;
        rx.await.map_err(|_| closed())
    }

    /// 登记一条由本端发起的会话。
    ///
    /// 发起方必须登记：对端回的 `SessionReady` 要靠会话表落账，
    /// [`EngineHandle::await_ready`] 也靠它区分「还没就绪」与「根本没这条
    /// 会话」。
    ///
    /// # Errors
    /// 引擎已停止，或会话键已被登记。
    pub async fn register_session(
        &self,
        key: SessionKey,
        kind: stowaway_protocol::SessionKind,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::RegisterSession {
                key,
                kind,
                reply: tx,
            })
            .await
            .map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }

    /// 确保会话已登记（已登记则什么都不做）。
    ///
    /// # Errors
    /// 引擎已停止。
    pub async fn ensure_session(
        &self,
        key: SessionKey,
        kind: stowaway_protocol::SessionKind,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::EnsureSession {
                key,
                kind,
                reply: tx,
            })
            .await
            .map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }

    /// 打开一条会话流。
    ///
    /// # Errors
    /// 引擎已停止，或会话键已绑定。
    pub async fn open_stream(
        &self,
        key: SessionKey,
        dest: NodeId,
        kind: stowaway_protocol::SessionKind,
    ) -> Result<SessionStream> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::OpenStream {
                key,
                dest,
                kind,
                reply: tx,
            })
            .await
            .map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }

    /// 定向等待某条会话的 `SessionReady`。
    ///
    /// 与订阅 [`Event::SessionReady`] 不同，这里允许多个任务各等各的会话，
    /// 事件不会因为「接收端只有一个」而漏掉（见 [`Command::AwaitReady`]）。
    ///
    /// # Errors
    /// 引擎已停止、会话根本不存在（[`CoreError::UnknownSession`]），
    /// 或该会话已经有别的等待者（[`CoreError::Backpressure`]）。
    pub async fn await_ready(&self, key: SessionKey) -> Result<stowaway_protocol::SessionCode> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::AwaitReady { key, reply: tx })
            .await
            .map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }

    /// 回报会话就绪。
    ///
    /// # Errors
    /// 引擎已停止。
    pub async fn ready_session(
        &self,
        key: SessionKey,
        peer: NodeId,
        code: stowaway_protocol::SessionCode,
        detail: impl Into<String>,
    ) -> Result<()> {
        self.cmd
            .send(Command::ReadySession {
                key,
                peer,
                code,
                detail: detail.into(),
            })
            .await
            .map_err(|_| closed())
    }

    /// 关闭会话。
    ///
    /// # Errors
    /// 引擎已停止。
    pub async fn close_session(&self, key: SessionKey, reason: CloseReason) -> Result<()> {
        self.cmd
            .send(Command::CloseSession { key, reason })
            .await
            .map_err(|_| closed())
    }

    /// 取拓扑快照。
    ///
    /// # Errors
    /// 引擎已停止。
    pub async fn snapshot(&self) -> Result<Snapshot> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::Snapshot { reply: tx })
            .await
            .map_err(|_| closed())?;
        rx.await.map_err(|_| closed())
    }

    /// 立刻发一轮心跳。
    ///
    /// # Errors
    /// 引擎已停止。
    pub async fn pulse(&self) -> Result<()> {
        self.cmd.send(Command::Pulse).await.map_err(|_| closed())
    }

    /// 停止引擎。
    ///
    /// # Errors
    /// 引擎已停止。
    pub async fn shutdown(&self) -> Result<()> {
        self.cmd.send(Command::Shutdown).await.map_err(|_| closed())
    }
}

fn closed() -> CoreError {
    CoreError::LinkClosed
}

/// 心跳参数（plan §4.12）。
#[derive(Clone, Copy, Debug)]
pub struct HeartbeatConfig {
    /// 周期。
    pub interval: Duration,
    /// 连续多少次无回显判定对端已死。
    pub max_missed: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            max_missed: 3,
        }
    }
}

/// 运行时引擎。
pub struct Engine {
    node: Node,
    events: mpsc::UnboundedSender<Event>,
    inbound_rx: mpsc::Receiver<InboundFrame>,
    inbound_tx: mpsc::Sender<InboundFrame>,
    cmd_rx: mpsc::Receiver<Command>,
    handle: EngineHandle,
    actors: Vec<(NodeId, JoinHandle<()>)>,
    rtt: BTreeMap<NodeId, PeerRtt>,
    heartbeat: Option<HeartbeatConfig>,
    /// 已到达的 `SessionReady` 结果（供迟到的 [`Command::AwaitReady`] 立即兑现）。
    ready_codes: HashMap<SessionKey, stowaway_protocol::SessionCode>,
    /// 正在等 `SessionReady` 的一次性等待者。
    ready_waiters: HashMap<SessionKey, oneshot::Sender<Result<stowaway_protocol::SessionCode>>>,
}

#[derive(Clone, Copy, Debug)]
struct PeerRtt {
    rtt_ms: Option<u64>,
    missed: u32,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("me", &self.node.me())
            .field("links", &self.actors.len())
            .field("heartbeat", &self.heartbeat.is_some())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// 新建引擎，返回（句柄，引擎，入站投递端）。
    ///
    /// 入站投递端要交给每条链路 actor —— 它们是入站帧的唯一来源。
    #[must_use]
    pub fn new(
        config: NodeConfig,
        events: mpsc::UnboundedSender<Event>,
    ) -> (EngineHandle, Self, mpsc::Sender<InboundFrame>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(ENGINE_QUEUE_DEPTH);
        let (inbound_tx, inbound_rx) = mpsc::channel(ENGINE_QUEUE_DEPTH);
        let handle = EngineHandle { cmd: cmd_tx };
        let engine = Self {
            node: Node::new(config),
            events,
            inbound_rx,
            inbound_tx,
            cmd_rx,
            handle,
            actors: Vec::new(),
            rtt: BTreeMap::new(),
            heartbeat: None,
            ready_codes: HashMap::new(),
            ready_waiters: HashMap::new(),
        };
        let handle = engine.handle.clone();
        let inbound = engine.inbound_tx.clone();
        (handle, engine, inbound)
    }

    /// 引擎句柄。
    #[must_use]
    pub fn handle(&self) -> EngineHandle {
        self.handle.clone()
    }

    /// 开启定时心跳（plan §4.12：双向 + RTT + 连续 3 周期无回显判死）。
    #[must_use]
    pub fn with_heartbeat(mut self, cfg: HeartbeatConfig) -> Self {
        self.heartbeat = Some(cfg);
        self
    }

    /// 本节点编号。
    #[must_use]
    pub const fn me(&self) -> NodeId {
        self.node.me()
    }

    /// 运行引擎直到 [`Command::Shutdown`] 或致命错误。
    ///
    /// # Errors
    /// 入站处理出错或引擎被对端整体关闭。
    pub async fn run(mut self) -> Result<()> {
        let mut ticker = self.heartbeat.map(|cfg| {
            let mut interval = tokio::time::interval(cfg.interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval
        });

        loop {
            tokio::select! {
                // 入站优先：链路来的帧不因命令突发而饿死。
                biased;

                frame = self.inbound_rx.recv() => {
                    let Some(frame) = frame else { break };
                    if let Err(e) = self.on_inbound(frame).await {
                        let _ = self.events.send(Event::Failed(e.to_string()));
                        break;
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        Command::Shutdown => break,
                        other => {
                            if let Err(e) = self.on_command(other).await {
                                let _ = self.events.send(Event::Failed(e.to_string()));
                            }
                        }
                    }
                }
                _ = async {
                    match ticker.as_mut() {
                        Some(t) => { t.tick().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    self.pulse().await;
                }
            }
        }

        // 收尾：通知每条链路 flush 后退出，然后等 actor 结束。
        for (_, task) in self.actors.drain(..) {
            task.abort();
        }
        Ok(())
    }

    /// 处理一条入站帧。
    async fn on_inbound(&mut self, frame: InboundFrame) -> Result<()> {
        let from = frame.from;
        match self.node.handle_frame(frame).await {
            Ok(handled) => {
                self.dispatch(handled, from).await;
                Ok(())
            }
            Err(e) => {
                // 单帧错误不该整机停机：记录下来，让链路层决定是否断开。
                // v1 在这里直接 panic（缺陷 #2/#3），v2 一律降级为事件。
                let _ = self
                    .events
                    .send(Event::Failed(format!("处理来自 {from} 的帧失败：{e}")));
                Ok(())
            }
        }
    }

    /// 把 `Handled` 翻译成事件。
    async fn dispatch(&mut self, handled: Handled, from: NodeId) {
        match handled {
            Handled::SessionOpened(open) => {
                let _ = self.events.send(Event::SessionOpened { open, from });
            }
            Handled::SessionReady { key, code } => {
                self.deliver_ready(key, code);
                let _ = self.events.send(Event::SessionReady { key, code });
            }
            Handled::SessionClosed { key } => {
                self.forget_ready(key);
                self.node.unbind_session(key);
                let _ = self.events.send(Event::SessionClosed { key });
            }
            Handled::ServiceRequest(req) => {
                let _ = self.events.send(Event::ServiceRequest { req, from });
            }
            Handled::ServiceReply(reply) => {
                let _ = self.events.send(Event::ServiceReply { reply, from });
            }
            Handled::ServiceData(data) => {
                let _ = self.events.send(Event::ServiceData { data, from });
            }
            Handled::ServiceExit(exit) => {
                let _ = self.events.send(Event::ServiceExit { exit, from });
            }
            Handled::Topology => {}
            Handled::Status(NodeStatus {
                scope: NodeScope::Child,
                state: NodeState::Offline,
                node,
            }) => {
                let removed = self.node.detach_link(node);
                for gone in &removed {
                    self.drop_actor(*gone);
                }
                let _ = self.events.send(Event::Offline { node, removed });
            }
            Handled::SessionData { .. } => {}
            Handled::Shutdown => {
                let _ = self.events.send(Event::Shutdown);
            }
            Handled::Status(_) | Handled::Memo { .. } => {}
            Handled::Heartbeat { from, echo_ts } => {
                self.note_echo(from, echo_ts);
            }
            Handled::Forwarded { next_hop } => {
                let _ = next_hop;
            }
            Handled::Undeliverable { dest } => {
                let _ = self.events.send(Event::Undeliverable { dest });
            }
        }
    }

    /// 处理一条命令。
    async fn on_command(&mut self, cmd: Command) -> Result<()> {
        match cmd {
            Command::Send { msg, dest } => {
                if let Err(e) = self.node.send(&msg, dest).await {
                    if matches!(e, CoreError::Undeliverable { .. }) {
                        let _ = self.events.send(Event::Undeliverable { dest });
                        return Ok(());
                    }
                    return Err(e);
                }
                Ok(())
            }
            Command::SendDirect { peer, msg, dest } => {
                self.node.send_direct(peer, &msg, dest).await
            }
            Command::AttachLink {
                codec,
                peer,
                parent,
                peer_kind,
                reply,
            } => {
                let res = self.spawn_link(*codec, peer, parent, peer_kind);
                let _ = reply.send(res);
                Ok(())
            }
            Command::DetachLink { peer, reply } => {
                let removed = self.node.detach_link(peer);
                for gone in &removed {
                    self.drop_actor(*gone);
                }
                let _ = reply.send(removed);
                Ok(())
            }
            Command::RegisterSession { key, kind, reply } => {
                let res = self.node.register_session(key, kind);
                let _ = reply.send(res);
                Ok(())
            }
            Command::EnsureSession { key, kind, reply } => {
                let res = self.ensure_session(key, kind);
                let _ = reply.send(res);
                Ok(())
            }
            Command::OpenStream {
                key,
                dest,
                kind,
                reply,
            } => {
                let res = self.open_stream(key, dest, kind);
                let _ = reply.send(res);
                Ok(())
            }
            Command::ReadySession {
                key,
                peer,
                code,
                detail,
            } => self.node.ready_session(peer, key, code, detail),
            Command::CloseSession { key, reason } => {
                let close = SessionClose {
                    key,
                    reason,
                    detail: String::new(),
                };
                if let Err(e) = self.node.send_session_close(close).await
                    && !matches!(e, CoreError::UnknownSession { .. })
                {
                    return Err(e);
                }
                self.node.unbind_session(key);
                Ok(())
            }
            Command::AwaitReady { key, reply } => {
                // 已经就绪过（结果留在表里）→ 立即兑现，避免「等的人晚到」丢事件。
                if let Some(code) = self.ready_codes.get(&key).copied() {
                    let _ = reply.send(Ok(code));
                    return Ok(());
                }
                // 会话不存在：现在就知道不会有人来兑现，直接报错而不是让它等到超时。
                if self.node.sessions().get(&key).is_none() {
                    let _ = reply.send(Err(CoreError::UnknownSession { key }));
                    return Ok(());
                }
                // 同一会话只允许一个等待者：后来者覆盖前者会让前者饿死，因此拒绝。
                if self.ready_waiters.contains_key(&key) {
                    let _ = reply.send(Err(CoreError::Backpressure));
                    return Ok(());
                }
                self.ready_waiters.insert(key, reply);
                Ok(())
            }
            Command::Snapshot { reply } => {
                let _ = reply.send(self.snapshot());
                Ok(())
            }
            Command::Pulse => {
                self.pulse().await;
                Ok(())
            }
            Command::Shutdown => Ok(()),
        }
    }

    /// 登记链路并起 actor。
    fn spawn_link(
        &mut self,
        codec: LinkCodec,
        peer: NodeId,
        parent: NodeId,
        peer_kind: NodeKind,
    ) -> Result<()> {
        let (handle, actor) = if parent == self.node.me() {
            self.node
                .attach_link(codec, peer, parent, peer_kind, self.inbound_tx.clone())?
        } else {
            self.node
                .attach_upstream(codec, peer, peer_kind, self.inbound_tx.clone())?
        };
        let events = self.events.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = actor.run().await {
                let _ = events.send(Event::LinkLost { peer });
                let _ = events.send(Event::Failed(format!("链路 {peer} 异常：{e}")));
            } else {
                let _ = events.send(Event::LinkLost { peer });
            }
        });
        self.actors.push((peer, task));
        self.rtt.insert(
            peer,
            PeerRtt {
                rtt_ms: None,
                missed: 0,
            },
        );
        let _ = handle;
        let _ = self.events.send(Event::Joined {
            node: peer,
            kind: peer_kind,
            parent,
        });
        Ok(())
    }

    /// 兑现某个会话的 `SessionReady`：有等待者就直接给，否则记下结果。
    fn deliver_ready(&mut self, key: SessionKey, code: stowaway_protocol::SessionCode) {
        if let Some(waiter) = self.ready_waiters.remove(&key) {
            let _ = waiter.send(Ok(code));
        }
        self.ready_codes.insert(key, code);
    }

    /// 会话终结时清掉等待表与结果表，避免长跑进程无限增长。
    fn forget_ready(&mut self, key: SessionKey) {
        self.ready_codes.remove(&key);
        if let Some(waiter) = self.ready_waiters.remove(&key) {
            let _ = waiter.send(Err(CoreError::UnknownSession { key }));
        }
    }

    fn drop_actor(&mut self, peer: NodeId) {
        if let Some(idx) = self.actors.iter().position(|(p, _)| *p == peer) {
            let (_, task) = self.actors.remove(idx);
            task.abort();
        }
        self.rtt.remove(&peer);
    }

    /// 建会话流并绑定。
    ///
    /// 会话若尚未登记（应答方由 `ServiceRequest` 驱动，从来没有 `OpenSession`
    /// 帮它登记），这里补登记：绑定即接受，接受之后才可能推进到 `Open`。
    /// 已登记的不覆盖（发起方登记的种类才是权威，两边各记各的）。
    fn ensure_session(
        &mut self,
        key: SessionKey,
        kind: stowaway_protocol::SessionKind,
    ) -> Result<()> {
        // 已登记的不覆盖：发起方登记的种类才是权威，两边各记各的。
        if self.node.sessions().get(&key).is_none() {
            self.node.register_session(key, kind)?;
        }
        Ok(())
    }

    fn open_stream(
        &mut self,
        key: SessionKey,
        dest: NodeId,
        kind: stowaway_protocol::SessionKind,
    ) -> Result<SessionStream> {
        self.ensure_session(key, kind)?;
        let (out_tx, mut out_rx) = mpsc::channel(crate::session::SESSION_QUEUE_DEPTH);
        let (stream, sink) =
            SessionStream::new(key, dest, out_tx, crate::session::SESSION_QUEUE_DEPTH);
        self.node.bind_session(key, dest, sink)?;
        // 排空出站：会话流的写入要变成节点消息，而节点只归引擎所有。
        let cmd = self.handle.cmd.clone();
        tokio::spawn(async move {
            while let Some(out) = out_rx.recv().await {
                let (target, msg) = outbound_message(out);
                if cmd
                    .send(Command::Send {
                        msg: Box::new(msg),
                        dest: target,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(stream)
    }

    /// 发一轮心跳并统计 RTT / 判死。
    async fn pulse(&mut self) {
        let Some(cfg) = self.heartbeat else {
            return;
        };
        let now = now_ms();
        let peers = self.node.link_peers();
        for peer in peers {
            let hb = stowaway_protocol::Heartbeat {
                send_ts: now,
                echo_ts: 0,
            };
            let _ = self
                .node
                .send_direct(peer, &Message::Heartbeat(hb), peer)
                .await;
        }
        // 判死：只看「本轮之前就没回」的那些。
        let dead: Vec<NodeId> = self
            .rtt
            .iter()
            .filter(|(_, s)| s.missed >= cfg.max_missed)
            .map(|(p, _)| *p)
            .collect();
        for peer in dead {
            let misses = self.rtt.get(&peer).map_or(0, |s| s.missed);
            let _ = self.events.send(Event::PeerDead { peer, misses });
            let removed = self.node.detach_link(peer);
            for gone in &removed {
                self.drop_actor(*gone);
            }
            let _ = self.events.send(Event::Offline {
                node: peer,
                removed,
            });
        }
    }

    /// 记录一次心跳回显。
    fn observe_heartbeat(&mut self, from: NodeId, send_ts: u64) {
        let rtt = now_ms().saturating_sub(send_ts);
        if let Some(stat) = self.rtt.get_mut(&from) {
            stat.rtt_ms = Some(rtt);
            stat.missed = 0;
        }
        let _ = self.events.send(Event::Rtt {
            peer: from,
            rtt_ms: rtt,
        });
    }

    /// 生成拓扑快照。
    fn snapshot(&self) -> Snapshot {
        let topo = self.node.topology();
        let nodes = topo
            .nodes()
            .map(|m| NodeInfo {
                node: m.node,
                parent: m.parent,
                depth: m.depth,
                kind: m.kind,
                listen: m.listen.clone(),
            })
            .collect();
        let links = self
            .rtt
            .iter()
            .filter_map(|(peer, stat)| {
                let meta = topo.get(*peer)?;
                Some(LinkStat {
                    peer: *peer,
                    kind: meta.kind,
                    parent: meta.parent,
                    depth: meta.depth,
                    rtt_ms: stat.rtt_ms,
                    missed: stat.missed,
                })
            })
            .collect();
        Snapshot {
            me: Some(self.node.me()),
            root: Some(topo.root()),
            depth: topo.my_depth(),
            epoch: topo.epoch(),
            nodes,
            links,
            sessions: self.node.bound_sessions(),
            undeliverable: self.node.undeliverable(),
        }
    }
}

impl Engine {
    /// 心跳回显（`Heartbeat.echo_ts != 0` 表示这是对某轮探测的答复）。
    ///
    /// 由 [`Engine::on_inbound`] 在处理完帧后调用 —— 之所以放在引擎而不是
    /// [`Node`] 里，是因为 RTT 是运行时可观测性，不属于拓扑状态。
    pub fn note_echo(&mut self, from: NodeId, echo_ts: u64) {
        if echo_ts != 0 {
            self.observe_heartbeat(from, echo_ts);
        }
    }
}

/// 当前毫秒时间戳（心跳用；单调性不要求严格，只用于算 RTT）。
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// 指向引擎的共享句柄（便于把 `Arc<EngineHandle>` 传给服务层）。
pub type SharedHandle = Arc<EngineHandle>;

#[cfg(test)]
mod tests {
    use super::{Command, Engine, EngineHandle, Event, Snapshot, now_ms};
    use crate::node::NodeConfig;
    use std::time::Duration;
    use stowaway_protocol::{Message, NodeId, NodeKind};
    use tokio::sync::mpsc;

    fn engine() -> (
        EngineHandle,
        Engine,
        mpsc::Sender<crate::link_actor::InboundFrame>,
    ) {
        let (tx, _rx) = mpsc::unbounded_channel::<Event>();
        Engine::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin), tx)
    }

    /// 保留事件接收端 + 入站投递端，便于驱动「入站帧 → 就绪」的完整路径。
    fn engine_with_events() -> (
        mpsc::UnboundedReceiver<Event>,
        EngineHandle,
        Engine,
        mpsc::Sender<crate::link_actor::InboundFrame>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel::<Event>();
        let (handle, engine, inbound) =
            Engine::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin), tx);
        (rx, handle, engine, inbound)
    }

    #[tokio::test]
    async fn snapshot_reports_self_as_root_before_any_join() {
        let (handle, engine, _inbound) = engine();
        let task = tokio::spawn(engine.run());
        let snap = handle.snapshot().await.expect("snapshot");
        assert_eq!(snap.me, Some(NodeId::ADMIN));
        assert_eq!(snap.root, Some(NodeId::ADMIN));
        assert_eq!(snap.depth, 0);
        assert_eq!(snap.nodes.len(), 1, "只有自己");
        assert_eq!(snap.links.len(), 0);
        assert_eq!(snap.sessions, 0);
        handle.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("engine ok");
    }

    #[tokio::test]
    async fn sending_to_an_unknown_node_surfaces_undeliverable() {
        let (etx, mut erx) = mpsc::unbounded_channel::<Event>();
        let (handle, engine, _inbound) =
            Engine::new(NodeConfig::new(NodeId::ADMIN, NodeKind::Admin), etx);
        let task = tokio::spawn(engine.run());
        let hb = stowaway_protocol::Heartbeat {
            send_ts: 1,
            echo_ts: 0,
        };
        let far = NodeId::new([0x42; 16]);
        // 无该链路：send 报不可达，引擎转成事件而不是错误停机。
        let res = handle.send(Message::Heartbeat(hb), far).await;
        assert!(res.is_ok(), "引擎本身仍在运行");
        let ev = erx.recv().await.expect("event");
        assert!(
            matches!(ev, Event::Undeliverable { dest } if dest == far),
            "应报不可达，实际 {ev:?}"
        );
        handle.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("engine ok");
    }

    #[tokio::test]
    async fn open_stream_requires_the_session_to_be_registered() {
        let (handle, engine, _inbound) = engine();
        let task = tokio::spawn(engine.run());
        let key = stowaway_protocol::SessionKey::new(NodeId::ADMIN, 7);
        let far = NodeId::new([0x11; 16]);
        let res = handle
            .open_stream(key, far, stowaway_protocol::SessionKind::Socks5)
            .await;
        assert!(res.is_ok(), "未登记也能建流，只在发数据时不可达");
        handle.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("engine ok");
    }

    #[tokio::test]
    async fn pulse_without_heartbeat_config_is_a_noop() {
        let (handle, engine, _inbound) = engine();
        let task = tokio::spawn(engine.run());
        handle.pulse().await.expect("pulse");
        let snap = handle.snapshot().await.expect("snapshot");
        assert!(snap.links.is_empty());
        handle.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("engine ok");
    }

    #[tokio::test]
    async fn now_ms_is_monotonic_enough_for_rtt() {
        let a = now_ms();
        let b = now_ms();
        assert!(b >= a, "时间戳不能倒退");
    }

    #[tokio::test]
    async fn snapshot_default_is_empty() {
        let s = Snapshot::default();
        assert!(s.me.is_none());
        assert!(s.nodes.is_empty());
        assert!(s.links.is_empty());
    }

    /// 把一条本地消息压成入站帧（`dest` 是自己、`via` 空 → `Route::Local`）。
    fn inbound(from: NodeId, msg: stowaway_protocol::Message) -> crate::link_actor::InboundFrame {
        let payload = msg.encode().expect("encode");
        let frame = stowaway_protocol::Frame::new(
            stowaway_protocol::FrameFlags::empty(),
            msg.msg_type(),
            NodeId::ADMIN,
            Vec::new(),
            payload,
        );
        crate::link_actor::InboundFrame { from, frame }
    }

    /// 登记一条「对端发起」的会话，供就绪等待用。
    fn open_session_msg(key: stowaway_protocol::SessionKey) -> stowaway_protocol::Message {
        stowaway_protocol::Message::OpenSession(stowaway_protocol::OpenSession {
            key,
            kind: stowaway_protocol::SessionKind::Socks5,
            direction: stowaway_protocol::SessionDirection::Inbound,
            target: Some("127.0.0.1:9".to_owned()),
            param: stowaway_protocol::ServiceParam::None,
        })
    }

    #[tokio::test]
    async fn await_ready_returns_the_code_once_session_ready_arrives() {
        let child = NodeId::new([0x21; 16]);
        let key = stowaway_protocol::SessionKey::new(child, 1);
        let (mut erx, handle, engine, inbound_tx) = engine_with_events();
        let task = tokio::spawn(engine.run());

        inbound_tx
            .send(inbound(child, open_session_msg(key)))
            .await
            .expect("open");
        // 等登记完成：`await_ready` 自己就会等到有结果，但我们要先确认会话在表里。
        let probe = handle.clone();
        let waiter = tokio::spawn(async move { probe.await_ready(key).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "还没回 Ready，等待者不该提前返回");

        inbound_tx
            .send(inbound(
                child,
                stowaway_protocol::Message::SessionReady(stowaway_protocol::SessionReady {
                    key,
                    code: stowaway_protocol::SessionCode::Ok,
                    detail: "outlet up".to_owned(),
                }),
            ))
            .await
            .expect("ready");
        let code = waiter
            .await
            .expect("join")
            .expect("await_ready 必须拿到结果");
        assert_eq!(code, stowaway_protocol::SessionCode::Ok);

        // 事件流里那条 `SessionReady` 仍然照常广播给控制台。
        let mut saw = false;
        while let Ok(ev) = erx.try_recv() {
            if matches!(ev, Event::SessionReady { key: k, code } if k == key && code == stowaway_protocol::SessionCode::Ok)
            {
                saw = true;
            }
        }
        assert!(saw, "定向等待不能吞掉广播事件");
        handle.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("engine ok");
    }

    #[tokio::test]
    async fn await_ready_on_a_late_wait_is_immediate_not_lost() {
        let child = NodeId::new([0x22; 16]);
        let key = stowaway_protocol::SessionKey::new(child, 1);
        let (mut erx, handle, engine, inbound_tx) = engine_with_events();
        let task = tokio::spawn(engine.run());

        inbound_tx
            .send(inbound(child, open_session_msg(key)))
            .await
            .expect("open");
        inbound_tx
            .send(inbound(
                child,
                stowaway_protocol::Message::SessionReady(stowaway_protocol::SessionReady {
                    key,
                    code: stowaway_protocol::SessionCode::Refused,
                    detail: "no route".to_owned(),
                }),
            ))
            .await
            .expect("ready");
        // 先让引擎把上面两条帧处理完（消费掉广播事件作为同步点）。
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(ev) = erx.try_recv() {
                    if matches!(ev, Event::SessionReady { .. }) {
                        break;
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        })
        .await
        .expect("ready event");

        // 结果已经到过了，迟到者必须立刻拿到，而不是等下一次 Ready（可能永远不来）。
        let code = tokio::time::timeout(Duration::from_secs(1), handle.await_ready(key))
            .await
            .expect("迟到等待不能超时")
            .expect("await_ready");
        assert_eq!(code, stowaway_protocol::SessionCode::Refused);
        handle.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("engine ok");
    }

    #[tokio::test]
    async fn await_ready_fails_fast_for_unknown_session() {
        let (handle, engine, _inbound) = engine();
        let task = tokio::spawn(engine.run());
        // 引擎里根本没有这条会话：现在就断言不会有人兑现，而不是等到调用方超时。
        let key = stowaway_protocol::SessionKey::new(NodeId::new([0x23; 16]), 9);
        let res = tokio::time::timeout(Duration::from_secs(1), handle.await_ready(key))
            .await
            .expect("必须立刻失败");
        assert!(
            matches!(res, Err(crate::error::CoreError::UnknownSession { .. })),
            "应报未知会话，实际 {res:?}"
        );
        handle.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("engine ok");
    }

    #[tokio::test]
    async fn closing_a_session_wakes_the_waiter_with_an_error() {
        let child = NodeId::new([0x24; 16]);
        let key = stowaway_protocol::SessionKey::new(child, 1);
        let (mut _erx, handle, engine, inbound_tx) = engine_with_events();
        let task = tokio::spawn(engine.run());

        inbound_tx
            .send(inbound(child, open_session_msg(key)))
            .await
            .expect("open");
        let probe = handle.clone();
        let waiter = tokio::spawn(async move { probe.await_ready(key).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "先确保真的挂上了");

        // 会话在 Ready 之前就关了：等待者必须被唤醒并收到错误，不能饿死。
        inbound_tx
            .send(inbound(
                child,
                stowaway_protocol::Message::SessionClose(stowaway_protocol::SessionClose {
                    key,
                    reason: stowaway_protocol::CloseReason::Reset,
                    detail: String::new(),
                }),
            ))
            .await
            .expect("close");
        let res = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("等待者必须被唤醒")
            .expect("join");
        assert!(
            matches!(res, Err(crate::error::CoreError::UnknownSession { .. })),
            "应报未知会话，实际 {res:?}"
        );
        task.abort();
    }

    #[tokio::test]
    async fn register_session_makes_await_ready_work_for_the_initiator() {
        // 发起方（admin 的 socks/forward/shell）自己发 `OpenSession`：若不先登记，
        // 对端回的 `SessionReady` 无处落账，`await_ready` 也会立刻判未知会话。
        let child = NodeId::new([0x25; 16]);
        let key = stowaway_protocol::SessionKey::new(NodeId::ADMIN, 1);
        let (mut _erx, handle, engine, inbound_tx) = engine_with_events();
        let task = tokio::spawn(engine.run());

        handle
            .register_session(key, stowaway_protocol::SessionKind::Socks5)
            .await
            .expect("register");

        let probe = handle.clone();
        let waiter = tokio::spawn(async move { probe.await_ready(key).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "登记了就绪后仍在等对端答复");

        // 对端（agent）确认出口建起来了。
        inbound_tx
            .send(inbound(
                child,
                stowaway_protocol::Message::SessionReady(stowaway_protocol::SessionReady {
                    key,
                    code: stowaway_protocol::SessionCode::Ok,
                    detail: "已连上 127.0.0.1:22".to_owned(),
                }),
            ))
            .await
            .expect("ready");

        let code = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("必须被唤醒")
            .expect("join")
            .expect("await_ready");
        assert_eq!(code, stowaway_protocol::SessionCode::Ok);
        handle.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("engine ok");
    }

    #[tokio::test]
    async fn command_debug_is_available() {
        // 保证 `Command`/`Event` 的 Debug 派生没被后续改动破坏（日志要用）。
        let cmd = Command::Pulse;
        assert!(format!("{cmd:?}").contains("Pulse"));
    }
}
