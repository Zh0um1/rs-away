//! 节点运行时聚合：拓扑 + 会话 + 链路句柄 + 派发。
//!
//! 权威：`docs/plan.md` §4.7（派发）、§4.9（agent 表）。
//!
//! 本类型**只持元数据与通道句柄**（plan §4.9：`TopologyActor` 不持 socket）；
//! 真正的读写由每条链路的 [`LinkActor`] 负责，因此这里没有 `&mut LinkCodec`，
//! 也就无法出现「多任务直写同一链路」这种 v1 竞态。

use std::collections::{BTreeSet, HashMap};

use stowaway_protocol::{
    CloseReason, Heartbeat, Message, MsgType, NodeId, NodeKind, NodeScope, NodeState, NodeStatus,
    OpenSession, SessionCode, SessionData, SessionKey, SessionKind,
};

use crate::dispatch::{Route, decide, undeliverable_status};
use crate::error::{CoreError, Result};
use crate::link_actor::{InboundFrame, LinkActor, LinkHandle};
use crate::session::SessionTable;
use crate::topology::{NodeMeta, Topology};

/// 节点配置。
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// 本节点编号。
    pub me: NodeId,
    /// 角色。
    pub kind: NodeKind,
    /// 最大树深（0 表示不限制子树存活，仍拒绝超过 `u16` 的深度）。
    pub max_depth: u16,
    /// 每条链路的写通道深度（背压阈值）。
    pub link_capacity: usize,
}

impl NodeConfig {
    /// 构造默认配置。
    #[must_use]
    pub const fn new(me: NodeId, kind: NodeKind) -> Self {
        Self {
            me,
            kind,
            max_depth: 8,
            link_capacity: 64,
        }
    }
}

/// 一条已建立的链路。
#[derive(Debug)]
pub struct LinkEntry {
    /// 写句柄（克隆给需要的任务）。
    pub handle: LinkHandle,
    /// 对端角色。
    pub peer_kind: NodeKind,
    /// 是否已握手密封。
    pub sealed: bool,
}

/// 一条已绑定的会话流。
#[derive(Debug)]
struct SessionBinding {
    /// 会话另一端。
    peer: NodeId,
    /// 入站数据投递端（由 [`crate::session_stream::SessionStream::new`] 产出）。
    sink: tokio::sync::mpsc::Sender<SessionData>,
}

/// 节点运行时。
#[derive(Debug)]
pub struct Node {
    config: NodeConfig,
    topology: Topology,
    sessions: SessionTable,
    links: HashMap<NodeId, LinkEntry>,
    /// 已绑定会话流：会话键 → (对端节点, 入站数据投递端)。
    ///
    /// 只有「本节点是会话某一端」时才登记；纯转发（中间节点）永不登记，
    /// 因此中间节点不会解 session 层（plan §4.7）。对端节点必须显式记录：
    /// 会话另一端的编号无法从帧里推出（v2 帧没有 sender 字段）。
    session_sinks: HashMap<SessionKey, SessionBinding>,
    /// 已发起的会话 id 计数器（`SessionKey.origin` 恒为本节点）。
    next_session_id: u64,
    /// 未送达计数（诊断）。
    undeliverable: u64,
}

impl Node {
    /// 新建节点。
    #[must_use]
    pub fn new(config: NodeConfig) -> Self {
        let topology = Topology::new(config.me, config.kind, config.max_depth);
        Self {
            config,
            topology,
            sessions: SessionTable::new(),
            links: HashMap::new(),
            session_sinks: HashMap::new(),
            next_session_id: 0,
            undeliverable: 0,
        }
    }

    /// 本节点编号。
    #[must_use]
    pub const fn me(&self) -> NodeId {
        self.config.me
    }

    /// 拓扑（只读）。
    #[must_use]
    pub const fn topology(&self) -> &Topology {
        &self.topology
    }

    /// 会话表（只读）。
    #[must_use]
    pub const fn sessions(&self) -> &SessionTable {
        &self.sessions
    }

    /// 不可达计数。
    #[must_use]
    pub const fn undeliverable(&self) -> u64 {
        self.undeliverable
    }

    /// 本节点在拓扑中的视图（可变，用于登记经 Join 上报的远端节点）。
    ///
    /// 改动后调用方必须自行调用 [`Topology::invalidate`]，否则路由缓存
    /// 仍指向旧下一跳。
    pub fn topology_mut(&mut self) -> &mut Topology {
        &mut self.topology
    }

    /// 向上游公告一个新接入的子节点（`Join{node: child}`）。
    ///
    /// 为什么必须显式公告：v2 帧没有「sender」字段，`from` 只是**链路对端**。
    /// 新子节点接入后如果不公告，admin 要等到该子节点自己的心跳经两跳到达
    /// 才会发现它存在（且那时也拿不到父子关系），这期间任何指向它的帧都
    /// 会被判为不可达。公告让拓扑在接入的瞬间就收敛。
    ///
    /// 没有上游（自己是根）时静默成功：根节点不需要向任何人公告。
    ///
    /// # Errors
    /// 链路关闭。
    pub async fn announce_child(&mut self, child: NodeId, kind: NodeKind) -> Result<()> {
        let Some(parent) = self
            .topology
            .get(self.config.me)
            .map(|m| m.parent)
            .filter(|p| *p != NodeId::UNASSIGNED)
        else {
            return Ok(());
        };
        let msg = Message::Join(stowaway_protocol::Join {
            kind,
            listen: None,
            capabilities: 0,
            node: child,
        });
        match self.links.get(&parent) {
            Some(entry) => {
                entry
                    .handle
                    .send(msg, self.topology.root(), Vec::new())
                    .await
            }
            // 上游链路还没建立：公告会随下次 Join/Rejoin 补齐，不算错误。
            None => Ok(()),
        }
    }

    /// 查到一个目标节点的下一跳（走缓存，供 CLI/诊断用）。
    ///
    /// # Errors
    /// 目标不可达。
    pub fn next_hop(&mut self, dest: NodeId) -> Result<NodeId> {
        self.topology
            .next_hop(dest)?
            .ok_or(CoreError::Undeliverable { dest })
    }

    /// 把一条**本地产生**的消息当作「来自本节点」处理（供控制台注入命令，
    /// 也让不依赖真实链路的用例能直接驱动业务分支）。
    ///
    /// # Errors
    /// 消息语义不合法。
    pub async fn handle_local_message(&mut self, msg: Message) -> Result<Handled> {
        let me = self.config.me;
        self.handle_local(me, msg).await
    }

    /// 分配一个新的会话键。
    pub fn allocate_session(&mut self, kind: SessionKind) -> Result<SessionKey> {
        let key = SessionKey::new(self.config.me, self.next_session_id);
        self.next_session_id = self.next_session_id.saturating_add(1);
        self.sessions.open(key, kind)?;
        Ok(key)
    }

    /// 登记一条链路；同时把对端写进拓扑。
    ///
    /// # Errors
    /// 拓扑拒绝（重复元数据/超深/成环）。
    pub fn attach_link(
        &mut self,
        codec: stowaway_transport::LinkCodec,
        peer: NodeId,
        parent: NodeId,
        peer_kind: NodeKind,
        inbound: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(LinkHandle, LinkActor)> {
        self.topology
            .insert(NodeMeta::new(peer, parent, 0, peer_kind))?;
        let sealed = codec.is_sealed();
        let (handle, actor) =
            LinkActor::channel(codec, peer, self.config.link_capacity, inbound.clone());
        self.links.insert(
            peer,
            LinkEntry {
                handle: handle.clone(),
                peer_kind,
                sealed,
            },
        );
        // 链路集合变化 → epoch+1 → 路由缓存整体失效（plan §4.7）。
        self.topology.invalidate();
        Ok((handle, actor))
    }

    /// 登记一条**上游**链路（agent 连上 admin 时用）。
    ///
    /// 与 [`Self::attach_link`] 的区别：这里把对端声明为本节点的父节点，
    /// 拓扑根随之改变（否则 agent 会把 admin 误认为自己的下游，路由全反）。
    ///
    /// # Errors
    /// 拓扑拒绝。
    pub fn attach_upstream(
        &mut self,
        codec: stowaway_transport::LinkCodec,
        peer: NodeId,
        peer_kind: NodeKind,
        inbound: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(LinkHandle, LinkActor)> {
        self.topology.attach_upstream(peer, peer_kind)?;
        let sealed = codec.is_sealed();
        let (handle, actor) =
            LinkActor::channel(codec, peer, self.config.link_capacity, inbound.clone());
        self.links.insert(
            peer,
            LinkEntry {
                handle: handle.clone(),
                peer_kind,
                sealed,
            },
        );
        self.topology.invalidate();
        Ok((handle, actor))
    }

    /// 移除一条链路（对端断开/被踢）。
    pub fn detach_link(&mut self, peer: NodeId) -> Vec<NodeId> {
        self.links.remove(&peer);
        let removed = self.topology.remove(peer);
        // 该节点**及其整支后代**发起的会话一并终结：后代跟着离线，
        // 它们的会话留着只会内存泄漏（v1 只删单点，孤儿子树一直留在表里）。
        let mut gone: BTreeSet<NodeId> = BTreeSet::new();
        gone.insert(peer);
        gone.extend(removed.iter().copied());
        let orphans: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter(|m| gone.contains(&m.key.origin))
            .map(|m| m.key)
            .collect();
        for key in orphans {
            let _ = self.sessions.close(&key, CloseReason::Reset);
            self.session_sinks.remove(&key);
        }
        self.topology.invalidate();
        removed
    }

    /// 取一个链路句柄。
    #[must_use]
    pub fn link(&self, peer: NodeId) -> Option<&LinkEntry> {
        self.links.get(&peer)
    }

    /// 把一个会话流绑定到本节点：之后属于该会话的 `SessionData` 会投给它。
    ///
    /// `out` 是流向外发帧的通道，`sink` 是流读取数据的入口 —— 两者由
    /// [`SessionStream::new`] 一起产出，这里只登记不创建。
    ///
    /// 同一个会话键只允许绑定一次（重复绑定说明业务层重复受理同一会话）。
    ///
    /// # Errors
    /// 会话键已被绑定。
    pub fn bind_session(
        &mut self,
        key: SessionKey,
        peer: NodeId,
        sink: tokio::sync::mpsc::Sender<SessionData>,
    ) -> Result<()> {
        if self.session_sinks.contains_key(&key) {
            return Err(CoreError::SessionExists { key });
        }
        self.session_sinks
            .insert(key, SessionBinding { peer, sink });
        Ok(())
    }

    /// 解除会话绑定（会话结束时调用，避免 sink 泄漏）。
    pub fn unbind_session(&mut self, key: SessionKey) {
        self.session_sinks.remove(&key);
    }

    /// 当前绑定的会话数（诊断/测试用）。
    #[must_use]
    pub fn bound_sessions(&self) -> usize {
        self.session_sinks.len()
    }

    /// 发一条 `SessionData` 到目标节点（由会话流发起）。
    ///
    /// # Errors
    /// 不可达或链路关闭。
    pub async fn send_session_data(&mut self, data: SessionData) -> Result<()> {
        let dest = self.session_dest(data.key)?;
        self.send(&Message::SessionData(data), dest).await
    }

    /// 发一条 `SessionClose` 到目标节点。
    ///
    /// # Errors
    /// 不可达或链路关闭。
    pub async fn send_session_close(
        &mut self,
        close: stowaway_protocol::SessionClose,
    ) -> Result<()> {
        let dest = self.session_dest(close.key)?;
        self.send(&Message::SessionClose(close), dest).await
    }

    /// 会话的对端节点（绑定时登记的那个）。
    fn session_dest(&self, key: SessionKey) -> Result<NodeId> {
        self.session_sinks
            .get(&key)
            .map(|b| b.peer)
            .ok_or(CoreError::UnknownSession { key })
    }

    /// 全部链路对端。
    #[must_use]
    pub fn link_peers(&self) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self.links.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// 处理一条入站帧。
    ///
    /// 返回值表示该帧的处理结果，供调用方（测试/CLI）断言与做后续动作。
    ///
    /// # Errors
    /// 拓扑/会话错误；「不可达」不是错误（会通过 `NodeStatus` 通告）。
    pub async fn handle_frame(&mut self, inbound: InboundFrame) -> Result<Handled> {
        let from = inbound.from;
        let frame = inbound.frame;
        let dest = frame.header.dest;
        let via = frame.header.via.clone();

        // 握手/链路层消息一律本地处理（它们始终以 UNASSIGNED 为目标）。
        let route = match frame.header.msg_type {
            MsgType::Hello | MsgType::HelloAck | MsgType::AuthConfirm => Route::Local,
            _ => decide(&mut self.topology, self.config.me, dest, &via)?,
        };

        match route {
            Route::Local => {
                let msg = Message::decode(frame.header.msg_type, &frame.payload)?;
                self.handle_local(from, msg).await
            }
            Route::Forward { next_hop, via } => {
                let Some(entry) = self.links.get(&next_hop) else {
                    self.undeliverable = self.undeliverable.saturating_add(1);
                    return Ok(Handled::Undeliverable { dest });
                };
                // 中间节点不解 session 层：载荷原样透传（plan §4.7）。
                entry
                    .handle
                    .forward(
                        frame.header.msg_type,
                        dest,
                        via,
                        frame.header.flags,
                        frame.payload.to_vec(),
                    )
                    .await?;
                Ok(Handled::Forwarded { next_hop })
            }
            Route::Undeliverable => {
                self.undeliverable = self.undeliverable.saturating_add(1);
                // 向来源通告不可达（v1 是静默丢弃 → 缺陷 #11）。
                let notice = undeliverable_status(dest, NodeScope::Node);
                if let Some(entry) = self.links.get(&from) {
                    let _ = entry
                        .handle
                        .try_send(Message::NodeStatus(notice), from, Vec::new());
                }
                Ok(Handled::Undeliverable { dest })
            }
        }
    }

    async fn handle_local(&mut self, from: NodeId, msg: Message) -> Result<Handled> {
        match msg {
            Message::Heartbeat(hb) => {
                // `echo_ts != 0` 是对 ping 的回显；否则要回一条 echo。
                if hb.echo_ts == 0
                    && let Some(entry) = self.links.get(&from)
                {
                    let reply = Message::Heartbeat(Heartbeat {
                        send_ts: hb.send_ts,
                        echo_ts: hb.send_ts.max(1),
                    });
                    let _ = entry.handle.try_send(reply, from, Vec::new());
                }
                Ok(Handled::Heartbeat { from })
            }
            Message::Join(join) => {
                // 两个用途（见 `Join::node` 的文档）：
                // 1. `node == UNASSIGNED`：对端自己入网，父节点就是 `from`；
                // 2. `node` 具体：对端替它的子节点向上游公告，父节点仍是 `from`。
                //
                // 两种情况父节点都只能是 `from` —— 这一点是安全的：帧里的
                // `node` 字段只影响「登记谁」，不影响「登记在哪条链路下」，
                // 因此上游节点无法通过伪造 `node` 把别的节点劫持到自己树下。
                let announced = if join.node == NodeId::UNASSIGNED {
                    from
                } else {
                    join.node
                };
                // 已登记的节点不重复登记（拓扑收敛靠 `Rejoin`/`reparent`），
                // 自己也不需要在自己的拓扑里当孩子。
                if announced != self.config.me && self.topology.get(announced).is_none() {
                    self.topology
                        .insert(NodeMeta::new(announced, from, 0, join.kind))?;
                }
                let _ = join.capabilities;
                let _ = join.listen;
                self.topology.invalidate();
                let parent = self.topology.get(from).map_or(self.config.me, |m| m.parent);
                let ack = Message::JoinAck(stowaway_protocol::JoinAck {
                    node: from,
                    parent,
                    root: self.topology.root(),
                    depth: self.topology.my_depth().saturating_add(1),
                });
                if let Some(entry) = self.links.get(&from) {
                    let _ = entry.handle.try_send(ack, from, Vec::new());
                }
                Ok(Handled::Topology)
            }
            Message::Rejoin(rejoin) => {
                // 重连：可能换了父节点。
                if self.topology.get(rejoin.node).is_some() {
                    self.topology.reparent(rejoin.node, rejoin.parent)?;
                    self.topology.invalidate();
                }
                Ok(Handled::Topology)
            }
            Message::NodeStatus(status) => {
                if status.scope == NodeScope::Child
                    && status.state == NodeState::Offline
                    && status.node != NodeId::UNASSIGNED
                {
                    // 子节点明确离线：让拓扑也把它摘掉（会话随之清理）。
                    let _ = self.detach_link(status.node);
                }
                Ok(Handled::Status(status))
            }
            Message::OpenSession(open) => {
                // 对端发起：登记为 Opening，由业务层决定接受与否。
                if self.sessions.get(&open.key).is_none() {
                    self.sessions.open(open.key, open.kind)?;
                }
                Ok(Handled::SessionOpened(open))
            }
            Message::SessionReady(ready) => {
                self.sessions.ready(&ready.key, ready.code)?;
                Ok(Handled::SessionReady {
                    key: ready.key,
                    code: ready.code,
                })
            }
            Message::SessionData(data) => {
                let seq = data.seq;
                let len = data.data.len();
                let key = data.key;
                // 先过会话表的序号校验（乱序/重放/未就绪一律报错），
                // 再把数据交给绑定在会话上的流。
                self.sessions.accept_data(&data)?;
                if let Some(binding) = self.session_sinks.get(&key) {
                    binding.sink.try_send(data).map_err(|e| match e {
                        // 消费端满了：不丢帧，而是把背压往链路方向传导。
                        tokio::sync::mpsc::error::TrySendError::Full(_) => CoreError::Backpressure,
                        tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                            CoreError::UnknownSession { key }
                        }
                    })?;
                }
                Ok(Handled::SessionData { key, seq, len })
            }
            Message::SessionClose(close) => {
                let _ = self.sessions.close(&close.key, close.reason);
                // 会话结束：解绑并关掉投递端，让会话流读到 EOF。
                self.session_sinks.remove(&close.key);
                Ok(Handled::SessionClosed { key: close.key })
            }
            Message::JoinAck(ack) => {
                // 自己的 Join 被接纳：把根/深度补齐（父节点已在握手时登记）。
                if ack.node == self.config.me && ack.root.is_assigned() {
                    self.topology.invalidate();
                }
                Ok(Handled::Topology)
            }
            Message::Shutdown(_) => Ok(Handled::Shutdown),
            Message::Memo(memo) => Ok(Handled::Memo { node: memo.node }),
            Message::ServiceRequest(req) => Ok(Handled::ServiceRequest { key: req.key }),
            Message::ServiceReply(reply) => Ok(Handled::ServiceReply { key: reply.key }),
            Message::ServiceData(data) => Ok(Handled::ServiceData { key: data.key }),
            Message::ServiceExit(exit) => Ok(Handled::ServiceExit { key: exit.key }),
            Message::Hello(_) | Message::HelloAck(_) | Message::AuthConfirm(_) => {
                // 握手 flight 由 `LinkCodec` 在建立链路时消费；走到这里说明
                // 对端在已建立的链路上又发了一次握手帧。
                Err(CoreError::Protocol(
                    stowaway_protocol::ProtocolError::Payload(
                        "已建立的链路上收到握手帧".to_owned(),
                    ),
                ))
            }
        }
    }

    /// 向指定节点发一条消息（自动路由）。
    ///
    /// # Errors
    /// 不可达（[`CoreError::Undeliverable`]）、链路已关闭。
    pub async fn send(&mut self, msg: &Message, dest: NodeId) -> Result<()> {
        let route = decide(&mut self.topology, self.config.me, dest, &[])?;
        match route {
            Route::Forward { next_hop, via } => {
                let entry = self
                    .links
                    .get(&next_hop)
                    .ok_or(CoreError::Undeliverable { dest })?;
                entry.handle.send(msg.clone(), dest, via).await
            }
            Route::Local => Err(CoreError::Undeliverable { dest }),
            Route::Undeliverable => Err(CoreError::Undeliverable { dest }),
        }
    }

    /// 向某条链路直接发（不查路由）。
    ///
    /// # Errors
    /// 链路不存在。
    pub async fn send_direct(&self, peer: NodeId, msg: &Message, dest: NodeId) -> Result<()> {
        let entry = self.links.get(&peer).ok_or(CoreError::LinkClosed)?;
        entry.handle.send(msg.clone(), dest, Vec::new()).await
    }

    /// 向某条链路直接发一条 `SessionReady`（业务层接受会话时用）。
    ///
    /// # Errors
    /// 链路不存在。
    pub fn ready_session(
        &self,
        peer: NodeId,
        key: SessionKey,
        code: SessionCode,
        detail: impl Into<String>,
    ) -> Result<()> {
        let entry = self.links.get(&peer).ok_or(CoreError::LinkClosed)?;
        let msg = Message::SessionReady(stowaway_protocol::SessionReady {
            key,
            code,
            detail: detail.into(),
        });
        entry.handle.try_send(msg, peer, Vec::new())
    }
}

/// 一帧被处理后的结果（供测试与上层断言）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Handled {
    /// 已本地派发的心跳。
    Heartbeat {
        /// 来源。
        from: NodeId,
    },
    /// 已经转发给 `next_hop`。
    Forwarded {
        /// 下一跳。
        next_hop: NodeId,
    },
    /// 不可达（已尽力通告）。
    Undeliverable {
        /// 目标。
        dest: NodeId,
    },
    /// 拓扑变化。
    Topology,
    /// 节点状态上报。
    Status(NodeStatus),
    /// 会话打开（携带完整请求：响应方要按 `kind`/`direction` 决定拨号还是监听）。
    SessionOpened(OpenSession),
    /// 会话确认。
    SessionReady {
        /// 键。
        key: SessionKey,
        /// 结果码。
        code: SessionCode,
    },
    /// 会话数据。
    SessionData {
        /// 键。
        key: SessionKey,
        /// 序号。
        seq: u64,
        /// 字节数。
        len: usize,
    },
    /// 会话关闭。
    SessionClosed {
        /// 键。
        key: SessionKey,
    },
    /// 收到关闭请求。
    Shutdown,
    /// 备注变更。
    Memo {
        /// 节点。
        node: NodeId,
    },
    /// 服务请求。
    ServiceRequest {
        /// 键。
        key: SessionKey,
    },
    /// 服务响应。
    ServiceReply {
        /// 键。
        key: SessionKey,
    },
    /// 服务数据。
    ServiceData {
        /// 键。
        key: SessionKey,
    },
    /// 服务退出。
    ServiceExit {
        /// 键。
        key: SessionKey,
    },
}
