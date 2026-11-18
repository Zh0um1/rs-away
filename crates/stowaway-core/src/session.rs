//! 会话表：`SessionKey` 的元数据、序号校验与有界背压。
//!
//! 权威：`docs/plan.md` §4.8（会话模型）、§4.9（`SessionActor` 有界 32 帧）。
//!
//! v1 的会话是用 `seq` 号做全局唯一标识的（`protocol/protocol.go` 里
//! `SocksTCPData{Seq, Data}`），而 admin 与 agent **各自**有独立
//! `BackwardManager`/`ForwardManager` 发号——两侧都从 0 开始，一次
//! forward + 一次 backward 就会撞号。v2 用 [`SessionKey`]（`origin` 节点
//! + 该节点分配的 `id`）做复合键，撞号在结构上不可能。
//!
//! 本模块只做**元数据与序号**，不持 socket；数据搬运属于
//! [`crate::link_actor`] 与 P4/P5 的服务实现。

use std::collections::HashMap;

use stowaway_protocol::{CloseReason, NodeId, SessionCode, SessionData, SessionKey, SessionKind};

use crate::error::{CoreError, Result};

/// 单个会话允许积压的帧数（plan §4.9 的「有界 32 帧」）。
pub const SESSION_QUEUE_DEPTH: usize = 32;

/// 会话生命周期状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SessionState {
    /// 已发出 `OpenSession`，等 `SessionReady`。
    #[default]
    Opening,
    /// 双方就绪，可收发数据。
    Open,
    /// 已发出 `SessionClose`，等对端收尾。
    Closing,
    /// 已终结。
    Closed,
}

/// 一个会话的元数据与统计。
#[derive(Clone, Debug)]
pub struct SessionMeta {
    /// 复合键。
    pub key: SessionKey,
    /// 种类。
    pub kind: SessionKind,
    /// 状态。
    pub state: SessionState,
    /// 期望的下一个入站序号（用于拒绝乱序/重放）。
    pub next_inbound_seq: u64,
    /// 已发送的最后一个序号 + 1。
    pub next_outbound_seq: u64,
    /// 当前积压（未交付给会话消费者的帧数）。
    pub queued: usize,
    /// 被背压拒绝过的次数（诊断用）。
    pub backpressure_events: u64,
}

impl SessionMeta {
    /// 新建一个 `Opening` 态会话。
    #[must_use]
    pub const fn new(key: SessionKey, kind: SessionKind) -> Self {
        Self {
            key,
            kind,
            state: SessionState::Opening,
            next_inbound_seq: 0,
            next_outbound_seq: 0,
            queued: 0,
            backpressure_events: 0,
        }
    }
}

/// 会话表。
#[derive(Clone, Debug, Default)]
pub struct SessionTable {
    sessions: HashMap<SessionKey, SessionMeta>,
}

impl SessionTable {
    /// 空表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 会话数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// 查一个会话。
    #[must_use]
    pub fn get(&self, key: &SessionKey) -> Option<&SessionMeta> {
        self.sessions.get(key)
    }

    /// 全部会话（按 key 有序输出，便于稳定展示）。
    pub fn iter(&self) -> impl Iterator<Item = &SessionMeta> {
        self.sessions.values()
    }

    /// 某节点发起的全部会话。
    #[must_use]
    pub fn by_origin(&self, origin: NodeId) -> Vec<&SessionMeta> {
        let mut out: Vec<&SessionMeta> = self
            .sessions
            .values()
            .filter(|m| m.key.origin == origin)
            .collect();
        out.sort_by_key(|m| m.key.id);
        out
    }

    /// 登记一个新会话。
    ///
    /// # Errors
    /// 复合键已存在（[`CoreError::SessionExists`]）。
    pub fn open(&mut self, key: SessionKey, kind: SessionKind) -> Result<&mut SessionMeta> {
        if self.sessions.contains_key(&key) {
            return Err(CoreError::SessionExists { key });
        }
        self.sessions.insert(key, SessionMeta::new(key, kind));
        self.sessions
            .get_mut(&key)
            .ok_or(CoreError::UnknownSession { key })
    }

    /// 对端确认（`SessionReady`）。
    ///
    /// 失败码会把会话直接推进到 `Closing`（调用方随后发 `SessionClose`）。
    ///
    /// # Errors
    /// 会话未知。
    pub fn ready(&mut self, key: &SessionKey, code: SessionCode) -> Result<&mut SessionMeta> {
        let meta = self
            .sessions
            .get_mut(key)
            .ok_or(CoreError::UnknownSession { key: *key })?;
        meta.state = match code {
            SessionCode::Ok => SessionState::Open,
            _ => SessionState::Closing,
        };
        Ok(meta)
    }

    /// 校验并接受一条入站数据。
    ///
    /// `seq` 必须**严格等于**期望值：Link 层已保证有序，因此乱序意味着
    /// 对端实现有 bug 或帧被注入，两者都必须报错而不是「尽力而为」地拼接
    /// （v1 的 `SocksTCPData` 没有序号，乱序即数据损坏）。
    ///
    /// # Errors
    /// 会话未知（[`CoreError::UnknownSession`]）、序号不连续
    /// （[`CoreError::Protocol`] 包装的 `TrailingBytes` 语义等价物）。
    pub fn accept_data(&mut self, data: &SessionData) -> Result<u64> {
        let key = data.key;
        let meta = self
            .sessions
            .get_mut(&key)
            .ok_or(CoreError::UnknownSession { key })?;
        if meta.state != SessionState::Open {
            // 会话存在但还没就绪：这是**顺序错误**，不是「不认识的会话」，
            // 两者必须分开报，否则上层会把协议问题当成路由问题处理。
            return Err(CoreError::Protocol(
                stowaway_protocol::ProtocolError::Payload(format!(
                    "会话 {} 尚未就绪（状态 {:?}）就收到数据",
                    key.id, meta.state
                )),
            ));
        }
        if data.seq != meta.next_inbound_seq {
            return Err(CoreError::Protocol(
                stowaway_protocol::ProtocolError::Payload(format!(
                    "会话 {} 的数据序号不连续：期望 {}，收到 {}",
                    key.id, meta.next_inbound_seq, data.seq
                )),
            ));
        }
        meta.next_inbound_seq = meta.next_inbound_seq.saturating_add(1);
        Ok(data.seq)
    }

    /// 登记一次积压；满 `SESSION_QUEUE_DEPTH` 时拒绝（背压）。
    ///
    /// # Errors
    /// 会话未知或队列已满（[`CoreError::Backpressure`]）。
    pub fn push_backpressure(&mut self, key: &SessionKey) -> Result<()> {
        let meta = self
            .sessions
            .get_mut(key)
            .ok_or(CoreError::UnknownSession { key: *key })?;
        if meta.queued >= SESSION_QUEUE_DEPTH {
            meta.backpressure_events = meta.backpressure_events.saturating_add(1);
            return Err(CoreError::Backpressure);
        }
        meta.queued = meta.queued.saturating_add(1);
        Ok(())
    }

    /// 消费一次积压。
    pub fn pop_backpressure(&mut self, key: &SessionKey) {
        if let Some(meta) = self.sessions.get_mut(key) {
            meta.queued = meta.queued.saturating_sub(1);
        }
    }

    /// 分配下一个出站序号。
    ///
    /// # Errors
    /// 会话未知。
    pub fn next_outbound(&mut self, key: &SessionKey) -> Result<u64> {
        let meta = self
            .sessions
            .get_mut(key)
            .ok_or(CoreError::UnknownSession { key: *key })?;
        let seq = meta.next_outbound_seq;
        meta.next_outbound_seq = seq.saturating_add(1);
        Ok(seq)
    }

    /// 关闭会话并返回其元数据。
    ///
    /// # Errors
    /// 会话未知。
    pub fn close(&mut self, key: &SessionKey, _reason: CloseReason) -> Result<SessionMeta> {
        self.sessions
            .remove(key)
            .ok_or(CoreError::UnknownSession { key: *key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_protocol::ByteBuf;

    fn id(n: u8) -> NodeId {
        let mut b = [0u8; 16];
        b[0] = n;
        NodeId(b)
    }

    fn key(origin: u8, n: u64) -> SessionKey {
        SessionKey::new(id(origin), n)
    }

    #[test]
    fn same_id_from_different_origins_do_not_collide() {
        // 这是 v1 的真实缺陷：两侧各自从 0 发号。
        let mut t = SessionTable::new();
        t.open(key(1, 0), SessionKind::Forward).expect("open a");
        t.open(key(2, 0), SessionKind::Socks5).expect("open b");
        assert_eq!(t.len(), 2);
        assert_eq!(t.by_origin(id(1)).len(), 1);
        assert_eq!(t.by_origin(id(2)).len(), 1);
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let mut t = SessionTable::new();
        t.open(key(1, 7), SessionKind::File).expect("open");
        let err = t.open(key(1, 7), SessionKind::Forward).expect_err("dup");
        assert!(matches!(err, CoreError::SessionExists { .. }));
    }

    #[test]
    fn data_before_ready_is_rejected() {
        let mut t = SessionTable::new();
        t.open(key(1, 1), SessionKind::Socks5).expect("open");
        let data = SessionData {
            key: key(1, 1),
            seq: 0,
            data: ByteBuf::from(vec![1, 2, 3]),
        };
        assert!(t.accept_data(&data).is_err(), "Opening 态不接受数据");
        t.ready(&key(1, 1), SessionCode::Ok).expect("ready");
        assert_eq!(t.accept_data(&data).expect("first"), 0);
    }

    #[test]
    fn out_of_order_data_is_rejected() {
        let mut t = SessionTable::new();
        t.open(key(1, 1), SessionKind::Socks5).expect("open");
        t.ready(&key(1, 1), SessionCode::Ok).expect("ready");
        let bad = SessionData {
            key: key(1, 1),
            seq: 5,
            data: ByteBuf::from(vec![0]),
        };
        let err = t.accept_data(&bad).expect_err("gap");
        assert!(matches!(err, CoreError::Protocol(_)));
    }

    #[test]
    fn replayed_data_is_rejected() {
        let mut t = SessionTable::new();
        t.open(key(1, 1), SessionKind::Socks5).expect("open");
        t.ready(&key(1, 1), SessionCode::Ok).expect("ready");
        let d = SessionData {
            key: key(1, 1),
            seq: 0,
            data: ByteBuf::from(vec![9]),
        };
        t.accept_data(&d).expect("first");
        assert!(t.accept_data(&d).is_err(), "同序号重放必须拒绝");
    }

    #[test]
    fn queue_depth_is_bounded() {
        let mut t = SessionTable::new();
        let k = key(1, 3);
        t.open(k, SessionKind::Socks5).expect("open");
        for _ in 0..SESSION_QUEUE_DEPTH {
            t.push_backpressure(&k).expect("within bound");
        }
        let err = t.push_backpressure(&k).expect_err("overflow");
        assert!(matches!(err, CoreError::Backpressure));
        let meta = t.get(&k).expect("meta");
        assert_eq!(meta.queued, SESSION_QUEUE_DEPTH);
        assert_eq!(meta.backpressure_events, 1);
        t.pop_backpressure(&k);
        t.push_backpressure(&k).expect("room again");
    }

    #[test]
    fn refused_ready_moves_session_to_closing() {
        let mut t = SessionTable::new();
        let k = key(1, 4);
        t.open(k, SessionKind::Forward).expect("open");
        t.ready(&k, SessionCode::NotFound).expect("ready");
        assert_eq!(t.get(&k).expect("meta").state, SessionState::Closing);
        let closed = t.close(&k, CloseReason::Refused).expect("close");
        assert_eq!(closed.key, k);
        assert!(t.is_empty());
    }

    #[test]
    fn outbound_seq_starts_at_zero_and_increments() {
        let mut t = SessionTable::new();
        let k = key(1, 5);
        t.open(k, SessionKind::File).expect("open");
        assert_eq!(t.next_outbound(&k).expect("seq"), 0);
        assert_eq!(t.next_outbound(&k).expect("seq"), 1);
        assert_eq!(t.next_outbound(&k).expect("seq"), 2);
    }
}
