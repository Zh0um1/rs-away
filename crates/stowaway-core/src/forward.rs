//! forward / backward 的 **Prepare / Commit 两阶段**服务。
//!
//! 权威：`docs/plan.md` §4.6（`ServiceRequest{phase: Probe|Run}`）、§4.8
//! （会话模型）、附录 A（`FORWARDTEST`/`FORWARDSTART` 的映射）。
//!
//! # 为什么必须两阶段
//!
//! v1 的 `admin/handler/forward.go:124-132` 里有一段 DEAD LOCK 注释：它先把
//! 数据通道注册进 manager，再发 `FORWARDSTART`；对端若不回数据就一直等
//! 注册好的通道，而发送方又在等注册完成，于是互相卡死。它靠「先
//! `F_GETDATACHAN` 再发 START」的人为顺序规避。
//!
//! v2 把这一步写成协议层契约：
//!
//! 1. **Probe**：`ServiceRequest{kind: Connect, phase: Probe}`，对端只验证
//!    「这个目标我能不能拨通」，不分配任何资源；
//! 2. **Commit**：只有 Probe 返回 `SessionCode::Ok` 才真正 `bind` 本地端口
//!    并进入数据阶段。
//!
//! 这样「端口已占用但没有通路」（v1 的实际故障形态）在结构上不可能出现：
//! 端口的 `TcpListener` 是 Commit 之后才创建的，失败路径里根本不存在它。

use std::net::SocketAddr;
use std::time::Duration;

use stowaway_protocol::{
    CloseReason, ConnectParam, Message, NodeId, ServiceExit, ServiceKind, ServiceParam,
    ServicePhase, ServiceRequest, SessionCode, SessionKey,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::error::{CoreError, Result};

/// 探测超时。与 v1 `FORWARDTEST` 一样，对端必须在这段时间内给出答复。
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// 一次 forward/backward 服务的规格。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    /// 会话键（由发起方分配）。
    pub key: SessionKey,
    /// 服务种类；forward 固定用 `Connect`（探测即「能不能拨到这个地址」）。
    pub kind: ServiceKind,
    /// 本地监听端口；`0` 表示让内核选一个。
    pub local_port: u16,
    /// 远端目标 `host:port`。
    pub remote_target: String,
}

impl ForwardSpec {
    /// 构造（`kind` 固定为 `ServiceKind::Connect`）。
    #[must_use]
    pub fn new(key: SessionKey, local_port: u16, remote_target: impl Into<String>) -> Self {
        Self {
            key,
            kind: ServiceKind::Connect,
            local_port,
            remote_target: remote_target.into(),
        }
    }

    /// 探测消息：`ServiceRequest{kind: Connect, phase: Probe}`。
    ///
    /// 携带的参数是**要拨的目标**（v1 的 `FORWARDTEST` 语义）。
    #[must_use]
    pub fn probe(&self) -> Message {
        Message::ServiceRequest(ServiceRequest {
            key: self.key,
            kind: self.kind,
            phase: ServicePhase::Probe,
            param: ServiceParam::Connect(ConnectParam {
                addr: self.remote_target.clone(),
            }),
        })
    }

    /// 执行消息：`ServiceRequest{kind: Connect, phase: Run}`。
    #[must_use]
    pub fn run(&self) -> Message {
        Message::ServiceRequest(ServiceRequest {
            key: self.key,
            kind: self.kind,
            phase: ServicePhase::Run,
            param: ServiceParam::Connect(ConnectParam {
                addr: self.remote_target.clone(),
            }),
        })
    }

    /// 远端目标。
    #[must_use]
    pub fn remote_target(&self) -> &str {
        &self.remote_target
    }
}

/// 发探测并等答复。
///
/// 返回对端的 `SessionCode`；只有 `Ok` 才允许调用 [`CommittedForward::bind`]。
///
/// # Errors
/// 超时、发送失败、对端拒绝（`ServiceReply` 非 Ok）、对端提前退出
/// （`ServiceExit`）。错误文案里带上对端码，便于控制台直接展示。
pub async fn probe<F>(
    spec: &ForwardSpec,
    peer: NodeId,
    send: F,
    replies: &mut mpsc::UnboundedReceiver<Message>,
) -> Result<SessionCode>
where
    F: FnOnce(Message) -> Result<()>,
{
    send(spec.probe())?;
    let fut = async {
        while let Some(msg) = replies.recv().await {
            match msg {
                Message::ServiceReply(reply) if reply.key == spec.key => {
                    if reply.code == SessionCode::Ok {
                        return Ok(SessionCode::Ok);
                    }
                    return Err(CoreError::Protocol(
                        stowaway_protocol::ProtocolError::Payload(format!(
                            "{} 到 {} 的探测被拒绝：{:?}{}",
                            peer,
                            spec.remote_target,
                            reply.code,
                            if reply.detail.is_empty() {
                                String::new()
                            } else {
                                format!("（{}）", reply.detail)
                            }
                        )),
                    ));
                }
                Message::ServiceExit(exit) if exit.key == spec.key => {
                    return Err(CoreError::Protocol(
                        stowaway_protocol::ProtocolError::Payload(format!(
                            "{} 在探测阶段退出：{:?}{}",
                            peer, exit.code, exit.detail
                        )),
                    ));
                }
                _ => {}
            }
        }
        Err(CoreError::LinkClosed)
    };
    match timeout(PROBE_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(CoreError::Protocol(
            stowaway_protocol::ProtocolError::Payload(format!(
                "等待 {} 的探测答复超时（{} 秒）",
                peer,
                PROBE_TIMEOUT.as_secs()
            )),
        )),
    }
}

/// 探测成功后才可创建的本地监听（Commit 阶段）。
///
/// 它自己持有 `TcpListener`：`Drop` 即释放端口，因此 `stop` 的实现就是
/// 「丢掉这个值」，不需要额外的注销协议。
#[derive(Debug)]
pub struct CommittedForward {
    addr: SocketAddr,
    listener: TcpListener,
}

impl CommittedForward {
    /// 绑定本地端口。**只能在 [`probe`] 返回 `Ok` 之后调用**。
    ///
    /// # Errors
    /// 端口被占用或权限不足。
    pub async fn bind(local_port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", local_port)).await?;
        let addr = listener.local_addr()?;
        Ok(Self { addr, listener })
    }

    /// 接受一条本地连接。
    ///
    /// # Errors
    /// 监听器出错。
    pub async fn accept(&self) -> Result<TcpStream> {
        let (stream, _) = self.listener.accept().await?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    /// 实际监听的地址（`local_port == 0` 时这里是内核分配的端口）。
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

/// 服务方向（只用于日志与控制台文案；协议层用 `SessionKind` 表达）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// admin 监听、agent 侧拨号（v1 `FORWARDSTART`）。
    Forward,
    /// agent 监听、admin 侧拨号（v1 `BACKWARDSTART`）。
    Backward,
}

impl Direction {
    /// 对应的协议服务种类。
    #[must_use]
    pub const fn service_kind(self) -> ServiceKind {
        ServiceKind::Connect
    }

    /// 控制台展示名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Backward => "backward",
        }
    }
}

/// 停止一条 forward/backward：统一形态是 `ServiceExit{code: Ok}`。
///
/// v1 用 `STOPFORWARDING`/`STOPBACKWARDING` + 端口复用 magic 两条独立路径，
/// 这里合并成一次 `ServiceExit`，接收方按 `key` 找到自己的监听器并将其
/// drop（端口随之释放）。
#[must_use]
pub fn stop_message(key: SessionKey, detail: impl Into<String>) -> Message {
    Message::ServiceExit(ServiceExit {
        key,
        code: SessionCode::Ok,
        detail: detail.into(),
    })
}

/// 会话关闭消息（中继结束时用）。
#[must_use]
pub fn close_message(key: SessionKey, reason: CloseReason) -> Message {
    Message::SessionClose(stowaway_protocol::SessionClose {
        key,
        reason,
        detail: String::new(),
    })
}

/// 控制台展示用的一句话描述。
#[must_use]
pub fn describe(spec: &ForwardSpec, addr: SocketAddr) -> String {
    format!(
        "{} :{} -> {}（会话 {}）",
        Direction::Forward.as_str(),
        spec.local_port,
        spec.remote_target,
        addr.port()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ForwardSpec {
        ForwardSpec::new(SessionKey::new(NodeId::ADMIN, 7), 0, "127.0.0.1:8080")
    }

    #[test]
    fn probe_and_run_carry_the_remote_target() {
        let s = spec();
        let Message::ServiceRequest(probe) = s.probe() else {
            panic!("probe 必须是 ServiceRequest")
        };
        assert_eq!(probe.phase, ServicePhase::Probe);
        assert_eq!(probe.kind, ServiceKind::Connect);
        let ServiceParam::Connect(c) = probe.param else {
            panic!("必须是 Connect 参数")
        };
        assert_eq!(c.addr, "127.0.0.1:8080");

        let Message::ServiceRequest(run) = s.run() else {
            panic!("run 必须是 ServiceRequest")
        };
        assert_eq!(run.phase, ServicePhase::Run);
        assert_eq!(run.key, s.key);
    }

    #[tokio::test]
    async fn probe_returns_ok_on_success() {
        let s = spec();
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Message::ServiceReply(stowaway_protocol::ServiceReply {
            key: s.key,
            code: SessionCode::Ok,
            detail: String::new(),
        }))
        .expect("send");
        let code = probe(&s, NodeId::ADMIN, |_m| Ok(()), &mut rx)
            .await
            .expect("probe");
        assert_eq!(code, SessionCode::Ok);
    }

    #[tokio::test]
    async fn probe_failure_carries_peer_code() {
        let s = spec();
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Message::ServiceReply(stowaway_protocol::ServiceReply {
            key: s.key,
            code: SessionCode::Refused,
            detail: "目标拒绝".to_owned(),
        }))
        .expect("send");
        let err = probe(&s, NodeId::ADMIN, |_m| Ok(()), &mut rx)
            .await
            .expect_err("必须失败");
        assert!(err.to_string().contains("Refused"), "{err}");
    }

    // 超时路径不在此处验证：那需要真的等 10 秒（`test-util` 的暂停时钟本仓
    // 未开启）。这里验证「通道关闭立刻返回」的等价兜底，保证不会永久挂住。
    #[tokio::test]
    async fn probe_ends_when_reply_channel_closes() {
        let s = spec();
        let (tx, mut rx) = mpsc::unbounded_channel();
        drop(tx);
        let err = probe(&s, NodeId::ADMIN, |_m| Ok(()), &mut rx)
            .await
            .expect_err("通道关闭必须报错而不是挂住");
        assert!(matches!(err, CoreError::LinkClosed), "{err}");
    }

    #[tokio::test]
    async fn probe_send_failure_is_propagated() {
        let s = spec();
        let (_tx, mut rx) = mpsc::unbounded_channel();
        let err = probe(&s, NodeId::ADMIN, |_m| Err(CoreError::LinkClosed), &mut rx)
            .await
            .expect_err("必须传播");
        assert!(matches!(err, CoreError::LinkClosed));
    }

    #[tokio::test]
    async fn committed_forward_releases_the_port_on_drop() {
        let committed = CommittedForward::bind(0).await.expect("bind");
        let addr = committed.local_addr();
        assert_ne!(addr.port(), 0);
        // 已占用：第二次 bind 必须失败。
        assert!(
            TcpListener::bind(addr).await.is_err(),
            "同一端口不应能重复绑定"
        );
        drop(committed);
        // 释放后应当可以重绑。
        assert!(
            TcpListener::bind(addr).await.is_ok(),
            "drop 之后端口必须释放"
        );
    }

    #[test]
    fn stop_message_is_ok_exit() {
        let key = SessionKey::new(NodeId::ADMIN, 9);
        let Message::ServiceExit(exit) = stop_message(key, "user stop") else {
            panic!("exit")
        };
        assert_eq!(exit.code, SessionCode::Ok);
        assert_eq!(exit.key, key);
        assert_eq!(exit.detail, "user stop");
    }

    #[test]
    fn direction_names_are_stable() {
        assert_eq!(Direction::Forward.as_str(), "forward");
        assert_eq!(Direction::Backward.as_str(), "backward");
        assert_eq!(Direction::Forward.service_kind(), ServiceKind::Connect);
    }

    #[test]
    fn describe_mentions_port_and_target() {
        let s = spec();
        let text = describe(&s, SocketAddr::from(([0, 0, 0, 0], 12345)));
        assert!(text.contains("12345"), "{text}");
        assert!(text.contains("127.0.0.1:8080"), "{text}");
    }
}
