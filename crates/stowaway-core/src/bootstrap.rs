//! 入网引导：把「谁给谁分配编号」这件事落到一个可测试的地方。
//!
//! v1 的流程是 `CHILDUUIDREQ{ParentUUID, IP}` → admin 内部
//! `dispatchChildUUID` → `CHILDUUIDRES`（`admin/handler/uuid.go`）。v2 用
//! `Join{node: UNASSIGNED}` + `JoinAck{node}` 表达同一件事（plan 附录 A 第 3、4 行）。
//!
//! # 为什么单独成模块
//!
//! 这里存在一个先有鸡还是先有蛋的问题：[`crate::Node`] 构造时就要确定自己的
//! `me`，而子节点的 `me` **只能由父节点分配**。于是握手完成与构造 `Node`
//! 之间必须先做一次纯链路层交换：
//!
//! ```text
//! 子节点：LinkCodec（已密封）── Join{node: UNASSIGNED} ──▶ 父节点
//! 父节点：                       分配 NodeId
//! 子节点：LinkCodec ◀── JoinAck{node: 分配值, parent, root, depth} ──
//! ```
//!
//! 交换完两边才知道对端编号，之后才 `Node::new` + `attach_link`。
//! 把这两步抽出来，既避免 `Node` 需要一个「改自己编号」的后门
//! （那会让拓扑里的 `me`/`root`/缓存全部失效），也让编号分配能被单测直接盯住。

use stowaway_protocol::{Join, JoinAck, Message, NodeId, NodeKind};
use stowaway_transport::LinkCodec;

use crate::alloc::NodeIdAllocator;
use crate::error::{CoreError, Result};

/// 子节点侧：发 `Join` 申领编号，读 `JoinAck`。
///
/// 返回（分配到的编号，应答）。调用方随后用这个编号构造
/// [`crate::NodeConfig`] 并 `attach_upstream`。
///
/// # Errors
/// 对端先发了别的消息（说明它没在按 bootstrap 流程走）、或链路关闭。
pub async fn request_id(codec: &mut LinkCodec, kind: NodeKind) -> Result<(NodeId, JoinAck)> {
    let join = Message::Join(Join {
        kind,
        listen: None,
        capabilities: 0,
        node: NodeId::UNASSIGNED,
    });
    codec.send(&join, NodeId::UNASSIGNED, &[]).await?;

    for _ in 0..8 {
        let (_, msg) = codec.recv_message().await?;
        match msg {
            Message::JoinAck(ack) => {
                if !ack.node.is_assigned() {
                    return Err(CoreError::Protocol(
                        stowaway_protocol::ProtocolError::Payload(
                            "父节点回了未分配的编号".to_owned(),
                        ),
                    ));
                }
                return Ok((ack.node, ack));
            }
            // 父节点可能先代子公告别的节点（`Join{node: <child>}`）——
            // 与本节点申领无关，跳过继续等。
            Message::Join(_) => continue,
            other => {
                return Err(CoreError::Protocol(
                    stowaway_protocol::ProtocolError::Payload(format!(
                        "申领编号时收到意外的 {:?}",
                        other.msg_type()
                    )),
                ));
            }
        }
    }
    Err(CoreError::Protocol(
        stowaway_protocol::ProtocolError::Payload("申领编号超时：8 帧内没有 JoinAck".to_owned()),
    ))
}

/// 父节点侧：读子节点的 `Join`，分配编号，回 `JoinAck`。
///
/// 返回（对端编号，对方的 `Join`）。
///
/// # Errors
/// 对方没先发 `Join`、或发的 `Join` 已经带了具体编号（那是在代子公告，
/// 不是自己申领，语义不同，不能混用）。
pub async fn assign_id(
    codec: &mut LinkCodec,
    alloc: &mut NodeIdAllocator,
    me: NodeId,
    root: NodeId,
    my_depth: u16,
) -> Result<(NodeId, Join)> {
    let (_, msg) = codec.recv_message().await?;
    let Message::Join(join) = msg else {
        return Err(CoreError::Protocol(
            stowaway_protocol::ProtocolError::Payload(format!(
                "入网引导期望 Join，收到 {:?}",
                msg.msg_type()
            )),
        ));
    };
    if join.node.is_assigned() {
        return Err(CoreError::Protocol(
            stowaway_protocol::ProtocolError::Payload(
                "入网引导的 Join 必须带 UNASSIGNED（带了具体编号是代子公告）".to_owned(),
            ),
        ));
    }

    let child = alloc.next();
    let ack = Message::JoinAck(JoinAck {
        node: child,
        parent: me,
        root,
        depth: my_depth.saturating_add(1),
    });
    codec.send(&ack, child, &[]).await?;
    Ok((child, join))
}

#[cfg(test)]
mod tests {
    use super::{assign_id, request_id};
    use crate::alloc::NodeIdAllocator;
    use crate::engine::now_ms;
    use stowaway_crypto::Secret;
    use stowaway_protocol::{NodeId, NodeKind, TransportKind};
    use stowaway_transport::{Link, LinkCodec, LinkMeta, boxed};
    use tokio::io::DuplexStream;

    #[derive(Debug)]
    struct TestLink {
        inner: DuplexStream,
        meta: LinkMeta,
    }

    impl tokio::io::AsyncRead for TestLink {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for TestLink {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl Link for TestLink {
        fn meta(&self) -> LinkMeta {
            self.meta.clone()
        }
    }

    async fn handshake_pair() -> (LinkCodec, LinkCodec) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let meta = LinkMeta::new(TransportKind::Raw, None);
        let s = Secret::load("bootstrap-shared-secret", 8).expect("secret");
        let s2 = Secret::load("bootstrap-shared-secret", 8).expect("secret");
        let ca = LinkCodec::new(boxed(TestLink {
            inner: a,
            meta: meta.clone(),
        }));
        let cb = LinkCodec::new(boxed(TestLink { inner: b, meta }));
        let ta = tokio::spawn(async move {
            let mut c = ca;
            c.client_handshake(NodeKind::Agent, TransportKind::Raw, None, &s)
                .await
                .map(|_| c)
        });
        let tb = tokio::spawn(async move {
            let mut c = cb;
            c.server_handshake(NodeKind::Admin, TransportKind::Raw, None, &s2)
                .await
                .map(|_| c)
        });
        (
            ta.await.expect("join").expect("client"),
            tb.await.expect("join").expect("server"),
        )
    }

    #[tokio::test]
    async fn child_receives_an_assigned_id_from_the_parent() {
        let (mut child, mut parent) = handshake_pair().await;
        let mut alloc = NodeIdAllocator::new([1, 2, 3, 4]);
        let admin = NodeId::ADMIN;

        let parent_task = tokio::spawn(async move {
            assign_id(&mut parent, &mut alloc, admin, admin, 0)
                .await
                .map(|(id, _)| id)
        });
        let (assigned, ack) = request_id(&mut child, NodeKind::Agent)
            .await
            .expect("request");
        let from_parent = parent_task.await.expect("join").expect("assign");

        assert_eq!(assigned, from_parent, "两侧必须得到同一个编号");
        assert!(assigned.is_assigned());
        assert_ne!(assigned, admin, "不能把自己分配成 admin");
        assert_eq!(ack.parent, admin);
        assert_eq!(ack.root, admin);
        assert_eq!(ack.depth, 1, "子节点深度是父 + 1");
    }

    #[tokio::test]
    async fn consecutive_children_get_distinct_ids() {
        let mut alloc = NodeIdAllocator::new([9, 8, 7, 6]);
        let admin = NodeId::ADMIN;
        let mut ids = Vec::new();
        for _ in 0..3 {
            let (mut child, mut parent) = handshake_pair().await;
            // 两侧必须并发：一边等 JoinAck，另一边等 Join。
            let (id, from_parent) = tokio::join!(
                request_id(&mut child, NodeKind::Agent),
                assign_id(&mut parent, &mut alloc, admin, admin, 0),
            );
            let (id, _) = id.expect("request");
            let (from_parent, _) = from_parent.expect("assign");
            assert_eq!(id, from_parent);
            ids.push(id);
        }
        assert_eq!(ids.len(), 3);
        assert_ne!(ids[0], ids[1], "两个子节点不能撞号");
        assert_ne!(ids[1], ids[2]);
        assert_ne!(ids[0], ids[2]);
    }

    #[tokio::test]
    async fn parent_rejects_a_join_that_already_carries_an_id() {
        let (mut child, mut parent) = handshake_pair().await;
        let mut alloc = NodeIdAllocator::new([1, 1, 1, 1]);
        let admin = NodeId::ADMIN;
        // 误把「代子公告」当成「自己申领」：应当明确报错，不能将错就错。
        let bogus = stowaway_protocol::Message::Join(stowaway_protocol::Join {
            kind: NodeKind::Agent,
            listen: None,
            capabilities: 0,
            node: NodeId::new([0x77; 16]),
        });
        // 由子节点一侧真的把这种 Join 发出去（父节点读到的才是它）。
        child.send(&bogus, admin, &[]).await.expect("send");
        let err = assign_id(&mut parent, &mut alloc, admin, admin, 0)
            .await
            .expect_err("必须报错");
        assert!(
            err.to_string().contains("UNASSIGNED"),
            "错误信息应指出语义混用"
        );
    }

    #[tokio::test]
    async fn request_id_gives_up_when_the_peer_sends_something_else() {
        let (mut child, mut parent) = handshake_pair().await;
        // 父节点不发 JoinAck，反而发心跳：子节点必须报错而不是无限等。
        let hb = stowaway_protocol::Message::Heartbeat(stowaway_protocol::Heartbeat {
            send_ts: now_ms(),
            echo_ts: 0,
        });
        // 由父节点那一侧发出（子节点读到的才是它）。
        parent.send(&hb, NodeId::ADMIN, &[]).await.expect("send");
        let err = request_id(&mut child, NodeKind::Agent)
            .await
            .expect_err("必须报错");
        assert!(
            err.to_string().contains("Heartbeat"),
            "错误信息应指出收到什么"
        );
    }
}
