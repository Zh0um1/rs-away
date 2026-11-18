//! 帧层：在 [`Link`](crate::link::Link) 之上做分帧、分片、密封与握手接线。
//!
//! 权威：`docs/plan.md` §4.4（帧格式）、§4.5（握手与密封）、
//! `docs/design/transport.md` §3（Link 契约：**字节流不保边界**）。
//!
//! ```text
//! 应用消息 ──Message::encode──▶ 逻辑帧 payload
//!    │超过 min(MAX_FRAME, link.max_frame) - 24
//!    ▼
//! 分片（每片置 flags.FRAG，最后一片不置）
//!    ▼
//! [可选] LinkSealer::seal(AAD = 帧头含 payload_len)
//!    ▼
//! payload = counter(8B, LE) ‖ ciphertext(明文 ‖ 16B tag)
//!    ▼
//! Frame::encode 写链路
//! ```
//!
//! **counter 为什么放在 payload 前缀而不是帧头**：帧头是 AEAD 的 AAD，
//! 若把 counter 放帧头，接收端在解封前就要信任它；放在密文前缀并由
//! [`LinkSealer::open`] 内部校验窗口，才满足「先验 AEAD 再推进窗口」。
//! 代价是每帧 8 字节开销，换来重放/乱序的严格判据。

use std::io;

use bytes::{Bytes, BytesMut};
use stowaway_crypto::{
    ClientHandshake, HandshakeOutcome, HandshakeSecrets, LinkSealer, Secret, ServerHandshake,
};
use stowaway_protocol::{
    FRAGMENT_MAX, Frame, FrameFlags, FrameHeader, MAX_FRAME, Message, MsgType, NodeId,
    ProtocolError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{Result, TransportError};
use crate::link::{DialTarget, Dialer, Link, LinkMeta, Listener};

/// AEAD tag 长度（AES-256-GCM）。
pub const TAG_LEN: usize = 16;
/// 帧内 counter 前缀长度。
pub const COUNTER_LEN: usize = 8;
/// 密封后每帧的固定额外开销。
pub const SEAL_OVERHEAD: usize = COUNTER_LEN + TAG_LEN;

/// 分片时单片允许的最小明文长度（防极端 `max_frame` 配置把单片挤成 0）。
const MIN_CHUNK: usize = 512;

/// 一次握手的结果。
#[derive(Debug)]
pub struct HandshakeResult {
    /// 派生出的链路密钥（含 `auth_key`/`link_key`/`session_key_seed`）。
    pub secrets: HandshakeSecrets,
    /// 双方一致的 transcript hash 与 `seed_ack`。
    pub outcome: HandshakeOutcome,
    /// 对端声明的传输种类（已参与 TH，不可降级）。
    pub peer_transport: stowaway_protocol::TransportKind,
    /// 对端声明的 TLS 指纹。
    pub peer_tls_fp: Option<[u8; 32]>,
    /// 对端角色。
    pub peer_kind: stowaway_protocol::NodeKind,
    /// 本端是否为发起方（决定 `LinkSealer` 的 iv 方向）。
    pub is_client: bool,
}

/// 链路编解码器：把「字节流」变成「逻辑帧 / 消息」。
pub struct LinkCodec {
    link: Box<dyn Link>,
    sealer: Option<LinkSealer>,
    /// 接收侧未解析完的字节（帧可能跨多次 `poll_read`）。
    buf: BytesMut,
    /// 分片重组缓冲。
    fragments: Vec<u8>,
    /// 分片重组时的首片标志（保留 LAST/E2E 等，去掉 FRAG）。
    frag_flags: Option<FrameFlags>,
    frag_type: Option<MsgType>,
    frag_dest: Option<NodeId>,
}

impl std::fmt::Debug for LinkCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkCodec")
            .field("link", &self.link.meta())
            .field("sealed", &self.sealer.is_some())
            .field("buffered", &self.buf.len())
            .field("fragmenting", &self.frag_flags.is_some())
            .finish_non_exhaustive()
    }
}

impl LinkCodec {
    /// 用一条未加密链路构造（握手 flight 走这条路）。
    #[must_use]
    pub fn new(link: Box<dyn Link>) -> Self {
        Self {
            link,
            sealer: None,
            buf: BytesMut::with_capacity(8 * 1024),
            fragments: Vec::new(),
            frag_flags: None,
            frag_type: None,
            frag_dest: None,
        }
    }

    /// 链路元数据。
    #[must_use]
    pub fn meta(&self) -> LinkMeta {
        self.link.meta()
    }

    /// 是否已启用链路密封。
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealer.is_some()
    }

    /// 尚未消费的字节数（诊断用）。
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// 单片明文长度上限：扣除密封开销与链路单帧上限。
    #[must_use]
    pub fn max_chunk(&self) -> usize {
        let overhead = if self.sealer.is_some() {
            SEAL_OVERHEAD
        } else {
            0
        };
        let cap = self.link.meta().max_frame.min(MAX_FRAME);
        let want = cap.saturating_sub(overhead);
        want.clamp(MIN_CHUNK, FRAGMENT_MAX)
    }

    // ---------------------------------------------------------------- 握手

    /// 客户端侧 3-flight 握手（Hello → HelloAck → AuthConfirm）。
    ///
    /// 成功后本编解码器自动切换为密封模式，后续帧一律带 `flags.SEALED`。
    ///
    /// # Errors
    /// 帧层错误、对端 proof 不匹配、secret 不符。
    pub async fn client_handshake(
        &mut self,
        role: stowaway_protocol::NodeKind,
        transport: stowaway_protocol::TransportKind,
        tls_fp: Option<[u8; 32]>,
        secret: &Secret,
    ) -> Result<HandshakeResult> {
        let client = ClientHandshake::new(role, transport, tls_fp);
        let hello = client.hello();
        self.send_payload(
            MsgType::Hello,
            NodeId::UNASSIGNED,
            &[],
            FrameFlags::empty(),
            &Message::Hello(hello).encode()?,
        )
        .await?;

        let (frame, ack) = self.recv_expect(MsgType::HelloAck).await?;
        let _ = frame;
        let stowaway_protocol::Message::HelloAck(ack) = ack else {
            return Err(TransportError::HandshakeOrder {
                expected: "HelloAck",
                actual: "其它",
            });
        };

        let (confirm, secrets, outcome) = client.finish(&ack, secret)?;
        let peer_kind = ack.kind;
        let peer_transport = transport;
        let peer_tls_fp = tls_fp;

        self.send_payload(
            MsgType::AuthConfirm,
            NodeId::UNASSIGNED,
            &[],
            FrameFlags::empty(),
            &Message::AuthConfirm(confirm).encode()?,
        )
        .await?;

        self.install_sealer(&secrets.keys.link_key, true);

        Ok(HandshakeResult {
            secrets,
            outcome,
            peer_transport,
            peer_tls_fp,
            peer_kind,
            is_client: true,
        })
    }

    /// 服务端侧 3-flight 握手（收 Hello → 发 HelloAck → 收 AuthConfirm）。
    ///
    /// # Errors
    /// 帧层错误、首帧不是 `Hello`、对端声明的传输/TLS 与实际不符、proof 不匹配。
    pub async fn server_handshake(
        &mut self,
        role: stowaway_protocol::NodeKind,
        expected_transport: stowaway_protocol::TransportKind,
        expected_tls_fp: Option<[u8; 32]>,
        secret: &Secret,
    ) -> Result<HandshakeResult> {
        let (_, hello) = self.recv_expect(MsgType::Hello).await?;
        let stowaway_protocol::Message::Hello(hello) = hello else {
            return Err(TransportError::HandshakeOrder {
                expected: "Hello",
                actual: "其它",
            });
        };

        let peer_kind = hello.kind;
        let peer_transport = hello.transport;
        let peer_tls_fp = hello.tls_fp;

        let (state, ack) =
            ServerHandshake::accept(&hello, secret, role, expected_transport, expected_tls_fp)?;
        self.send_payload(
            MsgType::HelloAck,
            NodeId::UNASSIGNED,
            &[],
            FrameFlags::empty(),
            &Message::HelloAck(ack).encode()?,
        )
        .await?;

        let (_, confirm) = self.recv_expect(MsgType::AuthConfirm).await?;
        let stowaway_protocol::Message::AuthConfirm(confirm) = confirm else {
            return Err(TransportError::HandshakeOrder {
                expected: "AuthConfirm",
                actual: "其它",
            });
        };

        let (secrets, outcome) = state.finish(&confirm)?;
        self.install_sealer(&secrets.keys.link_key, false);

        Ok(HandshakeResult {
            secrets,
            outcome,
            peer_transport,
            peer_tls_fp,
            peer_kind,
            is_client: false,
        })
    }

    fn install_sealer(&mut self, link_key: &[u8; stowaway_crypto::KEY_LEN], is_client: bool) {
        self.sealer = Some(LinkSealer::new(link_key, is_client));
    }

    // ---------------------------------------------------------------- 发送

    /// 发送一条消息（自动分片、自动密封）。
    ///
    /// # Errors
    /// 载荷编码失败、链路写失败、计数器耗尽。
    pub async fn send(&mut self, msg: &Message, dest: NodeId, via: &[NodeId]) -> Result<()> {
        let payload = msg.encode()?;
        self.send_payload(msg.msg_type(), dest, via, FrameFlags::empty(), &payload)
            .await
    }

    /// 发送一条消息并附加标志（`LAST`/`E2E` 等；`SEALED` 由本方法自己决定）。
    ///
    /// # Errors
    /// 同 [`Self::send`]。
    pub async fn send_with_flags(
        &mut self,
        msg: &Message,
        dest: NodeId,
        via: &[NodeId],
        flags: FrameFlags,
    ) -> Result<()> {
        let payload = msg.encode()?;
        self.send_payload(msg.msg_type(), dest, via, flags, &payload)
            .await
    }

    /// 发送已编码的逻辑帧（`payload` 为明文；密封与分片由本方法负责）。
    ///
    /// # Errors
    /// 链路写失败、计数器耗尽。
    pub async fn send_payload(
        &mut self,
        msg_type: MsgType,
        dest: NodeId,
        via: &[NodeId],
        flags: FrameFlags,
        payload: &[u8],
    ) -> Result<()> {
        let chunk = self.max_chunk();
        let mut rest = payload;
        loop {
            let take = rest.len().min(chunk);
            let (this, next) = rest.split_at(take);
            let more = !next.is_empty();
            let mut frag_flags = flags;
            if more {
                frag_flags.insert(FrameFlags::FRAG);
            }
            self.write_frame_payload(msg_type, dest, via, frag_flags, this)
                .await?;
            if !more {
                break;
            }
            rest = next;
        }
        // 空载荷也会走一次循环体（`take == 0`），因此「空帧」必然写出，
        // 对端不会因为零长消息而卡在等帧上。
        self.link.flush().await?;
        Ok(())
    }

    async fn write_frame_payload(
        &mut self,
        msg_type: MsgType,
        dest: NodeId,
        via: &[NodeId],
        flags: FrameFlags,
        plaintext: &[u8],
    ) -> Result<()> {
        let frame = match self.sealer.as_mut() {
            Some(sealer) => {
                let mut sealed_flags = flags;
                sealed_flags.insert(FrameFlags::SEALED);
                // payload_len 必须包含 counter 前缀与 AEAD tag，先算出来才能拿它做 AAD。
                let total = plaintext.len() + SEAL_OVERHEAD;
                let mut header = FrameHeader::new(sealed_flags, msg_type, dest, via.to_vec());
                header.payload_len = total;
                let aad = header.encode_to_vec();
                let (ct, counter) = sealer.seal(&aad, plaintext)?;
                debug_assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
                let mut payload = Vec::with_capacity(total);
                payload.extend_from_slice(&counter.to_le_bytes());
                payload.extend_from_slice(&ct);
                Frame {
                    header,
                    payload: Bytes::from(payload),
                }
            }
            None => Frame::new(flags, msg_type, dest, via.to_vec(), plaintext.to_vec()),
        };
        let bytes = frame.encode();
        self.link.write_all(&bytes).await?;
        Ok(())
    }

    // ---------------------------------------------------------------- 接收

    /// 接收一个逻辑帧（自动重组分片、自动解封）。
    ///
    /// # Errors
    /// 链路读失败、帧格式非法、AEAD 校验失败、重放、未握手却收到密封帧。
    pub async fn recv(&mut self) -> Result<Frame> {
        loop {
            let physical = self.read_physical_frame().await?;
            let logical = self.unseal(physical)?;
            if logical.header.flags.is_fragment() {
                self.push_fragment(&logical)?;
                continue;
            }
            if let Some(mut joined) = self.take_fragments() {
                joined.extend_from_slice(&logical.payload);
                let mut flags = logical.header.flags;
                flags.remove(FrameFlags::FRAG);
                if let Some(prev) = self.frag_flags.take() {
                    flags = flags.union(prev);
                }
                let dest = self.frag_dest.take().unwrap_or(logical.header.dest);
                let msg_type = self.frag_type.take().unwrap_or(logical.header.msg_type);
                return Ok(Frame {
                    header: FrameHeader {
                        flags,
                        msg_type,
                        dest,
                        via: logical.header.via,
                        payload_len: joined.len(),
                    },
                    payload: Bytes::from(joined),
                });
            }
            return Ok(logical);
        }
    }

    /// 接收一条消息（先取帧，再按 `msg_type` 解载荷）。
    ///
    /// # Errors
    /// 同 [`Self::recv`]，外加载荷解码失败。
    pub async fn recv_message(&mut self) -> Result<(Frame, Message)> {
        let frame = self.recv().await?;
        let msg = Message::decode(frame.header.msg_type, &frame.payload)?;
        Ok((frame, msg))
    }

    async fn recv_expect(&mut self, want: MsgType) -> Result<(Frame, Message)> {
        let (frame, msg) = self.recv_message().await?;
        if frame.header.msg_type != want {
            return Err(TransportError::HandshakeOrder {
                expected: msg_type_name(want),
                actual: msg_type_name(frame.header.msg_type),
            });
        }
        Ok((frame, msg))
    }

    fn push_fragment(&mut self, frame: &Frame) -> Result<()> {
        if self.fragments.len() + frame.payload.len() > MAX_FRAME {
            self.fragments.clear();
            self.frag_flags = None;
            return Err(TransportError::FrameTooLarge {
                actual: self.fragments.len() + frame.payload.len(),
                max: MAX_FRAME,
            });
        }
        if self.frag_flags.is_none() {
            // 首片自身带 FRAG 位；重组时必须剥掉，否则返回的逻辑帧会被
            // 误标成「还有后续分片」。
            let mut keep = frame.header.flags;
            keep.remove(FrameFlags::FRAG);
            self.frag_flags = Some(keep);
            self.frag_type = Some(frame.header.msg_type);
            self.frag_dest = Some(frame.header.dest);
        }
        self.fragments.extend_from_slice(&frame.payload);
        Ok(())
    }

    fn take_fragments(&mut self) -> Option<Vec<u8>> {
        if self.fragments.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.fragments))
        }
    }

    /// 从链路读出一个**物理**帧（未解封、未重组）。
    async fn read_physical_frame(&mut self) -> Result<Frame> {
        loop {
            if let Some(frame) = try_take_frame(&mut self.buf)? {
                return Ok(frame);
            }
            let n = self.link.read_buf(&mut self.buf).await?;
            if n == 0 {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "链路在对端关闭前中断",
                )));
            }
        }
    }

    fn unseal(&mut self, frame: Frame) -> Result<Frame> {
        if !frame.header.flags.is_sealed() {
            return Ok(frame);
        }
        let Some(sealer) = self.sealer.as_mut() else {
            return Err(TransportError::HandshakeOrder {
                expected: "握手完成（收到密封帧前必须先握手）",
                actual: "密封帧",
            });
        };
        if frame.payload.len() < SEAL_OVERHEAD {
            return Err(TransportError::Protocol(ProtocolError::Truncated {
                need: SEAL_OVERHEAD,
                have: frame.payload.len(),
                field: "sealed payload",
            }));
        }
        let (counter_bytes, ciphertext) = frame.payload.split_at(COUNTER_LEN);
        let mut c = [0u8; COUNTER_LEN];
        c.copy_from_slice(counter_bytes);
        let counter = u64::from_le_bytes(c);
        let plaintext = sealer.open(counter, &frame.header.header_bytes(), ciphertext)?;
        Ok(Frame {
            header: FrameHeader {
                payload_len: plaintext.len(),
                ..frame.header
            },
            payload: Bytes::from(plaintext),
        })
    }
}

/// 从缓冲区里取出一帧（不足则返回 `None`，头部非法则报错）。
fn try_take_frame(buf: &mut BytesMut) -> Result<Option<Frame>> {
    if buf.is_empty() {
        return Ok(None);
    }
    let parsed = FrameHeader::parse(buf);
    let (header, header_len) = match parsed {
        Ok(v) => v,
        Err(ProtocolError::Truncated { .. }) => {
            // 帧头还没到齐；但若缓冲已超过理论头部上限，说明对端在灌垃圾。
            if buf.len() > stowaway_protocol::MAX_HEADER_LEN {
                return Err(TransportError::Protocol(ProtocolError::Truncated {
                    need: stowaway_protocol::MAX_HEADER_LEN,
                    have: buf.len(),
                    field: "header",
                }));
            }
            return Ok(None);
        }
        Err(e) => return Err(TransportError::Protocol(e)),
    };
    let total = header_len + header.payload_len;
    if buf.len() < total {
        buf.reserve(total - buf.len());
        return Ok(None);
    }
    let raw = buf.split_to(total).freeze();
    let payload = raw.slice(header_len..);
    Ok(Some(Frame { header, payload }))
}

const fn msg_type_name(t: MsgType) -> &'static str {
    match t {
        MsgType::Hello => "Hello",
        MsgType::HelloAck => "HelloAck",
        MsgType::AuthConfirm => "AuthConfirm",
        MsgType::Heartbeat => "Heartbeat",
        MsgType::Shutdown => "Shutdown",
        MsgType::Join => "Join",
        MsgType::JoinAck => "JoinAck",
        MsgType::Rejoin => "Rejoin",
        MsgType::NodeStatus => "NodeStatus",
        MsgType::Memo => "Memo",
        MsgType::OpenSession => "OpenSession",
        MsgType::SessionReady => "SessionReady",
        MsgType::SessionData => "SessionData",
        MsgType::SessionClose => "SessionClose",
        MsgType::ServiceRequest => "ServiceRequest",
        MsgType::ServiceReply => "ServiceReply",
        MsgType::ServiceData => "ServiceData",
        MsgType::ServiceExit => "ServiceExit",
    }
}

/// 用协商好的 spec 建一个 dialer。
///
/// # Errors
/// 传输种类未编译进本二进制时返回 [`TransportError::FeatureDisabled`]。
pub fn dialer_for(
    spec: &crate::TransportSpec,
    tls: Option<crate::TlsConfig>,
) -> Result<crate::link::AnyDialer> {
    let nodelay = spec.nodelay;
    let keepalive = spec.keepalive_secs.map(std::time::Duration::from_secs);
    match spec.kind {
        stowaway_protocol::TransportKind::Raw => {
            #[cfg(feature = "transport-raw")]
            {
                Ok(crate::link::AnyDialer::Raw(crate::tcp::RawDialer::new(
                    nodelay, keepalive,
                )))
            }
            #[cfg(not(feature = "transport-raw"))]
            {
                let _ = (nodelay, keepalive, tls);
                Err(TransportError::FeatureDisabled {
                    kind: "raw",
                    feature: "transport-raw",
                })
            }
        }
        stowaway_protocol::TransportKind::Ws => {
            #[cfg(feature = "transport-ws")]
            {
                Ok(crate::link::AnyDialer::Ws(crate::ws::WsDialer::new(
                    spec.effective_path().to_owned(),
                    spec.effective_domain(),
                    tls,
                )))
            }
            #[cfg(not(feature = "transport-ws"))]
            {
                let _ = tls;
                Err(TransportError::FeatureDisabled {
                    kind: "ws",
                    feature: "transport-ws",
                })
            }
        }
        stowaway_protocol::TransportKind::Kcp => {
            #[cfg(feature = "transport-kcp")]
            {
                Ok(crate::link::AnyDialer::Kcp(
                    crate::kcp::KcpDialer::from_spec(spec)?,
                ))
            }
            #[cfg(not(feature = "transport-kcp"))]
            {
                let _ = tls;
                Err(TransportError::FeatureDisabled {
                    kind: "kcp",
                    feature: "transport-kcp",
                })
            }
        }
        stowaway_protocol::TransportKind::Quic => {
            Err(TransportError::Spec(crate::SpecError::QuicUnimplemented))
        }
    }
}

/// 用协商好的 spec 建一个 listener。
///
/// # Errors
/// 传输种类未编译进本二进制、KCP 与 TLS 组合（需 DTLS）时返回错误。
pub fn listener_for(
    spec: &crate::TransportSpec,
    tls: Option<crate::TlsConfig>,
) -> Result<impl std::future::Future<Output = Result<crate::link::AnyListener>> + Send + 'static> {
    let _ = &tls;
    let kind = spec.kind;
    let addr = spec.resolve_addr()?;
    let nodelay = spec.nodelay;
    let keepalive = spec.keepalive_secs.map(std::time::Duration::from_secs);
    let path = spec.effective_path().to_owned();
    let kcp_spec = spec.clone();
    Ok(Box::pin(async move {
        match kind {
            stowaway_protocol::TransportKind::Raw => {
                #[cfg(feature = "transport-raw")]
                {
                    let l = crate::tcp::RawListener::bind(addr, tls, nodelay, keepalive).await?;
                    Ok(crate::link::AnyListener::Raw(l))
                }
                #[cfg(not(feature = "transport-raw"))]
                {
                    let _ = (nodelay, keepalive);
                    Err(TransportError::FeatureDisabled {
                        kind: "raw",
                        feature: "transport-raw",
                    })
                }
            }
            stowaway_protocol::TransportKind::Ws => {
                #[cfg(feature = "transport-ws")]
                {
                    let l = crate::ws::WsListener::bind(addr, path, tls).await?;
                    Ok(crate::link::AnyListener::Ws(l))
                }
                #[cfg(not(feature = "transport-ws"))]
                {
                    let _ = path;
                    Err(TransportError::FeatureDisabled {
                        kind: "ws",
                        feature: "transport-ws",
                    })
                }
            }
            stowaway_protocol::TransportKind::Kcp => {
                #[cfg(feature = "transport-kcp")]
                {
                    if tls.is_some() {
                        // KCP 基于 UDP，TLS 无法叠加（需 DTLS，v2 不做）。
                        return Err(TransportError::Tls(
                            "kcp 不能与 TLS 叠加（需要 DTLS，v2 未实现）".to_owned(),
                        ));
                    }
                    let l = crate::kcp::KcpListener::bind(&kcp_spec, addr).await?;
                    Ok(crate::link::AnyListener::Kcp(l))
                }
                #[cfg(not(feature = "transport-kcp"))]
                {
                    let _ = kcp_spec;
                    Err(TransportError::FeatureDisabled {
                        kind: "kcp",
                        feature: "transport-kcp",
                    })
                }
            }
            stowaway_protocol::TransportKind::Quic => {
                Err(TransportError::Spec(crate::SpecError::QuicUnimplemented))
            }
        }
    }))
}

/// 便利函数：拨号 → 3-flight 握手。
///
/// # Errors
/// 建连失败、握手失败。
pub async fn dialer_handshake(
    dialer: &crate::link::AnyDialer,
    spec: &crate::TransportSpec,
    target: &DialTarget,
    role: stowaway_protocol::NodeKind,
    secret: &Secret,
) -> Result<(LinkCodec, HandshakeResult)> {
    let link = dialer.connect(target).await?;
    let mut codec = LinkCodec::new(link);
    let res = codec
        .client_handshake(
            role,
            spec.kind,
            target.tls.as_ref().and_then(|t| t.advertised_fingerprint()),
            secret,
        )
        .await?;
    Ok((codec, res))
}

/// 便利函数：接受一条链路 → 服务端 3-flight 握手。
///
/// # Errors
/// 握手失败。
pub async fn listener_handshake(
    listener: &mut crate::link::AnyListener,
    kind: stowaway_protocol::TransportKind,
    expected_tls_fp: Option<[u8; 32]>,
    role: stowaway_protocol::NodeKind,
    secret: &Secret,
) -> Result<(LinkCodec, HandshakeResult, std::net::SocketAddr)> {
    let (link, peer) = listener.accept().await?;
    let mut codec = LinkCodec::new(link);
    let res = codec
        .server_handshake(role, kind, expected_tls_fp, secret)
        .await?;
    Ok((codec, res, peer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_protocol::{NodeKind, TransportKind};
    use tokio::io::DuplexStream;

    /// 内存链路（测试用），可自定义 `max_frame` 以触发分片。
    struct DuplexLink {
        inner: DuplexStream,
        max_frame: usize,
    }

    impl tokio::io::AsyncRead for DuplexLink {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for DuplexLink {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl Link for DuplexLink {
        fn meta(&self) -> LinkMeta {
            LinkMeta::new(TransportKind::Raw, None).with_max_frame(self.max_frame)
        }
    }

    fn pair(max_frame: usize) -> (LinkCodec, LinkCodec) {
        let (a, b) = tokio::io::duplex(1 << 20);
        (
            LinkCodec::new(crate::link::boxed(DuplexLink {
                inner: a,
                max_frame,
            })),
            LinkCodec::new(crate::link::boxed(DuplexLink {
                inner: b,
                max_frame,
            })),
        )
    }

    fn secret() -> Secret {
        Secret::from_bytes(
            b"topsecret-value".to_vec(),
            stowaway_crypto::SecretSource::Argv,
            8,
        )
        .expect("测试 secret 合法")
    }

    #[tokio::test]
    async fn handshake_then_message_roundtrip() {
        let (mut client, mut server) = pair(FRAGMENT_MAX);
        let s = secret();
        let (c, sr) = tokio::join!(
            client.client_handshake(NodeKind::Agent, TransportKind::Raw, None, &s),
            server.server_handshake(NodeKind::Admin, TransportKind::Raw, None, &s),
        );
        let c = c.expect("客户端握手成功");
        let sr = sr.expect("服务端握手成功");
        assert_eq!(c.outcome.transcript_hash, sr.outcome.transcript_hash);
        assert_eq!(c.secrets.keys.link_key, sr.secrets.keys.link_key);
        assert_eq!(c.secrets.keys.auth_key, sr.secrets.keys.auth_key);
        assert!(client.is_sealed() && server.is_sealed());

        let msg = Message::Heartbeat(stowaway_protocol::Heartbeat {
            send_ts: 7,
            echo_ts: 3,
        });
        let dest = NodeId::new([1u8; 16]);
        let (a, b) = tokio::join!(
            async {
                client.send(&msg, dest, &[]).await?;
                Ok::<_, TransportError>(())
            },
            async {
                let (frame, got) = server.recv_message().await?;
                Ok::<_, TransportError>((frame, got))
            }
        );
        a.expect("发送成功");
        let (frame, got) = b.expect("接收成功");
        assert!(frame.header.flags.is_sealed());
        assert_eq!(frame.header.dest, dest);
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn large_payload_is_fragmented_and_reassembled() {
        let (mut client, mut server) = pair(1024);
        let s = secret();
        let (c, sr) = tokio::join!(
            client.client_handshake(NodeKind::Agent, TransportKind::Raw, None, &s),
            server.server_handshake(NodeKind::Admin, TransportKind::Raw, None, &s),
        );
        c.expect("握手");
        sr.expect("握手");

        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let msg = Message::SessionData(stowaway_protocol::SessionData {
            key: stowaway_protocol::SessionKey::new(NodeId::new([2u8; 16]), 9),
            seq: 1,
            data: stowaway_protocol::ByteBuf::from(payload.clone()),
        });
        let dest = NodeId::new([3u8; 16]);
        let (a, b) = tokio::join!(async { client.send(&msg, dest, &[]).await }, async {
            server.recv_message().await
        });
        a.expect("发送成功");
        let (frame, got) = b.expect("接收成功");
        assert_eq!(got, msg);
        assert_eq!(frame.header.msg_type, MsgType::SessionData);
        assert!(!frame.header.flags.is_fragment());
        // 重组后的 payload 必须与原始编码逐字节等价（长度直接由 postcard 决定，
        // 不要硬编码：origin 16 + id/seq/len 各自 varint + 数据）。
        let expect_len = msg.encode().map(|b| b.len()).unwrap_or_default();
        assert_eq!(frame.payload.len(), expect_len);
    }

    #[tokio::test]
    async fn tampered_ciphertext_is_rejected() {
        let (mut a, b) = tokio::io::duplex(1 << 16);
        let key = [7u8; 32];
        // 只用 sealer 造一帧（不经 LinkCodec，避免所有权纠缠）。
        let msg = Message::Heartbeat(stowaway_protocol::Heartbeat {
            send_ts: 1,
            echo_ts: 2,
        });
        let payload = msg.encode().expect("编码");
        let mut header = FrameHeader::new(
            FrameFlags::SEALED,
            MsgType::Heartbeat,
            NodeId::UNASSIGNED,
            vec![],
        );
        header.payload_len = payload.len() + SEAL_OVERHEAD;
        let aad = header.header_bytes();
        let mut sealer = LinkSealer::new(&key, true);
        let (ct, counter) = sealer.seal(&aad, &payload).expect("密封");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&counter.to_le_bytes());
        bytes.extend_from_slice(&ct);
        let frame = Frame {
            header,
            payload: Bytes::from(bytes),
        };
        let mut encoded = frame.encode();
        // 翻转密文最后一个字节（AEAD tag 区），必须被拒。
        let last = encoded.len() - 1;
        encoded[last] ^= 0xff;
        tokio::io::AsyncWriteExt::write_all(&mut a, &encoded)
            .await
            .expect("写入");

        let mut server = LinkCodec::new(crate::link::boxed(DuplexLink {
            inner: b,
            max_frame: FRAGMENT_MAX,
        }));
        server.install_sealer(&key, false);
        let err = match server.recv_message().await {
            Ok(_) => panic!("篡改必须失败"),
            Err(e) => e,
        };
        assert!(matches!(err, TransportError::Sealer(_)));
    }

    #[tokio::test]
    async fn replay_of_same_counter_is_rejected() {
        // 两个端点：`writer` 被封在 LinkCodec 里发一帧，`reader` 收两条同样的字节。
        let (mut writer_half, reader_half) = tokio::io::duplex(1 << 16);
        let key = [9u8; 32];

        let msg = Message::Heartbeat(stowaway_protocol::Heartbeat {
            send_ts: 5,
            echo_ts: 6,
        });
        let payload = msg.encode().expect("编码");
        let mut header = FrameHeader::new(
            FrameFlags::SEALED,
            MsgType::Heartbeat,
            NodeId::UNASSIGNED,
            vec![],
        );
        header.payload_len = payload.len() + SEAL_OVERHEAD;
        let aad = header.encode_to_vec();
        let mut sealer = LinkSealer::new(&key, true);
        let (ct, counter) = sealer.seal(&aad, &payload).expect("密封");
        let mut body = Vec::new();
        body.extend_from_slice(&counter.to_le_bytes());
        body.extend_from_slice(&ct);
        let frame = Frame {
            header,
            payload: Bytes::from(body),
        };
        let encoded = frame.encode();
        // 同一帧连发两遍（counter 相同）。
        tokio::io::AsyncWriteExt::write_all(&mut writer_half, &encoded)
            .await
            .expect("写1");
        tokio::io::AsyncWriteExt::write_all(&mut writer_half, &encoded)
            .await
            .expect("写2");

        let mut reader = LinkCodec::new(crate::link::boxed(DuplexLink {
            inner: reader_half,
            max_frame: FRAGMENT_MAX,
        }));
        reader.install_sealer(&key, false);
        reader.recv_message().await.expect("第一帧正常");
        let err = reader.recv_message().await.expect_err("重放必须失败");
        assert!(matches!(err, TransportError::Sealer(_)));

        // 反向：未密封的读取端必须拒绝密封帧。
        let (mut a, b) = tokio::io::duplex(1 << 12);
        tokio::io::AsyncWriteExt::write_all(&mut a, &encoded)
            .await
            .expect("写3");
        let mut plain = LinkCodec::new(crate::link::boxed(DuplexLink {
            inner: b,
            max_frame: FRAGMENT_MAX,
        }));
        let err = plain.recv_message().await.expect_err("未握手不得解封");
        assert!(matches!(err, TransportError::HandshakeOrder { .. }));

        // 抑制未使用告警：`reader_half` 的所有权已移入 reader。
        let _ = &reader;
    }

    #[tokio::test]
    async fn handshake_reports_eof_instead_of_hanging() {
        let (mut server, client) = pair(FRAGMENT_MAX);
        // 立刻丢掉对端，模拟「连上来就断」。
        drop(client);
        let s = secret();
        let e = server
            .server_handshake(NodeKind::Admin, TransportKind::Raw, None, &s)
            .await;
        // 对端未发任何东西且链路已断开 → 读错误（不是 panic，也不是永久等待）。
        match e {
            Err(TransportError::Io(io_err)) => {
                assert_eq!(io_err.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("期望 UnexpectedEof，实得 {other:?}"),
        }
    }
}
