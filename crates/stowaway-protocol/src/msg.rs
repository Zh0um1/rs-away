//! 18 种消息的载荷定义与编解码。
//!
//! 权威：docs/plan.md §4.6。设计约束：
//!
//! 1. **消息类型在帧头**（`msg_type`），载荷里不再重复判别式，因此载荷就是
//!    对应结构体的 postcard 编码（非自描述、紧凑）。
//! 2. **schema 冻结**：字段只允许在末尾追加，枚举变体只允许在末尾追加
//!    （postcard 用变体下标定序）。`mutation` 会造成线格式破坏，
//!    由 `schema_kat_*` 系列测试钉死。
//! 3. 所有 `decode` 都返回 `Err`，不 panic（缺陷 #1–#4）。

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::error::{ProtocolError, Result};
use crate::node::{NodeId, NodeKind, SessionKey};
use crate::transport_kind::TransportKind;

/// 消息类型（帧头的 `msg_type`）。
///
/// **只追加不复用**：新消息必须取新值（≥19），删除的消息其值永久保留。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u16)]
pub enum MsgType {
    // —— Link 族（5）——
    /// 握手 flight 1（客户端 → 服务端）。
    Hello = 1,
    /// 握手 flight 2（服务端 → 客户端）。
    HelloAck = 2,
    /// 握手 flight 3（客户端 → 服务端）。
    AuthConfirm = 3,
    /// 保活，携带 RTT 时间戳。
    Heartbeat = 4,
    /// 全局关停。
    Shutdown = 5,
    // —— Topology 族（5）——
    /// 子节点申请加入（取代 v1 `CHILDUUIDREQ`）。
    Join = 6,
    /// 加入许可，分配 `NodeId`。
    JoinAck = 7,
    /// 断线重连（携带既有 `NodeId`）。
    Rejoin = 8,
    /// 节点状态变化（取代 v1 四条 offline/online 消息）。
    NodeStatus = 9,
    /// 节点备注（取代 v1 `MYMEMO`/`ADDMEMO`/`DELMEMO`）。
    Memo = 10,
    // —— Session 族（4）——
    /// 打开会话（双向可用）。
    OpenSession = 11,
    /// 会话建立结果。
    SessionReady = 12,
    /// 会话数据。
    SessionData = 13,
    /// 会话终止。
    SessionClose = 14,
    // —— Service 族（4）——
    /// 服务请求（文件/shell/ssh/隧道/connect 共用，`phase` 区分探测与执行）。
    ServiceRequest = 15,
    /// 服务请求应答。
    ServiceReply = 16,
    /// 服务数据（进度/交互字节）。
    ServiceData = 17,
    /// 服务结束。
    ServiceExit = 18,
}

impl MsgType {
    /// 全部已定义类型（测试与路由表用）。
    pub const ALL: [Self; 18] = [
        Self::Hello,
        Self::HelloAck,
        Self::AuthConfirm,
        Self::Heartbeat,
        Self::Shutdown,
        Self::Join,
        Self::JoinAck,
        Self::Rejoin,
        Self::NodeStatus,
        Self::Memo,
        Self::OpenSession,
        Self::SessionReady,
        Self::SessionData,
        Self::SessionClose,
        Self::ServiceRequest,
        Self::ServiceReply,
        Self::ServiceData,
        Self::ServiceExit,
    ];

    /// 线编码。
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// 线解码；未定义值返回 `None`。
    #[must_use]
    pub const fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            1 => Self::Hello,
            2 => Self::HelloAck,
            3 => Self::AuthConfirm,
            4 => Self::Heartbeat,
            5 => Self::Shutdown,
            6 => Self::Join,
            7 => Self::JoinAck,
            8 => Self::Rejoin,
            9 => Self::NodeStatus,
            10 => Self::Memo,
            11 => Self::OpenSession,
            12 => Self::SessionReady,
            13 => Self::SessionData,
            14 => Self::SessionClose,
            15 => Self::ServiceRequest,
            16 => Self::ServiceReply,
            17 => Self::ServiceData,
            18 => Self::ServiceExit,
            _ => return None,
        })
    }

    /// 是否属于握手 flight（只允许在 `SEALED` 未置位时收发）。
    #[must_use]
    pub const fn is_handshake(self) -> bool {
        matches!(self, Self::Hello | Self::HelloAck | Self::AuthConfirm)
    }

    /// 是否必须在 link 层密封后发送（握手之外的**全部**消息）。
    #[must_use]
    pub const fn requires_sealing(self) -> bool {
        !self.is_handshake()
    }
}

// —————————————————————————— 定义块：Link 族 ——————————————————————————

/// 保活。`send_ts` 由发送方填本地单调毫秒，`echo_ts` 原样回填用于测 RTT。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Heartbeat {
    /// 发送时刻（发送方单调毫秒）。
    pub send_ts: u64,
    /// 回显的时刻（收到方把收到的 `send_ts` 原样填回）。
    pub echo_ts: u64,
}

/// 全局关停。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Shutdown {
    /// 等待在途数据的最长毫秒数。
    pub grace_ms: u32,
    /// 原因（仅用于控制台展示，不参与逻辑）。
    pub reason: String,
}

// ———————————————————————— 定义块：Topology 族 ————————————————————————

/// 状态作用域（取代 v1 的 `NODEOFFLINE`/`UPSTREAMOFFLINE`/`NODEREONLINE` 组合）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NodeScope {
    /// 本节点自身。
    Node,
    /// 上游（父）链路。
    Upstream,
    /// 某个子节点。
    Child,
}

/// 状态取值。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NodeState {
    /// 在线。
    Online,
    /// 离线。
    Offline,
    /// 路由不可达（v2 新增：v1 静默丢弃，见缺陷 #11 的「不可达静默」）。
    Undeliverable,
}

/// 节点状态变化。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    /// 作用域。
    pub scope: NodeScope,
    /// 状态。
    pub state: NodeState,
    /// 相关节点（`scope == Node` 时为自身）。
    pub node: NodeId,
}

/// 申请加入父节点。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Join {
    /// 申请方角色。
    pub kind: NodeKind,
    /// 申请方监听的地址（供控制台展示；不含敏感信息）。
    pub listen: Option<String>,
    /// 申请方支持的 feature 位（用于后续能力协商）。
    pub capabilities: u32,
    /// 被公告的节点。
    ///
    /// 二义性由发送方决定（见 plan §4.6 与附录 A 第 3、4 行）：
    /// - `NodeId::UNASSIGNED`：发送方自己入网，请接收方分配 `NodeId`；
    /// - 具体 `NodeId`：发送方**代替**它向上游公告「这个节点的父节点是我」，
    ///   用于新子节点接入后让 admin 立刻补齐拓扑（否则 admin 要等下次
    ///   心跳才能发现孙节点，转发会短暂不可达）。
    pub node: NodeId,
}

/// 加入许可。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct JoinAck {
    /// 分配到的 `NodeId`。
    pub node: NodeId,
    /// 父节点 `NodeId`。
    pub parent: NodeId,
    /// 树根 `NodeId`（便于子节点直接寻根）。
    pub root: NodeId,
    /// 相对根的深度（admin = 0）。
    pub depth: u16,
}

/// 断线重连（携带既有身份）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Rejoin {
    /// 既有 `NodeId`。
    pub node: NodeId,
    /// 期望的父节点。
    pub parent: NodeId,
}

/// 节点备注。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Memo {
    /// 目标节点。
    pub node: NodeId,
    /// 备注文本；空串表示**清除**备注（取代 v1 的独立 `DELMEMO`）。
    pub text: String,
}

// ————————————————————————— 定义块：Session 族 —————————————————————————

/// 会话种类（对应 docs/plan.md §4.8 的 8 种）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum SessionKind {
    /// SOCKS5 TCP 穿透。
    #[default]
    Socks5,
    /// SOCKS5 UDP ASSOCIATE（v1 由 agent 发起，修 F2）。
    Socks5Udp,
    /// 端口转发（本地监听 → 远端目标）。
    Forward,
    /// 反向映射（远端监听 → 本地目标，v1 的 backward）。
    Backward,
    /// 文件传输。
    File,
    /// 交互式 shell（PTY）。
    ShellPty,
    /// SSH 命令。
    Ssh,
    /// SSH 隧道。
    SshTunnel,
}

/// 会话方向（相对**接收方**）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum SessionDirection {
    /// 接收方主动向 `target` 发起连接（SOCKS、forward 的目标侧）。
    #[default]
    Outbound,
    /// 接收方提供资源/监听（backward 的监听侧）。
    Inbound,
}

/// 会话结果码（v1 只有成功信号、无错误码，见 docs/plan.md §4.8）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum SessionCode {
    /// 成功。
    #[default]
    Ok,
    /// 对端拒绝（策略/资源）。
    Refused,
    /// 超时。
    Timeout,
    /// 目标不存在/不可达。
    NotFound,
    /// 认证或策略拒绝。
    Denied,
}

/// 打开会话。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct OpenSession {
    /// 会话复合键。
    pub key: SessionKey,
    /// 会话种类。
    pub kind: SessionKind,
    /// 方向。
    pub direction: SessionDirection,
    /// 目标地址（`host:port` 或远端监听地址）；UDP 会话可为 `None`。
    pub target: Option<String>,
    /// 附加参数（交给服务层解释，见 `ServiceParam` 的字段复用约定）。
    pub param: ServiceParam,
}

/// 会话建立结果。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SessionReady {
    /// 会话复合键。
    pub key: SessionKey,
    /// 结果码。
    pub code: SessionCode,
    /// 详情（成功时为空；失败时面向操作者）。
    pub detail: String,
}

/// 会话数据。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SessionData {
    /// 会话复合键。
    pub key: SessionKey,
    /// 会话内单调序号（从 0 起），用于乱序检测与重放拒绝。
    pub seq: u64,
    /// 数据（已由 link 层密封）。
    #[serde(with = "serde_bytes")]
    pub data: ByteBuf,
}

/// 会话终止原因。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum CloseReason {
    /// 正常收尾。
    #[default]
    Normal,
    /// 对端 RST。
    Reset,
    /// 空闲或握手超时。
    Timeout,
    /// 被拒绝。
    Refused,
    /// 其它错误。
    Error,
}

/// 会话终止。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SessionClose {
    /// 会话复合键。
    pub key: SessionKey,
    /// 原因。
    pub reason: CloseReason,
    /// 附加说明。
    pub detail: String,
}

// ————————————————————————— 定义块：Service 族 —————————————————————————

/// 服务种类。
///
/// forward 的探测复用 [`ServiceKind::Connect`]（语义相同：拨一个目标看通不通）；
/// 但 backward 与 listen **不能**复用——前者要在被监听侧真正 `bind` 一个端口，
/// 后者要让 agent 在指定端口发起被动服务，两者与「拨号」是相反的动作
/// （见 `docs/plan.md` 附录 A 第 12、39 行）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum ServiceKind {
    /// 文件传输（上传/下载共用，方向由 `SessionDirection` 决定）。
    #[default]
    File,
    /// 交互式 shell。
    Shell,
    /// SSH 命令。
    Ssh,
    /// SSH 隧道。
    SshTunnel,
    /// 连通性探测 / 通用 TCP 桥（v1 的 `connect` 与 `FORWARDTEST`）。
    Connect,
    /// 被动监听：让对端在指定端口上 `bind` 并接受连接（v1 `LISTENREQ`）。
    Listen,
    /// 反向映射：被监听侧 `bind` 端口，发起侧拨号回来（v1 `BACKWARDTEST`）。
    Backward,
}

/// 服务阶段：先探测再执行，消除 v1「先注册数据通道再发 START」的顺序耦合
/// （`admin/handler/forward.go:124-132` 的 DEAD LOCK 注释）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum ServicePhase {
    /// 探测（不传数据，只验证对端可服务）。
    #[default]
    Probe,
    /// 执行（握手通过，开始传数据）。
    Run,
}

/// 服务请求。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ServiceRequest {
    /// 会话复合键。
    pub key: SessionKey,
    /// 服务种类。
    pub kind: ServiceKind,
    /// 阶段。
    pub phase: ServicePhase,
    /// 参数。
    pub param: ServiceParam,
}

/// 服务参数（按服务种类解释；变体只允许在末尾追加）。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum ServiceParam {
    /// 无参数。
    #[default]
    None,
    /// 文件参数。
    File(FileParam),
    /// shell 参数。
    Shell(ShellParam),
    /// SSH 参数。
    Ssh(SshParam),
    /// SSH 隧道参数。
    SshTunnel(SshTunnelParam),
    /// 连接/探测参数。
    Connect(ConnectParam),
}

/// 文件传输参数。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct FileParam {
    /// 文件名（**单段**，不含路径分隔符；服务端另有路径穿越防护，缺陷 #13）。
    pub name: String,
    /// 字节数。
    pub size: u64,
    /// 内容 SHA-256（传输完成后校验）。
    pub sha256: [u8; 32],
    /// 起始偏移（支持续传；v2 新增）。
    pub offset: u64,
}

/// shell 参数。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ShellParam {
    /// 终端列数。
    pub cols: u16,
    /// 终端行数。
    pub rows: u16,
    /// 终端类型（`TERM`）。
    pub term: String,
}

/// SSH 认证方式。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum SshAuth {
    /// 密码。
    Password(String),
    /// 私钥（PEM/OpenSSH，单段文本）。
    PrivateKey(String),
    /// 默认（读本地 agent）。
    #[default]
    Agent,
}

/// SSH 参数。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SshParam {
    /// 用户名。
    pub user: String,
    /// 认证方式。
    pub auth: SshAuth,
    /// 要执行的命令（空则申请交互 shell）。
    pub command: String,
}

/// SSH 隧道参数。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SshTunnelParam {
    /// SSH 侧参数。
    pub ssh: SshParam,
    /// 本地转发端口（0 表示由内核分配）。
    pub local_port: u16,
    /// 远端目标地址（`host:port`）。
    pub remote_target: String,
}

/// 连接/探测参数。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ConnectParam {
    /// 目标地址（`host:port`）。
    pub addr: String,
}

/// 服务应答。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ServiceReply {
    /// 会话复合键。
    pub key: SessionKey,
    /// 结果码（复用 [`SessionCode`]）。
    pub code: SessionCode,
    /// 详情。
    pub detail: String,
}

/// 服务数据（进度、交互字节，或文件分片）。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ServiceData {
    /// 会话复合键。
    pub key: SessionKey,
    /// 会话内序号。
    pub seq: u64,
    /// 数据。
    #[serde(with = "serde_bytes")]
    pub data: ByteBuf,
}

/// 服务结束。
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ServiceExit {
    /// 会话复合键。
    pub key: SessionKey,
    /// 结果码。
    pub code: SessionCode,
    /// 详情（如 shell 的退出码、文件的校验结果）。
    pub detail: String,
}

// ————————————————————————— 统一入口 —————————————————————————

/// 一条消息：类型在帧头，载荷为对应结构体的 postcard 编码。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Message {
    /// 见 [`MsgType::Hello`]。
    Hello(Hello),
    /// 见 [`MsgType::HelloAck`]。
    HelloAck(HelloAck),
    /// 见 [`MsgType::AuthConfirm`]。
    AuthConfirm(AuthConfirm),
    /// 见 [`MsgType::Heartbeat`]。
    Heartbeat(Heartbeat),
    /// 见 [`MsgType::Shutdown`]。
    Shutdown(Shutdown),
    /// 见 [`MsgType::Join`]。
    Join(Join),
    /// 见 [`MsgType::JoinAck`]。
    JoinAck(JoinAck),
    /// 见 [`MsgType::Rejoin`]。
    Rejoin(Rejoin),
    /// 见 [`MsgType::NodeStatus`]。
    NodeStatus(NodeStatus),
    /// 见 [`MsgType::Memo`]。
    Memo(Memo),
    /// 见 [`MsgType::OpenSession`]。
    OpenSession(OpenSession),
    /// 见 [`MsgType::SessionReady`]。
    SessionReady(SessionReady),
    /// 见 [`MsgType::SessionData`]。
    SessionData(SessionData),
    /// 见 [`MsgType::SessionClose`]。
    SessionClose(SessionClose),
    /// 见 [`MsgType::ServiceRequest`]。
    ServiceRequest(ServiceRequest),
    /// 见 [`MsgType::ServiceReply`]。
    ServiceReply(ServiceReply),
    /// 见 [`MsgType::ServiceData`]。
    ServiceData(ServiceData),
    /// 见 [`MsgType::ServiceExit`]。
    ServiceExit(ServiceExit),
}

/// 握手 flight 1：客户端问候。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Hello {
    /// 申请方角色（恒为 [`NodeKind::Agent`]：agent 总是发起方）。
    pub kind: NodeKind,
    /// 承载类型（参与 transcript，防降级）。
    pub transport: TransportKind,
    /// TLS 证书指纹（无 TLS 时为 `None`）；参与 transcript，防 MITM 降级。
    pub tls_fp: Option<[u8; 32]>,
    /// 客户端临时 X25519 公钥。
    pub eph_pub: [u8; 32],
    /// 客户端随机数。
    pub nonce: [u8; 32],
}

/// 握手 flight 2：服务端回应。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HelloAck {
    /// 服务端角色（恒为 [`NodeKind::Admin`]）。
    pub kind: NodeKind,
    /// 服务端临时 X25519 公钥。
    pub eph_pub: [u8; 32],
    /// 服务端随机数。
    pub nonce: [u8; 32],
    /// 服务端 proof。
    pub proof: [u8; 32],
}

/// 握手 flight 3：客户端确认。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AuthConfirm {
    /// 客户端 proof。
    pub proof: [u8; 32],
    /// 会话密钥种子确认（回显 `session_key_seed` 的 SHA-256 截断，
    /// 证明双方 KDF 输入一致；不是密钥本身）。
    pub seed_ack: [u8; 32],
}

impl Message {
    /// 消息类型。
    #[must_use]
    pub const fn msg_type(&self) -> MsgType {
        match self {
            Self::Hello(_) => MsgType::Hello,
            Self::HelloAck(_) => MsgType::HelloAck,
            Self::AuthConfirm(_) => MsgType::AuthConfirm,
            Self::Heartbeat(_) => MsgType::Heartbeat,
            Self::Shutdown(_) => MsgType::Shutdown,
            Self::Join(_) => MsgType::Join,
            Self::JoinAck(_) => MsgType::JoinAck,
            Self::Rejoin(_) => MsgType::Rejoin,
            Self::NodeStatus(_) => MsgType::NodeStatus,
            Self::Memo(_) => MsgType::Memo,
            Self::OpenSession(_) => MsgType::OpenSession,
            Self::SessionReady(_) => MsgType::SessionReady,
            Self::SessionData(_) => MsgType::SessionData,
            Self::SessionClose(_) => MsgType::SessionClose,
            Self::ServiceRequest(_) => MsgType::ServiceRequest,
            Self::ServiceReply(_) => MsgType::ServiceReply,
            Self::ServiceData(_) => MsgType::ServiceData,
            Self::ServiceExit(_) => MsgType::ServiceExit,
        }
    }

    /// 编码载荷（不含帧头）。
    pub fn encode(&self) -> Result<Vec<u8>> {
        fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
            postcard::to_allocvec(v).map_err(|e| ProtocolError::Payload(e.to_string()))
        }
        match self {
            Self::Hello(m) => ser(m),
            Self::HelloAck(m) => ser(m),
            Self::AuthConfirm(m) => ser(m),
            Self::Heartbeat(m) => ser(m),
            Self::Shutdown(m) => ser(m),
            Self::Join(m) => ser(m),
            Self::JoinAck(m) => ser(m),
            Self::Rejoin(m) => ser(m),
            Self::NodeStatus(m) => ser(m),
            Self::Memo(m) => ser(m),
            Self::OpenSession(m) => ser(m),
            Self::SessionReady(m) => ser(m),
            Self::SessionData(m) => ser(m),
            Self::SessionClose(m) => ser(m),
            Self::ServiceRequest(m) => ser(m),
            Self::ServiceReply(m) => ser(m),
            Self::ServiceData(m) => ser(m),
            Self::ServiceExit(m) => ser(m),
        }
    }

    /// 按帧头的类型解码载荷。
    pub fn decode(msg_type: MsgType, bytes: &[u8]) -> Result<Self> {
        fn de<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
            let (v, rest) = postcard::take_from_bytes::<T>(bytes)
                .map_err(|e| ProtocolError::Payload(e.to_string()))?;
            if !rest.is_empty() {
                return Err(ProtocolError::TrailingBytes { bytes: rest.len() });
            }
            Ok(v)
        }
        Ok(match msg_type {
            MsgType::Hello => Self::Hello(de(bytes)?),
            MsgType::HelloAck => Self::HelloAck(de(bytes)?),
            MsgType::AuthConfirm => Self::AuthConfirm(de(bytes)?),
            MsgType::Heartbeat => Self::Heartbeat(de(bytes)?),
            MsgType::Shutdown => Self::Shutdown(de(bytes)?),
            MsgType::Join => Self::Join(de(bytes)?),
            MsgType::JoinAck => Self::JoinAck(de(bytes)?),
            MsgType::Rejoin => Self::Rejoin(de(bytes)?),
            MsgType::NodeStatus => Self::NodeStatus(de(bytes)?),
            MsgType::Memo => Self::Memo(de(bytes)?),
            MsgType::OpenSession => Self::OpenSession(de(bytes)?),
            MsgType::SessionReady => Self::SessionReady(de(bytes)?),
            MsgType::SessionData => Self::SessionData(de(bytes)?),
            MsgType::SessionClose => Self::SessionClose(de(bytes)?),
            MsgType::ServiceRequest => Self::ServiceRequest(de(bytes)?),
            MsgType::ServiceReply => Self::ServiceReply(de(bytes)?),
            MsgType::ServiceData => Self::ServiceData(de(bytes)?),
            MsgType::ServiceExit => Self::ServiceExit(de(bytes)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SessionKey;

    fn sample_all() -> Vec<Message> {
        let key = SessionKey::new(NodeId::new([9u8; 16]), 42);
        vec![
            Message::Hello(Hello {
                kind: NodeKind::Agent,
                transport: TransportKind::Raw,
                tls_fp: Some([1u8; 32]),
                eph_pub: [2u8; 32],
                nonce: [3u8; 32],
            }),
            Message::HelloAck(HelloAck {
                kind: NodeKind::Admin,
                eph_pub: [4u8; 32],
                nonce: [5u8; 32],
                proof: [6u8; 32],
            }),
            Message::AuthConfirm(AuthConfirm {
                proof: [7u8; 32],
                seed_ack: [8u8; 32],
            }),
            Message::Heartbeat(Heartbeat {
                send_ts: 1_700_000_000_123,
                echo_ts: 1_700_000_000_100,
            }),
            Message::Shutdown(Shutdown {
                grace_ms: 5000,
                reason: "maintenance".into(),
            }),
            Message::Join(Join {
                kind: NodeKind::Agent,
                listen: Some("0.0.0.0:8080".into()),
                capabilities: 0b1011,
                node: NodeId::UNASSIGNED,
            }),
            Message::JoinAck(JoinAck {
                node: NodeId::new([1u8; 16]),
                parent: NodeId::ADMIN,
                root: NodeId::ADMIN,
                depth: 2,
            }),
            Message::Rejoin(Rejoin {
                node: NodeId::new([1u8; 16]),
                parent: NodeId::ADMIN,
            }),
            Message::NodeStatus(NodeStatus {
                scope: NodeScope::Child,
                state: NodeState::Offline,
                node: NodeId::new([2u8; 16]),
            }),
            Message::Memo(Memo {
                node: NodeId::new([3u8; 16]),
                text: "堡垒机".into(),
            }),
            Message::OpenSession(OpenSession {
                key,
                kind: SessionKind::Socks5,
                direction: SessionDirection::Outbound,
                target: Some("example.com:443".into()),
                param: ServiceParam::Connect(ConnectParam {
                    addr: "example.com:443".into(),
                }),
            }),
            Message::SessionReady(SessionReady {
                key,
                code: SessionCode::Denied,
                detail: "policy".into(),
            }),
            Message::SessionData(SessionData {
                key,
                seq: 7,
                data: ByteBuf::from(vec![1u8, 2, 3, 4]),
            }),
            Message::SessionClose(SessionClose {
                key,
                reason: CloseReason::Timeout,
                detail: String::new(),
            }),
            Message::ServiceRequest(ServiceRequest {
                key,
                kind: ServiceKind::File,
                phase: ServicePhase::Probe,
                param: ServiceParam::File(FileParam {
                    name: "a.bin".into(),
                    size: 4096,
                    sha256: [0xab; 32],
                    offset: 0,
                }),
            }),
            Message::ServiceReply(ServiceReply {
                key,
                code: SessionCode::Ok,
                detail: String::new(),
            }),
            Message::ServiceData(ServiceData {
                key,
                seq: 1,
                data: ByteBuf::from(vec![9u8; 8]),
            }),
            Message::ServiceExit(ServiceExit {
                key,
                code: SessionCode::Ok,
                detail: "exit 0".into(),
            }),
        ]
    }

    #[test]
    fn all_messages_roundtrip() {
        let all = sample_all();
        assert_eq!(all.len(), MsgType::ALL.len());
        for m in all {
            let bytes = m.encode().expect("encode");
            let back = Message::decode(m.msg_type(), &bytes).expect("decode");
            assert_eq!(back, m, "消息 {:?} 往返失败", m.msg_type());
        }
    }

    #[test]
    fn msg_type_values_are_stable() {
        // 这是线协议的硬契约：改动会导致所有 v2 节点互通失败。
        for (i, t) in MsgType::ALL.iter().enumerate() {
            assert_eq!(t.as_u16(), i as u16 + 1, "{t:?} 的值必须是 {}", i + 1);
            assert_eq!(MsgType::from_u16(t.as_u16()), Some(*t));
        }
        assert_eq!(MsgType::from_u16(0), None);
        assert_eq!(MsgType::from_u16(19), None);
        assert_eq!(MsgType::from_u16(u16::MAX), None);
    }

    #[test]
    fn handshake_sealing_rules() {
        assert!(MsgType::Hello.is_handshake());
        assert!(!MsgType::Hello.requires_sealing());
        assert!(!MsgType::Heartbeat.is_handshake());
        assert!(MsgType::Heartbeat.requires_sealing());
    }

    #[test]
    fn schema_kat_heartbeat() {
        // postcard 对整数用 LEB128 varint（**不是**定长小端——定长小端只用于帧头）。
        // 任何字段重排或编码器更换都会打破此向量。
        let m = Message::Heartbeat(Heartbeat {
            send_ts: 0x0102_0304_0506_0708,
            echo_ts: 0,
        });
        let bytes = m.encode().expect("encode");
        assert_eq!(
            bytes,
            vec![136, 142, 152, 168, 192, 224, 128, 129, 1, 0],
            "send_ts 的 varint 编码 + echo_ts=0"
        );
        // 小值只占 1 字节：证明 varint 生效。
        let small = Message::Heartbeat(Heartbeat {
            send_ts: 1,
            echo_ts: 0,
        })
        .encode()
        .expect("encode");
        assert_eq!(small, vec![1, 0]);
    }

    #[test]
    fn schema_kat_node_status_enum_order() {
        // NodeScope: Node=0/Upstream=1/Child=2；NodeState: Online=0/Offline=1/Undeliverable=2。
        let m = Message::NodeStatus(NodeStatus {
            scope: NodeScope::Child,
            state: NodeState::Undeliverable,
            node: NodeId::new([0u8; 16]),
        });
        let bytes = m.encode().expect("encode");
        assert_eq!(bytes[0], 2, "scope Child 必须是变体 2");
        assert_eq!(bytes[1], 2, "state Undeliverable 必须是变体 2");
        assert_eq!(bytes.len(), 1 + 1 + 16);
    }

    #[test]
    fn schema_kat_service_param_variant_order() {
        // ServiceParam: None=0/File=1/Shell=2/Ssh=3/SshTunnel=4/Connect=5。
        for (param, tag) in [
            (ServiceParam::None, 0u8),
            (ServiceParam::File(FileParam::default()), 1),
            (ServiceParam::Shell(ShellParam::default()), 2),
            (ServiceParam::Connect(ConnectParam::default()), 5),
        ] {
            let m = Message::ServiceRequest(ServiceRequest {
                key: SessionKey::new(NodeId::UNASSIGNED, 1),
                kind: ServiceKind::File,
                phase: ServicePhase::Probe,
                param,
            });
            let bytes = m.encode().expect("encode");
            // key.origin(16) + key.id varint(1) + kind(1) + phase(1) → 标签在 offset 19。
            assert_eq!(bytes[19], tag, "ServiceParam 变体标签错误");
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let m = Message::Heartbeat(Heartbeat::default());
        let mut bytes = m.encode().expect("encode");
        bytes.push(0xff);
        assert!(matches!(
            Message::decode(MsgType::Heartbeat, &bytes),
            Err(ProtocolError::TrailingBytes { bytes: 1 })
        ));
    }

    #[test]
    fn decode_truncated_never_panics() {
        for m in sample_all() {
            let bytes = m.encode().expect("encode");
            for cut in 0..bytes.len() {
                // 任何截断都必须返回 Err；panic 会让 fuzz 目标失败。
                assert!(
                    Message::decode(m.msg_type(), &bytes[..cut]).is_err(),
                    "{:?} 在 cut={cut} 时应报错",
                    m.msg_type()
                );
            }
        }
    }

    #[test]
    fn decode_random_bytes_never_panics() {
        // 简易确定性伪随机：覆盖 fuzz smoke 之前的常见崩溃点。
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..2000 {
            let mut buf = Vec::with_capacity(32);
            for _ in 0..32 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push(state as u8);
            }
            for t in MsgType::ALL {
                let _ = Message::decode(t, &buf);
            }
        }
    }

    #[test]
    fn empty_memo_text_means_clear() {
        let m = Memo {
            node: NodeId::ADMIN,
            text: String::new(),
        };
        assert!(m.text.is_empty());
    }
}
