# 连接协议与传输抽象层设计（v2）

> 本文件是 [`docs/plan.md`](../plan.md) §4.3 的详设。主方案只保留摘要，帧格式、握手、密码学的权威定义在 plan.md §4.4–§4.5，本文不重复。
>
> 目标：让「连接方式」（TCP 直连、WebSocket、未来的 KCP/QUIC）成为**可替换的一层**。新增一种传输不得改动帧格式、不得改动 `stowaway-core` 的业务逻辑、不得改变既有 CLI 取值的语义。

---

## 1. 范围与非目标

**范围**

1. 定义 Rust 侧 trait 契约（`Link` / `Listener` / `Dialer` / `LinkMeta`）与枚举分发形式 `AnyListener` / `AnyDialer`。
2. 定义配置语法（`TransportSpec`）、注册表与 CLI 映射。
3. 定义多传输共存规则：TCP 类共用端口的首字节嗅探、UDP 类的端口分配与 `conv` 初筛。
4. 定义传输 × TLS 的合法组合矩阵、feature gate、与构建矩阵的联动。
5. 定义**一致性闸门**：任何 `TransportKind` 必须通过的 9 条不变量测试。
6. 给出「新增一种传输」的 6 步清单，并以 KCP 为预演逐条验证该清单可执行。

**非目标**

- **不做不可靠数据报语义**。v2 只接受「可靠、有序字节流」；KCP 与 QUIC 都以可靠流形式接入。SOCKS5 UDP ASSOCIATE 在应用层做数据报封装（`Socks5Udp` 会话，见 plan.md §4.8），与传输层的可靠性无关。
- **不做传输层复用（multiplexing）**：一条 Link 上不并发多路，多路复用由 session 层的 `session_key` 承担（一条 Link 可承载多个 session 的帧）。这与 Go v1 的「单 Conn + 裸帧」一致，避免引入 QUIC 式的 stream 语义。
- **不在 v2 实现 QUIC**：仅留 `TransportKind::Quic` 变体与 feature 占位，用于证明枚举扩展点足够。
- **不改动 Go v1 的端口复用语义**：iptables / SO_REUSEPORT 回落只对 TCP raw 生效（见 §6.3）。

---

## 2. 分层栈

```
┌────────────────────────────────────────────────────────────┐
│ 应用层：SOCKS5 / forward / backward / file / shell / ssh   │
│ 只认 session_key，不知道字节从哪里来                        │
├────────────────────────────────────────────────────────────┤
│ 会话层（stowaway-core::session）                            │
│ SessionKey{origin, id} → 帧读写、背压、seq/ack              │
├────────────────────────────────────────────────────────────┤
│ 帧层（stowaway-protocol::FrameCodec）                       │
│ version | flags | msg_type | dest[16] | via[] | payload     │
├────────────────────────────────────────────────────────────┤
│ 密封层（stowaway-crypto::LinkSealer）                       │
│ 逐跳 AES-GCM，nonce = iv(4B) ‖ counter(8B)，AAD = 帧头      │
├────────────────────────────────────────────────────────────┤
│ 链路层（stowaway-transport::Link）  ← 本文件定义的边界       │
│ 只承诺：可靠、有序、字节流、EOF、背压                        │
├────────────────────────────────────────────────────────────┤
│ TransportKind: Raw(TCP) / Ws(TCP+HTTP101) / Kcp(UDP) / …    │
└────────────────────────────────────────────────────────────┘
```

**关键点**：`LinkSealer` 在 `Link` 之上，因此**加密与传输解耦**。TLS 是可选外壳，嵌在 `Link` 实现内部（`raw+`tls` → `rustls` 包一层 `TcpStream`；`ws+`tls` → 先自建 `rustls` 连接，再把 `TlsStream` 交给 `client_async`）。这意味着「换传输」不触碰密码学，「关 TLS」不影响帧层密封（修正 Go v1 缺陷 #5：`--tls-enable` 时把 `Secret` 置空导致载荷明文）。

---

## 3. 契约

### 3.1 类型草图（可直接抄进代码）

```rust
use std::io;
use std::net::SocketAddr;
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};

/// 传输种类。`#[non_exhaustive]` 让新增变体不破坏下游 match 的语义假设。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportKind { Raw, Ws, Kcp, Quic }

impl TransportKind {
    /// 写入 transcript hash 的稳定标识；一旦发布不可更改。
    pub const fn wire_id(self) -> u8 {
        match self { Raw => 1, Ws => 2, Kcp => 3, Quic => 4 }
    }
    pub const fn is_datagram_backed(self) -> bool { matches!(self, Kcp | Quic) }
}

#[derive(Clone, Debug)]
pub struct LinkMeta {
    pub kind: TransportKind,
    /// 对端地址；KCP/QUIC 为对端 UDP 地址（不一定是连入时的源地址）。
    pub peer: Option<SocketAddr>,
    /// 本链路允许的最大单帧（字节）。帧层取 min(MAX_FRAME, 此值)，见 plan.md §4.4。
    pub max_frame: usize,
    /// 底层是否数据报（影响 flush/批量策略，不影响可靠性）。
    pub datagram_backed: bool,
}

/// 唯一的传输抽象。热路径上只有 4 个实现，故用 `Box<dyn Link>` 而非枚举。
pub trait Link: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    fn meta(&self) -> LinkMeta;
}

pub trait Listener {
    fn local_addr(&self) -> io::Result<SocketAddr>;
    /// 注意：AFIT + `dyn` 组合受限，故 Listener/Dialer 走枚举，不用 trait object。
    fn accept(&mut self) -> impl Future<Output = io::Result<(Box<dyn Link>, SocketAddr)>> + Send;
}

pub struct DialTarget {
    pub addr: SocketAddr,
    /// ws 需要的 Host/SNI 与路径；raw 忽略。
    pub domain: Option<String>,
    pub path: Option<String>,
    /// TLS 配置句柄（None = 明文传输层）。
    pub tls: Option<crate::TlsConfig>,
}

pub trait Dialer {
    fn connect(&self, target: &DialTarget)
        -> impl Future<Output = io::Result<Box<dyn Link>>> + Send;
}
```

**为什么 `Link` 是 `Box<dyn>`、而 `Listener`/`Dialer` 是枚举**：

| 选择 | 理由 |
|---|---|
| `Link: Box<dyn>` | 它在每次 read/write 的热路径上，且实现数固定（v2 只有 4 个），vtable 开销可忽略；`Box<dyn Link>` 让 `Session` 与 `Router` 不必泛型化（否则泛型参数会传染整个 core crate）。 |
| `Listener`/`Dialer` 用枚举 | `async fn`（AFIT）产生的 future 未擦除，`dyn Listener` 需要额外的 boxed future；而监听器与拨号器**每进程只有 1–3 个**，枚举分发零成本，且能在编译期用 `#[cfg]` 精确裁剪未启用的传输（tier-3 目标关 ws/kcp 时不编译其代码）。 |

### 3.2 枚举扩展点

```rust
pub enum AnyListener {
    Raw(raw::Listener),
    #[cfg(feature = "transport-ws")]
    Ws(ws::Listener),
    #[cfg(feature = "transport-kcp")]
    Kcp(kcp::Listener),
    // QUIC 占位，不实现
    #[cfg(feature = "transport-quic")]
    Quic(...),
}

impl AnyListener {
    pub fn kind(&self) -> TransportKind { /* match 各变体 */ }
    pub fn local_addr(&self) -> io::Result<SocketAddr> { /* match */ }
    pub async fn accept(&mut self) -> io::Result<(Box<dyn Link>, SocketAddr)> { /* match */ }
}

pub enum AnyDialer { Raw(raw::Dialer), #[cfg(feature="transport-ws")] Ws(ws::Dialer), #[cfg(feature="transport-kcp")] Kcp(kcp::Dialer) }
impl AnyDialer { pub async fn connect(&self, t: &DialTarget) -> io::Result<Box<dyn Link>> { /* match */ } }
```

**约束（写死为审查项）**：新增传输必须在 **3 处**加分支——`TransportKind`（含 `wire_id`）、`AnyListener`、`AnyDialer`。任何 `_ =>` 通配都视为违规（会让新变体静默走错分支）。

### 3.3 `Link` 的语义承诺（不可缩小）

| 承诺 | 说明 | 反面（不允许） |
|---|---|---|
| 可靠性 | 已 `poll_write` 返回成功的字节，最终会被对端 `poll_read` 读到，或链路以错误/EOF 终止 | 静默丢包、返回成功却丢弃 |
| 有序性 | 字节流有序 | 重排 |
| 字节流 | 不承诺消息边界，帧层自行分帧 | 以「消息」为单位语义（ws/kcp 实现内部可借其消息语义，但对外必须是连续字节流） |
| EOF | 对端关闭后读到 `Ok(0)`（可能是半关闭） | 读端直接返回错误 |
| 背压 | `poll_write` 在缓冲满时返回 `Pending`，而非无限缓存 | 无界写缓冲（Go v1 的 `append` 直写无背压） |
| 取消安全 | `poll_read` 被 drop 不丢已读字节 | drop 时静默丢弃已缓冲数据 |

**已知不保证**：`max_frame` 之外无分片能力；对端 RST 在读端表现为 `ErrorKind::ConnectionReset`（不 panic）。

---

## 4. 配置语法

### 4.1 `TransportSpec`

沿用 Go v1 的「`-up` / `-down` 是两条独立链路各自的传输选择」语义，但把裸字符串 `raw|ws|http` 升级为带参数的 URI：

```
<scheme>://<host>:<port>[?<k>=<v>&...]
```

| scheme | 必需参数 | 可选参数 | 说明 |
|---|---|---|---|
| `raw` | host:port | `nodelay=0\|1`、`keepalive=<秒>` | 裸 TCP（默认） |
| `ws` | host:port | `domain=<SNI/Host>`、`path=</xxx>`、`nodelay`、`keepalive` | WebSocket over TCP |
| `kcp` | host:port | `conv=<u32>`（缺省从 secret 派生）、`nodelay=0\|1`、`mtu=<576..1400>`、`wnd=<recv>,<snd>` | KCP over UDP |
| `quic` | — | — | 占位，解析时报「v2 未实现」并退出 |

解析规则：

- 缺省值：`raw://0.0.0.0:8080`（agent 监听）/ 无 scheme 的 `host:port` 一律按 `raw` 解析（**向后兼容 Go v1 的 `-l 8080`**）。
- `http://` 显式报错：Go v1 的 `http` 伪协议删除（plan.md §5.3）。
- 未知 scheme → 启动失败并打印可用 scheme（不静默回落 raw；Go v1 的 `SetUpDownStream` 静默回落是隐性故障源）。
- `ws` 的 `domain` 缺省分别取 CLI `-domain`、其次 `-c` 的 host 部分（与 Go v1 一致）。
- 端口复用相关（`--reuse-magic` / `-rehost` / `-report`）**只能与 `raw` 组合**，与 `ws`/`kcp` 组合时启动失败。

### 4.2 注册表

```rust
pub struct TransportRegistry { listeners: Vec<AnyListener>, dialers: Vec<AnyDialer> }

impl TransportRegistry {
    /// specs 顺序即优先级顺序（见 §5.1 嗅探）。
    pub fn from_specs(specs: &[TransportSpec], opts: &RuntimeOpts) -> Result<Self, TransportError>;
    /// 按 kind 选拨号器；链路选择由「上行/下行」角色决定，不由对端告知。
    pub fn dialer_for(&self, kind: TransportKind) -> Option<&AnyDialer>;
}
```

**一条链路的传输种类由「发起方用哪种 dialer」单方面决定**，被 Finder 侧不用协商。但种类会写入握手 transcript hash（plan.md §4.5），因此中间人无法在不被发现的情况下把 `ws` 降级成 `raw`。

---

## 5. 多传输共存

### 5.1 TCP 类共用端口（raw + ws）

一条监听端口同时接受两种客户端，规则来自 Go v1 实战（`-down ws` 时 admin 仍可能收到 raw 的误连）：

```
accept(TcpStream) → peek(8) →
  b"STW2" (magic 前 4 字节)              → raw 链路
  b"GET " 或 b"POST "                  → ws 升级（再次 peek 到 \r\n\r\n 后交给 tungstenite）
  其它                                  → 见 §6.3 端口复用回落 / 否则 close
```

- `peek` **只取 8 字节、不消费**，避免与后续 TLS 握手抢字节（Go v1 缺陷 F10：先 `WrapTLSServerConn` 再读 token 导致嗅探失效）。
- 若端口启用了 TLS（`raw+tls`），嗅探顺序为：`peek(8)` 判定 `STW2`/HTTP → 再决定是否在上面包 TLS。TLS 记录层首字节是 `0x16`，永远不会是 `S`/`G`/`P`，规则不冲突。

### 5.2 UDP 类独立端口（kcp）

KCP 是 UDP，无法与 TCP 共端口，规则：

1. `kcp://` 的端口必须显式给定，**不得与任何 TCP 监听端口相同**（启动期校验）。
2. `conv` 缺省由 `HKDF(secret, "kcp-conv", 4 bytes)` 派生：同一部署的所有节点共享同一 `conv` 前缀，非本部署的 KCP 包在 `conv` 校验处被丢，避免与同机其它 KCP 服务互扰。
3. 若用户显式传 `conv=`，则**不**再做 secret 派生，并在启动日志中警告「conv 已固定，可能与同机其它服务冲突」。

### 5.3 同进程多传输

`-up` 与 `-down` 可各给一个 spec，因此一个进程可同时「上行 ws、下行 kcp」。约束：

- 两条链路**各自独立**做握手、密封、心跳，互不影响。
- 路由表与拓扑是**单一**的（节点不知道自己是被 ws 还是 kcp 接入的，除 `LinkMeta.kind` 用于诊断日志）。
- 内存与 fd 预算按监听器数量线性增长，`--max-listeners=4`（默认）超限即启动失败。

---

## 6. 传输 × TLS 组合矩阵

| 组合 | v2 状态 | 实现 | 备注 |
|---|---|---|---|
| `raw` + 明文 | ✅ 默认 | `TcpStream` 直接作为 `Link` | 帧层仍密封，明文只指「外层无 TLS」 |
| `raw` + TLS | ✅ | `tokio-rustls` + 确定性自签证书（plan.md §4.8） | 指纹（口径 **SPKI**，同 secret 恒同公钥；证书 DER 因签名随机化可变）进 TH，可 `--tls-pin` |
| `ws` + 明文 | ✅ | `tokio-tungstenite` + `WsLink` 适配层 | 过 NGINX/CDN 场景 |
| `ws` + TLS | ✅ | 自建 `rustls` 连接后 `client_async`（**不用 `Connector`**：本仓 `tokio-tungstenite` 只开 `handshake` feature） | 即 wss；`-domain` 同时用于 SNI 与 Host |
| `kcp` + 明文 | ✅（feature 开启时） | `tokio_kcp` | 帧层密封已足够；KCP 自带 FEC/重传 |
| `kcp` + TLS | ❌ | — | 需 DTLS，v2 不做（用「帧层密封 + KCP」替代） |
| `quic` | ❌ 占位 | — | QUIC 自带 TLS1.3，接入时需重新审视 TH 绑定 |

**防降级**：`transport_kind.wire_id || tls_fingerprint(32B or 全 0)` 一起进 transcript hash。攻击者若把 ws 降级成 raw，TH 变化 → `auth_key` 不同 → proof 校验失败。这与 plan.md §4.5 的 3-flight 握手共同构成「传输不可被中间人改写」的保证。

### 6.1 feature gate

| feature | 默认 | 内容 |
|---|---|---|
| `transport-raw` | ✅ 开 | `raw::Listener/Dialer` |
| `transport-ws` | ✅ 开 | `ws::Listener/Dialer` + `WsLink` |
| `transport-kcp` | ❌ 关 | `kcp::Listener/Dialer`；CI 全 feature 编译 |
| `transport-quic` | ❌ 关 | 仅枚举占位，编译期报 `todo!()` 路径不可达 |
| `tls` | ✅ 开 | `rustls` 相关；tier-3 目标关闭 |
| `tui` | admin 默认 | `ratatui`/`crossterm`；agent 关闭以减小体积 |

**规则**：`stowaway-transport` 必须能在 `--no-default-features --features transport-raw` 下单独编译通过（CI 检查矩阵含此组合）。这是 tier-3 目标（`armv5te`、`mipsel`，无 `target_has_atomic="64"`，`ring`/`aws-lc-rs` 不可用）能出包的前提。

### 6.2 与构建矩阵的联动

| 目标档 | 启用 feature |
|---|---|
| tier-1/2（x86_64、aarch64、armv7、i686） | `transport-raw,transport-ws,tls,tui` |
| `linux/musl`（best-effort） | 同上 + `transport-kcp` 试点 |
| tier-3（`armv5te-unknown-linux-musleabi`、`mipsel-unknown-linux-musl`） | **仅** `transport-raw`；关 `tls`、`transport-ws`、`transport-kcp`、`tui`（agent 无 TUI） |

### 6.3 端口复用的适用面

端口复用（iptables 规则 / SO_REUSEPORT 回落）本质是「在 TCP 端口上劫持非本协议流量」。因此：

- **仅 `raw`**：TCP + 首字节非 `STW2` → 走回落代理（`127.0.0.1:<report>`）或 close。
- **`ws` 不适用**：HTTP 首字节与端口复用 magic 的匹配规则冲突（`-m string` 无法同时安全匹配两者）。
- **`kcp` 不适用**：UDP 无此机制。
- **Windows 全平台不适用**（plan.md §4.11）。启动期对组合做校验并给出明确错误信息，不静默降级。

---

## 7. 一致性闸门（conformance suite）

`tests/transport_conformance` 对**每个已启用的 `TransportKind`** 跑同一套用例。新增传输若不能全绿，则不允许合并（这是「可插拔」的实际含义——插上去要能证明行为等价）。

| # | 用例 | 断言 |
|---|---|---|
| T1 | 小包往返 | 1 字节、255、4096 字节双向往返逐字节相等 |
| T2 | 大流量 | 写 10 MiB，读端聚合校验 SHA-256 相等；不 OOM |
| T3 | 背压 | 读端停读 3 秒、写端持续写：写端必须 `Pending`（不无限增长），进程 RSS 增长 < 32 MiB |
| T4 | 双向并发 | 两方向同时各 5 MiB，互不阻塞（无死锁） |
| T5 | 半关闭 | 写端 `shutdown(Write)` 后读端读到 `Ok(0)`；反向仍可写 |
| T6 | 对端 RST | 对端 close 后立即写：返回错误而非 panic |
| T7 | 快速建连/断开 | 1000 次 connect→close，无 fd 泄漏（`/proc/self/fd` 计数稳定） |
| T8 | 并发连接 | 32 条并发链路各自往返 1 MiB，全部正确 |
| T9 | `max_frame` 小于 `MAX_FRAME` | `LinkMeta.max_frame` 设为 4096 时，帧层正确分片（见 plan.md §4.4），无越界 |

**运行方式**：`cargo test -p stowaway-transport --features transport-raw,transport-ws,transport-kcp --test conformance`，CI 在 tier-1 上跑全 feature；`--features transport-raw` 下只跑 T1–T9 的 raw 变体。

---

## 8. 新增一种传输的 6 步清单

写死为 PR 检查项（评审时逐条打勾）：

1. **实现三个类型**：`kcp::Listener`（`bind`/`accept`/`local_addr`）、`kcp::Dialer`（`connect`）、`kcp::Link`（`AsyncRead`+`AsyncWrite`+`meta`）。
2. **接三处枚举**：`TransportKind`（含 `wire_id`）、`AnyListener`、`AnyDialer`。**禁止** `_ =>` 通配兜底。
3. **加 feature**：`transport-<name>` 加入 `Cargo.toml`；代码路径全部 `#[cfg(feature = "...")]`；验证 `--no-default-features --features transport-raw` 仍编译通过。
4. **加共存规则**：在 §5.1 嗅探表或 §5.2 UDP 端口规则中登记；若与端口复用互斥，在 §6.3 加校验。
5. **过一致性闸门**：§7 的 T1–T9 全绿。
6. **更新矩阵**：本文档 §6/§6.2 表 + `docs/plan.md` §4.13 构建矩阵 + `xtask` 的 target 列表。

### 8.1 KCP 预演（验证清单可执行）

已核对的依赖事实（2026-11）：

- crate：`tokio_kcp 0.9.8`（最后更新 2024-07-10，依赖 `kcp ^0.5.3` + `tokio ^1.37`）。**注意**：独立 crate `kcp` 已到 `0.6.0`，与 `tokio_kcp` 内部的 `0.5.3` **非同源，不可混用**。
- 类型：`KcpConfig`（`mtu`、`nodelay: KcpNoDelayConfig`、`wnd_size: (u16,u16)`、`session_expire`、`flush_write`、`stream`…）、`KcpListener`（`bind<A: ToSocketAddrs>(config, addr)`、`from_socket`、`accept`、`local_addr`）、`KcpStream`（实现 `AsyncRead + AsyncWrite`）。
- 陷阱：`KcpListener::bind` 收 `ToSocketAddrs`，但 `KcpStream::connect(config, addr: SocketAddr)` **只收 `SocketAddr`** → `Dialer` 必须自己先 `tokio::net::lookup_host` 解析（与 `raw`/`ws` 的拨号路径统一写法）。

映射到契约：

```rust
pub struct KcpLink { inner: tokio_kcp::KcpStream, meta: LinkMeta }
impl Link for KcpLink { fn meta(&self) -> LinkMeta { self.meta.clone() } }
// AsyncRead/AsyncWrite 直接委托 inner（KcpStream 已实现）

pub struct KcpListener { inner: tokio_kcp::KcpListener, cfg: KcpConfig, kind_meta: ... }
impl Listener for KcpListener { /* accept → KcpLink{ max_frame: cfg.mtu as usize * 8 , datagram_backed: true } */ }
```

`max_frame` 取 `mtu * 8`（约 11 KiB，1400 MTU）而非 `MAX_FRAME`（1 MiB）：KCP 的重传以段为单位，单帧过大会放大重传成本；帧层会按 §4.4 的 `min(MAX_FRAME, link.max_frame)` 自动分片。

**结论**：清单 1–6 步在 KCP 上均可落地，无需要改帧格式或 core 业务代码的地方。这验证了抽象层目标的达成。

---

## 9. 已知限制

1. **`tokio-tungstenite` 不是 `AsyncRead`**：`WebSocketStream<S>` 只实现 `Stream<Item=Result<Message, Error>>` + `Sink<Message>`。`WsLink` 必须自己实现适配：
   - 写方向：把 `poll_write` 的字节缓冲成 `Message::Binary`（单条消息承载整帧，或按 `max_frame` 分片），`SinkExt::send` 时必须处理 `Sink` 的 `Poll::Pending`。
   - 读方向：`poll_read` 从当前 `Message::Binary` payload 中取字节，用尽后 `Poll::Ready` 下一个消息；必须处理 `Message::Ping`/`Pong`/`Close`（Ping 回 Pong，Close 映射为 EOF）。
   - 这是 **v2 必须交付项**，不是可选优化。
2. **单 Link 不承载独立心跳**：心跳是帧层消息（`Heartbeat`），因此 ws 的 ping 帧不作为存活判据；两者不冲突但不可互相替代。
3. **`Box<dyn Link>` 的 `Unpin` 要求**：ws 适配层内部持有 `Message` 缓冲，需自行保证 `Unpin`（用 `Pin<Box<dyn Future>>` 或结构体字段不使用 `!Unpin` 类型）。
4. **`transport-quic` 占位不编译**：`AnyListener::Quic` 变体存在但构造路径为 `unreachable!("quic 未实现")`，避免加入无人维护的代码。
5. **`kcp` 依赖维护活跃度**：`tokio_kcp` 自 2024-07 未更新；若后续需要 `kcp 0.6` 的能力（如改进的 FEC），需评估自己维护 fork 的成本。这是 plan.md §9 风险表的一项。

---

## 10. 与主方案其他章节的衔接

| 本文内容 | 主方案位置 | 说明 |
|---|---|---|
| 分层栈 | plan.md §4.3 | 主方案只给摘要 |
| `MAX_FRAME` 与 `LinkMeta.max_frame` 的取小规则 | plan.md §4.4 | 帧层实现该规则 |
| `transport_kind` 进 transcript hash | plan.md §4.5 | 握手侧实现 |
| `-up`/`-down` 的 spec 语法 | plan.md §6 CLI 映射表 | CLI 解析层实现 |
| 嗅探与端口复用互斥 | plan.md §4.11 | 启动期校验 |
| feature × target 档 | plan.md §4.13 | xtask 编排 |
| 一致性套件 | plan.md §8 测试 | CI 编排 |