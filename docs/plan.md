# Stowaway Rust 重写方案（v2）

> 本文件是本仓库的权威实施方案：`rs-away` 的目标形态、与 Go 版 Stowaway 的差异、协议与密码学定义、可插拔传输层、CLI 映射、路线与验收。
> 基线：Go 仓库 `/root/workspace/coding/Stowaway`，HEAD `7f715be`，`LICENSE` MIT（Copyright (c) 2021 ph4ntom），`go.mod` = `module Stowaway` / `go 1.13`。
> 传输层详设见 [`docs/design/transport.md`](design/transport.md)；本文 §4.3 只给摘要。

---

## 0. 摘要与决策记录

把 Stowaway（Go，约 1.2 万行，admin + agent 双二进制）用 Rust 重写为 `rs-away`。重写目标不是逐行翻译，而是**保留全部能力、修掉 13 项必修缺陷、把不可测的并发模型换成结构化 actor**。

**与 v1 的关系**：线协议**不兼容**。v2 重新定义帧格式、握手与消息集；Go 与 Rust 节点不能混部。`tests/interop` 只对照**行为**（SOCKS5 语义、文件切分、shell 输出），不对照线格式。

**决策记录**

| # | 决策 | 依据 |
|---|---|---|
| D1 | 线协议不与 Go v1 兼容，直接定义 v2 | v1 的 10 字节定长 UUID + 冒号拼接路由串 + reflect 载荷，无法在不牺牲安全性与可演进性的前提下保留 |
| D2 | 控制台用 `ratatui` 全屏 TUI 复刻两级面板 | 替掉 termbox（Linux/macOS）+ ansicon（Windows）两套实现 |
| D3 | 全平台对等，但构建矩阵分 `blocking` / `best-effort` 两档 | Go 版 Makefile 实测只有 11 个 OS-ARCH 组合；tier-3 目标需 `-Z build-std`，不能与 tier-1 同等待遇 |
| D4 | 传输层可插拔：`raw` / `ws` 随 v2 发布，`kcp` 走 feature 预留，`quic` 仅占位 | 见 `docs/design/transport.md` |
| D5 | 帧层永远密封；TLS 只是可选外壳，关闭 TLS 不影响载荷加密 | 修正缺陷 #5：`--tls-enable` 时把 `Secret` 置空导致载荷明文 |
| D6 | secret 支持非 argv 来源；TLS 私钥确定性派生（指纹绑 SPKI，重启不变） | 修正缺陷 #7（静态明文 token）与 #6（RSA-1024 + `InsecureSkipVerify`） |
| D7 | **小步提交 + 阶段里程碑 tag + 提交信息溯源到本文档章节/缺陷号；`master` 任何时刻可构建** | 便于溯源与恢复，见 §10 |

**文档维护规则**

1. 任何关于 Go 版行为的结论必须带 `路径:行号`，且该行内容在基线 HEAD 上非空。
2. §3 缺陷表是**全仓缺陷的唯一事实源**：代码里修了表里没有的缺陷，先加一行再加修复；修复提交必须在提交信息里写 `Refs: plan §3#<n>`。
3. 不写本文件自身的哈希、字节数、生成时间、生成路径。
4. 术语统一：`admin` / `agent` / `节点` / `会话` / `链路（link）` / `传输（transport）`。除 §2 现状描述外，不再出现 `Route 字符串`、`TEMP_UUID`、`TEMP_ROUTE` 等 v1 概念。

---

## 1. 范围与非目标

### 1.1 范围（能力对等清单）

| 类别 | 能力 |
|---|---|
| 拓扑 | 树形多级网络；admin 为根；agent 可直连 admin，也可由上级 agent 以 `listen` 模式接入；掉线后 UUID/编号复用 |
| 代理 | SOCKS5（TCP CONNECT + UDP ASSOCIATE，含上游 SOCKS5/HTTP 代理链） |
| 转发 | forward（admin 本地监听 → 目标侧拨号）、backward（目标侧监听 → admin 侧中继） |
| 服务 | 文件上传/下载、交互式 Shell、SSH 命令执行、SSH 隧道（`sshtunnel`） |
| 桥接 | `connect`（跨 admin 隧道） |
| 端口复用 | iptables 规则劫持 + SO_REUSEPORT 回落（Linux/macOS/BSD；Windows 不支持，见 §4.11） |
| 运维 | 两级 TUI 控制台（22 条命令）、心跳、断线重建、`shutdown` |
| 工程 | 单元 + 属性测试 + fuzz + 传输一致性套件 + 端到端集成测试；`xtask` 交叉编译矩阵 |

### 1.2 非目标

| 非目标 | 原因 |
|---|---|
| 与 Go v1 线协议互通 | 见 D1 |
| 伪装成合法 HTTP 服务（域名前置 / CDN 隐身） | Go 版的 `http` 伪协议自身标注 deprecated，`ws` 也只做握手不分帧；v2 用真正的 RFC6455，伪装性由部署侧反代（NGINX/CDN）承担 |
| 不可靠数据报传输语义 | KCP/QUIC 都以可靠流接入，见 transport.md §1 |
| 传输层多路复用（单连接并发多路） | 多路由 session 层 `session_key` 承担，保持与 v1 相同的单 Conn 模型 |
| v2 实现 QUIC | 仅占位 |
| 读取 v1 配置/持久化格式 | 见 §5.6 |

### 1.3 环境与工具约束

| 项 | 值 |
|---|---|
| 语言 / 版本 | Rust，**MSRV 1.89**（上限来自 `russh 0.65.2`；`sha2 0.11.1` 与 `ratatui 0.30.2` 需 1.88） |
| edition | 2024 |
| 目标平台 | 见 §4.13（11 个 blocking 组合 + best-effort 档） |
| 源码规模预期 | 协议 + 加密 + 传输 ≈ 4.5k 行；core ≈ 8k 行；admin（含 TUI）≈ 5k 行；agent ≈ 5k 行；合计约 22k 行（Go 版约 12k 行，增量主要在类型化消息、传输抽象与测试） |

**本机开发环境的两个只读约束**（只影响当前这台开发机，不影响 CI 与普通开发机）：

1. `/` 是只读挂载（`/dev/vda1 on / type ext4 (ro,...)`），只有本工作区与 `/tmp` 可写。`rustup` 拉新 toolchain 需要写 `/root/.rustup/tmp` → 失败（`Read-only file system (os error 30)`）。因此 `rust-toolchain.toml` 固定 `stable`，MSRV 只由 `rust-version` 字段表达（§4.2）。
2. `CARGO_HOME` 默认在 `/root/.cargo`（只读），cargo 解包 crate 时会写 registry cache → 同样报 os error 30。解决：`scripts/dev-env.sh` 把 registry 复制到工作区内的 `.cargo-home/`（已 gitignore），构建前 `export CARGO_HOME=$PWD/.cargo-home`。

---

## 2. Go 现状基线

> 调查方法：`graphify query` 定位模块与枢纽节点（`ConstructMessage()` 是最高 betweenness 节点，横跨 10 个社区；`Topology` 与 `Manager` 是另两个跨社区桥），再逐文件精读核对。本节所有结论均已在基线 HEAD 上验证；与旧版方案不一致处以本表为准（**F1–F12 为事实修正**）。

### 2.1 角色与拓扑

| 概念 | 现状 |
|---|---|
| 角色 | 两个二进制 `admin` / `agent`，共用 `protocol/`；入口 `admin/admin.go`、`agent/agent.go` |
| 拓扑 | 树。admin 为根；agent 可直连 admin，也可挂在另一个 agent 下（`listen` 模式） |
| 路由 | `admin/topology/topology.go` 的 `Topology` actor 维护 `nodes map[int]*node` / `route map[string]string` / `history map[string]int`；`calculate()` 为每个节点算出冒号分隔的 UUID 链 |
| 转发 | `agent/process/process.go` `changeRoute(header)` 取链首作下一跳，剩余 `strings.Join(routes[1:], ":")` 回写 `header.Route` |
| 编号 | `idNum`（整数，给人看）与 `uuid`（10 字符，内部路由）双轨；`history` 支持掉线后复用原编号 |

### 2.2 线协议（`protocol/`）

**帧格式**（`protocol/raw.go:100-147`）

```
Sender      [10 bytes 定长]
Accepter    [10 bytes 定长]
MessageType uint16 BE
RouteLen    uint32 BE
Route       [RouteLen bytes]
DataLen     uint64 BE
Data        [DataLen bytes]   ← 长度是密文长度
```

**载荷编码**（`protocol/raw.go:32-94`）：`reflect` 遍历 Go struct 字段，按**声明顺序**拼接；约定每个 `string`/`[]byte` 字段前必须有 `<Name>Len` 字段（宽度 u16/u32/u64 混用），解码端靠 `FieldByName(name+"Len")` 反查长度。

**加密管线**：`gzip 压缩 → AES-256-GCM（12 字节随机 nonce 前置）`。

**条件解密**（`protocol/raw.go:155-159`）：仅当 `Accepter == TEMP_UUID || 接收方是 admin || 接收方 == Accepter` 时解密，否则原样透传——这就是多级转发的实现方式（**解密规则编码在 UUID 比较里**）。

**关键常量**：`ADMIN_UUID="IAMADMINXD"`、`TEMP_UUID="IAMNEWHERE"`、`TEMP_ROUTE="THEREISNOROUTE"`；UUID 固定 10 字节。

**消息常量（F1）**：`protocol/protocol.go:12-67` 的 const 块共 **56 行、54 个名字**（`HI=0` … `HEARTBEAT=53`，无空缺）。旧方案称「53 种」有误；本文一律按 **54**。

### 2.3 传输层（`protocol/websocket.go`、`share/transport/`）

| 模式 | 实现 | 实际行为 |
|---|---|---|
| `raw` | `RawProto` / `RawMessage` | 直接 TCP，帧即字节流 |
| `http` | `protocol/http.go` | **文件首行注释即 `// http.go is deprecated / Kept as a sample`**；构造伪 HTTP 头（随机路径 `/message|uploads|request|hellowd` + 伪造 Chrome UA），载荷仍是 stowaway 帧 |
| `ws` | `protocol/websocket.go` | 做 RFC6455 的 101 握手（校验 `Sec-WebSocket-Accept`），但 `WSMessage` **未覆写任何方法**，帧数据以裸字节直写 socket，**没有分帧**。源码 TODO 自述「data frames still have some issues」，实际只能过 NGINX 这类透传反代 |

**传输选择**：`protocol/protocol.go:428` `SetUpDownStream(upstream, downstream string)` 是**全局包级变量**，`ws`/`http` 之外的任意值一律回落 `raw`——没有接口注册点，也没有「未知取值报错」。`-up` 与 `-down` 是**两条独立链路**（上行链路 / 子节点链路）各自的传输选择；admin 固定 `up="raw"`，只有 `-down`（`admin/admin.go`）。

**TLS**（`share/transport/tls.go`）：`newRandomTLSKeyPair()` 用 `rsa.GenerateKey(rand.Reader, 1024)` 现场生成自签证书 → **每次重启指纹都变**；`NewClientTLSConfig` 硬编码 `InsecureSkipVerify = true`；CA 加载与 `newCustomTLSKeyPair`/`newCertPool` 整段被注释（`tls.go:65-88`，注释 `// Currently unused`）。

**预认证**（`share/preauth.go`）：`AuthToken = MD5(secret)[:16]`，16 字节**明文**双向对发（Active 方先发、Passive 方先发），10 秒超时，无重放保护。

### 2.4 Admin 侧

| 模块 | 行数 | 职责 |
|---|---|---|
| `admin/topology/topology.go` | 327 | 树拓扑 actor；`ADDNODE/GETUUID/GETROUTE/CALCULATE/DELNODE/REONLINENODE` 等 13 种 task |
| `admin/process/process.go` | 144 | 下行消息按 `MessageType` 分发到各 manager channel |
| `admin/handler/*.go` | **1777**（F4 修正） | 每类消息一个 dispatcher goroutine：socks/forward/backward/listen/connect/file/ssh/sshtunnel/shell/info/children |
| `admin/manager/*.go` | **1072**（5 个文件，F4 修正） | 功能状态持有者（actor），`TaskChan`/`ResultChan` 模式 |
| `admin/cli/interactive.go` + `interactive_win.go` | 2430 | termbox TUI，两级面板（Linux/macOS 1209 行 + Windows 1221 行） |
| `admin/process/process_win.go` | 137 | Windows 独有的一份重复分发器 |
| `admin/initial/method.go` | 278 | admin 侧握手与建链 |

### 2.5 Agent 侧

| 模块 | 行数 | 职责 |
|---|---|---|
| `agent/process/process.go` | 245 | 上行读取：`Accepter == 自己` → 派发给 manager；否则 `changeRoute` 后转给子节点（密文透传） |
| `agent/process/offline.go` | 502 | 断线恢复（见 §2.8） |
| `agent/handler/socks.go` | 769 | SOCKS5 **服务端**：`checkMethod`/`auth`/`buildConn`/`tcpConnect`/`udpAssociate`/`proxyC2STCP`/`proxyC2SUDP` |
| `agent/handler/listen.go` | 644 | 三种监听：normal / iptables / so_reuse |
| `agent/handler/connect.go` | 214 | 主动外连（对目标扮演 admin） |
| `agent/handler/backward.go` | 303 | 反向端口映射 |
| `agent/handler/{shell,ssh,sshtunnel,forward,file}.go` | ~768 | 各功能实现 |
| `agent/handler/*.go` 合计 | **2700**（F4 修正） | |
| `agent/manager/*.go` | **739**（6 个文件，F4 修正） | 状态持有者；比 admin 多一个 `children.go` |
| `agent/initial/method.go` | 423 | agent 侧握手、`SetPortReuseRules`/`DeletePortReuseRules`、`SoReusePassive`、`ProxyStream` |

**manager 规模（F4）**：两侧合计 **1811 行 / 11 个文件**（admin 5 + agent 6）。旧方案「manager 从 10 缩到 6」的口径是「两侧合计」，必须写清，否则容易被读成单侧。

### 2.6 核心数据流

**SOCKS5（TCP）**：admin 监听本地端口（默认 1080）→ 客户端 SOCKS5 握手**字节原样**封成 `SOCKSTCPDATA` → 路由链送达目标 agent → agent 侧执行 `checkMethod`/`auth`/`tcpConnect` 真正连目标 → 应答字节回传 → 之后双向 `SOCKSTCPDATA`。即 **admin 是 SOCKS5 客户端，agent 是 SOCKS5 服务端，握手字节被隧道化而非被 admin 解析**。

**UDP ASSOCIATE（F2 修正，方向与旧方案相反）**：**agent 侧发起**——agent 构造 `UDPAssStart{Seq, SourceAddr}` 上行（`agent/handler/socks.go:454`、`:540-570`），admin 回 `UDPAssRes` 并绑本地 UDP socket（`admin/handler/socks.go:259-330`、`:437-455`），之后 `SOCKSUDPDATA` 双向承载数据报。

**forward**：admin 本地 listen → 客户端接入 → 先发 `FORWARDTEST` 探测目标可达（`admin/handler/forward.go` 的 `ForwardReady` 握手）→ 通过后 `F_NEWFORWARD` 注册并注册数据通道 → 再发 `FORWARDSTART` → agent 拨号目标 → `FORWARDREADY` → 双向 `FORWARDDATA`。
**注意**：源码注释（`admin/handler/forward.go:124-132`）明确写了为避免「Done chan DEAD LOCK」，`F_GETDATACHAN`（`:134`）与发送 `FORWARDSTART` 必须**分两步**——先注册数据通道再发 START。v2 必须避免同类顺序耦合（用「先建 session 再发数据」的两阶段 `Prepare/Commit`，见 §4.8）。

**backward**：admin 发 `BACKWARDTEST` 探测 agent 能否监听 → agent 在本机 `lPort` 起 listener → 有连接时 agent 发 `BACKWARDSTART`（`Sender=自己`、`Accepter=ADMIN_UUID`、`Route=TEMP_ROUTE`，注释「No need to set route when agent send mess to admin」）→ 再向本地 manager 要 seq（`B_GETSEQCHAN`）→ `go handleBackward(mgr, conn, seq)` → admin 侧连 `rPort` 并中继。**即反向会话的 seq 由 agent 侧分配、admin 侧回填**——`session_id` 的单 u64 语义在多跳与 connect 桥接下会撞号（v2 用 `SessionKey{origin, id}`，见 §4.8）。

**listen（多级网络）**：admin 发 `LISTENREQ` → 目标 agent 起监听 → 子 agent 连入后，父 agent **扮演 admin** 与子节点完成 HI 握手（`agent/handler/listen.go:151-171` 用 `protocol.ADMIN_UUID` 伪造：回 HI 时 `IsAdmin: 1`、`UUID: ADMIN_UUID`、`Sender=ADMIN_UUID`、`Accepter=TEMP_UUID`，代码注释 `//fake admin`），再把 `CHILDUUIDREQ` 上报真 admin → admin `dispatchChildUUID` 分配 UUID 并下发 `CHILDUUIDRES` → 父 agent 转发给子节点。

**connect（跨 admin 桥接）**：admin 发 `CONNECTSTART` → 目标 agent 主动外连 `connect.Addr`，同样扮演 admin 完成握手 → 形成 admin↔admin 隧道。

**文件传输**：`FILESTATREQ/RES` → `FILEDATA`（分片 30720 字节，`share/file.go:194`）→ `FILEERR`；下载方向 `FILEDOWNREQ/RES` + `FILEDATA`。落盘用 `os.Create(file.FileName)`（`share/file.go:148`）——**直接用客户端文件名**。

**Shell / SSH / SSH 隧道**：请求/结果/退出三段式（`SHELLREQ/RES/COMMAND/RESULT/EXIT`；SSH 同构）；SSH 用 `golang.org/x/crypto/ssh`，agent 侧作 SSH 客户端连目标并中继，使用 `ssh.InsecureIgnoreHostKey()`（`agent/handler/ssh.go:88`、`sshtunnel.go:81`），私钥 bytes 经 `SSHREQ` 传递。Shell 用 `exec.Command("/bin/sh","-i")`（amd64/386 上改用 `/bin/bash -i`）+ `StdoutPipe`/`StdinPipe`/`cmd.Start`（`agent/handler/shell.go:76-90`），**无 PTY**。

### 2.7 端口复用

- **iptables 模式**（Linux + root）：`agent/initial/method.go:241-247` `setReuseSecret` 计算
  `finalSecret = MD5(secret)[:24] + MD5(MD5(secret))[:24]`（各 24 字符），
  `START_FORWARDING = finalSecret[16:32]`、`STOP_FORWARDING = finalSecret[32:]`（各 16 字符）——**不是** 旧方案所说的「由 `MD5(MD5(secret))` 派生」。
  `SetPortReuseRules` 建 `nat` 自定义链 `STOWAWAY`（`CHAIN_NAME = "STOWAWAY"`），`-A STOWAWAY -p tcp -j REDIRECT --to-port <localPort>`；`INPUT` 链用 `-m string --string <magic> --algo bm` 配 `-m recent --set/--remove --rsource` 维护源 IP 白名单；`PREROUTING` 用 `--syn -m recent --rcheck --seconds 3600 --rsource -j STOWAWAY`。退出时 `SIGINT`/`SIGTERM` → `DeletePortReuseRules` → `os.Exit(0)`。命令全部 `exec.Command(...).Run()` 且**丢弃返回值**（缺陷 #10）。
- **SO_REUSEPORT 模式**：用 `github.com/libp2p/go-reuseport` 起 listener；`conn.SetReadDeadline(time.Now().Add(2 * time.Second))`，2 秒内读不到 16 字节 token 则 `go initial.ProxyStream(conn, buffer[:count], userOptions.ReusePort)` 转投 `127.0.0.1:<report>`（`agent/initial/method.go:341-360`、`agent/handler/listen.go:491-510`、`agent/process/offline.go:199-218`）。
- **TLS 下的时序缺陷（F10）**：`--tls-enable` 时**先** `WrapTLSServerConn` 再读 16 字节 token（`agent/initial/method.go:330` 包 TLS → `:344-345` 才读 16 字节 token），所以非 stowaway 流量会先在 TLS 握手处失败，**回落逻辑在 TLS 下失效**。v2 必须用 `MSG_PEEK` 先嗅探再决定是否包 TLS。

### 2.8 失败与恢复语义

| 事件 | Go 版行为 |
|---|---|
| agent 上行断开 | `upstreamOffline()`（`agent/process/offline.go:23`）：`NORMAL_ACTIVE`/`SOCKS5_PROXY_ACTIVE`/`HTTP_PROXY_ACTIVE` → **直接 `os.Exit(0)`**；其余 → `forceShutdown` → `broadcastOfflineMess`（通知子节点上游已断）→ 按模式重建链路 → `global.UpdateGComponent(newConn)` → `tellAdminReonline`（`NODEREONLINE`）→ `broadcastReonlineMess` |
| 子节点断开 | `downStreamOffline` → 上报 admin → `topology.delNode` **递归摘除该节点及其整棵子树** |
| admin 侧 peer 断开 | `admin/process/process.go:68` 打印「[*] Peer node seems offline!」+「Press any key to exit」→ 等按键 → `os.Exit(0)` |
| 心跳 | admin `-heartbeat` 开启时（admin 独有，`admin/initial/parser.go:54`）每 10 秒向**节点 0** 发 `HEARTBEAT`（`admin/handler/heartbeat.go:21`，`route` 在循环外只取一次）；agent 侧 `case protocol.HEARTBEAT:` 是**空分支**（`agent/process/process.go:171`）——只做保活，不测 RTT、不判死亡 |
| 重连 | `--reconnect <秒>`：主动模式按固定间隔重拨（`normalReconnActiveReconn`） |

### 2.9 与并发/性能相关的事实（F3 修正）

旧方案称「每帧都要做一次拓扑 channel 往返来取路由」——**不成立**。实测 `GETROUTE` 全仓共 8 行命中，其中 6 处是调用点（另 2 行是定义与 match 臂）：

| 位置 | 频率 |
|---|---|
| `admin/handler/socks.go:259` | **仅** `startUDPAss` 一次（每条 UDP 会话一次） |
| `admin/handler/listen.go:95` | 每次 `listen` 建立一条子链路一次 |
| `admin/handler/backward.go:69` | 每次反向映射建立时一次 |
| `admin/handler/heartbeat.go:21` | 心跳循环外一次 |
| `admin/cli/interactive.go:532`、`interactive_win.go:544` | 用户执行 `connect`/`ssh` 等命令时一次 |

`socks.go` 的 `handleSocksListener` 把 `route` 作为**参数捕获**后整条 SOCKS 会话复用。真实开销在别处：

1. **每帧新建 `Message` + `reflect` 序列化 + gzip + AES（含随机 nonce）**——`protocol/raw.go` 的 `DeconstructData`/`ConstructMessage`；
2. **`SendMessage()` 用 `finalBuffer := append(message.HeaderBuffer, message.DataBuffer...)` 再 `Write`，随后两者置 nil**（`protocol/raw.go:331-336`）——每帧两次分配 + 一次拷贝；
3. **全局单 `Conn` 上多 goroutine 争写**，无写队列、无批量 flush；
4. 每新建一个 TCP 会话有 2 次 manager channel 往返（`S_GETNEWSEQ`、`S_ADDTCPSOCKET`）；
5. 全仓 `TCP_NODELAY` / `SetNoDelay` / `KeepAlive` **零命中**（F12）；拨号统一 `net.DialTimeout(..., 10*time.Second)`。

### 2.10 收包缓冲与超时（F12）

| 位置 | 值 |
|---|---|
| `admin/handler/socks.go:204` | recv buffer 20480 |
| `agent/handler/socks.go:398`、`:675` | recv buffer 20480 |
| `agent/handler/socks.go:619` | SOCKS UDP `make([]byte, 0, 1024)` |
| `share/file.go:194` | 文件分片 `SliceSize = 30720` |

---

## 3. 必修缺陷清单

> 唯一事实源。13 行，每行对应至少一条回归测试（§8）。`#1–#11` 来自 Go 版代码审查，`#12–#13` 为本轮新增。

| # | 缺陷 | 位置 | 触发条件 | 后果 | v2 对策 |
|---|---|---|---|---|---|
| 1 | 未知 `MessageType` → `reflect.TypeOf(mess)` 为 nil → `.Elem()` 空指针 | `protocol/raw.go:275` | 握手后发任意非法 type | **远程 panic，进程崩溃** | `msg_type` 用 `#[repr(u16)]` 枚举，未知值返回 `Err`；fuzz 覆盖 |
| 2 | GCM 认证失败被忽略 → 返回 nil → gzip 失败 → 空 buffer → 切片越界 | `crypto/aes.go:45` + `protocol/raw.go:300` | 密文被篡改 / 密钥不符 / 传输损坏 | **远程 panic** | 密封失败一律 `Err` 并断链；解压失败同样 `Err`（修 #8） |
| 3 | `DataLen` 为 u64 且无上限 → `make([]byte, header.DataLen)` | `protocol/raw.go:149` | 单帧声明超大长度 | **内存耗尽 DoS** | 帧层 `payload_len <= MAX_FRAME`（1 MiB），越界即断链 |
| 4 | 长度字段直接用于切片 `dataBuf[ptr:ptr+n]` | `protocol/raw.go:297-319` | 长度字段大于实际数据 | **panic** | 解码全程用 `checked_add` + 剩余长度校验；属性测试 |
| 5 | `--tls-enable` 时把 `Secret` 置空 → **载荷加密完全关闭** | `agent/initial/method.go:82-93`、`:184`、`:333`；`admin/initial/method.go:90`、`:213` | 用户开启 TLS | 与 `InsecureSkipVerify` 叠加 → **等同明文** | 帧层密封与 TLS 解耦（D5）；TLS 开关不影响 `Secret`；**且改的是共享 `options`（F11）→ 被动侧每 accept 一次即污染后续所有连接** |
| 6 | TLS 恒 `InsecureSkipVerify = true` + RSA-1024 自签 + 每次重启换指纹 | `share/transport/tls.go:113`、`tls.go:23`、`:65-88` | 任何时候 | **MITM 可完全透明代理**（不写成「任何人可解载荷」；载荷另有 AES 层） | 证书私钥由 `HKDF(secret, "tls-cert-key")` 确定性派生 → **同 secret 恒同公钥/SPKI**，指纹绑定 SPKI 故重启不变（证书 DER 因 ECDSA 签名随机化每次可不同，不影响 pin）；客户端默认校验指纹（`--tls-pin` / known_hosts 式 TOFU 持久化） |
| 7 | 预认证 token 明文、静态、可重放；`token = MD5(secret)[:16]` | `share/preauth.go:15,26`、`crypto` 层 | 抓包 | 真实危害是**重放** + 用垃圾帧触发 #2 的远程 panic；`MD5(secret)[:16]` 同时是**离线字典验证器**（拿到 token 即可暴破 secret），但**仅持 token 不足以构造合法 GCM 帧** | 3-flight 握手 + 挑战应答 + `proof = HMAC(auth_key, TH‖role)` + 时间窗与单调 counter（§4.5） |
| 8 | `gzip` 解压失败静默返回空 | `crypto/gzip.go:23` | 数据损坏 | 静默丢数据，是 #2 的放大器 | 解压失败 `Err`；压缩默认关闭（见 §4.4 flags 预留） |
| 9 | `aes.NewCipher` / `cipher.NewGCM` 错误被忽略 | `crypto/aes.go:41-42` | 异常密钥长度 | panic | 密钥长度在类型层固定（`[u8; 32]`），构造期即校验 |
| 10 | iptables 命令错误被忽略 | `agent/initial/method.go:260,277`（`exec.Command(...).Run()` 返回值丢弃） | 无 root / 规则冲突 | **防火墙半配置状态**，静默失效 | 命令执行检查退出码；失败即回滚已加规则并报错退出（或显式 `--allow-degraded`） |
| 11 | **旧表述失真**：并非「逐帧取路由」，瓶颈另在别处 | 见 §2.9 | — | 真实瓶颈是**每帧 Message 分配 + reflect + gzip + AES(随机 nonce) + `append` 两次分配 + 单 Conn 争写**，以及每 TCP 会话 2 次 manager 往返 | 零拷贝帧编解码、会话内缓存下一跳、批量 flush、单写队列（§4.9） |
| **12** | 代理回调负索引 panic；CONNECT 不带认证头 | `share/proxy.go:205`（`resultBuf[begin-4:begin]`）、同文件 CONNECT 分支 | SOCKS5/HTTP 上游代理**提前短响应**（`begin < 4`） | panic（进程崩溃） | 解析前校验 `begin >= 4`；CONNECT 补 RFC7235 `Proxy-Authorization`；两者各有回归测试 |
| **13** | 文件落盘无路径穿越防护；SOCKS 认证无凭据校验 | `share/file.go:148`（`os.Create(file.FileName)`）、`agent/handler/socks.go` `checkMethod` | 客户端传入 `../` 文件名 / 任意 SOCKS 客户端 | 任意路径写文件；SOCKS5 认证形同虚设 | 落盘路径经 `canonicalize` 且必须位于 `--download-dir` 内；SOCKS 认证改为可选强制（`--socks-auth`） |

**附带清理项**（不单列回归测试）：`utils/utils.go:196` 调试残留 `print("count is ", count)`；`utils.CheckRange` 用冒泡排序；`GetRandomString/GetRandomInt` 用 `math/rand`（非 CSPRNG）。

---

## 4. v2 目标架构

### 4.1 工程结构

```
rs-away/
├── Cargo.toml                        # workspace（resolver = "3"）
├── rust-toolchain.toml               # channel = stable（组件 rustfmt/clippy；MSRV 见 §4.2）
├── crates/
│   ├── stowaway-protocol/            # 帧编解码、消息枚举、SessionKey（无 IO）
│   ├── stowaway-crypto/              # HKDF/HMAC/X25519/AES-GCM/证书指纹/密封
│   ├── stowaway-transport/           # raw/ws/(kcp) + TLS + 握手 + 嗅探
│   │   └── src/transport/{raw,ws,kcp}
│   ├── stowaway-core/                # 拓扑/Session/Router/SOCKS5/forward/file/shell
│   ├── stowaway-admin/               # admin 二进制（thin main + 启动编排）
│   └── stowaway-agent/               # agent 二进制（thin main + 启动编排）
├── xtask/                            # check / doccheck / build-matrix / release
├── tests/
│   ├── interop/                      # 行为对照（不对照线格式）
│   ├── e2e/                          # 多跳场景
│   └── transport_conformance/        # 传输一致性闸门
└── docs/{plan.md,design/transport.md,threat-model.md}
```

依赖方向（**单向，CI 用 `cargo deny`/`xtask deps` 校验**）：
`protocol → crypto → transport → core → {admin, agent}`；`xtask` 依赖全部。`core` 不得依赖 `admin`/`agent`；`protocol` 不得依赖 `tokio`（纯字节层，可 `no_std` 编译用于测试）。

### 4.2 依赖与 MSRV

**MSRV = 1.89**，写进每个 `Cargo.toml` 的 `rust-version`。上限来自 `russh 0.65.2`；`sha2 0.11.1` 与 `ratatui 0.30.2` 需 1.88。

`rust-toolchain.toml` 固定 `channel = "stable"` 而非 `1.89.0`：`rustup` 需要写 `/root/.rustup/tmp` 才能拉取新 toolchain，而本机 `/` 是只读挂载（§1.3），只有工作区与 `/tmp` 可写 → 指定 `1.89.0` 会直接导致 `cargo` 不可用。MSRV 约束因此**只由 `rust-version` 字段表达**，CI（普通开发机）用 `1.89.0` 严格校验。

| 用途 | crate（版本为 2026-11 实测） | 备注 |
|---|---|---|
| 异步运行时 | `tokio 1.x`（`rt-multi-thread`/`net`/`io-util`/`sync`/`time`/`process`/`signal`/`fs`/`macros`） | |
| 帧编解码 | `tokio-util`（codec） + 自写 `FrameCodec` | 变长头不适合 `LengthDelimitedCodec` |
| 序列化 | `serde 1` + `postcard 1.1.3` + `serde_bytes` | **postcard 是非自描述紧凑编码**（不是「自描述」） |
| 对称加密 | `aes-gcm 0.11.1` | 依赖 `aead 0.6` |
| KDF / MAC | `hkdf 0.13.0` + `hmac 0.13.0` + `sha2 0.11.1` | |
| 密钥交换 | `x25519-dalek 3.0.0` | **必须开 `static_secrets` feature**（`StaticSecret` 默认不编译）；握手用 `EphemeralSecret` |
| 随机数 | `rand 0.10.4` | 与 `x25519-dalek 3` 的 `rand_core 0.10` 同代 |
| 密钥清洗 | `zeroize 1.9.2` + `subtle 2.6.1` | 常量时间比较、内存清零 |
| TLS | `rustls 0.23.46` + `tokio-rustls 0.26.6` + `rustls-pki-types 1.16.0` + `webpki-roots 1.0.12` + `rcgen 0.14.10` + `p256 0.14.0` | 默认 `ring` provider；tier-3 目标关 TLS |
| WebSocket | `tokio-tungstenite 0.30.0` | 真 RFC6455；**注意它不实现 `AsyncRead`**，需 `WsLink` 适配层 |
| 缓冲 | `bytes 1.12.1` | 零拷贝帧缓冲 |
| 并发工具 | `futures-util 0.3.34` | |
| TUI | `ratatui 0.30.2`（`default-features = false`，显式 `["crossterm_0_29", "all-widgets"]`）+ `crossterm 0.29.0` | 必须显式选 `crossterm_0_29`，否则默认后端与 `crossterm 0.29` 不匹配 |
| CLI | `clap 4`（derive） | `ArgGroup` 显式校验，替代 v1 的 9 种 Mode 穷举 |
| 日志 | `tracing 0.1.44` + `tracing-subscriber 0.3.23` | |
| 字符编码 | `encoding_rs 0.8.44` | GBK（`-cs`，**agent 侧 shell**） |
| socket 选项 | `socket2 0.6.5` | `TCP_NODELAY`、`SO_REUSEPORT` |
| 系统 | `nix`（unix，feature 门控）/ `windows-sys`（windows） | 信号、iptables 调用、`gethostname` |
| PTY | `portable-pty 0.9.0` | 修 v1「无 PTY」 |
| SSH | `russh 0.65.2` + `russh-keys` | 异步纯 Rust；API 变动频繁，锁死小版本 |
| 进度条 | `indicatif 0.18.6` | 文件传输 |
| 错误 | `thiserror 2.0.21`（库） + `anyhow 1.0.104`（二进制） | |
| KCP（feature） | `tokio_kcp 0.9.8` | 默认关闭；其内部依赖 `kcp 0.5.3`，**与独立 crate `kcp 0.6.0` 非同源，勿混用** |
| dev | `proptest 1.12.0`、`criterion 0.8.2`、`insta`、`cargo-fuzz` | |

**schema 演进规则**（因 postcard 非自描述）：`msg_type` 用 `#[repr(u16)]` 显式 discriminant 且**只追加不复用**；消息字段只允许追加，新字段必须 `#[serde(default)]`；版本号在 `Hello` 协商，`minor` 不一致时按「交集字段」降级；禁止依赖 serde 的结构推断来解析未知字段。

### 4.3 连接协议 / 传输抽象层（摘要）

```
应用消息 (SessionData / ServiceData / …)   ← 只认 session_key，无传输感知
  ↑ FrameCodec   (version | flags | msg_type | dest[16] | via[] | payload)
  ↑ LinkSealer   (逐跳 AES-GCM；nonce = iv(4B) ‖ counter(8B)；AAD = 帧头)
  ↑ Link         (AsyncRead + AsyncWrite 统一字节流，reliable/ordered/背压)
  ← TransportKind: raw(TCP) / ws(TCP+HTTP101) / kcp(UDP→可靠流) / quic(占位)
```

**六条约束**（详设与 trait 契约见 [`design/transport.md`](design/transport.md)）：

1. `Link` 只承诺**可靠、有序、字节流、EOF、背压**；不承诺消息边界。
2. `MAX_FRAME = min(1 MiB, link.meta().max_frame)`，帧层负责分片。
3. `transport_kind` 与 `tls_fingerprint` **一起进 transcript hash** → 中间人无法跨传输降级。
4. TCP 类（raw/ws）**共用端口**，由首字节嗅探分发（`STW2`→raw；`GET `/`POST `→ws；其它→端口复用回落）；嗅探用 `peek(8)` 不消费。
5. UDP 类（kcp/quic）**独立端口**；KCP `conv` 缺省由 `HKDF(secret,"kcp-conv")[:4]` 派生。
6. 端口复用（iptables / SO_REUSEPORT）**只适用于 TCP raw**；与 ws/kcp 组合时启动失败。

`-up` / `-down` 各接受一个 `TransportSpec`（`raw://0.0.0.0:8080`、`ws://0.0.0.0:8443/?domain=x`、`kcp://0.0.0.0:9000?nodelay=1`），无 scheme 的 `host:port` 按 `raw` 解析（向后兼容 v1 的 `-l 8080`），`http://` 显式报错，未知 scheme 启动失败（v1 的静默回落是隐性故障源）。

### 4.4 v2 帧格式

```
STW2 frame —— 所有定长整数小端；变长长度用 LEB128 varint

  offset  field         类型
  0       version       u8    = 2
  1       flags         u8    bit0 SEALED / bit1 COMPRESSED(预留,默认关) / bit2 LAST / bit3 E2E
  2       msg_type      u16
  4       dest          [16]  目标节点 NodeId（定长，无 dest_len）
  20      via_count     varint  ≤ 8
  ..      via           via_count × [16]  中间跳 NodeId 列表
  ..      payload_len   varint  ≤ MAX_FRAME(1 MiB)
  ..      payload       [payload_len]
```

**相对 v1 的关键改动**

| 改动 | 原因 |
|---|---|
| 删 `Route` 冒号串 → `dest` + `via` | v1 每跳都要 `strings.Split`/`Join`，且 `TEMP_ROUTE` 是魔法串 |
| 删 `Len` 前缀 + reflect → postcard（非自描述） | v1 的 `<Name>Len` 反查依赖字段名，改名即破坏兼容 |
| `Sender`/`Accepter` 10B → `dest [16]` 定长 | 定长才能零拷贝解析；**不采用 varint 长度前缀**（旧方案的 `dest_len` 与 16 字节承诺自相矛盾） |
| 新增 `flags.SEALED` | 用显式位取代「靠 UUID 比较推断是否解密」的隐式规则 |
| 新增 `flags.LAST`（bit2） | 表达「会话最后一帧」，与 `SessionClose` 语义不重叠：`LAST` 是数据流尾标记，`SessionClose` 是会话终止（可发生在任一侧） |
| 新增 `flags.E2E`（bit3） | 双层密封标记（§4.5） |
| `SessionData` 携带 `seq: u64` | 支持乱序检测与滑动窗口重放拒绝 |
| 分片上限 64 KiB | 兼顾 MTU 与 KCP 的段重传成本；`MAX_FRAME` 1 MiB 是**逻辑帧**上限，超过即由帧层分片 |

**解析约束**：`payload_len <= MAX_FRAME`、`via_count <= 8`、`dest`/`via` 定长 16 → 任何越界返回 `Err` 而非 panic（缺陷 #1–#4）；帧头全部字节进入 AEAD 的 AAD（§4.5）。

### 4.5 握手与密码学

**3-flight 握手**（取代 v1 的「明文 token 双向对发」）

```
C → S  Hello       { magic "STW2", version, role=Client, transport_kind, tls_fp, client_eph_pub(32), client_nonce(32) }
S → C  HelloAck    { magic, version, role=Server, server_eph_pub(32), server_nonce(32), server_proof(32) }
C → S  AuthConfirm { client_proof(32), session_key_seed_ack(32) }
S → C  Ready       （隐含：AuthConfirm 校验通过后开始收帧）
```

- **transcript hash 由双方各自本地计算**（消除旧方案「客户端先发 `transcript_hash`」的循环定义）：
  `TH = SHA256("STW2-transcript" ‖ role_self ‖ role_peer ‖ version ‖ transport_kind ‖ tls_fingerprint ‖ client_eph_pub ‖ client_nonce ‖ server_eph_pub ‖ server_nonce)`。
  两侧入参顺序固定（按 role 排序而非按时间），因此**不依赖谁先发**。
- **为什么 3-flight**：2-flight 时服务端 proof 早于客户端 proof 发出，MITM 可自选 TH 做离线爆破；3-flight 让 `auth_key` 派生依赖**双方**输入，且客户端在发送 `AuthConfirm` 前已校验服务端 proof。
- **KDF**：`X25519(EphemeralSecret)` → `shared`；`PRK = HKDF-Extract(salt = client_nonce ‖ server_nonce, ikm = shared)`；
  `auth_key = HKDF-Expand(PRK, "auth", 32)`、`link_key = HKDF-Expand(PRK, "link", 32)`、`session_key_seed = HKDF-Expand(PRK, "session", 32)`。
- **认证**：`proof = HMAC-SHA256(auth_key, TH ‖ role)`，比较用 `subtle::ConstantTimeEq`；`secret` 参与 `auth_key` 派生（`HKDF-Expand(PRK, "auth" ‖ secret_digest, 32)`），因此错误 secret 必然校验失败。
- **帧密封**：`AES-256-GCM`，`nonce = iv(4B, 由 link_key 派生) ‖ counter(8B, 单调递增)`——**不用随机 12B nonce**（2³² 帧后碰撞概率不可忽略）；counter 从 0 开始，接收端维护 **1024 位滑动窗口**拒绝重放与回退；每 2²⁸ 帧**密钥轮换**（`link_key' = HKDF(link_key, "rekey" ‖ counter)`）并在下一帧的 `flags` 之外用专用 `Rekey` 控制帧通告。
- **AAD** = `version ‖ flags ‖ msg_type ‖ dest ‖ via_count ‖ via ‖ payload_len`（整帧头），防止头部篡改与降级。
- **双层密封**（修正「`chain_key` 逐跳却宣称端到端」的矛盾）：
  - **link 层（必做，逐跳）**：中间节点必须解开并重新密封（`flags.SEALED`），因为要做路由与限速；
  - **session 层（E2E）**：`flags.E2E` 置位时，payload 内再用**目标节点的静态 X25519 公钥**做 KEM 封装（`HKDF(X25519(ephemeral, target_static))` → `session_key`），中间节点只见密文。目标公钥来源：`Join`/`JoinAck` 时上报并由 admin 校验后广播（信任模型假设树内节点互不敌意，**跨 admin 桥接时退化为 link 层**，显式写进 §9 风险）。
- **secret 来源**：`-s` 支持 `env:NAME`、`file:/path`、`stdin:`；内部用 `zeroize::Zeroizing<[u8;32]>` 持有，进程启动后立即 `mlock`（unix）；日志中永不打印（v1 走 argv，`ps` 可见）。

### 4.6 消息集合（54 → 18）

按族分组（`#[repr(u16)]`，**只追加不复用**）：

| 族 | 消息 | 说明 |
|---|---|---|
| Link（5） | `Hello` / `HelloAck` / `AuthConfirm` / `Heartbeat` / `Shutdown` | 建链、保活（带 `send_ts`、`echo_ts` 用于 RTT）、全局关停 |
| Topology（5） | `Join` / `JoinAck` / `Rejoin` / `NodeStatus` / `Memo` | `Join{node}` 双重用途（取代 `CHILDUUIDREQ` 与 v1 `UUID` 查询）：`node == UNASSIGNED` 表示发送方自己入网申请编号；`node` 具体表示发送方**代子公告**（父节点是发送方）；`NodeStatus{scope: Node\|Upstream\|Child, state: Online\|Offline, node}` 统一 v1 的 4 条 offline/online 消息 |
| Session（4） | `OpenSession` / `SessionReady` / `SessionData` / `SessionClose` | `OpenSession{kind, direction, target, ...}` 双向可用；`SessionReady{code}` 承载成功/错误；`SessionData{seq, flags}`；`SessionClose{reason}` |
| Service（4） | `ServiceRequest` / `ServiceReply` / `ServiceData` / `ServiceExit` | 文件、shell、ssh、sshtunnel、connect 五类共用；`ServiceRequest{kind, phase: Probe\|Run, ...}` 保留 v1 的 `FORWARDTEST`/`BACKWARDTEST` 探测语义 |

**逐条映射**见附录 A（54 行，每行标注映射目标或合并去向）。

### 4.7 路由与派发

**派发规则（写死）**：

```
收到帧 →
  1. if dest == self && via.is_empty()      → 本地派发（解 session 层 → 交 Session/Service）
  2. if !via.is_empty()                     → 转发给 via[0]，via 左移一位，不改 payload
  3. else                                   → 查 route_cache[dest]（带 link epoch 的下一跳）
  4. 查不到                                 → 回 NodeStatus{scope: Node, state: Undeliverable}
```

- `route_cache` 由拓扑计算（admin 独占）与「本节点子链路表」共同填充；**每条链路建立/断开时 `epoch += 1` 并整体失效**，避免 v1 的口径漂移。
- 中间节点**不解 session 层**（E2E 时只见密文），只解 link 层做路由与限速。
- 不产生逐帧 topology 往返（对比 §2.9）：下一跳在会话建立时缓存到 `Session` 元数据里。
- **拓扑收敛的主动通告**：v2 帧没有 `sender` 字段（派发时的 `from` 只是链路对端），因此子节点新接入时必须由**父节点**立刻向上游发一条代子公告（`Join{node: <child>}`），逐跳上传到 admin。否则 admin 要等该子节点自己的心跳跨两跳到达才知道它存在，而那时也拿不到父子关系——这期间任何指向它的帧都会被判为不可达。公告只影响「登记谁」，父节点恒为链路对端，所以上游无法伪造 `node` 把别人的子树劫持到自己名下。
- **不可达不再静默**：v1 的 `route` 为空时直接丢弃；v2 必回 `NodeStatus{Undeliverable}` 供控制台与 `bisect` 使用。

### 4.8 会话模型

```rust
pub struct SessionKey { pub origin: NodeId, pub id: u64 }   // 复合键：修正单 u64 在多跳/桥接下的撞号
pub enum SessionKind { Socks5, Socks5Udp, Forward, Backward, File, ShellPty, Ssh, SshTunnel }
```

| 变更 | 原因 |
|---|---|
| `SessionKey{origin, id}` | v1 的 `Seq` 由发起方（SOCKS 是 admin、backward 是 agent）各自分配，`connect` 桥接两侧可能撞号 |
| `OpenSession` **双向可用** | 表达 v1 的 backward 反向发起（agent → admin）；v1 靠 `BACKWARDSEQ` 二次协商，v2 由 `origin` 消歧，一次 `OpenSession` 完成 |
| `Prepare` / `Commit` 两阶段 | 保留 `FORWARDTEST`/`BACKWARDTEST` 的探测语义，并消除 v1「先注册数据通道再发 START」的顺序耦合（源码注释提到的 DEAD LOCK 隐患） |
| `SessionReady{code}` | v1 用一个独立 `SOCKSREADY`/`FORWARDREADY`/`UDPASSRES` 表示成功，**无错误码**；v2 统一 `code: Ok\|Refused\|Timeout\|NotFound\|Denied` |
| `ShellPty` | v1 的 shell 无 PTY（`exec.Command("/bin/sh","-i")` + Pipe）；v2 用 `portable-pty` 支持 resize 与全屏程序 |
| `Socks5Udp` 独立 kind | v1 的 UDP 方向（agent 发起 `UDPASSSTART`）与 TCP 不同，需显式建模（修 F2） |

### 4.9 并发与背压

| 组件 | 职责 | 约束 |
|---|---|---|
| `TopologyActor` | 树结构、编号、路由计算 | 只持元数据（`NodeId`/`parent`/`children`/`epoch`），**不持 socket** |
| `LinkActor`（每链路 1 个） | 读帧 → 派发；写队列 → 串行写出 | 单写者；批量 flush（64 KiB 或 4 ms，取先到者） |
| `SessionActor`（每会话 1 个） | 会话状态机、窗口/信用、seq/ack | 有界通道 **32 帧**；满则对源端施加背压（`poll_read` 返回 `Pending`） |
| `ServiceActor`（每服务 1 个） | 文件/shell/ssh 的状态与进度 | 同上 |
| `ConsoleActor` | TUI 事件循环与命令 | 只经 channel 与世界交互，不直持 socket |

- **禁止**多个 task 直写同一 Link：所有写入经 `LinkActor` 的 `mpsc::Sender`，这是 v1 的核心竞态点（§2.9 第 3 条）。
- 帧缓冲用 `bytes::BytesMut` 池化复用，避免 v1 的「每帧两次分配 + 一次拷贝」。
- 定时器统一用 `tokio::time::Sleep` + `select!`，禁止「每会话起一个 tick 线程」。

### 4.10 控制台

`ratatui 0.30.2` + `crossterm 0.29.0`，两级面板（主面板 → 节点面板），替换 termbox + ansicon 两套实现。

**命令清单（22 条，F8 修正）**

| 面板 | 命令 |
|---|---|
| 主面板 | `use` / `detail` / `topo` / `help` / `exit` |
| 节点面板 | `status` / `addmemo` / `delmemo` / `shell` / `listen` / `connect` / `ssh` / `sshtunnel` / `socks` / `stopsocks` / `forward` / `stopforward` / `backward` / `stopbackward` / `upload` / `download` / `shutdown` / `help` / `back` / `exit` |

- `status` 需 refcount（同一节点上多个会话共存时，v1 的「计数」是裸 int）。
- **GBK（F6 修正）**：`-cs` 是 **agent 侧 shell** 的编解码（`agent/handler/shell.go:122` `ConvertGBK2Str`、`:138` `ConvertStr2GBK`），不是控制台输出转码。
- 非 TTY 环境（CI / 重定向）不可用 → 新增 `--non-interactive` 与 `--command <cmd>` 批处理模式（v1 没有，属**新增能力**）。

### 4.11 端口复用

| 项 | v2 |
|---|---|
| 后端 | **只保留 iptables**。删除旧方案的「nftables 优先」——nftables **没有 `-m string` / `-m recent` 的等价物**，二者非等价迁移 |
| magic | 改为 `--reuse-magic <16 字符>` 由**安装期随机生成**并写入节点配置；`HKDF(secret, ...)` 派生值仍是 secret 的函数，仍是离线爆破面 |
| 命令错误 | 检查退出码；失败即回滚已加规则并报错（修 #10）；提供 `--allow-degraded` 显式降级 |
| 平台 | Linux（iptables）、macOS/BSD（`pf` 不可等价 → 仅 SO_REUSEPORT）、**Windows 不支持端口复用**（`SO_REUSEADDR` 语义不同，遇 `SO_EXCLUSIVEADDRUSE` 时 `bind` 直接失败）→ 启动期显式报错 |
| TLS 下嗅探 | 用 `MSG_PEEK` 先读 8 字节判首字节，再决定是否包 TLS（修 F10）；非本协议流量回落 `127.0.0.1:<report>` |
| 回落代理 | 修 #12（`begin < 4` 负索引 + `Proxy-Authorization`） |

### 4.12 失败与恢复语义

| 事件 | v2 行为 |
|---|---|
| 上行断开 | 指数退避 **1s → 60s**（2×，带 ±20% 抖动）；`--reconnect <秒>` 显式给定则按固定间隔 |
| **默认是否重连** | **默认不重连**（保持 v1 CLI 语义：v1 只有显式 `--reconnect` 才重连）；旧方案的「默认也重连」与 §5.1 的兼容承诺冲突，已删除 |
| 子节点断开 | `NodeStatus{scope: Child, Offline}` 上报；admin 递归摘除子树，并在控制台标记为 `(stale)` 而非立即删除（保留 `history` 供重连复用编号） |
| admin 侧 peer 断开 | 不再「打印 + 等按键 + exit」；进入降级态并在 TUI 顶部显示 banner，`exit` 才退出（可 `--exit-on-peer-loss` 恢复 v1 行为） |
| 心跳 | 双向；`Heartbeat{send_ts}` 与回显 `echo_ts` 用于 RTT；**连续 3 个周期无回显即判死**（v1 的 agent 侧是空分支，只保活） |
| 全局关停 | `Shutdown{grace}` 广播，等 in-flight 会话 `SessionClose` 后退出 |

### 4.13 构建与发布

**blocking 矩阵 = 11 个 OS-ARCH 组合**（与 Go 版 Makefile 实测一致，F9）：

| OS | ARCH | agent | admin | 备注 |
|---|---|---|---|---|
| linux | x86_64 | ✅ | ✅ | `x86_64-unknown-linux-gnu`（musl 版列 best-effort） |
| linux | i686 | ✅ | ✅ | `i686-unknown-linux-gnu`，需 32 位链接器 |
| linux | aarch64 | ✅ | ✅ | |
| linux | arm（GOARM=5） | ✅ | ❌ | 对应 `armv5te-unknown-linux-musleabi`，**tier-3**：`-Z build-std` + nightly + 关 TLS/ws/kcp |
| linux | mipsle | ✅ | ❌ | `mipsel-unknown-linux-musl`，**tier-3**：同上 |
| darwin | x86_64 | ✅ | ✅ | |
| darwin | aarch64 | ✅ | ✅ | |
| windows | x86_64 | ✅ | ✅ | 另有 `windows-nogui-agent`（`-H=windowsgui`） |
| windows | i686 | ✅ | ✅ | |
| freebsd | i686 | ✅ | ✅ | CI 走 FreeBSD VM/qemu |
| freebsd | arm | ✅ | ✅ | |

**best-effort 档**（不阻塞发布）：`linux-x86_64-musl`、`linux-aarch64-musl`、`linux-armv7-unknown-linux-musleabihf`、`linux-riscv64gc`、`freebsd-x86_64`。

**不合入 blocking 清单的项**（纠正旧方案）：`freebsd/armv7`、`linux/armv7-gnu`、以及任何「全 target 静态 musl」的表述——Go 版 Makefile 中 **`musl` 出现 0 次**，是 glibc 动态链接。

**工具链**：`xtask build-matrix`（不是 cargo-dist：它无 FreeBSD runner、tier-3 无 std、i686-musl 缺 32 位链接器）。`xtask` 驱动 `cargo build`（host 可交叉的）、`cross`（musl/arm）、FreeBSD VM；产物命名与 Go 版对齐（`release/agent_linux_x64` 等）。

---

## 5. 功能取舍

### 5.1 必须保留（13 项）

| # | 能力 | 备注 |
|---|---|---|
| 1 | 树形多级网络（`listen`） | 级数不设硬上限，`--max-depth=8` 可调 |
| 2 | `connect` 跨 admin 桥接 | |
| 3 | SOCKS5 TCP CONNECT | RFC1928 |
| 4 | SOCKS5 UDP ASSOCIATE | RFC1928；**方向为 agent 发起**（F2） |
| 5 | SOCKS5/HTTP 上游代理链 | 修 #12 |
| 6 | forward 端口转发 | 含 `Prepare/Commit` 探测 |
| 7 | backward 反向映射 | 含 stop/stopdone |
| 8 | 文件上传/下载 | 修 #13 路径穿越 |
| 9 | 交互式 Shell | 升级为 PTY |
| 10 | SSH 命令执行 | 可配 known_hosts |
| 11 | SSH 隧道 | |
| 12 | 端口复用（iptables + SO_REUSEPORT） | Linux/BSD/macOS；Windows 明确不支持 |
| 13 | CLI 语义 | agent **15** flag：`-s -l -c -reconnect -rehost -report -socks5-proxy -socks5-proxyu -socks5-proxyp -http-proxy -up -down -cs -domain -tls-enable`；admin **11** flag：`-s -l -c -socks5-proxy -socks5-proxyu -socks5-proxyp -http-proxy -down -domain -tls-enable -heartbeat`（**`-heartbeat` 为 admin 独有**）。`-up`/`-down` 是**上行/子节点两条独立链路**的传输选择，admin 固定 `up=raw` |

### 5.2 重新设计（6 项）

| 旧 | 新 |
|---|---|
| 10 字节定长 UUID + `TEMP_UUID`/`ADMIN_UUID` 魔法串 | 16 字节 `NodeId` + `flags.SEALED` 显式语义 |
| 冒号串路由 | `dest` + `via` 结构化路由 + epoch 化 `route_cache` |
| reflect + `<Name>Len` 载荷 | postcard（显式 schema 演进规则） |
| 明文静态 token | 3-flight 握手 + HMAC 证明 + counter 重放防护 |
| 每帧新建 Message + `append` 拷贝 + 单 Conn 争写 | 零拷贝帧、会话缓存下一跳、单写队列 + 批量 flush（**注意：瓶颈不是「逐帧取路由」**，见 §2.9） |
| magic 由 `MD5(MD5(secret))` 派生 | `--reuse-magic` 安装期随机 |

### 5.3 删除（18 项）

| 项 | 原因 |
|---|---|
| `http` 伪协议 | 源码自称 deprecated |
| `WSMessage` 裸写 socket | 改真 RFC6455 分帧 |
| 「nftables 迁移」 | nftables 无 `-m string`/`-m recent` 等价物 |
| `TEMP_UUID`/`TEMP_ROUTE`/`ADMIN_UUID` | 被 `NodeId` + `flags` 取代 |
| `<Name>Len` 反射约定 | 被 postcard 取代 |
| `Debug` 残留 `print(...)` | 调试代码 |
| 9 种 Mode 的隐式组合 | 改 `clap::ArgGroup` 显式校验，不合法组合启动即报错 |
| `process_win.go` 重复分发器 | 平台无关代码统一 |
| termbox / ansicon | `ratatui` |
| `MD5` 全部用途 | 改 SHA-256/HKDF（`MD5(secret)[:16]` 已被 #7 判定为离线验证器） |
| `RSA-1024` 自签 | `P-256` + 私钥确定性派生（指纹绑 SPKI） |
| `InsecureSkipVerify = true` | 指纹校验 + TOFU |
| `math/rand` 随机串 | `rand::rngs::OsRng` |
| `utils.CheckRange` 冒泡 | 直接范围校验 |
| 每帧 gzip | 默认关闭（COMPRESSED 位预留），收益低于 CPU 成本 |
| 逐帧 `append` 拷贝 | `BytesMut` 池化 |
| Windows 双份 TUI / 双份分发器 | 单实现 + 平台抽象 |
| 「默认自动重连」 | 与 v1 CLI 语义冲突 |

### 5.4 推迟

| 项 | 理由 |
|---|---|
| KCP 传输（feature 默认关） | 抽象层先落地，传输后接（transport.md §8.1） |
| QUIC 传输 | 仅占位 |
| 流量整形 / 带宽限制 | 非核心 |
| 多 admin 联邦 | 超出 v1 能力 |
| 插件化服务 | 无需求 |

### 5.5 不做

| 项 | 理由 |
|---|---|
| 与 Go v1 线协议互通 | D1 |
| 域名前置 / CDN 隐身伪装 | §1.2 |
| 不可靠数据报语义 | §1.2 |
| 传输层多路复用 | §1.2 |
| 读取 v1 配置/持久化格式 | 见 5.6 |

### 5.6 v1 迁移

v2 **不读** v1 配置与持久化格式。迁移动作：重新生成 `--reuse-magic`、按 §6 的 CLI 映射重写启动脚本（`-s 123` 这类短 secret 需先升级，见 §6 注）、`-heartbeat` 保留语义但改为双向、`-cs` 语义不变（仍是 agent 侧 shell 编码）。

---

## 6. CLI 映射表

| Go flag | v2 | 行为变化 |
|---|---|---|
| `-s <secret>` | `--secret <s>`（或 `env:NAME` / `file:/p` / `stdin:`） | **breaking**：v1 走 argv，`ps` 可见；v2 建议非 argv 来源。长度下限默认 **8**（可 `--allow-weak-secret` 放宽以兼容 README 的 `-s 123`，但启动时打印警告） |
| `-l <port>` | `--listen <port>` / `--up raw://host:port` | 端口复用模式下语义不变 |
| `-c <addr>` | `--connect <addr>` | |
| `-reconnect <s>` | `--reconnect <s>` | 语义不变（默认不重连，§4.12） |
| `-rehost <host>` | `--reuse-host <host>` | |
| `-report <port>` | `--report <port>` | |
| `-socks5-proxy{u,p}` | `--socks5-proxy[-user|-pass]` | |
| `-http-proxy` | `--http-proxy` | 修 #12 的 `Proxy-Authorization` |
| `-up raw\|ws\|http` | `--up <spec>` | **breaking**：`http` 删除；无 scheme 视作 `raw`；未知 scheme 报错 |
| `-down raw\|ws\|http` | `--down <spec>` | 同上；`ws` 需 `?domain=`（缺省取 `-domain`，再缺省取 `-c` 的 host） |
| `-cs utf-8\|gbk` | `--cs utf-8\|gbk` | 语义不变（**agent 侧 shell** 编解码） |
| `-domain <d>` | `--domain <d>` | 同时用于 WS `Host` 与 TLS SNI |
| `-tls-enable` | `--tls` + `--tls-pin <hex>` / `--tls-tofu` | **breaking**：不再关闭载荷加密（修 #5）；默认校验指纹 |
| `-heartbeat`（admin） | `--heartbeat` / `--heartbeat-interval <s>` | 改为双向 + RTT + 判死（§4.12） |
| —（新增） | `--reuse-magic <16 字符>` | 端口复用 magic（§4.11） |
| —（新增） | `--download-dir <dir>`、`--socks-auth` | 修 #13 |
| —（新增） | `--non-interactive`、`--command <cmd>` | TUI 不可用环境（CI） |
| —（新增） | `--max-depth`、`--max-listeners`、`--allow-degraded`、`--allow-weak-secret`、`--exit-on-peer-loss` | §4.11/§5.1/§4.12 |

**Mode 判定**：v1 是「参数组合穷举式 if/else 链」，得到 9 种 `Mode` 常量（`NORMAL_ACTIVE`、`NORMAL_RECONNECT_ACTIVE`、`NORMAL_PASSIVE`、`SOCKS5_PROXY_ACTIVE`、`HTTP_PROXY_ACTIVE`、`SOCKS5_PROXY_RECONNECT_ACTIVE`、`HTTP_PROXY_RECONNECT_ACTIVE`、`SO_REUSE_PASSIVE`、`IPTABLES_REUSE_PASSIVE`），任何不匹配组合直接 `os.Exit(1)`。v2 用 `clap::ArgGroup` 表达为 6 组互斥/依赖约束，非法组合在参数解析期报错并指出冲突项。

---

## 7. 路线 P0–P7

| 阶段 | 交付物 | 出口判据（可验证） | 收尾 tag |
|---|---|---|---|
| **P0** | workspace + `rust-toolchain.toml` + CI 骨架 + `xtask check` / `xtask doccheck` + `docs/threat-model.md` | `cargo build --workspace` 通过；`cargo xtask check` 通过；空壳二进制 `--help` 可跑；CI 绿 | `p0-done` |
| **P1** | `stowaway-protocol` + `stowaway-crypto` | 帧编解码属性测试全绿；fuzz smoke 60s 无 panic；§4.5 握手 KAT（已知答案测试）通过 | `p1-done` |
| **P2** | `stowaway-transport`（raw/ws + TLS + 握手 + 嗅探）+ `tests/transport_conformance` | transport.md §7 的 T1–T9 在 raw 与 ws 上全绿；`--no-default-features --features transport-raw` 可编译 | `p2-done` |
| **P3** | `stowaway-core`：拓扑、路由、Session、Router | 三节点链路的 e2e 帧转发测试通过；`route_cache` epoch 失效有专门用例 | `p3-done` |
| **P4** | SOCKS5（TCP+UDP）、forward、backward、文件传输 | e2e 场景 1–6 通过 | `p4-done` |
| **P5** | Shell（PTY）、SSH、SSH 隧道、`connect` 桥接 | e2e 场景 7–9 通过 | `p5-done` |
| **P6** | admin TUI（22 命令）、`stowaway-agent`、构建矩阵 `xtask build-matrix` | TUI 在真实终端可用；**11 个 blocking 组合出包**（见 §4.13） | `p6-done` |
| **P7** | 联调、DoD | §8 全部硬性项通过；`--non-interactive` 冒烟 | `v0.1.0` |

---

## 8. 测试与 DoD

### 8.1 单元与属性测试（`proptest`）

帧 round-trip（任意合法帧编解码幂等）、非法输入不 panic（截断/超长/`via_count` 超限/`payload_len` 超限）、`nonce` 单调、**滑动窗口拒重放**（重放旧 counter 必须被拒）、路由粒子（任意 via 列表派发结果符合 §4.7）、`SessionKey` 消歧。

### 8.2 fuzz（`cargo-fuzz`）

目标：`FrameCodec::decode`、握手状态机、ws 升级解析（`Sec-WebSocket-Key`/路径）。**CI 策略**：PR 跑 **60 s smoke**、夜间 **1 h**、发版前 **24 h soak**（替换不可执行的「fuzz 24h 一律」）。

`fuzz/` 是独立的 fuzz workspace（不在主 workspace 内），三个 target：`decode_frame`、`decode_payload`、`handshake_transcript`。

**无 nightly 时的等价兜底**：`cargo-fuzz` 需要 nightly + `-Z sanitizer-coverage`，而本机 `/` 为只读挂载、`rustup` 装不了第二个 toolchain（§1.3）。因此 `crates/stowaway-protocol/tests/fuzz_smoke.rs` 提供**同一套语料与变异策略**的确定性版本：
- `fuzz_smoke_quick`（普通 `cargo test` 内跑，2 万次迭代，约 0.7 s）；
- `fuzz_smoke_soak`（`#[ignore]`，时长由 `STOWAWAY_FUZZ_SECONDS` 控制，默认 60 s）——这就是 PR/夜间档在本机的执行方式，已实测 60 s 内 19,819,776 次迭代无 panic。

两者的不变量一致：解码器对**任意字节**返回 `Result`，不 panic、不越界、不为长度字段做超量分配。

### 8.3 传输一致性套件

`tests/transport_conformance`，对每个启用的 `TransportKind` 跑 transport.md §7 的 T1–T9（小包/大流量/背压/双向并发/半关闭/对端 RST/1000 次建连断开/32 并发/`max_frame` 分片）。

### 8.4 Go 黑盒对照（`tests/interop`）

只对照**行为**：SOCKS5 语义（含 UDP ASSOCIATE 的**方向**：agent 发起）、文件切分与校验、shell 输出编码（GBK）、forward/backward 的探测时序。**不对照线格式**（D1）。运行方式：预编译 Go 二进制（由 `xtask fetch-go-baseline` 构建），场景脚本对比退出码与输出规约。

### 8.5 端到端场景（10 项）

1. 直连 SOCKS5 TCP 穿透；
2. 两级链路 SOCKS5 穿透；
3. forward 端口转发（含探测失败路径）；
4. backward 反向映射（含 stop）；
5. 文件上传/下载（含 `../` 拒绝）；
6. **UDP ASSOCIATE**（agent 发起方向）；
7. shell 交互 + PTY resize；
8. SSH 命令 + 隧道；
9. `connect` 跨 admin 桥接；
10. 端口复用回落（外部服务共存）。

附加：**跨传输混跑**（上行 `ws`、子链路 `kcp`）、TLS 降级必须失败（篡改 `transport_kind` 后握手应失败）。

### 8.6 DoD（硬性、机械可验）

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo xtask doccheck                      # docs/**/*.md 的 `path:LINE` 引用全部有效（P0 前用 scripts/doccheck.sh）
cargo xtask no-panic                     # crates/*/src 非测试代码不得有 unwrap/expect/panic/todo/unreachable，
                                         # 除非该行带 `// assert-ok` 注释说明为何恒不成立；必须 0 命中
cargo geiger --workspace                  # 协议/加密/传输三 crate 的 unsafe 计数为 0
```
`stowaway-protocol`、`stowaway-crypto`、`stowaway-transport` 顶部 `#![forbid(unsafe_code)]`。
`crates/*/src` 内的 `#[cfg(test)] mod tests` 与 `crates/*/tests/*.rs` 不受 `no-panic` 约束
（测试里断言失败本就该 panic）；`no-panic` 只扫每个源文件 `#[cfg(test)]` 之前的部分。

**§3 的 13 项缺陷各有一条回归测试**（测试名以 `defect_<n>_` 开头，`cargo test defect_` 可一次跑全）。

---

## 9. 风险与未决

### 9.1 风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| v2 与 v1 不互通导致无法渐进迁移 | 升级需全量切换 | 明确写入 §0；提供 `tests/interop` 行为对照证明能力未退化 |
| tier-3 目标（armv5te / mipsel）无 `target_has_atomic="64"`，`ring`/`aws-lc-rs` 不可用 | 这两平台无法出 TLS 包 | feature 门控：关 `tls`/`transport-ws`/`transport-kcp`，只留 `transport-raw`（§4.13） |
| `tokio_kcp 0.9.8` 自 2024-07 未更新，内部 `kcp 0.5.3` 与独立 `kcp 0.6.0` 非同源 | 后续需自维护 fork | KCP 默认关闭；接口隔离在 `transport/kcp` 单模块内 |
| UDP 受中间设备 QoS/限速影响 | KCP 在这些网络下反而更差 | 保留 raw/ws 为默认；KCP 需显式开启 |
| `ratatui` 在无 TTY 环境不可用 | 自动化测试受阻 | `--non-interactive` / `--command`（§4.10） |
| E2E session 层在 `connect` 桥接时退化为 link 层 | 「端到端机密性」在桥接场景不成立 | §4.5 显式声明；桥接时控制台提示 |
| SSH 用 `russh`，API 变动频繁 | 编译期破坏 | 锁小版本 + `xtask check` 门禁 |
| 端口复用依赖 root 与 iptables | 部署门槛 | `--allow-degraded` 显式降级并告警 |

### 9.2 未决（3 项）

1. **UUID 短显示格式**：`NodeId` 是 16 字节，TUI 显示用前 6 字节 hex 还是 base32？倾向 hex 前 8 字符 + 冲突时扩展。
2. **`--tls-pin` 格式**：`sha256:<hex>` 还是 `spki:<hex>`？倾向 `sha256:`（对证书 DER 取 SHA-256，实现最简单）。
3. **TUI 补全**：命令是否需 Tab 补全与历史（`crossterm` 无内建，需自写）。倾向 P6 内实现最简历史（上/下箭头）。

---

## 10. 开发流程与提交纪律（强制）

> 目标：任何时间点都能回答「这行代码为什么在这里」与「回到上周三的状态」。这是**可执行的工程约束**，不是建议。

### G1 提交粒度

一次提交 = 一个能一句话说明的逻辑单元，且**同时**满足：`cargo build` 通过、相关测试通过、`cargo fmt --check` 与 `cargo clippy --all-targets -- -D warnings` 无新增警告。禁止「大爆炸提交」（跨 3+ crate 且说不清）。

### G2 提交信息格式（Conventional Commits + 计划溯源）

```
<type>(<scope>): <一句话摘要，≤72 字符>

Why: <动机，必须能对上 plan.md 的章节或缺陷号>
Refs: plan §3#5 | §4.9 | P2
```

- `type` ∈ `feat|fix|refactor|test|docs|chore|perf|build|ci`；`scope` = crate 名（`protocol`/`crypto`/`transport`/`core`/`admin`/`agent`/`xtask`/`docs`）。
- **强制**：每个 `fix` 提交的 body 必须写 `Refs: plan §3#<n>`。若修的问题不在表里，**先加一行 §3 再修**（保持缺陷表是唯一事实源）。

### G3 阶段检查点（溯源）

每阶段收尾打 annotated tag `p<n>-done`，tag message 抄该阶段「出口判据」的实际完成情况；发版打 `v0.x.y`。恢复视图 = `git tag -l 'p*-done'` + `git log --graph --oneline --decorate`。

### G4 分支

trunk-based：`master` 任何时刻可构建可测。实验/破坏性改造走 `exp/<topic>`、热修走 `fix/<topic>`，合并用 `--no-ff` 保留边界；**禁止**对已被 tag 引用的提交 force-push。

### G5 频率下限（硬性）

1. 每个 crate 骨架落地即提交；
2. 公开 trait/类型先「定接口」提交一次、再「落实现」提交一次（便于 review 与 `bisect`）；
3. **每次会话结束不得留脏工作区**，必须提交到可构建状态；
4. 每次提交前跑 `cargo xtask check`（fmt + clippy + test 三合一，P0 起提供）；
5. 每完成一个 e2e 场景提交一次（`bisect` 的前提）。

### G6 禁止提交

`target/`、`release/`、`*.log`、`.env*`、`*.pem`/`*.key`/任何 secret、`fuzz/artifacts/`、`fuzz/corpus/` 中的大语料。**`Cargo.lock` 要提交**（二进制项目）。WIP 只能在 `exp/*` 且前缀 `wip:`，合并前 rebase 成正式提交。

### G7 恢复演练（两条路径）

- 回到上一里程碑：`git switch -c recover p2-done`。
- 撤销单个功能：`git revert <sha>`（**不用** `reset --hard`）。
- `git bisect` 的前提就是「每次提交可构建」——G1/G5 把它变成可验证承诺。

### G8 文档提交也门禁

`docs:` 提交跳过构建，但必须过文档引用校验（校验 `docs/**.md` 内所有 `path/to/file.go:LINE` 引用存在且该行非空）。**P0 之前用 `scripts/doccheck.sh`**（已落地，可执行）；P0 起迁移为 `cargo xtask doccheck`，两阶段行为一致。

### G9 `.gitignore`

在 `/target` 之外增补：`/release`、`*.profraw`、`*.log`、`.env*`、`*.pem`、`*.key`、`/fuzz/artifacts`、`/docs/private`。

### G10 CI 门禁

P0 起每 push 跑：`fmt --check` / `clippy --workspace --all-targets --all-features -- -D warnings` / `test --workspace --all-features` / `cargo deny check`（license + advisory）。PR 合并条件 = 全绿 + 至少一条关联测试 + 提交信息符合 G2。

---

## 11. 调查依据

| 结论 | 依据 | 方法 |
|---|---|---|
| 消息 54 个 | `protocol/protocol.go:12-67` | `awk` 抽出 const 块逐行计数（56 行含 `const (`/`)`，54 个名字） |
| 帧格式与 reflect 载荷 | `protocol/raw.go:32-94`、`:100-147`、`:149`、`:275`、`:297-319`、`:331-336` | 精读 + 交叉核对 |
| 条件解密 | `protocol/raw.go:155-159` | 精读 |
| GETROUTE 仅 6 处调用点 | `admin/handler/socks.go:259`、`listen.go:95`、`backward.go:69`、`heartbeat.go:21`、`admin/cli/interactive.go:532`、`interactive_win.go:544` | `grep -rn "GETROUTE"` 全仓（排除定义处） |
| TLS 缺陷 | `share/transport/tls.go:23`、`:113`、`:65-88` | 精读 + `grep -n "1024\|InsecureSkipVerify"` |
| 预认证 token | `share/preauth.go:15`、`:26` | 精读 |
| magic 派生 | `agent/initial/method.go:241-247` | `sed -n '235,285p'` 逐行核对切片下标 |
| iptables 规则与错误忽略 | `agent/initial/method.go` `SetPortReuseRules`/`DeletePortReuseRules` | 精读（`exec.Command(...).Run()` 返回值丢弃） |
| SO_REUSEPORT 回落 | `agent/initial/method.go:341-360`、`agent/handler/listen.go:491-510`、`agent/process/offline.go:199-218` | 精读 |
| TLS 下嗅探失效 | `agent/initial/method.go:330`、`:344-345` | 精读调用顺序（wrap 先于读 token） |
| UDP ASSOCIATE 方向 | `agent/handler/socks.go:454`、`:540-570`；`admin/handler/socks.go:259-330`、`:437-455` | 精读两侧构造点 |
| backward seq 协商 | `admin/handler/backward.go:69`、`agent/handler/backward.go`（`B_GETSEQCHAN`） | 精读 + 源码注释 |
| forward 顺序耦合 | `admin/handler/forward.go:124-132`（DEAD LOCK 注释）→ `:134` 的 `F_GETDATACHAN` | 精读注释 |
| 假 admin | `agent/handler/listen.go:151-171` | 精读（`//fake admin` 注释） |
| 心跳空分支 | `admin/handler/heartbeat.go:21`、`agent/process/process.go:171` | 精读 |
| 断线语义 | `agent/process/offline.go:23` 起 | 精读 |
| 行数 | `admin/handler` 1777、`admin/manager` 1072（5 文件）、`agent/handler` 2700、`agent/manager` 739（6 文件） | `find ... | xargs wc -l` 汇总 |
| 构建矩阵 11 组合 | Go 版 `Makefile` | 抽出 `GOOS/GOARCH` 去重（20 个产物目标） |
| socket 无 NODELAY/KeepAlive | 全仓 | `grep -rn "TCP_NODELAY\|SetNoDelay\|KeepAlive"` 零命中 |
| CLI flag 清单 | `agent/initial/parser.go`、`admin/initial/parser.go:54` | 逐 flag 核对（agent 15 / admin 11） |
| 控制台命令 | `admin/cli/interactive.go` | 逐 `case` 标签核对（主面板 5 / 节点面板 20） |
| 代理负索引 | `share/proxy.go:205` | 精读切片边界 |
| 文件落盘 | `share/file.go:148`、`:194` | 精读 |
| 依赖版本与 MSRV | crates.io 稀疏索引 + docs.rs | `curl https://index.crates.io/...` 读取 `rust-version`；`russh 0.65.2` = 1.89 为上限 |
| `x25519-dalek` `StaticSecret` 需 feature | docs.rs `x25519-dalek/3.0.0` | 文档标注 `Available on crate feature static_secrets only` |
| `tokio-tungstenite` 非 `AsyncRead` | docs.rs `tokio-tungstenite/0.30.0` | `WebSocketStream` 仅 `Stream`+`Sink` |
| `tokio_kcp` API 与陷阱 | docs.rs `tokio_kcp/0.9.8` | `KcpStream::connect` 只收 `SocketAddr` |

---

## 附录 A：Go v1 的 54 条消息 → v2 映射

| # | Go 常量 | v2 消息 | 说明 |
|---|---|---|---|
| 1 | `HI` | `Hello` + `HelloAck` | 拆分方向；携带 `version`/`role`/`transport_kind`/`tls_fp` |
| 2 | `UUID` | `JoinAck` | UUID 查询被并入 `Join`/`JoinAck` 的 `assigned_node` 字段 |
| 3 | `CHILDUUIDREQ` | `Join` | 子节点申请 `NodeId`（`Join.node = UNASSIGNED`）；父节点扮演 admin 时改写为「代子申请」；另有 `Join.node = <child>` 的**代子公告**用法，用于子节点接入瞬间让所有上游补齐拓扑 |
| 4 | `CHILDUUIDRES` | `JoinAck` | 分配结果 + 父节点 `NodeId` + 深度 |
| 5 | `MYINFO` | `Join`（`info` 字段） | 身份信息随 `Join` 上报（主机名/用户名/OS/架构），无独立消息 |
| 6 | `MYMEMO` | `Memo` | 保留（控制台 `addmemo`/`delmemo` 依赖） |
| 7 | `SHELLREQ` | `ServiceRequest{kind: Shell, phase: Run}` | 统一到 Service 族 |
| 8 | `SHELLRES` | `ServiceReply` | 含 `code`（v1 无错误码） |
| 9 | `SHELLCOMMAND` | `ServiceData` | shell 输入为数据帧 |
| 10 | `SHELLRESULT` | `ServiceData` | shell 输出为数据帧（GBK 转码在 agent 侧） |
| 11 | `SHELLEXIT` | `ServiceExit` | 退出码 + 原因 |
| 12 | `LISTENREQ` | `ServiceRequest{kind: Listen, phase: Run}` | 触发子监听 |
| 13 | `LISTENRES` | `ServiceReply` | 监听是否成功 + 实际端口 |
| 14 | `SSHREQ` | `ServiceRequest{kind: Ssh}` | 私钥 bytes 随请求传递（v1 行为保留） |
| 15 | `SSHRES` | `ServiceReply` | |
| 16 | `SSHCOMMAND` | `ServiceData` | |
| 17 | `SSHRESULT` | `ServiceData` | |
| 18 | `SSHEXIT` | `ServiceExit` | |
| 19 | `SSHTUNNELREQ` | `ServiceRequest{kind: SshTunnel}` | |
| 20 | `SSHTUNNELRES` | `ServiceReply` | |
| 21 | `FILESTATREQ` | `ServiceRequest{kind: FileUpload, phase: Probe}` | 探测文件大小/分片数 |
| 22 | `FILESTATRES` | `ServiceReply` | |
| 23 | `FILEDATA` | `ServiceData` | 分片 30720 → v2 64 KiB |
| 24 | `FILEERR` | `ServiceExit{err}` | 错误改由统一的 exit reason 表达 |
| 25 | `FILEDOWNREQ` | `ServiceRequest{kind: FileDownload}` | |
| 26 | `FILEDOWNRES` | `ServiceReply` | |
| 27 | `SOCKSSTART` | `OpenSession{kind: Socks5, direction: Down}` | admin 发起 → agent 拨号 |
| 28 | `SOCKSTCPDATA` | `SessionData` | 带 `seq` |
| 29 | `SOCKSUDPDATA` | `SessionData`（`kind: Socks5Udp`） | 数据报边界由会话层编码 |
| 30 | `UDPASSSTART` | `OpenSession{kind: Socks5Udp, direction: Up}` | **agent 发起**（F2） |
| 31 | `UDPASSRES` | `SessionReady` | 携带绑定地址 |
| 32 | `SOCKSTCPFIN` | `SessionClose{reason: Eof}` | 半关闭用 `flags.LAST` 表示，不用此消息 |
| 33 | `SOCKSREADY` | `SessionReady{code: Ok}` | v1 无错误码 |
| 34 | `FORWARDTEST` | `ServiceRequest{kind: Forward, phase: Probe}` | 保留探测语义（§4.8 两阶段） |
| 35 | `FORWARDSTART` | `OpenSession{kind: Forward}` | Commit 阶段才发 |
| 36 | `FORWARDREADY` | `SessionReady` | |
| 37 | `FORWARDDATA` | `SessionData` | |
| 38 | `FORWARDFIN` | `SessionClose` | |
| 39 | `BACKWARDTEST` | `ServiceRequest{kind: Backward, phase: Probe}` | |
| 40 | `BACKWARDSTART` | `OpenSession{kind: Backward, direction: Up}` | 反向发起，`origin` 区分 |
| 41 | `BACKWARDSEQ` | `OpenSession`（`id` 协商字段） | 由 `SessionKey{origin,id}` 消歧，不再二次协商 |
| 42 | `BACKWARDREADY` | `SessionReady` | |
| 43 | `BACKWARDDATA` | `SessionData` | |
| 44 | `BACKWARDFIN` | `SessionClose` | |
| 45 | `BACKWARDSTOP` | `SessionClose{reason: Stopped}` | 停止请求 |
| 46 | `BACKWARDSTOPDONE` | `SessionClose`（ack 变体） | `reason: Stopped` + `flags.ACK`（`flags` 预留位） |
| 47 | `CONNECTSTART` | `ServiceRequest{kind: Connect}` | 跨 admin 桥接 |
| 48 | `CONNECTDONE` | `ServiceReply` | |
| 49 | `NODEOFFLINE` | `NodeStatus{scope: Node, state: Offline}` | v1 的 4 条离线消息统一 |
| 50 | `NODEREONLINE` | `NodeStatus{scope: Node, state: Online}` | 携带新 IP |
| 51 | `UPSTREAMOFFLINE` | `NodeStatus{scope: Upstream, state: Offline}` | |
| 52 | `UPSTREAMREONLINE` | `NodeStatus{scope: Upstream, state: Online}` | |
| 53 | `SHUTDOWN` | `Shutdown` | 增加 `grace` 与原因 |
| 54 | `HEARTBEAT` | `Heartbeat` | 增加 `send_ts`/`echo_ts`/`seq`，用于 RTT 与判死 |