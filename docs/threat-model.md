# 威胁模型（v2）

> 适用范围：`rs-away`（Rust 重写版）v2 线协议与运行期行为。基线对照：Go 版 Stowaway HEAD `7f715be`。
> 本文件是 `docs/plan.md` §9 的展开；**§3 缺陷表仍是缺陷的唯一事实源**，本文只描述「威胁 → 假设 → 对策 → 残余风险」。
> 维护规则：任何新增攻击面（新传输、新服务类型、新持久化）必须在本文件加一节，并在 `docs/plan.md` §9.1 增补风险行。

---

## 1. 资产

| 资产 | 位置 | 机密性要求 | 完整性要求 | 可用性要求 |
|---|---|---|---|---|
| 共享 secret | 启动参数 / `env:` / `file:` / `stdin:` | **极高**（泄露 = 全网可加入） | 极高 | 高 |
| `auth_key` / `link_key` / `session_key_seed` | 内存（`Zeroizing`） | 极高 | 极高 | — |
| 节点对静态 X25519 私钥 | 内存 | 极高 | — | — |
| 会话载荷（用户真实流量） | 帧 payload | **高**（端到端） | 高 | 高 |
| 拓扑结构与节点元数据 | TopologyActor | 中（暴露网络结构） | 高 | 高 |
| Shell / SSH 凭据 | `ServiceRequest` | 高 | 高 | — |
| 本地文件系统 | `--download-dir` | 高 | **极高**（防穿越） | — |
| 端口复用 iptables 规则 | 内核 | 低 | **高**（半配置即故障） | 中 |

---

## 2. 攻击者模型

| # | 攻击者 | 能力 | 动机 |
|---|---|---|---|
| A1 | 被动网络监听者 | 可读全部字节，不可改 | 取证、流量分析 |
| A2 | 主动中间人（MITM） | 可改、可插、可重放、可降级 | 拦截或注入 |
| A3 | 未授权接入者 | 知道服务地址与协议格式，**不知道 secret** | 蹭网、横向移动 |
| A4 | 已授权但恶意节点 | 持有 secret，能正常入网 | 观测他人流量、伪造拓扑 |
| A5 | 本地低权用户 | 可读同机 `ps`/`/proc`、可读工作目录 | 提权、窃取 secret |
| A6 | 恶意 SOCKS/HTTP 客户端 | 能向 admin 端口发起任意字节 | 触发 panic、路径穿越 |

**不在模型内**：能读取进程内存的 root/内核级对手；供应链投毒（由 `cargo deny` + 审计部分覆盖）；物理侧信道。

---

## 3. 威胁与对策

### T-1 secret 泄露（对应缺陷 #7、A1/A5）

- **v1 现状**：`secret` 走 argv（`ps` 可见）；预认证 token `= MD5(secret)[:16]` 明文双向发送，抓包即可离线字典暴破。
- **v2 对策**：`--secret` 支持 `env:NAME` / `file:/path` / `stdin:`；内部 `Zeroizing<[u8;32]>` + unix `mlock`；日志与错误信息永不打印 secret 或其派生值；`auth_key` 派生时 secret 参与 HKDF（`"auth" ‖ secret_digest`），**错误 secret 必然握手失败**且不泄露「接近正确」的信息。
- **残余**：argv 传入仍可见（显式告警）；`/proc/<pid>/environ` 对同 uid 可读（unix 语义，无法在应用层解决）。
- **回归测试**：`defect_7_`。

### T-2 握手降级与跨传输重放（A2）

- **v1 现状**：无版本协商，token 静态可重放。
- **v2 对策**：3-flight 握手；`TH = SHA256("STW2-transcript" ‖ role_self ‖ role_peer ‖ version ‖ transport_kind ‖ tls_fingerprint ‖ client_eph_pub ‖ client_nonce ‖ server_eph_pub ‖ server_nonce)`；`transport_kind` 与 `tls_fingerprint` **一起进 TH**，因此把 `ws+TLS` 降级成 `raw` 明文会改变 TH → proof 校验失败。`auth_key` 依赖双方 ephemeral 公钥，故离线爆破必须同时猜 secret 与解决一次 X25519。
- **残余**：secret 太短（`--allow-weak-secret`）时被动监听者仍可离线暴破；文档明确该开关不安全。
- **回归测试**：篡改 `transport_kind` 后握手必须失败（§8.5 附加场景）。

### T-3 帧重放与乱序（A1/A2）

- **v1 现状**：AES-GCM 用 12 字节随机 nonce，无 counter、无窗口；重放整帧可被接受。
- **v2 对策**：`nonce = iv(4B, 由 link_key 派生) ‖ counter(8B)`；接收端 1024 位滑动窗口拒重放与回退；整帧头进 AEAD AAD（改 `dest`/`via`/`flags` 即认证失败）；每 2²⁸ 帧 rekey。
- **残余**：窗口外的**极旧**帧被拒而非报错；链路中断后 counter 归零依赖新 `link_key`（每次握手都是新 key）。
- **回归测试**：重放旧 counter 必须被拒。

### T-4 端到端机密性在桥接场景退化（A4）

- **v1 现状**：条件解密（`Accepter == self` 才解）使得中间节点本可只看密文，但 `chain_key` 逐跳不同导致「宣称端到端」不成立。
- **v2 对策**：**双层密封**——link 层必做逐跳（路由需要），session 层 E2E 用目标静态 X25519 公钥 KEM 封装。
- **残余（登记为已知风险）**：`connect` 跨 admin 桥接时，目标节点公钥未经跨域信任锚校验，退化为 link 层加密；控制台必须提示该会话「非端到端」。恶意中间节点（A4）仍可观测量级、时序与目标地址。
- **回归测试**：`flags.E2E` 置位时中间节点解不出 payload。

### T-5 协议解析崩溃 / DoS（对应缺陷 #1–#4、#8、#9，A6）

- **v1 现状**：未知 `MessageType` → nil `reflect` panic；`DataLen` u64 无上限 → `make([]byte, huge)`；长度直接进切片 → 越界 panic；GCM 失败被忽略 → 空 buffer → 越界；gzip 失败静默返回空。
- **v2 对策**：`msg_type` 用 `#[repr(u16)]` 封闭枚举，未知值 `Err`；`payload_len <= MAX_FRAME`（1 MiB）、`via_count <= 8`、`dest`/`via` 定长 16；解码全程 `checked_add` + 剩余长度校验；密封/解压失败一律 `Err` 并断链。`stowaway-protocol` 顶部 `#![forbid(unsafe_code)]` 且 `unwrap()`/`expect()` 在 DoD 中 grep 为空。
- **残余**：解压后膨胀（zip bomb）——`COMPRESSED` 位 v2 默认关闭，启用时必须有解压上限。
- **回归测试**：`defect_1_`–`defect_4_`、`defect_8_`、`defect_9_`；fuzz `FrameCodec::decode` 60s/1h/24h。

### T-6 TLS 降级与不可信证书（对应缺陷 #5、#6，A2）

- **v1 现状**：`--tls-enable` 时 `Secret = ""`（**载荷加密被关闭**）；客户端 `InsecureSkipVerify = true`；RSA-1024 自签、每次重启换指纹。
- **v2 对策**：帧层密封与 TLS 解耦（关 TLS 不影响载荷加密）；证书私钥由 `HKDF(secret,"tls-cert-key")` **确定性派生**（同 secret 恒同公钥/SPKI，指纹对 SPKI 取哈希故重启不变；证书 DER 因签名随机化可变但不影响 pin）；客户端默认校验指纹（`--tls-pin sha256:<hex>` 或 `<download>/known_hosts` 式 TOFU 持久化）。
- **残余**：TOFU 首次连接无法防 MITM（与 SSH 同性质）；`--tls-pin` 未配置且无 known_hosts 时必须显式 `--tls-tofu` 才降级。
- **回归测试**：`defect_5_`、`defect_6_`；`--tls` 下 payload 仍被密封（`flags.SEALED` 恒为 1）。

### T-7 路径穿越与任意写（对应缺陷 #13，A6）

- **v1 现状**：`os.Create(file.FileName)` 直接用客户端文件名。
- **v2 对策**：文件名先取 `basename`，再 `canonicalize` 后在 `--download-dir` 内前缀校验；拒绝 `..`、绝对路径、符号链接逃逸；`--download-dir` 缺省为当前目录且启动时打印绝对路径。
- **残余**：目录内合法文件名可覆盖同名文件（v1 行为保留，属产品语义）。
- **回归测试**：`defect_13_`；e2e 场景 5 含 `../` 拒绝。

### T-8 端口复用的规则劫持面（对应缺陷 #10，A5）

- **v1 现状**：iptables magic 由 `MD5(MD5(secret))` 派生（secret 的函数，可离线暴破）；命令错误被忽略 → 防火墙半配置。
- **v2 对策**：`--reuse-magic <16 字符>` **安装期随机**生成；命令执行检查退出码，失败即回滚已加规则并报错（`--allow-degraded` 才降级）；**Windows 不支持**端口复用。
- **残余**：magic 明文出现在进程 argv 与 iptables 规则里，本机 root 可读；属于「本机已失陷」范畴。
- **回归测试**：`defect_10_`。

### T-9 恶意已授权节点（A4）

- **现状**：树内节点互不敌意是**显式假设**（`docs/plan.md` §4.5）。
- **v2 对策**：链路级 AEAD 阻止伪造帧；`Join`/`JoinAck` 由 admin 校验后广播拓扑；admin 侧限速与 `--max-depth`/`--max-listeners` 限制资源。
- **残余**：已授权节点可见其**直连**上下级的元数据（地址、会话计数），并可对自身子节点做流量分析。要消除需引入节点间证书体系（**v2 不做**，登记为风险）。

### T-10 资源耗尽（A3/A6）

- **v2 对策**：`via_count <= 8`、`MAX_FRAME` 1 MiB、`--max-listeners` 限制并发子链路、SessionActor 有界 32 帧（满则向上游施加背压）、`--max-depth` 限制树深。
- **残余**：未做 per-IP 连接速率限制（v1 亦无）；依赖部署侧（防火墙/反代）承担。

---

## 4. 与 v1 的缺陷对照

| §3 缺陷 | 本文件章节 |
|---|---|
| #1 #2 #3 #4 #8 #9 | T-5 |
| #5 #6 | T-6 |
| #7 | T-1 |
| #10 | T-8 |
| #11（性能，非安全） | —（见 plan §2.9） |
| #12（代理负索引） | T-5 的同类解析加固；由 `defect_12_` 单独覆盖 |
| #13 | T-7 |

---

## 5. 部署侧建议（不在代码内强制）

1. `--secret` 用 `file:` 或 `stdin:`，不要用 argv。
2. 生产环境开 `--tls` 且配置 `--tls-pin`，不要把 `--tls-tofu` 当默认。
3. 端口复用需 root；非必要时用 SO_REUSEPORT 回落，并把 `--report` 指向真实回落后端。
4. admin 监听口不要直接暴露公网；`ws` 走反代时由反代承担 TLS 终止与访问控制。
5. 定期轮换 secret（v2 无在线轮换，轮换即全量重启）。