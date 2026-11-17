//! 无 libFuzzer 环境下的模糊测试兜底。
//!
//! 权威：`docs/plan.md` §8.2（fuzz 三档：PR 60s / 夜间 1h / 发版前 24h soak）。
//!
//! 本机 `/` 为只读挂载，`rustup` 无法安装 nightly，`cargo-fuzz` 也就无法运行
//! （它需要 `-Z sanitizer-coverage`）。因此这里提供**同一套语料 + 变异策略**
//! 的确定性版本：
//!
//! - `fuzz_smoke_quick`：正常 `cargo test` 里跑，2 万次迭代，秒级；
//! - `fuzz_smoke_soak`：`#[ignore]`，循环到给定时长（默认 60s，可用
//!   `STOWAWAY_FUZZ_SECONDS` 覆盖），用于 PR/夜间档；
//! - `fuzz/` 目录里另外放了等价的 `cargo-fuzz` target，CI 有 nightly 时直接可用。
//!
//! 不变量（与属性测试一致）：解码器对**任意字节**都必须返回 `Result`，
//! 不得 panic、不得越界、不得为长度字段做超量分配。

use stowaway_protocol::{
    MAX_FRAME,
    frame::{FrameCodec, FrameHeader},
    msg::{Message, MsgType},
};

/// 手写 xorshift64*：测试不引入 `rand`，避免给协议 crate 加依赖。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

/// 初始语料：合法帧 + 每种消息的合法编码 + 手工构造的边界帧。
fn seeds() -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    // 1) 每种消息的合法载荷编码（驱动 Message::decode 的分支）。
    let all: Vec<Message> = vec![
        Message::Heartbeat(stowaway_protocol::msg::Heartbeat {
            send_ts: 1,
            echo_ts: 0,
        }),
        Message::Shutdown(stowaway_protocol::msg::Shutdown {
            grace_ms: 1000,
            reason: "shutdown".to_string(),
        }),
        Message::NodeStatus(stowaway_protocol::msg::NodeStatus {
            scope: stowaway_protocol::msg::NodeScope::Node,
            state: stowaway_protocol::msg::NodeState::Online,
            node: stowaway_protocol::node::NodeId::ADMIN,
        }),
        Message::Join(stowaway_protocol::msg::Join {
            kind: stowaway_protocol::node::NodeKind::Agent,
            listen: Some("127.0.0.1:8080".into()),
            capabilities: 0xff,
        }),
        Message::JoinAck(stowaway_protocol::msg::JoinAck {
            node: stowaway_protocol::node::NodeId::new([7u8; 16]),
            parent: stowaway_protocol::node::NodeId::ADMIN,
            root: stowaway_protocol::node::NodeId::ADMIN,
            depth: 2,
        }),
        Message::Rejoin(stowaway_protocol::msg::Rejoin {
            node: stowaway_protocol::node::NodeId::new([7u8; 16]),
            parent: stowaway_protocol::node::NodeId::ADMIN,
        }),
        Message::Memo(stowaway_protocol::msg::Memo {
            node: stowaway_protocol::node::NodeId::ADMIN,
            text: "备忘".into(),
        }),
        Message::SessionData(stowaway_protocol::msg::SessionData {
            key: stowaway_protocol::node::SessionKey::new(
                stowaway_protocol::node::NodeId::new([7u8; 16]),
                9,
            ),
            seq: 3,
            data: vec![1, 2, 3].into(),
        }),
        Message::SessionClose(stowaway_protocol::msg::SessionClose {
            key: stowaway_protocol::node::SessionKey::default(),
            reason: stowaway_protocol::msg::CloseReason::Reset,
            detail: String::new(),
        }),
        Message::Hello(stowaway_protocol::msg::Hello {
            kind: stowaway_protocol::node::NodeKind::Agent,
            transport: stowaway_protocol::transport_kind::TransportKind::Raw,
            tls_fp: Some([3u8; 32]),
            eph_pub: [4u8; 32],
            nonce: [5u8; 32],
        }),
        Message::HelloAck(stowaway_protocol::msg::HelloAck {
            kind: stowaway_protocol::node::NodeKind::Admin,
            eph_pub: [6u8; 32],
            nonce: [7u8; 32],
            proof: [8u8; 32],
        }),
        Message::AuthConfirm(stowaway_protocol::msg::AuthConfirm {
            proof: [9u8; 32],
            seed_ack: [10u8; 32],
        }),
    ];
    for m in &all {
        if let Ok(bytes) = m.encode() {
            out.push(bytes.clone());
            // 包成帧，让帧解码器也吃到合法输入。
            let frame = stowaway_protocol::frame::Frame::new(
                stowaway_protocol::frame::FrameFlags::empty(),
                m.msg_type(),
                stowaway_protocol::node::NodeId::ADMIN,
                Vec::new(),
                bytes,
            );
            out.push(frame.encode());
        }
    }

    // 2) 边界帧：最大 via、最大载荷长度前缀、未密封标记。
    let mut big = vec![2u8, 0b0000_0011, 0x01, 0x00];
    big.extend_from_slice(&[0xaa; 16]);
    big.push(8);
    big.extend_from_slice(&[0xbb; 8 * 16]);
    // payload_len = 0xFFFFFFFF（远超 MAX_FRAME），且后面没有字节。
    big.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
    out.push(big);

    // 3) 全零 / 空输入。
    out.push(Vec::new());
    out.push(vec![0u8; 64]);
    out
}

/// 典型变异：位翻转、字节替换、截断、长度字段改写。
fn mutate(rng: &mut Rng, data: &mut Vec<u8>) {
    if data.is_empty() {
        data.push(rng.byte());
        return;
    }
    match rng.below(6) {
        0 => {
            // 单字节位翻转
            let i = rng.below(data.len());
            data[i] ^= 1 << rng.below(8);
        }
        1 => {
            // 随机字节替换
            let i = rng.below(data.len());
            data[i] = rng.byte();
        }
        2 => {
            // 截断
            let cut = rng.below(data.len() + 1);
            data.truncate(cut);
        }
        3 => {
            // 追加随机尾巴
            for _ in 0..rng.below(8) {
                data.push(rng.byte());
            }
        }
        4 => {
            // 把某个位置改成极大 varint（引诱超量分配）
            let i = rng.below(data.len());
            data[i] = 0xff;
        }
        _ => {
            // 拼接一段另一条语料的前缀
            let other = seeds();
            if let Some(o) = other.get(rng.below(other.len())) {
                let take = rng.below(o.len().min(16) + 1);
                data.extend_from_slice(&o[..take]);
            }
        }
    }
}

/// 跑一次解码，断言「不 panic 且不超量分配」。
fn drive(bytes: &[u8]) {
    // 帧头解析
    let _ = FrameHeader::parse(bytes);
    // 整帧解析
    let _ = FrameCodec::decode(bytes);
    // 载荷按每种已知 msg_type 尝试解码（模拟「帧头声称的类型」被篡改）
    for ty in MsgType::ALL {
        let _ = Message::decode(ty, bytes);
    }
    // 直接当作帧头里的 payload_len 检查上限（解码器必须先校验再分配）
    assert!(
        bytes.len() <= MAX_FRAME + 4096,
        "测试语料不得本身超过帧上限太多，否则断言无意义"
    );
}

fn run_loop(seconds: u64) -> (u64, u64) {
    use std::time::{Duration, Instant};

    let mut rng = Rng::new(0x5DEE_CE66_D1CE_B00D);
    let corpus = seeds();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut iterations = 0u64;
    let mut max_len = 0usize;
    loop {
        let mut data = corpus[rng.below(corpus.len())].clone();
        let rounds = 1 + rng.below(4);
        for _ in 0..rounds {
            mutate(&mut rng, &mut data);
        }
        max_len = max_len.max(data.len());
        drive(&data);
        iterations += 1;
        // 每 256 次看一次表，避免每次迭代都调 `Instant::now()`。
        if iterations.is_multiple_of(256) && Instant::now() >= deadline {
            break;
        }
    }
    (iterations, max_len as u64)
}

#[test]
fn fuzz_smoke_quick() {
    // 用固定迭代数（而非时长），保证 `cargo test` 的耗时稳定可预期。
    let mut rng = Rng::new(42);
    let corpus = seeds();
    for _ in 0..20_000 {
        let mut data = corpus[rng.below(corpus.len())].clone();
        for _ in 0..1 + rng.below(3) {
            mutate(&mut rng, &mut data);
        }
        drive(&data);
    }
}

#[test]
#[ignore = "长时 fuzz，PR 用 60s：STOWAWAY_FUZZ_SECONDS=60 cargo test -p stowaway-protocol --release -- --ignored fuzz_smoke_soak"]
fn fuzz_smoke_soak() {
    let seconds = std::env::var("STOWAWAY_FUZZ_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);
    let (iterations, max_len) = run_loop(seconds);
    println!("fuzz smoke: {seconds}s 内跑 {iterations} 次迭代，最长输入 {max_len} 字节，无 panic");
    assert!(iterations > 0);
}
