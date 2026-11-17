//! link 层密封：`AES-256-GCM` + `iv‖counter` nonce + 1024 位滑动窗口 + rekey。
//!
//! 权威：`docs/plan.md` §4.5「帧密封」。相对 v1 的三处改正：
//!
//! 1. v1 每帧都用**随机 12 字节 nonce** 且不做重放检查（`crypto/aes.go`），
//!    在 2³² 帧后碰撞概率不可忽略，且整帧可被重放；
//! 2. v1 把帧头留在明文、只加密 payload，头部可被任意篡改（改 `Accepter`
//!    就能改变解密分支）；
//! 3. v1 没有密钥轮换。
//!
//! v2 的做法：
//! - `nonce = iv(4B, 由 link_key 派生) ‖ counter(8B, 单调递增)`；
//! - **AAD = 整帧头**（版本/flags/类型/dest/via/payload_len）；
//! - 接收端维护 1024 位滑动窗口，拒绝重放与过度回退；
//! - 每 `REKEY_INTERVAL`（2²⁸）帧按 `HKDF(link_key, "rekey"‖counter)` 换钥。

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroizing;

use crate::kdf::rekey;
use crate::{KEY_LEN, REKEY_INTERVAL, REPLAY_WINDOW_BITS};

/// 密封层错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealerError {
    /// AEAD 校验失败（密文/头部被改，或密钥不匹配）。
    #[error("帧认证失败：密文或头部被篡改")]
    AuthFailed,
    /// 计数器小于窗口下界，视为重放。
    #[error("帧重放：counter={counter} 已被处理或过于陈旧（窗口下界 {floor}）")]
    Replayed {
        /// 收到的计数器。
        counter: u64,
        /// 当前窗口下界。
        floor: u64,
    },
    /// 同一计数器重复出现。
    #[error("帧重复：counter={counter} 已在窗口内")]
    Duplicate {
        /// 重复的计数器。
        counter: u64,
    },
    /// 计数器溢出（正常流程先触发 rekey）。
    #[error("帧计数器溢出")]
    CounterExhausted,
    /// nonce 长度非法（内部不变量）。
    #[error("nonce 长度非法")]
    BadNonce,
}

/// 1024 位滑动窗口（按计数器判断重放）。
///
/// 用 16 个 `u64` 字表示最近 1024 个计数器；`highest` 是已见过的最大值。
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    /// 已见过的最大计数器（`None` 表示还没收到过任何帧）。
    highest: Option<u64>,
    /// 位图：bit 0 对应 `highest`，bit k 对应 `highest - k`。
    bits: [u64; REPLAY_WINDOW_BITS / 64],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// 空窗口。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            bits: [0u64; REPLAY_WINDOW_BITS / 64],
        }
    }

    /// 已见过的最大计数器。
    #[must_use]
    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// 窗口下界（小于它的计数器一律视为重放）。
    #[must_use]
    pub fn floor(&self) -> u64 {
        match self.highest {
            None => 0,
            Some(h) => h.saturating_sub(REPLAY_WINDOW_BITS as u64 - 1),
        }
    }

    /// 检查并标记一个计数器。成功表示「首次见到且未过期」。
    pub fn accept(&mut self, counter: u64) -> Result<(), SealerError> {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            self.set_bit(0);
            return Ok(());
        };

        if counter > highest {
            let shift = counter - highest;
            self.shift_left(shift);
            self.highest = Some(counter);
            self.set_bit(0);
            return Ok(());
        }

        let delta = highest - counter;
        if delta >= REPLAY_WINDOW_BITS as u64 {
            return Err(SealerError::Replayed {
                counter,
                floor: self.floor(),
            });
        }
        if self.get_bit(delta) {
            return Err(SealerError::Duplicate { counter });
        }
        self.set_bit(delta);
        Ok(())
    }

    fn set_bit(&mut self, idx: u64) {
        let word = (idx / 64) as usize;
        let bit = idx % 64;
        self.bits[word] |= 1u64 << bit;
    }

    fn get_bit(&self, idx: u64) -> bool {
        let word = (idx / 64) as usize;
        let bit = idx % 64;
        self.bits[word] & (1u64 << bit) != 0
    }

    /// 窗口右移 `shift` 位（`highest` 变大时）。
    fn shift_left(&mut self, shift: u64) {
        if shift >= REPLAY_WINDOW_BITS as u64 {
            self.bits = [0u64; REPLAY_WINDOW_BITS / 64];
            return;
        }
        let words = (shift / 64) as usize;
        let bits = (shift % 64) as u32;
        if words > 0 {
            self.bits.copy_within(words.., 0);
            for w in self.bits.iter_mut().skip(REPLAY_WINDOW_BITS / 64 - words) {
                *w = 0;
            }
        }
        if bits > 0 {
            let n = self.bits.len();
            for i in (1..n).rev() {
                self.bits[i] = (self.bits[i] << bits) | (self.bits[i - 1] >> (64 - bits));
            }
            self.bits[0] <<= bits;
        }
    }
}

/// 单帧允许跨越的最大 rekey 代数（防伪造大 counter 造成 HKDF DoS）。
pub const MAX_REKEY_JUMP: u64 = 4;

/// 逐跳密封器（一条链路上的发送/接收方向）。
///
/// 发送与接收用**同一个** `link_key`，但各自的计数器独立递增；
/// `iv` 由 `link_key` 派生并偏向方向（避免双向 nonce 复用）。
#[derive(Debug)]
pub struct LinkSealer {
    /// 发送方向密码器。
    send: Aes256Gcm,
    /// 接收方向密码器。
    recv: Aes256Gcm,
    /// 发送 nonce 的 4 字节前缀。
    send_iv: [u8; 4],
    /// 接收 nonce 的 4 字节前缀。
    recv_iv: [u8; 4],
    /// 下一个发送计数器。
    send_counter: u64,
    /// 接收窗口。
    window: ReplayWindow,
    /// 发送方向的 rekey 代（每 `REKEY_INTERVAL` 帧 +1）。
    send_generation: u64,
    /// 接收方向的 rekey 代。
    recv_generation: u64,
    /// 当前发送密钥（rekey 后更新）。
    send_key: Zeroizing<[u8; KEY_LEN]>,
    /// 当前接收密钥（rekey 后更新）。
    recv_key: Zeroizing<[u8; KEY_LEN]>,
}

impl LinkSealer {
    /// 用已派生的 `link_key` 初始化；`is_client` 决定 iv 方向分流。
    ///
    /// `iv` 派生：`SHA256(link_key ‖ "iv" ‖ role_byte)[..4]`，两侧对称：
    /// 客户端用 `role_byte=0` 作发送 iv、`role_byte=1` 作接收 iv，服务端相反。
    #[must_use]
    pub fn new(link_key: &[u8; KEY_LEN], is_client: bool) -> Self {
        let iv_c = Self::derive_iv(link_key, 0);
        let iv_s = Self::derive_iv(link_key, 1);
        let (send_iv, recv_iv) = if is_client {
            (iv_c, iv_s)
        } else {
            (iv_s, iv_c)
        };
        // `KeyInit::new` 收定长密钥，不存在「长度不对」的失败分支。
        let send = Aes256Gcm::new(&(*link_key).into());
        let recv = Aes256Gcm::new(&(*link_key).into());
        Self {
            send,
            recv,
            send_iv,
            recv_iv,
            send_counter: 0,
            window: ReplayWindow::new(),
            send_generation: 0,
            recv_generation: 0,
            send_key: Zeroizing::new(*link_key),
            recv_key: Zeroizing::new(*link_key),
        }
    }

    /// `iv = SHA256(link_key ‖ "STW2-iv" ‖ dir)[..4]`。
    #[must_use]
    pub fn derive_iv(link_key: &[u8; KEY_LEN], dir: u8) -> [u8; 4] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(link_key);
        h.update(b"STW2-iv");
        h.update([dir]);
        let d: [u8; 32] = h.finalize().into();
        [d[0], d[1], d[2], d[3]]
    }

    /// 下一个发送计数器（用于写进帧尾或调试）。
    #[must_use]
    pub const fn next_counter(&self) -> u64 {
        self.send_counter
    }

    /// 接收窗口当前状态。
    #[must_use]
    pub const fn window(&self) -> &ReplayWindow {
        &self.window
    }

    /// 发送方向的 nonce：`iv(4) ‖ counter(8)`。
    #[must_use]
    pub fn nonce_for(&self, counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.send_iv);
        n[4..].copy_from_slice(&counter.to_be_bytes());
        n
    }

    /// 接收方向的 nonce（对端用它的 `send_iv`，即我们的 `recv_iv`）。
    #[must_use]
    pub fn recv_nonce_for(&self, counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.recv_iv);
        n[4..].copy_from_slice(&counter.to_be_bytes());
        n
    }

    /// 加密一段明文，`aad` 必须是整帧头。返回「密文 ‖ 16 字节 tag」
    /// 以及本次使用的计数器。
    ///
    /// # Errors
    /// 只在计数器耗尽或内部不变量被破坏时失败。
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, u64), SealerError> {
        let counter = self.send_counter;
        if counter == u64::MAX {
            return Err(SealerError::CounterExhausted);
        }
        let nonce = self.nonce_for(counter);
        let ct = self
            .send
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| SealerError::AuthFailed)?;
        self.send_counter += 1;
        self.maybe_rekey_send();
        Ok((ct, counter))
    }

    /// 解密一帧。`aad` 必须是整帧头，`counter` 从帧里读回。
    ///
    /// 顺序很重要：**先验 AEAD**（证明发送方持密钥），再检查窗口，
    /// 这样攻击者无法用伪造帧推进窗口。
    pub fn open(
        &mut self,
        counter: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SealerError> {
        // 先按帧号决定密钥代（与发送方一致：counter ∈ [k*N, (k+1)*N) 用第 k 代），
        // **再**解密；窗口推进放在解密成功之后，防止伪造帧推进窗口。
        self.maybe_rekey_recv(counter)?;
        let nonce = self.recv_nonce_for(counter);
        let pt = self
            .recv
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| SealerError::AuthFailed)?;
        self.window.accept(counter)?;
        Ok(pt)
    }

    /// 发送方向的当前 rekey 代。
    #[must_use]
    pub const fn send_generation(&self) -> u64 {
        self.send_generation
    }

    /// 接收方向的当前 rekey 代。
    #[must_use]
    pub const fn recv_generation(&self) -> u64 {
        self.recv_generation
    }

    /// 已发送帧数到达阈值则换钥（发送方向）。
    ///
    /// 两侧对「第 n 帧用第几代密钥」的判定必须完全一致：
    /// 发送方在**跨过** `k * REKEY_INTERVAL` 之前换好，接收方在收到该帧后换。
    fn maybe_rekey_send(&mut self) {
        let want = self.send_counter / REKEY_INTERVAL;
        while self.send_generation < want {
            self.send_generation += 1;
            let next = rekey(&self.send_key, self.send_generation);
            self.send = Aes256Gcm::new(&(*next).into());
            self.send_key = next;
        }
    }

    /// 接收方向换钥：以收到的计数器为界，与发送方同代。
    ///
    /// 一次跳跃超过 [`MAX_REKEY_JUMP`] 代时拒绝：否则伪造一个巨大 counter
    /// 就能逼我们做几十万次 HKDF（DoS）。
    fn maybe_rekey_recv(&mut self, counter: u64) -> Result<(), SealerError> {
        let want = counter / REKEY_INTERVAL;
        if want > self.recv_generation.saturating_add(MAX_REKEY_JUMP) {
            return Err(SealerError::Replayed {
                counter,
                floor: self.window.floor(),
            });
        }
        while self.recv_generation < want {
            self.recv_generation += 1;
            let next = rekey(&self.recv_key, self.recv_generation);
            self.recv = Aes256Gcm::new(&(*next).into());
            self.recv_key = next;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (LinkSealer, LinkSealer) {
        let key = [9u8; 32];
        (LinkSealer::new(&key, true), LinkSealer::new(&key, false))
    }

    #[test]
    fn roundtrip_both_directions() {
        let (mut c, mut s) = pair();
        let aad = b"frame-header";
        let (ct, counter) = c.seal(aad, b"hello").expect("seal");
        assert_eq!(counter, 0);
        assert_eq!(s.open(counter, aad, &ct).expect("open"), b"hello");

        let (ct2, counter2) = s.seal(aad, b"world").expect("seal");
        assert_eq!(c.open(counter2, aad, &ct2).expect("open"), b"world");
    }

    #[test]
    fn tampered_aad_is_rejected() {
        let (mut c, mut s) = pair();
        let (ct, counter) = c.seal(b"header-a", b"payload").expect("seal");
        assert_eq!(
            s.open(counter, b"header-b", &ct),
            Err(SealerError::AuthFailed),
            "头部篡改必须被 AAD 拦下"
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut c, mut s) = pair();
        let (mut ct, counter) = c.seal(b"h", b"payload").expect("seal");
        ct[0] ^= 0xff;
        assert_eq!(s.open(counter, b"h", &ct), Err(SealerError::AuthFailed));
    }

    #[test]
    fn replay_is_rejected() {
        let (mut c, mut s) = pair();
        let (ct, counter) = c.seal(b"h", b"once").expect("seal");
        s.open(counter, b"h", &ct).expect("first ok");
        assert_eq!(
            s.open(counter, b"h", &ct),
            Err(SealerError::Duplicate { counter })
        );
    }

    #[test]
    fn wrong_key_fails() {
        let mut c = LinkSealer::new(&[1u8; 32], true);
        let mut s = LinkSealer::new(&[2u8; 32], false);
        let (ct, counter) = c.seal(b"h", b"x").expect("seal");
        assert_eq!(s.open(counter, b"h", &ct), Err(SealerError::AuthFailed));
    }

    #[test]
    fn forged_frame_does_not_advance_window() {
        // 用错密钥伪造一个大 counter，窗口不能被推进（先验后窗）。
        let mut c = LinkSealer::new(&[1u8; 32], true);
        let mut s = LinkSealer::new(&[2u8; 32], false);
        let (ct, _) = c.seal(b"h", b"x").expect("seal");
        let before = s.window().highest();
        assert!(s.open(9999, b"h", &ct).is_err());
        assert_eq!(s.window().highest(), before);
    }

    #[test]
    fn window_slides_and_rejects_too_old() {
        let mut w = ReplayWindow::new();
        w.accept(0).expect("0");
        for i in 1..REPLAY_WINDOW_BITS as u64 {
            w.accept(i).expect("in order");
        }
        assert_eq!(w.highest(), Some(1023));
        // 仍然在窗口内（1023 - 0 = 1023 < 1024），但已被标记。
        assert_eq!(w.accept(0), Err(SealerError::Duplicate { counter: 0 }));
        w.accept(1024).expect("advance");
        // 现在 0 掉出窗口。
        assert!(matches!(w.accept(0), Err(SealerError::Replayed { .. })));
    }

    #[test]
    fn window_allows_reordering() {
        let mut w = ReplayWindow::new();
        for c in [5u64, 3, 1, 4, 2, 0] {
            w.accept(c).expect("乱序应被接受一次");
        }
        assert_eq!(w.highest(), Some(5));
        for c in 0..=5u64 {
            assert!(w.accept(c).is_err(), "重复 {c} 必须被拒");
        }
    }

    #[test]
    fn window_handles_large_jump() {
        let mut w = ReplayWindow::new();
        w.accept(0).expect("0");
        w.accept(1_000_000).expect("大跳");
        assert_eq!(w.highest(), Some(1_000_000));
        // 旧值全部掉出窗口。
        assert!(matches!(w.accept(0), Err(SealerError::Replayed { .. })));
        assert!(w.accept(999_999).is_ok());
    }

    #[test]
    fn nonce_layout_is_iv_plus_big_endian_counter() {
        let (c, s) = pair();
        let n = c.nonce_for(0x0102_0304_0506_0708);
        assert_eq!(&n[..4], &c.send_iv);
        assert_eq!(&n[4..], &[1, 2, 3, 4, 5, 6, 7, 8], "counter 用大端");
        // 两侧不同方向 iv 不同，杜绝双向 nonce 复用。
        assert_ne!(c.send_iv, s.send_iv);
        assert_eq!(c.send_iv, s.recv_iv);
        assert_eq!(c.recv_iv, s.send_iv);
    }

    #[test]
    fn counter_increments_monotonically() {
        let (mut c, _) = pair();
        assert_eq!(c.next_counter(), 0);
        c.seal(b"h", b"a").expect("1");
        assert_eq!(c.next_counter(), 1);
        c.seal(b"h", b"b").expect("2");
        assert_eq!(c.next_counter(), 2);
    }

    #[test]
    fn rekey_switches_key_on_both_sides() {
        // 直接构造一个已经跨过 rekey 边界的场景：发送方把计数器推到边界，
        // 接收端在收到边界帧后也必须换到同一代密钥。
        let key = [5u8; 32];
        let mut c = LinkSealer::new(&key, true);
        let mut s = LinkSealer::new(&key, false);

        // 假造一个刚好在边界的发送计数器（避免真的发 2²⁸ 帧）。
        c.send_counter = REKEY_INTERVAL;
        c.maybe_rekey_send();
        assert_eq!(c.send_generation(), 1);

        s.maybe_rekey_recv(REKEY_INTERVAL).expect("rekey");
        assert_eq!(s.recv_generation(), 1);

        let (ct, counter) = c.seal(b"h", b"after-rekey").expect("seal");
        assert_eq!(counter, REKEY_INTERVAL);
        assert_eq!(s.open(counter, b"h", &ct).expect("open"), b"after-rekey");
    }
}
