//! 字节游标与 LEB128 varint。
//!
//! 帧头里只有 `via_count` 与 `payload_len` 是变长，其余定长整数一律**小端**
//! （docs/plan.md §4.4）。所有读取都做边界检查并返回
//! [`ProtocolError::Truncated`]，绝不越界索引（缺陷 #1 的回归基线）。

use crate::error::{ProtocolError, Result};

/// varint 最大字节数（u64 的 LEB128 最多 10 字节）。
pub const MAX_VARINT_LEN: usize = 10;

/// 只读游标。
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// 包装一个切片。
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// 已消费字节数。
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// 剩余未消费字节数。
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// 是否已读完。
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn need(&self, n: usize, field: &'static str) -> Result<()> {
        if self.remaining() < n {
            return Err(ProtocolError::Truncated {
                need: n,
                have: self.remaining(),
                field,
            });
        }
        Ok(())
    }

    /// 读定长数组。
    pub fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N]> {
        self.need(N, field)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    /// 读 u8。
    pub fn u8(&mut self, field: &'static str) -> Result<u8> {
        self.need(1, field)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// 读 u16（小端）。
    pub fn u16_le(&mut self, field: &'static str) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array::<2>(field)?))
    }

    /// 读 u32（小端）。
    pub fn u32_le(&mut self, field: &'static str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array::<4>(field)?))
    }

    /// 读 u64（小端）。
    pub fn u64_le(&mut self, field: &'static str) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array::<8>(field)?))
    }

    /// 读 LEB128 varint（无符号）。
    pub fn varint(&mut self, field: &'static str) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        for i in 0..MAX_VARINT_LEN {
            let byte = self.u8(field)?;
            // 第 10 个字节只允许低 1 位有效，否则 u64 溢出。
            if i == MAX_VARINT_LEN - 1 && byte > 0x01 {
                return Err(ProtocolError::BadVarint {
                    reason: "varint 超出 u64 范围",
                });
            }
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
        Err(ProtocolError::BadVarint {
            reason: "varint 超过 10 字节",
        })
    }

    /// 读一个切片（长度由调用方先行校验）。
    pub fn slice(&mut self, len: usize, field: &'static str) -> Result<&'a [u8]> {
        self.need(len, field)?;
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    /// 断言已读到末尾，返回多余字节数（严格解析，缺陷 #3）。
    pub fn finish(self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes {
                bytes: self.remaining(),
            })
        }
    }
}

/// 追加写入游标。
#[derive(Debug, Clone, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// 新建空缓冲。
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// 预分配容量。
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// 已写字节数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// 追加字节。
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// 追加 u8。
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// 追加 u16（小端）。
    pub fn u16_le(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// 追加 u32（小端）。
    pub fn u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// 追加 u64（小端）。
    pub fn u64_le(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// 追加 LEB128 varint。
    pub fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.buf.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.buf.push(v as u8);
    }

    /// 取出 `Vec`。
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// 借用底层字节。
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_boundaries() {
        for v in [
            0u64,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let mut w = Writer::new();
            w.varint(v);
            let bytes = w.into_vec();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.varint("v").expect("decode"), v, "value {v}");
            assert!(r.is_empty());
        }
    }

    #[test]
    fn varint_canonical_lengths() {
        let mut w = Writer::new();
        w.varint(0x7f);
        assert_eq!(w.len(), 1);
        let mut w = Writer::new();
        w.varint(0x80);
        assert_eq!(w.len(), 2);
        let mut w = Writer::new();
        w.varint(u64::MAX);
        assert_eq!(w.len(), MAX_VARINT_LEN);
    }

    #[test]
    fn varint_rejects_overlong() {
        // 11 字节的 varint：前 10 字节都带续位。
        let overlong = [0x80u8; 11];
        let mut r = Reader::new(&overlong);
        assert!(matches!(
            r.varint("v"),
            Err(ProtocolError::BadVarint { .. })
        ));

        // 第 10 字节带高位数据 → u64 溢出。
        let mut bytes = vec![0x80u8; 9];
        bytes.push(0x02);
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.varint("v"),
            Err(ProtocolError::BadVarint { .. })
        ));
    }

    #[test]
    fn truncated_arrays_do_not_panic() {
        for n in 0..8usize {
            let buf = vec![0u8; n];
            let mut r = Reader::new(&buf);
            // 任意短缓冲都必须返回 Err 而不是 panic。
            let _ = r.array::<16>("arr");
            let _ = r.varint("v");
        }
    }

    #[test]
    fn trailing_bytes_detected() {
        let buf = [1u8, 2, 3];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8("a").expect("read"), 1);
        assert_eq!(r.u16_le("b").expect("read"), 0x0302);
        assert!(r.finish().is_ok());

        let mut r = Reader::new(&buf);
        assert_eq!(r.u8("a").expect("read"), 1);
        assert_eq!(r.finish(), Err(ProtocolError::TrailingBytes { bytes: 2 }));
    }
}
