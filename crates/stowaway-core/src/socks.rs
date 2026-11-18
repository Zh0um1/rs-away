//! SOCKS5 线协议（RFC 1928 + RFC 1929 用户名/密码认证）。
//!
//! 只做**编解码与状态机判定**，不碰 socket —— 这样 SOCKS5 的解析逻辑
//! 既能被 admin 侧（接受客户端）复用，也能被 agent 侧（拨号目标）复用，
//! 并且全部可用纯字节单测覆盖。
//!
//! 与 v1 的差异（plan §3）：v1 的解析散在 `admin/handler/socks.go` 与
//! `agent/handler/socks.go` 两处，各自用 `buf[:n]` 直接切片，长度字段来自
//! 网络却未先校验，属于缺陷 #1/#3 的同源问题。这里所有读取都走
//! [`Reader`]，越界一律返回 [`SocksError`]。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

/// SOCKS 版本号（RFC 1928 只定义 5）。
pub const SOCKS_VERSION: u8 = 5;

/// 认证方法：无需认证。
pub const AUTH_NONE: u8 = 0x00;
/// 认证方法：用户名/密码（RFC 1929）。
pub const AUTH_USERPASS: u8 = 0x02;
/// 认证方法：没有可接受的方法。
pub const AUTH_UNACCEPTABLE: u8 = 0xff;

/// 命令：CONNECT。
pub const CMD_CONNECT: u8 = 0x01;
/// 命令：BIND（本实现不支持，但必须能识别并礼貌拒绝）。
pub const CMD_BIND: u8 = 0x02;
/// 命令：UDP ASSOCIATE。
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// 地址类型：IPv4。
pub const ATYP_IPV4: u8 = 0x01;
/// 地址类型：域名。
pub const ATYP_DOMAIN: u8 = 0x03;
/// 地址类型：IPv6。
pub const ATYP_IPV6: u8 = 0x04;

/// 回复码：成功。
pub const REP_SUCCEEDED: u8 = 0x00;
/// 回复码：一般性故障。
pub const REP_GENERAL_FAILURE: u8 = 0x01;
/// 回复码：规则不允许。
pub const REP_NOT_ALLOWED: u8 = 0x02;
/// 回复码：网络不可达。
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
/// 回复码：主机不可达。
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
/// 回复码：连接被拒绝。
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
/// 回复码：TTL 过期。
pub const REP_TTL_EXPIRED: u8 = 0x06;
/// 回复码：命令不支持。
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
/// 回复码：地址类型不支持。
pub const REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 解析/状态机错误。
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocksError {
    /// 字节不够（调用方应继续读，而不是报错给客户端）。
    #[error("需要更多字节：{need} 字节，实际 {have}")]
    Truncated {
        /// 需要的字节数。
        need: usize,
        /// 现有字节数。
        have: usize,
    },
    /// 版本号不是 5。
    #[error("不支持的 SOCKS 版本：{actual:#04x}")]
    BadVersion {
        /// 实际版本号。
        actual: u8,
    },
    /// 没有双方都支持的认证方法。
    #[error("没有可接受的认证方法")]
    NoAcceptableAuth,
    /// 认证失败。
    #[error("认证失败（用户名或密码错误）")]
    AuthFailed,
    /// 命令不支持。
    #[error("不支持的 SOCKS 命令：{cmd:#04x}")]
    UnsupportedCommand {
        /// 命令字节。
        cmd: u8,
    },
    /// 地址类型不支持。
    #[error("不支持的地址类型：{atyp:#04x}")]
    UnsupportedAddressType {
        /// 地址类型字节。
        atyp: u8,
    },
    /// 域名非法（空、超长、含非 ASCII）。
    #[error("非法域名：{reason}")]
    BadDomain {
        /// 原因。
        reason: &'static str,
    },
    /// 端口为 0。
    #[error("端口必须非 0")]
    ZeroPort,
    /// 回复码未知。
    #[error("未知的 SOCKS 回复码：{code:#04x}")]
    UnknownReply {
        /// 回复码。
        code: u8,
    },
}

/// 解析结果：要么已经拿到完整消息，要么字节还不够。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed<T> {
    /// 完整消息，附带消耗的字节数。
    Ready(T, usize),
    /// 需要继续读。
    NeedMore,
}

/// 安全读取器（所有切片都先做长度校验）。
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn need(&self, n: usize) -> Result<(), SocksError> {
        if self.buf.len() - self.pos < n {
            Err(SocksError::Truncated {
                need: n,
                have: self.buf.len() - self.pos,
            })
        } else {
            Ok(())
        }
    }

    fn u8(&mut self) -> Result<u8, SocksError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16_be(&mut self) -> Result<u16, SocksError> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SocksError> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// 客户端的第一步：`VER | NMETHODS | METHODS`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodOffer {
    /// 客户端支持的方法列表。
    pub methods: Vec<u8>,
}

impl MethodOffer {
    /// 解析（不足 2 字节时返回 [`Parsed::NeedMore`]）。
    ///
    /// # Errors
    /// 版本不是 5、方法数超限（>255 已被 u8 约束）后长度不够之外的非法输入。
    pub fn parse(buf: &[u8]) -> Result<Parsed<Self>, SocksError> {
        if buf.len() < 2 {
            return Ok(Parsed::NeedMore);
        }
        if buf[0] != SOCKS_VERSION {
            return Err(SocksError::BadVersion { actual: buf[0] });
        }
        let n = usize::from(buf[1]);
        if buf.len() < 2 + n {
            return Ok(Parsed::NeedMore);
        }
        let methods = buf[2..2 + n].to_vec();
        Ok(Parsed::Ready(Self { methods }, 2 + n))
    }

    /// 在「无认证」与「用户名/密码」里挑一个；都没有则 `None`。
    #[must_use]
    pub fn select(&self, allow_userpass: bool) -> Option<u8> {
        if self.methods.contains(&AUTH_NONE) {
            return Some(AUTH_NONE);
        }
        if allow_userpass && self.methods.contains(&AUTH_USERPASS) {
            return Some(AUTH_USERPASS);
        }
        None
    }
}

/// 服务端的**方法选择**回复：`VER | METHOD`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodReply {
    /// 选定的方法。
    pub method: u8,
}

impl MethodReply {
    /// 编码（2 字节）。
    #[must_use]
    pub const fn encode(self) -> [u8; 2] {
        [SOCKS_VERSION, self.method]
    }
}

/// RFC 1929 认证请求：`VER(0x01) | ULEN | UNAME | PLEN | PASSWD`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPassRequest {
    /// 用户名。
    pub username: String,
    /// 密码。
    pub password: String,
}

impl UserPassRequest {
    /// 解析。
    ///
    /// # Errors
    /// 子协议版本不是 1、长度不足、UTF-8 非法。
    pub fn parse(buf: &[u8]) -> Result<Parsed<Self>, SocksError> {
        if buf.len() < 2 {
            return Ok(Parsed::NeedMore);
        }
        if buf[0] != 0x01 {
            return Err(SocksError::AuthFailed);
        }
        let ulen = usize::from(buf[1]);
        if buf.len() < 2 + ulen + 1 {
            return Ok(Parsed::NeedMore);
        }
        let plen = usize::from(buf[2 + ulen]);
        if buf.len() < 2 + ulen + 1 + plen {
            return Ok(Parsed::NeedMore);
        }
        let Ok(username) = std::str::from_utf8(&buf[2..2 + ulen]) else {
            return Err(SocksError::AuthFailed);
        };
        let Ok(password) = std::str::from_utf8(&buf[2 + ulen + 1..2 + ulen + 1 + plen]) else {
            return Err(SocksError::AuthFailed);
        };
        Ok(Parsed::Ready(
            Self {
                username: username.to_owned(),
                password: password.to_owned(),
            },
            2 + ulen + 1 + plen,
        ))
    }

    /// 编码（便于测试与客户端实现）。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let u = self.username.as_bytes();
        let p = self.password.as_bytes();
        let mut out = Vec::with_capacity(3 + u.len() + p.len());
        out.push(0x01);
        out.push(u8::try_from(u.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(u);
        out.push(u8::try_from(p.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(p);
        out
    }
}

/// 认证结果：`VER(0x01) | STATUS`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPassReply {
    /// 是否成功。
    pub success: bool,
}

impl UserPassReply {
    /// 编码（2 字节）。
    #[must_use]
    pub const fn encode(self) -> [u8; 2] {
        [0x01, if self.success { 0x00 } else { 0x01 }]
    }

    /// 解析（客户端侧读认证结果）。
    ///
    /// # Errors
    /// 子协议版本不是 1。
    pub fn parse(buf: &[u8]) -> Result<Self, SocksError> {
        if buf.len() < 2 {
            return Err(SocksError::Truncated {
                need: 2,
                have: buf.len(),
            });
        }
        if buf[0] != 0x01 {
            return Err(SocksError::AuthFailed);
        }
        Ok(Self {
            success: buf[1] == 0x00,
        })
    }
}

/// SOCKS5 的目标地址（域名或 IP 字面量）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    /// IP 字面量。
    Ip(IpAddr),
    /// 域名（转小写便于比较）。
    Domain(String),
}

impl TargetAddr {
    /// `host:port` 形式（域名会原样拼上）。
    #[must_use]
    pub fn authority(&self, port: u16) -> String {
        match self {
            Self::Ip(ip) => match ip {
                IpAddr::V4(v4) => format!("{v4}:{port}"),
                IpAddr::V6(v6) => format!("[{v6}]:{port}"),
            },
            Self::Domain(d) => format!("{d}:{port}"),
        }
    }

    /// 若目标是 IP 字面量则转成 `SocketAddr`。
    #[must_use]
    pub fn socket_addr(&self, port: u16) -> Option<SocketAddr> {
        match self {
            Self::Ip(ip) => Some(SocketAddr::new(*ip, port)),
            Self::Domain(_) => None,
        }
    }
}

impl TargetAddr {
    /// 追写 `ATYP | ADDR`（不含端口）。
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Ip(IpAddr::V4(v4)) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&v4.octets());
            }
            Self::Ip(IpAddr::V6(v6)) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&v6.octets());
            }
            Self::Domain(d) => {
                out.push(ATYP_DOMAIN);
                out.push(u8::try_from(d.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(d.as_bytes());
            }
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Domain(d) => f.write_str(d),
        }
    }
}

/// 请求的目标：地址 + 端口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// 地址。
    pub addr: TargetAddr,
    /// 端口。
    pub port: u16,
}

impl Target {
    /// `host:port`。
    #[must_use]
    pub fn authority(&self) -> String {
        self.addr.authority(self.port)
    }
}

/// 请求：`VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// 命令（CONNECT / UDP ASSOCIATE / BIND）。
    pub cmd: u8,
    /// 目标。
    pub target: Target,
}

impl Request {
    /// 编码（客户端侧用）：`VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT`。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.push(SOCKS_VERSION);
        out.push(self.cmd);
        out.push(0x00);
        self.target.addr.encode_into(&mut out);
        out.extend_from_slice(&self.target.port.to_be_bytes());
        out
    }

    /// 解析。
    ///
    /// # Errors
    /// 版本不是 5、RSV 非 0、地址类型不支持、域名为空/超 255/非 UTF-8、端口为 0。
    pub fn parse(buf: &[u8]) -> Result<Parsed<Self>, SocksError> {
        if buf.len() < 4 {
            return Ok(Parsed::NeedMore);
        }
        if buf[0] != SOCKS_VERSION {
            return Err(SocksError::BadVersion { actual: buf[0] });
        }
        let cmd = buf[1];
        if buf[2] != 0x00 {
            return Err(SocksError::BadDomain {
                reason: "保留字节必须为 0",
            });
        }
        let atyp = buf[3];
        let mut c = Cursor::new(buf);
        c.pos = 4;
        let addr = match atyp {
            ATYP_IPV4 => {
                let Ok(bytes) = c.take(4) else {
                    return Ok(Parsed::NeedMore);
                };
                let mut a = [0u8; 4];
                a.copy_from_slice(bytes);
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(a)))
            }
            ATYP_IPV6 => {
                let Ok(bytes) = c.take(16) else {
                    return Ok(Parsed::NeedMore);
                };
                let mut a = [0u8; 16];
                a.copy_from_slice(bytes);
                TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(a)))
            }
            ATYP_DOMAIN => {
                let Ok(len) = c.u8() else {
                    return Ok(Parsed::NeedMore);
                };
                if len == 0 {
                    return Err(SocksError::BadDomain {
                        reason: "长度不能为 0",
                    });
                }
                let Ok(name) = c.take(usize::from(len)) else {
                    return Ok(Parsed::NeedMore);
                };
                let Ok(name) = std::str::from_utf8(name) else {
                    return Err(SocksError::BadDomain {
                        reason: "不是合法 UTF-8",
                    });
                };
                TargetAddr::Domain(name.to_ascii_lowercase())
            }
            other => return Err(SocksError::UnsupportedAddressType { atyp: other }),
        };
        let Ok(port) = c.u16_be() else {
            return Ok(Parsed::NeedMore);
        };
        if port == 0 {
            return Err(SocksError::ZeroPort);
        }
        Ok(Parsed::Ready(
            Self {
                cmd,
                target: Target { addr, port },
            },
            c.pos,
        ))
    }
}

/// 回复：`VER | REP | RSV | ATYP | BND.ADDR | BND.PORT`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// 回复码。
    pub rep: u8,
    /// 绑定地址（IPv4 时通常是全 0）。
    pub bind: Option<SocketAddr>,
}

impl Reply {
    /// 用回复码构造（绑定地址留空 → 全 0 IPv4:0）。
    #[must_use]
    pub const fn new(rep: u8) -> Self {
        Self { rep, bind: None }
    }

    /// 成功回复并带上绑定地址。
    #[must_use]
    pub const fn succeeded(bind: SocketAddr) -> Self {
        Self {
            rep: REP_SUCCEEDED,
            bind: Some(bind),
        }
    }

    /// 把错误映射成回复码（DNS 失败与拒连要分开报，便于客户端诊断）。
    #[must_use]
    pub fn code_for(err: &std::io::Error) -> u8 {
        match err.kind() {
            std::io::ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
            std::io::ErrorKind::TimedOut => REP_HOST_UNREACHABLE,
            std::io::ErrorKind::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
            std::io::ErrorKind::HostUnreachable => REP_HOST_UNREACHABLE,
            std::io::ErrorKind::PermissionDenied => REP_NOT_ALLOWED,
            _ => REP_GENERAL_FAILURE,
        }
    }

    /// 编码。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(22);
        out.push(SOCKS_VERSION);
        out.push(self.rep);
        out.push(0x00);
        match self.bind {
            Some(SocketAddr::V4(v4)) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            Some(SocketAddr::V6(v6)) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
            None => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&[0u8; 4]);
                out.extend_from_slice(&0u16.to_be_bytes());
            }
        }
        out
    }

    /// 解析（客户端侧用）。
    ///
    /// # Errors
    /// 版本不是 5、回复码未知、地址类型不支持、字节不足。
    pub fn parse(buf: &[u8]) -> Result<Parsed<Self>, SocksError> {
        if buf.len() < 5 {
            return Ok(Parsed::NeedMore);
        }
        if buf[0] != SOCKS_VERSION {
            return Err(SocksError::BadVersion { actual: buf[0] });
        }
        let rep = buf[1];
        if rep > REP_ADDRESS_NOT_SUPPORTED {
            return Err(SocksError::UnknownReply { code: rep });
        }
        let atyp = buf[3];
        let mut c = Cursor::new(buf);
        c.pos = 4;
        let bind = match atyp {
            ATYP_IPV4 => {
                let Ok(bytes) = c.take(4) else {
                    return Ok(Parsed::NeedMore);
                };
                let mut a = [0u8; 4];
                a.copy_from_slice(bytes);
                let Ok(port) = c.u16_be() else {
                    return Ok(Parsed::NeedMore);
                };
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), port))
            }
            ATYP_IPV6 => {
                let Ok(bytes) = c.take(16) else {
                    return Ok(Parsed::NeedMore);
                };
                let mut a = [0u8; 16];
                a.copy_from_slice(bytes);
                let Ok(port) = c.u16_be() else {
                    return Ok(Parsed::NeedMore);
                };
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port))
            }
            ATYP_DOMAIN => {
                let Ok(len) = c.u8() else {
                    return Ok(Parsed::NeedMore);
                };
                let Ok(_name) = c.take(usize::from(len)) else {
                    return Ok(Parsed::NeedMore);
                };
                let Ok(_port) = c.u16_be() else {
                    return Ok(Parsed::NeedMore);
                };
                None
            }
            other => return Err(SocksError::UnsupportedAddressType { atyp: other }),
        };
        Ok(Parsed::Ready(Self { rep, bind }, c.pos))
    }
}

/// UDP ASSOCIATE 的数据报头：`RSV(2) | FRAG(1) | ATYP | ADDR | PORT`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    /// 目标。
    pub target: Target,
    /// 分片号（0 = 完整数据报；v2 只支持 0，其它值必须丢弃）。
    pub frag: u8,
}

impl UdpHeader {
    /// 解析：返回头部与**剩余载荷的偏移**。
    ///
    /// # Errors
    /// 保留位非 0、地址类型不支持、域名/端口非法。
    pub fn parse(buf: &[u8]) -> Result<Parsed<(Self, usize)>, SocksError> {
        if buf.len() < 4 {
            return Ok(Parsed::NeedMore);
        }
        if buf[0] != 0x00 || buf[1] != 0x00 {
            return Err(SocksError::BadDomain {
                reason: "UDP 保留字节必须为 0",
            });
        }
        if buf[2] != 0x00 {
            return Err(SocksError::BadDomain {
                reason: "不支持 UDP 分片（FRAG 必须为 0）",
            });
        }
        let atyp = buf[3];
        let mut c = Cursor::new(buf);
        c.pos = 4;
        let addr = match atyp {
            ATYP_IPV4 => {
                let Ok(bytes) = c.take(4) else {
                    return Ok(Parsed::NeedMore);
                };
                let mut a = [0u8; 4];
                a.copy_from_slice(bytes);
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(a)))
            }
            ATYP_IPV6 => {
                let Ok(bytes) = c.take(16) else {
                    return Ok(Parsed::NeedMore);
                };
                let mut a = [0u8; 16];
                a.copy_from_slice(bytes);
                TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(a)))
            }
            ATYP_DOMAIN => {
                let Ok(len) = c.u8() else {
                    return Ok(Parsed::NeedMore);
                };
                if len == 0 {
                    return Err(SocksError::BadDomain {
                        reason: "长度不能为 0",
                    });
                }
                let Ok(name) = c.take(usize::from(len)) else {
                    return Ok(Parsed::NeedMore);
                };
                let Ok(name) = std::str::from_utf8(name) else {
                    return Err(SocksError::BadDomain {
                        reason: "不是合法 UTF-8",
                    });
                };
                TargetAddr::Domain(name.to_ascii_lowercase())
            }
            other => return Err(SocksError::UnsupportedAddressType { atyp: other }),
        };
        let Ok(port) = c.u16_be() else {
            return Ok(Parsed::NeedMore);
        };
        if port == 0 {
            return Err(SocksError::ZeroPort);
        }
        let offset = c.pos;
        Ok(Parsed::Ready(
            (
                Self {
                    target: Target { addr, port },
                    frag: 0,
                },
                offset,
            ),
            offset,
        ))
    }

    /// 编码头部（不含载荷）。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(22);
        out.extend_from_slice(&[0x00, 0x00, 0x00]);
        match &self.target.addr {
            TargetAddr::Ip(IpAddr::V4(v4)) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&v4.octets());
            }
            TargetAddr::Ip(IpAddr::V6(v6)) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&v6.octets());
            }
            TargetAddr::Domain(d) => {
                out.push(ATYP_DOMAIN);
                let bytes = d.as_bytes();
                out.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(bytes);
            }
        }
        out.extend_from_slice(&self.target.port.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4() -> TargetAddr {
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    }

    #[test]
    fn method_offer_parses_and_selects() {
        let buf = [5u8, 2, AUTH_NONE, AUTH_USERPASS];
        let Parsed::Ready(offer, used) = MethodOffer::parse(&buf).expect("parse") else {
            panic!("need more");
        };
        assert_eq!(used, 4);
        assert_eq!(offer.select(false), Some(AUTH_NONE));
        assert_eq!(offer.select(true), Some(AUTH_NONE));

        let buf = [5u8, 1, AUTH_USERPASS];
        let Parsed::Ready(offer, _) = MethodOffer::parse(&buf).expect("parse") else {
            panic!("need more");
        };
        assert_eq!(offer.select(false), None, "未开启认证时不得选 userpass");
        assert_eq!(offer.select(true), Some(AUTH_USERPASS));
    }

    #[test]
    fn method_offer_needs_more_until_complete() {
        assert_eq!(MethodOffer::parse(&[5]).expect("ok"), Parsed::NeedMore);
        assert_eq!(
            MethodOffer::parse(&[5, 3, 0, 2]).expect("ok"),
            Parsed::NeedMore
        );
    }

    #[test]
    fn wrong_version_is_rejected() {
        let err = MethodOffer::parse(&[4, 1, 0]).expect_err("v4");
        assert_eq!(err, SocksError::BadVersion { actual: 4 });
    }

    #[test]
    fn userpass_roundtrip() {
        let req = UserPassRequest {
            username: "alice".to_owned(),
            password: "s3cr3t".to_owned(),
        };
        let bytes = req.encode();
        let Parsed::Ready(got, used) = UserPassRequest::parse(&bytes).expect("parse") else {
            panic!("need more");
        };
        assert_eq!(used, bytes.len());
        assert_eq!(got, req);
    }

    #[test]
    fn userpass_truncation_needs_more() {
        let bytes = UserPassRequest {
            username: "ab".to_owned(),
            password: "cde".to_owned(),
        }
        .encode();
        for cut in 1..bytes.len() {
            assert_eq!(
                UserPassRequest::parse(&bytes[..cut]).expect("ok"),
                Parsed::NeedMore,
                "前缀 {cut} 字节应等待更多数据"
            );
        }
    }

    #[test]
    fn connect_request_ipv4() {
        let mut buf = vec![5u8, CMD_CONNECT, 0x00, ATYP_IPV4];
        buf.extend_from_slice(&[192, 0, 2, 1]);
        buf.extend_from_slice(&8080u16.to_be_bytes());
        let Parsed::Ready(req, used) = Request::parse(&buf).expect("parse") else {
            panic!("need more");
        };
        assert_eq!(used, buf.len());
        assert_eq!(req.cmd, CMD_CONNECT);
        assert_eq!(req.target.addr, v4());
        assert_eq!(req.target.port, 8080);
        assert_eq!(req.target.authority(), "192.0.2.1:8080");
    }

    #[test]
    fn connect_request_domain_is_lowercased() {
        let mut buf = vec![5u8, CMD_CONNECT, 0x00, ATYP_DOMAIN, 11];
        buf.extend_from_slice(b"Example.COM");
        buf.extend_from_slice(&443u16.to_be_bytes());
        let Parsed::Ready(req, _) = Request::parse(&buf).expect("parse") else {
            panic!("need more");
        };
        assert_eq!(
            req.target.addr,
            TargetAddr::Domain("example.com".to_owned())
        );
        assert_eq!(req.target.authority(), "example.com:443");
        assert!(req.target.addr.socket_addr(443).is_none());
    }

    #[test]
    fn connect_request_ipv6_is_supported() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut buf = vec![5u8, CMD_CONNECT, 0x00, ATYP_IPV6];
        buf.extend_from_slice(&addr.octets());
        buf.extend_from_slice(&80u16.to_be_bytes());
        let Parsed::Ready(req, _) = Request::parse(&buf).expect("parse") else {
            panic!("need more");
        };
        assert_eq!(req.target.authority(), "[2001:db8::1]:80");
    }

    #[test]
    fn zero_port_is_rejected() {
        let mut buf = vec![5u8, CMD_CONNECT, 0x00, ATYP_IPV4];
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            Request::parse(&buf).expect_err("zero port"),
            SocksError::ZeroPort
        );
    }

    #[test]
    fn bad_reserved_byte_is_rejected() {
        let mut buf = vec![5u8, CMD_CONNECT, 0x01, ATYP_IPV4];
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(&80u16.to_be_bytes());
        assert!(Request::parse(&buf).is_err());
    }

    #[test]
    fn request_truncation_never_indexes_out_of_bounds() {
        let mut full = vec![5u8, CMD_CONNECT, 0x00, ATYP_IPV4];
        full.extend_from_slice(&[127, 0, 0, 1]);
        full.extend_from_slice(&9u16.to_be_bytes());
        for cut in 0..full.len() {
            // 每个前缀都必须返回 NeedMore 或 Err，绝不 panic。
            let _ = Request::parse(&full[..cut]);
        }
    }

    #[test]
    fn empty_domain_is_rejected() {
        let buf = vec![5u8, CMD_CONNECT, 0x00, ATYP_DOMAIN, 0];
        assert!(Request::parse(&buf).is_err());
    }

    #[test]
    fn reply_encodes_ipv4_bind() {
        let bind: SocketAddr = "203.0.113.5:1080".parse().expect("addr");
        let bytes = Reply::succeeded(bind).encode();
        assert_eq!(bytes[0], SOCKS_VERSION);
        assert_eq!(bytes[1], REP_SUCCEEDED);
        assert_eq!(bytes[3], ATYP_IPV4);
        let Parsed::Ready(got, used) = Reply::parse(&bytes).expect("parse") else {
            panic!("need more");
        };
        assert_eq!(used, bytes.len());
        assert_eq!(got.bind, Some(bind));
    }

    #[test]
    fn reply_without_bind_uses_zero_address() {
        let bytes = Reply::new(REP_CONNECTION_REFUSED).encode();
        let Parsed::Ready(got, _) = Reply::parse(&bytes).expect("parse") else {
            panic!("need more");
        };
        assert_eq!(got.rep, REP_CONNECTION_REFUSED);
        assert_eq!(got.bind, Some("0.0.0.0:0".parse().expect("addr")));
    }

    #[test]
    fn reply_code_mapping_is_specific() {
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert_eq!(Reply::code_for(&refused), REP_CONNECTION_REFUSED);
        let timeout = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert_eq!(Reply::code_for(&timeout), REP_HOST_UNREACHABLE);
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(Reply::code_for(&denied), REP_NOT_ALLOWED);
        let other = std::io::Error::other("boom");
        assert_eq!(Reply::code_for(&other), REP_GENERAL_FAILURE);
    }

    #[test]
    fn udp_header_roundtrip() {
        let header = UdpHeader {
            target: Target {
                addr: TargetAddr::Domain("example.com".to_owned()),
                port: 53,
            },
            frag: 0,
        };
        let mut datagram = header.encode();
        datagram.extend_from_slice(b"payload");
        let Parsed::Ready((got, offset), _) = UdpHeader::parse(&datagram).expect("parse") else {
            panic!("need more");
        };
        assert_eq!(got, header);
        assert_eq!(&datagram[offset..], b"payload");
    }

    #[test]
    fn udp_fragment_is_rejected() {
        let buf = [0u8, 0, 1, ATYP_IPV4, 1, 2, 3, 4, 0, 53];
        assert!(UdpHeader::parse(&buf).is_err());
    }
}
