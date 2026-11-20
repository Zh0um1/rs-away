//! SOCKS5 UDP ASSOCIATE 的**数据面**：把数据报装在会话字节流上。
//!
//! 权威：`docs/plan.md` §4.8（`Socks5Udp` 是独立会话种类）、附录 A 第 29–31 行
//! （`SOCKSUDPDATA` = 带 `Socks5Udp` 种类的一条 `SessionData` 流；
//! `UDPASSSTART` → `OpenSession{kind: Socks5Udp, direction: Inbound}`，**agent 发起**）。
//!
//! 控制面（TCP 上的 SOCKS5 协商、`UDP ASSOCIATE` 请求/应答）不在本模块：
//! 这里只管「一条已经 `Open` 的 `Socks5Udp` 会话怎么把数据报搬进搬出」。
//! 线格式编解码与出口套接字绑定复用 [`crate::udp_relay`]，本模块不重复实现 UDP 编解码。
//!
//! # 为什么必须分帧
//!
//! [`SessionStream`] 是**字节流**，不是消息流：`SessionData` 的 `seq` 只保证各块
//! 之间的先后顺序，`SessionStream::poll_read` 把收到的块按序拼进同一个缓冲区，
//! 读端一次 `read` 完全可能拿到「半块」或「一块半」。而 UDP 数据报的语义是
//! **每个数据报自带边界、彼此独立**：一次 `recv_from` 拿到的 N 字节只能作为一个
//! 数据报发出，两次 `recv_from` 的载荷也绝不能被粘成一个数据报。
//!
//! 字节流本身不携带任何边界信息，所以边界只能在应用层补：**2 字节大端长度
//! 前缀 + 载荷**，一个数据报 == 一个逻辑帧。也不能把「一块 `SessionData` 就是
//! 一个数据报」写进假设：块的切分由写端每次 `poll_write` 决定（`write_all` 可能
//! 被拆成任意多次 `poll_write`），换个写入方式就崩。
//!
//! 长度前缀取 2 字节：`0..=65535` 正好覆盖任何 UDP 数据报（含 SOCKS5 头），
//! 见 [`UDP_FRAME_MAX`]。
//!
//! # 为什么域名目标不在出口侧解析
//!
//! SOCKS5 UDP 请求头的目标可以是域名。出口侧（agent）**不做 DNS**，理由与
//! [`crate::udp_relay::relay_datagrams`] 一致：
//!
//! 1. 解析是**发起侧**的职责：客户端本来就是按域名请求的，出口侧再解析等于替
//!    它做了一次它没要求的解析；而且客户端与出口侧看到的 DNS 结果可能不同
//!    （不同网络、不同解析器、不同缓存），「客户端以为连的是 A，出口侧连到 B」
//!    会让审计与策略判断失效；
//! 2. 出口侧常常是被控端，未必有可用解析器；阻塞解析还会拖住整条数据面。
//!
//! 因此上行遇到域名目标就**跳过该帧**（丢一个数据报，会话继续），与
//! `relay_datagrams` 的策略一致。要支持域名，正确做法是在发起侧先解析、把
//! `Datagram.target` 换成解析后的 IP 再送进来。
//!
//! # 收摊
//!
//! 出口侧在这几种情况下结束，都算正常结束：
//!
//! - 会话流读到 EOF（对端关会话：`SessionClose` 让节点解绑投递端）；
//! - 空闲超过 [`UDP_IDLE_TIMEOUT_SECS`] 秒（超时包住每一轮 `select`，任一方向
//!   一有活动就重新计时）——v1 没有超时，端口泄漏。
//!
//! 出口套接字出错则按错误返回，由调用方决定收尾。
//!
//! # 取消安全（为什么这里手写帧状态机，而不是每轮调 [`read_datagram`]）
//!
//! `tokio::select!` 每一轮都会**取消**没赢得竞争的分支。[`read_datagram`] 内部
//! 有多次 `read().await`（先长度头、再载荷），若在「长度头已读 1 字节、正等第
//! 2 字节」时被取消，那 1 个字节就随 future 一起丢了，字节流随之错位。所以
//! [`outlet_side_on`] 每轮只做**一次** `read()`（单次 `read` 返回 `Pending` 时不
//! 吞任何字节，取消安全），把读到的字节丢进自己的 `pending` 缓冲，再用与
//! [`read_datagram`] 完全相同的 [`take_frame`] 判边界。两个入口共用同一份判帧
//! 逻辑，语义不会漂移。
//!
//! 同理，这里的 `select!` **故意不加 `biased;`**：`biased` 会让先列的分支在
//! 持续可读时永远赢，上行一直繁忙就会把下行饿死——回包永远发不出去，这比
//! 「优先级不固定」糟得多。tokio 默认的随机轮转保证两个方向都有进展。

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::error::Result;
use crate::session_stream::SessionStream;
use crate::socks::{Target, TargetAddr};
use crate::udp_relay::{self, Datagram, MAX_UDP_DATAGRAM, UDP_IDLE_TIMEOUT_SECS, bind_outlet};

/// 一个逻辑帧能装的最大字节数。
///
/// 2 字节大端长度前缀的表达上限就是 `65535`，也正好覆盖任何 UDP 数据报
/// （IPv4 最大载荷 65507），所以不需要更宽的长度头。
pub const UDP_FRAME_MAX: usize = 65_535;

/// 出口侧读会话流时每轮 `select` 的临时缓冲大小。
const READ_CHUNK: usize = 16 * 1024;

/// 把一块载荷写成一帧：`u16` 大端长度 + 载荷。
///
/// 空载荷是合法帧（长度 0）。注意 [`read_datagram`] 用「空向量」表达流结束，
/// 两者在返回值的形状上不可区分；真实 SOCKS5 数据报至少带 4 字节头，不会是
/// 空载荷，所以这条歧义不影响数据面。
///
/// # Errors
/// 载荷超过 [`UDP_FRAME_MAX`] 时报 [`io::ErrorKind::InvalidInput`]，且**一个
/// 字节都不写**（不会留下半帧）；底层写失败按原错误返回。
pub async fn frame_datagram<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > UDP_FRAME_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "UDP 帧载荷 {} 字节，超过上限 {UDP_FRAME_MAX}",
                payload.len()
            ),
        ));
    }
    let len = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("UDP 帧载荷 {} 字节无法用 u16 表示", payload.len()),
        )
    })?;
    // 一次写完：`SessionStream` 的 `poll_write` 每次调用都会产生一条
    // `SessionData`，分两次写就会让长度前缀和载荷各自成一条消息，接收端
    // 看到的帧序列随之错位。分帧的原子性必须靠单次写来保证。
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    w.write_all(&frame).await?;
    Ok(())
}

/// 从 `buf` 头部取出一个完整帧的载荷。
///
/// `Ok(None)` 表示字节还不够（调用方继续读），**不动** `buf`；
/// `Ok(Some(payload))` 时该帧（含长度头）已从 `buf` 里摘掉。
///
/// # Errors
/// 长度前缀非法（超过 [`UDP_FRAME_MAX`]，[`io::ErrorKind::InvalidData`]）。
/// 长度头是 `u16`，所以这条检查只在 [`UDP_FRAME_MAX`] 被调小时才会触发；
/// 保留它是为了让「帧上限」只有一个权威，而不是散落在各处。
fn take_frame(buf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if len > UDP_FRAME_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("UDP 帧长度 {len} 超过上限 {UDP_FRAME_MAX}"),
        ));
    }
    if buf.len() < 2 + len {
        return Ok(None);
    }
    let payload = buf[2..2 + len].to_vec();
    buf.drain(..2 + len);
    Ok(Some(payload))
}

/// 读一帧：2 字节大端长度 + 载荷。
///
/// 流正常结束时返回 `Ok(Vec::new())`（空向量），调用方据此收摊；帧中途断掉
/// 则是错误（[`io::ErrorKind::UnexpectedEof`]），不能当正常结束——半帧静默
/// 丢弃正是 v1 的缺陷 #8/#9。
///
/// # Errors
/// 读失败、长度前缀非法、帧中途 EOF。
pub async fn read_datagram<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 2];
    // 第一字节单独读：只有它能区分「干净 EOF」和「半个长度头」。
    let first = r.read(&mut header[..1]).await?;
    if first == 0 {
        return Ok(Vec::new());
    }
    if let Err(e) = r.read_exact(&mut header[1..]).await {
        return Err(truncated_frame(1, e));
    }
    let len = usize::from(u16::from_be_bytes(header));
    if len > UDP_FRAME_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("UDP 帧长度 {len} 超过上限 {UDP_FRAME_MAX}"),
        ));
    }
    // **绝不预读**：多读的字节若留在临时缓冲里就会丢，而字节流上两个数据报
    // 完全可能同时到达（一次 `read` 就能拿到多个帧）。
    let mut payload = vec![0u8; len];
    if let Err(e) = r.read_exact(&mut payload).await {
        return Err(truncated_frame(2 + len, e));
    }
    Ok(payload)
}

/// 帧读到一半断掉：把底层错误（多半是 `UnexpectedEof`）改写成带上下文的说明。
fn truncated_frame(want: usize, err: io::Error) -> io::Error {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("会话在 UDP 帧中途结束（期望 {want} 字节）"),
        )
    } else {
        err
    }
}

/// 出口侧（agent）：在 `bind` 上起 UDP 套接字，与会话流双向搬数据报。
///
/// - 上行：会话帧 → [`Datagram::parse`]（解析失败跳过该帧，不拖垮会话）→
///   目标有 IP 字面量就 `send_to`；域名目标跳过（出口侧不做 DNS，见模块文档）。
/// - 下行：`recv_from` → 把**来源地址**写成回包头部目标（RFC 1928 §7；不做
///   `connect`，同一时刻可服务多个客户端）→ 编码成帧写回会话。
/// - 空闲 [`UDP_IDLE_TIMEOUT_SECS`] 秒无任何方向活动 → 正常收摊，返回 `Ok(())`。
///
/// `limit` 是单次出口读的缓冲上限（超过 [`MAX_UDP_DATAGRAM`] 按它截）。
///
/// # Errors
/// 绑定失败、会话读写出错、出口套接字出错。
pub async fn outlet_side(session: SessionStream, bind: SocketAddr, limit: usize) -> Result<()> {
    let socket = bind_outlet(bind).await?;
    outlet_side_on(
        socket,
        session,
        limit,
        Duration::from_secs(UDP_IDLE_TIMEOUT_SECS),
    )
    .await
}

/// 用**已绑定**的出口套接字跑出口侧，空闲超时由调用方指定。
///
/// 与 [`outlet_side`] 的唯一区别是套接字与超时都由外部给：
///
/// - 真实链路里 `SessionReady.detail` 必须报出**实际**出口地址，而 `bind` 写
///   `:0` 时调用方拿不到端口，只能先绑、再报、再交进来（见
///   `tests/udp_associate_e2e.rs`）；
/// - 超时可注入，测试才能在秒级内验证空闲收摊，而不必等满
///   [`UDP_IDLE_TIMEOUT_SECS`]。
///
/// # Errors
/// 会话读写出错、出口套接字出错。
pub async fn outlet_side_on(
    socket: UdpSocket,
    session: SessionStream,
    limit: usize,
    idle: Duration,
) -> Result<()> {
    let mut session = session;
    let mut buf = vec![0u8; limit.clamp(1, MAX_UDP_DATAGRAM)];
    let mut chunk = vec![0u8; READ_CHUNK];
    // 已读到但还没凑成一帧的字节（上界 2 + UDP_FRAME_MAX，有界）。
    let mut pending: Vec<u8> = Vec::new();
    loop {
        // 先处理已凑齐的帧。这一段没有 await，不会被 select 取消。
        while let Some(frame) = take_frame(&mut pending).map_err(udp_relay::as_core)? {
            if frame.is_empty() {
                // 空帧没有意义（真 EOF 走下面 read() == 0 的分支），跳过。
                continue;
            }
            let Ok(datagram) = Datagram::parse(&frame) else {
                // 单个坏帧只丢一个数据报，不能杀掉整条会话。
                continue;
            };
            let Some(target) = datagram.resolved() else {
                // 域名目标：出口侧不做 DNS（模块文档）。
                continue;
            };
            socket
                .send_to(&datagram.payload, target)
                .await
                .map_err(udp_relay::as_core)?;
        }

        // 每轮只做一次 read()：单次 read 返回 Pending 时不吞字节，取消安全。
        let round = tokio::time::timeout(idle, async {
            tokio::select! {
                got = session.read(&mut chunk) => Round::Upstream(got),
                down = socket.recv_from(&mut buf) => Round::Downstream(down),
            }
        })
        .await;

        // 一个超时周期内两个方向都没动静：空闲收摊，算正常结束。
        let Ok(round) = round else {
            return Ok(());
        };

        match round {
            Round::Upstream(Ok(0)) => return Ok(()),
            Round::Upstream(Ok(n)) => pending.extend_from_slice(&chunk[..n]),
            Round::Upstream(Err(e)) => return Err(udp_relay::as_core(e)),
            Round::Downstream(Ok((n, from))) => {
                let reply = Datagram {
                    target: Target {
                        addr: TargetAddr::Ip(from.ip()),
                        port: from.port(),
                    },
                    payload: buf[..n].to_vec(),
                };
                let frame = reply.encode();
                if frame.len() > UDP_FRAME_MAX {
                    // 装不进一帧（只在 limit 取到 64KiB 且对端发超大包时出现）：
                    // 丢这一个数据报，比让整条会话失败更好。
                    continue;
                }
                frame_datagram(&mut session, &frame)
                    .await
                    .map_err(udp_relay::as_core)?;
                session.flush().await.map_err(udp_relay::as_core)?;
            }
            Round::Downstream(Err(e)) => return Err(udp_relay::as_core(e)),
        }
    }
}

/// 客户端侧（admin）：把 SOCKS5 客户端发来的数据报搬进会话流，再搬回客户端。
///
/// - 上行：`recv_from(客户端)` → 整包（含 SOCKS5 UDP 头）`frame_datagram` 进会话；
///   出口侧负责解析头与发往目标，本端**不改写**载荷。
/// - 下行：会话帧 → 原样 `send_to(客户端)`。帧里已经是完整的 SOCKS5 UDP 回包
///   （出口侧把真实来源地址写进了头），本端再加一层只会让它认不出来。
/// - **只服务第一个看到的客户端地址**：RFC 1928 §7 规定一条关联只对应一个
///   客户端，接受第二个来源等于把别人的数据报塞进这条隧道。
/// - 空闲 [`UDP_IDLE_TIMEOUT_SECS`] 秒无活动或会话 EOF → 收摊。
///
/// TCP 控制连接断开应由调用方监控（RFC 1928：关联随 TCP 连接结束），本函数
/// 只负责数据面。
///
/// # Errors
/// 会话读写出错、UDP 套接字出错。
pub async fn client_side_on(
    socket: UdpSocket,
    session: SessionStream,
    limit: usize,
    idle: Duration,
) -> Result<()> {
    let mut session = session;
    let mut buf = vec![0u8; limit.clamp(1, MAX_UDP_DATAGRAM)];
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut pending: Vec<u8> = Vec::new();
    let mut client: Option<SocketAddr> = None;
    loop {
        // 先吐已凑齐的帧（无 await，取消安全）。
        while let Some(frame) = take_frame(&mut pending).map_err(udp_relay::as_core)? {
            if frame.is_empty() {
                continue;
            }
            let Some(addr) = client else {
                continue;
            };
            socket
                .send_to(&frame, addr)
                .await
                .map_err(udp_relay::as_core)?;
        }

        let round = tokio::time::timeout(idle, async {
            tokio::select! {
                got = session.read(&mut chunk) => Round::Upstream(got),
                down = socket.recv_from(&mut buf) => Round::Downstream(down),
            }
        })
        .await;

        let Ok(round) = round else {
            return Ok(());
        };

        match round {
            Round::Upstream(Ok(0)) => return Ok(()),
            Round::Upstream(Ok(n)) => pending.extend_from_slice(&chunk[..n]),
            Round::Upstream(Err(e)) => return Err(udp_relay::as_core(e)),
            Round::Downstream(Err(e)) => return Err(udp_relay::as_core(e)),
            Round::Downstream(Ok((n, from))) => {
                // RFC 1928 §7：一条关联只服务一个客户端。换来源就丢掉，
                // 否则别人的数据报会被塞进这条隧道。
                match client {
                    None => client = Some(from),
                    Some(known) if known != from => continue,
                    Some(_) => {}
                }
                if n == 0 {
                    continue;
                }
                frame_datagram(&mut session, &buf[..n])
                    .await
                    .map_err(udp_relay::as_core)?;
                session.flush().await.map_err(udp_relay::as_core)?;
            }
        }
    }
}

/// 一轮 `select` 的结果。
#[derive(Debug)]
enum Round {
    /// 会话流上读到（或试图读到）字节。
    Upstream(io::Result<usize>),
    /// 出口套接字上收到（或试图收到）数据报。
    Downstream(io::Result<(usize, SocketAddr)>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowaway_protocol::{ByteBuf, NodeId, SessionData, SessionKey};
    use tokio::sync::mpsc;

    use crate::session_stream::SessionOutbound;

    fn key() -> SessionKey {
        SessionKey::new(NodeId::ADMIN, 41)
    }

    /// 一条无主的会话流（出站通道与入站投递端都留在测试手里）。
    fn session_stream() -> (
        SessionStream,
        mpsc::Sender<SessionData>,
        mpsc::Receiver<SessionOutbound>,
    ) {
        let (out_tx, out_rx) = mpsc::channel(16);
        let (stream, sink) = SessionStream::new(key(), NodeId::ADMIN, out_tx, 16);
        (stream, sink, out_rx)
    }

    #[tokio::test]
    async fn framing_roundtrip_preserves_payloads() {
        let mut wire: Vec<u8> = Vec::new();
        frame_datagram(&mut wire, b"first").await.expect("frame 1");
        frame_datagram(&mut wire, b"second!")
            .await
            .expect("frame 2");
        assert_eq!(&wire[..2], &[0x00, 0x05], "长度前缀是 2 字节大端");

        let mut reader: &[u8] = &wire;
        assert_eq!(read_datagram(&mut reader).await.expect("read 1"), b"first");
        assert_eq!(
            read_datagram(&mut reader).await.expect("read 2"),
            b"second!"
        );
        assert!(
            read_datagram(&mut reader).await.expect("eof").is_empty(),
            "流结束用空向量表达"
        );
    }

    #[tokio::test]
    async fn framing_handles_empty_and_maximum_payloads() {
        let mut wire: Vec<u8> = Vec::new();
        frame_datagram(&mut wire, &[]).await.expect("empty frame");
        assert_eq!(wire, vec![0x00, 0x00], "空载荷就是长度 0 的帧");

        let max = vec![0xA5u8; UDP_FRAME_MAX];
        frame_datagram(&mut wire, &max).await.expect("max frame");
        assert_eq!(wire.len(), 2 + 2 + UDP_FRAME_MAX);
        assert_eq!(&wire[2..4], &[0xFF, 0xFF], "65535 的长度前缀是 ffff");

        let mut reader: &[u8] = &wire;
        assert!(
            read_datagram(&mut reader).await.expect("empty").is_empty(),
            "长度 0 的帧读回空载荷"
        );
        assert_eq!(
            read_datagram(&mut reader).await.expect("max"),
            max,
            "65535 字节的边界值必须完整往返"
        );
    }

    #[tokio::test]
    async fn framing_rejects_oversized_payload() {
        let too_big = vec![0u8; UDP_FRAME_MAX + 1];
        let mut wire: Vec<u8> = Vec::new();
        let err = frame_datagram(&mut wire, &too_big)
            .await
            .expect_err("超长载荷必须拒绝");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(wire.is_empty(), "被拒绝的帧一个字节都不能写出去");
    }

    #[tokio::test]
    async fn read_datagram_reports_end_of_stream_and_truncation() {
        let mut clean: &[u8] = &[];
        assert!(
            read_datagram(&mut clean).await.expect("EOF").is_empty(),
            "干净 EOF 用空向量表达，而不是错误"
        );

        // 长度头只有 1 字节就断了：不能当正常结束。
        let mut half_header: &[u8] = &[0x00];
        let err = read_datagram(&mut half_header)
            .await
            .expect_err("半个长度头必须报错");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        // 长度前缀说 5 字节，实际只给 3 字节。
        let mut short: &[u8] = &[0x00, 0x05, b'a', b'b', b'c'];
        let err = read_datagram(&mut short)
            .await
            .expect_err("载荷不足必须报错");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn client_side_forwards_only_the_first_client_both_ways() {
        let (session, sink, mut out) = session_stream();
        let socket = bind_outlet("127.0.0.1:0".parse().expect("addr"))
            .await
            .expect("bind");
        let listen_addr = socket.local_addr().expect("addr");
        let relay = tokio::spawn(client_side_on(
            socket,
            session,
            65_535,
            Duration::from_secs(5),
        ));

        // 第一个客户端发一包：上行必须是完整一帧，载荷原样保留。
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        client
            .send_to(b"first-client", listen_addr)
            .await
            .expect("send");
        let SessionOutbound::Data { data, .. } =
            tokio::time::timeout(Duration::from_secs(2), out.recv())
                .await
                .expect("上行超时")
                .expect("通道关闭")
        else {
            panic!("上行应该是数据帧");
        };
        assert_eq!(&data.data[..2], &[0x00, 0x0c], "长度前缀 = 载荷长度 12");
        assert_eq!(&data.data[2..], b"first-client");

        // 第二个客户端发一包：必须被丢掉（不回写会话）。
        let other = UdpSocket::bind("127.0.0.1:0").await.expect("other");
        other
            .send_to(b"second-client", listen_addr)
            .await
            .expect("send");
        let extra = tokio::time::timeout(Duration::from_millis(300), out.recv()).await;
        assert!(extra.is_err(), "第二个来源不该被转发");

        // 下行：会话帧原样送到第一个客户端（帧里已是完整 SOCKS5 回包）。
        let mut wire: Vec<u8> = Vec::new();
        frame_datagram(&mut wire, b"reply").await.expect("frame");
        sink.send(SessionData {
            key: key(),
            seq: 0,
            data: ByteBuf::from(wire),
        })
        .await
        .expect("send downstream");
        let mut down = [0u8; 8];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut down))
            .await
            .expect("recv")
            .expect("ok");
        assert_eq!(&down[..n], b"reply");

        relay.abort();
    }

    #[tokio::test]
    async fn outlet_relays_one_datagram_each_way() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_addr = echo.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], from).await;
            }
        });

        let outlet = UdpSocket::bind("127.0.0.1:0").await.expect("bind outlet");
        let (stream, sink, mut out_rx) = session_stream();
        let task = tokio::spawn(outlet_side_on(
            outlet,
            stream,
            MAX_UDP_DATAGRAM,
            Duration::from_secs(5),
        ));

        // 上行：把一个目标为回显套接字的数据报塞进会话流。
        let up = Datagram {
            target: Target {
                addr: TargetAddr::Ip(echo_addr.ip()),
                port: echo_addr.port(),
            },
            payload: b"udp-hello".to_vec(),
        };
        // 上行必须**分帧**投递：会话流是字节流，接收方靠长度前缀切分。
        // 直接塞裸数据报会被长度头当成 0 长度（SOCKS5 头的前两字节是 RSV=0），
        // 这正是本模块存在的理由，也是这里必须走 frame_datagram 的原因。
        let mut wire_up: Vec<u8> = Vec::new();
        frame_datagram(&mut wire_up, &up.encode())
            .await
            .expect("frame upstream");
        sink.send(SessionData {
            key: key(),
            seq: 0,
            data: ByteBuf::from(wire_up),
        })
        .await
        .expect("send upstream");

        // 下行：出口侧把回包封装成帧写回会话流（出站通道），按帧解开。
        let mut wire: Vec<u8> = Vec::new();
        let reply = loop {
            let out = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
                .await
                .expect("回包超时：出口侧没有把数据报发出去或没有写回会话")
                .expect("出站通道关闭");
            let SessionOutbound::Data { data, .. } = out else {
                panic!("期望数据，得到 {:?}", out);
            };
            wire.extend_from_slice(&data.data);
            if let Some(frame) = take_frame(&mut wire).expect("frame") {
                break Datagram::parse(&frame).expect("parse reply");
            }
        };

        assert_eq!(reply.payload, b"udp-hello", "回包载荷必须原样");
        assert_eq!(
            reply.resolved(),
            Some(echo_addr),
            "回包头里的目标必须是数据报的来源地址（RFC 1928 §7）"
        );
        task.abort();
    }

    #[tokio::test]
    async fn outlet_side_idles_out_and_returns_cleanly() {
        let outlet = UdpSocket::bind("127.0.0.1:0").await.expect("bind outlet");
        let (stream, _sink, _out_rx) = session_stream();
        let idle = Duration::from_millis(150);
        let started = std::time::Instant::now();
        let res = outlet_side_on(outlet, stream, MAX_UDP_DATAGRAM, idle).await;
        assert!(res.is_ok(), "空闲超时是正常收摊，不是错误");
        assert!(started.elapsed() >= idle, "至少等满一个空闲周期才收摊");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "不应该卡在 select 里"
        );
    }
}
