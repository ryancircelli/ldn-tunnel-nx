//! The module's own sockets, on its own `bsd:s` client.
//!
//! Coexistence with the `bsd:u` MITM (crates/sys/src/bsd/): Atmosphere only intercepts
//! `bsd:u` sessions opened by *games*; our sessions go to `bsd:s`, a different service
//! name, so they reach the real socket service untouched. The MITM forwards each game's
//! calls over that game's own `bsd:u` client (its own RegisterClient, fd table and
//! transfer memory); ours is a separate client with its own fd table, so the fds here and
//! the game's never mix. `bsd:s` (System) also allows the privileged socket options.
//!
//! nx's `nx::socket` would do the RegisterClient for us, but it does not expose raw calls
//! (no connect timeout, no keepalive, no recv/send split across sessions), so this file
//! talks to `IBsdClient` directly, like libnx's `bsdInitialize` does:
//! - sessions: `rx` for everything the relay thread does (poll, recv, connect, DNS) and
//!   `tx` for `send`, which game threads call while the relay thread may sit in a long
//!   `poll` on `rx`. One session serves one request at a time, so a blocked poll would
//!   otherwise stall every send.
//! - transfer memory: a page-aligned static sized like the C++ `LibnxSocketInitConfig`.
#![forbid(unsafe_code)]

use alloc::sync::Arc;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicI32, Ordering::Relaxed};

use nx::ipc::client::IClientObject;
use nx::ipc::sf::{Buffer, CopyHandle, ProcessId};
use nx::result::{ResultBase, ResultCode};
use nx::service::bsd::{
    BsdResult, BsdServiceConfig, FcntlCmd, IBsdClient, IpProto, PollFd, PollFlags, ReadFlags,
    SendFlags, SocketAddrRepr, SocketDomain, SocketOptions, SocketType, SystemBsdService,
    TcpOptions, SOL_SOCKET,
};
use nx::service::new_service_object;
use nx::svc::{self, MemoryPermission};
use nx::sync::RwLock;

/// C++ main.cpp `LibnxSocketInitConfig` (sb_efficiency 4 = buffers for 4 sockets; we use
/// 2 at most: the relay TCP socket and a DNS UDP socket).
fn config() -> BsdServiceConfig {
    BsdServiceConfig {
        tcp_tx_buf_size: 0x800,
        tcp_rx_buf_size: 0x1000,
        tcp_tx_buf_max_size: 0x2000,
        tcp_rx_buf_max_size: 0x2000,
        udp_tx_buf_size: 0x2000,
        udp_rx_buf_size: 0x2000,
        sb_efficiency: 4,
        ..Default::default() // version: picked from the firmware version
    }
}

/// `min_transfer_mem_size` of `config()`: 4 * align(0x8000, 0x1000) = 128 KiB.
// ponytail: sb_efficiency 2 would halve this; kept at the C++ value until measured.
const TMEM_SIZE: usize = 0x2_0000;

#[repr(C, align(0x1000))]
struct Tmem([u8; TMEM_SIZE]);

/// Handed to the kernel as transfer memory; Rust never reads or writes it.
static mut TMEM: Tmem = Tmem([0; TMEM_SIZE]);

struct Bsd {
    rx: SystemBsdService,
    tx: SystemBsdService,
    /// StartMonitoring session: keeps our client registered while it is open.
    _monitor: SystemBsdService,
}

static BSD: RwLock<Option<Bsd>> = RwLock::new(None);

/// O_NONBLOCK as the bsd service understands it (libnx and nx both send 0x800).
const O_NONBLOCK: i32 = 0x800;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    /// IPC to bsd:s failed (or it is not initialized).
    Ipc(ResultCode),
    /// The call failed with this errno (Linux numbering on Horizon).
    Errno(i32),
    /// Nothing arrived within the timeout (`read` with timeout 0: nothing buffered).
    TimedOut,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for NetError {}

impl embedded_io::Error for NetError {
    fn kind(&self) -> embedded_io::ErrorKind {
        use embedded_io::ErrorKind as K;
        match self {
            Self::TimedOut => K::TimedOut,
            Self::Errno(104) => K::ConnectionReset,
            Self::Errno(111) => K::ConnectionRefused,
            _ => K::Other,
        }
    }
}

type Res<T> = Result<T, NetError>;

fn ok<T>(r: nx::result::Result<BsdResult<T>>) -> Res<(i32, T)> {
    match r.map_err(NetError::Ipc)? {
        BsdResult::Ok(v, t) => Ok((v, t)),
        BsdResult::Err(e) => Err(NetError::Errno(e)),
    }
}

/// Registers our `bsd:s` client. Idempotent; call once at startup before any socket.
pub fn initialize() -> nx::result::Result<()> {
    let mut g = BSD.write();
    if g.is_some() {
        return Ok(());
    }
    let mut rx = new_service_object::<SystemBsdService>()?;
    let mut monitor = new_service_object::<SystemBsdService>()?;
    // The handle stays open for the life of the process (libnx closes it only at exit).
    let tmem = svc::create_transfer_memory((&raw mut TMEM).cast(), TMEM_SIZE, MemoryPermission::None())?;
    let cfg = config();
    log!(Verbose, "bsd:s: tmem={:#x} (static {:#x})", cfg.min_transfer_mem_size(), TMEM_SIZE);
    let pid = rx.register_client(cfg, ProcessId::new(), TMEM_SIZE, CopyHandle::from(tmem))?;
    monitor.start_monitoring(ProcessId::from(pid))?;
    // libnx clones its extra sessions after RegisterClient; same here.
    let tx = rx.clone()?;
    *g = Some(Bsd { rx, tx, _monitor: monitor });
    Ok(())
}

fn with<T>(f: impl FnOnce(&Bsd) -> Res<T>) -> Res<T> {
    match BSD.read().as_ref() {
        Some(b) => f(b),
        None => Err(NetError::Ipc(nx::rc::ResultNotInitialized::make())),
    }
}

/// Waits until `fd` is readable (data, EOF or error), up to `timeout_ms` (0 = just
/// check). `Ok(false)` = timeout.
pub fn wait_readable(fd: i32, timeout_ms: i32) -> Res<bool> {
    poll(fd, PollFlags::PollIn(), timeout_ms)
}

/// Waits up to `timeout_ms` (0 = just check) for `events` on `fd`. `Ok(false)` = timeout.
fn poll(fd: i32, events: PollFlags, timeout_ms: i32) -> Res<bool> {
    let mut fds = [PollFd { fd, events, revents: PollFlags::default() }];
    let fds_in = fds;
    let (n, ()) = with(|b| ok(b.rx.poll(1, timeout_ms, Buffer::from_array(&fds_in), Buffer::from_mut_array(&mut fds))))?;
    Ok(n > 0)
}

fn set_opt(fd: i32, level: i32, name: i32, value: i32) -> Res<()> {
    with(|b| ok(b.rx.set_sock_opt(fd, level, name, Buffer::from_other_var(&value)))).map(drop)
}

/// A socket on our bsd:s client; closed on drop.
pub struct Fd(i32);

impl Fd {
    fn new(ty: SocketType) -> Res<Self> {
        with(|b| ok(b.rx.socket(SocketDomain::INet as u32, ty, IpProto::IP))).map(|(fd, ())| Self(fd))
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = with(|b| ok(b.rx.close(self.0)));
    }
}

/// TCP keepalive (C++ socket.cpp): probe after 30 s idle, every 10 s, drop after 5 misses.
const KEEPALIVE: (i32, i32, i32) = (30, 10, 5);

/// Blocking TCP stream for the TLS layer. `read` waits at most the read timeout and then
/// fails with [`NetError::TimedOut`]; nothing is lost, so the caller may read again. 0 =
/// return at once when nothing is buffered (the relay thread polls before reading).
pub struct BsdSocket {
    fd: Fd,
    /// Shared so it can change after the socket moved into the `TlsStream`.
    read_timeout_ms: Arc<AtomicI32>,
}

impl BsdSocket {
    /// Connects with a timeout (non-blocking connect + poll + SO_ERROR, as socket.cpp),
    /// then switches back to blocking and turns keepalive on (best effort).
    pub fn connect(ip: Ipv4Addr, port: u16, timeout_ms: i32) -> Res<Self> {
        let fd = Fd::new(SocketType::Stream)?;
        let s = fd.0;
        let flags = with(|b| ok(b.rx.fcntl(s, FcntlCmd::GetFl, 0)))?.0;
        with(|b| ok(b.rx.fcntl(s, FcntlCmd::SetFl, flags | O_NONBLOCK)))?;
        let addr = SocketAddrRepr::from((ip, port));
        // EINPROGRESS is the expected answer. Its number is not relied on: any failure
        // also shows up as POLLOUT|POLLERR plus SO_ERROR below.
        let _ = with(|b| ok(b.rx.connect(s, Buffer::from_var(&addr))));
        if !poll(s, PollFlags::PollOut(), timeout_ms)? {
            return Err(NetError::TimedOut);
        }
        let mut err = 0i32;
        with(|b| ok(b.rx.get_sock_opt(s, SOL_SOCKET, SocketOptions::Error as i32, Buffer::from_other_mut_var(&mut err))))?;
        if err != 0 {
            return Err(NetError::Errno(err));
        }
        with(|b| ok(b.rx.fcntl(s, FcntlCmd::SetFl, flags & !O_NONBLOCK)))?;
        let tcp = IpProto::TCP as i32;
        let _ = set_opt(s, SOL_SOCKET, SocketOptions::KeepAlive as i32, 1)
            .and_then(|()| set_opt(s, tcp, TcpOptions::KeepIdle as i32, KEEPALIVE.0))
            .and_then(|()| set_opt(s, tcp, TcpOptions::KeepInterval as i32, KEEPALIVE.1))
            .and_then(|()| set_opt(s, tcp, TcpOptions::KeepCount as i32, KEEPALIVE.2));
        let _ = set_opt(s, tcp, TcpOptions::NoDelay as i32, 1);
        Ok(Self { fd, read_timeout_ms: Arc::new(AtomicI32::new(timeout_ms)) })
    }

    pub fn fd(&self) -> i32 {
        self.fd.0
    }

    /// Handle to the read timeout (ms) that stays valid once the socket is inside TLS.
    pub fn read_timeout(&self) -> Arc<AtomicI32> {
        self.read_timeout_ms.clone()
    }
}

impl embedded_io::ErrorType for BsdSocket {
    type Error = NetError;
}

impl embedded_io::Read for BsdSocket {
    /// `Ok(0)` = the peer closed the connection.
    fn read(&mut self, buf: &mut [u8]) -> Res<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // poll first so a recv never blocks past the timeout (no reliance on SO_RCVTIMEO
        // or on the EAGAIN number).
        if !wait_readable(self.fd.0, self.read_timeout_ms.load(Relaxed))? {
            return Err(NetError::TimedOut);
        }
        let s = self.fd.0;
        with(|b| ok(b.rx.recv(s, ReadFlags::None(), Buffer::from_mut_array(buf)))).map(|(n, ())| n.max(0) as usize)
    }
}

impl embedded_io::Write for BsdSocket {
    /// Blocking send on the `tx` session (callable while the relay thread polls `rx`).
    fn write(&mut self, buf: &[u8]) -> Res<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let s = self.fd.0;
        match with(|b| ok(b.tx.send(s, SendFlags::None(), Buffer::from_array(buf))))? {
            (0, ()) => Err(NetError::Errno(0)), // write_all would spin on 0
            (n, ()) => Ok(n as usize),
        }
    }

    fn flush(&mut self) -> Res<()> {
        Ok(())
    }
}

/// UDP socket for the DNS client.
pub struct UdpSocket(Fd);

impl UdpSocket {
    pub fn new() -> Res<Self> {
        Fd::new(SocketType::DataGram).map(Self)
    }

    pub fn send_to(&self, data: &[u8], ip: Ipv4Addr, port: u16) -> Res<()> {
        let addr = SocketAddrRepr::from((ip, port));
        let s = self.0 .0;
        with(|b| ok(b.rx.send_to(s, SendFlags::None(), Buffer::from_array(data), Buffer::from_var(&addr)))).map(drop)
    }

    /// One datagram within `timeout_ms`: `(len, from ip, from port)`, or `TimedOut`.
    pub fn recv_from(&self, buf: &mut [u8], timeout_ms: i32) -> Res<(usize, Ipv4Addr, u16)> {
        if !wait_readable(self.0 .0, timeout_ms)? {
            return Err(NetError::TimedOut);
        }
        let s = self.0 .0;
        let mut from = SocketAddrRepr::default();
        let (n, ()) =
            with(|b| ok(b.rx.recv_from(s, ReadFlags::None(), Buffer::from_mut_array(buf), Buffer::from_mut_var(&mut from))))?;
        Ok((n.max(0) as usize, Ipv4Addr::from(from.addr), u16::from_be(from.port)))
    }
}
