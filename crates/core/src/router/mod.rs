//! LDN proxy socket routing, sans-IO (port of the C++ `ProxySocketManager`,
//! `ProxySocket`, `EphemeralPortPool` and the proxied-fd paths of
//! `BsdMitmService`). UDP only; see README.md for where TCP plugs in.
//!
//! The shell calls one `on_*` method per bsd:u command on a game socket and
//! acts on the returned decision; the relay receive path calls
//! [`Router::on_proxy_data`]. The router never blocks, sleeps or allocates:
//! one `Router` lives in a static behind the shell's mutex. It is 145,232
//! bytes: 8 sockets of ~16.5 KB, the 8 KB pending ring, 128 tracked fds and
//! the 2 KB port bitset (checked against [`ROUTER_SIZE_BOUND`]).
//!
//! Sockets are identified by [`SocketKey`] = `(bsd:u session id << 32) | fd`,
//! because fd numbering is per bsd:u client.

pub mod bsd;
mod ports;
mod ring;
pub mod traffic;

#[cfg(test)]
mod tests;

pub use bsd::SockAddrIn;

use bsd::errno::*;
use ports::PortPool;
use ring::{Meta, PacketRing};

use crate::wire::{ProtocolType, ProxyDataHeader, ProxyInfo};

/// Live proxy sockets at once (all bsd:u clients together).
pub const MAX_PROXY_SOCKETS: usize = 8;
/// Game sockets whose type and options are remembered until they become a
/// proxy (bind/connect/sendto come after socket/fcntl/setsockopt). A socket
/// created while this is full is never proxied (it stays a real socket).
pub const MAX_TRACKED_SOCKETS: usize = 128;
/// Receive ring per proxy socket: ~11 MTU frames or 100+ small PIA packets.
pub const RX_BUFFER_SIZE: usize = 16 * 1024;
/// Datagrams for a port nobody has bound yet, delivered when it is bound.
pub const PENDING_BUFFER_SIZE: usize = 8 * 1024;
/// Largest datagram either way (MTU frames are ~1460 B).
pub const MAX_PAYLOAD: usize = 2000;
/// Longest a blocking recv may hold a bsd:u thread before EAGAIN.
pub const MAX_BLOCK_NS: i64 = 1_000_000_000;
/// Upper bound on `size_of::<Router>()`, checked by a test.
pub const ROUTER_SIZE_BOUND: usize = 144 * 1024;

const LDN_NET: u32 = 0x0A72_0000;
const LDN_MASK: u32 = 0xFFFF_0000;
const LEGACY_BROADCAST: u32 = 0xC0A8_00FF; // 192.168.0.255

pub type SocketKey = u64;

pub const fn socket_key(session_id: u32, fd: i32) -> SocketKey {
    ((session_id as u64) << 32) | (fd as u32 as u64)
}

/// 10.114.0.0/16 (Ryujinx format).
pub const fn is_ldn_addr(ip: u32) -> bool {
    ip & LDN_MASK == LDN_NET
}

/// Whether a datagram to `ip` goes through the relay: LDN addresses plus the
/// limited and legacy broadcasts. Anything else is internet traffic.
pub const fn is_proxy_destination(ip: u32) -> bool {
    is_ldn_addr(ip) || ip == u32::MAX || ip == LEGACY_BROADCAST
}

/// What the shell does with a bsd:u call.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision<'a> {
    /// Not ours: forward the untouched request to the real bsd:u.
    Forward,
    /// Answer the game with this result: `>= 0`, or `-errno`.
    Reply(i32),
    /// bind(INADDR_ANY) on a proxy: also run the real bind (ignore its
    /// result, so internet traffic keeps working), then reply with this.
    ReplyAndForward(i32),
    /// Send `LdnHeader(ProxyData) + header + payload` to the relay, then
    /// reply `payload.len()`, or `-ENETUNREACH` if it could not be sent.
    Emit { header: ProxyDataHeader, payload: &'a [u8] },
}

/// What the shell does with a recv/recvfrom.
#[derive(Debug, PartialEq, Eq)]
pub enum RecvDecision {
    Forward,
    /// `0` (EOF after shutdown) or `-errno`.
    Reply(i32),
    /// `len` bytes were copied into `out` (a longer datagram is truncated and
    /// the rest discarded); write `from` to the game's address buffer.
    Data { len: usize, from: SockAddrIn },
    /// Nothing queued on a blocking socket: wait for data (any successful
    /// `on_proxy_data`), shutdown or close for at most `limit_ns` since the
    /// call began and ask again; past the limit reply `-EAGAIN`.
    Wait { limit_ns: i64 },
}

/// Poll/select view of a socket.
#[derive(Debug, PartialEq, Eq)]
pub enum PollState {
    /// Not a proxy: the real poll answers.
    Real,
    /// Was a proxy, its LDN session ended: report error/hang-up so the
    /// game's next call gets ENETDOWN.
    Gone,
    /// Proxy: always writable; `readable` when data or EOF is queued.
    Proxy { readable: bool },
}

/// Datagram counters since the last [`Router::reset`], for logs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Incoming datagrams queued on at least one socket.
    pub delivered: u32,
    /// Incoming datagrams with no matching socket, kept in the pending ring.
    pub pending: u32,
    /// Datagrams dropped because a receive or pending ring was full (oldest first).
    pub evicted: u32,
    /// Incoming datagrams dropped as malformed, oversize or non-UDP.
    pub dropped: u32,
}

#[derive(Clone, Copy)]
struct Tracked {
    key: SocketKey,
    sock_type: i32,
    /// Became a proxy. Stays set after `reset` so its calls fail with ENETDOWN
    /// instead of reaching a real socket that was never bound to 10.114.x.x.
    is_proxy: bool,
    non_blocking: bool,
    broadcast: bool,
    rcv_timeout_ns: i64,
}

struct ProxySocket {
    /// `None` = free slot. Slots are reused in place (no 16 KB temporaries).
    key: Option<SocketKey>,
    local: SockAddrIn,
    /// connect()ed default destination.
    remote: Option<SockAddrIn>,
    shut_rd: bool,
    shut_wr: bool,
    rx: PacketRing<RX_BUFFER_SIZE>,
}

impl ProxySocket {
    const fn new() -> Self {
        Self { key: None, local: SockAddrIn::from_ryujinx(0, 0), remote: None, shut_rd: false, shut_wr: false, rx: PacketRing::new() }
    }

    /// Unicast: port and (IP or INADDR_ANY) match. Broadcast: port matches;
    /// every listener gets it (PIA mesh discovery needs the fan-out).
    fn accepts(&self, meta: &Meta, broadcast: bool) -> bool {
        let ip = self.local.addr_ryujinx();
        self.key.is_some() && self.local.port() == meta.dst_port && (ip == 0 || ip == meta.dst_ip || broadcast)
    }
}

pub struct Router {
    local_ip: u32,
    mask: u32,
    tracked: heapless::Vec<Tracked, MAX_TRACKED_SOCKETS>,
    slots: [ProxySocket; MAX_PROXY_SOCKETS],
    udp_ports: PortPool,
    pending: PacketRing<PENDING_BUFFER_SIZE>,
    stats: Stats,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub const fn new() -> Self {
        Self {
            local_ip: 0,
            mask: 0,
            tracked: heapless::Vec::new(),
            slots: [const { ProxySocket::new() }; MAX_PROXY_SOCKETS],
            udp_ports: PortPool::new(),
            pending: PacketRing::new(),
            stats: Stats { delivered: 0, pending: 0, evicted: 0, dropped: 0 },
        }
    }

    // ---- session ------------------------------------------------------

    /// From ProxyConfig (Ryujinx format). While `local_ip != 0` an
    /// INADDR_ANY bind becomes a proxy bound to it.
    pub fn set_proxy_config(&mut self, local_ip: u32, mask: u32) {
        self.local_ip = local_ip;
        self.mask = mask;
    }

    /// The session's IP (Ryujinx format), 0 outside a session.
    pub fn local_ip(&self) -> u32 {
        self.local_ip
    }

    /// LDN disconnect: closes every proxy, frees all ports, drops pending
    /// datagrams, the proxy config and the stats. Proxied fds answer ENETDOWN from now on.
    pub fn reset(&mut self) {
        self.stats = Stats::default();
        for s in &mut self.slots {
            s.key = None;
            s.rx.clear();
        }
        self.udp_ports.release_all();
        self.pending.clear();
        self.set_proxy_config(0, 0);
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn proxy_count(&self) -> usize {
        self.slots.iter().filter(|s| s.key.is_some()).count()
    }

    // ---- lookups ------------------------------------------------------

    fn tracked(&self, key: SocketKey) -> Option<Tracked> {
        self.tracked.iter().find(|t| t.key == key).copied()
    }

    fn tracked_mut(&mut self, key: SocketKey) -> Option<&mut Tracked> {
        self.tracked.iter_mut().find(|t| t.key == key)
    }

    fn slot(&self, key: SocketKey) -> Option<&ProxySocket> {
        self.slots.iter().find(|s| s.key == Some(key))
    }

    fn slot_mut(&mut self, key: SocketKey) -> Option<&mut ProxySocket> {
        self.slots.iter_mut().find(|s| s.key == Some(key))
    }

    fn is_gone(&self, key: SocketKey) -> bool {
        self.slot(key).is_none() && self.tracked(key).is_some_and(|t| t.is_proxy)
    }

    fn is_broadcast(&self, dst: u32) -> bool {
        dst & 0xFF == 0xFF || (self.mask != 0 && dst == self.local_ip | !self.mask)
    }

    /// The address an implicit bind (connect/sendto on an unbound fd) uses.
    fn session_addr(&self) -> SockAddrIn {
        SockAddrIn::from_ryujinx(self.local_ip, 0)
    }

    /// Makes `key` a proxy bound to `addr` (port 0 = ephemeral) and hands it
    /// the datagrams that were waiting for its port. Errors are errno values;
    /// on error nothing is left behind.
    fn create_bound(&mut self, key: SocketKey, addr: SockAddrIn) -> Result<(), i32> {
        if self.slot(key).is_some() {
            return Err(EINVAL); // already bound
        }
        if !self.slots.iter().any(|s| s.key.is_none()) {
            return Err(ENOMEM);
        }
        let port = match addr.port() {
            0 => self.udp_ports.allocate().ok_or(EADDRINUSE)?,
            p if self.udp_ports.reserve(p) => p,
            _ => return Err(EADDRINUSE),
        };
        let slot = self.slots.iter_mut().find(|s| s.key.is_none()).ok_or(ENOMEM)?;
        // Field by field: `*slot = ProxySocket { rx: PacketRing::new(), .. }` built a 16 KB ring on
        // the stack (a 32 KB frame), which overran the 32 KB bsd:u thread stack into ldn:u's.
        slot.key = Some(key);
        slot.local = SockAddrIn { sin_port: port.to_be(), ..addr };
        slot.remote = None;
        slot.shut_rd = false;
        slot.shut_wr = false;
        slot.rx.clear();
        if let Some(t) = self.tracked_mut(key) {
            t.is_proxy = true;
        }
        self.deliver_pending(key);
        Ok(())
    }

    fn deliver_pending(&mut self, key: SocketKey) {
        let mut buf = [0u8; MAX_PAYLOAD];
        for _ in 0..self.pending.count() {
            let Some((len, meta)) = self.pending.front(&mut buf) else { break };
            self.pending.pop();
            let data = buf.get(..len).unwrap_or_default();
            let broadcast = self.is_broadcast(meta.dst_ip);
            match self.slots.iter_mut().find(|s| s.key == Some(key)) {
                Some(s) if s.accepts(&meta, broadcast) => {
                    s.rx.push(meta, data);
                }
                // Same size as the record just popped: never evicts.
                _ => {
                    self.pending.push(meta, data);
                }
            }
        }
    }

    // ---- bsd:u commands ------------------------------------------------

    /// Socket/SocketExempt succeeded with `key`. Remembers AF_INET sockets;
    /// false when not tracked (other family, or the table is full).
    pub fn on_socket(&mut self, key: SocketKey, domain: i32, sock_type: i32, _protocol: i32) -> bool {
        self.on_close(key); // a reused fd starts clean
        domain == i32::from(bsd::AF_INET)
            && self
                .tracked
                .push(Tracked {
                    key,
                    sock_type: sock_type & bsd::SOCK_TYPE_MASK,
                    is_proxy: false,
                    non_blocking: sock_type & bsd::SOCK_NONBLOCK != 0,
                    broadcast: false,
                    rcv_timeout_ns: 0,
                })
                .is_ok()
    }

    /// Close: forgets the fd and frees its proxy and port. The shell always
    /// forwards close too (the real fd exists). True if a proxy was closed.
    pub fn on_close(&mut self, key: SocketKey) -> bool {
        self.tracked.retain(|t| t.key != key);
        let Some(s) = self.slot_mut(key) else { return false };
        s.key = None;
        s.rx.clear();
        let port = s.local.port();
        self.udp_ports.release(port);
        true
    }

    /// A bsd:u session closed (game exit or crash: its fds get no Close).
    /// Forgets its fds and frees their proxies and ports, as the C++
    /// `~BsdMitmService` does; without it the tracked table fills up over
    /// game launches and new sockets are never proxied.
    pub fn on_session_closed(&mut self, session_id: u32) {
        let ours = |k: SocketKey| k >> 32 == u64::from(session_id);
        for s in self.slots.iter_mut().filter(|s| s.key.is_some_and(ours)) {
            s.key = None;
            s.rx.clear();
            self.udp_ports.release(s.local.port());
        }
        self.tracked.retain(|t| !ours(t.key));
    }

    /// Bind. `real_radio`: the game's Local Wireless went to the real radio
    /// (ZR bypass), so its INADDR_ANY binds stay real.
    pub fn on_bind(&mut self, key: SocketKey, addr: &SockAddrIn, real_radio: bool) -> Decision<'static> {
        let any = addr.sin_addr == 0;
        let proxy_bind = is_ldn_addr(addr.addr_ryujinx()) || (any && self.local_ip != 0);
        let udp = self.tracked(key).is_some_and(|t| t.sock_type == bsd::SOCK_DGRAM);
        if (any && real_radio) || !proxy_bind || !udp {
            return Decision::Forward;
        }
        let bind = if any { SockAddrIn { sin_addr: self.local_ip.to_be(), ..*addr } } else { *addr };
        match self.create_bound(key, bind) {
            Err(e) => Decision::Reply(e.wrapping_neg()),
            Ok(()) if any => Decision::ReplyAndForward(0),
            Ok(()) => Decision::Reply(0),
        }
    }

    /// Connect: on a UDP fd to an LDN address, sets the default destination
    /// (binding a proxy first if needed).
    pub fn on_connect(&mut self, key: SocketKey, addr: &SockAddrIn) -> Decision<'static> {
        let Some(t) = self.tracked(key) else { return Decision::Forward };
        if !is_ldn_addr(addr.addr_ryujinx()) {
            return Decision::Forward;
        }
        if t.sock_type != bsd::SOCK_DGRAM {
            // TCP: ProxyConnect is not implemented; a real connect to
            // 10.114.x.x would hang until the stack gives up.
            return Decision::Reply(-ENETUNREACH);
        }
        if self.slot(key).is_none()
            && let Err(e) = self.create_bound(key, self.session_addr())
        {
            return Decision::Reply(e.wrapping_neg());
        }
        if let Some(s) = self.slot_mut(key) {
            s.remote = Some(*addr);
        }
        Decision::Reply(0)
    }

    /// SendTo. `dest` is `None` when the game passed no (AF_INET) address.
    pub fn on_sendto<'a>(&mut self, key: SocketKey, data: &'a [u8], dest: Option<&SockAddrIn>) -> Decision<'a> {
        let Some(t) = self.tracked(key) else { return Decision::Forward };
        let mut is_proxy = t.is_proxy;
        // First send to an LDN address from a plain UDP fd: auto-bind a proxy.
        if let Some(d) = dest
            && is_ldn_addr(d.addr_ryujinx())
            && !t.is_proxy
            && t.sock_type == bsd::SOCK_DGRAM
        {
            if let Err(e) = self.create_bound(key, self.session_addr()) {
                return Decision::Reply(e.wrapping_neg());
            }
            is_proxy = true;
        }
        // Internet destinations use the real socket even on a proxied fd.
        if !is_proxy || dest.is_some_and(|d| !is_proxy_destination(d.addr_ryujinx())) {
            return Decision::Forward;
        }
        match dest {
            Some(d) => self.emit(key, data, Some(*d)),
            None => self.emit(key, data, None),
        }
    }

    /// Send / Write.
    pub fn on_send<'a>(&mut self, key: SocketKey, data: &'a [u8]) -> Decision<'a> {
        if self.slot(key).is_none() && !self.is_gone(key) {
            return Decision::Forward;
        }
        self.emit(key, data, None)
    }

    /// Builds the ProxyData for a proxy send; `dest` None = connected peer.
    fn emit<'a>(&self, key: SocketKey, data: &'a [u8], dest: Option<SockAddrIn>) -> Decision<'a> {
        let Some(s) = self.slot(key) else { return Decision::Reply(-ENETDOWN) };
        let Some(dest) = dest.or(s.remote) else { return Decision::Reply(-ENOTCONN) };
        if s.shut_wr {
            return Decision::Reply(-EINVAL);
        }
        let Some(len) = u32::try_from(data.len()).ok().filter(|_| data.len() <= MAX_PAYLOAD) else {
            return Decision::Reply(-EMSGSIZE);
        };
        // A socket bound before the session had an IP sends with the current one.
        let src = match s.local.addr_ryujinx() {
            0 => self.local_ip,
            ip => ip,
        };
        let info = ProxyInfo {
            source_ipv4: src,
            source_port: s.local.port(),
            dest_ipv4: dest.addr_ryujinx(),
            dest_port: dest.port(),
            protocol: ProtocolType::Udp.raw(),
        };
        Decision::Emit { header: ProxyDataHeader { info, data_length: len }, payload: data }
    }

    /// RecvFrom: copies the oldest datagram into `out`. Never blocks.
    pub fn on_recvfrom(&mut self, key: SocketKey, out: &mut [u8], flags: i32) -> RecvDecision {
        let non_blocking = self.tracked(key).is_some_and(|t| t.non_blocking) || flags & bsd::MSG_DONTWAIT != 0;
        let limit_ns = self.tracked(key).map_or(0, |t| t.rcv_timeout_ns);
        let gone = self.is_gone(key);
        let Some(s) = self.slot_mut(key) else {
            return if gone { RecvDecision::Reply(-ENETDOWN) } else { RecvDecision::Forward };
        };
        if s.shut_rd {
            return RecvDecision::Reply(0);
        }
        if let Some((full, meta)) = s.rx.front(out) {
            if flags & bsd::MSG_PEEK == 0 {
                s.rx.pop();
            }
            return RecvDecision::Data { len: full.min(out.len()), from: SockAddrIn::from_ryujinx(meta.src_ip, meta.src_port) };
        }
        if non_blocking {
            return RecvDecision::Reply(-EAGAIN);
        }
        RecvDecision::Wait { limit_ns: if limit_ns > 0 { limit_ns.min(MAX_BLOCK_NS) } else { MAX_BLOCK_NS } }
    }

    /// Recv / Read: like recvfrom, but only on a connected socket.
    pub fn on_recv(&mut self, key: SocketKey, out: &mut [u8], flags: i32) -> RecvDecision {
        match self.slot(key) {
            Some(s) if s.remote.is_none() => RecvDecision::Reply(-ENOTCONN),
            _ => self.on_recvfrom(key, out, flags),
        }
    }

    /// GetSockName: `Some` for a proxy (network order), `None` = forward.
    pub fn on_getsockname(&self, key: SocketKey) -> Option<SockAddrIn> {
        self.slot(key).map(|s| s.local)
    }

    /// GetPeerName: `None` = forward; `Err(errno)` when not connected.
    pub fn on_getpeername(&self, key: SocketKey) -> Option<Result<SockAddrIn, i32>> {
        self.slot(key).map(|s| s.remote.ok_or(ENOTCONN))
    }

    /// Fcntl: records F_SETFL's O_NONBLOCK. Always forward the call too.
    pub fn on_fcntl(&mut self, key: SocketKey, cmd: i32, arg: i32) {
        if cmd == bsd::F_SETFL
            && let Some(t) = self.tracked_mut(key)
        {
            t.non_blocking = arg & bsd::O_NONBLOCK != 0;
        }
    }

    /// Ioctl. FIONBIO (`arg` = its int input) is recorded and forwarded
    /// (`None`). FIONREAD on a proxy returns `Some(queued payload bytes)`:
    /// write it to the output buffer and reply 0. `None` = forward.
    pub fn on_ioctl(&mut self, key: SocketKey, request: u32, arg: Option<i32>) -> Option<i32> {
        if request == bsd::FIONBIO {
            if let (Some(v), Some(t)) = (arg, self.tracked_mut(key)) {
                t.non_blocking = v != 0;
            }
            return None;
        }
        let s = self.slot(key).filter(|_| request == bsd::FIONREAD)?;
        Some(i32::try_from(s.rx.payload_bytes()).unwrap_or(i32::MAX))
    }

    /// SetSockOpt. SO_BROADCAST and SO_RCVTIMEO are remembered for a proxy
    /// made later; on a proxy every option is answered here.
    pub fn on_setsockopt(&mut self, key: SocketKey, level: i32, name: i32, optval: &[u8]) -> Decision<'static> {
        let int = optval.get(..4).and_then(|b| b.try_into().ok()).map(i32::from_le_bytes);
        let parsed = match (level, name) {
            (bsd::SOL_SOCKET, bsd::SO_BROADCAST) => Some(int.map(|v| (Some(v != 0), None))),
            (bsd::SOL_SOCKET, bsd::SO_RCVTIMEO) => Some(bsd::timeval_ns(optval).map(|ns| (None, Some(ns)))),
            _ => None,
        };
        if let (Some(Some((bcast, tmo))), Some(t)) = (parsed, self.tracked_mut(key)) {
            t.broadcast = bcast.unwrap_or(t.broadcast);
            t.rcv_timeout_ns = tmo.unwrap_or(t.rcv_timeout_ns);
        }
        match (self.slot(key), parsed) {
            (None, _) => Decision::Forward,
            (Some(_), Some(None)) => Decision::Reply(-EINVAL),
            // Everything else is accepted and ignored: there is no real socket.
            (Some(_), _) => Decision::Reply(0),
        }
    }

    /// GetSockOpt on a proxy: `Some(Ok(int value))` / `Some(Err(errno))`; `None` = forward.
    pub fn on_getsockopt(&self, key: SocketKey, level: i32, name: i32) -> Option<Result<i32, i32>> {
        self.slot(key)?;
        let t = self.tracked(key);
        Some(match (level, name) {
            (bsd::SOL_SOCKET, bsd::SO_TYPE) => Ok(t.map_or(bsd::SOCK_DGRAM, |t| t.sock_type)),
            (bsd::SOL_SOCKET, bsd::SO_ERROR) => Ok(0),
            (bsd::SOL_SOCKET, bsd::SO_BROADCAST) => Ok(i32::from(t.is_some_and(|t| t.broadcast))),
            _ => Err(ENOPROTOOPT),
        })
    }

    /// Shutdown on a proxy (this is how a game unblocks its receiver).
    pub fn on_shutdown(&mut self, key: SocketKey, how: i32) -> Decision<'static> {
        let Some(s) = self.slot_mut(key) else { return Decision::Forward };
        let (rd, wr) = match how {
            bsd::SHUT_RD => (true, false),
            bsd::SHUT_WR => (false, true),
            bsd::SHUT_RDWR => (true, true),
            _ => return Decision::Reply(-EINVAL),
        };
        s.shut_rd |= rd;
        s.shut_wr |= wr;
        Decision::Reply(0)
    }

    /// Poll/Select readiness of one fd.
    pub fn poll_state(&self, key: SocketKey) -> PollState {
        match self.slot(key) {
            Some(s) => PollState::Proxy { readable: !s.rx.is_empty() || s.shut_rd },
            None if self.is_gone(key) => PollState::Gone,
            None => PollState::Real,
        }
    }

    // ---- relay ----------------------------------------------------------

    /// A ProxyData from the relay. Unicast goes to the socket bound to the
    /// destination port and IP (or INADDR_ANY); broadcast to **every** socket
    /// on the port. With no match it waits in the pending ring for a bind.
    /// Returns the number of sockets it was queued on.
    pub fn on_proxy_data(&mut self, header: &ProxyDataHeader, payload: &[u8]) -> usize {
        let ProxyDataHeader { info, data_length } = *header;
        if info.protocol != ProtocolType::Udp.raw()
            || usize::try_from(data_length).ok() != Some(payload.len())
            || payload.len() > MAX_PAYLOAD
        {
            self.stats.dropped = self.stats.dropped.wrapping_add(1);
            return 0;
        }
        let meta = Meta { src_ip: info.source_ipv4, src_port: info.source_port, dst_ip: info.dest_ipv4, dst_port: info.dest_port };
        let broadcast = self.is_broadcast(meta.dst_ip);
        let mut evicted = 0usize;
        let mut queued = 0usize;
        for s in self.slots.iter_mut().filter(|s| s.accepts(&meta, broadcast)) {
            if let Some(n) = s.rx.push(meta, payload) {
                evicted = evicted.saturating_add(n);
                queued = queued.saturating_add(1);
            }
        }
        if queued > 0 {
            self.stats.delivered = self.stats.delivered.wrapping_add(1);
        } else if let Some(n) = self.pending.push(meta, payload) {
            evicted = evicted.saturating_add(n);
            self.stats.pending = self.stats.pending.wrapping_add(1);
        }
        self.stats.evicted = self.stats.evicted.wrapping_add(u32::try_from(evicted).unwrap_or(u32::MAX));
        queued
    }
}
