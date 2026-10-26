//! The bsd:u MitM service object and its handler layer.
//!
//! Every call is forwarded to the real bsd:u asynchronously (server/forward.rs)
//! and the request is deferred until the reply arrives, so a blocking call on
//! a real socket never blocks this server thread. Only the proxied-socket
//! paths are answered here, by the core router (`router_impl`).
//!
//! The real session: nx's manager calls AtmosphereAcknowledgeMitmSession when
//! it accepts a session, keeps the returned forward session in the holder
//! (clones get a clone of it) and hands it to us per request as
//! `ServerContext::mitm_forward`. Our own sockets (relay connection) use a
//! separate `bsd:s` session opened with nx's client (`service::bsd`); bsd:s is
//! not MitM'd, and our program id is not an application id, so they never
//! come back here.
// Raw IPC/SVC calls (async forwarding, handle plumbing); each block carries a SAFETY comment.
#![allow(unsafe_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU32, Ordering};

use ldn_tunnel_core::router::bsd::errno::{EAGAIN, ENETUNREACH};
use ldn_tunnel_core::router::{Decision, PollState, RecvDecision, SockAddrIn, SocketKey, socket_key};
use nx::ipc::client::IClientObject;
use nx::ipc::server::{
    Deferral, IMitmServerObject, IMitmService, ISessionObject, ServerContext, ServerManager,
};
use nx::ipc::sf::bsd::{BsdResult, BsdTimeout, IBsdClient, SocketAddrRepr};
use nx::ipc::sf::sm::mitm::MitmProcessInfo;
use nx::ipc::sf::sm::mitm::rc::ResultShouldForwardToSession;
use nx::ipc::sf::{
    self, CopyHandle, InAutoSelectBuffer, OutAutoSelectBuffer, ProcessId,
};
use nx::ipc::{CommandProtocol, ObjectInfo};
use nx::result::{Result, ResultBase};
use nx::service::bsd::UserBsdService;
use nx::sync::Mutex;
use nx::{arm, svc};
use zerocopy::IntoBytes;

use super::ifaces::{FdSet, IBsdMitmServer, LibraryConfig, PollFd, SelectTimeval};
use super::router_impl::{self as router, with};
use crate::server::forward::{self, Forward};
use crate::state::STATE;

/// Pointer buffer of the bsd:u manager (the C++ module's 4 KiB); also the
/// reply receive buffer of each forward.
pub const POINTER_BUFFER_SIZE: usize = 0x1000;

/// Intercepted bsd:u sessions (clones included) at once. svcWaitSynchronization
/// takes 64 handles: port + query session + rx event + per session its handle
/// and, while a forward is in flight, its async event: 3 + 2 x 30 = 63.
/// Sessions past the cap get the real bsd:u (they work, unproxied).
const MAX_SESSIONS: u32 = 30;

const APPLICATION_ID: core::ops::RangeInclusive<u64> = 0x0100_0000_0001_0000..=0x01FF_FFFF_FFFF_FFFF;
const POLLIN: i16 = 0x1;
const POLLOUT: i16 = 0x4;
const POLLERR: i16 = 0x8;
const POLLHUP: i16 = 0x10;
const POLLRDNORM: i16 = 0x40;
/// A wait over real and proxied fds re-polls the real ones this often.
const MIXED_SLICE_NS: u64 = 10_000_000;

/// bsd:u sessions per process, as the C++ MitmPidCounts: a game's first
/// session goes to the real service, later ones are intercepted.
static MITM_PIDS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());
/// Intercepted sessions seen so far (see MAX_SESSIONS).
static LIVE: AtomicU32 = AtomicU32::new(0);
static NEXT_CLIENT: AtomicU32 = AtomicU32::new(1);

/// Registers the bsd:u MitM (and its ShouldMitm query session) on `manager`.
pub fn register(manager: &mut ServerManager<POINTER_BUFFER_SIZE>) -> Result<()> {
    manager.register_mitm_service_server::<BsdMitmService>()
}

/// fd_set bit helpers: an fd past the set (cannot happen: nfds is clamped to 1024) reads as 0
/// and is ignored on write.
fn bit(set: &FdSet, fd: usize) -> bool {
    set.get(fd / 64).is_some_and(|w| (w >> (fd % 64)) & 1 != 0)
}

fn set_bit(set: &mut FdSet, fd: usize) {
    if let Some(w) = set.get_mut(fd / 64) {
        *w |= 1u64 << (fd % 64);
    }
}

fn clear_bit(set: &mut FdSet, fd: usize) {
    if let Some(w) = set.get_mut(fd / 64) {
        *w &= !(1u64 << (fd % 64));
    }
}

fn forward<T>() -> Result<T> {
    ResultShouldForwardToSession::make_err()
}

/// Router result (`>= 0` or `-errno`) as bsd:u's (ret, errno).
fn reply(r: i32) -> (i32, i32) {
    if r < 0 { (-1, r.wrapping_neg()) } else { (r, 0) }
}

fn deadline_after(ns: u64) -> u64 {
    // Clamp so the tick conversion can't overflow (~2 weeks).
    arm::get_system_tick().saturating_add(arm::nanoseconds_to_ticks(ns.min(1 << 50)))
}

fn in_bytes<'a>(buf: &'a InAutoSelectBuffer<u8>) -> &'a [u8] {
    if buf.get_address().is_null() {
        return &[];
    }
    // SAFETY: nx validated the descriptor; the data is in our pointer buffer
    // or a kernel mapping that lives until we reply.
    unsafe { core::slice::from_raw_parts(buf.get_address(), buf.get_size()) }
}

fn out_bytes<'a>(buf: &'a mut OutAutoSelectBuffer<u8>) -> &'a mut [u8] {
    if buf.get_address().is_null() {
        return &mut [];
    }
    // SAFETY: as in_bytes; nx placed out pointers apart from the in data.
    unsafe { core::slice::from_raw_parts_mut(buf.get_address(), buf.get_size()) }
}

/// Copies `bytes` into the game's out buffer; the length copied.
fn put(out: &mut [u8], bytes: &[u8]) -> u32 {
    let n = out.len().min(bytes.len());
    for (o, b) in out.iter_mut().zip(bytes) {
        *o = *b;
    }
    n as u32
}

/// What to do once a forwarded call has completed.
#[derive(Default)]
enum Post {
    #[default]
    None,
    /// Our copy of RegisterClient's transfer memory handle.
    CloseHandle(svc::Handle),
    Socket { domain: i32, ty: i32, protocol: i32 },
}

/// The request being dispatched (set by the ISessionObject wrapper).
#[derive(Default)]
struct Current {
    handle: svc::Handle,
    forward: ObjectInfo,
    defer: Option<Deferral>,
    post: Post,
}

pub struct BsdMitmService {
    pid: u64,
    /// The router's session id: fds are per bsd:u client, not per process.
    client: u32,
    /// Session handles of this object (clones share it) counted in LIVE.
    sessions: Vec<svc::Handle>,
    /// Forwards in flight, by session handle (one per session at most).
    inflight: Vec<(svc::Handle, Forward, Post)>,
    /// The forward whose reply was sent last; its buffers back that reply.
    retired: Option<Forward>,
    /// Deadline (ticks) of a proxied wait, by session handle, kept across resumes.
    waits: Vec<(svc::Handle, u64)>,
    cur: Current,
    /// Command ids this client sent that the interface does not declare (logged once each).
    unknown_cmds: Vec<u32>,
    /// First datagram out to / in from the relay logged (once per client).
    logged_send: bool,
    logged_recv: bool,
    /// fds whose recv got data with an empty out buffer (logged once each).
    empty_recv: Vec<i32>,
}

impl BsdMitmService {
    fn key(&self, fd: i32) -> SocketKey {
        socket_key(self.client, fd)
    }

    /// Deadline of the current wait, fixed at its first dispatch.
    fn wait_deadline(&mut self, timeout_ns: Option<u64>) -> u64 {
        let handle = self.cur.handle;
        if let Some(&(_, deadline)) = self.waits.iter().find(|w| w.0 == handle) {
            return deadline;
        }
        let deadline = timeout_ns.map_or(u64::MAX, deadline_after);
        self.waits.push((handle, deadline));
        deadline
    }

    /// Holds the current request until the router wakes it or `deadline`;
    /// with `mixed`, wakes every slice to re-poll the real fds.
    fn defer(&mut self, deadline: u64, mixed: bool) {
        let deadline = if mixed { deadline.min(deadline_after(MIXED_SLICE_NS)) } else { deadline };
        self.cur.defer = Some(Deferral { wait_handle: router::rx_event(), deadline });
    }

    /// The real bsd:u as a client, for calls that answer at once.
    fn real(&self) -> ManuallyDrop<UserBsdService> {
        // Borrowed: the server manager owns and closes the forward session.
        ManuallyDrop::new(UserBsdService::new(sf::Session::from(self.cur.forward)))
    }

    fn decide(&mut self, decision: Decision) -> Result<(i32, i32)> {
        match decision {
            Decision::Forward => forward(),
            Decision::Reply(r) => Ok(reply(r)),
            // Only bind returns this; `bind` handles it.
            Decision::ReplyAndForward(r) => Ok(reply(r)),
            Decision::Emit { header, payload } => Ok(if router::emit(&header, payload) {
                if !core::mem::replace(&mut self.logged_send, true) {
                    log!(Info, "bsd: client {} first datagram to the relay ({} bytes)", self.client, payload.len());
                }
                (payload.len() as i32, 0)
            } else {
                (-1, ENETUNREACH)
            }),
        }
    }

    /// `buf_len`: size of the game's data buffer, `fd`: for the empty-buffer log.
    fn recv_reply(&mut self, decision: RecvDecision, fd: i32, buf_len: usize, from: &mut [u8]) -> Result<(i32, i32, u32)> {
        match decision {
            RecvDecision::Forward => forward(),
            RecvDecision::Reply(r) => {
                let (ret, errno) = reply(r);
                Ok((ret, errno, 0))
            }
            RecvDecision::Data { len, from: addr } => {
                if !core::mem::replace(&mut self.logged_recv, true) {
                    log!(Info, "bsd: client {} first datagram from the relay ({len} bytes)", self.client);
                }
                if buf_len == 0 && !self.empty_recv.contains(&fd) {
                    self.empty_recv.push(fd);
                    log!(Info, "bsd: client {} recv buffer empty (fd {fd}: B size 0 or out-pointer size 0)", self.client);
                }
                Ok((len as i32, 0, put(from, addr.as_bytes())))
            }
            RecvDecision::Wait { limit_ns } => {
                let deadline = self.wait_deadline(Some(limit_ns.max(0) as u64));
                if arm::get_system_tick() >= deadline {
                    return Ok((-1, EAGAIN, 0));
                }
                self.defer(deadline, false);
                Ok((0, 0, 0)) // not sent: the request is deferred
            }
        }
    }

    fn after_forward(&mut self, post: Post, replied: bool) {
        match post {
            Post::None => {}
            Post::CloseHandle(handle) => {
                let _ = svc::close_handle(handle);
            }
            Post::Socket { domain, ty, protocol } => {
                let fd = match forward::reply_raw() {
                    Some((0, out)) if replied => i32::from_le_bytes([out[0], out[1], out[2], out[3]]),
                    _ => return,
                };
                if fd >= 0 {
                    let key = self.key(fd);
                    if with(|r| r.on_socket(key, domain, ty, protocol)) {
                        log!(Info, "bsd: client {} fd {fd} tracked (type {ty})", self.client);
                    }
                }
            }
        }
    }
}

impl IMitmServerObject for BsdMitmService {
    fn new(info: MitmProcessInfo) -> Self {
        Self {
            pid: info.process_id,
            client: NEXT_CLIENT.fetch_add(1, Ordering::Relaxed),
            sessions: Vec::new(),
            inflight: Vec::new(),
            retired: None,
            waits: Vec::new(),
            cur: Current::default(),
            unknown_cmds: Vec::new(),
            logged_send: false,
            logged_recv: false,
            empty_recv: Vec::new(),
        }
    }
}

impl IMitmService for BsdMitmService {
    fn get_name() -> sf::sm::ServiceName {
        sf::sm::ServiceName::new("bsd:u")
    }

    fn should_mitm(info: MitmProcessInfo) -> bool {
        let program = info.program_id.0;
        // Applications only; homebrew launched over a game (HBL override) keeps the real bsd:u.
        if !APPLICATION_ID.contains(&program) || info.override_flags & 1 != 0 {
            return false;
        }
        if !crate::config_io::is_whitelisted(program) {
            return false;
        }
        if LIVE.load(Ordering::Relaxed) >= MAX_SESSIONS {
            log!(Warning, "bsd: {MAX_SESSIONS} sessions intercepted, pid {} gets the real bsd:u", info.process_id);
            return false;
        }
        let mut pids = MITM_PIDS.lock();
        let count = pids.entry(info.process_id).or_insert(0);
        *count = count.saturating_add(1);
        if *count > 1 {
            return true;
        }
        // A new game: entries left at 1 belong to processes that have exited.
        pids.retain(|&pid, &mut n| pid == info.process_id || n != 1);
        false
    }
}

impl Drop for BsdMitmService {
    fn drop(&mut self) {
        // The client's fds get no Close (game exit or crash), as C++ ~BsdMitmService.
        with(|r| r.on_session_closed(self.client));
        // Last clone of an intercepted session gone: back to the uncounted first one.
        if let Some(n) = MITM_PIDS.lock().get_mut(&self.pid)
            && *n > 1
        {
            *n = n.saturating_sub(1);
        }
    }
}

impl ISessionObject for BsdMitmService {
    fn try_handle_request_by_id(
        &mut self,
        req_id: u32,
        protocol: CommandProtocol,
        ctx: &mut ServerContext,
    ) -> Option<Result<()>> {
        let handle = ctx.ctx.object_info.handle;
        // The manager replies right after each dispatch, so the last reply is out.
        self.retired = None;
        if !self.sessions.contains(&handle) {
            self.sessions.push(handle);
            LIVE.fetch_add(1, Ordering::Relaxed);
            STATE.mitm_sessions.fetch_add(1, Ordering::Relaxed);
        }

        // The session cannot send while its forward is in flight: this is its resume.
        if let Some(i) = self.inflight.iter().position(|f| f.0 == handle) {
            let (_, mut fwd, post) = self.inflight.swap_remove(i);
            let result = fwd.finish();
            self.after_forward(post, result.is_ok());
            self.retired = Some(fwd);
            return Some(result);
        }

        if !ctx.resumed {
            self.waits.retain(|w| w.0 != handle);
        }
        let msg = forward::snapshot();
        self.cur = Current { handle, forward: ctx.mitm_forward, ..Default::default() };

        match <Self as IBsdMitmServer>::try_handle_request_by_id(self, req_id, protocol, ctx) {
            Some(Ok(())) => {
                ctx.defer = self.cur.defer.take();
                Some(Ok(()))
            }
            Some(Err(rc)) if !ResultShouldForwardToSession::matches(rc) => {
                let post = core::mem::take(&mut self.cur.post);
                self.after_forward(post, false);
                Some(Err(rc))
            }
            // A handler asked to forward, or the command isn't declared (or is
            // version-gated off): send it to the real bsd:u without waiting.
            result => {
                if result.is_none() && !self.unknown_cmds.contains(&req_id) {
                    self.unknown_cmds.push(req_id);
                    log!(Info, "bsd: client {} sent cmd {req_id}, forwarded untouched", self.client);
                }
                let post = core::mem::take(&mut self.cur.post);
                Some(match Forward::start(&msg, ctx.mitm_forward.handle, POINTER_BUFFER_SIZE) {
                    Ok(fwd) => {
                        ctx.defer = Some(Deferral { wait_handle: fwd.event(), deadline: u64::MAX });
                        self.inflight.push((handle, fwd, post));
                        Ok(())
                    }
                    Err(rc) => {
                        self.after_forward(post, false);
                        Err(rc)
                    }
                })
            }
        }
    }

    fn on_session_closed(&mut self, handle: svc::Handle) {
        if let Some(i) = self.sessions.iter().position(|&h| h == handle) {
            self.sessions.swap_remove(i);
            LIVE.fetch_sub(1, Ordering::Relaxed);
            STATE.mitm_sessions.fetch_sub(1, Ordering::Relaxed);
        }
        self.waits.retain(|w| w.0 != handle);
        if let Some(i) = self.inflight.iter().position(|f| f.0 == handle) {
            let (_, fwd, post) = self.inflight.swap_remove(i);
            drop(fwd);
            self.after_forward(post, false);
        }
    }
}

impl IBsdMitmServer for BsdMitmService {
    fn register_client(
        &mut self,
        _config: LibraryConfig,
        _pid: ProcessId,
        _tmem_size: u64,
        tmem: CopyHandle,
    ) -> Result<u64> {
        // The forwarded message still names our copy of the handle; close it once sent.
        self.cur.post = Post::CloseHandle(tmem.handle);
        forward()
    }

    fn socket(&mut self, domain: i32, ty: i32, protocol: i32) -> Result<(i32, i32)> {
        self.cur.post = Post::Socket { domain, ty, protocol };
        forward()
    }

    fn socket_exempt(&mut self, domain: i32, ty: i32, protocol: i32) -> Result<(i32, i32)> {
        self.socket(domain, ty, protocol)
    }

    fn select(
        &mut self,
        nfds: i32,
        timeout: SelectTimeval,
        readfds_in: InAutoSelectBuffer<u8>,
        writefds_in: InAutoSelectBuffer<u8>,
        errorfds_in: InAutoSelectBuffer<u8>,
        mut readfds_out: OutAutoSelectBuffer<u8>,
        mut writefds_out: OutAutoSelectBuffer<u8>,
        mut errorfds_out: OutAutoSelectBuffer<u8>,
    ) -> Result<(i32, i32)> {
        let nfds = nfds.clamp(0, 1024) as usize;
        let mut sets: [FdSet; 3] = [[0; 16]; 3];
        for (set, buf) in sets.iter_mut().zip([&readfds_in, &writefds_in, &errorfds_in]) {
            for (word, chunk) in set.iter_mut().zip(in_bytes(buf).as_chunks::<8>().0) {
                *word = u64::from_le_bytes(*chunk);
            }
        }
        let wanted: Vec<usize> = (0..nfds).filter(|&fd| sets.iter().any(|s| bit(s, fd))).collect();
        let proxied: Vec<(usize, PollState)> = with(|r| {
            wanted
                .iter()
                .map(|&fd| (fd, r.poll_state(self.key(fd as i32))))
                .filter(|(_, s)| *s != PollState::Real)
                .collect()
        });
        if proxied.is_empty() {
            return forward();
        }
        let mixed = proxied.len() < wanted.len();

        let mut ready = [[0; 16]; 3];
        if mixed {
            let mut real = sets;
            for set in real.iter_mut() {
                for &(fd, _) in &proxied {
                    clear_bit(set, fd);
                }
            }
            let [ri, wi, ei] = real;
            let [r, w, e] = &mut real;
            let result = self.real().select(
                nfds as u32,
                BsdTimeout::timeout(core::time::Duration::ZERO),
                InAutoSelectBuffer::from_var(&ri),
                InAutoSelectBuffer::from_var(&wi),
                InAutoSelectBuffer::from_var(&ei),
                OutAutoSelectBuffer::from_mut_var(r),
                OutAutoSelectBuffer::from_mut_var(w),
                OutAutoSelectBuffer::from_mut_var(e),
            )?;
            if let BsdResult::Err(errno) = result {
                return Ok((-1, errno));
            }
            ready = real;
        }
        for (fd, state) in proxied {
            // Datagram sockets: always writable; a gone proxy reports ready so
            // the game's next call gets ENETDOWN.
            let (readable, writable) = match state {
                PollState::Proxy { readable } => (readable, true),
                _ => (true, true),
            };
            for ((want, out), on) in sets.iter().zip(ready.iter_mut()).zip([readable, writable]) {
                if on && bit(want, fd) {
                    set_bit(out, fd);
                }
            }
        }
        let count: u32 = ready.iter().flatten().map(|w| w.count_ones()).sum();

        let timeout_ns = (!timeout.is_null).then(|| {
            (timeout.sec.max(0) as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add((timeout.usec.max(0) as u64).saturating_mul(1000))
        });
        let deadline = self.wait_deadline(timeout_ns);
        if count == 0 && timeout_ns != Some(0) && arm::get_system_tick() < deadline {
            self.defer(deadline, mixed);
            return Ok((0, 0));
        }
        let outs = [out_bytes(&mut readfds_out), out_bytes(&mut writefds_out), out_bytes(&mut errorfds_out)];
        for (set, out) in ready.iter().zip(outs) {
            for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(set) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
        }
        Ok((count as i32, 0))
    }

    fn poll(
        &mut self,
        nfds: i32,
        timeout: i32,
        fds_in: InAutoSelectBuffer<u8>,
        mut fds_out: OutAutoSelectBuffer<u8>,
    ) -> Result<(i32, i32)> {
        let input = in_bytes(&fds_in);
        let n = (nfds.max(0) as usize).min(input.len() / 8 /* size_of::<PollFd>(), asserted in ifaces.rs */);
        // SAFETY: n entries fit in `input`; PollFd is plain data, read unaligned.
        let mut fds: Vec<PollFd> =
            (0..n).map(|i| unsafe { input.as_ptr().cast::<PollFd>().add(i).read_unaligned() }).collect();
        let states: Vec<PollState> = with(|r| {
            fds.iter().map(|p| if p.fd < 0 { PollState::Real } else { r.poll_state(self.key(p.fd)) }).collect()
        });
        if states.iter().all(|s| *s == PollState::Real) {
            return forward();
        }
        let mixed = fds.iter().zip(&states).any(|(p, s)| p.fd >= 0 && *s == PollState::Real);

        if mixed {
            // Real fds only, no wait; bsd ignores negative fds.
            let mut real: Vec<PollFd> = fds
                .iter()
                .zip(&states)
                .map(|(p, s)| PollFd { fd: if *s == PollState::Real { p.fd } else { -1 }, ..*p })
                .collect();
            // SAFETY: ifaces::PollFd and nx's PollFd are both repr(C) {i32, 2 bytes, 2 bytes}.
            let real_in = real.clone();
            let (buf_in, buf_out) = unsafe {
                (
                    InAutoSelectBuffer::from_ptr(real_in.as_ptr().cast::<nx::ipc::sf::bsd::PollFd>(), real_in.len()),
                    OutAutoSelectBuffer::from_mut_ptr(real.as_mut_ptr().cast::<nx::ipc::sf::bsd::PollFd>(), real.len()),
                )
            };
            if let BsdResult::Err(errno) = self.real().poll(real.len() as u32, 0, buf_in, buf_out)? {
                return Ok((-1, errno));
            }
            for (p, r) in fds.iter_mut().zip(&real) {
                p.revents = r.revents;
            }
        }
        for (p, s) in fds.iter_mut().zip(&states) {
            match s {
                PollState::Real => {}
                PollState::Gone => p.revents = POLLERR | POLLHUP,
                PollState::Proxy { readable } => {
                    p.revents = p.events & (POLLOUT | if *readable { POLLIN | POLLRDNORM } else { 0 });
                }
            }
        }
        let ready = fds.iter().filter(|p| p.revents != 0).count();

        let deadline = self.wait_deadline((timeout >= 0).then(|| (timeout as u64).saturating_mul(1_000_000)));
        if ready == 0 && timeout != 0 && arm::get_system_tick() < deadline {
            self.defer(deadline, mixed);
            return Ok((0, 0));
        }
        let out = out_bytes(&mut fds_out);
        for (i, p) in fds.iter().enumerate().take(out.len() / 8 /* size_of::<PollFd>() */) {
            // SAFETY: entry i fits in `out` (checked by take); unaligned write of plain data.
            unsafe { out.as_mut_ptr().cast::<PollFd>().add(i).write_unaligned(*p) };
        }
        Ok((ready as i32, 0))
    }

    fn recv(&mut self, fd: i32, flags: i32, mut buf: OutAutoSelectBuffer<u8>) -> Result<(i32, i32)> {
        let key = self.key(fd);
        let out = out_bytes(&mut buf);
        let buf_len = out.len();
        let d = with(|r| r.on_recv(key, out, flags));
        self.recv_reply(d, fd, buf_len, &mut []).map(|(ret, errno, _)| (ret, errno))
    }

    fn recv_from(
        &mut self,
        fd: i32,
        flags: i32,
        mut buf: OutAutoSelectBuffer<u8>,
        mut addr: OutAutoSelectBuffer<u8>,
    ) -> Result<(i32, i32, u32)> {
        let key = self.key(fd);
        let out = out_bytes(&mut buf);
        let buf_len = out.len();
        let d = with(|r| r.on_recvfrom(key, out, flags));
        self.recv_reply(d, fd, buf_len, out_bytes(&mut addr))
    }

    fn send(&mut self, fd: i32, _flags: i32, buf: InAutoSelectBuffer<u8>) -> Result<(i32, i32)> {
        let key = self.key(fd);
        let data = in_bytes(&buf);
        let d = with(|r| r.on_send(key, data));
        self.decide(d)
    }

    fn send_to(
        &mut self,
        fd: i32,
        _flags: i32,
        buf: InAutoSelectBuffer<u8>,
        addr: InAutoSelectBuffer<u8>,
    ) -> Result<(i32, i32)> {
        let key = self.key(fd);
        let (data, dest) = (in_bytes(&buf), SockAddrIn::from_bytes(in_bytes(&addr)));
        let d = with(|r| r.on_sendto(key, data, dest.as_ref()));
        self.decide(d)
    }

    fn accept(&mut self, _fd: i32, _addr: OutAutoSelectBuffer<u8>) -> Result<(i32, i32, u32)> {
        forward()
    }

    fn bind(&mut self, fd: i32, addr: InAutoSelectBuffer<u8>) -> Result<(i32, i32)> {
        let Some(sa) = SockAddrIn::from_bytes(in_bytes(&addr)) else { return forward() };
        let key = self.key(fd);
        // ponytail: real_radio is false until the ldn:u side records which
        // games went to the real radio (C++ SharedState::IsRealWirelessPid).
        let d = with(|r| r.on_bind(key, &sa, false));
        if d != Decision::Forward {
            log!(Info, "bsd: client {} fd {fd} bound to the LDN proxy (port {})", self.client, sa.port());
        }
        match d {
            Decision::ReplyAndForward(r) => {
                // INADDR_ANY: the real socket binds too, so internet traffic
                // keeps working; its result is ignored. Bind answers at once.
                // SAFETY: `sa` is 16 bytes like nx's SocketAddrRepr and outlives the call.
                let real_addr = unsafe { InAutoSelectBuffer::from_ptr(core::ptr::from_ref(&sa).cast::<SocketAddrRepr>(), 1) };
                let _ = self.real().bind(fd, real_addr);
                Ok(reply(r))
            }
            d => self.decide(d),
        }
    }

    fn connect(&mut self, fd: i32, addr: InAutoSelectBuffer<u8>) -> Result<(i32, i32)> {
        let Some(sa) = SockAddrIn::from_bytes(in_bytes(&addr)) else { return forward() };
        let key = self.key(fd);
        let d = with(|r| r.on_connect(key, &sa));
        self.decide(d)
    }

    fn get_peer_name(&mut self, fd: i32, mut addr: OutAutoSelectBuffer<u8>) -> Result<(i32, i32, u32)> {
        let key = self.key(fd);
        match with(|r| r.on_getpeername(key)) {
            Some(Ok(sa)) => Ok((0, 0, put(out_bytes(&mut addr), sa.as_bytes()))),
            Some(Err(errno)) => Ok((-1, errno, 0)),
            None => forward(),
        }
    }

    fn get_sock_name(&mut self, fd: i32, mut addr: OutAutoSelectBuffer<u8>) -> Result<(i32, i32, u32)> {
        let key = self.key(fd);
        match with(|r| r.on_getsockname(key)) {
            Some(sa) => Ok((0, 0, put(out_bytes(&mut addr), sa.as_bytes()))),
            None => forward(),
        }
    }

    fn get_sock_opt(
        &mut self,
        fd: i32,
        level: i32,
        optname: i32,
        mut optval: OutAutoSelectBuffer<u8>,
    ) -> Result<(i32, i32, u32)> {
        let key = self.key(fd);
        match with(|r| r.on_getsockopt(key, level, optname)) {
            Some(Ok(v)) => Ok((0, 0, put(out_bytes(&mut optval), &v.to_le_bytes()))),
            Some(Err(errno)) => Ok((-1, errno, 0)),
            None => forward(),
        }
    }

    fn listen(&mut self, _fd: i32, _backlog: i32) -> Result<(i32, i32)> {
        forward()
    }

    fn ioctl(
        &mut self,
        fd: i32,
        request: u32,
        _bufcount: u32,
        in1: InAutoSelectBuffer<u8>,
        _in2: InAutoSelectBuffer<u8>,
        _in3: InAutoSelectBuffer<u8>,
        _in4: InAutoSelectBuffer<u8>,
        mut out1: OutAutoSelectBuffer<u8>,
        _out2: OutAutoSelectBuffer<u8>,
        _out3: OutAutoSelectBuffer<u8>,
        _out4: OutAutoSelectBuffer<u8>,
    ) -> Result<(i32, i32)> {
        let key = self.key(fd);
        let arg = in_bytes(&in1).first_chunk::<4>().map(|b| i32::from_le_bytes(*b));
        match with(|r| r.on_ioctl(key, request, arg)) {
            Some(v) => {
                put(out_bytes(&mut out1), &v.to_le_bytes());
                Ok((0, 0))
            }
            None => forward(),
        }
    }

    fn fcntl(&mut self, fd: i32, cmd: i32, arg: i32) -> Result<(i32, i32)> {
        let key = self.key(fd);
        with(|r| r.on_fcntl(key, cmd, arg));
        forward()
    }

    fn set_sock_opt(
        &mut self,
        fd: i32,
        level: i32,
        optname: i32,
        optval: InAutoSelectBuffer<u8>,
    ) -> Result<(i32, i32)> {
        let key = self.key(fd);
        let d = with(|r| r.on_setsockopt(key, level, optname, in_bytes(&optval)));
        self.decide(d)
    }

    fn shutdown(&mut self, fd: i32, how: i32) -> Result<(i32, i32)> {
        let key = self.key(fd);
        let d = with(|r| r.on_shutdown(key, how));
        if d != Decision::Forward {
            router::wake(); // a game shuts a socket down to unblock its receiver
        }
        self.decide(d)
    }

    fn write(&mut self, fd: i32, buf: InAutoSelectBuffer<u8>) -> Result<(i32, i32)> {
        self.send(fd, 0, buf)
    }

    fn read(&mut self, fd: i32, buf: OutAutoSelectBuffer<u8>) -> Result<(i32, i32)> {
        IBsdMitmServer::recv(self, fd, 0, buf)
    }

    fn close(&mut self, fd: i32) -> Result<(i32, i32)> {
        let key = self.key(fd);
        if with(|r| r.on_close(key)) {
            router::wake();
        }
        forward() // the real fd exists either way
    }

    fn register_client_shared(
        &mut self,
        _config: LibraryConfig,
        _pid: ProcessId,
        _tmem_size: u64,
    ) -> Result<u64> {
        forward()
    }
}
