//! The relay link: our `bsd:s` socket -> TLS -> WebSocket (`core::conn::Conn`), driven
//! for the LDN session (`ldn::session`, `ldn::outbox`), plus the status the overlay shows.
//! Port of network/client.cpp + wss_client.cpp; the loop order is the one in the
//! `ldn::session` module doc (= crates/core/tests/sim/console.rs).
//!
//! Two threads:
//! - the main thread ([`run`], its 128 KiB npdm stack: rustls needs > 48 KiB for a
//!   handshake) owns the link: session wishes, `Conn` timers, opening DNS/TCP/TLS, reading
//!   and delivering packets, remote log, status.
//! - `relay-tx` waits on the outbox event and sends what the session/router queued the
//!   moment it is queued (bsd `poll` cannot also wait on a kernel event, so the reading
//!   thread alone would add up to a tick of latency to every game packet).
//!
//! Updates (0xC1–0xC4, `core::conn::update_dl`) ride whatever link is up: a check after
//! a handshake (at most every 10 min, as the C++ update worker) and on the overlay's
//! CheckForUpdates, which opens a link of its own when no game holds one. Packets are sent
//! under `LINK`; the staging file work (append, hash, install) runs with `LINK` released.
//!
//! Locking:
//! - `LINK` (one nx mutex) holds the `Conn` and the TLS stream. Every TLS read/write and
//!   every `Conn` call happens under it (a TLS session cannot read and write at once). It
//!   is never held while waiting: the socket is polled and DNS/TCP/TLS opened outside it.
//! - `ldn::session` calls (which take the Session and Router locks) are made with `LINK`
//!   released; packets are copied out of the `Conn` first. `ldn::session` never calls back
//!   in here: it states wishes (`relay_request`) and queues packets (outbox).
//! - Under `LINK` we may take: the outbox queue (a leaf), the logger (`log!`, remote-log
//!   ring) and `STATE` setters. None of them calls into the relay.
#![forbid(unsafe_code)]

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering::Relaxed;

use embedded_io::{Read as _, Write as _};
use ldn_tunnel_core::cfg_types::ConnectionStatus;
use ldn_tunnel_core::config::Server;
use ldn_tunnel_core::conn::remote_log::{self, RemoteLog};
use ldn_tunnel_core::conn::update_dl::{self, CHUNK_HEADER, Progress, State as Dl, UpdateDl};
use ldn_tunnel_core::conn::{Action, Conn, ConnConfig, ConnectionState, Failure, Session};
use ldn_tunnel_core::config::Channel;
use ldn_tunnel_core::notify::Event;
use ldn_tunnel_core::update::ManifestResult;
use ldn_tunnel_core::wire::{PacketId, UpdateChannel};
use ldn_tunnel_tls::TlsStream;
use nx::sync::Mutex;
use nx::thread::{Builder, JoinHandle, ThreadPriority};

use crate::config_io;
use crate::ldn::{outbox, session};
use crate::net::socket::{self, BsdSocket, NetError};
use crate::net::{clock, dns, rng};
use crate::state::{check, uptime_ms, STATE};
use crate::update_io::{self, Stager};
use zerocopy::IntoBytes;

/// relay-tx only encrypts records (no handshake): a small heap stack.
// ponytail: not measured on hardware; raise if relay-tx ever overflows.
const TX_STACK: usize = 0x8000;
/// Same as the cfg thread (C++ os priority 10): above maintenance, below the MITMs. The
/// main thread is raised to it in [`run`] (npdm starts it at 42).
const PRIORITY: i32 = 38;
/// Reassembly buffer of the `Conn` (C++ `PacketBuffer<0x2000>`): the largest relay packet.
const RX_CAP: usize = 0x2000;
/// One outgoing frame: LdnHeader + the largest session/router payload + WebSocket header.
const OUT_CAP: usize = 12 + outbox::PAYLOAD_MAX + 14;
/// TLS plaintext read chunk.
const READ_CHUNK: usize = 0x1000;
/// How long the thread waits for the socket before it runs the timers again.
const TICK_MS: i32 = 100;
/// TCP connect, and each TLS handshake read (the `Conn` bounds the whole open at 5 s).
const IO_TIMEOUT_MS: i32 = 5000;
/// A CA bundle bigger than this is not read (C++ MAX_CA_FILE_SIZE is 64 KiB).
const MAX_CA: usize = 64 * 1024;
/// Automatic update checks: after a handshake, at most this often (C++ kCheckIntervalMs).
const CHECK_INTERVAL_MS: u64 = 10 * 60 * 1000;

type Tls = TlsStream<BsdSocket>;
// `Link::payload` also stages remote-log payloads.
const _: () = assert!(outbox::PAYLOAD_MAX >= remote_log::MAX_PAYLOAD);

struct Link {
    conn: Conn<RX_CAP>,
    /// The stream and its socket fd (polled outside `LINK`).
    tls: Option<(Tls, i32)>,
    out: [u8; OUT_CAP],
    /// Staging for one outbox payload / one remote-log payload.
    payload: [u8; outbox::PAYLOAD_MAX],
    remote: RemoteLog,
}

static LINK: Mutex<Option<Link>> = Mutex::new(None);

/// Registers our bsd:s client and starts `relay-tx`; then call [`run`] on the main
/// thread. Call after `ldn::start` (the outbox event must exist). Keep the handle: nx
/// frees a thread's stack when its handle drops.
pub fn start() -> nx::result::Result<JoinHandle<()>> {
    socket::initialize()?;
    // The relay assigns the session id and MAC in its Initialize answer; these are only
    // what the console proposes (C++ generate_mac_address: random, locally administered).
    let mut mac: [u8; 6] = rng::bytes();
    mac[0] = (mac[0] & 0xFE) | 0x02;
    *LINK.lock() = Some(Link {
        conn: Conn::new(ConnConfig::new(rng::bytes(), mac)),
        tls: None,
        out: [0; OUT_CAP],
        payload: [0; outbox::PAYLOAD_MAX],
        remote: RemoteLog::new(""),
    });
    Builder::new()
        .name("relay-tx")
        .priority(ThreadPriority::Set(PRIORITY))
        .stack_size(TX_STACK)
        .spawn(tx_loop)
}

/// The relay loop, on the calling (main) thread. Returns only if [`start`] did not run.
pub fn run() {
    let _ = nx::svc::set_thread_priority(nx::svc::CURRENT_THREAD_PSEUDO_HANDLE, PRIORITY);
    Relay::new().run();
}

/// relay-tx: send queued packets as soon as they are queued.
fn tx_loop() {
    let event = outbox::signal_handle();
    loop {
        // Timeout only as a safety net; the relay thread also drains every tick.
        if nx::svc::wait_synchronization_one(event, 1_000_000_000).is_ok() {
            let _ = nx::svc::clear_event(event);
        }
        if let Some(l) = LINK.lock().as_mut() {
            flush_outbox(l);
        }
    }
}

/// Sends what the session/router queued, while the link is Ready (otherwise it waits in
/// the queue; `relay_closed` clears it). Called with `LINK` held; the outbox lock is a leaf.
fn flush_outbox(l: &mut Link) {
    let Link { conn, tls: Some((tls, _)), out, payload, .. } = l else { return };
    while conn.is_ready() {
        let Some((id, n)) = outbox::pop_outgoing(payload) else { return };
        let len = conn.send_packet(id, payload.get(..n).unwrap_or_default(), rng::bytes(), out);
        if len == 0 {
            log!(Warning, "relay: {id:?} with {n} bytes does not fit a frame, dropped");
        } else if !write(conn, tls, out.get(..len).unwrap_or_default()) {
            return;
        }
    }
}

/// One relay-only packet (update check/chunk request) while the WebSocket is up.
fn send(l: &mut Link, id: PacketId, payload: &[u8]) {
    let Link { conn, tls: Some((tls, _)), out, .. } = l else { return };
    let len = conn.send_packet(id, payload, rng::bytes(), out);
    if len != 0 {
        write(conn, tls, out.get(..len).unwrap_or_default()); // a failure drops the link
    }
}

/// The channel to check, or `None`: `[update] channel = off`, or a developer build (build 0
/// never updates, as in the C++).
fn update_channel() -> Option<UpdateChannel> {
    match config_io::get().update.channel {
        _ if update_io::RUNNING_BUILD == 0 => None,
        Channel::Off => None,
        c => UpdateChannel::from_raw(c as u8),
    }
}

const fn stager_which(w: update_dl::Which) -> update_io::Which {
    match w {
        update_dl::Which::Exefs => update_io::Which::Exefs,
        update_dl::Which::Overlay => update_io::Which::Overlay,
    }
}

/// Writes a frame; a failure marks the transport lost (the relay thread then drops it).
fn write(conn: &mut Conn<RX_CAP>, tls: &mut Tls, frame: &[u8]) -> bool {
    match tls.write_all(frame) {
        Ok(()) => true,
        Err(e) => {
            log!(Warning, "relay: send failed: {e:?}");
            conn.transport_lost();
            false
        }
    }
}

/// Relay-thread-only state.
struct Relay {
    /// Decrypted bytes not yet taken by `Conn::on_bytes` (`rx[pos..len]`).
    rx: Vec<u8>,
    pos: usize,
    len: usize,
    /// One packet copied out of the `Conn`, delivered with `LINK` released.
    stage: Vec<u8>,
    shown: (ConnectionStatus, ConnectionState),
    /// Last `session::relay_request()` sequence acted on.
    seq: u32,
    /// The session wants the link and has not been told it is up (sim `wants_link`).
    wanted: bool,
    /// We closed the link ourselves: its Drop is not a loss (sim `closing`).
    closing: bool,
    /// Last Ready edge toasted.
    up: bool,
    /// Last state logged by `edges`.
    last: ConnectionState,
    /// Why the last [`open`] failed (overlay text while backing off).
    why: &'static str,
    /// The update download and its staging file.
    dl: UpdateDl,
    stager: Stager,
    /// Last download state reported (log + STATE).
    dl_shown: Dl,
    /// Run an update check on the next Ready link.
    check_due: bool,
    /// The overlay asked for a check: bring a link up for it if no game has one.
    open_for_check: bool,
    /// The link is up only for an update check (no game wants it).
    own_link: bool,
    /// Uptime of the last check started.
    last_check: Option<u64>,
}

/// What a pass under `LINK` left for the thread to do with the lock released.
#[allow(clippy::large_enum_variant)] // one at a time, short-lived
enum Next {
    Wait(Option<i32>),
    Open(Server),
    Deliver(PacketId),
    Ready(Session),
    Lost,
}

impl Relay {
    fn new() -> Self {
        Self {
            rx: vec![0; READ_CHUNK],
            pos: 0,
            len: 0,
            stage: Vec::with_capacity(RX_CAP),
            shown: (ConnectionStatus::Disconnected, ConnectionState::Disconnected),
            seq: 0, // RELAY_SEQ starts at 0: any request made before this thread counts
            wanted: false,
            closing: false,
            up: false,
            last: ConnectionState::Disconnected,
            why: "",
            dl: UpdateDl::new(),
            stager: Stager::new(),
            dl_shown: Dl::Idle,
            check_due: false,
            open_for_check: false,
            own_link: false,
            last_check: None,
        }
    }

    fn run(mut self) {
        log!(Info, "relay: thread started");
        let mut readable = false;
        loop {
            let request = session::relay_request();
            let next = {
                let mut g = LINK.lock();
                let Some(l) = g.as_mut() else { return };
                self.step(l, request, readable)
            };
            readable = false;
            match next {
                Next::Deliver(id) => {
                    match id {
                        PacketId::UpdateManifest => {
                            self.dl.on_manifest(&self.stage, &update_io::PUBLIC_KEY);
                        }
                        PacketId::UpdateChunkData => self.on_chunk(),
                        // 0xC0..=0xC4 are the link's own (DebugLog, Ping, update): not the session's.
                        _ if !(0xC0..=0xC4).contains(&id.raw()) => session::deliver_packet(id.raw(), &self.stage),
                        _ => {}
                    }
                    readable = true; // keep draining before waiting again
                }
                Next::Ready(s) => session::relay_ready(s.id, s.mac),
                Next::Lost => session::relay_closed(),
                Next::Open(server) => {
                    let opened = open(&server);
                    let mut g = LINK.lock();
                    let Some(l) = g.as_mut() else { return };
                    self.opened(l, &server, opened);
                }
                Next::Wait(fd) => {
                    self.update_files();
                    session::tick();
                    self.toast();
                    // While downloading, wake for the next chunk request (pacing is the Dl's).
                    let tick = if self.dl.state() == Dl::Downloading { update_dl::CHUNK_PAUSE_MS as i32 } else { TICK_MS };
                    readable = match fd {
                        Some(fd) => socket::wait_readable(fd, tick).unwrap_or_else(|e| {
                            log!(Warning, "relay: poll failed: {e:?}");
                            true // the read reports the error
                        }),
                        None => {
                            let _ = nx::thread::sleep(i64::from(tick).saturating_mul(1_000_000));
                            false
                        }
                    };
                }
            }
        }
    }

    /// One pass with `LINK` held: session wish, `Conn` timers and sends, outbox, remote
    /// log, status, then reading. Returns as soon as something needs `LINK` released.
    fn step(&mut self, l: &mut Link, (want, seq): (bool, u32), readable: bool) -> Next {
        let now = uptime_ms();
        if STATE.update_check_requested.swap(false, Relaxed) {
            self.manual_check();
        }
        if seq != self.seq {
            // session doc step 1: send what is queued, close (not reported), maybe connect.
            self.seq = seq;
            flush_outbox(l);
            self.flush_log(l, now, true);
            let state = l.conn.state();
            if !want && self.own_link {
                // The session never had this link (a wish and its withdrawal): the check keeps it.
                self.wanted = false;
            } else if state != ConnectionState::Disconnecting
                && state.is_transitioning()
                && (want || state == ConnectionState::Backoff)
            {
                // No open link to drop: keep the attempt running for a wish, and a backoff
                // (with its retry count) either way, so retries slow down instead of
                // restarting at 200 ms on every wish. An unwanted retry that comes up is
                // closed below.
                self.own_link = false;
                self.wanted = want;
            } else {
                self.own_link = false;
                self.closing = true;
                l.conn.close();
                if let Some(next) = self.drive(l, now) {
                    return next;
                }
                self.wanted = want;
                if want {
                    l.conn.connect(now);
                }
            }
        }
        if let Some(next) = self.drive(l, now) {
            return next;
        }
        flush_outbox(l);
        self.flush_log(l, now, false);
        self.status(l);
        if self.wanted
            && l.conn.is_ready()
            && let Some(s) = l.conn.session().copied()
        {
            self.wanted = false;
            return Next::Ready(s);
        }
        if !want && !self.wanted && !self.own_link && !self.closing && l.conn.is_ready() {
            // A retry came up after the session gave the link up: nobody needs it.
            log!(Verbose, "relay: link up but not wanted, closed");
            self.closing = true;
            l.conn.close();
        }
        self.update_link(l, now, want);
        if readable {
            if let Some(id) = self.read(l) {
                return Next::Deliver(id);
            }
            // A read failure marked the transport lost: Drop it now.
            if let Some(next) = self.drive(l, now) {
                return next;
            }
        }
        Next::Wait(l.tls.as_ref().map(|(_, fd)| *fd))
    }

    /// `Conn::poll` until Idle, or until it wants a connection or reports a loss.
    fn drive(&mut self, l: &mut Link, now: u64) -> Option<Next> {
        loop {
            let ping = l.conn.ping_pending();
            let action = l.conn.poll(now, rng::bytes(), &mut l.out);
            self.edges(l);
            match action {
                Action::Idle => return None,
                Action::Send(n) => {
                    if let Some((tls, _)) = l.tls.as_mut()
                        && write(&mut l.conn, tls, l.out.get(..n).unwrap_or_default())
                        && ping
                        && !l.conn.ping_pending()
                    {
                        log!(Verbose, "relay: Ping ok");
                    }
                }
                Action::Drop => {
                    l.tls = None; // closes the socket
                    (self.pos, self.len) = (0, 0);
                    if core::mem::take(&mut self.closing) {
                        log!(Verbose, "relay: link closed");
                    } else if self.own_link {
                        // The check's own link: no retries, the overlay shows the failure.
                        log!(Warning, "update: relay not reachable for the check ({:?})", l.conn.failure());
                        self.own_link = false;
                        self.abort_update(true);
                        self.closing = true;
                        l.conn.close(); // cancels the backoff; ends in a quiet Drop
                    } else {
                        match l.conn.failure() {
                            Some(Failure::UpgradeRejected(code)) => log!(Warning, "relay: auth rejected (HTTP {code})"),
                            f => log!(Warning, "relay: link down ({f:?})"),
                        }
                        match l.conn.state() {
                            ConnectionState::Backoff => {
                                log!(Info, "relay: retry {} in {} ms", l.conn.retry_count(), l.conn.backoff_ms());
                            }
                            s => log!(Warning, "relay: no more retries ({})", s.as_str()),
                        }
                        self.wanted = false;
                        self.status(l);
                        return Some(Next::Lost);
                    }
                }
                Action::Open => return Some(Next::Open(config_io::get().server)),
            }
        }
    }

    /// Back under `LINK` after [`open`]: hand the stream to the `Conn` and send the upgrade.
    fn opened(&mut self, l: &mut Link, server: &Server, opened: Result<(Tls, i32), &'static str>) {
        let (mut tls, fd) = match opened {
            Ok(o) => o,
            Err(why) => {
                self.why = why;
                l.conn.open_failed();
                return;
            }
        };
        (self.pos, self.len) = (0, 0);
        let key: [u8; 16] = rng::bytes();
        match l.conn.opened(&server.host, server.port, &server.path, &server.token, &key, &mut l.out) {
            Ok(n) => {
                if write(&mut l.conn, &mut tls, l.out.get(..n).unwrap_or_default()) {
                    l.tls = Some((tls, fd));
                }
            }
            Err(e) => {
                log!(Error, "relay: upgrade request not built ({e:?}): check [server] host/path/token");
                self.why = "Server not configured";
                l.conn.open_failed();
            }
        }
    }

    /// Feeds the `Conn` until it yields a packet (copied to `stage`) or TLS has nothing more.
    fn read(&mut self, l: &mut Link) -> Option<PacketId> {
        loop {
            self.edges(l);
            if let Some((id, payload)) = l.conn.next_packet() {
                self.stage.clear();
                self.stage.extend_from_slice(payload);
                return Some(id);
            }
            if self.pos < self.len {
                let used = l.conn.on_bytes(self.rx.get(self.pos..self.len).unwrap_or_default());
                // 0 = the Conn dropped the stream (bad frame): it reports the loss itself.
                self.pos = if used == 0 { self.len } else { self.pos.saturating_add(used) };
                continue;
            }
            let (tls, _) = l.tls.as_mut()?;
            match tls.read(&mut self.rx) {
                Ok(0) => {
                    log!(Info, "relay: TLS session closed by the relay");
                    l.conn.transport_lost();
                    return None;
                }
                Ok(n) => (self.pos, self.len) = (0, n),
                // Nothing more buffered (read timeout 0): wait for the socket again.
                Err(ldn_tunnel_tls::Error::Io(NetError::TimedOut)) => return None,
                Err(e) => {
                    log!(Warning, "relay: TLS read failed: {e:?}");
                    l.conn.transport_lost();
                    return None;
                }
            }
        }
    }

    /// DebugLog (0xC0) packets from the remote-log ring while Ready.
    fn flush_log(&mut self, l: &mut Link, now: u64, force: bool) {
        let Link { conn, tls: Some((tls, _)), remote, out, payload } = l else { return };
        if !conn.is_ready() {
            return;
        }
        let buf = payload.get_mut(..remote_log::MAX_PAYLOAD).unwrap_or_default();
        while let Some(n) = crate::log::with_remote_ring(|ring| remote.next_payload(ring, now, force, buf)) {
            let len = conn.send_packet(PacketId::DebugLog, buf.get(..n).unwrap_or_default(), rng::bytes(), out);
            if len == 0 || !write(conn, tls, out.get(..len).unwrap_or_default()) {
                return;
            }
        }
    }

    /// Overlay status (cfg GetConnectionStatus / transport string).
    fn status(&mut self, l: &Link) {
        let state = l.conn.state();
        let status = match state {
            ConnectionState::Ready => ConnectionStatus::Ready,
            ConnectionState::Connected | ConnectionState::Handshaking => ConnectionStatus::Connected,
            ConnectionState::Connecting | ConnectionState::Retrying | ConnectionState::Backoff => {
                ConnectionStatus::Connecting
            }
            ConnectionState::Error => ConnectionStatus::Error,
            ConnectionState::Disconnected | ConnectionState::Disconnecting => ConnectionStatus::Disconnected,
        };
        if (status, state) != self.shown {
            self.shown = (status, state);
            STATE.set_connection(status);
            let down = matches!(state, ConnectionState::Backoff | ConnectionState::Error | ConnectionState::Disconnected);
            STATE.set_transport_status(match l.conn.failure() {
                // The relay answers an unknown token with 404 (relay.ts `notFound()`), others 401/403.
                Some(Failure::UpgradeRejected(401 | 403 | 404)) if down => "Rejected: check token",
                Some(Failure::OpenFailed) if down => self.why,
                _ => state.as_str(),
            });
            log!(Verbose, "relay: {}", state.as_str());
        }
    }

    /// Logs the link milestones (upgrade, Initialize sent, reply) on state edges.
    fn edges(&mut self, l: &Link) {
        let state = l.conn.state();
        if state == self.last {
            return;
        }
        self.last = state;
        match state {
            ConnectionState::Connected => log!(Info, "ws: upgrade 101"),
            ConnectionState::Handshaking => log!(Info, "relay: Initialize sent"),
            ConnectionState::Ready => {
                let id = l.conn.session().map(|s| s.id).unwrap_or_default();
                log!(Info, "relay: Initialize reply ok, id={id:02x?}");
                crate::update_io::mark_healthy();
                if self.last_check.is_none_or(|t| uptime_ms().saturating_sub(t) >= CHECK_INTERVAL_MS) {
                    self.check_due = true;
                }
            }
            _ => {}
        }
    }

    /// Connection toasts on Ready edges.
    fn toast(&mut self) {
        // Only the session's link: an update check's own link or an unwanted retry is no news.
        let up = self.shown.1 == ConnectionState::Ready && session::relay_request().0;
        if up != self.up {
            self.up = up;
            STATE.notify_event(Event::Relay { up });
        }
    }

    // ---- updates ----------------------------------------------------------------

    /// cfg CheckForUpdates (it already shows "checking").
    fn manual_check(&mut self) {
        if update_channel().is_none() {
            log!(Info, "update: check skipped (channel off or developer build)");
            STATE.update_check.store(check::IDLE, Relaxed);
            return;
        }
        log!(Info, "update: manual check");
        if self.dl.state().is_terminal() {
            self.dl = UpdateDl::new(); // its old outcome would overwrite "checking"
        }
        if self.dl.state() == Dl::Idle {
            self.check_due = true;
            self.open_for_check = true;
        }
    }

    /// Under `LINK`, every pass: start a due check, request the next chunk, time out, and
    /// bring a link up for (or close it after) a manual check.
    fn update_link(&mut self, l: &mut Link, now: u64, want: bool) {
        let ready = l.conn.is_ready() && !self.closing;
        if matches!(self.dl.state(), Dl::AwaitManifest | Dl::Downloading) && !ready {
            self.abort_update(false); // the link went: resume on the next one
        }
        self.dl.poll(now);
        if ready {
            if self.check_due && !self.dl_busy() {
                self.check_due = false;
                self.open_for_check = false;
                self.start_check(l, now);
            }
            if let Some(r) = self.dl.next_request(now) {
                send(l, PacketId::UpdateChunk, r.as_bytes());
            }
        } else if self.open_for_check && !want && matches!(l.conn.state(), ConnectionState::Disconnected | ConnectionState::Error) {
            self.open_for_check = false;
            self.own_link = true;
            log!(Info, "update: connecting to the relay for the check");
            l.conn.connect(now);
        }
        if self.own_link && ready && !self.check_due && !self.dl_busy() && !self.closing {
            self.own_link = false;
            self.closing = true;
            l.conn.close();
        }
        self.report();
    }

    fn start_check(&mut self, l: &mut Link, now: u64) {
        let Some(channel) = update_channel() else { return };
        let st = update_io::get_status();
        let (running, version) = (update_io::RUNNING_BUILD, update_io::VERSION);
        // No label (the C++ sent nickname + serial): the relay names the console by its token.
        let req = self.dl.start(now, channel, running, st.rejected_build, st.staged_build, st.on_probation, "", version);
        self.last_check = Some(now);
        log!(Info, "update: checking {channel:?} (running build {running})");
        send(l, PacketId::UpdateCheck, req.as_bytes());
    }

    /// The download needs the link (or the file steps between its packets).
    fn dl_busy(&self) -> bool {
        !matches!(self.dl.state(), Dl::Idle) && !self.dl.state().is_terminal()
    }

    /// Link lost mid-check. `failed`: show it (a manual check's own link); else retry on the
    /// next link. The partial staging file is kept (closed) for the resume.
    fn abort_update(&mut self, failed: bool) {
        if self.dl_busy() {
            log!(Info, "update: link lost at {}%", self.dl.percent());
        }
        self.dl = UpdateDl::new();
        self.stager = Stager::new();
        self.dl_shown = Dl::Idle;
        self.check_due = !failed;
        self.open_for_check = false;
        STATE.update_download.store(0, Relaxed);
        STATE.update_check.store(if failed { check::FAILED } else { check::IDLE }, Relaxed);
    }

    /// An UpdateChunkData packet (in `stage`), with `LINK` released.
    fn on_chunk(&mut self) {
        let data = match self.dl.on_chunk(uptime_ms(), &self.stage) {
            Progress::Append { len, .. } | Progress::Complete { len } => self.stage.get(CHUNK_HEADER..).and_then(|d| d.get(..len)),
            Progress::Ignored | Progress::Failed(_) => return,
        };
        if !data.is_some_and(|d| self.stager.append(d)) {
            self.dl.fail_io();
        }
        STATE.update_download.store(self.dl.percent().saturating_add(1), Relaxed);
    }

    /// The file steps of the download, with `LINK` released: open/resume the staging file,
    /// hash it, install. Hashing ~2 MB holds this thread (not relay-tx) for a moment.
    fn update_files(&mut self) {
        loop {
            match self.dl.state() {
                Dl::NeedBegin(b) => match self.stager.begin(stager_which(b.which), &b.sha256, b.size) {
                    Some(off) => {
                        log!(Info, "update: downloading {:?} ({} bytes, from {off})", b.which, b.size);
                        self.dl.begun(off);
                    }
                    None => self.dl.fail_io(),
                },
                Dl::NeedVerify(_) => {
                    let ok = self.stager.verify();
                    self.dl.verified(ok);
                }
                Dl::NeedInstall => {
                    let ok = self.dl.manifest().is_some_and(update_io::install_staged);
                    self.dl.installed(ok);
                }
                _ => break,
            }
        }
        self.report();
    }

    /// Download state -> overlay (`STATE.update_check` / `update_download`) and the log, on change.
    fn report(&mut self) {
        let s = self.dl.state();
        if s == self.dl_shown {
            return;
        }
        self.dl_shown = s;
        let shown = match s {
            Dl::Idle => return,
            Dl::AwaitManifest => check::CHECKING,
            Dl::Staged => {
                log!(Info, "update: build {} ready, restart the module to run it", update_io::get_status().staged_build);
                check::IDLE
            }
            Dl::NoRelease => {
                log!(Info, "update: no release on the channel");
                check::IDLE
            }
            Dl::Refused(r @ (ManifestResult::NotNewer | ManifestResult::Rejected | ManifestResult::AlreadyStaged)) => {
                log!(Info, "update: up to date ({r:?})");
                check::IDLE
            }
            Dl::WaitRestart => {
                log!(Info, "update: newer build available after the pending restart");
                check::IDLE
            }
            Dl::Refused(r) => {
                log!(Warning, "update: manifest refused ({r:?})");
                check::FAILED
            }
            Dl::Failed(f) => {
                log!(Warning, "update: failed ({f:?})");
                self.stager = Stager::new(); // close the staging file (kept for a resume)
                check::FAILED
            }
            Dl::NeedBegin(_) | Dl::Downloading | Dl::NeedVerify(_) | Dl::NeedInstall => check::CHECKING,
        };
        STATE.update_check.store(shown, Relaxed);
        if s.is_terminal() {
            STATE.update_download.store(0, Relaxed);
        }
    }
}

/// DNS + TCP + TLS, with no lock held (several seconds at worst). Logs why it failed and
/// returns the overlay text for it. Never logs the token.
fn open(server: &Server) -> Result<(Tls, i32), &'static str> {
    let t0 = uptime_ms();
    if server.host.is_empty() || server.token.is_empty() {
        log!(Warning, "relay: [server] host/token not configured");
        return Err("Server not configured");
    }
    let Some((now, src)) = clock::unix_now() else {
        log!(Warning, "relay: waiting for network time");
        return Err("Waiting for network time");
    };
    let ca = read_ca(&server.ca_file)?;
    let ip = dns::resolve(&server.host).map_err(|e| {
        log!(Warning, "relay: cannot resolve {}: {e:?}", server.host);
        "DNS failed"
    })?;
    log!(Info, "relay: resolve {} -> {ip}", server.host);
    let sock = BsdSocket::connect(ip, server.port, IO_TIMEOUT_MS).map_err(|e| {
        log!(Warning, "relay: TCP {ip}:{} failed: {e:?}", server.port);
        "TCP connect failed"
    })?;
    let (fd, timeout) = (sock.fd(), sock.read_timeout());
    let t_tcp = uptime_ms();
    log!(Info, "relay: tcp connected ({ip}:{}, {} ms)", server.port, t_tcp.saturating_sub(t0));
    let tls = match ldn_tunnel_tls::connect(&server.host, &ca, sock, now, &rng::CSRNG) {
        Ok(t) => t,
        Err(ldn_tunnel_tls::Error::Tls(e)) if is_clock_error(&e) => {
            log!(Error, "tls: certificate time invalid / clock not set (now={now}, {src:?} clock): {e:?}");
            return Err("TLS: check date and time");
        }
        Err(e) => {
            log!(Warning, "tls: handshake with {} failed: {e:?}", server.host);
            return Err("TLS handshake failed");
        }
    };
    // ponytail: crates/tls exposes no negotiated version/cipher; log them once it does.
    log!(Info, "tls: handshake ok, host verified ({} ms)", uptime_ms().saturating_sub(t_tcp));
    // From here the thread polls before reading, so reads return at once.
    timeout.store(0, Relaxed);
    Ok((tls, fd))
}

fn is_clock_error(e: &rustls::Error) -> bool {
    use rustls::{CertificateError as C, Error as E};
    matches!(e, E::InvalidCertificate(C::Expired | C::NotValidYet | C::ExpiredContext { .. } | C::NotValidYetContext { .. }))
}

fn read_ca(path: &str) -> Result<Vec<u8>, &'static str> {
    let size = crate::fs_util::file_size(path).ok().filter(|&s| s > 0 && s <= MAX_CA);
    let Some(size) = size else {
        log!(Error, "tls: ca_file unreadable: {path} missing, empty or over {MAX_CA} bytes");
        return Err("CA file missing");
    };
    let mut buf = vec![0; size];
    match crate::fs_util::read_into(path, &mut buf) {
        Ok(n) => {
            buf.truncate(n);
            Ok(buf)
        }
        Err(rc) => {
            log!(Error, "tls: ca_file unreadable: {path}: {rc:?}");
            Err("CA file missing")
        }
    }
}
