//! The one LDN `Session` (core::ldn, sans-IO) and the shell around it: the
//! action drain, pending requests as nx deferrals, and the relay thread's API.
//!
//! ## Locks
//! Outermost first: `SESSION` → outbox queue (leaf) / logger / `STATE`.
//! The router (`bsd::router_impl`) is never called while `SESSION` is held:
//! router work found during a drain is collected (`After`) and done once the
//! session lock is released.
//!
//! ## Relay thread (a lock-order trap the C++ module had too)
//! Each call below holds the session lock for its duration. Never call them
//! while holding the transport's own lock (or from a callback that does), and
//! never connect/disconnect/send from inside them: the session asks for a link
//! through `relay_request()` and for packets through the outbox, and the relay
//! loop acts on those between calls. Order of operations = the reference
//! wiring in crates/core/tests/sim/console.rs:
//! 1. `relay_request()` → `(wanted, seq)`. When `seq` changed since the last
//!    turn: send what the outbox holds, close the transport if open (a close
//!    asked for here is not reported), and if `wanted`, connect `Conn`.
//! 2. `Conn` Ready → `relay_ready(id, mac)` with `Conn::session()` (Conn did
//!    the Initialize handshake; the session must not send its own).
//! 3. Each decoded LDN packet (not 0xC0..=0xC4) → `deliver_packet(id, payload)`.
//! 4. Transport lost, or never came up → `relay_closed()`.
//! 5. Every turn (≤ 1 s apart): `tick()`, then drain the outbox.
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};

use ldn_tunnel_core::cfg_types::SessionInfoIpc;
use ldn_tunnel_core::ldn::{Action, CommState, LdnError, Level, Pending, Session};
use ldn_tunnel_core::wire::ProxyDataHeader;
use nx::ipc::server::Deferral;
use nx::result::Result;
use nx::sync::Mutex;
use nx::{arm, svc};

use super::outbox;
use crate::log;
use crate::bsd::router_impl;
use crate::state::{STATE, uptime_ms};

/// A kernel event created once at startup and never closed (process lifetime).
pub struct KEvent {
    writable: AtomicU32,
    readable: AtomicU32,
}

impl KEvent {
    pub const fn new() -> Self {
        Self { writable: AtomicU32::new(0), readable: AtomicU32::new(0) }
    }

    pub(crate) fn init(&self) -> Result<()> {
        let (w, r) = svc::create_event()?;
        self.writable.store(w, Relaxed);
        self.readable.store(r, Relaxed);
        Ok(())
    }

    pub fn signal(&self) {
        let _ = svc::signal_event(self.writable.load(Relaxed));
    }

    pub fn clear(&self) {
        let _ = svc::clear_event(self.readable.load(Relaxed));
    }

    pub fn handle(&self) -> svc::Handle {
        self.readable.load(Relaxed)
    }
}

/// AttachStateChangeEvent: signaled on every `Action::StateChanged`.
pub(super) static STATE_EVENT: KEvent = KEvent::new();
/// Resumes the deferred IPC request when its reply is ready (`Action::ReplyReady`).
static REPLY: KEvent = KEvent::new();

static RELAY_WANTED: AtomicBool = AtomicBool::new(false);
static RELAY_SEQ: AtomicU32 = AtomicU32::new(0);

struct Slot {
    /// The `CommunicationService` that owns the session (one game at a time).
    owner: u32,
    s: Session,
}

/// ~28 KB in .bss.
static SESSION: Mutex<Option<Slot>> = Mutex::new(None);

/// Creates the kernel events; before the ldn:u server starts.
pub(super) fn init() -> Result<()> {
    STATE_EVENT.init()?;
    REPLY.init()?;
    outbox::SIGNAL.init()
}

// ---------------------------------------------------------------- drain

/// Router work from one drain, done after the session lock is released.
#[derive(Default)]
struct After {
    proxy_config: Option<(u32, u32)>,
    reset: bool,
}

impl After {
    fn apply(self) {
        // A reset (link gone) and a new config never come from one drain:
        // ProxyConfig only arrives on a live link.
        if self.reset {
            router_impl::reset();
        }
        if let Some((ip, mask)) = self.proxy_config {
            router_impl::with(|r| r.set_proxy_config(ip, mask));
        }
    }
}

fn request_relay(wanted: bool) {
    RELAY_WANTED.store(wanted, Relaxed);
    RELAY_SEQ.fetch_add(1, Relaxed);
    outbox::SIGNAL.signal();
}

/// Carries out the session's actions (crates/core/src/ldn/README.md "Shell contract").
fn drain(s: &mut Session, after: &mut After) {
    while let Some(action) = s.next_action() {
        match action {
            Action::Send { id, payload } => outbox::push(id, payload),
            Action::StateChanged => STATE_EVENT.signal(),
            Action::ProxyConfig { ip, mask } => after.proxy_config = Some((ip, mask)),
            Action::RelayConnect => request_relay(true),
            Action::RelayDisconnect => {
                request_relay(false);
                after.reset = true;
            }
            Action::Log { level, text } => {
                let level = match level {
                    Level::Error => log::Level::Error,
                    Level::Warn => log::Level::Warning,
                    Level::Info => log::Level::Info,
                };
                log::write(level, format_args!("ldn: {text}"));
            }
            Action::ReplyReady => REPLY.signal(),
        }
    }
    publish(s);
}

/// The overlay's view (ldnt:cfg GetLdnState / GetSessionInfo).
fn publish(s: &Session) {
    outbox::set_dropping(s.is_resuming());
    let state = s.state();
    STATE.ldn_state.store(state as u32, Relaxed);
    let ldn = s.network_info().ldn;
    STATE.set_session_info(SessionInfoIpc {
        node_count: ldn.node_count,
        max_nodes: ldn.node_count_max,
        local_node_id: s.local_node_id(),
        is_host: u8::from(state == CommState::AccessPointCreated),
        reserved: [0; 4],
    });
}

/// Runs `f` on the slot under the lock, drains, then does the router work.
fn locked<R>(f: impl FnOnce(&mut Option<Slot>, u64, &mut After) -> R) -> R {
    let now = uptime_ms();
    let mut after = After::default();
    let r = {
        let mut g = SESSION.lock();
        let r = f(&mut g, now, &mut after);
        if let Some(slot) = g.as_mut() {
            drain(&mut slot.s, &mut after);
        }
        r
    };
    after.apply();
    r
}

// ---------------------------------------------------------------- IPC side

/// Initialize: a session for `owner`. Another owner's session is finalized
/// and replaced; the same owner re-initializing after Finalize keeps its own.
pub(super) fn open(owner: u32, program_id: u64) -> core::result::Result<(), LdnError> {
    locked(|g, now, _| {
        if let Some(old) = g.as_mut().filter(|o| o.owner != owner) {
            old.s.finalize(now);
        }
    });
    locked(|g, _, _| {
        if g.as_ref().is_some_and(|o| o.owner != owner) {
            *g = None;
        }
        // ponytail: relies on the 28 KB Session being built in place (it is in
        // this build: see the ldn thread's stack note in mod.rs); a reset method
        // on Session removes the temporary for good if a toolchain stops doing it.
        let slot = g.get_or_insert_with(|| Slot { owner, s: Session::new(program_id) });
        STATE_EVENT.clear();
        slot.s.initialize()
    })
}

/// Runs `f` on `owner`'s session after its due timers; `InvalidState` if
/// another service owns it (or nothing was initialized).
pub(super) fn with<R>(owner: u32, f: impl FnOnce(&mut Session, u64) -> R) -> core::result::Result<R, LdnError> {
    locked(|g, now, _| match g.as_mut() {
        Some(slot) if slot.owner == owner => {
            slot.s.poll(now);
            Ok(f(&mut slot.s, now))
        }
        _ => Err(LdnError::InvalidState),
    })
}

/// The service closed: finalize and free the session if it is `owner`'s
/// (true), else leave it to its newer owner (false).
pub(super) fn close(owner: u32) -> bool {
    if with(owner, |s, now| s.finalize(now)).is_err() {
        return false;
    }
    let mut g = SESSION.lock();
    let mine = g.as_ref().is_some_and(|slot| slot.owner == owner);
    if mine {
        *g = None;
    }
    mine
}

/// A relay-bound request. First dispatch: `start` it. Then, and on every
/// resume: `Ok(result)` once its reply is in, else the deferral that resumes
/// it (on `REPLY`, or at the session's next deadline, which `with` polls).
pub(super) fn request(
    owner: u32,
    first: bool,
    start: impl FnOnce(&mut Session, u64) -> core::result::Result<Pending, LdnError>,
) -> core::result::Result<core::result::Result<(), LdnError>, Deferral> {
    if first && let Err(e) = with(owner, start).and_then(|r| r) {
        return Ok(Err(e));
    }
    let step = with(owner, |s, now| match (s.take_reply(), s.next_deadline()) {
        (Some(reply), _) => Ok(reply),
        (None, Some(deadline)) => {
            let ns = deadline.saturating_sub(now).saturating_mul(1_000_000);
            Err(Deferral {
                wait_handle: REPLY.handle(),
                deadline: arm::get_system_tick().saturating_add(arm::nanoseconds_to_ticks(ns)),
            })
        }
        // A pending request always has a deadline (link setup or its own):
        // none means it is gone.
        (None, None) => Ok(Err(LdnError::InvalidState)),
    });
    step.unwrap_or_else(|e| Ok(Err(e)))
}

// ---------------------------------------------------------------- relay side

/// `(wanted, seq)`: whether the session wants the relay transport; `seq`
/// changes on every connect/disconnect request (see the module doc).
pub fn relay_request() -> (bool, u32) {
    (RELAY_WANTED.load(Relaxed), RELAY_SEQ.load(Relaxed))
}

/// One decoded relay packet (LdnHeader type + payload). Game data goes to the router.
pub fn deliver_packet(id: u8, payload: &[u8]) {
    let data = locked(|g, now, _| g.as_mut().and_then(|slot| slot.s.on_packet(id, payload, now)));
    if let Some(d) = data {
        let header = ProxyDataHeader { info: d.info, data_length: u32::try_from(d.payload.len()).unwrap_or(u32::MAX) };
        router_impl::deliver_proxy_data(&header, d.payload);
    }
}

/// `Conn` is Ready: `id`/`mac` from `Conn::session()`.
pub fn relay_ready(id: [u8; 16], mac: [u8; 6]) {
    locked(|g, now, _| {
        if let Some(slot) = g.as_mut() {
            slot.s.on_relay_ready(now, id, mac);
        }
    });
}

/// The transport failed to come up, or closed without being asked to. A room
/// is resumed on a new link (the session asks for it again; the game's proxy
/// sockets stay); anything else is gone with the link and the router is reset
/// (the session emits no RelayDisconnect for this).
pub fn relay_closed() {
    outbox::clear();
    request_relay(false);
    locked(|g, now, after| {
        let resuming = g.as_mut().is_some_and(|slot| {
            slot.s.on_relay_closed(now);
            slot.s.is_resuming()
        });
        after.reset = !resuming;
    });
}

/// Timers (idle timeout, link setup) while no IPC call comes in.
pub fn tick() {
    locked(|g, now, _| {
        if let Some(slot) = g.as_mut() {
            slot.s.poll(now);
        }
    });
}
