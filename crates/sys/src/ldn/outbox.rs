//! Everything for the relay, for the relay thread: the session's packets
//! (`Action::Send`) and the router's game datagrams (`PacketId::ProxyData`,
//! payload = ProxyDataHeader + data, from `bsd::router_impl::emit`).
//! `Conn` adds the LdnHeader and the WebSocket frame:
//!
//! ```ignore
//! let mut payload = [0u8; ldn::outbox::PAYLOAD_MAX];
//! while let Some((id, n)) = ldn::outbox::pop_outgoing(&mut payload) {
//!     let len = conn.send_packet(id, &payload[..n], mask, &mut out);
//!     write_all(&out[..len])?;
//! }
//! ```
//!
//! `signal_handle()` is a kernel event signaled on every push and on every
//! connect/disconnect request (`session::relay_request`). A relay thread that
//! blocks can include it in its wait and must clear it (`svc::clear_event`)
//! itself; one that polls its socket can ignore it and drain every turn.
//! The queue lock is a leaf: nothing else is locked while it is held.
#![forbid(unsafe_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

use ldn_tunnel_core::ldn::Payload;
use ldn_tunnel_core::wire::{PacketId, ProxyDataHeader};
use nx::svc;
use nx::sync::Mutex;
use zerocopy::IntoBytes;

use super::session::KEvent;

const PROXY_MAX: usize = size_of::<ProxyDataHeader>() + ldn_tunnel_core::router::MAX_PAYLOAD;
/// The largest payload `pop_outgoing` hands out (a ProxyData).
pub const PAYLOAD_MAX: usize =
    if PROXY_MAX > ldn_tunnel_core::ldn::MAX_PAYLOAD { PROXY_MAX } else { ldn_tunnel_core::ldn::MAX_PAYLOAD };
/// Game datagrams waiting (~64 KB worst case). Past it a send fails with
/// ENETUNREACH, as a full socket buffer would.
const CAPACITY: usize = 32;
/// Slots past CAPACITY only the session may use, so a game-data flood never
/// drops a session packet (a call emits at most 2).
const SESSION_RESERVE: usize = 8;

static QUEUE: Mutex<VecDeque<(PacketId, Vec<u8>)>> = Mutex::new(VecDeque::new());
pub(super) static SIGNAL: KEvent = KEvent::new();
/// The session is resuming its room on a new link: game datagrams are dropped (stale by the
/// time the room is back), not refused, so the game sees a lossy network, not an error.
static DROPPING: AtomicBool = AtomicBool::new(false);

pub(super) fn set_dropping(on: bool) {
    DROPPING.store(on, Relaxed);
}

fn enqueue(limit: usize, id: PacketId, bytes: Vec<u8>) -> bool {
    {
        let mut q = QUEUE.lock();
        if q.len() >= limit {
            return false;
        }
        q.push_back((id, bytes));
    }
    SIGNAL.signal();
    true
}

/// A session packet (`Action::Send`).
pub(super) fn push(id: PacketId, payload: Payload) {
    if !enqueue(CAPACITY + SESSION_RESERVE, id, payload.to_vec()) {
        log!(Warning, "ldn: relay send queue full, dropped {id:?}");
    }
}

/// A game datagram; false when the queue is full.
pub(crate) fn push_proxy_data(header: &ProxyDataHeader, data: &[u8]) -> bool {
    if DROPPING.load(Relaxed) {
        return true;
    }
    let mut bytes = Vec::with_capacity(size_of::<ProxyDataHeader>().saturating_add(data.len()));
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(data);
    enqueue(CAPACITY, PacketId::ProxyData, bytes)
}

/// The relay link went away: what is queued was for it.
pub(super) fn clear() {
    QUEUE.lock().clear();
}

/// Nothing waits to be sent (the remote log yields to game packets).
pub fn is_empty() -> bool {
    QUEUE.lock().is_empty()
}

/// Oldest queued packet: its id, and its payload copied into `payload`.
pub fn pop_outgoing(payload: &mut [u8; PAYLOAD_MAX]) -> Option<(PacketId, usize)> {
    let (id, p) = QUEUE.lock().pop_front()?;
    let n = p.len();
    payload.get_mut(..n)?.copy_from_slice(&p);
    Some((id, n))
}

/// Readable handle of the "something for the relay thread" event.
pub fn signal_handle() -> svc::Handle {
    SIGNAL.handle()
}
