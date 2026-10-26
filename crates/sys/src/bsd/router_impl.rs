//! The process-wide LDN router (`ldn_tunnel_core::router::Router`) and the
//! event that wakes bsd:u requests waiting on proxied sockets.
//!
//! Lock order: ROUTER is a leaf (`emit` runs without it and only takes the
//! outbox queue). The ldn:u session never holds its lock while calling here.
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

use ldn_tunnel_core::router::Router;
use ldn_tunnel_core::wire::ProxyDataHeader;
use nx::result::Result;
use nx::svc;
use nx::sync::Mutex;

use crate::ldn::outbox;
use crate::ldn::session::KEvent;

/// 145 KB in .bss (see the router's README).
static ROUTER: Mutex<Router> = Mutex::new(Router::new());
/// Signaled when a proxied socket may have become readable (data, shutdown,
/// close, LDN reset). Only the bsd:u server waits on it; its manager clears it.
static RX: KEvent = KEvent::new();
/// First ProxyData each way logged (once per LDN session; `reset` re-arms them).
static LOGGED_IN: AtomicBool = AtomicBool::new(false);
static LOGGED_OUT: AtomicBool = AtomicBool::new(false);

/// Creates the rx event. Call once, before the bsd:u or relay threads start
/// (the outbox's event is ldn::start's).
pub fn init() -> Result<()> {
    RX.init()
}

/// Runs `f` on the router under its lock.
pub fn with<R>(f: impl FnOnce(&mut Router) -> R) -> R {
    f(&mut ROUTER.lock())
}

/// Wakes bsd:u requests waiting on proxied sockets so they re-check.
pub fn wake() {
    RX.signal();
}

pub fn rx_event() -> svc::Handle {
    RX.handle()
}

/// A ProxyData from the relay. Returns how many sockets it was queued on.
pub fn deliver_proxy_data(header: &ProxyDataHeader, payload: &[u8]) -> usize {
    let n = with(|r| r.on_proxy_data(header, payload));
    if !LOGGED_IN.swap(true, Relaxed) {
        let i = header.info; // packed: fields are copied out below
        log!(Info, "bsd: first ProxyData in: {:08X}:{} -> {:08X}:{}, {} bytes, queued on {n} sockets",
            { i.source_ipv4 }, { i.source_port }, { i.dest_ipv4 }, { i.dest_port }, payload.len());
    }
    if n > 0 {
        wake();
    }
    n
}

/// LDN session ended: every proxy closes and its waiters get ENETDOWN.
/// The outbox is left alone: it may still hold the session's goodbye, which
/// the relay thread flushes before closing (`session::relay_closed` clears it).
pub fn reset() {
    with(Router::reset);
    LOGGED_IN.store(false, Relaxed);
    LOGGED_OUT.store(false, Relaxed);
    wake();
}

/// Hands a game datagram to the relay thread; false if it could not be queued.
pub fn emit(header: &ProxyDataHeader, payload: &[u8]) -> bool {
    let queued = outbox::push_proxy_data(header, payload);
    if !LOGGED_OUT.swap(true, Relaxed) {
        let i = header.info; // packed: fields are copied out below
        log!(Info, "bsd: first ProxyData out: {:08X}:{} -> {:08X}:{}, {} bytes{}",
            { i.source_ipv4 }, { i.source_port }, { i.dest_ipv4 }, { i.dest_port }, payload.len(), if queued { "" } else { ", queue full" });
    }
    queued
}
