//! bsd:u MitM: forwards every call to the real bsd:u, except the socket
//! paths the LDN router (`ldn_tunnel_core::router`) claims.
//!
//! Game datagrams go out through `ldn::outbox` and come in through
//! `ldn::session::deliver_packet`: the relay thread only talks to ldn.

pub mod ifaces;
pub mod router_impl;
mod service;

use crate::state::STATE;

/// bsd:u thread stack. Static estimate (llvm-objdump frames + call graph): manager with
/// its pointer buffer + dispatch ~8 KiB, deepest handler (select) ~7 KiB, log/panic ~4 KiB.
/// 48 KiB keeps 2x over that ~19 KiB.
const STACK: usize = 0xC000;

/// Starts the bsd:u MitM thread (no-op when LDN services are off this boot).
pub fn start() {
    if !STATE.ldn_services_allowed() {
        return;
    }
    let started = router_impl::init().and_then(|()| {
        crate::server::spawn::<{ service::POINTER_BUFFER_SIZE }>("bsd:u", STACK, service::register)
    });
    if let Err(rc) = started {
        log!(Error, "bsd:u MitM failed to start: {rc:?}");
    }
}
