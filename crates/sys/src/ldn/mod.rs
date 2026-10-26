//! `ldn:u` MITM: the ldn:u server thread, the LDN session shell and the relay
//! thread's API (`session::{relay_request, relay_ready, relay_closed,
//! deliver_packet, tick}`, `outbox::{pop_outgoing, signal_handle}`).

pub mod ifaces;
mod monitor;
mod nifm;
pub mod outbox;
mod service;
pub mod session;

use nx::ipc::server::ServerManager;
use nx::thread::{Builder, JoinHandle, ThreadPriority};

/// C++ `mitm::ThreadPriority` 6 (os) = svc priority 34, above ldnt:cfg (38).
const PRIORITY: i32 = 34;
/// Holds the manager (its 4 KiB pointer buffer) and the IPC frames; the 28 KB Session is
/// in .bss, built in place (no stack copy). Static estimate (llvm-objdump frames + call
/// graph): ~8 KiB thread + dispatch, ~7 KiB deepest handler, ~4 KiB log/panic = ~19 KiB;
/// 48 KiB keeps 2x (the C++ module used 32 KiB).
const STACK: usize = 0xC000;
/// C++ LdnMitmManagerOptions::PointerBufferSize.
const POINTER_BUFFER_SIZE: usize = 0x1000;

/// Starts the ldn:u MITM on its own thread (its own ServerManager). Only when
/// `STATE.ldn_services_allowed()`. Keep the handle alive.
pub fn start() -> nx::result::Result<JoinHandle<(), false>> {
    session::init()?;
    Builder::new()
        .name("ldn:u")
        .priority(ThreadPriority::Set(PRIORITY))
        .stack_size(STACK)
        .spawn(|| {
            // ponytail: nx's sm registration of a MITM takes no session limit
            // (the C++ capped ldn:u at 6); a game holds about 3.
            if let Err(rc) = nifm::open() {
                log!(Warning, "ldn:u: nifm not open yet: {rc:?}");
            }
            let r = ServerManager::<POINTER_BUFFER_SIZE>::new().and_then(|mut sm| {
                sm.register_mitm_service_server::<service::LdnMitm>()?;
                log!(Info, "ldn:u: MITM registered");
                sm.loop_process()
            });
            if let Err(rc) = r {
                log!(Error, "ldn:u: server stopped: {rc:?}");
            }
        })
}

/// Our result codes.
pub mod rc {
    /// 9-bit result module of ldn-tunnel (nx itself uses 430).
    pub const MODULE: u32 = 431;
}
