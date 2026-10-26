//! ldn-tunnel sysmodule (Horizon shell). Startup in the C++ order (main.cpp):
//! mount SD → config.ini → logger → update boot_check → firstboot → gamelist →
//! ldnt:cfg on its own thread; then the main thread idles. The ldn:u / bsd:u
//! MITMs are registered by the server code (other modules), gated by
//! `STATE.ldn_services_allowed()`.
#![no_std]
#![no_main]
// Unsafe lives only in `rt` (heap, entry symbols), `bsd/service` (buffer views, poll entries),
// `server/forward` (raw IPC forwarding) and `net/getrandom` (the backend macro); each opts in
// at its top with the reason.
#![deny(unsafe_code)]

extern crate alloc;

#[macro_use]
mod log;
mod bsd;
mod net;
mod relay_thread;
mod cfg;
mod compat;
mod config_io;
mod firstboot;
mod fs_util;
mod ldn;
mod notify_io;
mod rt;
mod server;
mod state;
mod update_io;

use core::sync::atomic::Ordering::Relaxed;

use ldn_tunnel_core::ident;
use nx::thread::{Builder, ThreadPriority};

use crate::state::STATE;

/// C++ cfg thread: os priority 10 = svc priority 38; maintenance below it.
const CFG_PRIORITY: i32 = 38;
const MAINT_PRIORITY: i32 = 43;
/// cfg and maint. Static estimate (llvm-objdump frames + call graph, with log formatting
/// and the panic path): cfg ~13 KiB, maint ~8 KiB. Keep 2x.
const THREAD_STACK: usize = 0x8000;
const SECOND_NS: i64 = 1_000_000_000;

#[allow(clippy::panic)] // boot failure: with no SD card or no threads there is nothing to run
fn run() {
    if let Err(rc) = fs_util::mount_sd() {
        panic!("SD mount failed: {rc:?}");
    }
    let cfg = config_io::load_at_boot(); // also configures the logger
    log!(Info, "{} {} (build {}) starting", ident::NAME, update_io::VERSION, update_io::RUNNING_BUILD);
    log!(Info, "config: {} -> {cfg:?}", ident::CONFIG_PATH);

    let stand_down = update_io::boot_check();
    STATE.update_stand_down.store(stand_down, Relaxed);
    let st = update_io::get_status();
    log!(
        Info,
        "update: build {}{}{}",
        st.running_build,
        if st.on_probation { ", on probation" } else { "" },
        if stand_down { ", rolled back: LDN services off this boot" } else { "" }
    );

    firstboot::run();
    if STATE.needs_restart.load(Relaxed) {
        // Also cfg 30 GetSetupStatus bit 0; the string is for overlays that only show status.
        STATE.set_transport_status("Restart once to finish setup");
    }
    compat::check(); // after firstboot: a too-old firmware's status wins
    config_io::load_whitelist();
    let c = config_io::get();
    log!(Verbose, "server: {}:{}{}", c.server.host, c.server.port, c.server.path);
    notify_io::boot();

    let cfg_thread = Builder::new()
        .name("ldnt:cfg")
        .priority(ThreadPriority::Set(CFG_PRIORITY))
        .stack_size(THREAD_STACK)
        .spawn(|| {
            if let Err(rc) = cfg::serve() {
                log!(Error, "cfg: server stopped: {rc:?}");
            }
        });
    if let Err(rc) = cfg_thread.as_ref() {
        panic!("thread start failed: {rc:?}");
    }
    let ldn_thread = if STATE.ldn_services_allowed() {
        ldn::start().map_err(|rc| log!(Error, "ldn:u: start failed: {rc:?}")).ok()
    } else {
        log!(Warning, "ldn:u/bsd:u stay off this boot (restart pending, update rolled back or firmware too old)");
        None
    };
    bsd::start();

    rt::log_mem();
    // The relay serves only the LDN session; its loop runs on this thread (128 KiB stack).
    let relay = ldn_thread.as_ref().and_then(|_| {
        relay_thread::start().map_err(|rc| log!(Error, "relay: start failed: {rc:?}")).ok()
    });
    // Last: every thread stack (and its no-access guard page, which rt::heap_high_water must
    // skip) exists before maint starts scanning the heap.
    let maint_thread = Builder::new()
        .name("maint")
        .priority(ThreadPriority::Set(MAINT_PRIORITY))
        .stack_size(THREAD_STACK)
        .spawn(|| {
            // Cycles 0..600 so the counter never overflows: odd seconds trim the log, every second logs memory growth,
            // every 10 min ends an update probation.
            for tick in (0..600u32).cycle() {
                let _ = nx::thread::sleep(SECOND_NS);
                notify_io::pump();
                if tick % 2 == 1 {
                    log::maintain();
                }
                rt::log_mem();
                if tick == 599 {
                    update_io::mark_healthy(); // 10 min up counts as healthy (no-op off probation)
                }
            }
        });
    if let Err(rc) = maint_thread.as_ref() {
        panic!("thread start failed: {rc:?}");
    }
    // nx never frees a started thread's stack; keeping the handles costs nothing.
    let _keep = (cfg_thread, maint_thread, ldn_thread, relay);
    if _keep.3.is_some() {
        relay_thread::run();
    }
    loop {
        let _ = nx::thread::sleep(SECOND_NS);
    }
}
