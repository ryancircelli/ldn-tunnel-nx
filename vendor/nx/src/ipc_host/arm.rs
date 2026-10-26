//! Host stand-in for `arm.rs` (see `ipc_host.rs`): the types `svc` names and a fake tick.

use core::sync::atomic::{AtomicU64, Ordering};

/// Not a real register dump: only `svc`'s debug calls name it, and they panic on the host.
#[derive(Copy, Clone, Debug, Default)]
pub struct ThreadContext;

define_bit_set! {
    RegisterGroup (u32) {
        CpuGprs = bit!(0),
        CpuSprs = bit!(1),
        FpuGprs = bit!(2),
        FpuSprs = bit!(3)
    }
}

/// 19.2 MHz, as the console.
const TICK_FREQUENCY: u64 = 19_200_000;
static TICK: AtomicU64 = AtomicU64::new(0);

pub fn cache_flush(_address: *mut u8, _size: usize) {}

/// Advances on every read, so deadlines computed from it are always in the future.
pub fn get_system_tick() -> u64 {
    TICK.fetch_add(1, Ordering::Relaxed)
}

pub fn get_system_tick_frequency() -> u64 {
    TICK_FREQUENCY
}

pub const fn ticks_to_nanoseconds(ticks: u64) -> u64 {
    (ticks * 625) / 12
}

pub const fn nanoseconds_to_ticks(ns: u64) -> u64 {
    (ns * 12) / 625
}
