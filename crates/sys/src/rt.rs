//! Runtime entry points nx's rrt0 links against: heap, `main`, panic handler.
//! `unsafe` in crates/sys lives here and in bsd/service.rs + server/forward.rs (the crate root denies `unsafe_code`; every other
//! module also forbids it). Each item says why it is sound.
#![allow(unsafe_code)]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use ldn_tunnel_core::ident;
use nx::diag::abort::{self, AbortLevel};
use nx::result::ResultBase;
use nx::{rc, util};

// Expands to the `#[unsafe(link_section)]` module-name record rrt0 expects.
nx::rrt0_define_module_name!(ident::NAME);

/// Every Box/Vec/Arc AND every extra thread's stack (nx::thread::Builder
/// allocates stacks from this heap) lives here. It sits in .bss, so it costs
/// memory but not NSO size. 1 MiB ran out once a game opened a room (every intercepted bsd
/// session holds forward buffers); the maint thread logs the high-water mark every 30 s.
const HEAP_SIZE: usize = 0x30_0000;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

// SAFETY (no_mangle): the symbol name is the one nx's rrt0 calls; nothing else
// in the link defines it.
#[unsafe(no_mangle)]
pub fn initialize_heap(_hbl_heap: util::PointerAndSize) -> util::PointerAndSize {
    // SAFETY: nx calls this exactly once, before main and before any other
    // thread exists; the buffer is handed to the allocator and never touched again.
    util::PointerAndSize::new((&raw mut HEAP).cast(), HEAP_SIZE)
}

// SAFETY (no_mangle): rrt0's entry symbol, defined once.
#[unsafe(no_mangle)]
pub fn main() {
    crate::run()
}

/// Bytes of the heap ever touched: the offset past the last non-zero byte of
/// `HEAP` (a never-used .bss page is all zero, a freed block keeps its data), so
/// it is the allocator's high-water mark rounded to what was actually written.
/// ponytail: underestimates by trailing zero bytes of the topmost block; exact
/// used/peak needs a counting allocator in nx (private `GLOBAL_ALLOCATOR`).
/// Pages the kernel reports unreadable (the guard page nx puts under every thread stack)
/// are skipped: reading one faults.
pub fn heap_high_water() -> usize {
    use core::sync::atomic::AtomicU8;
    use nx::svc::{query_memory, MemoryPermission};
    // SAFETY: HEAP lives for the whole run; AtomicU8 has the layout of u8 and
    // atomic loads make the race with the allocator's writes benign.
    let heap: &[AtomicU8; HEAP_SIZE] = unsafe { &*(&raw const HEAP).cast() };
    let base = heap.as_ptr() as usize;
    let mut end = HEAP_SIZE;
    while let Some(last) = end.checked_sub(1).and_then(|i| heap.get(i)) {
        // The kernel memory block holding `last`: [start, end) of HEAP shares its permission.
        let Ok((mi, _)) = query_memory(last.as_ptr().cast_const()) else { return 0 };
        let start = mi.base_address.saturating_sub(base).min(end);
        if mi.permission.contains(MemoryPermission::Read()) {
            let block = heap.get(start..end).unwrap_or_default();
            if let Some(i) = block.iter().rposition(|b| b.load(Ordering::Relaxed) != 0) {
                return start.saturating_add(i).saturating_add(1);
            }
        }
        end = start;
    }
    0
}

/// `mem: heap high=<n> of <cap> proc=<used> of <total>`.
/// `proc` is the kernel's UsedMemorySize/TotalMemorySize for this process.
/// Logs at Info only when the heap high-water mark rose 64 KiB or more since the last line,
/// so a runaway allocation shows its growth second by second before the heap runs out.
pub fn log_mem() {
    use core::sync::atomic::AtomicUsize;
    static LAST: AtomicUsize = AtomicUsize::new(0);
    let high = heap_high_water();
    if high < LAST.load(Ordering::Relaxed).saturating_add(0x1_0000) {
        return;
    }
    LAST.store(high, Ordering::Relaxed);
    let info = |id| nx::svc::get_info(id, nx::svc::CURRENT_PROCESS_PSEUDO_HANDLE, 0).unwrap_or(0);
    log!(
        Info,
        "mem: heap high={} of {} proc={} of {}",
        high,
        HEAP_SIZE,
        info(nx::svc::InfoId::UsedMemorySize),
        info(nx::svc::InfoId::TotalMemorySize)
    );
}

static PANICKING: AtomicBool = AtomicBool::new(false);

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Best effort, once: the log write allocates, so a nested panic (e.g. an
    // out-of-memory heap) skips it.
    if !PANICKING.swap(true, Ordering::SeqCst) {
        crate::log::panic_line(format_args!("{info}"));
    }
    // svcBreak: Atmosphere's creport writes a crash report to the SD card.
    abort::abort(AbortLevel::SvcBreak(), rc::ResultPanicked::make())
}
