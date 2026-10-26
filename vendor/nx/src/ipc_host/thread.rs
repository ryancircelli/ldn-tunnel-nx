//! Host stand-in for `thread.rs` (see `ipc_host.rs`): one thread-local region per host thread.

use crate::result::Result;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

pub type ThreadName = crate::util::ArrayString<0x20>;

#[repr(C)]
pub struct LibNxThreadVars {
    /// Unique per host thread: `sync::Mutex` tags its owner with it.
    pub handle: u32,
}

#[repr(C, align(16))]
pub struct ThreadLocalRegion {
    pub msg_buffer: [u8; 0x100],
    pub nx_thread_vars: LibNxThreadVars,
}

pub mod imp {
    pub struct Thread {
        pub name: super::ThreadName,
    }

    impl Thread {
        pub fn id(&self) -> crate::result::Result<u64> {
            Ok(0)
        }
    }
}

static NEXT_HANDLE: AtomicU32 = AtomicU32::new(0x100);

std::thread_local! {
    static TLR: UnsafeCell<ThreadLocalRegion> = UnsafeCell::new(ThreadLocalRegion {
        msg_buffer: [0; 0x100],
        nx_thread_vars: LibNxThreadVars { handle: NEXT_HANDLE.fetch_add(1, Ordering::Relaxed) },
    });
}

pub fn get_thread_local_region() -> *mut ThreadLocalRegion {
    TLR.with(|tlr| tlr.get())
}

pub(crate) unsafe fn current() -> *mut imp::Thread {
    core::ptr::null_mut()
}

pub fn sleep(timeout: i64) -> Result<()> {
    std::thread::sleep(std::time::Duration::from_nanos(timeout.max(0) as u64));
    Ok(())
}
