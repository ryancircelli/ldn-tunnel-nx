use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::*;

//use super::*;

use crate::diag::abort;
use crate::svc;

use super::get_current_thread_handle;

const WAIT_MASK: u32 = 0x40_00_00_00;

pub struct Mutex {
    owner_thread_handle: AtomicU32,
}

impl Mutex {
    #[inline]
    pub const fn new() -> Self {
        Self {
            owner_thread_handle: AtomicU32::new(svc::INVALID_HANDLE),
        }
    }

    #[inline]
    pub fn is_locked(&self) -> bool {
        (self.owner_thread_handle.load(Relaxed) & !WAIT_MASK) != svc::INVALID_HANDLE
    }

    #[inline]
    pub fn try_lock(&self) -> bool {
        self.owner_thread_handle
            .compare_exchange(
                svc::INVALID_HANDLE,
                get_current_thread_handle(),
                Acquire,
                Relaxed,
            )
            .is_ok()
    }

    #[inline]
    pub fn lock(&self) {
        let current_thread = get_current_thread_handle();
        let _current_val = self.owner_thread_handle.load(Relaxed);
        if let Err(state) = self.owner_thread_handle.compare_exchange(
            svc::INVALID_HANDLE,
            current_thread,
            Acquire,
            Relaxed,
        ) {
            self.lock_contended(state, current_thread);
        }
    }

    /// libnx `mutexLock`: owned → make sure the wait bit is set, then let the kernel queue
    /// us behind the owner; re-read after every step. Every path either takes the lock,
    /// sleeps in `svcArbitrateLock`, or retries on a fresh value, so it never spins.
    #[cold]
    fn lock_contended(&self, mut state: u32, current_thread: u32) {
        loop {
            if state == svc::INVALID_HANDLE {
                match self.owner_thread_handle.compare_exchange(
                    svc::INVALID_HANDLE,
                    current_thread,
                    Acquire,
                    Relaxed,
                ) {
                    Ok(_) => return,
                    Err(s) => {
                        state = s;
                        continue;
                    }
                }
            }
            if state & WAIT_MASK == 0
                && let Err(s) = self.owner_thread_handle.compare_exchange(
                    state,
                    state | WAIT_MASK,
                    Relaxed,
                    Relaxed,
                )
            {
                state = s;
                continue;
            }
            if let Err(rc) = unsafe {
                svc::arbitrate_lock(
                    state & !WAIT_MASK,
                    &self.owner_thread_handle as *const _ as _,
                    current_thread,
                )
            } {
                abort::abort(abort::AbortLevel::Panic(), rc);
            }
            // The kernel hands the lock straight to the waiter it wakes.
            state = self.owner_thread_handle.load(Acquire);
            if state & !WAIT_MASK == current_thread {
                return;
            }
        }
    }

    /// libnx `mutexUnlock`. With waiters the value is left for the kernel, which writes the
    /// next owner (zeroing it first would let a `try_lock` in and give the lock out twice).
    ///
    /// # Safety
    ///
    /// Only the thread holding the lock may call this.
    #[inline]
    pub unsafe fn unlock(&self) {
        let current_thread = get_current_thread_handle();
        if self
            .owner_thread_handle
            .compare_exchange(current_thread, svc::INVALID_HANDLE, Release, Relaxed)
            .is_err()
            && let Err(rc) =
                unsafe { svc::arbitrate_unlock(&self.owner_thread_handle as *const _ as _) }
        {
            abort::abort(abort::AbortLevel::Panic(), rc);
        }
    }
}

impl Default for Mutex {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::declare_interior_mutable_const)]
unsafe impl lock_api::RawMutex for Mutex {
    // mark that a mutex guard can be Send
    type GuardMarker = lock_api::GuardSend;

    // const initializer for the Mutex
    const INIT: Self = Self::new();

    fn is_locked(&self) -> bool {
        self.is_locked()
    }

    fn lock(&self) {
        self.lock()
    }

    fn try_lock(&self) -> bool {
        self.try_lock()
    }

    unsafe fn unlock(&self) {
        unsafe { self.unlock() }
    }
}
