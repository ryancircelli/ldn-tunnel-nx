//! Host stand-in for `mem.rs` (see `ipc_host.rs`): std's allocator is the heap.

pub mod alloc {
    pub fn is_enabled() -> bool {
        true
    }
}
