//! Host build of nx's IPC layer, for the layout tests in `crates/ipc-tests` (`make test`).
//!
//! This is a second crate root over the same sources as `lib.rs`: every module below is the
//! production file, except the few that only make sense on the console, which come from
//! `ipc_host/`:
//! - `thread`: just the thread-local region, whose message buffer is the IPC buffer;
//! - `arm`: system tick from a counter instead of `cntpct_el0`;
//! - `mem`, `rrt0`: no heap set-up (std's allocator) and no process entry/exit;
//! - `svc/asm.rs` (swapped in `svc.rs`): the IPC SVCs go to [`ipc_host::kernel`], a model of
//!   what Horizon's kernel does with a message; every other SVC panics.
//!
//! Not built for the Switch (crates/sys uses `lib.rs`).

#![feature(allocator_api)]
#![allow(dead_code, unused_imports, unused_macros, stable_features, clippy::all)]

extern crate self as nx;

#[macro_use]
extern crate alloc;

extern crate std;

#[macro_use]
extern crate static_assertions;

#[macro_use]
pub mod macros;

#[macro_use]
pub mod result;

pub mod rc;

#[macro_use]
pub mod util;

#[path = "ipc_host/mem.rs"]
pub mod mem;

pub mod hbl;

#[path = "ipc_host/rrt0.rs"]
pub mod rrt0;

pub mod sync;

#[path = "ipc_host/thread.rs"]
pub mod thread;

#[allow(clippy::missing_safety_doc)]
pub mod svc;

#[macro_use]
pub mod ipc;

#[macro_use]
pub mod diag;

#[path = "ipc_host/arm.rs"]
pub mod arm;

pub mod wait;

pub mod version;

pub mod service;

pub mod ipc_host {
    pub mod kernel;
}
