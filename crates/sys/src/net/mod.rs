//! Transport for the relay thread: our own `bsd:s` sockets, DNS, wall clock, csrng.
//! `socket::initialize()` must run once before any socket or `dns::resolve`.
pub mod clock;
pub mod dns;
mod getrandom;
mod ipc;
pub mod rng;
pub mod socket;
