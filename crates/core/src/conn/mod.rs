//! The relay connection as pure sans-IO logic: the shell moves bytes over the TLS stream and
//! supplies the clock and random numbers; nothing here does I/O.
//!
//! - [`drop_stats`]: the line logged when a link ends (who cut it).
//! - [`handshake`]: WebSocket upgrade request and response check.
//! - [`state`]: [`ConnectionState`] machine and [`Conn`] (frame decode, Initialize, Ping,
//!   keepalive, Close, backoff).
//! - [`reconnect`]: the backoff schedule.
//! - [`update_dl`]: console side of the update channel (0xC1..0xC4).
//! - [`remote_log`]: DebugLog (0xC0) packets from the log ring.
pub mod drop_stats;
pub mod handshake;
pub mod reconnect;
pub mod remote_log;
pub mod state;
pub mod update_dl;

pub use state::{Action, Conn, ConnConfig, ConnectionState, Failure, Session};

#[cfg(test)]
mod tests;
