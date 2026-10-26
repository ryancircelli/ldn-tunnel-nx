//! Game datagram counters for one LDN session, for the session-end log line. Counters
//! only: the send/receive paths add to them, nothing allocates.

use core::fmt;

/// One direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dir {
    pub packets: u32,
    pub bytes: u64,
    /// Longest silence between two datagrams.
    pub max_gap_ms: u64,
    last_ms: Option<u64>,
}

impl Dir {
    pub const fn new() -> Self {
        Self { packets: 0, bytes: 0, max_gap_ms: 0, last_ms: None }
    }

    fn add(&mut self, len: usize, now_ms: u64) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
        if let Some(last) = self.last_ms {
            self.max_gap_ms = self.max_gap_ms.max(now_ms.saturating_sub(last));
        }
        self.last_ms = Some(now_ms);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    /// Game -> relay (queued for the relay thread).
    pub out: Dir,
    /// Relay -> game sockets (or the pending ring).
    pub inp: Dir,
    /// Sends refused because the relay queue was full (the game got ENETUNREACH).
    pub queue_full: u32,
    /// Datagrams in with no socket bound to their port (kept in the pending ring).
    pub no_socket: u32,
}

impl Traffic {
    pub const fn new() -> Self {
        Self { out: Dir::new(), inp: Dir::new(), queue_full: 0, no_socket: 0 }
    }

    /// A game datagram handed to the relay queue (`queued`) or refused.
    pub fn on_out(&mut self, len: usize, queued: bool, now_ms: u64) {
        if queued {
            self.out.add(len, now_ms);
        } else {
            self.queue_full = self.queue_full.saturating_add(1);
        }
    }

    /// A datagram from the relay, queued on `sockets` sockets.
    pub fn on_in(&mut self, len: usize, sockets: usize, now_ms: u64) {
        self.inp.add(len, now_ms);
        if sockets == 0 {
            self.no_socket = self.no_socket.saturating_add(1);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.out.packets == 0 && self.inp.packets == 0 && self.queue_full == 0
    }

    /// Formats the summary as of `now_ms` (how long ago the last datagram went each way).
    pub fn report(&self, now_ms: u64) -> Report<'_> {
        Report(self, now_ms)
    }
}

pub struct Report<'a>(&'a Traffic, u64);

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Report(t, now) = *self;
        for (name, d) in [("out", &t.out), ("in", &t.inp)] {
            write!(f, "{name} {} pkts {} B, max gap {} ms", d.packets, d.bytes, d.max_gap_ms)?;
            match d.last_ms {
                Some(last) => write!(f, ", last {} ms ago; ", now.saturating_sub(last))?,
                None => f.write_str("; ")?,
            }
        }
        write!(f, "{} sends refused (queue full), {} in with no socket", t.queue_full, t.no_socket)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::ToString;

    #[test]
    fn counts_gaps_and_report() {
        let mut t = Traffic::default();
        assert!(t.is_empty());
        t.on_out(100, true, 1000);
        t.on_out(50, true, 1016);
        t.on_out(50, false, 1020);
        t.on_in(200, 1, 1000);
        t.on_in(200, 0, 3500);
        assert_eq!(
            t.report(4000).to_string(),
            "out 2 pkts 150 B, max gap 16 ms, last 2984 ms ago; in 2 pkts 400 B, max gap 2500 ms, last 500 ms ago; \
             1 sends refused (queue full), 1 in with no socket"
        );
    }
}
