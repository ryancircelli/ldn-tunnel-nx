//! Remote log flush (port of `RyuLdnClient::send_remote_log`): lines drained from the
//! [`LogRing`] become DebugLog (0xC0) packets `[u8 label_len][label][lines, \n-separated]`,
//! at most [`MAX_PACKETS`] per [`INTERVAL_MS`]. While a game holds the link
//! ([`RemoteLog::set_game`]) the logs share the WebSocket with its packets, so they keep out
//! of the way: one packet per [`GAME_INTERVAL_MS`], none while game packets wait to be sent.
//! A forced flush (the session ends) sends the full budget.
//!
//! The ring is drained when a payload is built, so a payload that cannot be sent is lost
//! (the C++ keeps a cursor and retries). Only flush while the connection is Ready.
use core::fmt::Write;

use heapless::String;

use crate::SliceWriter;
use crate::logring::LogRing;

pub const INTERVAL_MS: u64 = 500;
/// Packets per interval.
pub const MAX_PACKETS: u8 = 4;
/// During a game: one packet (<= 2 KB) per this many ms, ~400 B/s at most.
pub const GAME_INTERVAL_MS: u64 = 5000;
/// The C++ packet buffer is 2000 bytes including the 12-byte header; the relay drops > 2048.
pub const MAX_PAYLOAD: usize = 1988;
pub const MAX_LABEL: usize = 32;
/// Room kept for "[N earlier log lines dropped]\n".
const NOTE_ROOM: usize = 40;
/// Smallest `out` that fits a label, one full line and the note.
pub const MIN_OUT: usize = 1 + MAX_LABEL + crate::logring::LINE_LEN + 1 + NOTE_ROOM;

#[derive(Clone, Debug)]
pub struct RemoteLog {
    label: String<MAX_LABEL>,
    last_ms: Option<u64>,
    sent: u8,
    active: bool,
    game: bool,
    /// In a game and its packets are queued: send nothing (unless forced).
    hold: bool,
}

impl RemoteLog {
    /// `label` = "<nickname> <last 4 of serial>"; cut to 32 bytes, "switch" when empty (the
    /// relay drops a packet without a label).
    pub fn new(label: &str) -> Self {
        let mut l = String::new();
        for c in label.chars() {
            if c.is_control() || l.push(c).is_err() {
                break;
            }
        }
        if l.trim().is_empty() {
            l.clear();
            let _ = l.push_str("switch");
        }
        Self { label: l, last_ms: None, sent: 0, active: false, game: false, hold: false }
    }

    /// Before each flush: does a game hold the link (the session wants it), and is its send
    /// queue empty.
    pub fn set_game(&mut self, game: bool, queue_empty: bool) {
        self.game = game;
        self.hold = game && !queue_empty;
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// Write the next DebugLog payload to `out` and return its length; `None` when the ring is
    /// empty, the interval has not elapsed, or this interval's budget is spent. Call in a loop
    /// (`while let Some(n) = ...`) and send each payload as `PacketId::DebugLog`. `force`
    /// ignores the interval (the flush before a disconnect). `out` should be at least
    /// [`MIN_OUT`] bytes; at most [`MAX_PAYLOAD`] are used.
    pub fn next_payload(&mut self, ring: &mut LogRing, now_ms: u64, force: bool, out: &mut [u8]) -> Option<usize> {
        let paced = self.game && !force;
        if paced && self.hold {
            return None;
        }
        let (interval, budget) = if paced { (GAME_INTERVAL_MS, 1) } else { (INTERVAL_MS, MAX_PACKETS) };
        if !self.active {
            if !force && self.last_ms.is_some_and(|l| now_ms.saturating_sub(l) < interval) {
                return None;
            }
            self.active = true;
            self.sent = 0;
            self.last_ms = Some(now_ms);
        }
        if self.sent >= budget || ring.is_empty() {
            self.active = false;
            return None;
        }
        let cap = out.len().min(MAX_PAYLOAD);
        let out = out.get_mut(..cap)?;
        let head = 1usize.saturating_add(self.label.len());
        if out.len() < MIN_OUT {
            return None;
        }
        let (hdr, text) = out.split_at_mut(head);
        let (len_byte, label) = hdr.split_first_mut()?;
        *len_byte = self.label.len() as u8;
        label.copy_from_slice(self.label.as_bytes());

        let room = text.len().saturating_sub(NOTE_ROOM);
        let (used, dropped) = ring.drain_into(text.get_mut(..room)?);
        let mut c = SliceWriter { buf: text, pos: used };
        let mut total = used;
        if dropped > 0 && writeln!(c, "[{dropped} earlier log lines dropped]").is_ok() {
            total = c.pos;
        }
        if total == 0 {
            self.active = false;
            return None;
        }
        self.sent = self.sent.saturating_add(1);
        Some(head.saturating_add(total))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;
    use std::{format, vec::Vec};

    fn split(p: &[u8]) -> (&str, &str) {
        let n = p[0] as usize;
        (core::str::from_utf8(&p[1..1 + n]).unwrap(), core::str::from_utf8(&p[1 + n..]).unwrap())
    }

    #[test]
    fn packages_lines_with_label() {
        let mut ring = LogRing::new();
        ring.push("hello");
        ring.push("world");
        let mut rl = RemoteLog::new("Switch 1234");
        let mut out = [0u8; 2048];
        let n = rl.next_payload(&mut ring, 1000, false, &mut out).unwrap();
        assert_eq!(split(&out[..n]), ("Switch 1234", "hello\nworld\n"));
        assert_eq!(rl.next_payload(&mut ring, 1000, false, &mut out), None);
    }

    #[test]
    fn interval_and_packet_budget() {
        let mut ring = LogRing::new();
        let mut rl = RemoteLog::new("x");
        let mut out = [0u8; 2048];
        // ~60 lines of 250 bytes = many packets; only 4 per interval
        for i in 0..60 {
            ring.push(&format!("{i:03}{}", "z".repeat(240)));
        }
        let mut packets = Vec::new();
        while let Some(n) = rl.next_payload(&mut ring, 10_000, false, &mut out) {
            assert!(n <= MAX_PAYLOAD);
            packets.push(n);
        }
        assert_eq!(packets.len(), 4);
        assert!(!ring.is_empty());
        // too early: nothing; after the interval: more, in order
        assert_eq!(rl.next_payload(&mut ring, 10_499, false, &mut out), None);
        let n = rl.next_payload(&mut ring, 10_500, false, &mut out).unwrap();
        // 4 packets * 7 lines (7*251 = 1757 <= 1988-2) were taken before, so line 028 is next
        assert!(split(&out[..n]).1.starts_with("028"), "{}", &split(&out[..n]).1[..3]);
        assert!(rl.next_payload(&mut ring, 10_501, false, &mut out).is_some()); // same window
    }

    #[test]
    fn force_and_dropped_note() {
        let mut ring = LogRing::new();
        let mut rl = RemoteLog::new("x");
        let mut out = [0u8; 2048];
        for i in 0..70 {
            ring.push(&format!("l{i}"));
        }
        let n = rl.next_payload(&mut ring, 5, true, &mut out).unwrap();
        let text = split(&out[..n]).1;
        assert!(text.starts_with("l6\n"));
        assert!(text.ends_with("[6 earlier log lines dropped]\n"), "{text:?}");
        ring.push("late");
        let n = rl.next_payload(&mut ring, 6, false, &mut out).unwrap();
        assert_eq!(split(&out[..n]).1, "late\n");
        assert_eq!(rl.next_payload(&mut ring, 6, false, &mut out), None); // empty closes the window
        ring.push("next");
        assert_eq!(rl.next_payload(&mut ring, 7, false, &mut out), None); // too early
        assert!(rl.next_payload(&mut ring, 7, true, &mut out).is_some()); // force
        ring.push("more");
        assert!(rl.next_payload(&mut ring, 8, false, &mut out).is_some()); // window still open
    }

    #[test]
    fn game_pacing() {
        let mut ring = LogRing::new();
        let mut rl = RemoteLog::new("x");
        let mut out = [0u8; 2048];
        for i in 0..60 {
            ring.push(&format!("{i:03}{}", "z".repeat(240)));
        }
        rl.set_game(true, false); // game packets queued: nothing
        assert_eq!(rl.next_payload(&mut ring, 1000, false, &mut out), None);
        rl.set_game(true, true);
        assert!(rl.next_payload(&mut ring, 1000, false, &mut out).is_some());
        assert_eq!(rl.next_payload(&mut ring, 1000, false, &mut out), None); // one per window
        assert_eq!(rl.next_payload(&mut ring, 5999, false, &mut out), None);
        assert!(rl.next_payload(&mut ring, 6000, false, &mut out).is_some());
        assert_eq!(rl.next_payload(&mut ring, 6000, false, &mut out), None);
        // the session ends: forced, full budget even with a queue
        rl.set_game(true, false);
        let mut n = 0;
        while rl.next_payload(&mut ring, 6001, true, &mut out).is_some() {
            n += 1;
        }
        assert_eq!(n, MAX_PACKETS);
        // no game: back to 4 per 500 ms
        for i in 0..40 {
            ring.push(&format!("{i:03}{}", "z".repeat(240)));
        }
        rl.set_game(false, false);
        let mut n = 0;
        while rl.next_payload(&mut ring, 6600, false, &mut out).is_some() {
            n += 1;
        }
        assert_eq!(n, MAX_PACKETS);
    }

    #[test]
    fn label_rules() {
        assert_eq!(RemoteLog::new("").label(), "switch");
        assert_eq!(RemoteLog::new("  ").label(), "switch");
        assert_eq!(RemoteLog::new(&"a".repeat(80)).label().len(), 32);
        assert_eq!(RemoteLog::new("a\nb").label(), "a");
        // multi-byte chars are cut on a boundary
        let l = RemoteLog::new(&"é".repeat(40));
        assert_eq!(l.label().len(), 32);
    }
}
