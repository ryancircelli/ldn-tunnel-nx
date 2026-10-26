//! Remote-log ring (port of `LogBuffer`/`Logger::take_remote` in `debug/log.cpp` and the
//! DebugLog (0xC0) flush in `client.cpp`). Pure: the shell formats lines (timestamp, level
//! tag), pushes them, and sends what [`LogRing::drain_into`] fills into a packet.
use heapless::{Deque, String};

pub const RING_LINES: usize = 64;
/// C++ MAX_LOG_MESSAGE_LENGTH is 256 including the NUL.
pub const LINE_LEN: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warning = 1,
    Info = 2,
    Verbose = 3,
}

#[derive(Debug, Default)]
pub struct LogRing {
    lines: Deque<String<LINE_LEN>, RING_LINES>,
    dropped: u64,
}

impl LogRing {
    pub const fn new() -> Self {
        Self { lines: Deque::new(), dropped: 0 }
    }

    /// Stores `msg` (cut to [`LINE_LEN`] bytes on a char boundary; line breaks become spaces
    /// because the flush format is `\n`-separated). A full ring overwrites its oldest line.
    pub fn push(&mut self, msg: &str) {
        let mut text = String::new();
        for c in msg.chars() {
            if text.push(if c == '\n' || c == '\r' { ' ' } else { c }).is_err() {
                break;
            }
        }
        if self.lines.is_full() {
            self.lines.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        let _ = self.lines.push_back(text);
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Lines overwritten before they were drained, since the last successful drain.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Copies lines oldest first as `line\n` into `out` and removes them from the ring; stops
    /// before a line that does not fit (it stays for the next call). Returns
    /// `(bytes_used, dropped)` and resets the dropped counter, so the caller can append
    /// "[N earlier log lines dropped]".
    pub fn drain_into(&mut self, out: &mut [u8]) -> (usize, u64) {
        let mut used = 0usize;
        while let Some(line) = self.lines.front() {
            let bytes = line.as_bytes();
            let end = used.saturating_add(bytes.len()).saturating_add(1);
            let Some(dst) = out.get_mut(used..end) else { break };
            let (body, nl) = dst.split_at_mut(bytes.len());
            body.copy_from_slice(bytes);
            nl.fill(b'\n');
            used = end;
            self.lines.pop_front();
        }
        (used, core::mem::take(&mut self.dropped))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    #[test]
    fn push_truncate_and_drain_order() {
        let mut r = LogRing::new();
        r.push("first");
        r.push(&"x".repeat(400));
        r.push("a\nb");
        let mut out = [0u8; 1024];
        let (n, dropped) = r.drain_into(&mut out);
        assert_eq!(dropped, 0);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        let lines: std::vec::Vec<_> = s.split('\n').collect();
        assert_eq!(lines[0], "first");
        assert_eq!(lines[1].len(), LINE_LEN);
        assert_eq!(lines[2], "a b");
        assert!(r.is_empty());
    }

    #[test]
    fn overwrite_counts_dropped_and_partial_drain_keeps_rest() {
        let mut r = LogRing::new();
        for i in 0..RING_LINES + 3 {
            r.push(&format!("l{i}"));
        }
        assert_eq!(r.len(), RING_LINES);
        assert_eq!(r.dropped(), 3);
        let mut small = [0u8; 8]; // "l3\n" "l4\n" fit, "l5\n" does not
        let (n, dropped) = r.drain_into(&mut small);
        assert_eq!((n, dropped), (6, 3));
        assert_eq!(&small[..n], b"l3\nl4\n");
        assert_eq!(r.len(), RING_LINES - 2);
        assert_eq!(r.dropped(), 0);
        let mut big = [0u8; 4096];
        let (n, _) = r.drain_into(&mut big);
        assert!(core::str::from_utf8(&big[..n]).unwrap().starts_with("l5\n"));
        assert_eq!(r.drain_into(&mut big), (0, 0));
    }
}
