//! `gamelist.txt` parser (port of `whitelist_parser.hpp` + `game_whitelist.cpp`).
//!
//! One hex program id per line (`0x` optional, any case), BOM and leading blanks skipped,
//! parsing of a line stops at the first non-hex character (so trailing comments work),
//! ids that parse to 0 are ignored, lines are cut at 24 bytes, only the first
//! [`MAX_ENTRIES`] ids are kept.
use heapless::Vec;

pub const MAX_ENTRIES: usize = 8192;
const MAX_LINE: usize = 24;

#[derive(Clone, Debug, Default)]
pub struct Whitelist {
    ids: Vec<u64, MAX_ENTRIES>,
}

fn parse_hex_id(line: &[u8]) -> u64 {
    let digits = match line {
        [b'0', b'x' | b'X', rest @ ..] => rest,
        _ => line,
    };
    let mut id = 0u64;
    for &c in digits {
        let Some(d) = (c as char).to_digit(16) else { break };
        id = (id << 4) | u64::from(d);
    }
    id
}

/// The id on one line (no line break), 0 for none. The overlay reads gamelist.txt line by line.
pub fn line_id(raw: &[u8]) -> u64 {
    let start = raw.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(raw.len());
    let line = raw.get(start..).unwrap_or(&[]);
    parse_hex_id(line.get(..MAX_LINE).unwrap_or(line))
}

impl Whitelist {
    pub const fn new() -> Self {
        Self { ids: Vec::new() }
    }

    /// Replaces the contents. Returns how many valid ids were found beyond the capacity.
    pub fn load(&mut self, data: &[u8]) -> usize {
        self.ids.clear();
        let data = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
        let mut overflow = 0usize;
        for raw in data.split(|&b| b == b'\n' || b == b'\r') {
            let id = line_id(raw);
            if id != 0 && self.ids.push(id).is_err() {
                overflow = overflow.saturating_add(1);
            }
        }
        overflow
    }

    pub fn contains(&self, program_id: u64) -> bool {
        self.ids.contains(&program_id)
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    extern crate std;
    use super::*;
    use std::{format, string::String, vec::Vec};

    #[test]
    fn parses_forms() {
        let mut w = Whitelist::new();
        let n = w.load(b"\xEF\xBB\xBF0x0100C2500FC20000\r\n  0100a3d008c5c000 # c\n\n0\nzz\n0X10\n");
        assert_eq!(n, 0);
        assert_eq!(w.len(), 3);
        assert!(w.contains(0x0100_C250_0FC2_0000));
        assert!(w.contains(0x0100_a3d0_08c5_c000));
        assert!(w.contains(0x10));
        assert!(!w.contains(0));
    }

    #[test]
    fn capacity() {
        let text: String = (1..=MAX_ENTRIES + 5).map(|i| format!("{i:x}\n")).collect();
        let mut w = Whitelist::new();
        assert_eq!(w.load(text.as_bytes()), 5);
        assert_eq!(w.len(), MAX_ENTRIES);
        assert!(!w.contains(MAX_ENTRIES as u64 + 1));
    }

    #[test]
    fn shipped_list_loads() {
        let mut w = Whitelist::new();
        assert_eq!(w.load(include_bytes!("../../../relay/assets/gamelist.txt")), 0);
        assert!(w.len() > 4000);
        assert!(w.contains(0x0100_c250_0fc2_0000));
    }

    #[test]
    fn random_input_does_not_panic() {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut w = Whitelist::new();
        for round in 0..2000 {
            let len = (next() % 900) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| if round % 2 == 0 { next() as u8 } else { b"0123456789abcdefxX \r\n#"[(next() % 22) as usize] })
                .collect();
            w.load(&bytes);
            let _ = w.contains(next());
        }
    }
}
