//! TCP stream buffer (port of protocol/packet_buffer.hpp, PacketBuffer<N>).
//!
//! The storage is the caller's: `buf` is the whole array (capacity long)
//! and `len` the byte count in it. Trivial accessors stay in C++.

use crate::protocol::{DecodeResult, HEADER_SIZE, check_complete_packet, decode_header};

/// Mirrors ryu_ldn::protocol::BufferResult.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferResult {
    Success = 0,
    BufferFull = 1,
    NoCompletePacket = 2,
    PacketTooLarge = 3,
    InvalidPacket = 4,
}

/// Append `data`; BufferFull (nothing copied) if it does not fit.
pub fn append(buf: &mut [u8], len: &mut usize, data: &[u8]) -> BufferResult {
    if data.is_empty() {
        return BufferResult::Success;
    }
    // *len > cap would be a caller bug; clamp instead of panicking.
    let used = (*len).min(buf.len());
    let end = used.saturating_add(data.len());
    match buf.get_mut(used..end) {
        Some(dst) if end > used => {
            dst.copy_from_slice(data);
            *len = end;
            BufferResult::Success
        }
        _ => BufferResult::BufferFull,
    }
}

/// Status of the packet at the head of `data` (the buffered bytes).
/// The size is check_complete_packet's: 12 + data_size on Success and on
/// IncompletePacket (reported as NoCompletePacket), else 0. Same as C++.
pub fn peek_packet_info(data: &[u8]) -> (BufferResult, usize) {
    if data.len() < HEADER_SIZE {
        return (BufferResult::NoCompletePacket, 0);
    }
    let (result, packet_size) = check_complete_packet(data);
    let result = match result {
        DecodeResult::Success => BufferResult::Success,
        DecodeResult::IncompletePacket | DecodeResult::BufferTooSmall => {
            BufferResult::NoCompletePacket
        }
        DecodeResult::PacketTooLarge => BufferResult::PacketTooLarge,
        DecodeResult::InvalidMagic | DecodeResult::InvalidVersion => BufferResult::InvalidPacket,
    };
    (result, packet_size)
}

/// Type byte of the head packet if its header decodes, else 0 (PacketId::Initialize).
pub fn peek_packet_type(data: &[u8]) -> u8 {
    if data.len() < HEADER_SIZE {
        return 0;
    }
    match decode_header(data) {
        (DecodeResult::Success, header) => header.type_,
        _ => 0,
    }
}

/// Drop `n` bytes from the front, shifting the rest down.
pub fn consume(buf: &mut [u8], len: &mut usize, n: usize) {
    if n == 0 {
        return;
    }
    let used = (*len).min(buf.len());
    if n >= used {
        *len = 0;
        return;
    }
    buf.copy_within(n..used, 0);
    *len = used.saturating_sub(n);
}

/// Copy the head packet to `out` and consume it. Returns peek_packet_info's
/// result and size, or BufferFull if `out` is too small (nothing consumed).
pub fn extract_packet(buf: &mut [u8], len: &mut usize, out: &mut [u8]) -> (BufferResult, usize) {
    let used = (*len).min(buf.len());
    let (result, packet_size) = peek_packet_info(buf.get(..used).unwrap_or_default());
    if result != BufferResult::Success {
        return (result, packet_size);
    }
    // Success means 12 + data_size <= used, so both slices exist.
    let (Some(dst), Some(src)) = (out.get_mut(..packet_size), buf.get(..packet_size)) else {
        return (BufferResult::BufferFull, packet_size);
    };
    dst.copy_from_slice(src);
    consume(buf, len, packet_size);
    (BufferResult::Success, packet_size)
}

/// Discard bytes one at a time until the head header decodes (Success or
/// IncompletePacket) or fewer than 12 bytes remain. Returns the count.
pub fn discard_until_valid(buf: &mut [u8], len: &mut usize) -> usize {
    let mut discarded: usize = 0;
    *len = (*len).min(buf.len());
    while *len >= HEADER_SIZE {
        // ponytail: one memmove per byte (O(n^2)) like the C++; fine for a recovery path.
        let (result, _) = decode_header(buf.get(..*len).unwrap_or_default());
        if result == DecodeResult::Success || result == DecodeResult::IncompletePacket {
            break;
        }
        consume(buf, len, 1);
        discarded = discarded.saturating_add(1);
    }
    discarded
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::arithmetic_side_effects
    )]
    extern crate std;
    use super::*;
    use crate::protocol::encode_header;
    use std::{vec, vec::Vec};

    const PING: u8 = 254;
    const SCAN: u8 = 10;

    /// Test stand-in for PacketBuffer<N>: storage + byte count.
    struct Pb {
        buf: Vec<u8>,
        len: usize,
    }

    impl Pb {
        fn new(cap: usize) -> Pb {
            Pb {
                buf: vec![0; cap],
                len: 0,
            }
        }
        fn append(&mut self, data: &[u8]) -> BufferResult {
            append(&mut self.buf, &mut self.len, data)
        }
        fn data(&self) -> &[u8] {
            &self.buf[..self.len]
        }
        fn info(&self) -> (BufferResult, usize) {
            peek_packet_info(self.data())
        }
        fn has_complete_packet(&self) -> bool {
            self.info().0 == BufferResult::Success
        }
        fn consume(&mut self, n: usize) {
            consume(&mut self.buf, &mut self.len, n)
        }
    }

    fn header(type_: u8, data_size: i32) -> [u8; 12] {
        let mut h = [0u8; 12];
        encode_header(&mut h, type_, data_size);
        h
    }

    /// encode_ping: header + PingMessage { requester, id }.
    fn ping(requester: u8, id: u8) -> Vec<u8> {
        let mut p = header(PING, 2).to_vec();
        p.extend_from_slice(&[requester, id]);
        p
    }

    #[test]
    fn buffer_empty_initially() {
        let b = Pb::new(1024);
        assert_eq!(b.len, 0);
        assert!(!b.has_complete_packet());
    }

    #[test]
    fn buffer_append_data() {
        let mut b = Pb::new(1024);
        assert_eq!(b.append(&[1, 2, 3, 4, 5]), BufferResult::Success);
        assert_eq!(b.len, 5);
        assert_eq!(b.data(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn buffer_size_and_available_after_append() {
        let mut b = Pb::new(256);
        b.append(&[0; 10]);
        assert_eq!(b.len, 10);
        assert_eq!(b.buf.len() - b.len, 246);
    }

    #[test]
    fn buffer_complete_packet_single_append() {
        let mut b = Pb::new(1024);
        let p = ping(1, 23);
        b.append(&p);
        assert_eq!(b.info(), (BufferResult::Success, p.len()));
    }

    #[test]
    fn buffer_fragmented_packet_2_parts() {
        let mut b = Pb::new(1024);
        let p = ping(1, 23);
        b.append(&p[..6]);
        assert!(!b.has_complete_packet());
        b.append(&p[6..]);
        assert!(b.has_complete_packet());
    }

    #[test]
    fn buffer_fragmented_packet_n_parts() {
        let mut b = Pb::new(1024);
        let p = ping(1, 42);
        for byte in &p[..p.len() - 1] {
            b.append(core::slice::from_ref(byte));
            assert!(!b.has_complete_packet());
        }
        b.append(&p[p.len() - 1..]);
        assert!(b.has_complete_packet());
    }

    #[test]
    fn buffer_multiple_packets() {
        let mut b = Pb::new(1024);
        b.append(&ping(1, 11));
        b.append(&ping(0, 22));
        b.append(&ping(1, 33));
        for id in [11, 22, 33] {
            let (r, size) = b.info();
            assert_eq!(r, BufferResult::Success);
            assert_eq!(b.data()[13], id);
            b.consume(size);
        }
        assert!(!b.has_complete_packet());
        assert_eq!(b.len, 0);
    }

    #[test]
    fn buffer_extract_packet() {
        let mut b = Pb::new(1024);
        let p = ping(0, 77);
        b.append(&p);
        let mut out = [0u8; 32];
        let (r, size) = extract_packet(&mut b.buf, &mut b.len, &mut out);
        assert_eq!(r, BufferResult::Success);
        assert_eq!(size, p.len());
        assert_eq!(b.len, 0);
        assert_eq!(&out[..size], &p[..]);
        assert_eq!((out[12], out[13]), (0, 77));
    }

    #[test]
    fn buffer_overflow_protection() {
        let mut b = Pb::new(64);
        assert_eq!(b.append(&[0; 128]), BufferResult::BufferFull);
        assert_eq!(b.len, 0);
    }

    #[test]
    fn buffer_append_overflow() {
        let mut b = Pb::new(16);
        assert_eq!(b.append(&[0; 20]), BufferResult::BufferFull);
        // Exactly full is fine, one more byte is not.
        assert_eq!(b.append(&[0; 16]), BufferResult::Success);
        assert_eq!(b.append(&[0]), BufferResult::BufferFull);
        assert_eq!(b.len, 16);
    }

    #[test]
    fn buffer_has_complete_packet_too_small() {
        let mut b = Pb::new(256);
        b.append(&[0; 4]);
        assert!(!b.has_complete_packet());
    }

    #[test]
    fn buffer_peek_packet_info_incomplete() {
        let b = Pb::new(256);
        assert_eq!(b.info(), (BufferResult::NoCompletePacket, 0));
    }

    #[test]
    fn buffer_peek_packet_info_partial_data_keeps_size() {
        // As in C++: NoCompletePacket, but the size is the announced one.
        let mut b = Pb::new(256);
        b.append(&ping(1, 2)[..13]);
        assert_eq!(b.info(), (BufferResult::NoCompletePacket, 14));
    }

    #[test]
    fn buffer_peek_packet_info_invalid_magic() {
        let mut b = Pb::new(256);
        b.append(&[0; 12]);
        assert_eq!(b.info(), (BufferResult::InvalidPacket, 0));
    }

    #[test]
    fn buffer_peek_packet_info_invalid_version() {
        let mut b = Pb::new(256);
        let mut h = header(PING, 0);
        h[5] = 99;
        b.append(&h);
        assert_eq!(b.info(), (BufferResult::InvalidPacket, 0));
    }

    #[test]
    fn buffer_peek_packet_info_valid() {
        let mut b = Pb::new(256);
        b.append(&header(PING, 2));
        b.append(&[0, 0]);
        assert_eq!(b.info(), (BufferResult::Success, 14));
    }

    #[test]
    fn buffer_peek_packet_valid() {
        let mut b = Pb::new(256);
        b.append(&header(PING, 0));
        assert_eq!(b.info(), (BufferResult::Success, 12));
    }

    #[test]
    fn buffer_peek_packet_type() {
        let mut b = Pb::new(256);
        b.append(&header(SCAN, 0));
        assert_eq!(peek_packet_type(b.data()), SCAN);
        // Incomplete data still reports the type (only the header must decode).
        let mut b = Pb::new(256);
        b.append(&header(SCAN, 100));
        assert_eq!(peek_packet_type(b.data()), SCAN);
    }

    #[test]
    fn buffer_peek_packet_type_empty() {
        assert_eq!(peek_packet_type(&[]), 0);
        let mut bad = header(SCAN, 0);
        bad[0] ^= 1;
        assert_eq!(peek_packet_type(&bad), 0);
    }

    #[test]
    fn buffer_consume_zero() {
        let mut b = Pb::new(256);
        b.append(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        b.consume(0);
        assert_eq!(b.len, 10);
    }

    #[test]
    fn buffer_consume_all() {
        let mut b = Pb::new(256);
        b.append(&[0; 10]);
        b.consume(10);
        assert_eq!(b.len, 0);
        b.append(&[0; 10]);
        b.consume(usize::MAX);
        assert_eq!(b.len, 0);
    }

    #[test]
    fn buffer_consume_partial_shift() {
        let mut b = Pb::new(256);
        b.append(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        b.consume(3);
        assert_eq!(b.data(), &[4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn buffer_extract_packet_too_small() {
        let mut b = Pb::new(256);
        b.append(&header(PING, 0));
        let mut out = [0u8; 4];
        assert_eq!(
            extract_packet(&mut b.buf, &mut b.len, &mut out),
            (BufferResult::BufferFull, 12)
        );
        assert_eq!(b.len, 12); // nothing consumed
    }

    #[test]
    fn buffer_extract_packet_passes_peek_errors() {
        let mut b = Pb::new(256);
        b.append(&header(PING, 500_000));
        let mut out = [0u8; 64];
        assert_eq!(
            extract_packet(&mut b.buf, &mut b.len, &mut out),
            (BufferResult::PacketTooLarge, 0)
        );
        assert_eq!(b.len, 12);
    }

    #[test]
    fn buffer_discard_until_valid() {
        let mut b = Pb::new(256);
        b.append(&[0xFF, 0xFF, 0xFF]);
        b.append(&header(PING, 0));
        assert_eq!(discard_until_valid(&mut b.buf, &mut b.len), 3);
        assert!(b.has_complete_packet());
    }

    #[test]
    fn buffer_discard_until_valid_stops_on_incomplete_and_short() {
        // Incomplete packet counts as valid.
        let mut b = Pb::new(256);
        b.append(&[0xAA; 5]);
        b.append(&header(PING, 50));
        assert_eq!(discard_until_valid(&mut b.buf, &mut b.len), 5);
        assert_eq!(b.len, 12);
        // All garbage: stops with 11 bytes left.
        let mut b = Pb::new(256);
        b.append(&[0x11; 40]);
        assert_eq!(discard_until_valid(&mut b.buf, &mut b.len), 29);
        assert_eq!(b.len, 11);
        // A too-large header is discarded too.
        let mut b = Pb::new(256);
        b.append(&header(PING, -1));
        b.append(&header(PING, 0));
        assert_eq!(discard_until_valid(&mut b.buf, &mut b.len), 12);
    }

    #[test]
    fn buffer_discard_until_valid_empty() {
        let mut b = Pb::new(256);
        assert_eq!(discard_until_valid(&mut b.buf, &mut b.len), 0);
    }

    #[test]
    fn buffer_packet_too_large() {
        let mut b = Pb::new(256);
        b.append(&header(PING, 500_000));
        assert_eq!(b.info(), (BufferResult::PacketTooLarge, 0));
    }

    #[test]
    fn buffer_len_above_cap_is_clamped() {
        let mut buf = [0u8; 16];
        let mut len = 1000usize;
        assert_eq!(append(&mut buf, &mut len, &[1]), BufferResult::BufferFull);
        consume(&mut buf, &mut len, 4);
        assert_eq!(len, 12);
        let mut len = 1000usize;
        assert_eq!(discard_until_valid(&mut buf, &mut len), 5);
        assert_eq!(len, 11);
    }
}
