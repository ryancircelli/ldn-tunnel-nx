//! LdnHeader encode/decode (port of protocol/ryu_protocol.hpp).

use zerocopy::{FromBytes, FromZeros, IntoBytes};

/// "RLDN" read as a little-endian u32.
pub const PROTOCOL_MAGIC: u32 = 0x4E44_4C52;
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_PACKET_SIZE: usize = 131_072;
pub const HEADER_SIZE: usize = 12;

pub use crate::wire::LdnHeader;

/// Mirrors ryu_ldn::protocol::DecodeResult.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeResult {
    Success = 0,
    BufferTooSmall = 1,
    InvalidMagic = 2,
    InvalidVersion = 3,
    PacketTooLarge = 4,
    IncompletePacket = 5,
}

impl LdnHeader {
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        let _ = self.write_to(&mut out); // exact size, cannot fail
        out
    }

    /// Raw read of the first 12 bytes, no validation. `None` if `buf` is shorter.
    pub fn from_bytes(buf: &[u8]) -> Option<LdnHeader> {
        LdnHeader::read_from_prefix(buf).ok().map(|(h, _)| h)
    }
}

/// Write a header for `type_` with `data_size` payload bytes into the front of
/// `out`; returns 12, or 0 (nothing written) if `out` is shorter than 12.
pub fn encode_header(out: &mut [u8], type_: u8, data_size: i32) -> usize {
    let header = LdnHeader {
        magic: PROTOCOL_MAGIC,
        type_,
        version: PROTOCOL_VERSION,
        reserved: 0,
        data_size,
    };
    match out.get_mut(..HEADER_SIZE) {
        Some(dst) => {
            dst.copy_from_slice(&header.to_bytes());
            HEADER_SIZE
        }
        None => 0,
    }
}

/// Decode and validate the header at the front of `buf`.
/// On an error other than BufferTooSmall the header is still filled (as C++ does).
pub fn decode_header(buf: &[u8]) -> (DecodeResult, LdnHeader) {
    let Some(header) = LdnHeader::from_bytes(buf) else {
        return (DecodeResult::BufferTooSmall, LdnHeader::new_zeroed());
    };
    let data_size = header.data_size;
    let result = if header.magic != PROTOCOL_MAGIC {
        DecodeResult::InvalidMagic
    } else if header.version != PROTOCOL_VERSION {
        DecodeResult::InvalidVersion
    } else if data_size < 0 || data_size as usize > MAX_PACKET_SIZE {
        DecodeResult::PacketTooLarge
    } else {
        DecodeResult::Success
    };
    (result, header)
}

/// Is a whole packet (header + data_size) in `buf`? Returns the packet size
/// when the header is valid (Success or IncompletePacket), else 0.
pub fn check_complete_packet(buf: &[u8]) -> (DecodeResult, usize) {
    let (result, header) = decode_header(buf);
    if result != DecodeResult::Success {
        return (result, 0);
    }
    let packet_size = HEADER_SIZE.saturating_add(header.data_size as usize);
    if buf.len() < packet_size {
        (DecodeResult::IncompletePacket, packet_size)
    } else {
        (DecodeResult::Success, packet_size)
    }
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
    use core::mem::size_of;

    #[test]
    fn roundtrip() {
        let mut buf = [0u8; 20];
        assert_eq!(encode_header(&mut buf, 7, 8), 12);
        assert_eq!(&buf[0..4], b"RLDN");
        let (r, h) = decode_header(&buf);
        assert_eq!(r, DecodeResult::Success);
        assert_eq!(h.type_, 7);
        assert_eq!({ h.data_size }, 8);
        assert_eq!(check_complete_packet(&buf), (DecodeResult::Success, 20));
        assert_eq!(
            check_complete_packet(&buf[..15]),
            (DecodeResult::IncompletePacket, 20)
        );
    }

    const PING: u8 = 254;

    fn header(magic: u32, type_: u8, version: u8, data_size: i32) -> [u8; HEADER_SIZE] {
        LdnHeader {
            magic,
            type_,
            version,
            reserved: 0,
            data_size,
        }
        .to_bytes()
    }

    #[test]
    fn structure_sizes() {
        assert_eq!(size_of::<LdnHeader>(), 0xC);
        // data_size sits at offset 8 (C# StructLayout).
        let b = header(PROTOCOL_MAGIC, 0, 1, 0x0403_0201);
        assert_eq!(&b[8..12], &[1, 2, 3, 4]);
    }

    #[test]
    fn protocol_constants() {
        assert_eq!(PROTOCOL_MAGIC, 0x4E44_4C52);
        assert_eq!(PROTOCOL_MAGIC.to_le_bytes(), *b"RLDN");
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(MAX_PACKET_SIZE, 131_072);
    }

    #[test]
    fn decode_valid_header() {
        let (r, h) = decode_header(&header(PROTOCOL_MAGIC, PING, PROTOCOL_VERSION, 8));
        assert_eq!(r, DecodeResult::Success);
        assert_eq!({ h.magic }, PROTOCOL_MAGIC);
        assert_eq!(h.type_, PING);
        assert_eq!({ h.data_size }, 8);
    }

    #[test]
    fn decode_invalid_magic() {
        let (r, h) = decode_header(&header(0xDEAD_BEEF, 1, PROTOCOL_VERSION, 0));
        assert_eq!(r, DecodeResult::InvalidMagic);
        assert_eq!({ h.magic }, 0xDEAD_BEEF); // header still filled, as in C++
    }

    #[test]
    fn decode_invalid_version() {
        let (r, h) = decode_header(&header(PROTOCOL_MAGIC, 1, 99, 0));
        assert_eq!(r, DecodeResult::InvalidVersion);
        assert_eq!(h.version, 99);
    }

    #[test]
    fn decode_packet_too_large() {
        let buf = header(PROTOCOL_MAGIC, 0, PROTOCOL_VERSION, 131_073);
        assert_eq!(decode_header(&buf).0, DecodeResult::PacketTooLarge);
        // Exactly MAX_PACKET_SIZE is allowed.
        let buf = header(PROTOCOL_MAGIC, 0, PROTOCOL_VERSION, MAX_PACKET_SIZE as i32);
        assert_eq!(decode_header(&buf).0, DecodeResult::Success);
    }

    #[test]
    fn decode_header_negative_data_size() {
        for ds in [-1, -12, i32::MIN] {
            let buf = header(PROTOCOL_MAGIC, 1, PROTOCOL_VERSION, ds);
            assert_eq!(decode_header(&buf).0, DecodeResult::PacketTooLarge);
            assert_eq!(
                check_complete_packet(&buf),
                (DecodeResult::PacketTooLarge, 0)
            );
        }
    }

    #[test]
    fn decode_buffer_too_small() {
        assert_eq!(decode_header(&[0; 4]).0, DecodeResult::BufferTooSmall);
        assert_eq!(
            decode_header(&header(PROTOCOL_MAGIC, 0, 1, 0)[..11]).0,
            DecodeResult::BufferTooSmall
        );
    }

    #[test]
    fn check_complete_packet_success() {
        let mut buf = header(PROTOCOL_MAGIC, PING, PROTOCOL_VERSION, 8).to_vec();
        buf.resize(20, 0);
        assert_eq!(check_complete_packet(&buf), (DecodeResult::Success, 20));
        // Extra trailing bytes are fine.
        buf.resize(30, 0);
        assert_eq!(check_complete_packet(&buf), (DecodeResult::Success, 20));
    }

    #[test]
    fn check_complete_packet_incomplete() {
        let mut buf = header(PROTOCOL_MAGIC, PING, PROTOCOL_VERSION, 8).to_vec();
        buf.resize(16, 0);
        assert_eq!(
            check_complete_packet(&buf),
            (DecodeResult::IncompletePacket, 20)
        );
    }

    #[test]
    fn check_complete_packet_buffer_too_small() {
        assert_eq!(
            check_complete_packet(&[0; 4]),
            (DecodeResult::BufferTooSmall, 0)
        );
    }

    #[test]
    fn encode_header_function() {
        let mut out = [0xFFu8; 12];
        assert_eq!(encode_header(&mut out, PING, 2), 12);
        assert_eq!(out, header(PROTOCOL_MAGIC, PING, PROTOCOL_VERSION, 2));
        assert_eq!(encode_header(&mut out[..11], PING, 2), 0);
    }
}
