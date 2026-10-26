//! WebSocket client frame codec (port of network/wss_client.cpp: ws::encode_header,
//! ws::apply_mask, WssClient::check_buffered_head, reset_decoder, consume_stream,
//! begin_frame, check_upgrade_response). Control frames are handed back to the
//! caller (`WsStatus::Control`), which answers them (ping -> pong with the same
//! payload, close -> echo the code, then drop the connection).
//!
//! Not here: `compute_accept` (SHA-1 + base64 of the key and the RFC GUID); the
//! shell computes it and passes the result to [`check_upgrade_response`].

use crate::packet_buffer::{BufferResult, append};
use crate::protocol::{DecodeResult, HEADER_SIZE, decode_header};

pub const MAX_HEADER_SIZE: usize = 14;
pub const MAX_CONTROL_PAYLOAD: usize = 125;

pub const OPCODE_CONTINUATION: u8 = 0x0;
pub const OPCODE_BINARY: u8 = 0x2;
pub const OPCODE_CLOSE: u8 = 0x8;
pub const OPCODE_PING: u8 = 0x9;
pub const OPCODE_PONG: u8 = 0xA;

/// Receive-side decoder state, embedded by value in the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsDecoder {
    pub frame_remaining: u64,
    pub frame_header_size: usize,
    pub skip_remaining: usize,
    pub control_size: usize,
    pub frame_header: [u8; MAX_HEADER_SIZE],
    pub control: [u8; MAX_CONTROL_PAYLOAD],
    pub frame_opcode: u8,
    pub frame_active: bool,
    pub in_message: bool,
}

/// Result of [`WsDecoder::consume`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsStatus {
    Ok,
    /// A complete control frame is in `frame_opcode` / `control`.
    Control,
    ProtocolError,
    Overflow,
}

/// Result of [`WsDecoder::check_head`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadStatus {
    Ok,
    Invalid,
    Skipping,
}

impl WsDecoder {
    pub const ZERO: WsDecoder = WsDecoder {
        frame_remaining: 0,
        frame_header_size: 0,
        skip_remaining: 0,
        control_size: 0,
        frame_header: [0; MAX_HEADER_SIZE],
        control: [0; MAX_CONTROL_PAYLOAD],
        frame_opcode: 0,
        frame_active: false,
        in_message: false,
    };

    /// The control payload collected so far.
    pub fn control_payload(&self) -> &[u8] {
        self.control.get(..self.control_size).unwrap_or_default()
    }

    /// reset_decoder (also clears the header/control bytes).
    pub fn reset(&mut self) {
        *self = Self::ZERO;
    }

    /// consume_stream. `pb` is the whole packet buffer storage (cap bytes),
    /// `pb_len` its fill. Returns the status and the input bytes used; on
    /// Control the caller acts on frame_opcode/control, then calls again
    /// with data[consumed..].
    pub fn consume(&mut self, pb: &mut [u8], pb_len: &mut usize, data: &[u8]) -> (WsStatus, usize) {
        let mut pos = 0;
        while let Some(rest) = data.get(pos..).filter(|r| !r.is_empty()) {
            if !self.frame_active {
                // Header: 2 bytes, then a 2- or 8-byte extended length
                let (Some(slot), Some(&byte)) = (
                    self.frame_header.get_mut(self.frame_header_size),
                    rest.first(),
                ) else {
                    return (WsStatus::ProtocolError, pos); // unreachable: at most 10 bytes are collected
                };
                *slot = byte;
                self.frame_header_size = self.frame_header_size.saturating_add(1);
                pos = pos.saturating_add(1);
                if self.frame_header_size < 2 {
                    continue;
                }
                let len7 = self.frame_header.get(1).copied().unwrap_or(0) & 0x7F;
                let header_needed = 2_usize.saturating_add(if len7 == 126 {
                    2
                } else if len7 == 127 {
                    8
                } else {
                    0
                });
                if self.frame_header_size < header_needed {
                    continue;
                }
                if !self.begin_frame() {
                    return (WsStatus::ProtocolError, pos);
                }
            } else {
                let chunk = self.frame_remaining.min(rest.len() as u64) as usize;
                let Some(bytes) = rest.get(..chunk) else {
                    return (WsStatus::ProtocolError, pos);
                };
                if self.frame_opcode >= OPCODE_CLOSE {
                    // begin_frame bounds control frames to 125 bytes
                    let end = self.control_size.saturating_add(chunk);
                    let Some(dst) = self.control.get_mut(self.control_size..end) else {
                        return (WsStatus::ProtocolError, pos);
                    };
                    dst.copy_from_slice(bytes);
                    self.control_size = end;
                } else {
                    let skip = self.skip_remaining.min(chunk);
                    self.skip_remaining = self.skip_remaining.saturating_sub(skip);
                    // Reads are capped to the free space, so this is a bug guard
                    if append(pb, pb_len, bytes.get(skip..).unwrap_or_default())
                        != BufferResult::Success
                    {
                        return (WsStatus::Overflow, pos);
                    }
                }
                pos = pos.saturating_add(chunk);
                self.frame_remaining = self.frame_remaining.saturating_sub(chunk as u64);
            }

            if self.frame_active && self.frame_remaining == 0 {
                self.frame_active = false;
                self.frame_header_size = 0;
                if self.frame_opcode >= OPCODE_CLOSE {
                    return (WsStatus::Control, pos);
                }
            }
        }
        (WsStatus::Ok, pos)
    }

    /// begin_frame: validate the collected header and start its payload.
    fn begin_frame(&mut self) -> bool {
        let h = &self.frame_header;
        let (b0, b1) = (h[0], h[1]);
        let len7 = b1 & 0x7F;

        // No extensions are negotiated, and servers must not mask
        if (b0 & 0x70) != 0 || (b1 & 0x80) != 0 {
            return false;
        }

        let mut length = len7 as u64;
        if len7 == 126 {
            length = u16::from_be_bytes([h[2], h[3]]) as u64;
        } else if len7 == 127 {
            length = u64::from_be_bytes([h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9]]);
        }

        let opcode = b0 & 0x0F;
        let fin = (b0 & 0x80) != 0;

        // in_message / control_size change even when the frame is rejected, as in C++
        let valid = if opcode >= OPCODE_CLOSE {
            self.control_size = 0;
            opcode <= OPCODE_PONG && fin && length <= MAX_CONTROL_PAYLOAD as u64
        } else if opcode == OPCODE_BINARY {
            let valid = !self.in_message;
            self.in_message = !fin;
            valid
        } else if opcode == OPCODE_CONTINUATION {
            let valid = self.in_message;
            self.in_message = !fin;
            valid
        } else {
            false // Text and reserved opcodes break the contract
        };
        if !valid {
            return false;
        }

        self.frame_opcode = opcode;
        self.frame_remaining = length;
        self.frame_active = true;
        true
    }

    /// check_buffered_head. Returns (status, packet_size, packet_type); the
    /// size and type are only meaningful on Skipping.
    pub fn check_head(&mut self, pb: &[u8], pb_len: &mut usize) -> (HeadStatus, usize, u8) {
        if *pb_len < HEADER_SIZE {
            return (HeadStatus::Ok, 0, 0);
        }
        let (result, header) = decode_header(pb.get(..*pb_len).unwrap_or(pb));
        if result != DecodeResult::Success {
            return (HeadStatus::Invalid, 0, 0);
        }
        let packet_size = HEADER_SIZE.saturating_add(header.data_size as usize);
        if packet_size > pb.len() {
            // Head is incomplete, so every buffered byte belongs to it
            self.skip_remaining = packet_size.saturating_sub(*pb_len);
            *pb_len = 0;
            return (HeadStatus::Skipping, packet_size, header.type_);
        }
        (HeadStatus::Ok, 0, 0)
    }
}

/// ws::encode_header for one FIN frame. Returns the header bytes and their count (2..14).
/// Client frames must pass a mask key; the payload then goes through [`apply_mask`].
pub fn encode_header(
    opcode: u8,
    payload_size: usize,
    mask_key: Option<&[u8; 4]>,
) -> ([u8; MAX_HEADER_SIZE], usize) {
    let mut out = [0u8; MAX_HEADER_SIZE];
    let mask_bit = if mask_key.is_some() { 0x80 } else { 0x00 };
    let (len_byte, ext): (u8, &[u8]) = if payload_size < 126 {
        (payload_size as u8, &[])
    } else if payload_size <= 0xFFFF {
        (126, &(payload_size as u16).to_be_bytes())
    } else {
        (127, &(payload_size as u64).to_be_bytes())
    };
    // FIN | opcode, mask bit | length form, extended length, mask key
    let mut at: usize = 0;
    let mut put = |bytes: &[u8]| {
        if let Some(dst) = out.get_mut(at..at.saturating_add(bytes.len())) {
            dst.copy_from_slice(bytes);
        }
        at = at.saturating_add(bytes.len());
    };
    put(&[0x80 | (opcode & 0x0F), mask_bit | len_byte]);
    put(ext);
    if let Some(key) = mask_key {
        put(key);
    }
    let offset = at;
    (out, offset)
}

/// ws::apply_mask: XOR with the 4-byte key.
pub fn apply_mask(data: &mut [u8], mask_key: &[u8; 4]) {
    for (b, k) in data.iter_mut().zip(mask_key.iter().cycle()) {
        *b ^= k;
    }
}

/// Payload of the close frame to echo back for a received close: the 2-byte
/// status code if there is one, else empty.
pub fn close_echo(control: &[u8]) -> &[u8] {
    control.get(..2).unwrap_or_default()
}

/// Status code of a received close frame (1005 = none present).
pub fn close_code(control: &[u8]) -> u16 {
    match control {
        [a, b, ..] => u16::from_be_bytes([*a, *b]),
        _ => 1005,
    }
}

/// Result of [`check_upgrade_response`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeResult {
    Ok,
    Malformed,
    NotSwitching,
    BadUpgrade,
    BadAccept,
}

/// Value of header `name` (case-insensitive) in the header block of `response`,
/// leading blanks skipped, ending at the CR.
fn find_header<'a>(response: &'a [u8], name: &str) -> Option<&'a [u8]> {
    response.split(|&b| b == b'\n').skip(1).find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let (n, v) = line.split_at_checked(name.len())?;
        let v = v.strip_prefix(b":")?;
        n.eq_ignore_ascii_case(name.as_bytes())
            .then(|| v.trim_ascii_start())
    })
}

/// check_upgrade_response: validate the server's HTTP upgrade response (`101`,
/// `Upgrade: websocket`, `Sec-WebSocket-Accept` == `expected_accept`). Returns
/// the result and the status code (0 if the status line is malformed).
pub fn check_upgrade_response(response: &[u8], expected_accept: &[u8]) -> (UpgradeResult, u32) {
    let Some(rest) = response.strip_prefix(b"HTTP/1.1 ") else {
        return (UpgradeResult::Malformed, 0);
    };
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    let status = rest
        .get(..digits)
        .unwrap_or_default()
        .iter()
        .fold(0u32, |a, d| {
            a.saturating_mul(10)
                .saturating_add(u32::from(d.wrapping_sub(b'0')))
        });
    if status != 101 {
        return (UpgradeResult::NotSwitching, status);
    }
    let r = if !find_header(response, "Upgrade").is_some_and(|v| value_is(v, b"websocket", true)) {
        UpgradeResult::BadUpgrade
    } else if !find_header(response, "Sec-WebSocket-Accept")
        .is_some_and(|v| value_is(v, expected_accept, false))
    {
        UpgradeResult::BadAccept
    } else {
        UpgradeResult::Ok
    };
    (r, status)
}

/// `value` starts with `expected` and ends there or at a blank / CR.
fn value_is(value: &[u8], expected: &[u8], ignore_case: bool) -> bool {
    let Some((head, tail)) = value.split_at_checked(expected.len()) else {
        return false;
    };
    let same = if ignore_case {
        head.eq_ignore_ascii_case(expected)
    } else {
        head == expected
    };
    same && matches!(tail.first(), None | Some(b'\r' | b' ' | b'\t'))
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
    use crate::protocol::{check_complete_packet, encode_header as ldn_header};
    use std::{vec, vec::Vec};

    const MASK: [u8; 4] = [0x37, 0xFA, 0x21, 0x3D];

    fn packet(type_: u8, data_size: usize, fill: u8) -> Vec<u8> {
        let mut p = vec![fill; HEADER_SIZE + data_size];
        ldn_header(&mut p, type_, data_size as i32);
        p
    }

    /// Server frame: first header byte b0 (FIN/opcode), unmasked, shortest length form.
    fn frame(b0: u8, payload: &[u8]) -> Vec<u8> {
        let (h, n) = encode_header(b0 & 0x0F, payload.len(), None);
        let mut f = h[..n].to_vec();
        f[0] = b0;
        f.extend_from_slice(payload);
        f
    }

    #[derive(Debug, PartialEq)]
    struct Run {
        status: WsStatus,
        pb: Vec<u8>,
        controls: Vec<(u8, Vec<u8>)>,
    }

    /// Feed `data` in the given chunks, answering every Control like C++ does.
    fn feed(
        d: &mut WsDecoder,
        pb: &mut [u8],
        pb_len: &mut usize,
        chunks: &[&[u8]],
        controls: &mut Vec<(u8, Vec<u8>)>,
    ) -> WsStatus {
        for chunk in chunks {
            let mut rest = *chunk;
            loop {
                let (status, used) = d.consume(pb, pb_len, rest);
                assert!(used <= rest.len());
                rest = &rest[used..];
                match status {
                    WsStatus::Control => {
                        controls.push((d.frame_opcode, d.control_payload().to_vec()))
                    }
                    WsStatus::Ok => {
                        assert!(rest.is_empty());
                        break;
                    }
                    err => return err,
                }
            }
        }
        WsStatus::Ok
    }

    fn run(chunks: &[&[u8]], cap: usize) -> Run {
        let mut d = WsDecoder::ZERO;
        let mut pb = vec![0u8; cap];
        let mut len = 0;
        let mut controls = Vec::new();
        let status = feed(&mut d, &mut pb, &mut len, chunks, &mut controls);
        if status == WsStatus::Ok {
            assert!(
                !d.frame_active && d.frame_header_size == 0,
                "stream ends on a frame boundary"
            );
        }
        Run {
            status,
            pb: pb[..len].to_vec(),
            controls,
        }
    }

    /// Whole, byte at a time, and every two-way split give the same result.
    fn check_splits(stream: &[u8], cap: usize, pb: &[u8], controls: &[(u8, &[u8])]) {
        let expected = Run {
            status: WsStatus::Ok,
            pb: pb.to_vec(),
            controls: controls.iter().map(|(o, p)| (*o, p.to_vec())).collect(),
        };
        assert_eq!(run(&[stream], cap), expected);
        let bytes: Vec<&[u8]> = stream.chunks(1).collect();
        assert_eq!(run(&bytes, cap), expected);
        for split in 0..=stream.len() {
            let (a, b) = stream.split_at(split);
            assert_eq!(run(&[a, b], cap), expected, "split at {split}");
        }
    }

    fn rejected(stream: &[u8]) {
        assert_eq!(
            run(&[stream], 0x2000).status,
            WsStatus::ProtocolError,
            "{stream:02X?}"
        );
    }

    #[test]
    fn encode_header_lengths() {
        let (h, n) = encode_header(OPCODE_BINARY, 125, None);
        assert_eq!((n, h[0], h[1]), (2, 0x82, 125));
        let (h, n) = encode_header(OPCODE_BINARY, 126, None);
        assert_eq!((n, h[1], h[2], h[3]), (4, 126, 0x00, 126));
        let (h, n) = encode_header(OPCODE_BINARY, 0x10000, None);
        assert_eq!((n, h[1], h[7], h[8], h[9]), (10, 127, 0x01, 0x00, 0x00));
    }

    #[test]
    fn encode_header_masked() {
        let (h, n) = encode_header(OPCODE_BINARY, 300, Some(&MASK));
        assert_eq!(n, 8);
        assert_eq!(h[..4], [0x82, 0x80 | 126, 0x01, 0x2C]);
        assert_eq!(h[4..8], MASK);
    }

    #[test]
    fn mask_rfc_vector() {
        let mut data = *b"Hello";
        apply_mask(&mut data, &MASK);
        assert_eq!(data, [0x7F, 0x9F, 0x4D, 0x51, 0x58]);
        apply_mask(&mut data, &MASK);
        assert_eq!(&data, b"Hello");
    }

    #[test]
    fn single_binary_frame() {
        let p = packet(3, 20, 0xAB);
        check_splits(&frame(0x82, &p), 0x2000, &p, &[]);
    }

    #[test]
    fn fragmented_with_interleaved_ping() {
        let p = packet(3, 20, 0xCD);
        let mut s = frame(0x02, &p[..5]);
        s.extend(frame(0x89, b"abc"));
        s.extend(frame(0x00, &p[5..15]));
        s.extend(frame(0x80, &p[15..]));
        check_splits(&s, 0x2000, &p, &[(OPCODE_PING, b"abc")]);
        let mut d = WsDecoder::ZERO;
        let mut pb = [0u8; 64];
        let mut len = 0;
        feed(&mut d, &mut pb, &mut len, &[&s], &mut Vec::new());
        assert!(!d.in_message);
    }

    #[test]
    fn extended_lengths() {
        // 16-bit form, shortest encoding
        let p = packet(1, 300, 0x11);
        let s = frame(0x82, &p);
        assert_eq!(s[1], 126);
        check_splits(&s, 0x2000, &p, &[]);

        // 64-bit form (non-minimal, which C++ accepts too)
        let p = packet(1, 20, 0x22);
        let mut s = vec![0x82, 127, 0, 0, 0, 0, 0, 0, 0, p.len() as u8];
        s.extend_from_slice(&p);
        check_splits(&s, 0x2000, &p, &[]);

        // Real 64-bit frame
        let p = packet(1, 70_000, 0x33);
        let s = frame(0x82, &p);
        assert_eq!(s[1], 127);
        let r = run(&[&s], 0x20000);
        assert_eq!((r.status, r.pb == p), (WsStatus::Ok, true));
        let bytes: Vec<&[u8]> = s.chunks(1).collect();
        assert!(run(&bytes, 0x20000).pb == p);
    }

    #[test]
    fn zero_length_frames() {
        let p = packet(2, 4, 0x44);
        let mut s = frame(0x82, &[]);
        s.extend(frame(0x89, &[]));
        s.extend(frame(0x82, &p));
        check_splits(&s, 0x2000, &p, &[(OPCODE_PING, b"")]);

        // The zero-length ping completes on its second header byte
        let mut d = WsDecoder::ZERO;
        let mut len = 0;
        assert_eq!(
            d.consume(&mut [], &mut len, &[0x89, 0x00, 0x82]),
            (WsStatus::Control, 2)
        );
        assert_eq!(
            (d.frame_opcode, d.control_size, d.frame_active),
            (OPCODE_PING, 0, false)
        );
    }

    #[test]
    fn rejections() {
        rejected(&[0x81, 0x00]); // text (e2e_text_frame_rejected)
        rejected(&[0xC2, 0x00]); // RSV1
        rejected(&[0x92, 0x00]); // RSV3
        rejected(&[0x82, 0x81, 1, 2, 3, 4, 0]); // masked server frame
        rejected(&[0x80, 0x00]); // continuation with no message open
        rejected(&[0x02, 0x00, 0x82, 0x00]); // binary while a message is open
        rejected(&[0x09, 0x00]); // control without FIN
        rejected(&[0x89, 0x7E, 0x00, 0x7E]); // control longer than 125
        rejected(&[0x8B, 0x00]); // reserved control opcode
        rejected(&[0x83, 0x00]); // reserved data opcode

        // State after a rejected frame matches C++ (in_message still updated)
        let mut d = WsDecoder::ZERO;
        let mut len = 0;
        assert_eq!(
            d.consume(&mut [], &mut len, &[0x02, 0x00, 0x02, 0x00, 0xFF]),
            (WsStatus::ProtocolError, 4)
        );
        assert!(d.in_message && !d.frame_active);
        assert_eq!(d.frame_header_size, 2);
    }

    /// Packets drained, (size, type) of skipped heads, and the error that stopped it.
    type Relayed = (Vec<Vec<u8>>, Vec<(usize, u8)>, Option<i32>);

    /// Drive like receive_into_buffer / fuzz_relay: head check, read capped to
    /// min(free, 2048), consume, drain whole packets.
    fn relay(stream: &[u8], cap: usize, rng: Option<&mut u64>) -> Relayed {
        let mut d = WsDecoder::ZERO;
        let mut pb = vec![0u8; cap];
        let mut len = 0;
        let (mut packets, mut skips) = (Vec::new(), Vec::new());
        let mut rng = rng;
        let mut rest = stream;
        while !rest.is_empty() {
            match d.check_head(&pb, &mut len) {
                (HeadStatus::Invalid, ..) => return (packets, skips, Some(-1)),
                (HeadStatus::Skipping, size, type_) => skips.push((size, type_)),
                (HeadStatus::Ok, ..) => {}
            }
            let read = (cap - len).min(2048);
            assert!(read > 0);
            let read = match rng.as_deref_mut() {
                Some(s) => 1 + (xorshift(s) as usize % read),
                None => read,
            }
            .min(rest.len());
            let mut chunk = &rest[..read];
            rest = &rest[read..];
            loop {
                let (status, used) = d.consume(&mut pb, &mut len, chunk);
                chunk = &chunk[used..];
                assert!(
                    d.frame_header_size <= MAX_HEADER_SIZE && d.control_size <= MAX_CONTROL_PAYLOAD
                );
                match status {
                    WsStatus::Ok => break,
                    WsStatus::Control if d.frame_opcode == OPCODE_CLOSE => {
                        return (packets, skips, Some(OPCODE_CLOSE as i32));
                    }
                    WsStatus::Control => {}
                    err => return (packets, skips, Some(err as i32)),
                }
            }
            while let (DecodeResult::Success, size) = check_complete_packet(&pb[..len]) {
                packets.push(pb[..size].to_vec());
                pb.copy_within(size..len, 0);
                len -= size;
            }
        }
        // The next receive starts with a head check
        if d.check_head(&pb, &mut len).0 == HeadStatus::Invalid {
            return (packets, skips, Some(-1));
        }
        (packets, skips, None)
    }

    #[test]
    fn e2e_oversized_packets_consumed() {
        let small = packet(17, 100, 1);
        let big = packet(17, 10_000, 2);
        let ping = packet(254, 8, 7);
        let mut s = frame(0x82, &small);
        s.extend(frame(0x82, &big));
        s.extend(frame(0x82, &ping));
        let (packets, skips, err) = relay(&s, 0x2000, None);
        assert_eq!(err, None);
        assert_eq!(packets, vec![small, ping]);
        assert_eq!(skips, vec![(HEADER_SIZE + 10_000, 17)]);
    }

    #[test]
    fn check_head_cases() {
        let mut d = WsDecoder::ZERO;
        let big = packet(5, 10_000, 0);
        let mut pb = [0u8; 0x2000];
        pb[..100].copy_from_slice(&big[..100]);
        let mut len = 11;
        assert_eq!(d.check_head(&pb, &mut len).0, HeadStatus::Ok);
        len = 100;
        assert_eq!(
            d.check_head(&pb, &mut len),
            (HeadStatus::Skipping, 10_012, 5)
        );
        assert_eq!((len, d.skip_remaining), (0, 10_012 - 100));
        // A packet that fits is left alone
        pb[..12].copy_from_slice(&packet(5, 0x2000 - 12, 0)[..12]);
        len = 12;
        assert_eq!(d.check_head(&pb, &mut len).0, HeadStatus::Ok);
        assert_eq!(len, 12);
    }

    #[test]
    fn e2e_bad_header_is_connection_lost() {
        let mut garbage = [0u8; HEADER_SIZE + 4];
        garbage[..4].copy_from_slice(b"GET ");
        let (packets, _, err) = relay(&frame(0x82, &garbage), 0x2000, None);
        assert!(packets.is_empty());
        assert_eq!(err, Some(-1));
    }

    #[test]
    fn overflow() {
        assert_eq!(
            run(&[&frame(0x82, &[0; 20])], 16).status,
            WsStatus::Overflow
        );
        // Partly full buffer: the chunk that does not fit is not consumed
        let mut d = WsDecoder::ZERO;
        let mut pb = [0u8; 16];
        let mut len = 10;
        let s = frame(0x82, &[9; 7]);
        assert_eq!(d.consume(&mut pb, &mut len, &s), (WsStatus::Overflow, 2));
        assert_eq!(len, 10);
        // Bytes being skipped do not count against the free space
        let mut d = WsDecoder::ZERO;
        d.skip_remaining = 5;
        let mut len = 10;
        assert_eq!(d.consume(&mut pb, &mut len, &s), (WsStatus::Ok, s.len()));
        assert_eq!((len, d.skip_remaining), (12, 0));
    }
    #[test]
    fn upgrade_response() {
        let ok = b"HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept:  abc=\r\n\r\n";
        assert_eq!(
            check_upgrade_response(ok, b"abc="),
            (UpgradeResult::Ok, 101)
        );
        assert_eq!(
            check_upgrade_response(ok, b"abd=").0,
            UpgradeResult::BadAccept
        );
        assert_eq!(
            check_upgrade_response(b"HTTP/1.1 200 OK\r\n\r\n", b"x"),
            (UpgradeResult::NotSwitching, 200)
        );
        assert_eq!(
            check_upgrade_response(b"garbage", b"x"),
            (UpgradeResult::Malformed, 0)
        );
        let no_upgrade = b"HTTP/1.1 101 X\r\nSec-WebSocket-Accept: abc=\r\n\r\n";
        assert_eq!(
            check_upgrade_response(no_upgrade, b"abc=").0,
            UpgradeResult::BadUpgrade
        );
        // The accept value must not merely start with the expected one.
        let longer =
            b"HTTP/1.1 101 X\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: abc=zz\r\n\r\n";
        assert_eq!(
            check_upgrade_response(longer, b"abc=").0,
            UpgradeResult::BadAccept
        );
    }

    #[test]
    fn close_helpers() {
        assert_eq!(close_code(&[0x03, 0xE8, b'x']), 1000);
        assert_eq!(close_code(&[]), 1005);
        assert_eq!(close_echo(&[0x03, 0xE8, b'x']), &[0x03, 0xE8]);
        assert_eq!(close_echo(&[1]), &[] as &[u8]);
    }

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    /// Random streams, mostly frame-shaped, in random read sizes: no panic,
    /// invariants hold (checked inside relay()).
    #[test]
    fn random_streams() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let (mut packets, mut skips, mut clean) = (0, 0, 0);
        for _ in 0..3000 {
            let mut stream = Vec::new();
            let target = (xorshift(&mut s) % 6000) as usize;
            while stream.len() < target {
                let r = xorshift(&mut s);
                match r % 64 {
                    0 => stream.push(r as u8), // corruption
                    1..=8 => {
                        // Any opcode the decoder accepts, random payload
                        let b0 = [0x82, 0x02, 0x00, 0x80, 0x89, 0x8A, 0x88][(r >> 8) as usize % 7];
                        let n = (r >> 16) as usize % if b0 >= 0x88 { 126 } else { 300 };
                        stream.extend(frame(b0, &vec![(r >> 24) as u8; n]));
                    }
                    9..=12 => {
                        // Oversized packet
                        let n = 0x2000 + (r >> 8) as usize % 0x4000;
                        stream.extend(frame(0x82, &packet(1, n, 0)));
                    }
                    _ => {
                        // One packet, split into 1-3 fragments, maybe a ping between them
                        let p = packet((r >> 8) as u8, (r >> 16) as usize % 1500, (r >> 40) as u8);
                        let a = (r >> 28) as usize % (p.len() + 1);
                        let b = a + (r >> 44) as usize % (p.len() - a + 1);
                        let parts: Vec<&[u8]> = match (r >> 52) % 3 {
                            0 => vec![&p],
                            1 => vec![&p[..b], &p[b..]],
                            _ => vec![&p[..a], &p[a..b], &p[b..]],
                        };
                        let n = parts.len();
                        for (i, part) in parts.into_iter().enumerate() {
                            let fin = if i + 1 == n { 0x80 } else { 0 };
                            stream.extend(frame(
                                fin | if i == 0 {
                                    OPCODE_BINARY
                                } else {
                                    OPCODE_CONTINUATION
                                },
                                part,
                            ));
                            if r & (1 << (60 + i)) != 0 {
                                stream.extend(frame(0x89, b"p"));
                            }
                        }
                    }
                }
            }
            for _ in 0..1 + xorshift(&mut s) % 2 {
                let (p, k, err) = relay(&stream, 0x2000, Some(&mut s));
                packets += p.len();
                skips += k.len();
                clean += err.is_none() as usize;
            }
            // Raw noise too
            let noise: Vec<u8> = (0..target / 4).map(|_| xorshift(&mut s) as u8).collect();
            let _ = relay(&noise, 0x2000, Some(&mut s));
        }
        assert!(
            packets > 1000 && skips > 100 && clean > 1000,
            "{packets} {skips} {clean}"
        );
    }
}
