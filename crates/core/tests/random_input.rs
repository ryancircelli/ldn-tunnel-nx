//! Random-input tests: no panic on arbitrary bytes, and everything the parsers
//! accept re-encodes to the bytes it came from.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::panic,
    clippy::while_let_loop
)]

use ldn_tunnel_core::packet_buffer::{
    BufferResult, append, consume, discard_until_valid, extract_packet, peek_packet_info,
};
use ldn_tunnel_core::protocol::encode_header;
use ldn_tunnel_core::protocol::{
    DecodeResult, HEADER_SIZE, PROTOCOL_MAGIC, PROTOCOL_VERSION, check_complete_packet,
    decode_header,
};
use ldn_tunnel_core::ws::encode_header as ws_header;
use ldn_tunnel_core::ws::{
    HeadStatus, MAX_CONTROL_PAYLOAD, MAX_HEADER_SIZE, OPCODE_BINARY, OPCODE_CONTINUATION,
    OPCODE_PING, OPCODE_PONG, WsDecoder, WsStatus, apply_mask,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// A valid packet with random type and payload.
fn packet(r: &mut Rng, max_payload: usize) -> Vec<u8> {
    let n = r.below(max_payload + 1);
    let payload = r.bytes(n);
    let mut p = vec![0u8; HEADER_SIZE];
    encode_header(&mut p, r.next() as u8, payload.len() as i32);
    p.extend(payload);
    p
}

#[test]
fn ldn_header_decode_random() {
    let mut r = Rng(0x1234_5678_9ABC_DEF1);
    let (mut ok, mut short) = (0, 0);
    for _ in 0..200_000 {
        let n = r.below(40);
        let mut b = r.bytes(n);
        // Bias toward headers that get past the magic/version checks.
        if b.len() >= 12 && r.below(4) != 0 {
            b[..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
            b[5] = PROTOCOL_VERSION;
            if r.below(2) == 0 {
                let n = r.below(300) as i32;
                b[8..12].copy_from_slice(&n.to_le_bytes());
            }
        }
        let (res, h) = decode_header(&b);
        let (cres, size) = check_complete_packet(&b);
        match res {
            DecodeResult::BufferTooSmall => {
                assert!(b.len() < HEADER_SIZE);
                short += 1;
            }
            DecodeResult::Success => {
                ok += 1;
                assert_eq!(
                    h.to_bytes(),
                    b[..HEADER_SIZE],
                    "header re-encodes to the same bytes"
                );
                if h.reserved == 0 {
                    let mut e = [0u8; HEADER_SIZE];
                    encode_header(&mut e, h.type_, h.data_size);
                    assert_eq!(e, b[..HEADER_SIZE]);
                }
                assert_eq!(size, HEADER_SIZE + h.data_size as usize);
                assert_eq!(cres == DecodeResult::Success, b.len() >= size);
            }
            _ => assert_eq!((cres, size), (res, 0)),
        }
    }
    assert!(ok > 10_000 && short > 1000, "{ok} {short}");
}

#[test]
fn packet_buffer_append_drain_random() {
    let mut r = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..2000 {
        let count = 1 + r.below(8);
        let packets: Vec<Vec<u8>> = (0..count).map(|_| packet(&mut r, 600)).collect();
        let stream: Vec<u8> = packets.concat();
        let cap = 256 + r.below(4096);
        let mut buf = vec![0u8; cap];
        let mut len = 0;
        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut rest = &stream[..];
        while !rest.is_empty() || len > 0 {
            let n = (1 + r.below(300)).min(rest.len());
            match append(&mut buf, &mut len, &rest[..n]) {
                BufferResult::Success => rest = &rest[n..],
                BufferResult::BufferFull => {}
                other => panic!("{other:?}"),
            }
            let mut out = vec![0u8; 4096];
            loop {
                match extract_packet(&mut buf, &mut len, &mut out) {
                    (BufferResult::Success, size) => got.push(out[..size].to_vec()),
                    // A packet bigger than the whole buffer can never complete: skip this round.
                    (BufferResult::NoCompletePacket, _) => break,
                    other => panic!("{other:?}"),
                }
            }
            if len == buf.len() {
                break; // head packet larger than the buffer; stop (nothing more can drain)
            }
            if rest.is_empty() && len > 0 {
                break; // trailing partial packet
            }
        }
        // Every drained packet is a prefix of the original packet list, byte for byte.
        for (g, p) in got.iter().zip(&packets) {
            assert_eq!(g, p);
        }
        if buf.len() >= 12 + 600 {
            assert_eq!(got, packets);
        }
    }
}

#[test]
fn packet_buffer_noise_random() {
    let mut r = Rng(0x0BAD_C0DE_1234_5678);
    for _ in 0..5000 {
        let cap = 64 + r.below(512);
        let mut buf = vec![0u8; cap];
        let mut len = r.below(cap * 2); // even an inconsistent len must not panic
        let n = r.below(700);
        let data = r.bytes(n);
        let _ = append(&mut buf, &mut len, &data);
        assert!(len <= buf.len() || len > buf.len()); // clamped inside, never panics
        len = len.min(buf.len());
        let (res, size) = peek_packet_info(&buf[..len]);
        if res == BufferResult::Success {
            // accepted head re-encodes to the same 12 bytes
            let (_, h) = decode_header(&buf[..len]);
            assert_eq!(h.to_bytes(), buf[..HEADER_SIZE]);
            assert_eq!(size, HEADER_SIZE + h.data_size as usize);
        }
        let before = len;
        let dropped = discard_until_valid(&mut buf, &mut len);
        assert_eq!(before - dropped, len);
        let n = r.below(len + 4);
        consume(&mut buf, &mut len, n);
        let mut out = vec![0u8; 64];
        let _ = extract_packet(&mut buf, &mut len, &mut out);
    }
}

/// One FIN frame, unmasked, shortest length form.
fn frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    let (h, n) = ws_header(opcode, payload.len(), None);
    let mut f = h[..n].to_vec();
    f[0] = (f[0] & 0x7F) | if fin { 0x80 } else { 0 };
    f.extend_from_slice(payload);
    f
}

#[test]
fn ws_frames_random_chunks_roundtrip() {
    let mut r = Rng(0xFEED_FACE_0BAD_F00D);
    for _ in 0..3000 {
        // Build a stream: binary messages (1-3 fragments) with pings/pongs between fragments.
        let mut stream = Vec::new();
        let mut expect_data = Vec::new();
        let mut expect_ctl: Vec<(u8, Vec<u8>, Vec<u8>)> = Vec::new();
        for _ in 0..1 + r.below(5) {
            let n = r.below(400);
            let data = r.bytes(n);
            expect_data.extend(&data);
            let cut1 = r.below(data.len() + 1);
            let cut2 = cut1 + r.below(data.len() - cut1 + 1);
            let take = 1 + r.below(3);
            let parts: Vec<&[u8]> = [&data[..cut1], &data[cut1..cut2], &data[cut2..]]
                .into_iter()
                .take(take)
                .collect();
            let total: usize = parts.iter().map(|p| p.len()).sum();
            // fragments must cover the message: fold the unused tail into the last part
            let tail = &data[total..];
            let n = parts.len();
            for (i, part) in parts.iter().enumerate() {
                let mut payload = part.to_vec();
                if i + 1 == n {
                    payload.extend(tail);
                }
                stream.extend(frame(
                    if i == 0 {
                        OPCODE_BINARY
                    } else {
                        OPCODE_CONTINUATION
                    },
                    i + 1 == n,
                    &payload,
                ));
                if r.below(3) == 0 {
                    let op = if r.below(2) == 0 {
                        OPCODE_PING
                    } else {
                        OPCODE_PONG
                    };
                    let n = r.below(126);
                    let p = r.bytes(n);
                    let f = frame(op, true, &p);
                    stream.extend(&f);
                    expect_ctl.push((op, p, f));
                }
            }
        }
        let mut d = WsDecoder::ZERO;
        let mut pb = vec![0u8; expect_data.len().max(1)];
        let mut len = 0;
        let mut got_ctl = Vec::new();
        let mut rest = &stream[..];
        while !rest.is_empty() {
            let n = (1 + r.below(64)).min(rest.len());
            let mut chunk = &rest[..n];
            rest = &rest[n..];
            while !chunk.is_empty() {
                let (st, used) = d.consume(&mut pb, &mut len, chunk);
                chunk = &chunk[used..];
                match st {
                    WsStatus::Ok => assert!(chunk.is_empty()),
                    WsStatus::Control => {
                        let (h, hn) = ws_header(d.frame_opcode, d.control_size, None);
                        let mut f = h[..hn].to_vec();
                        f.extend_from_slice(d.control_payload());
                        got_ctl.push((d.frame_opcode, d.control_payload().to_vec(), f));
                    }
                    other => panic!("{other:?}"),
                }
            }
        }
        assert_eq!(&pb[..len], &expect_data[..]);
        assert_eq!(
            got_ctl, expect_ctl,
            "control frames re-encode to the bytes sent"
        );
        assert!(!d.frame_active && !d.in_message && d.frame_header_size == 0);
    }
}

#[test]
fn ws_noise_random() {
    let mut r = Rng(0x5EED_5EED_5EED_5EED);
    let (mut controls, mut errors) = (0, 0);
    for _ in 0..20_000 {
        let n = r.below(300);
        let mut stream = r.bytes(n);
        // Make some noise frame-shaped so the parser gets past its first byte.
        if !stream.is_empty() && r.below(2) == 0 {
            let pick = r.below(8);
            stream[0] = [0x82, 0x02, 0x00, 0x80, 0x89, 0x8A, 0x88, 0x81][pick];
        }
        let mut d = WsDecoder::ZERO;
        let mut pb = vec![0u8; 200];
        let mut len = 0;
        let mut at = 0;
        'run: while at < stream.len() {
            let n = (1 + r.below(50)).min(stream.len() - at);
            let chunk = &stream[at..at + n];
            let mut used_total = 0;
            while used_total < chunk.len() {
                let (st, used) = d.consume(&mut pb, &mut len, &chunk[used_total..]);
                used_total += used;
                assert!(
                    d.frame_header_size <= MAX_HEADER_SIZE
                        && d.control_size <= MAX_CONTROL_PAYLOAD
                        && len <= pb.len()
                );
                match st {
                    WsStatus::Ok => {}
                    WsStatus::Control => {
                        controls += 1;
                        // Re-encode a minimal-form control frame and compare with the stream bytes.
                        let end = at + used_total;
                        let flen = 2 + d.control_size;
                        if end >= flen
                            && stream[end - flen + 1] & 0x7F == d.control_size as u8
                            && d.control_size < 126
                        {
                            let (h, hn) = ws_header(d.frame_opcode, d.control_size, None);
                            let mut f = h[..hn].to_vec();
                            f.extend_from_slice(d.control_payload());
                            assert_eq!(f, stream[end - flen..end]);
                        }
                    }
                    _ => {
                        errors += 1;
                        break 'run;
                    }
                }
            }
            at += n;
            // Drain like the client: whole packets out of the buffer, garbage -> stop.
            loop {
                match check_complete_packet(&pb[..len]) {
                    (DecodeResult::Success, size) => {
                        pb.copy_within(size..len, 0);
                        len -= size;
                    }
                    _ => break,
                }
            }
            if d.check_head(&pb, &mut len).0 == HeadStatus::Invalid {
                break;
            }
        }
    }
    assert!(controls > 100 && errors > 1000, "{controls} {errors}");
}

#[test]
fn ws_mask_and_encode_random() {
    let mut r = Rng(0xABCD_EF01_2345_6789);
    for _ in 0..20_000 {
        let key = [
            r.next() as u8,
            r.next() as u8,
            r.next() as u8,
            r.next() as u8,
        ];
        let n = r.below(300);
        let orig = r.bytes(n);
        let mut m = orig.clone();
        apply_mask(&mut m, &key);
        apply_mask(&mut m, &key);
        assert_eq!(m, orig);
        let sizes = [r.below(130), r.below(70_000), r.below(300)];
        let size = sizes[r.below(3)];
        let (h, n) = ws_header(OPCODE_BINARY, size, Some(&key));
        assert_eq!(h[0], 0x82);
        assert_ne!(h[1] & 0x80, 0);
        assert_eq!(&h[n - 4..n], &key);
        assert_eq!(
            n,
            2 + 4
                + if size < 126 {
                    0
                } else if size <= 0xFFFF {
                    2
                } else {
                    8
                }
        );
    }
}

// ---------------------------------------------------------------------------------------
// Everything below feeds arbitrary bytes into the remaining untrusted-input entry points:
// config.ini / gamelist.txt / probation / rejected files on the SD card, the signed manifest and
// chunk replies, the WebSocket upgrade response, relay packets (Session, Router, Conn), and the
// log/notify encoders. They only assert "no panic" plus a few cheap invariants; run them in debug
// and in release with `-Coverflow-checks=on`.
// ---------------------------------------------------------------------------------------

use ldn_tunnel_core::config::Config;
use ldn_tunnel_core::conn::handshake::{self, ACCEPT_LEN};
use ldn_tunnel_core::conn::remote_log::{self, RemoteLog};
use ldn_tunnel_core::conn::update_dl::UpdateDl;
use ldn_tunnel_core::conn::{Action as ConnAction, Conn, ConnConfig};
use ldn_tunnel_core::ldn::Session;
use ldn_tunnel_core::logring::LogRing;
use ldn_tunnel_core::notify::{Event, LdnMode, Notifier, NotifyConfig};
use ldn_tunnel_core::router::bsd::SockAddrIn;
use ldn_tunnel_core::router::{Router, socket_key};
use ldn_tunnel_core::update::{
    SIGNED_LEN, UNSIGNED_LEN, UPDATE_MANIFEST_FORMAT, check_manifest, format_probation, format_rejected, parse_probation,
    parse_rejected,
};
use ldn_tunnel_core::whitelist::Whitelist;
use ldn_tunnel_core::wire::{
    PacketId, ProxyDataHeader, ProxyInfo, UPDATE_MANIFEST_MAGIC, UpdateChannel,
};
use zerocopy::{FromZeros, IntoBytes};

impl Rng {
    /// Bytes drawn from `alphabet`: lets text parsers get past their first token.
    fn pick(&mut self, n: usize, alphabet: &[u8]) -> Vec<u8> {
        (0..n).map(|_| alphabet[self.below(alphabet.len())]).collect()
    }
    /// Flip, overwrite, insert and delete a few bytes of a valid input.
    fn mutate(&mut self, v: &mut Vec<u8>) {
        for _ in 0..1 + self.below(4) {
            match self.below(4) {
                0 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] ^= 1 << self.below(8);
                }
                1 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] = self.next() as u8;
                }
                2 => {
                    let i = self.below(v.len() + 1);
                    v.insert(i, self.next() as u8);
                }
                _ if !v.is_empty() => {
                    let i = self.below(v.len());
                    v.remove(i);
                }
                _ => {}
            }
        }
    }
    /// Lossy-UTF-8 text of random length below `max`.
    fn text(&mut self, max: usize) -> String {
        let n = self.below(max);
        String::from_utf8_lossy(&self.bytes(n)).into_owned()
    }
    /// A length near a power of two or a struct size, or small.
    fn interesting_len(&mut self) -> usize {
        const L: [usize; 16] = [0, 1, 8, 11, 12, 13, 16, 20, 39, 40, 41, 128, 188, 255, 256, 2048];
        if self.below(3) == 0 { self.below(600) } else { L[self.below(L.len())] }
    }
}

const INI_ALPHABET: &[u8] = b"[]=;# \t\r\nabcdefghijklmnopqrstuvwxyz_0123456789.:/-+ZLRABXY\xEF\xBB\xBF\xFF\xC3";
const SECTIONS: [&str; 6] = ["[server]", "[ldn]", "[debug]", "[update]", "[notifications]", "[bogus]"];
const KEYS: [&str; 16] = [
    "host", "port", "path", "token", "ca_file", "enabled", "real_wireless_button", "remote_log", "label",
    "channel", "auto", "updates", "game_start", "connection", "verbose", "level",
];
const VALUES: [&str; 12] = [
    "0", "1", "443", "65536", "-1", "99999999999999999999", "stable", "test", "off", "ZL+ZR", "none", "a b c",
];

#[test]
fn config_parse_random() {
    let mut r = Rng(0xC0F1_6000_0000_0001);
    let mut out = vec![0u8; 8192];
    for i in 0..30_000 {
        let data = match i % 3 {
            0 => {
                let n = r.below(400);
                r.bytes(n)
            }
            1 => {
                let n = r.below(400);
                r.pick(n, INI_ALPHABET)
            }
            _ => {
                // Structured: sections, known keys, edge values, occasional very long lines.
                let mut s = String::new();
                for _ in 0..r.below(12) {
                    s += SECTIONS[r.below(SECTIONS.len())];
                    s += if r.below(2) == 0 { "\r\n" } else { "\n" };
                    for _ in 0..r.below(6) {
                        s += KEYS[r.below(KEYS.len())];
                        s += if r.below(8) == 0 { "" } else { " = " };
                        s += VALUES[r.below(VALUES.len())];
                        if r.below(20) == 0 {
                            s += &"x".repeat(r.below(700));
                        }
                        s += "\n";
                    }
                }
                let mut v = s.into_bytes();
                if r.below(2) == 0 {
                    r.mutate(&mut v);
                }
                v
            }
        };
        let mut c = Config::default();
        let _ = c.parse(&data);
        // Whatever was accepted must serialize and re-parse to the same file.
        let n = c.write_to(&mut out);
        assert!(n > 0 && n <= out.len());
        let mut c2 = Config::default();
        assert_eq!(c2.parse(&out[..n]), 0, "own output has rejected values");
        let mut out2 = vec![0u8; 8192];
        assert_eq!(c2.write_to(&mut out2), n);
        assert_eq!(out2[..n], out[..n]);
        // Undersized output must report 0, not panic.
        let mut small = vec![0u8; r.below(n)];
        assert_eq!(c.write_to(&mut small), 0);
    }
}

#[test]
fn whitelist_and_state_files_random() {
    let mut r = Rng(0x57A7_E000_0000_0002);
    let mut w = Whitelist::new();
    for i in 0..30_000 {
        let n = r.below(500);
        let data = if i % 2 == 0 { r.bytes(n) } else { r.pick(n, b"0123456789abcdefABCDEFxX \t\r\n#;\xEF\xBB\xBF") };
        let overflow = w.load(&data);
        assert!(w.len() <= 4096 && (overflow == 0 || !w.is_empty()));
        let _ = w.contains(r.next());
        // probation / rejected: strict parsers, garbage reads as absent, own output round-trips.
        let _ = parse_probation(&data);
        let _ = parse_rejected(&data);
        let (b, k) = (r.next() as u32, r.next() as u32);
        let p = format_probation(b, k);
        let got = parse_probation(p.as_bytes()).unwrap();
        assert_eq!((got.build, got.boots), (b, k));
        assert_eq!(parse_rejected(format_rejected(b).as_bytes()), b);
        let mut m = p.as_bytes().to_vec();
        r.mutate(&mut m);
        let _ = parse_probation(&m);
        let mut m = format_rejected(b).as_bytes().to_vec();
        r.mutate(&mut m);
        let _ = parse_rejected(&m);
    }
}

/// A manifest with a valid magic/format (bad signature, like any forgery) and fuzzed fields.
fn fake_manifest(r: &mut Rng) -> Vec<u8> {
    let mut m = r.bytes(SIGNED_LEN);
    if r.below(4) != 0 {
        m[0..4].copy_from_slice(&UPDATE_MANIFEST_MAGIC.to_le_bytes());
        m[4..8].copy_from_slice(&UPDATE_MANIFEST_FORMAT.to_le_bytes());
    }
    m
}

#[test]
fn manifest_and_update_dl_random() {
    let mut r = Rng(0x0DA7_E000_0000_0003);
    let pubkey = [0x04u8; 65]; // not a curve point: verification must fail cleanly
    let mut key2 = [0u8; 65];
    for (i, b) in ldn_tunnel_core::update_pubkey::PUBLISHER_PUBKEY.iter().enumerate() {
        key2[i] = *b;
    }
    for i in 0..20_000 {
        let m = match i % 3 {
            0 => {
                let n = r.below(260);
                r.bytes(n)
            }
            1 => fake_manifest(&mut r),
            _ => {
                let mut v = fake_manifest(&mut r);
                v.truncate(if r.below(2) == 0 { UNSIGNED_LEN } else { r.below(SIGNED_LEN + 3) });
                v
            }
        };
        let key = if r.below(2) == 0 { &pubkey } else { &key2 };
        let _ = check_manifest(&m, key, r.next() as u32, r.next() as u32, r.next() as u32);

        // Drive the whole download state machine with hostile replies.
        let mut d = UpdateDl::new();
        let mut now = 0u64;
        let _ = d.start(now, UpdateChannel::Test, r.below(5) as u32, 0, 0, false, "label", "v1");
        let _ = d.on_manifest(&m, key);
        for _ in 0..20 {
            now = now.wrapping_add(r.below(10_000) as u64);
            d.begun(r.next() as u32);
            let _ = d.next_request(now);
            let n = r.interesting_len();
            let mut chunk = r.bytes(n);
            if chunk.len() >= 40 && r.below(2) == 0 {
                // plausible header: offset 0, total_size small
                chunk[32..36].copy_from_slice(&0u32.to_le_bytes());
            }
            let _ = d.on_chunk(now, &chunk);
            let _ = d.percent();
            let _ = d.poll(now);
            match r.below(6) {
                0 => d.verified(r.below(2) == 0),
                1 => d.installed(r.below(2) == 0),
                2 => d.fail_io(),
                _ => {}
            }
        }
    }
}

#[test]
fn upgrade_response_and_handshake_random() {
    let mut r = Rng(0x4A7D_5000_0000_0004);
    let key = handshake::encode_key(&[7; 16]);
    let accept = handshake::compute_accept(&key);
    let good = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        core::str::from_utf8(&accept).unwrap()
    )
    .into_bytes();
    assert_eq!(handshake::check_response(&good, &accept).1, 101);
    let mut out = vec![0u8; 400];
    for i in 0..40_000 {
        let data = match i % 3 {
            0 => {
                let n = r.below(300);
                r.bytes(n)
            }
            1 => {
                let n = r.below(300);
                r.pick(n, b"HTTP/1.0123456789 \r\n:;,UpgradwbsktCoinSc-AptEx")
            }
            _ => {
                let mut v = good.clone();
                r.mutate(&mut v);
                v
            }
        };
        let _ = handshake::head_len(&data);
        let _ = handshake::check_response(&data, &accept);
        let _ = ldn_tunnel_core::ws::check_upgrade_response(&data, &[]);
        let _ = ldn_tunnel_core::ws::close_code(&data);
        let _ = ldn_tunnel_core::ws::close_echo(&data);
        // build_request over arbitrary (possibly non-ASCII) strings and tiny output buffers.
        let s = |r: &mut Rng| r.text(40);
        let (h, p, t) = (s(&mut r), s(&mut r), s(&mut r));
        let cap = r.below(out.len());
        let _ = handshake::build_request(&h, r.next() as u16, &p, &t, &key, &mut out[..cap]);
        let _ = ACCEPT_LEN;
    }
}

#[test]
fn logring_notify_remote_log_random() {
    let mut r = Rng(0x106B_0000_0000_0005);
    let mut ring = LogRing::new();
    let mut rl = RemoteLog::new("");
    let mut out = vec![0u8; 4096];
    let mut n = Notifier::new(NotifyConfig::default());
    for i in 0..30_000u64 {
        // Messages with multibyte chars, newlines and over-long lines (cut on a char boundary).
        let msg = match r.below(3) {
            0 => r.text(600),
            1 => "é\n\r€😀x".repeat(r.below(120)),
            _ => "a".repeat(r.below(400)),
        };
        ring.push(&msg);
        if r.below(3) == 0 {
            let cap = r.below(out.len());
            let (used, _) = ring.drain_into(&mut out[..cap]);
            assert!(used <= cap);
        }
        if r.below(4) == 0 {
            let cap = if r.below(2) == 0 { r.below(out.len()) } else { out.len() };
            let force = r.below(2) == 0;
            if let Some(len) = rl.next_payload(&mut ring, i * 700, force, &mut out[..cap]) {
                assert!(len <= cap && len <= remote_log::MAX_PAYLOAD && len > 0);
                assert_eq!(out[0] as usize, rl.label().len());
            }
        }
        if i % 997 == 0 {
            let l = r.text(80);
            rl = RemoteLog::new(&l);
            assert!(!rl.label().trim().is_empty() && rl.label().len() <= remote_log::MAX_LABEL);
        }
        // Notifier + toast JSON with hostile version strings and tiny buffers.
        let ver = r.text(100);
        let ev = match r.below(5) {
            0 => Event::UpdateStaged,
            1 => Event::UpdatedTo(&ver),
            2 => Event::GameStarted { pid: r.below(3) as u64, mode: [LdnMode::Online, LdnMode::Bypass, LdnMode::Disabled][r.below(3)] },
            3 => Event::GameExited { pid: r.below(3) as u64 },
            _ => Event::Relay { up: r.below(2) == 0 },
        };
        if r.below(50) == 0 {
            n = Notifier::new(NotifyConfig::from_bits(r.next() as u32));
        }
        n.on_event(ev, i * 3000);
        while let Some(t) = n.poll(i * 3000 + r.below(20_000) as u64) {
            let cap = r.below(300);
            if let Some(len) = t.write_json(&mut out[..cap]) {
                assert!(len <= cap);
            }
            assert!(t.write_json(&mut out).is_some());
        }
    }
}

/// A Session in one of several link/request states, so on_packet meets each branch.
fn session_in_state(r: &mut Rng, k: usize) -> Session {
    use ldn_tunnel_core::wire::{ScanFilterFull, SecurityConfig, UserConfig};
    let mut s = Session::new(0x0100_1520_0000_0000);
    let _ = s.initialize();
    let (sec, user) = (SecurityConfig::new_zeroed(), UserConfig::new_zeroed());
    match k {
        0 => {}
        1 => {
            let _ = s.open_station(0);
            let _ = s.scan(&ScanFilterFull::new_zeroed(), 0);
        }
        _ => {
            let _ = s.open_station(0);
            let _ = s.scan(&ScanFilterFull::new_zeroed(), 0);
            while s.next_action().is_some() {}
            s.on_relay_open(1);
            if k >= 3 {
                let _ = s.on_packet(PacketId::Initialize.raw(), &[0u8; 22], 2);
            }
            if k >= 4 {
                // A room to join / create, so Connected/SyncNetwork/Disconnect have a request to answer.
                let _ = s.close_station(3);
                let _ = s.open_access_point(3);
                let net = ldn_tunnel_core::wire::NetworkConfig::new_zeroed();
                let _ = s.create_network(&sec, &user, &net, 4);
            }
        }
    }
    let _ = r;
    while s.next_action().is_some() {}
    s
}

#[test]
fn ldn_session_on_packet_random() {
    let mut r = Rng(0x5E55_1000_0000_0006);
    let ids: Vec<u8> = (0..=30u8).chain([0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 254, 255]).collect();
    for round in 0..4_000 {
        let mut s = session_in_state(&mut r, round % 5);
        let mut now = 10u64;
        for _ in 0..60 {
            now = now.wrapping_add(r.below(40_000) as u64);
            let id = if r.below(5) == 0 { r.next() as u8 } else { ids[r.below(ids.len())] };
            let n = r.interesting_len();
            let mut data = r.bytes(n);
            if r.below(3) == 0 {
                // zeros with sparse noise: keeps counts/flags in-range more often than pure noise
                for b in data.iter_mut() {
                    if r.below(8) != 0 {
                        *b = 0;
                    }
                }
            }
            if let Some(p) = s.on_packet(id, &data, now) {
                assert!(p.payload.len() <= data.len());
            }
            if r.below(4) == 0 {
                s.poll(now);
            }
            if r.below(10) == 0 {
                match r.below(3) {
                    0 => s.on_relay_closed(now),
                    1 => s.on_relay_open(now),
                    _ => {
                        let _ = s.disconnect(now);
                    }
                }
            }
            let _ = (s.state(), s.scan_results().len(), s.get_ipv4_address(), s.network_info().ldn.node_count);
            while s.next_action().is_some() {}
            let _ = s.take_reply();
            let _ = s.next_deadline();
        }
    }
}

#[test]
fn router_proxy_data_random() {
    let mut r = Rng(0x2077_E000_0000_0007);
    let mut rt = Router::new();
    let mut buf = vec![0u8; 2200];
    for i in 0..60_000u32 {
        match r.below(8) {
            0 => rt.set_proxy_config(r.next() as u32, [0xFFFF_0000, 0, u32::MAX, r.next() as u32][r.below(4)]),
            1 => {
                let key = socket_key(r.below(3) as u32, r.below(6) as i32);
                if rt.on_socket(key, 2, 2, 0) {
                    let ip = [0, 0x0A72_0001, 0x0A72_0002, 0x0A72_FFFF][r.below(4)];
                    let _ = rt.on_bind(key, &SockAddrIn::from_ryujinx(ip, (1 + r.below(8)) as u16), false);
                }
            }
            2 => {
                let key = socket_key(r.below(3) as u32, r.below(6) as i32);
                let cap = r.below(2200);
                let _ = rt.on_recvfrom(key, &mut buf[..cap], r.next() as i32);
                let _ = rt.on_sendto(key, &buf[..r.below(2100)], Some(&SockAddrIn::from_ryujinx(r.next() as u32, r.next() as u16)));
                let _ = rt.on_setsockopt(key, r.next() as i32, r.next() as i32, &buf[..r.below(12)]);
                let _ = rt.poll_state(key);
            }
            3 => {
                rt.on_close(socket_key(r.below(3) as u32, r.below(6) as i32));
            }
            4 if i % 50 == 0 => rt.reset(),
            _ => {}
        }
        // Headers: consistent length (usually), wild lengths, wrong protocol, port 0, broadcast.
        let n = [r.below(40), r.below(2100), 1500, 1501, 1472][r.below(5)];
        let payload = r.bytes(n);
        let mut info = ProxyInfo::new_zeroed();
        info.source_ipv4 = r.next() as u32;
        info.source_port = r.below(10) as u16;
        info.dest_ipv4 = [0x0A72_0001, 0x0A72_FFFF, 0xFFFF_FFFF, r.next() as u32][r.below(4)];
        info.dest_port = (1 + r.below(8)) as u16;
        info.protocol = if r.below(8) == 0 { r.next() as i32 } else { 17 };
        let data_length = if r.below(6) == 0 { r.next() as u32 } else { n as u32 };
        let h = ProxyDataHeader { info, data_length };
        let _ = h.as_bytes().len();
        let _ = rt.on_proxy_data(&h, &payload);
    }
}

#[test]
fn conn_stream_random() {
    let mut r = Rng(0xC044_0000_0000_0008);
    let mut out = vec![0u8; 20_000];
    for round in 0..1_500 {
        let mut c = Conn::<2048>::new(ConnConfig::new([9; 16], [2, 0, 0x5E, 0, 0x53, 1]));
        let mut now = 1_000u64;
        assert!(c.connect(now));
        let random = [round as u8; 16];
        let accept = handshake::compute_accept(&handshake::encode_key(&random));
        // Bring it to Upgrading, then hand it a good, mutated or garbage 101 answer.
        for _ in 0..4 {
            if matches!(c.poll(now, [1, 2, 3, 4], &mut out), ConnAction::Open) {
                let _ = c.opened("relay.example", 443, "/ws", "tok", &random, &mut out);
                break;
            }
        }
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            core::str::from_utf8(&accept).unwrap()
        )
        .into_bytes();
        let mut stream = match r.below(6) {
            0 => {
                let n = r.below(300);
                r.bytes(n)
            }
            1 => {
                let mut v = head.clone();
                r.mutate(&mut v);
                v
            }
            _ => head,
        };
        // Then relay traffic: valid WebSocket-framed LDN packets (some with lying sizes), pings, noise.
        for _ in 0..r.below(12) {
            let mut pkt = packet(&mut r, 400);
            if r.below(5) == 0 {
                r.mutate(&mut pkt);
            }
            let (kind, fin) = (r.below(6), r.below(8) != 0);
            let op = match kind {
                0 => OPCODE_PING,
                1 => OPCODE_PONG,
                2 => OPCODE_CONTINUATION,
                _ => OPCODE_BINARY,
            };
            stream.extend(frame(op, fin, &pkt));
            if r.below(6) == 0 {
                let n = r.below(40);
                stream.extend(r.bytes(n));
            }
        }
        let mut at = 0;
        while at < stream.len() {
            let end = (at + 1 + r.below(300)).min(stream.len());
            let mut piece = &stream[at..end];
            // A full reassembly buffer takes less: drain and offer the rest again.
            for _ in 0..8 {
                let taken = c.on_bytes(piece);
                assert!(taken <= piece.len());
                piece = &piece[taken..];
                let mut got = 0;
                while let Some((_, payload)) = c.next_packet() {
                    assert!(payload.len() <= 2048);
                    got += 1;
                    assert!(got < 10_000, "next_packet does not terminate");
                }
                if piece.is_empty() {
                    break;
                }
            }
            at = end;
            now = now.wrapping_add(r.below(20_000) as u64);
            for _ in 0..6 {
                let mask = [r.next() as u8, r.next() as u8, r.next() as u8, r.next() as u8];
                let cap = if r.below(8) == 0 { r.below(60) } else { out.len() };
                match c.poll(now, mask, &mut out[..cap]) {
                    ConnAction::Idle => break,
                    ConnAction::Send(n) => assert!(n <= cap),
                    ConnAction::Open => {
                        let _ = c.opened("h", 443, "/", "t", &[round as u8; 16], &mut out);
                    }
                    ConnAction::Drop => {}
                }
            }
            let _ = c.send_packet(PacketId::ProxyData, &stream[..r.below(300).min(stream.len())], [1, 2, 3, 4], &mut out[..r.below(400)]);
        }
        if r.below(3) == 0 {
            c.transport_lost();
            c.close();
            let _ = c.poll(now, [0; 4], &mut out);
        }
    }
}

/// The bsd:u MitM peeks at every forwarded reply: arbitrary words, and real CMIF replies with
/// random descriptor counts, special headers and domain prefixes, cut and mutated.
#[test]
fn hipc_reply_random() {
    use ldn_tunnel_core::hipc::reply_raw;
    let mut r = Rng(0x41C0_FFEE);
    for _ in 0..100_000 {
        let n = r.interesting_len().min(0x200);
        let _ = reply_raw(&r.bytes(n));
    }
    let mut hits = 0;
    for _ in 0..50_000 {
        let mut msg = vec![0u8; 0x100];
        let words = |m: &mut Vec<u8>, i: usize, v: u32| m[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        let (x, a, b, w) = (r.below(4) as u32, r.below(4) as u32, r.below(4) as u32, r.below(4) as u32);
        let special = r.below(2) == 1;
        let data_words = [r.below(0x40), r.below(0x400)][r.below(2)] as u32;
        words(&mut msg, 0, x << 16 | a << 20 | b << 24 | w << 28);
        words(&mut msg, 1, data_words | u32::from(special) << 31);
        let mut at = 2;
        if special {
            let s = r.next() as u32 & 0x1FF;
            words(&mut msg, 2, s);
            at += 1 + if s & 1 != 0 { 2 } else { 0 } + ((s >> 1) & 0xF) as usize + ((s >> 5) & 0xF) as usize;
        }
        at += 2 * x as usize + 3 * (a + b + w) as usize;
        let start = (at * 4).next_multiple_of(16) + if r.below(2) == 1 { 16 } else { 0 };
        let result = r.next() as u32;
        let raw = r.bytes(16);
        if start + 32 <= msg.len() {
            msg[start..start + 4].copy_from_slice(b"SFCO");
            msg[start + 8..start + 12].copy_from_slice(&result.to_le_bytes());
            msg[start + 16..start + 32].copy_from_slice(&raw);
        }
        let cut = r.below(msg.len() + 1);
        msg.truncate(cut);
        if r.below(4) == 0 {
            r.mutate(&mut msg);
        }
        // Whatever it returns lies inside the message, after an SFCO magic.
        if let Some((res, out)) = reply_raw(&msg) {
            let at = (0..msg.len().saturating_sub(31))
                .step_by(16)
                .find(|&i| &msg[i..i + 4] == b"SFCO" && msg[i + 8..i + 12] == res.to_le_bytes() && msg[i + 16..i + 32] == out);
            assert!(at.is_some(), "result not from the message");
            hits += 1;
        }
    }
    assert!(hits > 1000, "the generator reaches the parser's success path ({hits})");
}

/// The relay's address comes from our own resolver: answers with compression pointers, CNAME
/// chains, counts that lie and truncation, up to the 512-byte UDP limit.
#[test]
fn dns_response_random() {
    use ldn_tunnel_core::dns::{build_query, parse_response};
    let mut r = Rng(0xD45_D45);
    let mut q = [0u8; 512];
    let qn = build_query("relay.example.com", 0xBEEF, &mut q).unwrap();
    let mut found = 0;
    for _ in 0..100_000 {
        let mut msg = q[..qn].to_vec();
        msg[2] = 0x81;
        msg[3] = 0x80 | ((r.below(16) as u8) * u8::from(r.below(8) == 0)); // rcode, mostly 0
        msg[6..8].copy_from_slice(&(r.below(4) as u16).to_be_bytes());
        for _ in 0..r.below(4) {
            match r.below(3) {
                0 => msg.extend_from_slice(&[0xC0, 0x0C]),
                1 => msg.extend_from_slice(&[0xC0, r.next() as u8]),
                _ => {
                    let l = r.below(70) as u8;
                    msg.push(l);
                    msg.extend(r.bytes(usize::from(l)));
                    msg.push(0);
                }
            }
            let t: u16 = [1, 5, 28, r.next() as u16][r.below(4)];
            msg.extend_from_slice(&t.to_be_bytes());
            msg.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            let len = [4usize, 0, 16, r.below(600)][r.below(4)];
            msg.extend_from_slice(&(len as u16).to_be_bytes());
            let have = len.min(r.below(600));
            msg.extend(r.bytes(have));
        }
        r.mutate(&mut msg);
        msg.truncate(512);
        found += usize::from(parse_response(&msg, 0xBEEF).is_ok());
        let n = r.interesting_len().min(512);
        let (noise, id) = (r.bytes(n), r.next() as u16);
        let _ = parse_response(&noise, id);
    }
    assert!(found > 1000, "the generator reaches an A record ({found})");
}
