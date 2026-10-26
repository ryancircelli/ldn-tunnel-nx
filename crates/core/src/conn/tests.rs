//! Host tests for the connection: a fake relay on the other end of [`Conn`], byte for byte.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
extern crate std;

use std::{vec, vec::Vec};

use zerocopy::IntoBytes;

use super::handshake::{self, ACCEPT_LEN};
use super::remote_log::RemoteLog;
use super::state::*;
use super::update_dl::{CHUNK_HEADER, Progress, State, UpdateDl, tests::release};
use crate::logring::LogRing;
use crate::protocol::{HEADER_SIZE, encode_header as ldn_header};
use crate::wire::{NetworkErrorCode, PacketId, UpdateChannel, UpdateChunkRequest};
use crate::ws::{OPCODE_BINARY, OPCODE_CLOSE, OPCODE_PING, OPCODE_PONG, apply_mask, encode_header as ws_header};

const ID: [u8; 16] = [0x11; 16];
const MAC: [u8; 6] = [2, 0, 0x5E, 0, 0x53, 1];

// ---- the relay side -------------------------------------------------------------------

/// An unmasked server frame.
fn raw_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let (h, n) = ws_header(opcode, payload.len(), None);
    let mut f = h[..n].to_vec();
    f.extend_from_slice(payload);
    f
}

fn ldn_packet(type_: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; HEADER_SIZE + payload.len()];
    ldn_header(&mut p, type_, payload.len() as i32);
    p[HEADER_SIZE..].copy_from_slice(payload);
    p
}

fn server_packet(id: PacketId, payload: &[u8]) -> Vec<u8> {
    raw_frame(OPCODE_BINARY, &ldn_packet(id.raw(), payload))
}

/// The 101 answer to an upgrade request, after checking the request line by line.
fn relay_accepts(req: &[u8]) -> Vec<u8> {
    let text = core::str::from_utf8(req).unwrap();
    let lines: Vec<&str> = text.split("\r\n").collect();
    assert!(lines[0].starts_with("GET /") && lines[0].ends_with(" HTTP/1.1"));
    assert!(lines.contains(&"Upgrade: websocket"));
    assert!(lines.contains(&"Connection: Upgrade"));
    assert!(lines.contains(&"Sec-WebSocket-Version: 13"));
    assert!(lines.contains(&"Authorization: Bearer tok"));
    assert!(text.ends_with("\r\n\r\n"));
    let key = lines.iter().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap();
    let accept = handshake::compute_accept(key.as_bytes().try_into().unwrap());
    std::format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        core::str::from_utf8(&accept).unwrap()
    )
    .into_bytes()
}

/// Client frames: every one must be masked; returns (opcode, unmasked payload).
fn client_frames(mut b: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while !b.is_empty() {
        assert_eq!(b[0] & 0x80, 0x80, "FIN");
        assert_eq!(b[1] & 0x80, 0x80, "client frames are masked");
        let (len, mut at) = match b[1] & 0x7F {
            126 => (u16::from_be_bytes([b[2], b[3]]) as usize, 4),
            127 => (u64::from_be_bytes(b[2..10].try_into().unwrap()) as usize, 10),
            n => (n as usize, 2),
        };
        let mask: [u8; 4] = b[at..at + 4].try_into().unwrap();
        at += 4;
        let mut p = b[at..at + len].to_vec();
        apply_mask(&mut p, &mask);
        out.push((b[0] & 0x0F, p));
        b = &b[at + len..];
    }
    out
}

/// The LDN packet inside a client binary frame.
fn client_packet(frame: &[u8]) -> (u8, Vec<u8>) {
    let f = client_frames(frame);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].0, OPCODE_BINARY);
    let p = &f[0].1;
    assert_eq!(&p[..4], b"RLDN");
    let n = i32::from_le_bytes(p[8..12].try_into().unwrap()) as usize;
    assert_eq!(p.len(), HEADER_SIZE + n);
    (p[4], p[HEADER_SIZE..].to_vec())
}

// ---- rig ------------------------------------------------------------------------------

struct Rig<const N: usize = 8192> {
    c: Conn<N>,
    now: u64,
    rng: u64,
    out: Vec<u8>,
}

impl<const N: usize> Rig<N> {
    fn with(cfg: ConnConfig) -> Self {
        Rig { c: Conn::new(cfg), now: 1000, rng: 0x9E37_79B9_7F4A_7C15, out: vec![0; 20_000] }
    }

    fn new() -> Self {
        Self::with(ConnConfig::new(ID, MAC))
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn poll(&mut self) -> Action {
        let m = (self.rand() as u32).to_le_bytes();
        self.c.poll(self.now, m, &mut self.out)
    }

    fn sent(&mut self) -> Vec<u8> {
        match self.poll() {
            Action::Send(n) => self.out[..n].to_vec(),
            a => panic!("expected Send, got {a:?}"),
        }
    }

    fn mask(&mut self) -> [u8; 4] {
        (self.rand() as u32).to_le_bytes()
    }

    /// Everything the shell would write until Idle.
    fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        loop {
            match self.poll() {
                Action::Send(n) => v.push(self.out[..n].to_vec()),
                Action::Idle => return v,
                a => panic!("{a:?}"),
            }
        }
    }

    fn open(&mut self) -> Vec<u8> {
        assert_eq!(self.poll(), Action::Open);
        let mut random = [0u8; 16];
        random[..8].copy_from_slice(&self.rand().to_le_bytes());
        random[8..].copy_from_slice(&self.rand().to_le_bytes());
        let mut out = [0u8; handshake::MAX_REQUEST];
        let n = self.c.opened("relay.example.com", 443, "/ws", "tok", &random, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn feed_all(&mut self, data: &[u8]) -> Vec<(PacketId, Vec<u8>)> {
        let mut got = Vec::new();
        let mut rest = data;
        while !rest.is_empty() {
            let used = self.c.on_bytes(rest);
            rest = &rest[used..];
            while let Some((id, p)) = self.c.next_packet() {
                got.push((id, p.to_vec()));
            }
            if used == 0 && self.c.next_packet().is_none() {
                break;
            }
        }
        got
    }

    /// connect -> upgrade -> Initialize -> relay answer -> Ready.
    fn ready(&mut self) {
        assert!(self.c.connect(self.now));
        let req = self.open();
        let resp = relay_accepts(&req);
        assert!(self.feed_all(&resp).is_empty());
        assert_eq!(self.c.state(), ConnectionState::Connected);
        let init = self.sent();
        assert_eq!(client_packet(&init), (0, [ID.as_slice(), MAC.as_slice()].concat()));
        assert_eq!(self.c.state(), ConnectionState::Handshaking);
        let assigned = [[0x77u8; 16].as_slice(), [2, 0, 0x5E, 9, 9, 9].as_slice()].concat();
        assert!(self.feed_all(&server_packet(PacketId::Initialize, &assigned)).is_empty());
        assert_eq!(self.c.state(), ConnectionState::Ready);
        assert_eq!(self.c.session(), Some(&Session { id: [0x77; 16], mac: [2, 0, 0x5E, 9, 9, 9] }));
        assert_eq!(self.poll(), Action::Idle);
    }
}

// ---- state machine --------------------------------------------------------------------

#[test]
fn transition_table_matches_cpp() {
    use ConnectionEvent as E;
    use ConnectionState as S;
    let ok = |from: S, ev: E, to: S| {
        let mut m = StateMachine::new();
        m.force_state(from);
        assert_eq!(m.process_event(ev), TransitionResult::Success, "{from:?} {ev:?}");
        assert_eq!(m.state(), to, "{from:?} {ev:?}");
    };
    ok(S::Disconnected, E::Connect, S::Connecting);
    ok(S::Disconnected, E::RetryRequested, S::Connecting);
    ok(S::Connecting, E::ConnectSuccess, S::Connected);
    ok(S::Connecting, E::ConnectFailed, S::Backoff);
    ok(S::Connecting, E::Disconnect, S::Disconnected);
    ok(S::Connecting, E::FatalError, S::Error);
    ok(S::Connected, E::HandshakeStarted, S::Handshaking);
    ok(S::Connected, E::HandshakeSuccess, S::Ready);
    ok(S::Connected, E::HandshakeFailed, S::Backoff);
    ok(S::Connected, E::Disconnect, S::Disconnecting);
    ok(S::Connected, E::ConnectionLost, S::Backoff);
    ok(S::Connected, E::FatalError, S::Error);
    ok(S::Handshaking, E::HandshakeSuccess, S::Ready);
    ok(S::Handshaking, E::HandshakeFailed, S::Backoff);
    ok(S::Handshaking, E::Disconnect, S::Disconnecting);
    ok(S::Handshaking, E::ConnectionLost, S::Backoff);
    ok(S::Handshaking, E::FatalError, S::Error);
    ok(S::Ready, E::Disconnect, S::Disconnecting);
    ok(S::Ready, E::ConnectionLost, S::Backoff);
    ok(S::Ready, E::FatalError, S::Error);
    ok(S::Backoff, E::Disconnect, S::Disconnected);
    ok(S::Backoff, E::BackoffExpired, S::Retrying);
    ok(S::Backoff, E::RetryRequested, S::Retrying);
    ok(S::Backoff, E::FatalError, S::Error);
    ok(S::Retrying, E::ConnectSuccess, S::Connected);
    ok(S::Retrying, E::ConnectFailed, S::Backoff);
    ok(S::Retrying, E::Disconnect, S::Disconnected);
    ok(S::Retrying, E::FatalError, S::Error);
    ok(S::Disconnecting, E::ConnectSuccess, S::Disconnected);
    ok(S::Disconnecting, E::ConnectFailed, S::Disconnected);
    ok(S::Disconnecting, E::ConnectionLost, S::Disconnected);
    ok(S::Disconnecting, E::FatalError, S::Disconnected);
    ok(S::Error, E::Disconnect, S::Disconnected);
    ok(S::Error, E::RetryRequested, S::Connecting);

    // exhaustive: every other pair is invalid, plus the two AlreadyInState cases
    const STATES: [S; 9] =
        [S::Disconnected, S::Connecting, S::Connected, S::Handshaking, S::Ready, S::Backoff, S::Retrying, S::Disconnecting, S::Error];
    const EVENTS: [E; 11] = [
        E::Connect, E::ConnectSuccess, E::ConnectFailed, E::HandshakeStarted, E::HandshakeSuccess, E::HandshakeFailed,
        E::Disconnect, E::ConnectionLost, E::BackoffExpired, E::RetryRequested, E::FatalError,
    ];
    let valid = 34 + 2; // lines above + the two no-ops
    let mut seen_ok = 0;
    for s in STATES {
        for e in EVENTS {
            let mut m = StateMachine::new();
            m.force_state(s);
            match m.process_event(e) {
                TransitionResult::Success | TransitionResult::AlreadyInState => seen_ok += 1,
                TransitionResult::InvalidTransition => assert_eq!(m.state(), s),
            }
        }
    }
    assert_eq!(seen_ok, valid);
    let mut m = StateMachine::new();
    assert_eq!(m.process_event(E::Disconnect), TransitionResult::AlreadyInState);
    m.force_state(S::Ready);
    assert_eq!(m.process_event(E::ConnectSuccess), TransitionResult::AlreadyInState);
}

#[test]
fn state_helpers_and_retry_count() {
    use ConnectionEvent as E;
    use ConnectionState as S;
    assert!(S::Connected.is_connected() && S::Handshaking.is_connected() && S::Ready.is_connected());
    assert!(!S::Backoff.is_connected() && !S::Connecting.is_connected());
    for s in [S::Connecting, S::Handshaking, S::Retrying, S::Disconnecting, S::Backoff] {
        assert!(s.is_transitioning());
    }
    assert!(!S::Ready.is_transitioning() && !S::Error.is_transitioning());
    assert_eq!(S::Handshaking.as_str(), "Handshaking");

    let mut m = StateMachine::new();
    m.process_event(E::Connect);
    m.process_event(E::ConnectFailed);
    m.process_event(E::BackoffExpired);
    assert_eq!(m.retry_count(), 1);
    m.process_event(E::ConnectFailed);
    m.process_event(E::BackoffExpired);
    assert_eq!(m.retry_count(), 2);
    m.process_event(E::ConnectSuccess);
    m.process_event(E::HandshakeSuccess);
    assert_eq!((m.state(), m.retry_count()), (S::Ready, 0));
    m.force_state(S::Backoff);
    m.process_event(E::RetryRequested);
    assert_eq!(m.state(), S::Retrying);
}

// ---- Conn happy path ------------------------------------------------------------------

#[test]
fn happy_path_ping_and_dispatch() {
    let mut r = Rig::<8192>::new();
    r.ready();
    // relay Ping (requester 0, id 7) is echoed, never delivered
    assert!(r.feed_all(&server_packet(PacketId::Ping, &[0, 7])).is_empty());
    let sent = r.sent();
    assert_eq!(client_packet(&sent), (254, vec![0, 7]));
    assert_eq!(r.poll(), Action::Idle);
    // a ping that answers one of ours (requester 1) is swallowed
    assert!(r.feed_all(&server_packet(PacketId::Ping, &[1, 7])).is_empty());
    assert_eq!(r.poll(), Action::Idle);
    // LDN packets are delivered in order with their payload; unknown ids skipped
    let mut stream = server_packet(PacketId::ScanReply, &[1, 2, 3]);
    stream.extend(raw_frame(OPCODE_BINARY, &ldn_packet(100, &[9; 5])));
    stream.extend(server_packet(PacketId::Disconnect, &[0, 0, 0, 0]));
    stream.extend(server_packet(PacketId::NetworkError, &[5, 0, 0, 0]));
    let got = r.feed_all(&stream);
    assert_eq!(
        got,
        vec![
            (PacketId::ScanReply, vec![1, 2, 3]),
            (PacketId::Disconnect, vec![0; 4]),
            (PacketId::NetworkError, vec![5, 0, 0, 0]),
        ]
    );
    assert!(r.c.is_ready());
}

#[test]
fn control_frames_fragments_and_split_input() {
    // control ping between fragments of one message, then a normal packet
    let pkt = ldn_packet(PacketId::ScanReply.raw(), &[4; 300]);
    let (a, b) = pkt.split_at(100);
    let mut after = raw_frame(OPCODE_PING, b"hi");
    let mut f1 = raw_frame(OPCODE_BINARY, a);
    f1[0] &= 0x7F; // FIN clear
    after.extend(f1);
    after.extend(raw_frame(OPCODE_PING, b""));
    after.extend(raw_frame(0x0, b)); // continuation
    after.extend(raw_frame(OPCODE_PONG, b"unsolicited"));
    after.extend(server_packet(PacketId::ProxyData, &[8; 9]));

    for chunk in [usize::MAX, 1, 2, 7, 64] {
        let mut r = Rig::<8192>::new();
        r.ready();
        let mut got = Vec::new();
        let mut frames = Vec::new();
        for piece in after.chunks(chunk.min(after.len())) {
            got.extend(r.feed_all(piece));
            for f in r.drain() {
                frames.extend(client_frames(&f));
            }
        }
        assert_eq!(got, vec![(PacketId::ScanReply, vec![4; 300]), (PacketId::ProxyData, vec![8; 9])], "chunk {chunk}");
        // a pong per ping; pings that arrive in one read coalesce into the newest (RFC 6455 5.5.3)
        if chunk == usize::MAX {
            assert_eq!(frames, vec![(OPCODE_PONG, vec![])]);
        } else {
            assert_eq!(frames, vec![(OPCODE_PONG, b"hi".to_vec()), (OPCODE_PONG, vec![])], "chunk {chunk}");
        }
    }
}

#[test]
fn early_packets_wait_for_handshaking() {
    let mut r = Rig::<8192>::new();
    assert!(r.c.connect(r.now));
    let req = r.open();
    let mut all = relay_accepts(&req);
    all.extend(server_packet(PacketId::ScanReply, &[1]));
    assert!(r.feed_all(&all).is_empty()); // Connected: nothing delivered yet
    assert!(r.c.next_packet().is_none());
    let _ = r.sent(); // Initialize
    assert_eq!(r.c.next_packet().map(|(i, p)| (i, p.to_vec())), Some((PacketId::ScanReply, vec![1])));
}

// ---- failures and retries -------------------------------------------------------------

fn no_jitter() -> ConnConfig {
    let mut cfg = ConnConfig::new(ID, MAC);
    cfg.reconnect.jitter_percent = 0;
    cfg
}

#[test]
fn backoff_schedule_and_give_up() {
    let mut r = Rig::<4096>::with(no_jitter());
    assert!(r.c.connect(r.now));
    assert!(!r.c.connect(r.now), "already connecting");
    let mut delays = Vec::new();
    for _ in 0..11 {
        assert_eq!(r.poll(), Action::Open);
        r.c.open_failed();
        assert_eq!(r.poll(), Action::Drop);
        if r.c.state() == ConnectionState::Disconnected {
            break;
        }
        assert_eq!(r.c.state(), ConnectionState::Backoff);
        let d = r.c.backoff_ms();
        delays.push(d);
        // not before the delay, exactly at it
        r.now += u64::from(d) - 1;
        assert_eq!(r.poll(), Action::Idle);
        r.now += 1;
    }
    assert_eq!(delays, [200, 1000, 2000, 4000, 8000, 10_000, 10_000, 10_000, 10_000, 10_000]);
    assert_eq!(r.c.state(), ConnectionState::Disconnected);
    assert_eq!(r.c.failure(), Some(Failure::OpenFailed));
    assert_eq!(r.poll(), Action::Idle);
    // a fresh connect has a fresh budget
    assert!(r.c.connect(r.now));
    assert_eq!(r.c.retry_count(), 0);
    assert_eq!(r.poll(), Action::Open);
}

#[test]
fn jittered_delay_stays_in_bounds() {
    let mut r = Rig::<4096>::new();
    assert!(r.c.connect(r.now));
    assert_eq!(r.poll(), Action::Open);
    r.c.open_failed();
    assert_eq!(r.poll(), Action::Drop);
    assert!((180..=220).contains(&r.c.backoff_ms()), "{}", r.c.backoff_ms());
}

#[test]
fn connect_during_backoff_restarts_budget() {
    let mut r = Rig::<4096>::with(no_jitter());
    assert!(r.c.connect(r.now));
    for _ in 0..3 {
        assert_eq!(r.poll(), Action::Open);
        r.c.open_failed();
        assert_eq!(r.poll(), Action::Drop);
        r.now += u64::from(r.c.backoff_ms());
    }
    assert_eq!(r.c.retry_count(), 3);
    assert_eq!(r.poll(), Action::Open);
    r.c.open_failed();
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!(r.c.state(), ConnectionState::Backoff);
    assert!(r.c.connect(r.now));
    assert_eq!((r.c.state(), r.c.retry_count()), (ConnectionState::Connecting, 0));
    assert_eq!(r.poll(), Action::Open);
}

#[test]
fn connect_timeout() {
    let mut r = Rig::<4096>::with(no_jitter());
    assert!(r.c.connect(r.now));
    assert_eq!(r.poll(), Action::Open);
    r.now += 4999;
    assert_eq!(r.poll(), Action::Idle);
    r.now += 1;
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!(r.c.failure(), Some(Failure::ConnectTimeout));
    assert_eq!(r.c.state(), ConnectionState::Backoff);
}

fn upgrade_with(r: &mut Rig<4096>, response: &[u8]) {
    assert!(r.c.connect(r.now));
    let _ = r.open();
    assert!(r.feed_all(response).is_empty());
}

#[test]
fn upgrade_failures() {
    let mut r = Rig::<4096>::with(no_jitter());
    upgrade_with(&mut r, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!(r.c.failure(), Some(Failure::UpgradeRejected(404)));
    assert_eq!(r.c.state(), ConnectionState::Backoff);

    let mut r = Rig::<4096>::with(no_jitter());
    upgrade_with(
        &mut r,
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
    );
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!(r.c.failure(), Some(Failure::UpgradeInvalid));

    // a response head that never ends overflows the buffer
    let mut r = Rig::<4096>::with(no_jitter());
    upgrade_with(&mut r, &vec![b'a'; 5000]);
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!(r.c.failure(), Some(Failure::Protocol));
}

#[test]
fn handshake_timeout_and_rejections() {
    // no answer to Initialize
    let mut r = Rig::<4096>::with(no_jitter());
    assert!(r.c.connect(r.now));
    let req = r.open();
    r.feed_all(&relay_accepts(&req));
    let _ = r.sent();
    r.now += 4999;
    assert_eq!(r.poll(), Action::Idle);
    r.now += 1;
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!((r.c.failure(), r.c.last_error()), (Some(Failure::HandshakeTimeout), None));
    assert_eq!(r.c.state(), ConnectionState::Backoff);

    let reject = |payload: Vec<u8>, id: PacketId| {
        let mut r = Rig::<4096>::with(no_jitter());
        assert!(r.c.connect(r.now));
        let req = r.open();
        r.feed_all(&relay_accepts(&req));
        let _ = r.sent();
        assert!(r.feed_all(&server_packet(id, &payload)).is_empty());
        assert_eq!(r.poll(), Action::Drop);
        r
    };
    let r = reject(3u32.to_le_bytes().to_vec(), PacketId::NetworkError);
    assert_eq!((r.c.state(), r.c.failure()), (ConnectionState::Error, Some(Failure::VersionMismatch)));
    assert_eq!(r.c.last_error(), Some(NetworkErrorCode::VersionTooLow));
    let mut r = r;
    assert_eq!(r.poll(), Action::Idle, "no retry after a fatal error");
    assert!(r.c.connect(r.now), "but a manual connect leaves Error");
    assert_eq!(r.poll(), Action::Open);

    let r = reject(127u32.to_le_bytes().to_vec(), PacketId::NetworkError);
    assert_eq!((r.c.state(), r.c.failure()), (ConnectionState::Backoff, Some(Failure::HandshakeRejected)));
    assert_eq!(r.c.last_error(), Some(NetworkErrorCode::BannedByServer));
    let r = reject(vec![], PacketId::NetworkError);
    assert_eq!(r.c.last_error(), Some(NetworkErrorCode::Unknown));
    let r = reject(vec![0; 4], PacketId::Disconnect);
    assert_eq!((r.c.state(), r.c.failure()), (ConnectionState::Backoff, Some(Failure::ServerDisconnected)));
}

#[test]
fn sync_network_also_completes_the_handshake() {
    let mut r = Rig::<4096>::new();
    assert!(r.c.connect(r.now));
    let req = r.open();
    r.feed_all(&relay_accepts(&req));
    let _ = r.sent();
    assert!(r.feed_all(&server_packet(PacketId::SyncNetwork, &[0; 8])).is_empty());
    assert!(r.c.is_ready());
    assert_eq!(r.c.session(), None);
}

#[test]
fn reconnect_after_loss_runs_the_whole_handshake_again() {
    let mut r = Rig::<4096>::with(no_jitter());
    r.ready();
    r.c.transport_lost();
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!((r.c.state(), r.c.failure(), r.c.session()), (ConnectionState::Backoff, Some(Failure::Transport), None));
    assert_eq!(r.c.backoff_ms(), 200, "fast first retry");
    // bytes that trickle in after the drop are discarded
    assert_eq!(r.c.on_bytes(&[1, 2, 3]), 3);
    r.now += 200;
    let req = r.open();
    assert_eq!(r.c.state(), ConnectionState::Retrying);
    r.feed_all(&relay_accepts(&req));
    let _ = r.sent();
    let assigned = [[0x55u8; 16].as_slice(), [2, 0, 0, 0, 0, 1].as_slice()].concat();
    r.feed_all(&server_packet(PacketId::Initialize, &assigned));
    assert!(r.c.is_ready());
    assert_eq!((r.c.retry_count(), r.c.failure()), (0, None));
}

#[test]
fn close_frame_is_echoed_then_dropped() {
    let mut r = Rig::<4096>::with(no_jitter());
    r.ready();
    let mut close = 1001u16.to_be_bytes().to_vec();
    close.extend_from_slice(b"going away");
    assert!(r.feed_all(&raw_frame(OPCODE_CLOSE, &close)).is_empty());
    let echo = r.sent();
    assert_eq!(client_frames(&echo), vec![(OPCODE_CLOSE, 1001u16.to_be_bytes().to_vec())]);
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!(r.c.failure(), Some(Failure::PeerClosed(1001)));
    assert_eq!(r.c.state(), ConnectionState::Backoff);
    // empty close payload: empty echo
    let mut r = Rig::<4096>::with(no_jitter());
    r.ready();
    r.feed_all(&raw_frame(OPCODE_CLOSE, &[]));
    assert_eq!(client_frames(&r.sent()), vec![(OPCODE_CLOSE, vec![])]);
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!(r.c.failure(), Some(Failure::PeerClosed(1005)));
}

#[test]
fn protocol_violations_drop() {
    for bad in [
        vec![0x81, 0x01, b'x'],                                       // text frame
        vec![0x82 | 0x40, 0x00],                                      // reserved bit
        vec![0x82, 0x80, 0, 0, 0, 0],                                 // masked server frame
        raw_frame(OPCODE_BINARY, b"not an ldn packet at all, sorry"), // bad magic
    ] {
        let mut r = Rig::<4096>::with(no_jitter());
        r.ready();
        r.feed_all(&bad);
        assert_eq!(r.on_bytes_rest(), 0);
        assert_eq!(r.poll(), Action::Drop, "{bad:02X?}");
        assert_eq!(r.c.failure(), Some(Failure::Protocol), "{bad:02X?}");
    }
}

impl<const N: usize> Rig<N> {
    /// Stray bytes after a failure are all taken (and ignored).
    fn on_bytes_rest(&mut self) -> usize {
        let used = self.c.on_bytes(&[]);
        assert_eq!(self.c.on_bytes(&[0; 10]), 10);
        used
    }
}

#[test]
fn silence_detection_and_pings_keep_it_alive() {
    let mut r = Rig::<4096>::with(no_jitter());
    r.ready();
    r.now += 29_999;
    assert_eq!(r.poll(), Action::Idle);
    // the relay's ping every 10 s keeps the link alive
    for _ in 0..5 {
        r.now += 10_000;
        r.feed_all(&server_packet(PacketId::Ping, &[0, 1]));
        assert!(matches!(r.poll(), Action::Send(_)));
        assert_eq!(r.poll(), Action::Idle);
    }
    // our own traffic alone also counts (the relay stops pinging a chatty console)
    for _ in 0..5 {
        r.now += 20_000;
        let m = r.mask();
        let mut out = vec![0u8; 100];
        assert!(r.c.send_packet(PacketId::ProxyData, &[1], m, &mut out) > 0);
        assert_eq!(r.poll(), Action::Idle);
    }
    // nothing at all for the timeout
    r.now += 29_999;
    assert_eq!(r.poll(), Action::Idle);
    r.now += 1;
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!((r.c.failure(), r.c.state()), (Some(Failure::Silent), ConnectionState::Backoff));
}

#[test]
fn graceful_close() {
    let mut r = Rig::<4096>::with(no_jitter());
    r.ready();
    r.c.close();
    let first = r.sent();
    assert_eq!(client_packet(&first), (PacketId::Disconnect.raw(), vec![0; 4]));
    assert_eq!(client_frames(&r.sent()), vec![(OPCODE_CLOSE, vec![0x03, 0xE8])]);
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!((r.c.state(), r.c.failure(), r.c.retry_count()), (ConnectionState::Disconnected, None, 0));
    assert_eq!(r.poll(), Action::Idle);

    // close while waiting to retry cancels it
    let mut r = Rig::<4096>::with(no_jitter());
    assert!(r.c.connect(r.now));
    assert_eq!(r.poll(), Action::Open);
    r.c.open_failed();
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!(r.c.state(), ConnectionState::Backoff);
    r.c.close();
    assert_eq!(r.poll(), Action::Drop);
    assert_eq!(r.c.state(), ConnectionState::Disconnected);
    r.now += 100_000;
    assert_eq!(r.poll(), Action::Idle);
}

// ---- buffering ------------------------------------------------------------------------

#[test]
fn oversized_packets_are_skipped_and_full_buffer_drains() {
    let mut r = Rig::<1024>::new();
    r.ready();
    let mut stream = server_packet(PacketId::ProxyData, &[1; 100]);
    stream.extend(server_packet(PacketId::ProxyData, &vec![2; 5000])); // does not fit in 1024
    stream.extend(server_packet(PacketId::ProxyData, &[3; 100]));
    for _ in 0..20 {
        stream.extend(server_packet(PacketId::ScanReply, &[4; 400])); // fills the buffer repeatedly
    }
    // on_bytes takes the whole stream in several rounds as the shell drains
    let got = r.feed_all(&stream);
    assert_eq!(got.len(), 22);
    assert_eq!(got[0], (PacketId::ProxyData, vec![1; 100]));
    assert_eq!(got[1], (PacketId::ProxyData, vec![3; 100]));
    assert!(got[2..].iter().all(|(i, p)| *i == PacketId::ScanReply && *p == vec![4; 400]));
    assert!(r.c.is_ready());
}

#[test]
fn send_packet_frames() {
    let mut r = Rig::<4096>::new();
    let mut out = vec![0u8; 70_000];
    assert_eq!(r.c.send_packet(PacketId::Scan, &[], [1, 2, 3, 4], &mut out), 0, "not open yet");
    r.ready();
    for len in [0usize, 1, 100, 113, 114, 200, 70_000 - 40] {
        let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let n = r.c.send_packet(PacketId::ProxyData, &payload, [0xDE, 0xAD, 0xBE, 0xEF], &mut out);
        assert!(n > 0, "{len}");
        let (t, p) = client_packet(&out[..n]);
        assert_eq!((t, p), (PacketId::ProxyData.raw(), payload));
    }
    // too small / over the protocol maximum
    assert_eq!(r.c.send_packet(PacketId::ProxyData, &[0; 100], [0; 4], &mut out[..50]), 0);
    // relay parsePacket: header + data >= MAX_PACKET_SIZE closes the socket with 1002
    let max = crate::protocol::MAX_PACKET_SIZE - HEADER_SIZE;
    let mut huge = vec![0u8; 140_000];
    assert!(r.c.send_packet(PacketId::ProxyData, &vec![0u8; max - 1], [0; 4], &mut huge) > 0);
    assert_eq!(r.c.send_packet(PacketId::ProxyData, &vec![0u8; max], [0; 4], &mut huge), 0);
    assert_eq!(frame_packet(1, &[], [0; 4], &mut []), 0);
}

// ---- update + remote log over a Conn ----------------------------------------------------

#[test]
fn update_download_through_the_connection() {
    let (rel, pk) = release(200, 10_000, 5_000);
    let mut r = Rig::<8192>::with(no_jitter());
    r.ready();
    let mut dl = UpdateDl::new();
    let check = dl.start(r.now, UpdateChannel::Test, 100, 0, 0, false, "Switch 1234", "v1");
    let m = r.mask();
    let n = r.c.send_packet(PacketId::UpdateCheck, check.as_bytes(), m, &mut r.out);
    let (t, p) = client_packet(&r.out[..n]);
    assert_eq!((t, p.len(), p[8]), (0xC1, 76, 2));
    assert_eq!(p[9], 11);
    assert_eq!(p[10], crate::ident::UPDATE_MODULE_ID);

    // the relay answers with the manifest, then serves chunks
    let mut inbound = server_packet(PacketId::UpdateManifest, &rel.signed);
    let mut staged: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    let mut idx = 0;
    for _ in 0..10_000 {
        for (id, payload) in r.feed_all(&core::mem::take(&mut inbound)) {
            match id {
                PacketId::UpdateManifest => {
                    dl.on_manifest(&payload, &pk);
                }
                PacketId::UpdateChunkData => match dl.on_chunk(r.now, &payload) {
                    Progress::Append { len, .. } | Progress::Complete { len } => {
                        staged[idx].extend_from_slice(&payload[CHUNK_HEADER..CHUNK_HEADER + len]);
                    }
                    p => panic!("{p:?}"),
                },
                other => panic!("{other:?}"),
            }
        }
        r.now += 60;
        match dl.state() {
            State::NeedBegin(_) => dl.begun(0),
            State::NeedVerify(b) => {
                dl.verified(staged[idx].len() as u32 == b.size);
                idx = 1;
            }
            State::NeedInstall => dl.installed(true),
            State::Downloading => {
                if let Some(req) = dl.next_request(r.now) {
                    let m = r.mask();
                    let n = r.c.send_packet(PacketId::UpdateChunk, req.as_bytes(), m, &mut r.out);
                    let (t, p) = client_packet(&r.out[..n]);
                    assert_eq!((t, p.len()), (0xC3, 40));
                    let parsed = <UpdateChunkRequest as zerocopy::FromBytes>::read_from_bytes(&p).unwrap();
                    assert_eq!(parsed, req);
                    // the fake relay answers over the same connection
                    inbound = server_packet(PacketId::UpdateChunkData, &rel.chunk_reply(&parsed));
                }
            }
            _ => break,
        }
        assert_eq!(r.poll(), Action::Idle);
    }
    assert_eq!(dl.state(), State::Staged);
    assert_eq!(staged[0], rel.exefs);
    assert_eq!(staged[1], rel.overlay);
}

#[test]
fn remote_log_flush_through_the_connection() {
    let mut r = Rig::<4096>::new();
    r.ready();
    let mut ring = LogRing::new();
    ring.push("boot");
    ring.push("hello relay");
    let mut rl = RemoteLog::new("Lite 1234");
    let mut payload = [0u8; 2048];
    let n = rl.next_payload(&mut ring, r.now, false, &mut payload).unwrap();
    let m = r.mask();
    let w = r.c.send_packet(PacketId::DebugLog, &payload[..n], m, &mut r.out);
    let (t, p) = client_packet(&r.out[..w]);
    assert_eq!(t, 0xC0);
    assert_eq!(p[0], 9);
    assert_eq!(&p[1..10], b"Lite 1234");
    assert_eq!(&p[10..], b"boot\nhello relay\n");
}

// ---- random input ---------------------------------------------------------------------

#[test]
fn random_bytes_never_panic() {
    let mut x = 0x1234_5678_9ABC_DEF1u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let assigned = [[0x77u8; 16].as_slice(), [2, 0, 0x5E, 9, 9, 9].as_slice()].concat();
    let valid_tail: Vec<u8> = [
        server_packet(PacketId::Initialize, &assigned),
        raw_frame(OPCODE_PING, b"x"),
        server_packet(PacketId::ScanReply, &[1; 50]),
        server_packet(PacketId::Ping, &[0, 3]),
        raw_frame(OPCODE_CLOSE, &[3, 232]),
    ]
    .concat();

    for round in 0..400 {
        let mut r = Rig::<512>::with(no_jitter());
        // start in a random phase
        match round % 4 {
            0 => {}
            1 => {
                r.c.connect(r.now);
                let _ = r.open();
            }
            2 => {
                r.c.connect(r.now);
                let req = r.open();
                r.feed_all(&relay_accepts(&req));
            }
            _ => r.ready(),
        }
        for _ in 0..30 {
            let len = (next() % 700) as usize;
            let mut data: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            match next() % 4 {
                0 => {}
                1 if !data.is_empty() => {
                    // plausible frame heads
                    data[0] = [0x82, 0x81, 0x89, 0x88, 0x8A, 0x02, 0x00][(next() % 7) as usize];
                    if data.len() > 1 {
                        data[1] = (next() % 140) as u8;
                    }
                }
                2 => data.splice(0..0, valid_tail.iter().copied()).for_each(drop),
                _ => data = [raw_frame(OPCODE_BINARY, &data), valid_tail.clone()].concat(),
            }
            // feed in random pieces, draining as a shell would
            let mut rest = &data[..];
            while !rest.is_empty() {
                let take = (1 + (next() as usize % 200)).min(rest.len());
                let used = r.c.on_bytes(&rest[..take]);
                assert!(used <= take);
                rest = &rest[used..];
                let mut guard = 0;
                while let Some((_, p)) = r.c.next_packet() {
                    assert!(p.len() <= 512);
                    guard += 1;
                    assert!(guard < 100);
                }
                if used == 0 && r.c.next_packet().is_none() {
                    break;
                }
            }
            // drive time and actions like a shell
            r.now += next() % 15_000;
            for _ in 0..5 {
                match r.poll() {
                    Action::Open => {
                        if next() % 2 == 0 {
                            r.c.open_failed();
                        } else {
                            let _ = r.open_noasserts();
                        }
                    }
                    Action::Send(n) => assert!(n > 0 && n <= r.out.len()),
                    Action::Drop => {}
                    Action::Idle => break,
                }
            }
            if next() % 7 == 0 {
                r.c.transport_lost();
            }
            if next() % 11 == 0 {
                r.c.connect(r.now);
            }
        }
    }
}

impl<const N: usize> Rig<N> {
    fn open_noasserts(&mut self) -> Option<usize> {
        let mut out = [0u8; handshake::MAX_REQUEST];
        self.c.opened("h", 1, "/", "t", &[7; 16], &mut out).ok()
    }
}

#[test]
fn accept_len_is_28() {
    assert_eq!(ACCEPT_LEN, 28);
}
