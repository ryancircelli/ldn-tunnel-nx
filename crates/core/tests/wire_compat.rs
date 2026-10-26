//! Cross-language wire check against the relay (`relay/test/node-wire.test.ts` is the other half).
//!
//! - `console_bytes`: the exact bytes `Conn` + `Session` + `Router` + `UpdateDl` + `RemoteLog` put on
//!   the wire (upgrade request, then masked frames) must equal `relay/test/wire/console.json`. The
//!   relay test decodes that file with the relay's codec and checks every field.
//! - `relay_bytes`: the frames in `relay/test/wire/relay.json` (encoded by the relay's codec, the
//!   relay test keeps them current) go through `Conn` and the LDN layer; every field is checked here.
//!
//! `WIRE_FIXTURES=write cargo test -p ldn-tunnel-core --test wire_compat` rewrites console.json.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic, clippy::arithmetic_side_effects)]

use std::fmt::Write as _;

use ldn_tunnel_core::conn::handshake;
use ldn_tunnel_core::conn::remote_log::RemoteLog;
use ldn_tunnel_core::conn::update_dl::{Progress, State, UpdateDl, Which};
use ldn_tunnel_core::conn::{Action, Conn, ConnConfig, ConnectionState, Session as ConnSession};
use ldn_tunnel_core::ldn::{Action as LdnAction, LdnError, Session};
use ldn_tunnel_core::ldn_types::CommState;
use ldn_tunnel_core::logring::LogRing;
use ldn_tunnel_core::protocol::{HEADER_SIZE, encode_header};
use ldn_tunnel_core::router::bsd::SOCK_DGRAM;
use ldn_tunnel_core::router::{Decision, Router, SockAddrIn, socket_key};
use ldn_tunnel_core::wire::*;
use ldn_tunnel_core::ws::{OPCODE_BINARY, OPCODE_CLOSE, apply_mask, encode_header as ws_header};
use zerocopy::{FromBytes, FromZeros, IntoBytes};

const PROGRAM_ID: u64 = 0x0100_0000_0000_1234;
const CLIENT_ID: [u8; 16] = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF];
const CLIENT_MAC: [u8; 6] = [2, 0, 0x5E, 0, 0x53, 0x42];
/// The relay test's console token (its SHA-256 is a TOKEN_* binding there).
const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RANDOM: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const IP_A: u32 = 0x0A72_0001;
const IP_B: u32 = 0x0A72_0002;
const MASK: u32 = 0xFFFF_0000;
const SCENE: u16 = 3;
/// What the relay assigns in the Initialize reply (relay.json).
const RELAY_SID: [u8; 16] = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F];
const RELAY_MAC: [u8; 6] = [2, 0, 0x5E, 0, 0, 7];
const FIXTURE_MANIFEST: &[u8] = include_bytes!("../../../tools/release/test/fixture-manifest.bin");
const FIXTURE_PUBKEY: [u8; 65] = *include_bytes!("../../../tools/release/test/fixture-pubkey.bin");

fn fixture(name: &str) -> String {
    format!("{}/../../relay/test/wire/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn mask(k: u8) -> [u8; 4] {
    [0xA0 ^ k, 0x5B, 0xC6 ^ k, 0x0D]
}

fn bytes<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    out[..s.len()].copy_from_slice(s.as_bytes());
    out
}

/// An unmasked server frame (FIN, binary) holding one LDN packet.
fn server_frame(id: PacketId, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; HEADER_SIZE + payload.len()];
    encode_header(&mut p, id.raw(), payload.len() as i32);
    p[HEADER_SIZE..].copy_from_slice(payload);
    let (h, n) = ws_header(OPCODE_BINARY, p.len(), None);
    [&h[..n], &p[..]].concat()
}

/// (opcode, unmasked payload) of one client frame; asserts FIN + mask.
fn client_frame(f: &[u8]) -> (u8, Vec<u8>) {
    assert_eq!(f[0] & 0xF0, 0x80, "FIN, no RSV bits");
    assert_eq!(f[1] & 0x80, 0x80, "masked");
    let (len, at) = match f[1] & 0x7F {
        126 => (u16::from_be_bytes([f[2], f[3]]) as usize, 4),
        127 => (u64::from_be_bytes(f[2..10].try_into().unwrap()) as usize, 10),
        n => (n as usize, 2),
    };
    let key: [u8; 4] = f[at..at + 4].try_into().unwrap();
    assert_eq!(f.len(), at + 4 + len, "one frame");
    let mut p = f[at + 4..].to_vec();
    apply_mask(&mut p, &key);
    (f[0] & 0x0F, p)
}

fn sends(s: &mut Session) -> Vec<(PacketId, Vec<u8>)> {
    let mut out = vec![];
    while let Some(a) = s.next_action() {
        if let LdnAction::Send { id, payload } = a {
            out.push((id, payload.to_vec()));
        }
    }
    out
}

fn drain(s: &mut Session) -> Vec<LdnAction> {
    std::iter::from_fn(|| s.next_action()).collect()
}

/// A Conn that has sent its upgrade request and Initialize; returns (conn, request, Initialize frame).
fn handshaking() -> (Box<Conn<16384>>, Vec<u8>, Vec<u8>) {
    let mut c = Box::new(Conn::<16384>::new(ConnConfig::new(CLIENT_ID, CLIENT_MAC)));
    let mut out = vec![0u8; 4096];
    assert!(c.connect(0));
    assert_eq!(c.poll(0, mask(0), &mut out), Action::Open);
    let n = c.opened("relay.example.com", 443, "/ldn", TOKEN, &RANDOM, &mut out).unwrap();
    let request = out[..n].to_vec();
    let accept = handshake::compute_accept(&handshake::encode_key(&RANDOM));
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        core::str::from_utf8(&accept).unwrap()
    );
    assert_eq!(c.on_bytes(resp.as_bytes()), resp.len());
    let Action::Send(n) = c.poll(1, mask(1), &mut out) else { panic!("Initialize") };
    assert_eq!(c.state(), ConnectionState::Handshaking);
    (c, request, out[..n].to_vec())
}

fn security() -> SecurityConfig {
    let mut s = SecurityConfig::new_zeroed();
    s.security_mode = 1;
    s
}

fn user(name: &str) -> UserConfig {
    let mut u = UserConfig::new_zeroed();
    u.user_name[..name.len()].copy_from_slice(name.as_bytes());
    u
}

/// A Session whose link is up (as the shell wires it after `Conn` is Ready).
fn linked_session(station: bool) -> Box<Session> {
    let mut s = Box::new(Session::new(PROGRAM_ID));
    s.initialize().unwrap();
    if station { s.open_station(0).unwrap() } else { s.open_access_point(0).unwrap() };
    s.on_relay_ready(0, RELAY_SID, RELAY_MAC);
    drain(&mut s);
    s
}

/// The NetworkInfo the relay test encodes (node-wire.test.ts `NI`), every field set.
fn network_info() -> NetworkInfo {
    let mut n = NetworkInfo::new_zeroed();
    n.network_id.intent_id = IntentId { local_communication_id: PROGRAM_ID as i64, reserved1: 0x1111, scene_id: SCENE, reserved2: 0x2222_2222 };
    n.network_id.session_id = SessionId { data: core::array::from_fn(|i| 0xA0 + i as u8) };
    n.common = CommonNetworkInfo {
        mac_address: MacAddress { data: [2, 0, 0x5E, 0, 0, 1] },
        ssid: Ssid { length: 32, name: bytes("12345678123456781234567812345678") },
        channel: 6,
        link_level: 3,
        network_type: 2,
        reserved: 0x3333_3333,
    };
    let node = |ip, last, id, name| NodeInfo {
        ipv4_address: ip,
        mac_address: MacAddress { data: [2, 0, 0x5E, 0, 0, last] },
        node_id: id,
        is_connected: 1,
        user_name: bytes(name),
        reserved1: 0x66,
        local_communication_version: 1,
        reserved2: [0x77; 16],
    };
    let mut nodes = [NodeInfo::new_zeroed(); MAX_NODES];
    nodes[0] = node(IP_A, 1, 0, "alice");
    nodes[1] = node(IP_B, 2, 1, "bob");
    let mut advertise_data = [0u8; 384];
    advertise_data[..4].copy_from_slice(&[1, 2, 3, 4]);
    n.ldn = LdnNetworkInfo {
        security_parameter: core::array::from_fn(|i| 0x10 + i as u8),
        security_mode: 1,
        station_accept_policy: 0,
        unknown1: 0x44,
        reserved1: 0x5555,
        node_count_max: 8,
        node_count: 2,
        nodes,
        reserved2: 0x8888,
        advertise_data_size: 4,
        advertise_data,
        unknown2: [0x99; 140],
        authentication_id: 0x0123_4567_89AB_CDEF,
    };
    n
}

/// Everything the console sends, in order: (name, bytes on the wire).
fn console_stream() -> Vec<(&'static str, Vec<u8>)> {
    let (mut c, request, init) = handshaking();
    let mut frames = vec![("Upgrade", request), ("Initialize", init)];
    let reply = InitializeMessage { id: SessionId { data: RELAY_SID }, mac_address: MacAddress { data: RELAY_MAC } };
    c.on_bytes(&server_frame(PacketId::Initialize, reply.as_bytes()));
    assert!(c.next_packet().is_none());
    assert!(c.is_ready());
    let mut out = vec![0u8; 4096];
    let mut k = 2u8;
    let mut tx = |c: &mut Conn<16384>, frames: &mut Vec<(&'static str, Vec<u8>)>, name, id: PacketId, payload: &[u8]| {
        let n = c.send_packet(id, payload, mask(k), &mut out);
        assert!(n > 0, "{name}");
        frames.push((name, out[..n].to_vec()));
        k += 1;
    };

    // Host: CreateAccessPoint (with advertise data), then room-only requests, then leave.
    let mut h = linked_session(false);
    h.set_advertise_data(&[1, 2, 3, 4]);
    let mut net = NetworkConfig::new_zeroed();
    net.intent_id.local_communication_id = -1; // the SDK's "use the program id"
    net.intent_id.scene_id = SCENE;
    net.channel = 6;
    net.node_count_max = 8;
    net.local_communication_version = 1;
    let _p = h.create_network(&security(), &user("alice"), &net, 0).unwrap();
    let [(id, p)] = &sends(&mut h)[..] else { panic!() };
    tx(&mut c, &mut frames, "CreateAccessPoint", *id, p);
    h.on_packet(PacketId::Connected.raw(), network_info().as_bytes(), 0);
    assert_eq!(h.state(), CommState::AccessPointCreated);
    drain(&mut h);
    h.set_station_accept_policy(AcceptPolicy::RejectAll.raw());
    h.set_advertise_data(&[5, 6, 7]);
    let _p = h.reject(1, 0).unwrap();
    for (name, (id, p)) in ["SetAcceptPolicy", "SetAdvertiseData", "Reject"].into_iter().zip(sends(&mut h)) {
        tx(&mut c, &mut frames, name, id, &p);
    }
    h.destroy_network(0).unwrap();
    let [(id, p)] = &sends(&mut h)[..] else { panic!() };
    tx(&mut c, &mut frames, "Disconnect", *id, p);

    // Station: Scan, Connect to the result, ProxyData, leave.
    let mut s = linked_session(true);
    let mut f = ScanFilterFull::new_zeroed();
    f.network_id.intent_id.local_communication_id = -1;
    f.network_id.intent_id.scene_id = SCENE;
    f.network_type = 2;
    let _p = s.scan(&f, 0).unwrap();
    let [(id, p)] = &sends(&mut s)[..] else { panic!() };
    tx(&mut c, &mut frames, "Scan", *id, p);
    let mut found = network_info();
    found.ldn.node_count = 1;
    found.ldn.nodes[1] = NodeInfo::new_zeroed();
    s.on_packet(PacketId::ScanReply.raw(), found.as_bytes(), 0);
    s.on_packet(PacketId::ScanReplyEnd.raw(), &[], 0);
    drain(&mut s);
    let net = s.scan_results()[0];
    let _p = s.connect(&security(), &user("bob"), 1, 0, &net, 0).unwrap();
    let [(id, p)] = &sends(&mut s)[..] else { panic!() };
    tx(&mut c, &mut frames, "Connect", *id, p);

    let mut r = Box::new(Router::new());
    let key = socket_key(1, 5);
    r.set_proxy_config(IP_B, MASK);
    assert!(r.on_socket(key, 2, SOCK_DGRAM, 0));
    assert_eq!(r.on_bind(key, &SockAddrIn::from_ryujinx(0, 1234), false), Decision::ReplyAndForward(0));
    let Decision::Emit { header, payload } = r.on_sendto(key, b"hello", Some(&SockAddrIn::from_ryujinx(IP_A, 5678))) else {
        panic!("emit")
    };
    tx(&mut c, &mut frames, "ProxyData", PacketId::ProxyData, &[header.as_bytes(), payload].concat());

    // Update check (module id 1) and a remote log flush.
    let mut dl = UpdateDl::new();
    let req = dl.start(0, UpdateChannel::Test, 1, 7, 0, false, "Switch 1234", "v0.1.0-3-gabcdef0");
    tx(&mut c, &mut frames, "UpdateCheck", PacketId::UpdateCheck, req.as_bytes());
    let mut ring = LogRing::new();
    ring.push("hello");
    ring.push("world");
    let mut buf = [0u8; 2048];
    let n = RemoteLog::new("Switch 1234").next_payload(&mut ring, 0, true, &mut buf).unwrap();
    tx(&mut c, &mut frames, "DebugLog", PacketId::DebugLog, &buf[..n]);

    // The relay's ping, echoed by Conn; then a graceful close: Disconnect + Close(1000).
    c.on_bytes(&server_frame(PacketId::Ping, &[0, 7]));
    assert!(c.next_packet().is_none());
    for (t, name) in [(2, "PingEcho"), (3, "CloseDisconnect"), (4, "Close")] {
        if t == 3 {
            c.close();
        }
        let Action::Send(n) = c.poll(2, mask(k), &mut out) else { panic!("{name}") };
        frames.push((name, out[..n].to_vec()));
        k += 1;
    }
    assert_eq!(c.poll(3, mask(k), &mut out), Action::Drop);
    frames
}

fn console_json() -> String {
    let key = handshake::encode_key(&RANDOM);
    let accept = handshake::compute_accept(&key);
    let mut s = String::from("{\n");
    writeln!(s, "  \"key\": \"{}\",", core::str::from_utf8(&key).unwrap()).unwrap();
    writeln!(s, "  \"accept\": \"{}\",", core::str::from_utf8(&accept).unwrap()).unwrap();
    s.push_str("  \"frames\": [\n");
    let frames = console_stream();
    for (i, (name, b)) in frames.iter().enumerate() {
        let comma = if i + 1 < frames.len() { "," } else { "" };
        writeln!(s, "    {{\"name\": \"{name}\", \"hex\": \"{}\"}}{comma}", hex(b)).unwrap();
    }
    s.push_str("  ]\n}\n");
    s
}

#[test]
fn console_bytes() {
    let json = console_json();
    let path = fixture("console.json");
    if std::env::var("WIRE_FIXTURES").as_deref() == Ok("write") {
        std::fs::write(&path, &json).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap();
    assert!(committed == json, "{path} is stale: WIRE_FIXTURES=write cargo test --test wire_compat, then rerun the relay tests");

    // Our own reading of a few frames, so a regression shows here first.
    let frames = console_stream();
    let get = |n: &str| frames.iter().find(|f| f.0 == n).unwrap().1.clone();
    let (op, p) = client_frame(&get("Close"));
    assert_eq!((op, p), (OPCODE_CLOSE, vec![0x03, 0xE8]));
    let (op, p) = client_frame(&get("UpdateCheck"));
    assert_eq!(op, OPCODE_BINARY);
    let r = UpdateCheckRequest::read_from_bytes(&p[HEADER_SIZE..]).unwrap();
    assert_eq!(r.reserved, [1, 0], "module id 1");
    let (_, p) = client_frame(&get("Initialize"));
    assert_eq!(&p[HEADER_SIZE..], [CLIENT_ID.as_slice(), CLIENT_MAC.as_slice()].concat());
    assert!(!frames.iter().any(|(_, f)| f.len() > 1 && f[0] == 0x80 | PacketId::Passphrase.raw()), "no Passphrase");
}

/// (name, frame) entries of relay.json.
fn relay_frames() -> Vec<(String, Vec<u8>)> {
    let json = std::fs::read_to_string(fixture("relay.json")).unwrap();
    json.lines()
        .filter(|l| l.contains("\"hex\""))
        .map(|l| {
            let field = |k: &str| l.split(&format!("\"{k}\": \"")).nth(1).unwrap().split('"').next().unwrap().to_string();
            (field("name"), unhex(&field("hex")))
        })
        .collect()
}

#[test]
fn relay_bytes() {
    let frames = relay_frames();
    let names: Vec<&str> = frames.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(
        names,
        [
            "Initialize", "Ping", "ProxyConfig", "Connected", "SyncNetwork", "ScanReply", "ScanReplyEnd", "ProxyData",
            "NetworkError", "RejectReply", "Disconnect", "UpdateManifest", "UpdateManifestEmpty", "UpdateChunkData",
        ]
    );
    let stream: Vec<u8> = frames.iter().flat_map(|f| f.1.clone()).collect();

    // Whole, in 1-byte reads and in 7-byte reads: Conn hands out the same packets.
    for chunk in [stream.len(), 1, 7] {
        let (mut c, _, _) = handshaking();
        let mut got: Vec<(PacketId, Vec<u8>)> = vec![];
        for part in stream.chunks(chunk) {
            let mut rest = part;
            while !rest.is_empty() {
                let used = c.on_bytes(rest);
                rest = &rest[used..];
                while let Some((id, p)) = c.next_packet() {
                    got.push((id, p.to_vec()));
                }
            }
        }
        assert!(c.is_ready(), "the Initialize reply finished the handshake");
        assert_eq!(c.session(), Some(&ConnSession { id: RELAY_SID, mac: RELAY_MAC }));
        let mut out = vec![0u8; 256];
        let Action::Send(n) = c.poll(5, mask(9), &mut out) else { panic!("ping echo") };
        let (_, echo) = client_frame(&out[..n]);
        assert_eq!((echo[4], &echo[HEADER_SIZE..]), (PacketId::Ping.raw(), &[0u8, 7][..]), "Ping echoed");
        // Ping and Initialize stay in Conn; the rest arrives in order with the relay's payload bytes.
        let want: Vec<(PacketId, Vec<u8>)> = frames[2..]
            .iter()
            .map(|(_, f)| {
                let (h, n) = match f[1] {
                    126 => (4, u16::from_be_bytes([f[2], f[3]]) as usize),
                    127 => (10, u64::from_be_bytes(f[2..10].try_into().unwrap()) as usize),
                    n => (2, n as usize),
                };
                assert_eq!((f[0], f.len()), (0x82, h + n), "FIN binary, unmasked, one frame");
                (PacketId::from_raw(f[h + 4]).unwrap(), f[h + HEADER_SIZE..].to_vec())
            })
            .collect();
        assert_eq!(got, want, "chunk {chunk}");
    }

    // Every field, as the Rust structs read them.
    let payload = |name: &str| {
        let f = &frames.iter().find(|f| f.0 == name).unwrap().1;
        let h = match f[1] {
            126 => 4,
            127 => 10,
            _ => 2,
        };
        f[h + HEADER_SIZE..].to_vec()
    };
    assert_eq!(
        InitializeMessage::read_from_bytes(&payload("Initialize")).unwrap(),
        InitializeMessage { id: SessionId { data: RELAY_SID }, mac_address: MacAddress { data: RELAY_MAC } }
    );
    assert_eq!(PingMessage::read_from_bytes(&payload("Ping")).unwrap(), PingMessage { requester: 0, id: 7 });
    assert_eq!(ProxyConfig::read_from_bytes(&payload("ProxyConfig")).unwrap(), ProxyConfig { proxy_ip: IP_B, proxy_subnet_mask: MASK });
    for n in ["Connected", "SyncNetwork", "ScanReply"] {
        assert_eq!(NetworkInfo::read_from_bytes(&payload(n)).unwrap(), network_info(), "{n}");
    }
    assert!(payload("ScanReplyEnd").is_empty() && payload("RejectReply").is_empty() && payload("UpdateManifestEmpty").is_empty());
    let pd = payload("ProxyData");
    let (h, data) = ProxyDataHeader::read_from_prefix(&pd).unwrap();
    let info = ProxyInfo { source_ipv4: IP_A, source_port: 5678, dest_ipv4: IP_B, dest_port: 1234, protocol: ProtocolType::Udp.raw() };
    assert_eq!((h, data), (ProxyDataHeader { info, data_length: 5 }, &b"howdy"[..]));
    let code = NetworkErrorMessage::read_from_bytes(&payload("NetworkError")).unwrap().error_code;
    assert_eq!(NetworkErrorCode::from_raw(code), Some(NetworkErrorCode::TooManyPlayers));
    assert_eq!(DisconnectMessage::read_from_bytes(&payload("Disconnect")).unwrap(), DisconnectMessage { disconnect_ip: 0 });
    assert_eq!(payload("UpdateManifest"), FIXTURE_MANIFEST);
    let m = SignedManifest::read_from_bytes(FIXTURE_MANIFEST).unwrap().manifest;
    let cd = payload("UpdateChunkData");
    let (ch, data) = UpdateChunkHeader::read_from_prefix(&cd).unwrap();
    assert_eq!(ch, UpdateChunkHeader { sha256: m.exefs_sha256, offset: 0, total_size: m.exefs_size });
    assert_eq!(data, (0..m.exefs_size as u8).collect::<Vec<u8>>());

    // What the LDN layer makes of them.
    let mut h = linked_session(false);
    let _p = h.create_network(&security(), &user("alice"), &NetworkConfig { node_count_max: 8, ..NetworkConfig::new_zeroed() }, 0).unwrap();
    drain(&mut h);
    h.on_packet(PacketId::ProxyConfig.raw(), &payload("ProxyConfig"), 0);
    h.on_packet(PacketId::Connected.raw(), &payload("Connected"), 0);
    let acts = drain(&mut h);
    assert!(acts.contains(&LdnAction::ProxyConfig { ip: IP_B, mask: MASK }));
    assert_eq!(h.take_reply(), Some(Ok(())));
    assert_eq!((h.state(), h.get_ipv4_address()), (CommState::AccessPointCreated, Some((IP_B, MASK))));
    assert_eq!(*h.network_info(), network_info());
    let mut changed = network_info();
    changed.ldn.node_count = 1;
    changed.ldn.nodes[1].is_connected = 0;
    h.on_packet(PacketId::SyncNetwork.raw(), changed.as_bytes(), 0);
    assert_eq!(*h.network_info(), changed);
    assert_eq!(
        h.on_packet(PacketId::ProxyData.raw(), &pd, 0).map(|d| (d.info, d.payload.to_vec())),
        Some((info, b"howdy".to_vec()))
    );
    let _p = h.reject(1, 0).unwrap();
    drain(&mut h);
    h.on_packet(PacketId::RejectReply.raw(), &payload("RejectReply"), 0);
    assert_eq!(h.take_reply(), Some(Ok(())));
    h.on_packet(PacketId::Disconnect.raw(), &payload("Disconnect"), 0);
    assert_eq!(h.state(), CommState::AccessPoint, "the room is gone");

    let mut s = linked_session(true);
    let mut f = ScanFilterFull::new_zeroed();
    f.network_id.intent_id.scene_id = SCENE;
    let _p = s.scan(&f, 0).unwrap();
    drain(&mut s);
    s.on_packet(PacketId::ScanReply.raw(), &payload("ScanReply"), 0);
    s.on_packet(PacketId::ScanReplyEnd.raw(), &payload("ScanReplyEnd"), 0);
    drain(&mut s);
    assert_eq!(s.take_reply(), Some(Ok(())));
    assert_eq!(s.scan_results(), [network_info()]);
    let net = s.scan_results()[0];
    let _p = s.connect(&security(), &user("bob"), 1, 0, &net, 0).unwrap();
    drain(&mut s);
    s.on_packet(PacketId::NetworkError.raw(), &payload("NetworkError"), 0);
    drain(&mut s);
    assert_eq!(s.take_reply(), Some(Err(LdnError::TooManyPlayers)));

    let mut dl = UpdateDl::new();
    let _ = dl.start(0, UpdateChannel::Test, 1, 0, 0, false, "x", "v");
    assert_eq!(dl.on_manifest(&payload("UpdateManifestEmpty"), &FIXTURE_PUBKEY), State::NoRelease);
    let _ = dl.start(0, UpdateChannel::Test, 1, 0, 0, false, "x", "v");
    let State::NeedBegin(b) = dl.on_manifest(&payload("UpdateManifest"), &FIXTURE_PUBKEY) else { panic!("manifest refused") };
    assert_eq!((b.which, b.sha256, b.size), (Which::Exefs, m.exefs_sha256, m.exefs_size));
    dl.begun(0);
    let req = dl.next_request(0).unwrap();
    assert_eq!((req.sha256, req.offset, req.length), (m.exefs_sha256, 0, m.exefs_size));
    assert_eq!(dl.on_chunk(0, &cd), Progress::Complete { len: m.exefs_size as usize });
}
