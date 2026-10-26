//! End-to-end host simulation: two consoles (`Conn` + `Session` + `Router`, wired as the shell
//! wires them) against a fake relay that answers like `relay/src/core/relay.ts`.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

#[path = "sim/mod.rs"]
mod world;

use ldn_tunnel_core::conn::ConnectionState;
use ldn_tunnel_core::ldn::LdnError;
use ldn_tunnel_core::ldn_types::{CommState, NodeStateChange};
use ldn_tunnel_core::wire::*;
use world::console::PROGRAM_ID;
use world::{World, relay::BROADCAST};
use zerocopy::{FromBytes, FromZeros};

const A: usize = 0;
const B: usize = 1;
const IP_A: u32 = 0x0A72_0001;
const IP_B: u32 = 0x0A72_0002;
const SCENE: u16 = 3;
const VERSION: u16 = 1;

fn user(name: &str) -> UserConfig {
    let mut u = UserConfig::new_zeroed();
    u.user_name[..name.len()].copy_from_slice(name.as_bytes());
    u
}

fn network_config(max: u8) -> NetworkConfig {
    let mut c = NetworkConfig::new_zeroed();
    c.intent_id.local_communication_id = -1; // the SDK fills in the NACP value
    c.intent_id.scene_id = SCENE;
    c.channel = 6;
    c.node_count_max = max;
    c.local_communication_version = VERSION;
    c
}

fn host(w: &mut World, max: u8) {
    host_on(w, A, max);
}

fn host_on(w: &mut World, i: usize, max: u8) {
    let now = w.now;
    let s = &mut w.c[i].session;
    s.initialize().unwrap();
    s.open_access_point(now).unwrap();
    let _p = s.create_network(&SecurityConfig::new_zeroed(), &user("alice"), &network_config(max), now).unwrap();
    assert_eq!(w.wait(i), Ok(()));
}

fn scan(w: &mut World, i: usize) -> usize {
    let now = w.now;
    let mut f = ScanFilterFull::new_zeroed();
    f.network_id.intent_id.scene_id = SCENE;
    let _p = w.c[i].session.scan(&f, now).unwrap();
    assert_eq!(w.wait(i), Ok(()));
    w.c[i].session.scan_results().len()
}

fn connect_with(w: &mut World, i: usize, version: u32) -> Result<(), LdnError> {
    let now = w.now;
    let net = w.c[i].session.scan_results()[0];
    let _p = w.c[i]
        .session
        .connect(&SecurityConfig::new_zeroed(), &user("bob"), version, 0, &net, now)
        .unwrap();
    w.wait(i)
}

fn join(w: &mut World, i: usize) {
    let now = w.now;
    w.c[i].session.initialize().unwrap();
    w.c[i].session.open_station(now).unwrap();
    assert_eq!(scan(w, i), 1);
    assert_eq!(connect_with(w, i, u32::from(VERSION)), Ok(()));
}

fn node_ips(s: &ldn_tunnel_core::ldn::Session) -> Vec<u32> {
    let info = s.network_info();
    let nodes = info.ldn.nodes;
    nodes.iter().filter(|n| n.is_connected != 0).map(|n| n.ipv4_address).collect()
}

fn types(w: &World, link: usize) -> Vec<(u8, usize)> {
    w.relay.packets(link).iter().map(|r| (r.type_, r.payload.len())).collect()
}

/// Scenario 1.
#[test]
fn host_creates_a_network() {
    let mut w = World::new();
    host(&mut w, 8);
    let s = &w.c[A].session;
    assert_eq!(s.state(), CommState::AccessPointCreated);
    assert_eq!(node_ips(s), [IP_A]);
    let info = s.network_info();
    let (count, max) = (info.ldn.node_count, info.ldn.node_count_max);
    assert_eq!((count, max), (1, 8));
    assert_eq!(s.local_node_id(), 0);
    assert_eq!(s.get_ipv4_address(), Some((IP_A, 0xFFFF_0000)));
    assert_eq!(w.c[A].router.local_ip(), IP_A);

    // Exactly these packets, with these sizes (wire.rs): Initialize 22, CreateAccessPoint 188.
    // No Passphrase and no second Initialize: Conn does the handshake.
    assert_eq!(types(&w, 0), [(0, 22), (2, 188)]);
    let pk = w.relay.packets(0);
    assert_eq!(pk[0].payload, [w.c[A].client_id.as_slice(), w.c[A].mac.as_slice()].concat());
    let req = &pk[1].payload;
    assert_eq!(&req[68..73], b"alice"); // UserConfig after SecurityConfig(68)
    // NetworkConfig at 116: local_communication_id (program id, not -1), scene at +10, max at +18
    assert_eq!(i64::from_le_bytes(req[116..124].try_into().unwrap()), PROGRAM_ID as i64);
    assert_eq!(u16::from_le_bytes(req[126..128].try_into().unwrap()), SCENE);
    assert_eq!(req[134], 8);
    assert!(w.c[A].state_changes > 0);
}

/// Scenarios 2 and 3.
#[test]
fn guest_joins_and_traffic_flows() {
    let mut w = World::new();
    host(&mut w, 8);
    w.c[A].session.get_network_info_latest_update(8); // the game polled once while hosting
    let (a, b) = (A, B);
    // 2: scan, connect
    w.c[b].session.initialize().unwrap();
    let now = w.now;
    w.c[b].session.open_station(now).unwrap();
    assert_eq!(scan(&mut w, b), 1);
    let found = w.c[b].session.scan_results()[0];
    assert_eq!(found.ldn.node_count, 1);
    let scene = found.network_id.intent_id.scene_id;
    assert_eq!(scene, SCENE);
    assert_eq!(connect_with(&mut w, b, u32::from(VERSION)), Ok(()));

    assert_eq!(w.c[b].session.state(), CommState::StationConnected);
    assert_eq!(node_ips(&w.c[b].session), [IP_A, IP_B]);
    assert_eq!(node_ips(&w.c[a].session), [IP_A, IP_B], "SyncNetwork reached the host");
    assert_eq!(w.c[b].session.local_node_id(), 1);
    assert_eq!(w.c[b].session.get_ipv4_address(), Some((IP_B, 0xFFFF_0000)));
    assert_eq!(w.c[b].router.local_ip(), IP_B);
    assert_eq!(w.c[a].session.get_network_info_latest_update(8)[1], NodeStateChange::Connect);

    // B's bytes on the wire: Initialize 22, Scan 96, Connect 1280 (ConnectRequest).
    assert_eq!(types(&w, 1), [(0, 22), (10, 96), (13, 1280)]);
    let conn = &w.relay.packets(1)[2].payload;
    assert_eq!(&conn[68..71], b"bob");
    assert_eq!(u32::from_le_bytes(conn[116..120].try_into().unwrap()), u32::from(VERSION));
    let sid = w.c[a].session.network_info().network_id.session_id;
    assert_eq!(conn[128 + 16..128 + 32], sid.data); // ConnectRequest.network_info.network_id.session_id

    // 3: UDP 1234 both ways
    for (c, fd) in [(a, 5), (b, 7)] {
        w.c[c].socket(fd);
        w.c[c].bind(fd, 1234);
    }
    let n = w.c[b].sendto(&mut w.relay, 7, b"hello", IP_A, 1234);
    assert_eq!(n, 5);
    w.pump();
    let (data, from) = w.c[a].recvfrom(5).expect("A got the datagram");
    assert_eq!(data, b"hello");
    assert_eq!((from.addr_ryujinx(), from.port()), (IP_B, 1234));
    assert!(w.c[b].recvfrom(7).is_none(), "unicast does not echo");
    // exact bytes: ProxyDataHeader (20) + 5; source = B's IP, dest = A's
    let sent = w.relay.log.last().unwrap();
    assert_eq!((sent.link, sent.type_, sent.payload.len()), (1, PacketId::ProxyData.raw(), 25));
    assert_eq!(u32::from_le_bytes(sent.payload[0..4].try_into().unwrap()), IP_B);
    assert_eq!(u32::from_le_bytes(sent.payload[6..10].try_into().unwrap()), IP_A);
    assert_eq!(u32::from_le_bytes(sent.payload[12..16].try_into().unwrap()), 17);
    assert_eq!(u32::from_le_bytes(sent.payload[16..20].try_into().unwrap()), 5);
    assert_eq!(&sent.payload[20..], b"hello");

    // broadcast from A reaches B (and, as in the C# relay, A itself)
    assert_eq!(w.c[a].sendto(&mut w.relay, 5, b"all", BROADCAST, 1234), 3);
    w.pump();
    let (data, from) = w.c[b].recvfrom(7).expect("B got the broadcast");
    assert_eq!((data.as_slice(), from.addr_ryujinx()), (&b"all"[..], IP_A));
    assert_eq!(w.c[a].recvfrom(5).map(|(d, _)| d), Some(b"all".to_vec()));
}

/// Scenario 4.
#[test]
fn guest_leaves_and_host_destroys() {
    let mut w = World::new();
    host(&mut w, 8);
    join(&mut w, B);
    w.c[A].session.get_network_info_latest_update(8);

    let now = w.now;
    w.c[B].session.disconnect(now).unwrap();
    w.pump();
    assert_eq!(w.c[B].session.state(), CommState::Station);
    assert_eq!(node_ips(&w.c[A].session), [IP_A]);
    assert_eq!(w.c[A].session.get_network_info_latest_update(8)[1], NodeStateChange::Disconnect);
    assert_eq!(*types(&w, 1).last().unwrap(), (PacketId::Disconnect.raw(), 4));
    assert_eq!(w.relay.game_count(), 1);

    w.c[A].session.destroy_network(now).unwrap();
    w.pump();
    assert_eq!(w.c[A].session.state(), CommState::AccessPoint);
    assert_eq!(*types(&w, 0).last().unwrap(), (PacketId::Disconnect.raw(), 4));
    assert_eq!(w.relay.game_count(), 0);

    // 6 s after leaving a room the idle timeout closes the link: Disconnect + Close, no retry
    w.advance(6100);
    w.advance(100);
    assert_eq!(w.c[A].conn.state(), ConnectionState::Disconnected);
    assert_eq!(w.c[A].link, None);
    assert_eq!(w.c[A].router.local_ip(), 0);
}

/// Scenario 5.
#[test]
fn link_loss_then_rejoin() {
    let mut w = World::new();
    host(&mut w, 8);
    join(&mut w, B);
    w.c[B].socket(7);
    w.c[B].bind(7, 1234);
    assert_eq!(w.c[B].router.proxy_count(), 1);

    // the transport under B breaks
    let link = w.c[B].link.unwrap();
    w.relay.close(link);
    w.c[B].conn.transport_lost();
    w.pump();
    assert_eq!(w.c[B].session.state(), CommState::Station, "the room is gone");
    assert_eq!(w.c[B].session.get_disconnect_reason(), ldn_tunnel_core::ldn::DisconnectReason::DestroyedByUser);
    assert!(node_ips(&w.c[B].session).is_empty());
    assert_eq!(w.c[B].router.local_ip(), 0);
    assert_eq!(w.c[B].router.proxy_count(), 0);
    assert_eq!(w.c[B].conn.state(), ConnectionState::Backoff);
    assert_eq!(w.c[B].conn.retry_count(), 1);
    assert_eq!(node_ips(&w.c[A].session), [IP_A], "the host saw B leave");

    // the Conn reconnects by itself after its backoff
    let wait = u64::from(w.c[B].conn.backoff_ms());
    w.advance(wait.saturating_sub(1));
    assert_eq!(w.c[B].conn.state(), ConnectionState::Backoff);
    for _ in 0..50 {
        if w.c[B].conn.is_ready() {
            break;
        }
        w.advance(50);
    }
    assert!(w.c[B].conn.is_ready());
    assert_eq!(w.c[B].conn.retry_count(), 0);

    // and B joins again: same node slot, but the relay's DHCP has moved on (dhcp.ts cycles)
    assert_eq!(scan(&mut w, B), 1);
    assert_eq!(connect_with(&mut w, B, u32::from(VERSION)), Ok(()));
    assert_eq!(node_ips(&w.c[B].session), [IP_A, IP_B + 1]);
    assert_eq!(node_ips(&w.c[A].session), [IP_A, IP_B + 1]);
    assert_eq!(w.c[B].session.local_node_id(), 1);
    assert_eq!(w.c[B].router.local_ip(), IP_B + 1);
}

/// Scenario 6.
#[test]
fn connect_errors_map_to_ldn_errors() {
    use NetworkErrorCode as E;
    let mut w = World::new();
    host(&mut w, 1); // room for the host only
    w.c[B].session.initialize().unwrap();
    let now = w.now;
    w.c[B].session.open_station(now).unwrap();
    assert_eq!(scan(&mut w, B), 1);

    assert_eq!(connect_with(&mut w, B, 1), Err(LdnError::TooManyPlayers));
    assert_eq!(w.c[B].session.state(), CommState::Station, "state reverted");
    assert_eq!(connect_with(&mut w, B, 0), Err(LdnError::VersionTooLow));
    assert_eq!(connect_with(&mut w, B, 2), Err(LdnError::VersionTooHigh));
    for (code, want) in [
        (E::ConnectRejected, LdnError::ConnectRejected),
        (E::ConnectNotFound, LdnError::ConnectNotFound),
        (E::ConnectFailure, LdnError::ConnectFailure),
        (E::ConnectTimeout, LdnError::ConnectTimeout),
    ] {
        w.relay.force_connect_error = Some(code);
        assert_eq!(connect_with(&mut w, B, 1), Err(want), "{code:?}");
        assert_eq!(w.c[B].session.state(), CommState::Station);
    }
    // the same link kept working throughout: one Initialize
    assert_eq!(types(&w, 1).iter().filter(|t| t.0 == 0).count(), 1);
    assert_eq!(w.c[B].conn.retry_count(), 0);
}

// ---- real-play scenarios (MK8D-like) ----------------------------------------------------

use ldn_tunnel_core::ldn::{DisconnectReason, Session};
use ldn_tunnel_core::ldn_types::scan_filter_flag as flag;
use ldn_tunnel_core::notify::{Event, LdnMode, Notifier, NotifyConfig};
use ldn_tunnel_core::router::bsd::{FIONREAD, MSG_DONTWAIT, MSG_PEEK};
use ldn_tunnel_core::router::{PollState, RecvDecision, socket_key};

/// MK8D binds every console's game socket on 0.0.0.0:12345.
const PORT: u16 = 12345;

fn ip(n: u32) -> u32 {
    world::relay::NETWORK_BASE + n
}

/// Scan with the game's own filter; returns the rooms found.
fn scan_with(w: &mut World, i: usize, f: &ScanFilterFull) -> Vec<NetworkInfo> {
    let now = w.now;
    let _p = w.c[i].session.scan(f, now).unwrap();
    assert_eq!(w.wait(i), Ok(()));
    w.c[i].session.scan_results().to_vec()
}

fn filter(flags: u32) -> ScanFilterFull {
    let mut f = ScanFilterFull::new_zeroed();
    f.flag = flags;
    f.network_id.intent_id.local_communication_id = PROGRAM_ID as i64;
    f.network_id.intent_id.scene_id = SCENE;
    f.network_type = 2;
    f
}

/// Bind the race socket on every console in `who`.
fn bind_all(w: &mut World, who: &[usize]) {
    for &i in who {
        w.c[i].socket(9);
        w.c[i].bind(9, PORT);
    }
}

fn recv(w: &mut World, i: usize, buf: &mut [u8], flags: i32) -> RecvDecision {
    w.c[i].router.on_recvfrom(socket_key(1, 9), buf, flags | MSG_DONTWAIT)
}

/// Everything queued on console `i`'s race socket: (payload, source ip).
fn drain(w: &mut World, i: usize) -> Vec<(Vec<u8>, u32)> {
    std::iter::from_fn(|| w.c[i].recvfrom(9).map(|(d, from)| (d, from.addr_ryujinx()))).collect()
}

/// Host on console 0, everyone else joins: the race lobby.
fn lobby(n: u8) -> World {
    let mut w = World::with(n);
    host(&mut w, 8);
    for i in 1..usize::from(n) {
        join(&mut w, i);
    }
    w
}

#[test]
fn scan_filters_the_game_sends() {
    let mut w = World::with(3);
    host(&mut w, 8);
    w.c[B].session.initialize().unwrap();
    let now = w.now;
    w.c[B].session.open_station(now).unwrap();
    let sid = w.c[A].session.network_info().network_id.session_id;

    // flag 0x1 with the title's id (what MK8D sends), and -1/0 (SDK fills in the NACP value)
    for lcid in [PROGRAM_ID as i64, -1, 0] {
        let mut f = filter(flag::LOCAL_COMMUNICATION_ID);
        f.network_id.intent_id.local_communication_id = lcid;
        assert_eq!(scan_with(&mut w, B, &f).len(), 1, "lcid {lcid:#x}");
        // on the wire: always the real id, flag 0x1 forced on, reserved cleared
        let sent = &w.relay.packets(1).last().unwrap().payload;
        let wire = ScanFilterFull::read_from_bytes(sent).unwrap();
        assert_eq!({ wire.network_id.intent_id.local_communication_id }, PROGRAM_ID as i64);
        assert_ne!({ wire.flag } & flag::LOCAL_COMMUNICATION_ID, 0);
    }
    // scene, network type, session id: match and mismatch
    type Edit = fn(&mut ScanFilterFull);
    let cases: [(u32, Edit, usize); 7] = [
        (flag::INTENT_ID, |_| {}, 1),
        (flag::INTENT_ID, |f| f.network_id.intent_id.scene_id = SCENE + 1, 0),
        (flag::NETWORK_TYPE, |_| {}, 1),
        (flag::NETWORK_TYPE, |f| f.network_type = 1, 0),
        (flag::SESSION_ID, |f| f.network_id.session_id.data = [0x55; 16], 0),
        (0, |_| {}, 1),
        (flag::LOCAL_COMMUNICATION_ID | flag::NETWORK_TYPE | flag::SCENE_ID, |_| {}, 1),
    ];
    for (flags, edit, want) in cases {
        let mut f = filter(flags);
        edit(&mut f);
        assert_eq!(scan_with(&mut w, B, &f).len(), want, "flags {flags:#x}");
    }
    let mut f = filter(flag::NETWORK_ID);
    f.network_id.session_id = sid;
    let found = scan_with(&mut w, B, &f);
    assert_eq!(found.len(), 1);
    // what the game reads back: its own scene and id, a real channel, the host as node 0
    let r = found[0];
    assert_eq!(({ r.network_id.intent_id.scene_id }, { r.network_id.intent_id.local_communication_id }), (SCENE, PROGRAM_ID as i64));
    assert_ne!({ r.common.channel }, 0);
    assert_eq!(({ r.ldn.node_count }, { r.ldn.nodes[0].ipv4_address }), (1, IP_A));

    // another game scanning with its own id (-1 = from its NACP) never sees this room
    *w.c[2].session = Session::new(PROGRAM_ID + 1);
    w.c[2].session.initialize().unwrap();
    w.c[2].session.open_station(now).unwrap();
    for flags in [0, flag::LOCAL_COMMUNICATION_ID, flag::SCENE_ID] {
        let mut f = filter(flags);
        f.network_id.intent_id.local_communication_id = -1;
        assert!(scan_with(&mut w, 2, &f).is_empty(), "flags {flags:#x}");
    }
}

#[test]
fn race_traffic_broadcast_unicast_and_recv_semantics() {
    let mut w = lobby(4);
    let all = [0, 1, 2, 3];
    bind_all(&mut w, &all);
    for i in all {
        assert_eq!(w.c[i].router.local_ip(), ip(i as u32 + 1));
        assert_eq!(w.c[i].router.poll_state(socket_key(1, 9)), PollState::Proxy { readable: false });
    }

    // the host's 1200-byte race-state broadcast reaches every console, its own echo included
    let race: Vec<u8> = (0..1200u32).map(|i| i as u8).collect();
    assert_eq!(w.c[A].sendto(&mut w.relay, 9, &race, BROADCAST, PORT), 1200);
    w.pump();
    for i in all {
        assert_eq!(w.c[i].router.poll_state(socket_key(1, 9)), PollState::Proxy { readable: true }, "console {i}");
        assert_eq!(w.c[i].router.on_ioctl(socket_key(1, 9), FIONREAD, None), Some(1200));
        let got = drain(&mut w, i);
        assert_eq!(got, [(race.clone(), IP_A)], "console {i}");
    }
    // unicast 2 -> 3 only, and 3 -> 2 back
    assert_eq!(w.c[2].sendto(&mut w.relay, 9, b"to three", ip(4), PORT), 8);
    assert_eq!(w.c[3].sendto(&mut w.relay, 9, b"to two", ip(3), PORT), 6);
    w.pump();
    assert_eq!(drain(&mut w, 3), [(b"to three".to_vec(), ip(3))]);
    assert_eq!(drain(&mut w, 2), [(b"to two".to_vec(), ip(4))]);
    assert!(drain(&mut w, 0).is_empty() && drain(&mut w, 1).is_empty());
    // unicast to an address nobody has is dropped by the relay
    assert_eq!(w.c[1].sendto(&mut w.relay, 9, b"void", ip(77), PORT), 4);
    w.pump();
    for i in all {
        assert!(drain(&mut w, i).is_empty());
    }

    // recvfrom buffer sizes: MSG_PEEK keeps it, a short buffer truncates and drops the rest,
    // a zero-length buffer consumes the datagram, the next datagram is intact
    for n in [100, 101, 102] {
        let msg = vec![n as u8; n];
        w.c[A].sendto(&mut w.relay, 9, &msg, ip(2), PORT);
    }
    w.pump();
    let mut buf = [0u8; 1536];
    let peek = recv(&mut w, B, &mut buf[..10], MSG_PEEK);
    assert!(matches!(peek, RecvDecision::Data { len: 10, from } if from.addr_ryujinx() == IP_A), "{peek:?}");
    assert!(matches!(recv(&mut w, B, &mut buf[..16], 0), RecvDecision::Data { len: 16, .. }));
    assert_eq!(buf[..16], [100; 16]);
    assert!(matches!(recv(&mut w, B, &mut [], 0), RecvDecision::Data { len: 0, .. }));
    assert!(matches!(recv(&mut w, B, &mut buf, 0), RecvDecision::Data { len: 102, .. }));
    assert_eq!(buf[..102], [102; 102]);
    assert_eq!(recv(&mut w, B, &mut buf, 0), RecvDecision::Reply(-11), "EAGAIN when empty");

    // a socket nobody reads: the 16 KiB ring keeps the newest datagrams, in order
    for k in 0..100u8 {
        w.c[A].sendto(&mut w.relay, 9, &[k; 1000], ip(2), PORT);
    }
    w.pump();
    let got = drain(&mut w, B);
    assert!((10..=16).contains(&got.len()), "{}", got.len());
    let firsts: Vec<u8> = got.iter().map(|(d, _)| d[0]).collect();
    assert_eq!(*firsts.last().unwrap(), 99);
    assert!(firsts.windows(2).all(|p| p[1] == p[0] + 1), "{firsts:?}");
    assert!(w.c[B].router.stats().evicted > 0);

    // bigger than any LDN frame: EMSGSIZE, nothing sent
    let before = w.relay.log.len();
    assert_eq!(w.c[A].sendto(&mut w.relay, 9, &[0; 2001], BROADCAST, PORT), -90);
    assert_eq!(w.relay.log.len(), before);

    // the relay's idle ping mid-race is echoed and the race goes on
    let link = w.c[C].link.unwrap();
    w.relay.ping(link, 7);
    w.pump();
    let echo = w.relay.packets(link).into_iter().rev().find(|r| r.type_ == PacketId::Ping.raw()).cloned();
    assert_eq!(echo.map(|r| r.payload), Some(vec![0, 7]));
}

const C: usize = 2;

#[test]
fn eight_consoles_fill_the_room_then_a_slot_is_reused() {
    let mut w = lobby(8);
    for (i, c) in w.c.iter().enumerate() {
        let s = &c.session;
        assert_eq!(s.local_node_id(), i as u8, "console {i}");
        assert_eq!(node_ips(s), (1..=8).map(ip).collect::<Vec<_>>(), "console {i} sees everyone");
        assert_eq!(s.get_ipv4_address(), Some((ip(i as u32 + 1), 0xFFFF_0000)));
    }
    let info = w.c[7].session.network_info();
    assert_eq!(({ info.ldn.node_count }, { info.ldn.node_count_max }), (8, 8));

    // a ninth console finds the room but cannot join
    w.c.push(world::console::Console::new(9));
    w.c[8].session.initialize().unwrap();
    let now = w.now;
    w.c[8].session.open_station(now).unwrap();
    assert_eq!(scan(&mut w, 8), 1);
    assert_eq!(connect_with(&mut w, 8, u32::from(VERSION)), Err(LdnError::TooManyPlayers));
    assert_eq!(w.c[8].session.state(), CommState::Station);

    // node 3 quits to the menu; the ninth takes its slot and a fresh address
    w.c[3].session.disconnect(now).unwrap();
    w.pump();
    for i in [0, 1, 2, 4, 5, 6, 7] {
        assert_eq!(node_ips(&w.c[i].session).len(), 7, "console {i}");
    }
    assert_eq!(connect_with(&mut w, 8, u32::from(VERSION)), Ok(()));
    assert_eq!(w.c[8].session.local_node_id(), 3);
    assert_eq!(w.c[8].router.local_ip(), ip(9));
    let want: Vec<u32> = [1, 2, 3, 9, 5, 6, 7, 8].into_iter().map(ip).collect();
    for i in [0, 1, 2, 4, 5, 6, 7, 8] {
        assert_eq!(node_ips(&w.c[i].session), want, "console {i}");
    }

    // the newcomer's broadcast reaches all eight (itself included), not the one that left
    let racers = [0, 1, 2, 4, 5, 6, 7, 8];
    bind_all(&mut w, &racers);
    w.c[3].socket(9);
    w.c[8].sendto(&mut w.relay, 9, b"hi", BROADCAST, PORT);
    w.pump();
    for i in racers {
        assert_eq!(drain(&mut w, i), [(b"hi".to_vec(), ip(9))], "console {i}");
    }
}

#[test]
fn leave_and_rejoin_the_same_room() {
    let mut w = lobby(3);
    let now = w.now;
    w.c[B].session.disconnect(now).unwrap();
    w.pump();
    assert_eq!(node_ips(&w.c[A].session), [ip(1), ip(3)]);
    assert_eq!(w.c[B].session.get_disconnect_reason(), DisconnectReason::User);
    assert_eq!(scan(&mut w, B), 1);
    assert_eq!(connect_with(&mut w, B, u32::from(VERSION)), Ok(()));
    assert_eq!(w.c[B].session.local_node_id(), 1);
    assert_eq!(node_ips(&w.c[C].session), [ip(1), ip(4), ip(3)]);
    // the old address is not routed to anyone any more; the new one is
    bind_all(&mut w, &[0, 1, 2]);
    w.c[A].sendto(&mut w.relay, 9, b"old", ip(2), PORT);
    w.c[A].sendto(&mut w.relay, 9, b"new", ip(4), PORT);
    w.pump();
    assert_eq!(drain(&mut w, B), [(b"new".to_vec(), IP_A)]);
}

#[test]
fn host_quits_then_a_guest_hosts_the_next_race() {
    let mut w = lobby(3);
    bind_all(&mut w, &[0, 1, 2]);
    let now = w.now;
    w.c[A].session.destroy_network(now).unwrap();
    w.pump();
    for i in [B, C] {
        let s = &w.c[i].session;
        assert_eq!(s.state(), CommState::Station, "console {i}");
        assert_eq!(s.get_disconnect_reason(), DisconnectReason::DestroyedByUser);
        assert!(node_ips(s).is_empty());
        assert!(w.c[i].conn.is_ready(), "the link stays up");
    }
    assert_eq!(scan(&mut w, B), 0, "the closed room is not listed");

    // B goes back to the menu and hosts; C joins B's room
    w.c[B].session.close_station(now).unwrap();
    w.c[B].session.open_access_point(now).unwrap();
    let _p = w.c[B]
        .session
        .create_network(&SecurityConfig::new_zeroed(), &user("bob"), &network_config(8), now)
        .unwrap();
    assert_eq!(w.wait(B), Ok(()), "a guest of a closed room can host");
    assert_eq!(w.c[B].session.state(), CommState::AccessPointCreated);
    assert_eq!(scan(&mut w, C), 1);
    assert_eq!(connect_with(&mut w, C, u32::from(VERSION)), Ok(()));
    assert_eq!(node_ips(&w.c[B].session).len(), 2);
}

#[test]
fn guest_link_drop_leaves_the_others_racing() {
    let mut w = lobby(3);
    bind_all(&mut w, &[0, 1, 2]);
    let link = w.c[C].link.unwrap();
    w.relay.close(link);
    w.c[C].conn.transport_lost();
    w.pump();
    assert_eq!(w.c[C].session.state(), CommState::Station);
    assert_eq!(w.c[C].router.proxy_count(), 0);
    for i in [A, B] {
        assert_eq!(node_ips(&w.c[i].session), [ip(1), ip(2)], "console {i}");
    }
    w.c[B].sendto(&mut w.relay, 9, b"go", BROADCAST, PORT);
    w.pump();
    assert_eq!(drain(&mut w, A), [(b"go".to_vec(), ip(2))]);
    assert_eq!(drain(&mut w, B), [(b"go".to_vec(), ip(2))]);
}

#[test]
fn host_link_drop_mid_race_status_and_recovery() {
    let mut w = lobby(2);
    bind_all(&mut w, &[0, 1]);
    // the overlay's toasts, fed as the shell feeds them
    let mut toasts = Notifier::new(NotifyConfig::default());
    let mut seen = vec![];
    let tick = |w: &mut World, ms: u64, t: &mut Notifier, seen: &mut Vec<String>| {
        for _ in 0..ms / 100 {
            w.advance(100);
            t.on_event(Event::Relay { up: w.c[A].conn.is_ready() }, w.now);
            while let Some(x) = t.poll(w.now) {
                seen.push(x.text.as_str().to_string());
            }
        }
    };
    toasts.on_event(Event::GameStarted { pid: 0x51, mode: LdnMode::Online }, w.now);
    tick(&mut w, 6000, &mut toasts, &mut seen);
    assert_eq!(seen, ["Online play on", "Connected"]);

    let link = w.c[A].link.unwrap();
    w.relay.close(link);
    w.c[A].conn.transport_lost();
    w.pump();
    let s = &w.c[A].session;
    assert_eq!(s.state(), CommState::AccessPoint, "back to the lobby screen");
    assert_eq!(s.get_disconnect_reason(), DisconnectReason::DestroyedBySystem);
    assert_eq!(w.c[A].router.local_ip(), 0);
    assert_eq!(w.c[A].router.poll_state(socket_key(1, 9)), PollState::Gone);
    assert_eq!(w.c[A].sendto(&mut w.relay, 9, b"x", BROADCAST, PORT), -100, "ENETDOWN on the dead proxy");
    assert_eq!(w.c[B].session.state(), CommState::Station, "the guest saw the room close");
    assert_eq!(w.relay.game_count(), 0);

    // a short outage is not announced; a long one is, then the reconnect
    tick(&mut w, 2000, &mut toasts, &mut seen);
    assert_eq!(seen.len(), 2);
    assert!(w.c[A].conn.is_ready(), "Conn reconnected by itself");
    tick(&mut w, 6000, &mut toasts, &mut seen);
    assert_eq!(seen.len(), 2, "back up within STABLE_MS: no toast at all");

    // the next race: A hosts again, B finds it
    let now = w.now;
    let _p = w.c[A]
        .session
        .create_network(&SecurityConfig::new_zeroed(), &user("alice"), &network_config(8), now)
        .unwrap();
    assert_eq!(w.wait(A), Ok(()));
    assert_eq!(scan(&mut w, B), 1);
    assert_eq!(connect_with(&mut w, B, u32::from(VERSION)), Ok(()));
    assert_eq!(node_ips(&w.c[A].session), [ip(1), ip(2)]);
}
