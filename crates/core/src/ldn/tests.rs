#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

extern crate std;

use std::vec;
use std::vec::Vec as StdVec;

use zerocopy::{FromBytes, FromZeros, IntoBytes};

use super::*;
use crate::wire::{ConnectRequest, CreateAccessPointRequest, NodeInfo, ScanFilterFull};

const PROGRAM_ID: u64 = 0x0100_1520_0000_0000;
/// 10.114.0.1 / 255.255.0.0, Ryujinx format.
const MY_IP: u32 = 0x0A72_0001;
const MASK: u32 = 0xFFFF_0000;
const OTHER_IP: u32 = 0x0A72_0002;

fn drain(s: &mut Session) -> StdVec<Action> {
    let mut out = StdVec::new();
    while let Some(a) = s.next_action() {
        out.push(a);
    }
    assert!(out.len() < OUTBOX, "outbox may have overflowed: {out:?}");
    out
}

fn sends(actions: &[Action]) -> StdVec<(PacketId, StdVec<u8>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send { id, payload } => Some((*id, payload.to_vec())),
            _ => None,
        })
        .collect()
}

fn has(actions: &[Action], want: &Action) -> bool {
    actions.contains(want)
}

fn node(ip: u32, id: u8) -> NodeInfo {
    let mut n = NodeInfo::new_zeroed();
    n.ipv4_address = ip;
    n.node_id = id;
    n.is_connected = 1;
    n
}

/// A room as the relay reports it: `ips` connected, channel 0, scene 0.
fn room(ips: &[u32]) -> NetworkInfo {
    let mut info = NetworkInfo::new_zeroed();
    info.network_id.intent_id.local_communication_id = PROGRAM_ID as i64;
    info.ldn.node_count_max = 8;
    info.ldn.node_count = ips.len() as u8;
    for (i, ip) in ips.iter().enumerate() {
        info.ldn.nodes[i] = node(*ip, i as u8);
    }
    info
}

fn initialize_msg(id: u8, mac: u8) -> StdVec<u8> {
    InitializeMessage {
        id: SessionId { data: [id; 16] },
        mac_address: MacAddress { data: [mac; 6] },
    }
    .as_bytes()
    .to_vec()
}

fn proxy_config() -> StdVec<u8> {
    ProxyConfig {
        proxy_ip: MY_IP,
        proxy_subnet_mask: MASK,
    }
    .as_bytes()
    .to_vec()
}

fn error(code: u32) -> StdVec<u8> {
    code.to_le_bytes().to_vec()
}

fn packet(s: &mut Session, id: PacketId, data: &[u8], now: u64) -> StdVec<Action> {
    assert!(s.on_packet(id.raw(), data, now).is_none());
    drain(s)
}

/// Bring the link up after RelayConnect was emitted.
fn handshake(s: &mut Session, now: u64) -> StdVec<Action> {
    s.on_relay_open(now);
    let out = drain(s);
    let ids: StdVec<_> = sends(&out).into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, [PacketId::Passphrase, PacketId::Initialize]);
    let mut out = packet(s, PacketId::Initialize, &initialize_msg(7, 9), now);
    out.extend(packet(s, PacketId::ProxyConfig, &proxy_config(), now));
    out
}

fn session_in(open: fn(&mut Session, u64) -> Result<(), LdnError>) -> Session {
    let mut s = Session::new(PROGRAM_ID);
    s.initialize().unwrap();
    open(&mut s, 0).unwrap();
    assert!(has(&drain(&mut s), &Action::RelayConnect));
    handshake(&mut s, 0);
    assert!(s.is_relay_ready());
    s
}

fn network_config(scene: u16) -> NetworkConfig {
    let mut c = NetworkConfig::new_zeroed();
    c.intent_id.local_communication_id = -1;
    c.intent_id.scene_id = scene;
    c.node_count_max = 8;
    c
}

fn create(s: &mut Session, now: u64) -> StdVec<Action> {
    let Pending = s
        .create_network(
            &SecurityConfig::new_zeroed(),
            &UserConfig::new_zeroed(),
            &network_config(3),
            now,
        )
        .unwrap();
    drain(s)
}

fn hosting() -> Session {
    let mut s = session_in(Session::open_access_point);
    create(&mut s, 0);
    let out = packet(&mut s, PacketId::Connected, room(&[MY_IP]).as_bytes(), 10);
    assert!(has(&out, &Action::ReplyReady));
    assert_eq!(s.take_reply(), Some(Ok(())));
    s
}

fn connect(s: &mut Session, info: &NetworkInfo, now: u64) -> StdVec<Action> {
    let Pending = s
        .connect(
            &SecurityConfig::new_zeroed(),
            &UserConfig::new_zeroed(),
            1,
            0,
            info,
            now,
        )
        .unwrap();
    drain(s)
}

fn joined() -> Session {
    let mut s = session_in(Session::open_station);
    connect(&mut s, &room(&[OTHER_IP]), 0);
    packet(
        &mut s,
        PacketId::Connected,
        room(&[OTHER_IP, MY_IP]).as_bytes(),
        10,
    );
    assert_eq!(s.take_reply(), Some(Ok(())));
    s
}

#[test]
fn result_codes() {
    assert_eq!(LdnError::InvalidState.result_code(), 203 | (32 << 9));
    assert_eq!(LdnError::TooManyPlayers.result_code(), 203 | (144 << 9));
    let table = [
        (0, LdnError::ConnectTimeout),
        (1, LdnError::DeviceNotAvailable),
        (2, LdnError::TooManyPlayers),
        (3, LdnError::VersionTooLow),
        (4, LdnError::VersionTooHigh),
        (5, LdnError::ConnectFailure),
        (6, LdnError::ConnectNotFound),
        (7, LdnError::ConnectTimeout),
        (8, LdnError::ConnectRejected),
        (9, LdnError::DeviceNotAvailable),
        (i32::MAX, LdnError::DeviceNotAvailable),
    ];
    for (wire, want) in table {
        assert_eq!(connect_failure(wire), want, "wire {wire}");
    }
}

#[test]
fn state_transitions() {
    let mut s = Session::new(PROGRAM_ID);
    s.finalize(0);
    assert!(drain(&mut s).is_empty(), "finalize from None is silent");
    assert_eq!(s.open_station(0), Err(LdnError::InvalidState));
    assert_eq!(s.initialize(), Ok(()));
    assert_eq!(drain(&mut s), [Action::StateChanged]);
    assert_eq!(
        s.initialize(),
        Err(LdnError::InvalidState),
        "already in state is a failure"
    );
    assert_eq!(s.destroy_network(0), Err(LdnError::InvalidState));
    assert_eq!(s.disconnect(0), Err(LdnError::InvalidState));
    assert_eq!(s.close_station(0), Err(LdnError::InvalidState));

    assert_eq!(s.open_access_point(0), Ok(()));
    assert_eq!(drain(&mut s), [Action::StateChanged, Action::RelayConnect]);
    assert_eq!(s.state(), CommState::AccessPoint);
    assert_eq!(s.open_station(0), Err(LdnError::InvalidState));
    assert_eq!(s.close_access_point(0), Ok(()));
    assert_eq!(
        drain(&mut s),
        [Action::RelayDisconnect, Action::StateChanged]
    );
    assert_eq!(s.state(), CommState::Initialized);

    assert_eq!(s.open_station(0), Ok(()));
    assert_eq!(s.close_access_point(0), Err(LdnError::InvalidState));
    drain(&mut s);
    assert_eq!(s.close_station(0), Ok(()));
    assert_eq!(s.state(), CommState::Initialized);
    s.finalize(0);
    assert!(has(&drain(&mut s), &Action::StateChanged));
    assert_eq!(s.state(), CommState::None);

    assert_eq!(s.set_protocol(1), Ok(()));
    assert_eq!(s.set_protocol(3), Ok(()));
    assert_eq!(s.set_protocol(2), Err(LdnError::InvalidArgument));
}

#[test]
fn host_flow() {
    let mut s = Session::new(PROGRAM_ID);
    s.initialize().unwrap();
    s.open_access_point(0).unwrap();
    drain(&mut s);
    s.set_advertise_data(&[1, 2, 3]);
    // The link is still opening: the request waits for it.
    let out = create(&mut s, 0);
    assert!(sends(&out).is_empty());
    assert_eq!(s.state(), CommState::AccessPoint);

    let out = handshake(&mut s, 100);
    let sent = sends(&out);
    assert_eq!(sent.len(), 1);
    let (id, payload) = &sent[0];
    assert_eq!(*id, PacketId::CreateAccessPoint);
    assert_eq!(payload.len(), size_of::<CreateAccessPointRequest>() + 3);
    let (req, adv) = CreateAccessPointRequest::read_from_prefix(payload).unwrap();
    assert_eq!(
        { req.network_config.intent_id.local_communication_id },
        PROGRAM_ID as i64
    );
    assert_eq!(adv, [1, 2, 3]);
    assert_eq!(s.state(), CommState::AccessPointCreated);
    assert!(has(
        &out,
        &Action::ProxyConfig {
            ip: MY_IP,
            mask: MASK
        }
    ));
    assert_eq!(s.next_deadline(), Some(100 + CONNECT_TIMEOUT_MS));

    let out = packet(&mut s, PacketId::Connected, room(&[MY_IP]).as_bytes(), 200);
    assert!(has(&out, &Action::ReplyReady));
    assert!(has(&out, &Action::StateChanged));
    assert_eq!(s.take_reply(), Some(Ok(())));
    assert_eq!(s.take_reply(), None);
    let info = s.network_info();
    assert_eq!({ info.common.channel }, 6, "channel 0 becomes 6");
    assert_eq!(
        { info.network_id.intent_id.scene_id },
        3,
        "relay scene 0 becomes the requested one"
    );
    assert_eq!(s.local_node_id(), 0);
    assert_eq!(s.get_ipv4_address(), Some((MY_IP, MASK)));
    assert_eq!(s.get_network_config().node_count_max, 8);
    assert_eq!(s.next_deadline(), None, "idle timeout off while hosting");

    assert_eq!(
        s.get_network_info_latest_update(8)[0],
        NodeStateChange::Connect
    );
    assert_eq!(
        s.get_network_info_latest_update(8)[0],
        NodeStateChange::None
    );

    // Destroy: tell the relay, back to AccessPoint, the link stays for a new room.
    assert_eq!(s.destroy_network(300), Ok(()));
    let out = drain(&mut s);
    assert_eq!(sends(&out), [(PacketId::Disconnect, vec![0; 4])]);
    assert_eq!(s.state(), CommState::AccessPoint);
    assert_eq!(s.local_node_id(), 0xFF);
    assert_eq!(s.next_deadline(), Some(300 + IDLE_TIMEOUT_MS));
}

#[test]
fn station_flow() {
    let mut s = session_in(Session::open_station);
    let mut filter = ScanFilterFull::new_zeroed();
    filter.network_id.intent_id.local_communication_id = 0;
    filter.network_id.intent_id.scene_id = 5;
    filter.network_id.intent_id.reserved1 = 0xFFFF;
    filter.reserved = [0xAA; 16];
    let Pending = s.scan(&filter, 0).unwrap();
    let sent = sends(&drain(&mut s));
    let (id, payload) = &sent[0];
    assert_eq!(*id, PacketId::Scan);
    let f = ScanFilterFull::read_from_bytes(payload).unwrap();
    assert_eq!({ f.flag } & 1, 1);
    assert_eq!(
        { f.network_id.intent_id.local_communication_id },
        PROGRAM_ID as i64
    );
    assert_eq!({ f.network_id.intent_id.reserved1 }, 0);
    assert_eq!({ f.reserved }, [0; 16]);

    assert_eq!(
        s.scan(&filter, 0).map(|_| ()),
        Err(LdnError::InvalidState),
        "one request at a time"
    );
    packet(
        &mut s,
        PacketId::ScanReply,
        room(&[OTHER_IP]).as_bytes(),
        10,
    );
    packet(
        &mut s,
        PacketId::ScanReply,
        room(&[OTHER_IP, 0x0A72_0003]).as_bytes(),
        20,
    );
    packet(&mut s, PacketId::ScanReply, &[1, 2, 3], 20); // short: dropped
    let out = packet(&mut s, PacketId::ScanReplyEnd, &[], 30);
    assert!(has(&out, &Action::ReplyReady));
    assert_eq!(s.take_reply(), Some(Ok(())));
    assert_eq!(s.scan_results().len(), 2);
    assert_eq!({ s.scan_results()[0].network_id.intent_id.scene_id }, 5);
    // A late reply does not change the results.
    packet(
        &mut s,
        PacketId::ScanReply,
        room(&[OTHER_IP]).as_bytes(),
        40,
    );
    assert_eq!(s.scan_results().len(), 2);

    let target = s.scan_results()[0];
    let out = connect(&mut s, &target, 50);
    let sent = sends(&out);
    assert_eq!(sent[0].0, PacketId::Connect);
    assert_eq!(sent[0].1.len(), size_of::<ConnectRequest>());
    let req = ConnectRequest::read_from_bytes(&sent[0].1).unwrap();
    assert_eq!({ req.local_communication_version }, 1);
    assert_eq!(s.state(), CommState::StationConnected);

    // The relay sends ProxyConfig, then Connected.
    let out = packet(
        &mut s,
        PacketId::ProxyConfig,
        ProxyConfig {
            proxy_ip: 0x0A72_0009,
            proxy_subnet_mask: MASK,
        }
        .as_bytes(),
        60,
    );
    assert!(has(
        &out,
        &Action::ProxyConfig {
            ip: 0x0A72_0009,
            mask: MASK
        }
    ));
    assert!(s.take_reply().is_none(), "async packets don't end the wait");
    let out = packet(
        &mut s,
        PacketId::Connected,
        room(&[OTHER_IP, 0x0A72_0009]).as_bytes(),
        70,
    );
    assert!(has(&out, &Action::ReplyReady));
    assert_eq!(s.take_reply(), Some(Ok(())));
    assert_eq!(s.local_node_id(), 1);
    assert_eq!(s.state(), CommState::StationConnected);

    assert_eq!(s.disconnect(80), Ok(()));
    let out = drain(&mut s);
    assert_eq!(sends(&out), [(PacketId::Disconnect, vec![0; 4])]);
    assert_eq!(s.get_disconnect_reason(), DisconnectReason::User);
    assert_eq!(s.state(), CommState::Station);
}

#[test]
fn network_error_codes() {
    let mut s = session_in(Session::open_station);
    connect(&mut s, &room(&[OTHER_IP]), 0);
    // PortUnreachable is informational: no reply, no stored error.
    let out = packet(&mut s, PacketId::NetworkError, &error(1), 10);
    assert!(!has(&out, &Action::ReplyReady));
    assert_eq!(s.last_network_error, 0);
    let out = packet(&mut s, PacketId::NetworkError, &error(2), 20);
    assert!(has(&out, &Action::ReplyReady));
    assert_eq!(s.take_reply(), Some(Err(LdnError::TooManyPlayers)));
    assert_eq!(s.state(), CommState::Station);
    assert_eq!(s.last_network_error, 0, "consumed");

    // A short NetworkError still ends the wait, as a timeout.
    connect(&mut s, &room(&[OTHER_IP]), 30);
    packet(&mut s, PacketId::NetworkError, &[1], 40);
    assert_eq!(s.take_reply(), Some(Err(LdnError::ConnectTimeout)));

    // Create fails with InvalidState whatever the code.
    let mut s = session_in(Session::open_access_point);
    create(&mut s, 0);
    packet(&mut s, PacketId::NetworkError, &error(5), 10);
    assert_eq!(s.take_reply(), Some(Err(LdnError::InvalidState)));
    assert_eq!(s.state(), CommState::AccessPoint);

    // A scan error: Ok with no results.
    let Pending = s.scan(&ScanFilterFull::new_zeroed(), 20).unwrap();
    drain(&mut s);
    packet(
        &mut s,
        PacketId::ScanReply,
        room(&[OTHER_IP]).as_bytes(),
        21,
    );
    packet(&mut s, PacketId::NetworkError, &error(6), 22);
    assert_eq!(s.take_reply(), Some(Ok(())));
    assert!(s.scan_results().is_empty());
}

#[test]
fn spurious_replies_keep_waiting() {
    let mut s = session_in(Session::open_station);
    connect(&mut s, &room(&[OTHER_IP]), 0);
    for id in [
        PacketId::ScanReplyEnd,
        PacketId::RejectReply,
        PacketId::ProxyConnectReply,
        PacketId::ScanReply,
        PacketId::Ping,
    ] {
        let out = packet(&mut s, id, &[0; 8], 10);
        assert!(!has(&out, &Action::ReplyReady), "{id:?}");
    }
    // SyncNetwork outside a room is ignored.
    let out = packet(
        &mut s,
        PacketId::SyncNetwork,
        room(&[OTHER_IP]).as_bytes(),
        10,
    );
    assert!(out.is_empty());
    assert!(s.take_reply().is_none());
    packet(
        &mut s,
        PacketId::Connected,
        room(&[OTHER_IP, MY_IP]).as_bytes(),
        20,
    );
    assert_eq!(s.take_reply(), Some(Ok(())));
}

#[test]
fn timeouts() {
    // Scan: a timeout keeps what arrived.
    let mut s = session_in(Session::open_station);
    let Pending = s.scan(&ScanFilterFull::new_zeroed(), 1000).unwrap();
    drain(&mut s);
    packet(
        &mut s,
        PacketId::ScanReply,
        room(&[OTHER_IP]).as_bytes(),
        1500,
    );
    s.poll(1999);
    assert!(s.take_reply().is_none());
    s.poll(2000);
    assert!(has(&drain(&mut s), &Action::ReplyReady));
    assert_eq!(s.take_reply(), Some(Ok(())));
    assert_eq!(s.scan_results().len(), 1);
    assert_eq!(s.next_deadline(), Some(2000 + IDLE_TIMEOUT_MS));

    // Connect timeout, then the late Connected is answered with a Disconnect.
    connect(&mut s, &room(&[OTHER_IP]), 3000);
    assert_eq!(
        s.next_deadline(),
        Some(3000 + CONNECT_TIMEOUT_MS),
        "idle timer disabled"
    );
    s.poll(3000 + CONNECT_TIMEOUT_MS);
    drain(&mut s);
    assert_eq!(s.take_reply(), Some(Err(LdnError::ConnectTimeout)));
    assert_eq!(s.state(), CommState::Station);
    let out = packet(
        &mut s,
        PacketId::Connected,
        room(&[OTHER_IP, MY_IP]).as_bytes(),
        9000,
    );
    assert_eq!(sends(&out), [(PacketId::Disconnect, vec![0; 4])]);
    assert!(!s.network_connected);

    // Private connect uses the 4 s timeout.
    let Pending = s
        .connect_private(
            &SecurityConfig::new_zeroed(),
            &SecurityParameter::new_zeroed(),
            &UserConfig::new_zeroed(),
            0,
            0,
            &network_config(1),
            10_000,
        )
        .unwrap();
    assert_eq!(sends(&drain(&mut s))[0].0, PacketId::ConnectPrivate);
    assert_eq!(s.next_deadline(), Some(10_000 + PRIVATE_TIMEOUT_MS));

    // Create timeout: InvalidState, back to AccessPoint.
    let mut s = session_in(Session::open_access_point);
    create(&mut s, 0);
    s.poll(CONNECT_TIMEOUT_MS);
    assert_eq!(s.take_reply(), Some(Err(LdnError::InvalidState)));
    assert_eq!(s.state(), CommState::AccessPoint);

    // The relay never answers the transport: Connect gives DeviceNotAvailable.
    let mut s = Session::new(PROGRAM_ID);
    s.initialize().unwrap();
    s.open_station(0).unwrap();
    connect(&mut s, &room(&[OTHER_IP]), 0);
    s.poll(LINK_TIMEOUT_MS);
    let out = drain(&mut s);
    assert!(has(&out, &Action::RelayDisconnect));
    assert_eq!(s.take_reply(), Some(Err(LdnError::DeviceNotAvailable)));
    assert_eq!(s.state(), CommState::Station);

    // The handshake is refused: same.
    s.open_station(0).unwrap_err();
    connect(&mut s, &room(&[OTHER_IP]), 0);
    s.on_relay_open(10);
    drain(&mut s);
    packet(&mut s, PacketId::NetworkError, &error(4), 20);
    assert_eq!(s.take_reply(), Some(Err(LdnError::DeviceNotAvailable)));

    // Idle: the link closes 6 s after leaving the room.
    let mut s = joined();
    s.disconnect(100).unwrap();
    drain(&mut s);
    s.poll(100 + IDLE_TIMEOUT_MS - 1);
    assert!(drain(&mut s).is_empty());
    s.poll(100 + IDLE_TIMEOUT_MS);
    assert!(has(&drain(&mut s), &Action::RelayDisconnect));
    assert!(!s.is_relay_ready());
    assert_eq!(s.get_ipv4_address(), None);
    assert_eq!(s.next_deadline(), None);

    // The next request reconnects with the id and MAC the relay gave us.
    let Pending = s.scan(&ScanFilterFull::new_zeroed(), 20_000).unwrap();
    assert!(has(&drain(&mut s), &Action::RelayConnect));
    s.on_relay_open(20_001);
    let sent = sends(&drain(&mut s));
    assert_eq!(sent[1], (PacketId::Initialize, initialize_msg(7, 9)));
}

#[test]
fn disconnect_reasons() {
    // Station: the room goes away.
    let mut s = joined();
    let out = packet(&mut s, PacketId::Disconnect, &[0; 4], 100);
    assert!(has(&out, &Action::StateChanged));
    // acknowledged, so the relay drops us from the closed room and lets us host
    assert_eq!(sends(&out), [(PacketId::Disconnect, vec![0; 4])]);
    assert_eq!(s.state(), CommState::Station);
    assert_eq!(s.get_disconnect_reason(), DisconnectReason::DestroyedByUser);
    assert_eq!(s.network_info().ldn.node_count, 0);
    assert_eq!(s.next_deadline(), Some(100 + IDLE_TIMEOUT_MS));

    // Station: kicked by the host.
    let mut s = joined();
    packet(
        &mut s,
        PacketId::Reject,
        RejectRequest {
            node_id: 1,
            disconnect_reason: 5,
        }
        .as_bytes(),
        100,
    );
    assert_eq!(
        s.state(),
        CommState::StationConnected,
        "Reject alone changes nothing"
    );
    packet(&mut s, PacketId::Disconnect, &[0; 4], 110);
    assert_eq!(s.get_disconnect_reason(), DisconnectReason::Rejected);
    // A short Reject still counts as Rejected.
    let mut s = joined();
    packet(&mut s, PacketId::Reject, &[], 100);
    packet(&mut s, PacketId::Disconnect, &[], 110);
    assert_eq!(s.get_disconnect_reason(), DisconnectReason::Rejected);

    // Host: the relay drops the room.
    let mut s = hosting();
    packet(&mut s, PacketId::Disconnect, &[0; 4], 100);
    assert_eq!(
        s.get_disconnect_reason(),
        DisconnectReason::DestroyedBySystem
    );
    assert_eq!(s.state(), CommState::AccessPoint);

    // Host: the link dies (Ryujinx OnDisconnected) and the room is not resumed in time.
    let mut s = hosting();
    s.on_relay_closed(100);
    let out = drain(&mut s);
    assert!(
        !has(&out, &Action::RelayDisconnect),
        "the shell already knows"
    );
    assert_eq!(s.state(), CommState::AccessPointCreated, "resuming");
    s.poll(100 + RESUME_MS);
    assert!(has(&drain(&mut s), &Action::RelayDisconnect), "the reconnect attempt is dropped");
    assert_eq!(s.state(), CommState::AccessPoint);
    assert_eq!(
        s.get_disconnect_reason(),
        DisconnectReason::DestroyedBySystem
    );
    assert_eq!(s.get_ipv4_address(), None);

    // Disconnect outside a room is ignored.
    let mut s = session_in(Session::open_station);
    assert!(packet(&mut s, PacketId::Disconnect, &[0; 4], 100).is_empty());
    assert_eq!(s.get_disconnect_reason(), DisconnectReason::None);
}

#[test]
fn reject_flow() {
    let mut s = hosting();
    let Pending = s.reject(1, 0).unwrap();
    let sent = sends(&drain(&mut s));
    assert_eq!(
        sent,
        [(
            PacketId::Reject,
            RejectRequest {
                node_id: 1,
                disconnect_reason: 5
            }
            .as_bytes()
            .to_vec()
        )]
    );
    packet(&mut s, PacketId::RejectReply, &[], 10);
    assert_eq!(s.take_reply(), Some(Ok(())));

    let Pending = s.reject(1, 20).unwrap();
    drain(&mut s);
    packet(&mut s, PacketId::NetworkError, &error(9), 30);
    assert_eq!(s.take_reply(), Some(Err(LdnError::InvalidState)));

    let Pending = s.reject(1, 40).unwrap();
    drain(&mut s);
    s.poll(40 + REJECT_TIMEOUT_MS);
    assert_eq!(s.take_reply(), Some(Err(LdnError::InvalidState)));
    assert_eq!(
        s.state(),
        CommState::AccessPointCreated,
        "a failed reject keeps the room"
    );

    let mut s = joined();
    assert_eq!(s.reject(0, 0).map(|_| ()), Err(LdnError::InvalidState));
}

#[test]
fn sync_network_updates_nodes() {
    let mut s = hosting();
    assert_eq!(
        s.get_network_info_latest_update(8)[..2],
        [NodeStateChange::Connect, NodeStateChange::None]
    );
    let out = packet(
        &mut s,
        PacketId::SyncNetwork,
        room(&[MY_IP, OTHER_IP]).as_bytes(),
        20,
    );
    assert_eq!(
        out.iter().filter(|a| **a == Action::StateChanged).count(),
        1
    );
    assert_eq!(s.network_info().ldn.node_count, 2);
    assert_eq!({ s.network_info().common.channel }, 6);
    assert_eq!(
        s.get_network_info_latest_update(8)[..2],
        [NodeStateChange::None, NodeStateChange::Connect]
    );
    let mut left = room(&[MY_IP, OTHER_IP]);
    left.ldn.nodes[1].is_connected = 0;
    left.ldn.node_count = 1;
    packet(&mut s, PacketId::SyncNetwork, left.as_bytes(), 30);
    // Only the first `count` nodes are compared (and remembered).
    assert_eq!(
        s.get_network_info_latest_update(1)[..2],
        [NodeStateChange::None; 2]
    );
    assert_eq!(
        s.get_network_info_latest_update(8)[..2],
        [NodeStateChange::None, NodeStateChange::Disconnect]
    );
    // Short SyncNetwork: ignored.
    assert!(packet(&mut s, PacketId::SyncNetwork, &[0; 100], 40).is_empty());
}

#[test]
fn clamps_and_advertise_data() {
    let mut s = session_in(Session::open_access_point);
    s.set_advertise_data(&[0xAB; 500]);
    assert!(drain(&mut s).is_empty(), "not sent outside a room");
    let sent = sends(&create(&mut s, 0));
    assert_eq!(
        sent[0].1.len(),
        size_of::<CreateAccessPointRequest>() + ADVERTISE_DATA_MAX
    );

    let mut info = room(&[MY_IP]);
    info.ldn.advertise_data_size = 1000;
    info.ldn.node_count_max = 20;
    info.ldn.node_count = 30;
    packet(&mut s, PacketId::Connected, info.as_bytes(), 10);
    let ldn = &s.network_info().ldn;
    assert_eq!(
        (
            { ldn.advertise_data_size },
            ldn.node_count_max,
            ldn.node_count
        ),
        (384, 8, 8)
    );

    s.set_advertise_data(&[1; 10]);
    s.set_station_accept_policy(1);
    let sent = sends(&drain(&mut s));
    assert_eq!(
        sent,
        [
            (PacketId::SetAdvertiseData, vec![1; 10]),
            (PacketId::SetAcceptPolicy, vec![1])
        ]
    );
}

#[test]
fn ping_and_proxy_data() {
    let mut s = session_in(Session::open_station);
    assert_eq!(
        sends(&packet(&mut s, PacketId::Ping, &[0, 42], 0)),
        [(PacketId::Ping, vec![0, 42])]
    );
    assert!(
        sends(&packet(&mut s, PacketId::Ping, &[1, 42], 0)).is_empty(),
        "our own ping coming back"
    );

    let mut header = ProxyDataHeader::new_zeroed();
    header.info.protocol = ProtocolType::Udp.raw();
    header.info.dest_port = 1234;
    header.data_length = 3;
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(&[7, 8, 9, 10]);
    let got = s.on_packet(PacketId::ProxyData.raw(), &bytes, 0).unwrap();
    assert_eq!(got.payload, [7, 8, 9]);
    assert_eq!({ got.info.dest_port }, 1234);
    assert!(
        s.on_packet(PacketId::ProxyData.raw(), &bytes[..22], 0)
            .is_none(),
        "truncated"
    );
    header.info.protocol = 1;
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(&[7, 8, 9]);
    assert!(
        s.on_packet(PacketId::ProxyData.raw(), &bytes, 0).is_none(),
        "not TCP/UDP"
    );
}

#[test]
fn finalize_cancels_and_resets() {
    let mut s = session_in(Session::open_station);
    connect(&mut s, &room(&[OTHER_IP]), 0);
    s.finalize(10);
    let out = drain(&mut s);
    assert!(!has(&out, &Action::ReplyReady));
    assert!(has(&out, &Action::RelayDisconnect));
    assert_eq!(s.state(), CommState::None);
    assert_eq!(s.next_deadline(), None);
    assert!(
        s.on_packet(PacketId::Connected.raw(), room(&[MY_IP]).as_bytes(), 20)
            .is_none()
    );
    assert!(!s.network_connected);
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn check_invariants(s: &Session) {
    if s.network_connected {
        assert!(
            matches!(
                s.state,
                CommState::AccessPointCreated | CommState::StationConnected
            ),
            "{:?}",
            s.state
        );
    }
    let ldn = &s.network_info.ldn;
    assert!(usize::from(ldn.node_count_max) <= NODE_COUNT_MAX);
    assert!(ldn.node_count <= ldn.node_count_max);
    assert!(usize::from({ ldn.advertise_data_size }) <= ADVERTISE_DATA_MAX);
    for info in s.scan_results() {
        assert!(info.ldn.node_count <= info.ldn.node_count_max);
    }
    if s.request.is_some() {
        assert!(s.reply.is_none());
    }
    if s.link != Link::Ready {
        assert_eq!(s.get_ipv4_address(), None);
    }
    if let Some(r) = &s.request
        && r.deadline.is_some()
    {
        assert_eq!(s.link, Link::Ready, "a sent request needs the link");
    }
}

#[test]
fn random_input() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let sizes = [0, 1, 2, 4, 8, 20, 22, 1152, 1153, 2000];
    let mut buf = [0u8; 2000];
    for round in 0..40 {
        let mut s = Session::new(rng.next());
        let mut now = 0u64;
        for _ in 0..2000 {
            now += rng.below(700);
            match rng.below(10) {
                0..=5 => {
                    let id = if rng.below(4) == 0 {
                        rng.below(256) as u8
                    } else {
                        rng.below(24) as u8
                    };
                    let id = if rng.below(8) == 0 {
                        0xFE | rng.below(2) as u8
                    } else {
                        id
                    };
                    let len = sizes[rng.below(sizes.len() as u64) as usize];
                    for b in buf.iter_mut().take(len) {
                        // Mostly small values, so states and lengths look plausible.
                        *b = if rng.below(2) == 0 {
                            rng.below(4) as u8
                        } else {
                            rng.next() as u8
                        };
                    }
                    if let Some(p) = s.on_packet(id, &buf[..len], now) {
                        assert!(p.payload.len() <= len);
                    }
                }
                6 => s.poll(now),
                7 => match rng.below(3) {
                    0 => s.on_relay_open(now),
                    1 => s.on_relay_closed(now),
                    _ => s.poll(now + LINK_TIMEOUT_MS),
                },
                _ => {
                    let net = NetworkInfo::read_from_bytes(&buf[..1152]).unwrap();
                    let cfg = network_config(rng.below(3) as u16);
                    let (sec, user) = (SecurityConfig::new_zeroed(), UserConfig::new_zeroed());
                    let _ = match rng.below(16) {
                        0 => s.initialize().map(|_| ()),
                        1 => {
                            s.finalize(now);
                            Ok(())
                        }
                        2 => s.open_access_point(now),
                        3 => s.open_station(now),
                        4 => s.close_access_point(now),
                        5 => s.close_station(now),
                        6 => s.create_network(&sec, &user, &cfg, now).map(|_| ()),
                        7 => s.connect(&sec, &user, 0, 0, &net, now).map(|_| ()),
                        8 => s.scan(&ScanFilterFull::new_zeroed(), now).map(|_| ()),
                        9 => s.reject(1, now).map(|_| ()),
                        10 => s.destroy_network(now),
                        11 => s.disconnect(now),
                        12 => {
                            s.set_advertise_data(&buf[..rng.below(500) as usize]);
                            Ok(())
                        }
                        13 => {
                            let _ = s.get_network_info_latest_update(rng.below(12) as usize);
                            Ok(())
                        }
                        _ => {
                            let _ = s.take_reply();
                            Ok(())
                        }
                    };
                }
            }
            let _ = drain(&mut s);
            check_invariants(&s);
            assert!(
                s.local_node_id() == 0xFF || usize::from(s.local_node_id()) < NODE_COUNT_MAX,
                "round {round}"
            );
        }
    }
}

/// With `Conn` doing Initialize, the session must not send a second one and goes
/// straight to Ready, releasing the request that waited for the link.
#[test]
fn relay_ready_skips_the_handshake() {
    let mut s = Session::new(PROGRAM_ID);
    s.initialize().unwrap();
    s.open_access_point(0).unwrap();
    assert!(has(&drain(&mut s), &Action::RelayConnect));
    let Pending = s
        .create_network(&SecurityConfig::new_zeroed(), &UserConfig::new_zeroed(), &network_config(3), 5)
        .unwrap();
    assert!(drain(&mut s).is_empty());
    s.on_relay_ready(10, [7; 16], [2, 0, 0x5E, 1, 2, 3]);
    let ids: StdVec<_> = sends(&drain(&mut s)).into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, [PacketId::CreateAccessPoint]);
    assert!(s.is_relay_ready());
    // not connecting any more: ignored
    s.on_relay_ready(11, [8; 16], [0; 6]);
    assert!(drain(&mut s).iter().all(|a| matches!(a, Action::Log { .. })));
}

// ---- parity review: C++ behaviour kept, and C++ bugs the port fixes on purpose ----

/// C++/Ryujinx: a Reject carrying reason 0 (None) is no reason, so the Disconnect
/// that follows reports the room-lost default, not None.
#[test]
fn reject_reason_none_falls_back_to_default() {
    let mut s = joined();
    let zero = RejectRequest {
        node_id: 1,
        disconnect_reason: 0,
    };
    packet(&mut s, PacketId::Reject, zero.as_bytes(), 100);
    packet(&mut s, PacketId::Disconnect, &[0; 4], 110);
    assert_eq!(s.get_disconnect_reason(), DisconnectReason::DestroyedByUser);

    let mut s = hosting();
    packet(&mut s, PacketId::Reject, zero.as_bytes(), 100);
    packet(&mut s, PacketId::Disconnect, &[0; 4], 110);
    assert_eq!(
        s.get_disconnect_reason(),
        DisconnectReason::DestroyedBySystem
    );
}

/// Fixed C++ bug: its idle timer could fire during a Scan (Scan does not disable
/// it) and drop the link under the request. Here a pending request holds the link.
#[test]
fn idle_timeout_waits_for_a_pending_scan() {
    let mut s = joined();
    s.disconnect(0).unwrap();
    drain(&mut s);
    let Pending = s
        .scan(&ScanFilterFull::new_zeroed(), IDLE_TIMEOUT_MS - 10)
        .unwrap();
    drain(&mut s);
    s.poll(IDLE_TIMEOUT_MS);
    assert!(!has(&drain(&mut s), &Action::RelayDisconnect));
    assert!(s.is_relay_ready());
    packet(&mut s, PacketId::ScanReplyEnd, &[], IDLE_TIMEOUT_MS + 5);
    assert_eq!(s.take_reply(), Some(Ok(())));
    assert_eq!(s.next_deadline(), Some(2 * IDLE_TIMEOUT_MS + 5), "re-armed");
}

/// Deliberate: channel 0 becomes 6 in scan results too (C++ fixes it only in
/// Connected, and a later SyncNetwork put 0 back there; see sync_network_updates_nodes).
#[test]
fn scan_results_get_the_channel_fix() {
    let mut s = session_in(Session::open_station);
    let Pending = s.scan(&ScanFilterFull::new_zeroed(), 0).unwrap();
    drain(&mut s);
    packet(&mut s, PacketId::ScanReply, room(&[OTHER_IP]).as_bytes(), 1);
    packet(&mut s, PacketId::ScanReplyEnd, &[], 2);
    assert_eq!({ s.scan_results()[0].common.channel }, 6);
}

/// Fixed C++ bug: its GetIpv4Address returned the previous link's ProxyConfig
/// after a reconnect (m_proxy_config was never cleared). Here the virtual IP
/// lives and dies with the link; the next ProxyConfig sets it again.
#[test]
fn virtual_ip_does_not_survive_a_reconnect() {
    let mut s = joined();
    s.on_relay_closed(10);
    s.poll(10 + RESUME_MS); // not resumed: the room and the link are gone
    drain(&mut s);
    assert_eq!(s.get_ipv4_address(), None);
    let t = 20 + RESUME_MS;
    let Pending = s.scan(&ScanFilterFull::new_zeroed(), t).unwrap();
    assert!(has(&drain(&mut s), &Action::RelayConnect));
    s.on_relay_ready(t + 10, [7; 16], [9; 6]);
    drain(&mut s);
    assert_eq!(s.get_ipv4_address(), None, "nifm until a new ProxyConfig");
    packet(&mut s, PacketId::ProxyConfig, &proxy_config(), t + 20);
    assert_eq!(s.get_ipv4_address(), Some((MY_IP, MASK)));
}

// ---------------------------------------------------------------- resume

/// The Resume a session sends on its new link: old link id (7s from `handshake`) + room id.
fn resume_payload(room_id: [u8; 16]) -> StdVec<u8> {
    let mut v = vec![7; 16];
    v.extend_from_slice(&room_id);
    v
}

/// The relay cut the link mid-race (hardware: Cloudflare closes the socket under us). The
/// game sees nothing: same state, same IP, no StateChanged; the new link resumes the room.
#[test]
fn a_dropped_link_resumes_the_room_without_the_game_noticing() {
    for host in [true, false] {
        let mut s = if host { hosting() } else { joined() };
        let state = s.state();
        let room_id = s.network_info().network_id.session_id.data;
        s.on_relay_closed(100);
        let out = drain(&mut s);
        assert!(has(&out, &Action::RelayConnect), "{out:?}");
        assert!(!has(&out, &Action::StateChanged) && !has(&out, &Action::RelayDisconnect), "{out:?}");
        assert!(s.is_resuming());
        assert_eq!((s.state(), s.get_ipv4_address()), (state, Some((MY_IP, MASK))));
        assert_eq!(s.next_deadline(), Some(100 + RESUME_MS));

        // A failed attempt is retried within the same window.
        s.on_relay_closed(300);
        assert!(has(&drain(&mut s), &Action::RelayConnect));
        assert_eq!(s.next_deadline(), Some(100 + RESUME_MS), "window not extended");

        s.on_relay_ready(1500, [8; 16], [9; 6]);
        assert_eq!(sends(&drain(&mut s)), [(PacketId::Resume, resume_payload(room_id))]);
        packet(&mut s, PacketId::ProxyConfig, &proxy_config(), 1510);
        let out = packet(&mut s, PacketId::Connected, room(&[OTHER_IP, MY_IP]).as_bytes(), 1520);
        assert!(!has(&out, &Action::ReplyReady), "no request was pending");
        assert!(!s.is_resuming());
        assert_eq!(s.state(), state);
        assert_eq!(s.get_disconnect_reason(), DisconnectReason::None);
        s.poll(100 + RESUME_MS);
        assert_eq!(s.state(), state, "the window is over");
        // The next drop resumes against the new link's id.
        s.on_relay_closed(2000);
        s.on_relay_ready(2100, [9; 16], [9; 6]);
        let resume = sends(&drain(&mut s));
        assert_eq!(resume[0].1[..16], [8; 16]);
    }
}

#[test]
fn a_room_the_relay_no_longer_holds_is_lost() {
    let mut s = joined();
    s.on_relay_closed(100);
    s.on_relay_ready(200, [8; 16], [9; 6]);
    drain(&mut s);
    let out = packet(&mut s, PacketId::NetworkError, &error(6), 210);
    assert!(!s.is_resuming());
    assert_eq!(s.state(), CommState::Station);
    assert_eq!(s.get_disconnect_reason(), DisconnectReason::DestroyedByUser);
    assert!(has(&out, &Action::RelayDisconnect), "proxies reset, as a plain link loss did");
    assert_eq!(s.get_ipv4_address(), None);
}

#[test]
fn leaving_during_a_resume_cancels_it() {
    let mut s = joined();
    s.on_relay_closed(100);
    drain(&mut s);
    s.disconnect(150).unwrap();
    assert!(!s.is_resuming());
    s.on_relay_ready(200, [8; 16], [9; 6]);
    assert!(sends(&drain(&mut s)).is_empty(), "no Resume for a room we left");
}
