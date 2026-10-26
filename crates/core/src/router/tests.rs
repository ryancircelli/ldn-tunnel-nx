#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::panic)]

use super::bsd::*;
use super::ports::{EPHEMERAL_MIN, PortPool};
use super::ring::{Meta, PacketRing};
use super::*;

const ME: u32 = 0x0A72_0001; // 10.114.0.1
const PEER: u32 = 0x0A72_0002;
const BCAST: u32 = 0x0A72_FFFF;
const UDP: i32 = 17;

fn key(fd: i32) -> SocketKey {
    socket_key(1, fd)
}

fn router() -> Router {
    let mut r = Router::new();
    r.set_proxy_config(ME, 0xFFFF_0000);
    r
}

fn udp(r: &mut Router, fd: i32) {
    assert!(r.on_socket(key(fd), 2, SOCK_DGRAM, 0));
}

fn bound(r: &mut Router, fd: i32, ip: u32, port: u16) {
    udp(r, fd);
    let want = if ip == 0 { Decision::ReplyAndForward(0) } else { Decision::Reply(0) };
    assert_eq!(r.on_bind(key(fd), &SockAddrIn::from_ryujinx(ip, port), false), want);
}

fn data(src: u32, sport: u16, dst: u32, dport: u16, payload: &[u8]) -> ProxyDataHeader {
    ProxyDataHeader {
        info: ProxyInfo { source_ipv4: src, source_port: sport, dest_ipv4: dst, dest_port: dport, protocol: UDP },
        data_length: payload.len() as u32,
    }
}

fn deliver(r: &mut Router, src: u32, dst: u32, dport: u16, payload: &[u8]) -> usize {
    r.on_proxy_data(&data(src, 4000, dst, dport, payload), payload)
}

fn recv(r: &mut Router, fd: i32) -> Option<(heapless::Vec<u8, 64>, SockAddrIn)> {
    let mut buf = [0u8; 64];
    match r.on_recvfrom(key(fd), &mut buf, MSG_DONTWAIT) {
        RecvDecision::Data { len, from } => Some((heapless::Vec::from_slice(&buf[..len]).unwrap(), from)),
        RecvDecision::Reply(e) if e == -errno::EAGAIN => None,
        other => panic!("{other:?}"),
    }
}

// ---- byte order ---------------------------------------------------------

#[test]
fn sockaddr_byte_order_round_trip() {
    let a = SockAddrIn::from_ryujinx(ME, 8000);
    // 10.114.0.1:8000 as the game lays it out in memory.
    assert_eq!(a.as_bytes(), &[16, 2, 0x1F, 0x40, 10, 114, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0][..]);
    assert_eq!(a.addr_ryujinx(), ME);
    assert_eq!(a.port(), 8000);
    assert_eq!(SockAddrIn::from_bytes(a.as_bytes()), Some(a));
    assert_eq!(SockAddrIn::from_bytes(&a.as_bytes()[..15]), None);
    let mut v6 = [0u8; 16];
    v6.copy_from_slice(a.as_bytes());
    v6[1] = 28;
    assert_eq!(SockAddrIn::from_bytes(&v6), None);
}

#[test]
fn explicit_ldn_bind_sends_with_its_own_ip() {
    let mut r = router();
    bound(&mut r, 3, PEER, 8000);
    let dest = SockAddrIn::from_ryujinx(0x0A72_0003, 9000);
    let Decision::Emit { header, payload } = r.on_sendto(key(3), b"x", Some(&dest)) else { panic!() };
    let info = header.info;
    assert_eq!((info.source_ipv4, info.source_port, info.dest_ipv4, info.dest_port), (PEER, 8000, 0x0A72_0003, 9000));
    assert_eq!((info.protocol, { header.data_length }, payload), (UDP, 1, &b"x"[..]));
}

#[test]
fn inaddr_any_bind_uses_session_ip_and_also_binds_real() {
    let mut r = router();
    udp(&mut r, 3);
    assert_eq!(r.on_bind(key(3), &SockAddrIn::from_ryujinx(0, 8001), false), Decision::ReplyAndForward(0));
    let local = r.on_getsockname(key(3)).unwrap();
    assert_eq!((local.addr_ryujinx(), local.port()), (ME, 8001));
    assert_eq!(local.sin_addr.to_ne_bytes(), [10, 114, 0, 1]); // network order
}

#[test]
fn socket_bound_without_ip_sends_with_session_ip() {
    let mut r = Router::new(); // no session yet
    udp(&mut r, 3);
    let dest = SockAddrIn::from_ryujinx(BCAST, 9000);
    assert!(matches!(r.on_sendto(key(3), b"x", Some(&dest)), Decision::Emit { .. }));
    r.set_proxy_config(0x0A72_0005, 0xFFFF_0000);
    let Decision::Emit { header, .. } = r.on_sendto(key(3), b"x", Some(&dest)) else { panic!() };
    assert_eq!({ header.info.source_ipv4 }, 0x0A72_0005);
}

#[test]
fn recvfrom_reports_source_in_network_order() {
    let mut r = router();
    bound(&mut r, 3, ME, 8002);
    deliver(&mut r, PEER, ME, 8002, b"u");
    let (d, from) = recv(&mut r, 3).unwrap();
    assert_eq!(&d[..], b"u");
    assert_eq!((from.addr_ryujinx(), from.port(), from.sin_len, from.sin_family), (PEER, 4000, 16, AF_INET));
}

// ---- which calls are proxied --------------------------------------------

#[test]
fn bind_rules() {
    let mut r = Router::new();
    udp(&mut r, 1);
    // INADDR_ANY is proxied only during a session.
    assert_eq!(r.on_bind(key(1), &SockAddrIn::from_ryujinx(0, 1000), false), Decision::Forward);
    // Non-LDN addresses never.
    r.set_proxy_config(ME, 0xFFFF_0000);
    assert_eq!(r.on_bind(key(1), &SockAddrIn::from_ryujinx(0xC0A8_0105, 1000), false), Decision::Forward);
    // ZR real-radio: INADDR_ANY stays real, 10.114.x.y is still proxied.
    assert_eq!(r.on_bind(key(1), &SockAddrIn::from_ryujinx(0, 1000), true), Decision::Forward);
    assert_eq!(r.on_bind(key(1), &SockAddrIn::from_ryujinx(ME, 1000), true), Decision::Reply(0));
    // Binding twice is EINVAL.
    assert_eq!(r.on_bind(key(1), &SockAddrIn::from_ryujinx(ME, 1001), false), Decision::Reply(-errno::EINVAL));
    // TCP and untracked fds are left alone.
    assert!(r.on_socket(key(2), 2, SOCK_STREAM, 0));
    assert_eq!(r.on_bind(key(2), &SockAddrIn::from_ryujinx(ME, 1002), false), Decision::Forward);
    assert_eq!(r.on_bind(key(9), &SockAddrIn::from_ryujinx(ME, 1003), false), Decision::Forward);
    // Other families are not tracked.
    assert!(!r.on_socket(key(4), 28, SOCK_DGRAM, 0));
}

#[test]
fn proxy_destinations() {
    assert!(is_proxy_destination(0x0A72_0001));
    assert!(is_proxy_destination(0x0A72_FFFF));
    assert!(is_proxy_destination(0xFFFF_FFFF));
    assert!(is_proxy_destination(0xC0A8_00FF));
    assert!(!is_proxy_destination(0x0808_0808));
    assert!(!is_proxy_destination(0x0A00_0001));
}

#[test]
fn sendto_auto_binds_and_internet_goes_real() {
    let mut r = router();
    udp(&mut r, 3);
    // Internet traffic from a plain fd: real.
    assert_eq!(r.on_sendto(key(3), b"x", Some(&SockAddrIn::from_ryujinx(0x0808_0808, 53))), Decision::Forward);
    // First LDN send: auto-bound to an ephemeral port.
    let Decision::Emit { header, .. } = r.on_sendto(key(3), b"x", Some(&SockAddrIn::from_ryujinx(PEER, 9000))) else { panic!() };
    assert!(header.info.source_port >= EPHEMERAL_MIN);
    // Internet traffic from the now-proxied fd still goes real.
    assert_eq!(r.on_sendto(key(3), b"x", Some(&SockAddrIn::from_ryujinx(0x0808_0808, 53))), Decision::Forward);
    // No address and not connected.
    assert_eq!(r.on_sendto(key(3), b"x", None), Decision::Reply(-errno::ENOTCONN));
    assert_eq!(r.on_send(key(3), b"x"), Decision::Reply(-errno::ENOTCONN));
    // Untracked fd.
    assert_eq!(r.on_send(key(7), b"x"), Decision::Forward);
}

#[test]
fn connect_sets_default_destination() {
    let mut r = router();
    udp(&mut r, 3);
    let peer = SockAddrIn::from_ryujinx(PEER, 9000);
    assert_eq!(r.on_connect(key(3), &SockAddrIn::from_ryujinx(0x0808_0808, 53)), Decision::Forward);
    assert_eq!(r.on_connect(key(3), &peer), Decision::Reply(0));
    assert_eq!(r.on_getpeername(key(3)), Some(Ok(peer)));
    let Decision::Emit { header, .. } = r.on_send(key(3), b"hi") else { panic!() };
    assert_eq!(({ header.info.dest_ipv4 }, { header.info.dest_port }), (PEER, 9000));
    assert!(matches!(r.on_sendto(key(3), b"hi", None), Decision::Emit { .. }));
    // TCP connect to LDN fails fast.
    assert!(r.on_socket(key(4), 2, SOCK_STREAM, 6));
    assert_eq!(r.on_connect(key(4), &peer), Decision::Reply(-errno::ENETUNREACH));
}

#[test]
fn send_limits() {
    let mut r = router();
    bound(&mut r, 3, ME, 8000);
    let dest = SockAddrIn::from_ryujinx(PEER, 9000);
    let big = [0u8; MAX_PAYLOAD + 1];
    assert_eq!(r.on_sendto(key(3), &big, Some(&dest)), Decision::Reply(-errno::EMSGSIZE));
    assert!(matches!(r.on_sendto(key(3), &big[..MAX_PAYLOAD], Some(&dest)), Decision::Emit { .. }));
    assert_eq!(r.on_shutdown(key(3), SHUT_WR), Decision::Reply(0));
    assert_eq!(r.on_sendto(key(3), b"x", Some(&dest)), Decision::Reply(-errno::EINVAL));
}

// ---- incoming routing ---------------------------------------------------

#[test]
fn pia_mesh_broadcast_reaches_every_socket_on_the_port() {
    let mut r = router();
    bound(&mut r, 3, ME, 12345);
    udp(&mut r, 4);
    assert_eq!(r.on_bind(key(4), &SockAddrIn::from_ryujinx(0, 12345), false), Decision::ReplyAndForward(0));
    bound(&mut r, 5, ME, 12346); // other port
    assert_eq!(deliver(&mut r, PEER, BCAST, 12345, b"disc"), 2);
    assert_eq!(&recv(&mut r, 3).unwrap().0[..], b"disc");
    assert_eq!(&recv(&mut r, 4).unwrap().0[..], b"disc");
    assert!(recv(&mut r, 5).is_none());
    // Limited and legacy broadcasts fan out too.
    assert_eq!(deliver(&mut r, PEER, 0xFFFF_FFFF, 12345, b"l"), 2);
    assert_eq!(deliver(&mut r, PEER, 0xC0A8_00FF, 12345, b"g"), 2);
}

#[test]
fn unicast_is_exact_match() {
    let mut r = router();
    bound(&mut r, 3, ME, 8002);
    bound(&mut r, 4, PEER, 8002); // a second LDN IP on the same port
    assert_eq!(deliver(&mut r, 0x0A72_0003, ME, 8002, b"u"), 1);
    assert_eq!(&recv(&mut r, 3).unwrap().0[..], b"u");
    assert!(recv(&mut r, 4).is_none());
    // Other IP / other port: no socket (goes pending).
    assert_eq!(deliver(&mut r, 0x0A72_0003, 0x0A72_0009, 8002, b"o"), 0);
    assert_eq!(deliver(&mut r, 0x0A72_0003, ME, 8003, b"o"), 0);
    assert_eq!(r.stats().pending, 2);
}

#[test]
fn malformed_proxy_data_is_dropped() {
    let mut r = router();
    bound(&mut r, 3, ME, 8000);
    let mut h = data(PEER, 1, ME, 8000, b"abc");
    assert_eq!(r.on_proxy_data(&h, b"ab"), 0); // length mismatch
    h.info.protocol = 6;
    assert_eq!(r.on_proxy_data(&h, b"abc"), 0); // TCP
    let big = [0u8; MAX_PAYLOAD + 1];
    assert_eq!(r.on_proxy_data(&data(PEER, 1, ME, 8000, &big), &big), 0);
    assert_eq!(r.stats().dropped, 3);
    assert!(recv(&mut r, 3).is_none());
}

#[test]
fn ring_overflow_drops_oldest() {
    let mut r = router();
    bound(&mut r, 3, ME, 8000);
    let frame = [7u8; 1460];
    for i in 0..20u8 {
        let mut f = frame;
        f[0] = i;
        assert_eq!(deliver(&mut r, PEER, ME, 8000, &f), 1);
    }
    // 16 KB holds 11 records of 1474 bytes: the newest 11 survive, in order.
    assert_eq!(r.stats().evicted, 9);
    let mut buf = [0u8; 1460];
    for i in 9..20u8 {
        assert!(matches!(r.on_recvfrom(key(3), &mut buf, MSG_DONTWAIT), RecvDecision::Data { len: 1460, .. }));
        assert_eq!(buf[0], i);
    }
    assert!(recv(&mut r, 3).is_none());
}

#[test]
fn pending_datagrams_reach_the_socket_that_binds_later() {
    let mut r = router();
    deliver(&mut r, PEER, ME, 7000, b"one");
    deliver(&mut r, PEER, ME, 7001, b"other");
    deliver(&mut r, PEER, BCAST, 7000, b"two");
    bound(&mut r, 3, ME, 7000);
    assert_eq!(&recv(&mut r, 3).unwrap().0[..], b"one");
    assert_eq!(&recv(&mut r, 3).unwrap().0[..], b"two");
    assert!(recv(&mut r, 3).is_none());
    bound(&mut r, 4, 0, 7001);
    assert_eq!(&recv(&mut r, 4).unwrap().0[..], b"other");
}

// ---- receive semantics --------------------------------------------------

#[test]
fn recv_blocking_peek_truncate_shutdown() {
    let mut r = router();
    bound(&mut r, 3, ME, 8000);
    let mut buf = [0u8; 3];
    assert_eq!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Wait { limit_ns: MAX_BLOCK_NS });
    let mut tv = [0u8; 16];
    tv[8..].copy_from_slice(&60_000i64.to_le_bytes()); // 60 ms
    assert_eq!(r.on_setsockopt(key(3), SOL_SOCKET, SO_RCVTIMEO, &tv), Decision::Reply(0));
    assert_eq!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Wait { limit_ns: 60_000_000 });
    assert_eq!(r.on_recvfrom(key(3), &mut buf, MSG_DONTWAIT), RecvDecision::Reply(-errno::EAGAIN));
    r.on_fcntl(key(3), F_SETFL, O_NONBLOCK);
    assert_eq!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Reply(-errno::EAGAIN));

    deliver(&mut r, PEER, ME, 8000, b"abcdef");
    deliver(&mut r, PEER, ME, 8000, b"xy");
    assert_eq!(r.on_ioctl(key(3), FIONREAD, None), Some(8));
    assert_eq!(r.poll_state(key(3)), PollState::Proxy { readable: true });
    assert!(matches!(r.on_recvfrom(key(3), &mut buf, MSG_PEEK), RecvDecision::Data { len: 3, .. }));
    assert!(matches!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Data { len: 3, .. }));
    assert_eq!(&buf, b"abc");
    assert!(matches!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Data { len: 2, .. }));
    assert_eq!(r.poll_state(key(3)), PollState::Proxy { readable: false });
    // recv() needs a connected socket.
    assert_eq!(r.on_recv(key(3), &mut buf, 0), RecvDecision::Reply(-errno::ENOTCONN));
    assert_eq!(r.on_shutdown(key(3), SHUT_RD), Decision::Reply(0));
    assert_eq!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Reply(0));
    assert_eq!(r.poll_state(key(3)), PollState::Proxy { readable: true });
    assert_eq!(r.on_shutdown(key(3), 7), Decision::Reply(-errno::EINVAL));
}

#[test]
fn options_set_before_the_proxy_carry_over() {
    let mut r = router();
    assert!(r.on_socket(key(3), 2, SOCK_DGRAM | SOCK_NONBLOCK, 0));
    assert_eq!(r.on_setsockopt(key(3), SOL_SOCKET, SO_BROADCAST, &1i32.to_le_bytes()), Decision::Forward);
    assert_eq!(r.on_bind(key(3), &SockAddrIn::from_ryujinx(ME, 8000), false), Decision::Reply(0));
    let mut buf = [0u8; 4];
    assert_eq!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Reply(-errno::EAGAIN));
    assert_eq!(r.on_getsockopt(key(3), SOL_SOCKET, SO_BROADCAST), Some(Ok(1)));
    assert_eq!(r.on_getsockopt(key(3), SOL_SOCKET, SO_TYPE), Some(Ok(SOCK_DGRAM)));
    assert_eq!(r.on_getsockopt(key(3), SOL_SOCKET, SO_ERROR), Some(Ok(0)));
    assert_eq!(r.on_getsockopt(key(3), 0, 1), Some(Err(errno::ENOPROTOOPT)));
    // FIONBIO clears it again and is still forwarded.
    assert_eq!(r.on_ioctl(key(3), FIONBIO, Some(0)), None);
    assert!(matches!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Wait { .. }));
    // On a proxy: short values are EINVAL, unknown options accepted.
    assert_eq!(r.on_setsockopt(key(3), SOL_SOCKET, SO_BROADCAST, &[1]), Decision::Reply(-errno::EINVAL));
    assert_eq!(r.on_setsockopt(key(3), SOL_SOCKET, 0x0004, &1i32.to_le_bytes()), Decision::Reply(0));
    // Non-proxy fds forward everything.
    assert_eq!(r.on_getsockopt(key(9), SOL_SOCKET, SO_TYPE), None);
    assert_eq!(r.on_getsockname(key(9)), None);
    assert_eq!(r.on_ioctl(key(9), FIONREAD, None), None);
}

// ---- lifetime -----------------------------------------------------------

#[test]
fn close_frees_everything() {
    let mut r = router();
    bound(&mut r, 3, ME, 50000);
    deliver(&mut r, PEER, ME, 50000, b"x");
    assert!(r.on_close(key(3)));
    assert_eq!(r.proxy_count(), 0);
    assert_eq!(r.poll_state(key(3)), PollState::Real);
    assert_eq!(r.on_send(key(3), b"x"), Decision::Forward);
    // Port 50000 is free again and the new socket starts with an empty ring.
    bound(&mut r, 3, ME, 50000);
    assert!(recv(&mut r, 3).is_none());
    assert!(!r.on_close(key(8)));
}

#[test]
fn proxy_count_is_capped() {
    let mut r = router();
    for fd in 0..MAX_PROXY_SOCKETS as i32 {
        bound(&mut r, fd, ME, 0);
    }
    udp(&mut r, 99);
    assert_eq!(r.on_bind(key(99), &SockAddrIn::from_ryujinx(ME, 0), false), Decision::Reply(-errno::ENOMEM));
    assert_eq!(r.on_getsockname(key(99)), None);
    r.on_close(key(0));
    assert_eq!(r.on_bind(key(99), &SockAddrIn::from_ryujinx(ME, 0), false), Decision::Reply(0));
}

#[test]
fn ephemeral_port_in_use_is_eaddrinuse() {
    let mut r = router();
    bound(&mut r, 3, ME, 50000);
    udp(&mut r, 4);
    assert_eq!(r.on_bind(key(4), &SockAddrIn::from_ryujinx(ME, 50000), false), Decision::Reply(-errno::EADDRINUSE));
    assert_eq!(r.proxy_count(), 1); // nothing left behind
}

#[test]
fn reset_makes_proxied_fds_fail_with_enetdown() {
    let mut r = router();
    bound(&mut r, 3, ME, 50000);
    udp(&mut r, 4);
    r.reset();
    assert_eq!(r.local_ip(), 0);
    assert_eq!(r.proxy_count(), 0);
    let mut buf = [0u8; 4];
    assert_eq!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Reply(-errno::ENETDOWN));
    assert_eq!(r.on_send(key(3), b"x"), Decision::Reply(-errno::ENETDOWN));
    assert_eq!(r.on_sendto(key(3), b"x", Some(&SockAddrIn::from_ryujinx(PEER, 1))), Decision::Reply(-errno::ENETDOWN));
    assert_eq!(r.poll_state(key(3)), PollState::Gone);
    assert_eq!(r.poll_state(key(4)), PollState::Real);
    // Ports were released.
    r.set_proxy_config(ME, 0xFFFF_0000);
    bound(&mut r, 5, ME, 50000);
}

#[test]
fn same_fd_in_two_sessions_is_two_sockets() {
    assert_ne!(socket_key(1, 0), socket_key(2, 0));
    assert_eq!(socket_key(1, 5) & 0xFFFF_FFFF, 5);
    let mut r = router();
    for s in [1, 2] {
        assert!(r.on_socket(socket_key(s, 0), 2, SOCK_DGRAM, 0));
        assert_eq!(r.on_bind(socket_key(s, 0), &SockAddrIn::from_ryujinx(ME, 0), false), Decision::Reply(0));
    }
    assert_eq!(r.proxy_count(), 2);
    r.on_close(socket_key(2, 0));
    assert!(r.on_getsockname(socket_key(1, 0)).is_some());
}

#[test]
fn tracked_table_is_bounded() {
    let mut r = router();
    for fd in 0..MAX_TRACKED_SOCKETS as i32 {
        udp(&mut r, fd);
    }
    assert!(!r.on_socket(key(1000), 2, SOCK_DGRAM, 0)); // full: stays a real socket
    assert_eq!(r.on_bind(key(1000), &SockAddrIn::from_ryujinx(ME, 1), false), Decision::Forward);
    r.on_close(key(0));
    assert!(r.on_socket(key(1000), 2, SOCK_DGRAM, 0));
}

#[test]
fn closed_session_frees_its_fds_and_proxies() {
    let mut r = router();
    // Session 1 (a game that exits without closing) fills the tracked table.
    for fd in 0..MAX_TRACKED_SOCKETS as i32 {
        assert!(r.on_socket(socket_key(1, fd), 2, SOCK_DGRAM, 0));
    }
    assert_eq!(r.on_bind(socket_key(1, 0), &SockAddrIn::from_ryujinx(ME, 50000), false), Decision::Reply(0));
    assert!(!r.on_socket(socket_key(2, 0), 2, SOCK_DGRAM, 0));
    r.on_session_closed(1);
    assert_eq!(r.proxy_count(), 0);
    // The next game's sockets are tracked and its port is free again.
    assert!(r.on_socket(socket_key(2, 0), 2, SOCK_DGRAM, 0));
    assert_eq!(r.on_bind(socket_key(2, 0), &SockAddrIn::from_ryujinx(ME, 50000), false), Decision::Reply(0));
    // Another session's sockets are left alone.
    r.on_session_closed(3);
    assert_eq!(r.proxy_count(), 1);
}

/// C++ `ProxySocket::SetSockOpt` falls through from SO_REUSEADDR..SO_RCVLOWAT
/// into the SO_RCVTIMEO case: an int value is EINVAL and a 16-byte one sets
/// the receive timeout. A real socket accepts them; so does the router.
#[test]
fn int_socket_options_on_a_proxy_succeed_and_leave_the_timeout_alone() {
    let mut r = router();
    bound(&mut r, 3, ME, 8000);
    for name in [0x0004, 0x0008, 0x0200, 0x1001, 0x1002, 0x1003, 0x1004] {
        assert_eq!(r.on_setsockopt(key(3), SOL_SOCKET, name, &1i32.to_le_bytes()), Decision::Reply(0), "{name:#x}");
    }
    let mut tv = [0u8; 16];
    tv[8..].copy_from_slice(&60_000i64.to_le_bytes());
    assert_eq!(r.on_setsockopt(key(3), SOL_SOCKET, 0x1002, &tv), Decision::Reply(0));
    let mut buf = [0u8; 4];
    assert_eq!(r.on_recvfrom(key(3), &mut buf, 0), RecvDecision::Wait { limit_ns: MAX_BLOCK_NS });
}

/// C++ only fans a broadcast out to sockets in the destination's /16, so the
/// relay's 192.168.0.255 (sent to everyone, destination kept) never reached a
/// socket bound to 10.114.x.x. The router gives it to every socket on the port.
#[test]
fn legacy_broadcast_reaches_sockets_bound_to_the_ldn_ip() {
    let mut r = router();
    bound(&mut r, 3, ME, 12345);
    assert_eq!(deliver(&mut r, PEER, 0xC0A8_00FF, 12345, b"g"), 1);
    assert_eq!(&recv(&mut r, 3).unwrap().0[..], b"g");
}

// ---- building blocks ----------------------------------------------------

#[test]
fn port_pool_exhaustion_and_reuse() {
    let mut p = PortPool::new();
    assert_eq!(p.allocate(), Some(EPHEMERAL_MIN));
    assert_eq!(p.allocate(), Some(EPHEMERAL_MIN + 1)); // round robin
    p.release(EPHEMERAL_MIN);
    assert_eq!(p.allocate(), Some(EPHEMERAL_MIN + 2)); // hint moves on
    assert!(!p.reserve(EPHEMERAL_MIN + 1));
    assert!(p.reserve(12345) && p.reserve(12345)); // below the range: untracked
    while p.allocate().is_some() {}
    assert_eq!(p.available(), 0);
    assert!(!p.reserve(65535));
    p.release(60000);
    assert_eq!(p.allocate(), Some(60000));
    p.release_all();
    assert_eq!(p.available(), 16384);
}

#[test]
fn packet_ring_wraps_and_drops_oldest() {
    let mut ring = PacketRing::<64>::new();
    let payload: [u8; 20] = core::array::from_fn(|i| b'a' + i as u8);
    // 23-byte records (14 + 9) straddle the end of 64 bytes.
    for i in 0..10u16 {
        assert!(ring.push(Meta { src_port: i, ..Meta::default() }, &payload[i as usize..][..9]).is_some());
    }
    assert_eq!(ring.count(), 2);
    let mut buf = [0u8; 16];
    for i in 8..10u16 {
        let (len, meta) = ring.front(&mut buf).unwrap();
        assert_eq!((len, meta.src_port), (9, i));
        assert_eq!(&buf[..9], &payload[i as usize..][..9]);
        assert!(ring.pop());
    }
    assert!(ring.is_empty() && ring.payload_bytes() == 0 && !ring.pop());
    assert!(ring.push(Meta::default(), b"x").is_some());
    assert_eq!(ring.push(Meta::default(), &[0; 51]), None); // can never fit: nothing evicted
    assert_eq!(ring.count(), 1);
}

#[test]
fn memory_footprint() {
    // 145,232 bytes on x86_64 / aarch64.
    assert!(size_of::<Router>() <= ROUTER_SIZE_BOUND, "{}", size_of::<Router>());
    assert!(size_of::<ProxySocket>() <= 16 * 1024 + 512, "{}", size_of::<ProxySocket>());
}

#[test]
fn timeval_ns_saturates() {
    let tv = |s: i64, u: i64| {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&s.to_le_bytes());
        b[8..].copy_from_slice(&u.to_le_bytes());
        timeval_ns(&b)
    };
    assert_eq!(tv(1, 500_000), Some(1_500_000_000));
    assert_eq!(tv(-1, 0), Some(0));
    assert_eq!(tv(i64::MAX, 0), Some(i64::MAX));
    assert_eq!(timeval_ns(&[0; 15]), None);
}

/// Random headers and payloads: no panic, and the invariants hold.
#[test]
fn random_proxy_data() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut r = router();
    for fd in 0..4 {
        bound(&mut r, fd, if fd % 2 == 0 { ME } else { 0 }, 7000 + (fd as u16 % 2));
    }
    let mut payload = [0u8; MAX_PAYLOAD + 64];
    for _ in 0..20_000 {
        let mut hb = [0u8; 20];
        hb.iter_mut().for_each(|b| *b = rnd() as u8);
        let mut h = ProxyDataHeader::read_from_bytes(&hb).unwrap();
        // Bias towards valid, matching packets so the rings fill up.
        if rnd() % 2 == 0 {
            h.info.protocol = UDP;
            h.info.dest_port = 7000 + (rnd() % 2) as u16;
            h.info.dest_ipv4 = [ME, BCAST, PEER][(rnd() % 3) as usize];
        }
        let len = (rnd() as usize) % payload.len();
        if rnd() % 2 == 0 {
            h.data_length = len as u32;
        }
        payload[..len].iter_mut().for_each(|b| *b = rnd() as u8);
        let before = r.stats();
        let n = r.on_proxy_data(&h, &payload[..len]);
        assert!(n <= 4);
        let after = r.stats();
        let counted = (after.delivered - before.delivered) + (after.pending - before.pending) + (after.dropped - before.dropped);
        assert_eq!(counted, 1);
        for s in &r.slots {
            assert!(s.rx.payload_bytes() <= RX_BUFFER_SIZE);
        }
        assert!(r.pending.payload_bytes() <= PENDING_BUFFER_SIZE);
        if rnd() % 64 == 0 {
            let mut buf = [0u8; 128];
            let _ = r.on_recvfrom(key((rnd() % 4) as i32), &mut buf, MSG_DONTWAIT);
        }
    }
    assert!(r.stats().evicted > 0 && r.stats().delivered > 0);
}

use zerocopy::{FromBytes, IntoBytes};

