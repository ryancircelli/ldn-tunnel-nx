//! bsd:u as the MitM serves it (crates/sys/src/bsd/ifaces.rs on nx's ServerManager): requests
//! built as libnx's bsd.c sends them (argument structs, auto-select buffers through cmif.h, the
//! process id and transfer memory of RegisterClient), delivered as Horizon's kernel delivers
//! them (`nx::ipc_host::kernel`), checked for the values the handler gets and for the reply
//! (libnx's `struct { int ret; int errno_; [socklen_t len;] } out` and the X descriptors that
//! carry out-buffer data back, at each buffer's receive index). Layouts cross-checked with
//! Ryujinx `Ryujinx.HLE/HOS/Services/Sockets/Bsd/IClient.cs` and Switchbrew "Sockets services".

mod common;

#[path = "../../sys/src/bsd/ifaces.rs"]
#[allow(dead_code)]
mod bsd_ifaces;

use bsd_ifaces::{IBsdMitmServer, LibraryConfig, SelectTimeval};
use common::hipc::{self, Buf, Hipc};
use common::*;
#[allow(unused_imports)]
use common::compat;
use nx::ipc::server::{ISessionObject, ServerContext};
use nx::ipc::sf::{CopyHandle, InAutoSelectBuffer as In, OutAutoSelectBuffer as Out, ProcessId};
use nx::ipc::CommandProtocol;
use nx::result::Result;

/// crates/sys/src/bsd/service.rs POINTER_BUFFER_SIZE.
const P: usize = 0x1000;

/// Logs every call; returns ret 7, errno 0 (and length 9).
struct Rec;

impl ISessionObject for Rec {
    fn try_handle_request_by_id(&mut self, id: u32, p: CommandProtocol, ctx: &mut ServerContext) -> Option<Result<()>> {
        <Self as IBsdMitmServer>::try_handle_request_by_id(self, id, p, ctx)
    }
}

const R: Result<(i32, i32)> = Ok((7, 0));
const RL: Result<(i32, i32, u32)> = Ok((7, 0, 9));

impl IBsdMitmServer for Rec {
    fn register_client(&mut self, c: LibraryConfig, pid: ProcessId, tmem_size: u64, tmem: CopyHandle) -> Result<u64> {
        log(format!("register_client {c:x?} pid={:#x} tmem_size={tmem_size:#x} tmem={:#x}", pid.process_id, tmem.handle));
        Ok(0x1234)
    }
    fn socket(&mut self, d: i32, t: i32, p: i32) -> Result<(i32, i32)> {
        log(format!("socket {d} {t} {p}"));
        R
    }
    fn socket_exempt(&mut self, d: i32, t: i32, p: i32) -> Result<(i32, i32)> {
        log(format!("socket_exempt {d} {t} {p}"));
        R
    }
    fn select(&mut self, nfds: i32, t: SelectTimeval, ri: In<u8>, wi: In<u8>, ei: In<u8>, ro: Out<u8>, wo: Out<u8>, eo: Out<u8>) -> Result<(i32, i32)> {
        log(format!(
            "select {nfds} {}/{}/{} {} {} {} {} {} {}",
            t.sec, t.usec, t.is_null, in_buf(&ri), in_buf(&wi), in_buf(&ei), out_buf(&ro, 0xB0), out_buf(&wo, 0xB1), out_buf(&eo, 0xB2)
        ));
        R
    }
    fn poll(&mut self, nfds: i32, timeout: i32, fds: In<u8>, out: Out<u8>) -> Result<(i32, i32)> {
        log(format!("poll {nfds} {timeout} {} {}", in_buf(&fds), out_buf(&out, 0xB0)));
        R
    }
    fn recv(&mut self, fd: i32, flags: i32, buf: Out<u8>) -> Result<(i32, i32)> {
        log(format!("recv {fd} {flags:#x} {}", out_buf(&buf, 0xB0)));
        R
    }
    fn recv_from(&mut self, fd: i32, flags: i32, buf: Out<u8>, addr: Out<u8>) -> Result<(i32, i32, u32)> {
        log(format!("recv_from {fd} {flags:#x} {} {}", out_buf(&buf, 0xB0), out_buf(&addr, 0xB1)));
        RL
    }
    fn send(&mut self, fd: i32, flags: i32, buf: In<u8>) -> Result<(i32, i32)> {
        log(format!("send {fd} {flags:#x} {}", in_buf(&buf)));
        R
    }
    fn send_to(&mut self, fd: i32, flags: i32, buf: In<u8>, addr: In<u8>) -> Result<(i32, i32)> {
        log(format!("send_to {fd} {flags:#x} {} {}", in_buf(&buf), in_buf(&addr)));
        R
    }
    fn accept(&mut self, fd: i32, addr: Out<u8>) -> Result<(i32, i32, u32)> {
        log(format!("accept {fd} {}", out_buf(&addr, 0xB0)));
        RL
    }
    fn bind(&mut self, fd: i32, addr: In<u8>) -> Result<(i32, i32)> {
        log(format!("bind {fd} {}", in_buf(&addr)));
        R
    }
    fn connect(&mut self, fd: i32, addr: In<u8>) -> Result<(i32, i32)> {
        log(format!("connect {fd} {}", in_buf(&addr)));
        R
    }
    fn get_peer_name(&mut self, fd: i32, addr: Out<u8>) -> Result<(i32, i32, u32)> {
        log(format!("get_peer_name {fd} {}", out_buf(&addr, 0xB0)));
        RL
    }
    fn get_sock_name(&mut self, fd: i32, addr: Out<u8>) -> Result<(i32, i32, u32)> {
        log(format!("get_sock_name {fd} {}", out_buf(&addr, 0xB0)));
        RL
    }
    fn get_sock_opt(&mut self, fd: i32, level: i32, name: i32, v: Out<u8>) -> Result<(i32, i32, u32)> {
        log(format!("get_sock_opt {fd} {level:#x} {name:#x} {}", out_buf(&v, 0xB0)));
        RL
    }
    fn listen(&mut self, fd: i32, backlog: i32) -> Result<(i32, i32)> {
        log(format!("listen {fd} {backlog}"));
        R
    }
    fn ioctl(&mut self, fd: i32, request: u32, bufcount: u32, i1: In<u8>, i2: In<u8>, i3: In<u8>, i4: In<u8>, o1: Out<u8>, o2: Out<u8>, o3: Out<u8>, o4: Out<u8>) -> Result<(i32, i32)> {
        log(format!(
            "ioctl {fd} {request:#x} {bufcount} {} {} {} {} {} {} {} {}",
            in_buf(&i1), in_buf(&i2), in_buf(&i3), in_buf(&i4), out_buf(&o1, 0xB0), out_buf(&o2, 0xB1), out_buf(&o3, 0xB2), out_buf(&o4, 0xB3)
        ));
        R
    }
    fn fcntl(&mut self, fd: i32, cmd: i32, arg: i32) -> Result<(i32, i32)> {
        log(format!("fcntl {fd} {cmd} {arg:#x}"));
        R
    }
    fn set_sock_opt(&mut self, fd: i32, level: i32, name: i32, v: In<u8>) -> Result<(i32, i32)> {
        log(format!("set_sock_opt {fd} {level:#x} {name:#x} {}", in_buf(&v)));
        R
    }
    fn shutdown(&mut self, fd: i32, how: i32) -> Result<(i32, i32)> {
        log(format!("shutdown {fd} {how}"));
        R
    }
    fn write(&mut self, fd: i32, buf: In<u8>) -> Result<(i32, i32)> {
        log(format!("write {fd} {}", in_buf(&buf)));
        R
    }
    fn read(&mut self, fd: i32, buf: Out<u8>) -> Result<(i32, i32)> {
        log(format!("read {fd} {}", out_buf(&buf, 0xB0)));
        R
    }
    fn close(&mut self, fd: i32) -> Result<(i32, i32)> {
        log(format!("close {fd}"));
        R
    }
    fn register_client_shared(&mut self, c: LibraryConfig, pid: ProcessId, tmem_size: u64) -> Result<u64> {
        log(format!("register_client_shared {c:x?} pid={:#x} tmem_size={tmem_size:#x}", pid.process_id));
        Ok(0x1234)
    }
}

/// An empty A/B descriptor, as libnx pairs with an auto-select buffer sent as X/C.
const NONE: Buf = Buf { addr: 0, size: 0, mode: 0 };

/// Serves `req` on a fresh bsd:u session (a domain when `domain`), returns the handler log,
/// the reply's raw out data (`out_len` bytes) and its X descriptors with their data.
fn serve(req: Request, domain: bool, out_len: usize) -> (Vec<String>, Vec<u8>, Vec<(u8, Vec<u8>)>) {
    set_version(18);
    let mut s = Server::<P>::new(Rec);
    if domain {
        s.convert_to_domain();
    }
    let (words, x) = req.build(s.domain);
    let reply = s.send(words, x, 0x1234_5678).expect("no reply");
    let out = hipc::cmif_out(&reply, domain, out_len);
    assert_eq!((out.magic, out.result), (hipc::SFCO, 0), "reply header");
    (take_log(), out.raw, reply_x(&reply))
}

fn in_auto(n: usize) -> Vec<Buf> {
    vec![NONE; n]
}

fn sockaddr() -> Vec<u8> {
    // struct sockaddr_in: len 16, AF_INET, port 11452 (big endian), 10.0.0.2, zero.
    [vec![16, 2, 0x2C, 0xBC, 10, 0, 0, 2], vec![0; 8]].concat()
}

#[test]
fn register_client() {
    // bsdRegisterClient: in { BsdInitConfig (8 x u32); u64 pid placeholder; u64 tmem size },
    // send pid, copy handle = transfer memory. The kernel writes the client's pid.
    let raw = le!(9u32, 0x8000u32, 0x10000u32, 0x40000u32, 0x40000u32, 0x2400u32, 0xA500u32, 4u32, 0u64, 0x6000u64);
    let req = Request { cmd: 0, raw, pid: Some(0), copy: vec![0x55], ..Default::default() };
    let (log, out, _) = serve(req, false, 8);
    assert_eq!(log, ["register_client LibraryConfig { version: 9, tcp_tx_buf_size: 8000, tcp_rx_buf_size: 10000, tcp_tx_buf_max_size: 40000, tcp_rx_buf_max_size: 40000, udp_tx_buf_size: 2400, udp_rx_buf_size: a500, sb_efficiency: 4 } pid=0x12345678 tmem_size=0x6000 tmem=0x55"]);
    assert_eq!(out, le!(0x1234u64));
}

#[test]
fn register_client_shared() {
    // Switchbrew: RegisterClientShared [10.0.0+], RegisterClient without the transfer memory.
    let raw = le!(10u32, 0x8000u32, 0x10000u32, 0x40000u32, 0x40000u32, 0x2400u32, 0xA500u32, 4u32, 0u64, 0x6000u64);
    let (log, out, _) = serve(Request { cmd: 33, raw, pid: Some(0), ..Default::default() }, false, 8);
    assert!(log[0].starts_with("register_client_shared LibraryConfig { version: a,") && log[0].ends_with("pid=0x12345678 tmem_size=0x6000"), "{log:?}");
    assert_eq!(out, le!(0x1234u64));
}

#[test]
fn socket_and_socket_exempt() {
    // bsdSocket / bsdSocketExempt: in { int domain; int type; int protocol; }.
    for (cmd, name) in [(2, "socket"), (3, "socket_exempt")] {
        let (log, out, _) = serve(Request { cmd, raw: le!(2i32, 2i32, 17i32), ..Default::default() }, false, 8);
        assert_eq!(log, [format!("{name} 2 2 17")]);
        assert_eq!(out, le!(7i32, 0i32));
    }
}

#[test]
fn select() {
    // bsdSelect: in { int nfds; struct timeval timeout (at 8); bool nullTimeout (at 24); },
    // read/write/except sets In auto-select (X indices 0, 1, 2), then Out auto-select. The
    // reply returns each out set as an X descriptor at its receive index.
    let raw = [le!(5i32, 0u32, 1i64, 500i64), vec![0u8; 8]].concat();
    let req = Request {
        cmd: 5,
        raw,
        x: vec![vec![1; 8], vec![2; 8], vec![3; 8]],
        a: in_auto(3),
        b: in_auto(3),
        c: vec![8, 8, 8],
        ..Default::default()
    };
    let (log, out, x) = serve(req, false, 8);
    assert_eq!(log, ["select 5 1/500/false [01, 01, 01, 01, 01, 01, 01, 01] [02, 02, 02, 02, 02, 02, 02, 02] [03, 03, 03, 03, 03, 03, 03, 03] out[0x8] out[0x8] out[0x8]"]);
    assert_eq!(out, le!(7i32, 0i32));
    assert_eq!(x, [(0, vec![0xB0; 8]), (1, vec![0xB1; 8]), (2, vec![0xB2; 8])]);
}

#[test]
fn poll() {
    // bsdPoll: in { int nfds; int timeout; }, fds In then Out auto-select (nfds * 8 bytes).
    let fd = le!(4i32, 1i16, 0i16);
    let req = Request { cmd: 6, raw: le!(1i32, 250i32), x: vec![fd], a: in_auto(1), b: in_auto(1), c: vec![8], ..Default::default() };
    let (log, out, x) = serve(req, false, 8);
    assert_eq!(log, ["poll 1 250 [04, 00, 00, 00, 01, 00, 00, 00] out[0x8]"]);
    assert_eq!(out, le!(7i32, 0i32));
    assert_eq!(x, [(0, vec![0xB0; 8])]);
}

#[test]
fn recv() {
    // bsdRecv: in { int sockfd; int flags; }, buffer Out auto-select.
    let req = Request { cmd: 8, raw: le!(3i32, 0x80i32), b: in_auto(1), c: vec![0x100], ..Default::default() };
    let (log, out, x) = serve(req, false, 8);
    assert_eq!(log, ["recv 3 0x80 out[0x100]"]);
    assert_eq!(out, le!(7i32, 0i32));
    assert_eq!(x, [(0, vec![0xB0; 0x100])]);
}

#[test]
fn recv_into_map_alias_buffer() {
    // cmifRequestOutAutoBuffer, buffer larger than the pointer buffer: B carries it, the C entry
    // and table size are 0; the handler writes straight into it and the reply's X descriptor
    // for it is empty.
    let buf = low(&[0; 0x2000]);
    let b = Buf { addr: addr(buf.as_ptr()), size: 0x2000, mode: 0 };
    let req = Request { cmd: 8, raw: le!(3i32, 0i32), b: vec![b], c: vec![0], ..Default::default() };
    let (log, _, x) = serve(req, false, 8);
    assert_eq!(log, ["recv 3 0x0 out[0x2000]"]);
    assert_eq!(x, [(0, vec![])]);
    assert!(buf.iter().all(|&v| v == 0xB0));
}

#[test]
fn recv_from() {
    // bsdRecvFrom: in { int sockfd; int flags; }, buffer and address Out auto-select;
    // out { int ret; int errno_; socklen_t fromlen; }.
    let req = Request { cmd: 9, raw: le!(3i32, 0i32), b: in_auto(2), c: vec![0x100, 16], ..Default::default() };
    let (log, out, x) = serve(req, false, 12);
    assert_eq!(log, ["recv_from 3 0x0 out[0x100] out[0x10]"]);
    assert_eq!(out, le!(7i32, 0i32, 9u32));
    assert_eq!(x, [(0, vec![0xB0; 0x100]), (1, vec![0xB1; 16])]);
}

#[test]
fn send() {
    // bsdSend: in { int sockfd; int flags; }, buffer In auto-select.
    let req = Request { cmd: 10, raw: le!(3i32, 0i32), x: vec![b"hello".to_vec()], a: in_auto(1), ..Default::default() };
    let (log, out, _) = serve(req, false, 8);
    assert_eq!(log, ["send 3 0x0 [68, 65, 6c, 6c, 6f]"]);
    assert_eq!(out, le!(7i32, 0i32));
}

#[test]
fn send_to() {
    // bsdSendTo: in { int sockfd; int flags; }, buffer then address In auto-select (index 1).
    let req = Request { cmd: 11, raw: le!(3i32, 0i32), x: vec![b"hi".to_vec(), sockaddr()], a: in_auto(2), ..Default::default() };
    let (log, _, _) = serve(req, false, 8);
    assert_eq!(log, ["send_to 3 0x0 [68, 69] [10, 02, 2c, bc, 0a, 00, 00, 02, 00, 00, 00, 00, 00, 00, 00, 00]"]);
}

#[test]
fn accept_get_peer_name_get_sock_name() {
    // bsdAccept / GetPeerName / GetSockName: in { int sockfd; }, address Out auto-select;
    // out { int ret; int errno_; socklen_t addrlen; }.
    for (cmd, name) in [(12, "accept"), (15, "get_peer_name"), (16, "get_sock_name")] {
        let req = Request { cmd, raw: le!(3i32), b: in_auto(1), c: vec![16], ..Default::default() };
        let (log, out, x) = serve(req, false, 12);
        assert_eq!(log, [format!("{name} 3 out[0x10]")]);
        assert_eq!(out, le!(7i32, 0i32, 9u32));
        assert_eq!(x, [(0, vec![0xB0; 16])]);
    }
}

#[test]
fn bind_and_connect() {
    // bsdBind / bsdConnect: in { int sockfd; }, address In auto-select.
    for (cmd, name) in [(13, "bind"), (14, "connect")] {
        let req = Request { cmd, raw: le!(3i32), x: vec![sockaddr()], a: in_auto(1), ..Default::default() };
        let (log, _, _) = serve(req, false, 8);
        assert_eq!(log, [format!("{name} 3 [10, 02, 2c, bc, 0a, 00, 00, 02, 00, 00, 00, 00, 00, 00, 00, 00]")]);
    }
}

#[test]
fn get_sock_opt() {
    // bsdGetSockOpt: in { int sockfd; int level; int optname; }, optval Out auto-select;
    // out { int ret; int errno_; socklen_t optlen; }.
    let req = Request { cmd: 17, raw: le!(3i32, 0xFFFFi32, 0x1007i32), b: in_auto(1), c: vec![4], ..Default::default() };
    let (log, out, x) = serve(req, false, 12);
    assert_eq!(log, ["get_sock_opt 3 0xffff 0x1007 out[0x4]"]);
    assert_eq!(out, le!(7i32, 0i32, 9u32));
    assert_eq!(x, [(0, vec![0xB0; 4])]);
}

#[test]
fn listen_fcntl_shutdown_close() {
    // bsdListen { sockfd; backlog }, bsdFcntl { sockfd; cmd; flags }, bsdShutdown
    // { sockfd; how }, bsdClose { fd }.
    for (cmd, raw, expect) in [
        (18, le!(3i32, 5i32), "listen 3 5"),
        (20, le!(3i32, 4i32, 0x800i32), "fcntl 3 4 0x800"),
        (22, le!(3i32, 2i32), "shutdown 3 2"),
        (26, le!(3i32), "close 3"),
    ] {
        let (log, out, _) = serve(Request { cmd, raw, ..Default::default() }, false, 8);
        assert_eq!(log, [expect]);
        assert_eq!(out, le!(7i32, 0i32));
    }
}

#[test]
fn ioctl() {
    // Switchbrew Ioctl: in { int fd; u32 request; u32 bufcount; }, four In auto-select then four
    // Out auto-select buffers (libnx bsdIoctl fills the first of each).
    let req = Request {
        cmd: 19,
        raw: le!(3i32, 0x8020_6919u32, 1u32),
        x: vec![vec![9; 4], vec![], vec![], vec![]],
        a: in_auto(4),
        b: in_auto(4),
        c: vec![4, 0, 0, 0],
        ..Default::default()
    };
    let (log, _, x) = serve(req, false, 8);
    assert_eq!(log, ["ioctl 3 0x80206919 1 [09, 09, 09, 09] [] [] [] out[0x4] out[0x0] out[0x0] out[0x0]"]);
    assert_eq!(x, [(0, vec![0xB0; 4]), (1, vec![]), (2, vec![]), (3, vec![])]);
}

#[test]
fn set_sock_opt() {
    // bsdSetSockOpt: in { int sockfd; int level; int optname; }, optval In auto-select.
    let req = Request { cmd: 21, raw: le!(3i32, 0xFFFFi32, 4i32), x: vec![le!(1i32)], a: in_auto(1), ..Default::default() };
    let (log, _, _) = serve(req, false, 8);
    assert_eq!(log, ["set_sock_opt 3 0xffff 0x4 [01, 00, 00, 00]"]);
}

#[test]
fn write_and_read() {
    // bsdWrite { fd } + In auto-select, bsdRead { fd } + Out auto-select.
    let req = Request { cmd: 24, raw: le!(3i32), x: vec![b"ab".to_vec()], a: in_auto(1), ..Default::default() };
    assert_eq!(serve(req, false, 8).0, ["write 3 [61, 62]"]);
    let req = Request { cmd: 25, raw: le!(3i32), b: in_auto(1), c: vec![0x40], ..Default::default() };
    let (log, _, x) = serve(req, false, 8);
    assert_eq!(log, ["read 3 out[0x40]"]);
    assert_eq!(x, [(0, vec![0xB0; 0x40])]);
}

#[test]
fn domain_requests() {
    // libnx bsdInitialize converts the bsd session to a domain: requests then carry a
    // CmifDomainInHeader (object id) and replies a CmifDomainOutHeader. Same handler values.
    let req = Request { cmd: 9, raw: le!(3i32, 0i32), b: in_auto(2), c: vec![0x100, 16], ..Default::default() };
    let (log, out, x) = serve(req, true, 12);
    assert_eq!(log, ["recv_from 3 0x0 out[0x100] out[0x10]"]);
    assert_eq!(out, le!(7i32, 0i32, 9u32));
    assert_eq!(x, [(0, vec![0xB0; 0x100]), (1, vec![0xB1; 16])]);
    let req = Request { cmd: 11, raw: le!(3i32, 0i32), x: vec![b"hi".to_vec(), sockaddr()], a: in_auto(2), ..Default::default() };
    assert_eq!(serve(req, true, 8).0.len(), 1);
}

#[test]
fn unknown_command_is_not_handled() {
    // 23 ShutdownAllSockets is not declared: try_handle_request_by_id returns None (the bsd:u
    // service then forwards it).
    let mut s = Server::<P>::new(Rec);
    let (words, x) = Request { cmd: 23, raw: le!(2i32), ..Default::default() }.build(None);
    let reply = s.send(words, x, 0).expect("reply");
    let out = hipc::cmif_out(&reply, false, 0);
    assert_ne!(out.result, 0);
    assert!(take_log().is_empty());
    let _ = Hipc::default();
}
