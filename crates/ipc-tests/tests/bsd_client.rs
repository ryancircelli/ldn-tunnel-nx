//! bsd:s as the module's own socket client sends it (nx `ipc::sf::bsd::IBsdClient`, used by
//! crates/sys/src/net/socket.rs), against libnx `nx/source/services/bsd.c` (bsdRegisterClient
//! ... bsdClose: argument structs, buffer attributes) and `nx/include/switch/sf/cmif.h`
//! (`cmifRequestInAutoBuffer` / `cmifRequestOutAutoBuffer`: a buffer that fits the server's
//! pointer buffer goes as X / C + out-pointer size with an empty A / B, otherwise as A / B with an
//! empty X / C). Replies: libnx's `struct { int ret; int errno_; [socklen_t len;] } out`.

mod common;

use common::hipc::{Buf, Hipc, Recv, Static};
use common::*;
use nx::ipc::sf::bsd::{
    BsdResult, BsdServiceConfig, BsdTimeout, FcntlCmd, IBsdClient, IpProto, PollFd, ReadFlags,
    SendFlags, SocketAddrRepr, SocketType,
};
use nx::ipc::sf::{Buffer, CopyHandle, ProcessId};
use nx::service::bsd::SystemBsdService;

const PTR: u16 = 0x1000;

fn bsd() -> SystemBsdService {
    client(false)
}

fn answer(raw: Vec<u8>) -> Answer {
    Answer { raw, pointer_buffer_size: PTR, ..Default::default() }
}

fn ok<T>(r: BsdResult<T>) -> (i32, T) {
    match r {
        BsdResult::Ok(ret, v) => (ret, v),
        BsdResult::Err(e) => panic!("errno {e}"),
    }
}

/// An empty A/B descriptor (cmifRequestInBuffer / OutBuffer with NULL, 0, mode Normal).
const NONE: Buf = Buf { addr: 0, size: 0, mode: 0 };

fn x(index: u8, p: *const u8, size: usize) -> Static {
    Static { index, addr: addr(p), size: size as u16 }
}

fn c(p: *const u8, size: usize) -> Recv {
    Recv { addr: addr(p), size: size as u16 }
}

#[test]
fn register_client() {
    // bsdRegisterClient: in { BsdInitConfig config; u64 pid_placeholder; u64 tmem_sz; },
    // send pid, one copy handle (the transfer memory). BsdInitConfig: version then the seven
    // buffer sizes, all u32.
    set_version(18);
    let cfg = BsdServiceConfig::default();
    let (pid, sent) = call(answer(le!(0x1234u64)), || {
        bsd().register_client(cfg, ProcessId::new(), 0x6000, CopyHandle::from(0x55)).unwrap()
    });
    assert_eq!(pid, 0x1234);
    let raw = le!(9u32, 0x8000u32, 0x10000u32, 0x40000u32, 0x40000u32, 0x2400u32, 0xA500u32, 4u32, 0u64, 0x6000u64);
    assert_cmif(&sent[0], Hipc { pid: Some(0), copy: vec![0x55], ..Default::default() }, 0, &raw, &[]);
}

#[test]
fn start_monitoring() {
    // bsdStartMonitoring: in u64 pid, send pid.
    let (_, sent) = call(answer(vec![]), || bsd().start_monitoring(ProcessId::from(0x77)).unwrap());
    assert_cmif(&sent[0], Hipc { pid: Some(0), ..Default::default() }, 1, &le!(0x77u64), &[]);
}

#[test]
fn bug1_socket_domain_is_a_u32() {
    // bsdSocket: in { int domain; int type; int protocol; } (Ryujinx IClient.Socket reads three
    // i32). Bug 1: domain went as a u8 with three stale bytes after it.
    let (r, sent) = call(answer(le!(3i32, 0i32)), || {
        bsd().socket(2, SocketType::DataGram, IpProto::UDP).unwrap()
    });
    assert_eq!(ok(r), (3, ()));
    assert_cmif(&sent[0], Hipc::default(), 2, &le!(2i32, 2i32, 17i32), &[]);
}

#[test]
fn bug3_select_layout() {
    // bsdSelect: in { int nfds; struct timeval timeout; bool nullTimeout; } (timeval at 8:
    // i64 sec, i64 usec; nullTimeout at 24; 32 bytes), then readfds, writefds, exceptfds as In
    // auto-select and the same three as Out auto-select. Bug 3.
    let sets: [&'static mut [u64; 16]; 6] = std::array::from_fn(|i| low_val([i as u64; 16]));
    let p: Vec<*const u8> = sets.iter().map(|s| s.as_ptr() as *const u8).collect();
    let [r_in, w_in, e_in, r_out, w_out, e_out] = sets;
    let (r, sent) = call(answer(le!(1i32, 0i32)), || {
        bsd()
            .select(
                5,
                BsdTimeout::new(),
                Buffer::from_var(r_in),
                Buffer::from_var(w_in),
                Buffer::from_var(e_in),
                Buffer::from_mut_var(r_out),
                Buffer::from_mut_var(w_out),
                Buffer::from_mut_var(e_out),
            )
            .unwrap()
    });
    assert_eq!(ok(r), (1, ()));
    let expect = Hipc {
        x: vec![x(0, p[0], 128), x(1, p[1], 128), x(2, p[2], 128)],
        a: vec![NONE; 3],
        b: vec![NONE; 3],
        c: vec![c(p[3], 128), c(p[4], 128), c(p[5], 128)],
        ..Default::default()
    };
    // BsdTimeout::new(): no timeout (nullTimeout true). Bytes 4..8 and 25..32 are padding.
    let raw = [le!(5i32, 0u32, 0i64, 0i64), vec![1u8], vec![0u8; 7]].concat();
    assert_request(&sent[0], expect, None, 5, &raw, &[4..8, 25..32], &[128, 128, 128]);
}

#[test]
fn bug3_poll_count_and_separate_buffers() {
    // bsdPoll: in { int nfds; int timeout; }, fds In auto-select, fds Out auto-select, each
    // nfds * sizeof(struct pollfd) (8). Bug 3: nx sent one InOut buffer and no count.
    let fds_in = low_arr(&[PollFd { fd: 4, ..Default::default() }]);
    let fds_out = low_arr(&[PollFd::default()]);
    let (pi, po) = (fds_in.as_ptr() as *const u8, fds_out.as_ptr() as *const u8);
    let (r, sent) = call(answer(le!(1i32, 0i32)), || {
        bsd().poll(1, 250, Buffer::from_array(fds_in), Buffer::from_mut_array(fds_out)).unwrap()
    });
    assert_eq!(ok(r), (1, ()));
    let expect = Hipc { x: vec![x(0, pi, 8)], a: vec![NONE], b: vec![NONE], c: vec![c(po, 8)], ..Default::default() };
    assert_cmif(&sent[0], expect, 6, &le!(1i32, 250i32), &[8]);
}

#[test]
fn recv() {
    // bsdRecv: in { int sockfd; int flags; }, buffer Out auto-select.
    let buf = low(&[0; 0x200]);
    let p = buf.as_ptr();
    let (r, sent) = call(answer(le!(0x20i32, 0i32)), || {
        bsd().recv(3, ReadFlags::DontWait(), Buffer::from_mut_array(buf)).unwrap()
    });
    assert_eq!(ok(r), (0x20, ()));
    let expect = Hipc { b: vec![NONE], c: vec![c(p, 0x200)], ..Default::default() };
    assert_cmif(&sent[0], expect, 8, &le!(3i32, 0x80i32), &[0x200]);
}

#[test]
fn recv_into_buffer_larger_than_pointer_buffer() {
    // cmifRequestOutAutoBuffer, buffer too large: C (NULL, 0) + size 0 in the table, B with the
    // buffer (mode Normal).
    let buf = low(&[0; 0x2000]);
    let p = buf.as_ptr();
    let (_, sent) = call(answer(le!(0i32, 0i32)), || {
        bsd().recv(3, ReadFlags::None(), Buffer::from_mut_array(buf)).unwrap()
    });
    let expect = Hipc { b: vec![Buf { addr: addr(p), size: 0x2000, mode: 0 }], c: vec![Recv::default()], ..Default::default() };
    assert_cmif(&sent[0], expect, 8, &le!(3i32, 0i32), &[0]);
}

#[test]
fn recv_from() {
    // bsdRecvFrom: in { int sockfd; int flags; }, buffer and from-address Out auto-select;
    // out { int ret; int errno_; socklen_t fromlen; }.
    let buf = low(&[0; 0x100]);
    let from = low_val(SocketAddrRepr::default());
    let (pb, pf) = (buf.as_ptr(), from as *const SocketAddrRepr as *const u8);
    let (r, sent) = call(answer(le!(0x10i32, 0i32, 16u32)), || {
        bsd().recv_from(3, ReadFlags::None(), Buffer::from_mut_array(buf), Buffer::from_mut_var(from)).unwrap()
    });
    assert_eq!(ok(r), (0x10, ()));
    let expect = Hipc { b: vec![NONE, NONE], c: vec![c(pb, 0x100), c(pf, 16)], ..Default::default() };
    assert_cmif(&sent[0], expect, 9, &le!(3i32, 0i32), &[0x100, 16]);
}

#[test]
fn send() {
    // bsdSend: in { int sockfd; int flags; }, buffer In auto-select.
    let buf = low(b"hello");
    let p = buf.as_ptr();
    let (r, sent) = call(answer(le!(5i32, 0i32)), || bsd().send(3, SendFlags::None(), Buffer::from_array(buf)).unwrap());
    assert_eq!(ok(r), (5, ()));
    assert_cmif(&sent[0], Hipc { x: vec![x(0, p, 5)], a: vec![NONE], ..Default::default() }, 10, &le!(3i32, 0i32), &[]);
}

#[test]
fn send_to() {
    // bsdSendTo: in { int sockfd; int flags; }, buffer then to-address In auto-select: the
    // address is the second X descriptor, index 1.
    let buf = low(b"payload!");
    let to = low_val(SocketAddrRepr::from((core::net::Ipv4Addr::new(10, 0, 0, 2), 11452)));
    let (pb, pt) = (buf.as_ptr(), to as *const SocketAddrRepr as *const u8);
    let (_, sent) = call(answer(le!(8i32, 0i32)), || {
        bsd().send_to(3, SendFlags::None(), Buffer::from_array(buf), Buffer::from_var(to)).unwrap()
    });
    let expect = Hipc { x: vec![x(0, pb, 8), x(1, pt, 16)], a: vec![NONE, NONE], ..Default::default() };
    assert_cmif(&sent[0], expect, 11, &le!(3i32, 0i32), &[]);
    // struct sockaddr_in as bsd reads it: len, family (AF_INET 2), port (big endian), address.
    let sa = unsafe { std::slice::from_raw_parts(pt, 16) };
    assert_eq!(&sa[..8], &[6, 2, 0x2C, 0xBC, 10, 0, 0, 2]);
}

#[test]
fn connect() {
    // bsdConnect: in { int sockfd; }, address In auto-select.
    let to = low_val(SocketAddrRepr::from((core::net::Ipv4Addr::new(1, 2, 3, 4), 443)));
    let pt = to as *const SocketAddrRepr as *const u8;
    let (_, sent) = call(answer(le!(0i32, 0i32)), || bsd().connect(3, Buffer::from_var(to)).unwrap());
    assert_cmif(&sent[0], Hipc { x: vec![x(0, pt, 16)], a: vec![NONE], ..Default::default() }, 14, &le!(3i32), &[]);
}

#[test]
fn get_sock_opt() {
    // bsdGetSockOpt: in { int sockfd; int level; int optname; }, optval Out auto-select;
    // out { int ret; int errno_; socklen_t optlen; }.
    let v = low_val(0i32);
    let p = v as *const i32 as *const u8;
    let (r, sent) = call(answer(le!(0i32, 0i32, 4u32)), || {
        bsd().get_sock_opt(3, 0xFFFF, 0x1007, Buffer::from_other_mut_var(v)).unwrap()
    });
    assert_eq!(ok(r), (0, 4));
    let expect = Hipc { b: vec![NONE], c: vec![c(p, 4)], ..Default::default() };
    assert_cmif(&sent[0], expect, 17, &le!(3i32, 0xFFFFi32, 0x1007i32), &[4]);
}

#[test]
fn fcntl() {
    // bsdFcntl: in { int sockfd; int cmd; int flags; }.
    let (_, sent) = call(answer(le!(0i32, 0i32)), || bsd().fcntl(3, FcntlCmd::SetFl, 0x800).unwrap());
    assert_cmif(&sent[0], Hipc::default(), 20, &le!(3i32, 4i32, 0x800i32), &[]);
}

#[test]
fn set_sock_opt() {
    // bsdSetSockOpt: in { int sockfd; int level; int optname; }, optval In auto-select.
    let v = low_val(1i32);
    let p = v as *const i32 as *const u8;
    let (_, sent) = call(answer(le!(0i32, 0i32)), || {
        bsd().set_sock_opt(3, 0xFFFF, 0x4, Buffer::from_other_var(v)).unwrap()
    });
    let expect = Hipc { x: vec![x(0, p, 4)], a: vec![NONE], ..Default::default() };
    assert_cmif(&sent[0], expect, 21, &le!(3i32, 0xFFFFi32, 4i32), &[]);
}

#[test]
fn close() {
    // bsdClose: in { int fd; }.
    let (_, sent) = call(answer(le!(0i32, 0i32)), || bsd().close(3).unwrap());
    assert_cmif(&sent[0], Hipc::default(), 26, &le!(3i32), &[]);
}

#[test]
fn error_reply() {
    // ret < 0: errno is the error (bsd.c _bsdDispatchCommand sets errno from out.errno_).
    let (r, _) = call(answer(le!(-1i32, 97i32)), || bsd().socket(2, SocketType::Stream, IpProto::IP).unwrap());
    assert!(matches!(r, BsdResult::Err(97)));
}
