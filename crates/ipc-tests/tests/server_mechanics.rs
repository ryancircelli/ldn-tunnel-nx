//! nx's server machinery against what Horizon's kernel does (Atmosphere Mesosphere
//! `kern_k_server_session.cpp`, modelled in `nx::ipc_host::kernel`) and what Atmosphere's
//! servers do with it (`sf_hipc_server_session_manager.cpp`, `sf_cmif_server_message_processor`
//! / `HipcCommandProcessor`), plus the descriptor bit layouts of Switchbrew "IPC_Marshalling".
//! The bsd:u interface serves as the example service.

mod common;

#[path = "../../sys/src/bsd/ifaces.rs"]
#[allow(dead_code)]
mod bsd_ifaces;

use bsd_ifaces::{IBsdMitmServer, LibraryConfig, SelectTimeval};
use common::hipc::{self, Buf, Hipc, Recv, Static};
use common::*;
#[allow(unused_imports)]
use common::compat;
use nx::ipc::server::{ISessionObject, ServerContext};
use nx::ipc::sf::{CopyHandle, InAutoSelectBuffer as In, OutAutoSelectBuffer as Out, ProcessId};
use nx::ipc::{BufferDescriptor, BufferFlags, CommandHeader, CommandProtocol, ReceiveStaticDescriptor, SendStaticDescriptor};
use nx::ipc_host::kernel;
use nx::result::Result;

const P: usize = 0x1000;

/// Only the commands these tests send do anything.
struct Bsd;

impl ISessionObject for Bsd {
    fn try_handle_request_by_id(&mut self, id: u32, p: CommandProtocol, ctx: &mut ServerContext) -> Option<Result<()>> {
        <Self as IBsdMitmServer>::try_handle_request_by_id(self, id, p, ctx)
    }
}

const R: Result<(i32, i32)> = Ok((0, 0));
const RL: Result<(i32, i32, u32)> = Ok((0, 0, 0));

#[rustfmt::skip]
impl IBsdMitmServer for Bsd {
    fn register_client(&mut self, _: LibraryConfig, _: ProcessId, _: u64, _: CopyHandle) -> Result<u64> { Ok(0) }
    fn socket(&mut self, _: i32, _: i32, _: i32) -> Result<(i32, i32)> { R }
    fn socket_exempt(&mut self, _: i32, _: i32, _: i32) -> Result<(i32, i32)> { R }
    fn select(&mut self, _: i32, _: SelectTimeval, _: In<u8>, _: In<u8>, _: In<u8>, _: Out<u8>, _: Out<u8>, _: Out<u8>) -> Result<(i32, i32)> { R }
    fn poll(&mut self, _: i32, _: i32, _: In<u8>, _: Out<u8>) -> Result<(i32, i32)> { R }
    fn recv(&mut self, fd: i32, _: i32, buf: Out<u8>) -> Result<(i32, i32)> {
        log(format!("recv {fd} {}", out_buf(&buf, 0xB0)));
        Ok((buf.get_size() as i32, 0))
    }
    fn recv_from(&mut self, fd: i32, _: i32, buf: Out<u8>, addr: Out<u8>) -> Result<(i32, i32, u32)> {
        log(format!("recv_from {fd} {} {}", out_buf(&buf, 0xB0), out_buf(&addr, 0xB1)));
        RL
    }
    fn send(&mut self, _: i32, _: i32, _: In<u8>) -> Result<(i32, i32)> { R }
    fn send_to(&mut self, fd: i32, _: i32, buf: In<u8>, addr: In<u8>) -> Result<(i32, i32)> {
        log(format!("send_to {fd} {} {}", in_buf(&buf), in_buf(&addr)));
        R
    }
    fn accept(&mut self, _: i32, _: Out<u8>) -> Result<(i32, i32, u32)> { RL }
    fn bind(&mut self, _: i32, _: In<u8>) -> Result<(i32, i32)> { R }
    fn connect(&mut self, _: i32, _: In<u8>) -> Result<(i32, i32)> { R }
    fn get_peer_name(&mut self, _: i32, _: Out<u8>) -> Result<(i32, i32, u32)> { RL }
    fn get_sock_name(&mut self, _: i32, _: Out<u8>) -> Result<(i32, i32, u32)> { RL }
    fn get_sock_opt(&mut self, _: i32, _: i32, _: i32, _: Out<u8>) -> Result<(i32, i32, u32)> { RL }
    fn listen(&mut self, _: i32, _: i32) -> Result<(i32, i32)> { R }
    fn ioctl(&mut self, _: i32, _: u32, _: u32, _: In<u8>, _: In<u8>, _: In<u8>, _: In<u8>, _: Out<u8>, _: Out<u8>, _: Out<u8>, _: Out<u8>) -> Result<(i32, i32)> { R }
    fn fcntl(&mut self, _: i32, _: i32, _: i32) -> Result<(i32, i32)> { R }
    fn set_sock_opt(&mut self, _: i32, _: i32, _: i32, _: In<u8>) -> Result<(i32, i32)> { R }
    fn shutdown(&mut self, _: i32, _: i32) -> Result<(i32, i32)> { R }
    fn write(&mut self, _: i32, _: In<u8>) -> Result<(i32, i32)> { R }
    fn read(&mut self, _: i32, _: Out<u8>) -> Result<(i32, i32)> { R }
    fn close(&mut self, _: i32) -> Result<(i32, i32)> { R }
    fn register_client_shared(&mut self, _: LibraryConfig, _: ProcessId, _: u64) -> Result<u64> { Ok(0) }
}

const NONE: Buf = Buf { addr: 0, size: 0, mode: 0 };

fn send_to_request() -> Request {
    // bsdSendTo: data then address as In auto-select: X descriptors with index 0 and 1.
    Request { cmd: 11, raw: le!(3i32, 0i32), x: vec![b"data".to_vec(), vec![0xAD; 16]], a: vec![NONE; 2], ..Default::default() }
}

#[test]
fn bug5_receive_list_is_one_buffer_for_all_x_descriptors() {
    // Atmosphere's servers receive with one receive buffer for every X descriptor (receive list
    // mode 2, libnx HIPC_AUTO_RECV_STATIC). The old receive list (mode 3: index mode with one
    // entry) made the kernel reject any X descriptor with index >= 1, e.g. SendTo's address:
    // the client got ResultOutOfResource and the request never reached the handler.
    let mut s = Server::<P>::new(Bsd);
    let (words, x) = send_to_request().build(None);
    let reply = s.send(words, x, 0);
    let (mode, entries) = kernel::receive_lists().last().cloned().unwrap();
    assert_eq!((mode, entries.len(), entries[0].1), (2, 1, P), "receive list the server offered");
    assert_eq!(kernel::undeliverable(), 0);
    assert!(reply.is_some());
    assert_eq!(take_log(), [format!("send_to 3 [64, 61, 74, 61] {:02x?}", vec![0xADu8; 16])]);
}

#[test]
fn x_data_lands_in_the_pointer_buffer_in_order() {
    // Mesosphere ReceiveList::GetBuffer, single-buffer mode: each X descriptor's data at the
    // next 0x10-aligned address in the one receive buffer, the descriptor rewritten to point
    // there (index and size kept).
    let mut s = Server::<P>::new(Bsd);
    let (words, x) = send_to_request().build(None);
    s.send(words, x, 0);
    let (base, _) = s.pointer_buffer();
    assert_eq!(take_log().len(), 1);
    let first = base.next_multiple_of(0x10);
    let second = (first + 4).next_multiple_of(0x10);
    let at = |a: u64, n: usize| unsafe { std::slice::from_raw_parts(a as *const u8, n).to_vec() };
    assert_eq!((at(first, 4), at(second, 16)), (b"data".to_vec(), vec![0xAD; 16]));
}

#[test]
fn bug7_out_auto_select_size_comes_from_the_out_pointer_table() {
    // The kernel does not deliver the client's C descriptors (the words there are stale, zero
    // here). Atmosphere's HipcCommandProcessor sizes an auto-select out buffer from the
    // client's out-pointer size table and returns the data as an X descriptor with the buffer's
    // receive index. nx used to read the size from the C descriptor: 0, so every proxied recv
    // delivered 0 bytes.
    let mut s = Server::<P>::new(Bsd);
    let req = Request { cmd: 8, raw: le!(3i32, 0i32), b: vec![NONE], c: vec![0x123], ..Default::default() };
    let (words, x) = req.build(None);
    let reply = s.send(words, x, 0).unwrap();
    assert_eq!(take_log(), ["recv 3 out[0x123]"]);
    assert_eq!(reply.x, [Static { index: 0, addr: reply.x[0].addr, size: 0x123 }]);
    assert_eq!(reply_x(&reply)[0].1, vec![0xB0; 0x123]);
    assert_eq!(hipc::cmif_out(&reply, false, 8).raw, le!(0x123i32, 0i32));
}

#[test]
fn out_pointers_go_after_the_requests_own_x_data() {
    // HipcCommandProcessor: out-pointer data is placed after the request's X data in the
    // pointer buffer, never over it; each reply X descriptor carries its out buffer's receive
    // index (recv_from: 0 = data, 1 = address).
    let mut s = Server::<P>::new(Bsd);
    let req = Request { cmd: 9, raw: le!(3i32, 0i32), b: vec![NONE; 2], c: vec![0x30, 16], ..Default::default() };
    let (words, x) = req.build(None);
    let reply = s.send(words, x, 0).unwrap();
    let (base, _) = s.pointer_buffer();
    assert_eq!(reply.x.iter().map(|x| (x.index, x.size)).collect::<Vec<_>>(), [(0, 0x30), (1, 16)]);
    assert!(reply.x.iter().all(|x| x.addr >= base && x.addr + x.size as u64 <= base + P as u64));
    assert_eq!(reply.x[1].addr, reply.x[0].addr + 0x30, "0x10-aligned, one after the other");
}

#[test]
fn out_pointer_table_after_domain_header_and_objects() {
    // cmifMakeRequest: the u16 table sits after the 16 bytes of padding, the domain header, the
    // CmifInHeader, the arguments and the input object ids, hword-aligned, counted from the
    // start of the raw data words. A domain request with an input object id must still give
    // the handler the table's size.
    let mut s = Server::<P>::new(Bsd);
    let id = s.convert_to_domain();
    let req = Request { cmd: 8, raw: le!(3i32, 0i32), b: vec![NONE], c: vec![0x44], objects: vec![id], ..Default::default() };
    let (words, x) = req.build(Some(id));
    let reply = s.send(words, x, 0).unwrap();
    assert_eq!(take_log(), ["recv 3 out[0x44]"]);
    let out = hipc::cmif_out(&reply, true, 8);
    assert_eq!((out.magic, out.result, out.raw), (hipc::SFCO, 0, le!(0x44i32, 0i32)));
}

#[test]
fn request_that_does_not_fit_is_dropped_and_the_session_survives() {
    // An X descriptor larger than what is left of the receive buffer: the kernel fails it to
    // the client and the server's receive returns ResultNotFound. Atmosphere treats that as
    // nothing to do (ReceiveResult::NeedsRetry); the manager must not error out, and the next
    // request on the session is served.
    let mut s = Server::<P>::new(Bsd);
    let big = Request { cmd: 10, raw: le!(3i32, 0i32), x: vec![vec![0; P + 1]], a: vec![NONE], ..Default::default() };
    let (words, x) = big.build(None);
    assert!(s.send(words, x, 0).is_none());
    assert_eq!(kernel::undeliverable(), 1);
    let (words, x) = send_to_request().build(None);
    assert!(s.send(words, x, 0).is_some());
    assert_eq!(take_log().len(), 1);
}

#[test]
fn mitm_forward_rewrites_pid_and_receive_list() {
    // Atmosphere PreProcessCommandBufferForMitm (via cmif::server::prepare_mitm_forward): a
    // sent process id gets the 0xFFFE tag so the kernel passes the client's through, and the
    // client's receive list is replaced by one mode-2 entry over our buffer.
    let h = Hipc {
        pid: Some(0x51),
        b: vec![NONE; 2],
        recv_mode: 4,
        c: vec![Recv { addr: 0x7_0000_1000, size: 0x100 }, Recv { addr: 0x7_0000_2000, size: 16 }],
        ..Default::default()
    };
    let h = hipc::cmif_request(h, &hipc::Cmif { cmd: 9, raw: le!(3i32, 0i32), out_pointer_sizes: vec![0x100, 16], ..Default::default() });
    let mut msg = hipc::to_msg(&hipc::encode(&h));
    let buf = low(&[0; 0x800]);
    unsafe { nx::ipc::cmif::server::prepare_mitm_forward(msg.as_mut_ptr(), buf.as_mut_ptr(), buf.len()) };
    let got = hipc::decode(&msg);
    assert_eq!(got.pid, Some(0xFFFE_0000_0000_0051));
    assert_eq!((got.recv_mode, got.c.clone()), (2, vec![Recv { addr: addr(buf.as_ptr()), size: 0x800 }]));
    assert_eq!((got.b, got.data), (h.b, h.data), "descriptors and raw data unchanged");
}

#[test]
fn descriptor_bit_layouts() {
    // Switchbrew IPC_Marshalling / libnx hipc.h: every address bit range, including bits 36+
    // that host test buffers never reach.
    let a = 0x3F_9876_5432usize as *const u8; // bits 36..41 set
    let x = SendStaticDescriptor::new(a, 0xBEEF, 5);
    let enc = |d: Static| hipc::encode(&Hipc { x: vec![d], ..Default::default() })[2..4].to_vec();
    let raw: [u32; 2] = unsafe { std::mem::transmute(x) };
    assert_eq!(raw.to_vec(), enc(Static { index: 5, addr: 0x3F_9876_5432, size: 0xBEEF }));
    assert_eq!((x.get_address() as usize, x.get_size()), (0x3F_9876_5432, 0xBEEF));

    let b = BufferDescriptor::new(0x7F_FFFF_F000_1234usize as *const u8, 0xA_0000_1000, BufferFlags::NonDevice);
    let raw: [u32; 3] = unsafe { std::mem::transmute(b) };
    let expect = hipc::encode(&Hipc { a: vec![Buf { addr: 0x7F_FFFF_F000_1234, size: 0xA_0000_1000, mode: 3 }], ..Default::default() });
    assert_eq!(raw.to_vec(), expect[2..5].to_vec());

    let c = ReceiveStaticDescriptor::new(0xABCD_1234_5678usize as *const u8, 0x8000);
    let raw: [u32; 2] = unsafe { std::mem::transmute(c) };
    let expect = hipc::encode(&Hipc { recv_mode: 3, c: vec![Recv { addr: 0xABCD_1234_5678, size: 0x8000 }], ..Default::default() });
    assert_eq!(raw.to_vec(), expect[2..4].to_vec());
}

#[test]
fn header_bit_layout_and_receive_list_count() {
    // HipcHeader: type:16 send_statics:4 send_buffers:4 recv_buffers:4 exch_buffers:4 |
    // data_words:10 recv_static_mode:4 pad:6 recv_list_offset:11 has_special_header:1.
    // recv_static_mode: 0 none, 2 + n for n entries, 2 for HIPC_AUTO_RECV_STATIC (0xFF).
    let h = CommandHeader::new(4, 1, 2, 3, 4, 0x3FF, 5, true);
    let raw: [u32; 2] = unsafe { std::mem::transmute(h) };
    assert_eq!(raw, [4 | 1 << 16 | 2 << 20 | 3 << 24 | 4 << 28, 0x3FF | 7 << 10 | 1 << 31]);
    assert_eq!(CommandHeader::encode_receive_static_type(0), 0);
    assert_eq!(CommandHeader::encode_receive_static_type(0xFF), 2);
    assert_eq!(CommandHeader::encode_receive_static_type(1), 3);
    assert_eq!(CommandHeader::decode_receive_static_type(2), 0xFF);
    assert_eq!(h.get_receive_static_count(), 5);
}

#[test]
fn client_domain_request_and_reply() {
    // cmifMakeRequest on a domain object: CmifDomainInHeader (type 1 SendMessage, object
    // count, payload size, object id) before the CmifInHeader; cmifParseResponse reads the
    // CmifDomainOutHeader before the CmifOutHeader. (Parsing domain replies on the forwarding
    // path is crates/core/src/hipc.rs, tested there.)
    use nx::ipc::sf::bsd::{BsdResult, IBsdClient, IpProto, SocketType};
    let bsd: nx::service::bsd::SystemBsdService = domain_client(7);
    let answer = Answer { raw: le!(9i32, 0i32), domain_objects: Some(vec![]), ..Default::default() };
    let (r, sent) = call(answer, || bsd.socket(2, SocketType::Stream, IpProto::TCP).unwrap());
    assert!(matches!(r, BsdResult::Ok(9, ())));
    assert_request(&sent[0], Hipc::default(), Some((7, vec![])), 2, &le!(2i32, 1i32, 6i32), &[], &[]);
}
