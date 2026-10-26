//! Shared harness: a client session whose "service" records what nx sent, and a server session
//! fed hand-built requests through nx's real ServerManager (`nx::ipc_host::kernel`).
#![allow(dead_code)]

pub mod hipc;

use hipc::{Buf, Cmif, Hipc, Recv, Static};
use nx::ipc::server::{ISessionObject, ServerManager};
use nx::ipc_host::kernel::{self, Incoming, Msg};
use nx::result::ResultCode;
use nx::sync::Mutex;
use std::cell::RefCell;
use std::rc::Rc;

/// What the ifaces name as `crate::compat` (crates/sys/src/compat.rs): only `since`, the
/// rest of that module needs the running module's state. Test roots `use common::compat;`.
pub mod compat {
    pub const fn since(v: ldn_tunnel_core::compat::Ver) -> nx::version::VersionInterval {
        nx::version::VersionInterval::from(nx::version::Version::new(v.0, v.1, v.2))
    }
}

/// A fake handle value for sessions (any non-zero value; the host kernel does not check).
pub const SESSION: u32 = 0x0BAD_0001;

/// `bytes` copied to memory a HIPC descriptor can address (see `kernel::low_alloc`).
pub fn low(bytes: &[u8]) -> &'static mut [u8] {
    let p = kernel::low_alloc(bytes.len());
    let s = unsafe { std::slice::from_raw_parts_mut(p, bytes.len()) };
    s.copy_from_slice(bytes);
    s
}

/// `v` copied to addressable memory.
pub fn low_arr<T: Copy>(v: &[T]) -> &'static mut [T] {
    let p = kernel::low_alloc(std::mem::size_of_val(v)) as *mut T;
    let s = unsafe { std::slice::from_raw_parts_mut(p, v.len()) };
    s.copy_from_slice(v);
    s
}

pub fn low_val<T: Copy>(v: T) -> &'static mut T {
    &mut low_arr(&[v])[0]
}

/// Address of a buffer as a descriptor carries it.
pub fn addr<T>(p: *const T) -> u64 {
    p as usize as u64
}

/// The system version handlers see (`#[version]` gates).
pub fn set_version(major: u8) {
    unsafe { nx::version::set_version(nx::version::Version::new(major, 0, 0)) };
}

/// Fills the message buffer with a pattern, as a buffer holding an earlier message would be:
/// any byte nx does not write on purpose shows up as 0xAA.
pub fn dirty_msg_buffer() {
    unsafe { (*nx::thread::get_thread_local_region()).msg_buffer.fill(0xAA) };
}

// ---------------------------------------------------------------------------------------------
// Client side

/// How the remote service answers.
#[derive(Clone, Default)]
pub struct Answer {
    pub tipc: bool,
    pub result: u32,
    pub raw: Vec<u8>,
    pub copy: Vec<u32>,
    pub moves: Vec<u32>,
    /// Reply to a domain request (DomainOutHeader + these out objects).
    pub domain_objects: Option<Vec<u32>>,
    /// What QueryPointerBufferSize returns.
    pub pointer_buffer_size: u16,
}

/// Runs `f` against a remote that answers every request with `answer` (and control
/// QueryPointerBufferSize with its size); returns `f`'s value and the requests nx sent, minus
/// the QueryPointerBufferSize ones.
pub fn call<T>(answer: Answer, f: impl FnOnce() -> T) -> (T, Vec<Msg>) {
    let a = answer.clone();
    kernel::set_remote(move |msg: &mut Msg| {
        let req = hipc::decode(msg);
        let reply = Hipc { copy: a.copy.clone(), moves: a.moves.clone(), ..Default::default() };
        let reply = if req.ty == hipc::CMIF_CONTROL {
            hipc::cmif_reply(reply, 0, &a.pointer_buffer_size.to_le_bytes(), None)
        } else if a.tipc {
            hipc::tipc_reply(Hipc { ty: req.ty, ..reply }, a.result, &a.raw)
        } else {
            hipc::cmif_reply(reply, a.result, &a.raw, a.domain_objects.as_deref())
        };
        msg.fill(0);
        *msg = hipc::to_msg(&hipc::encode(&reply));
        ResultCode::new(0)
    });
    let before = kernel::sent().len();
    dirty_msg_buffer();
    let out = f();
    let sent = kernel::sent()[before..]
        .iter()
        .filter(|m| hipc::decode(&m[..]).ty != hipc::CMIF_CONTROL)
        .copied()
        .collect();
    (out, sent)
}

/// A client object of an nx ipc_trait type on a fake session handle.
pub fn client<C: nx::ipc::client::IClientObject>(tipc: bool) -> C {
    let mut info = nx::ipc::ObjectInfo::from_handle(SESSION);
    if tipc {
        info.protocol = nx::ipc::CommandProtocol::Tipc;
    }
    C::new(nx::ipc::sf::Session::from(info))
}

/// The same client on a domain object `object_id`.
pub fn domain_client<C: nx::ipc::client::IClientObject>(object_id: u32) -> C {
    C::new(nx::ipc::sf::Session::from(nx::ipc::ObjectInfo::from_domain_object_id(SESSION, object_id)))
}

/// Checks a CMIF request nx sent against the one libnx's cmifMakeRequest builds from `expect`
/// (descriptors, handles, receive list) plus `cmd`, the argument bytes `raw` and the
/// out-pointer table. Compares every header and descriptor field, the CMIF header, the argument
/// bytes, the table and the raw data word count; the process id slot only for presence (the
/// kernel fills it).
pub fn assert_cmif(sent: &Msg, expect: Hipc, cmd: u32, raw: &[u8], out_pointer_sizes: &[u16]) {
    assert_request(sent, expect, None, cmd, raw, &[], out_pointer_sizes)
}

/// `assert_cmif` with argument bytes the service never reads (struct padding) left out.
pub fn assert_request(
    sent: &Msg,
    expect: Hipc,
    domain: Option<(u32, Vec<u32>)>,
    cmd: u32,
    raw: &[u8],
    padding: &[std::ops::Range<usize>],
    out_pointer_sizes: &[u16],
) {
    let n = out_pointer_sizes.len();
    let expect = hipc::cmif_request(
        Hipc { recv_mode: if expect.c.is_empty() { 0 } else { 2 + expect.c.len() as u8 }, ..expect },
        &Cmif { ty: 0, cmd, raw: raw.to_vec(), domain: domain.clone(), out_pointer_sizes: out_pointer_sizes.to_vec() },
    );
    let mut got = hipc::decode(&sent[..]);
    got.pid = got.pid.map(|_| 0);
    let expect = hipc::decode(&hipc::to_msg(&hipc::encode(&expect)));
    let strip = |h: &Hipc| Hipc { data: vec![], ..h.clone() };
    assert_eq!(strip(&got), strip(&expect), "HIPC header / descriptors");
    let is_domain = domain.is_some();
    let unpadded = |h: &Hipc| {
        let mut c = hipc::cmif_in(h, is_domain, raw.len(), n);
        for r in padding {
            c.raw[r.clone()].fill(0);
        }
        c
    };
    assert_eq!(
        unpadded(&got),
        unpadded(&expect),
        "CMIF header, arguments, out-pointer table, data word count"
    );
}

/// The same for a TIPC request (tipcMakeRequest: type = 16 + id, arguments from word 0 of the
/// raw data, no CMIF header).
pub fn assert_tipc(sent: &Msg, expect: Hipc, cmd: u32, raw: &[u8]) {
    let mut words = raw.to_vec();
    words.resize(raw.len().div_ceil(4) * 4, 0);
    let expect = Hipc { ty: 16 + cmd as u16, data: hipc::words(&words), ..expect };
    let mut got = hipc::decode(&sent[..]);
    got.pid = got.pid.map(|_| 0);
    let expect = hipc::decode(&hipc::to_msg(&hipc::encode(&expect)));
    let strip = |h: &Hipc| Hipc { data: vec![], ..h.clone() };
    assert_eq!(strip(&got), strip(&expect), "HIPC header / descriptors");
    assert_eq!(got.data.len(), expect.data.len(), "raw data words");
    assert_eq!(&hipc::raw_bytes(&got)[..raw.len()], raw, "arguments");
}

// ---------------------------------------------------------------------------------------------
// Server side

/// One server session of `S` on nx's ServerManager with a `P`-byte pointer buffer.
pub struct Server<const P: usize> {
    manager: &'static mut ServerManager<P>,
    pub domain: Option<u32>,
}

impl<const P: usize> Server<P> {
    pub fn new<S: ISessionObject + 'static>(object: S) -> Self {
        // The manager holds the pointer buffer X data lands in: it must be addressable.
        let p = kernel::low_alloc(std::mem::size_of::<ServerManager<P>>()) as *mut ServerManager<P>;
        let manager = unsafe {
            p.write(ServerManager::new().unwrap());
            &mut *p
        };
        manager.register_session(SESSION, Rc::new(Mutex::new(object)));
        Self { manager, domain: None }
    }

    pub fn pointer_buffer(&self) -> (u64, usize) {
        // ServerManager { server_holders, wait_handles, pointer_buffer: [u8; P], .. }: find it
        // from the receive list the server offers instead of relying on field layout.
        let (_, list) = kernel::receive_lists().last().cloned().expect("no receive yet");
        (list[0].0 as u64, list[0].1)
    }

    /// Delivers `words` (+ X data) and runs one turn of the manager; returns the reply.
    pub fn send(&mut self, words: Vec<u32>, x_data: Vec<Vec<u8>>, pid: u64) -> Option<Hipc> {
        let before = kernel::replies().len();
        kernel::deliver(Incoming { handle: SESSION, words, x_data, process_id: pid });
        self.manager.process().unwrap();
        kernel::replies().get(before).map(|m| hipc::decode(&m[..]))
    }

    /// ConvertCurrentObjectToDomain (control 0) as libnx's cmifConvertCurrentObjectToDomain.
    pub fn convert_to_domain(&mut self) -> u32 {
        let req = hipc::cmif_request(Hipc::default(), &Cmif { ty: hipc::CMIF_CONTROL, cmd: 0, ..Default::default() });
        let reply = self.send(hipc::encode(&req), vec![], 0).expect("no reply");
        let out = hipc::cmif_out(&reply, false, 4);
        assert_eq!((out.magic, out.result), (hipc::SFCO, 0));
        let id = u32::from_le_bytes(out.raw[..4].try_into().unwrap());
        self.domain = Some(id);
        id
    }
}

/// A request as a libnx client builds it (cmifMakeRequest), described by its parts.
#[derive(Clone, Default)]
pub struct Request {
    pub cmd: u32,
    pub raw: Vec<u8>,
    pub pid: Option<u64>,
    pub copy: Vec<u32>,
    /// In pointers / in auto-select buffers that fit the pointer buffer: their data, in
    /// descriptor order (index = order, as libnx's cur_in_ptr_id).
    pub x: Vec<Vec<u8>>,
    pub a: Vec<Buf>,
    pub b: Vec<Buf>,
    /// Out pointers / out auto-select buffers: their sizes (the table and the receive list).
    pub c: Vec<u16>,
    /// The out-pointer size table when it is not `c` (fixed-size out pointers have no entry).
    pub table: Option<Vec<u16>>,
    /// Domain input objects.
    pub objects: Vec<u32>,
}

/// A client address for X data the kernel copies (the server never sees it).
const CLIENT_X_ADDR: u64 = 0x7_0000_0000;
const CLIENT_C_ADDR: u64 = 0x7_8000_0000;

impl Request {
    pub fn build(&self, domain: Option<u32>) -> (Vec<u32>, Vec<Vec<u8>>) {
        let mut x_addr = CLIENT_X_ADDR;
        let mut c_addr = CLIENT_C_ADDR;
        let h = Hipc {
            pid: self.pid.map(|_| 0),
            copy: self.copy.clone(),
            x: self
                .x
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    x_addr += 0x1000;
                    Static { index: i as u8, addr: x_addr, size: d.len() as u16 }
                })
                .collect(),
            a: self.a.clone(),
            b: self.b.clone(),
            recv_mode: if self.c.is_empty() { 0 } else { 2 + self.c.len() as u8 },
            c: self
                .c
                .iter()
                .map(|&size| {
                    c_addr += 0x1000;
                    Recv { addr: c_addr, size }
                })
                .collect(),
            ..Default::default()
        };
        let h = hipc::cmif_request(
            h,
            &Cmif {
                ty: 0,
                cmd: self.cmd,
                raw: self.raw.clone(),
                domain: domain.map(|id| (id, self.objects.clone())),
                out_pointer_sizes: self.table.clone().unwrap_or_else(|| self.c.clone()),
            },
        );
        let mut words = hipc::encode(&h);
        // The kernel never delivers the receive list: cut it, the server must not need it.
        words.truncate(h.data_at_after_encode());
        (words, self.x.clone())
    }
}

trait DataEnd {
    fn data_at_after_encode(&self) -> usize;
}

impl DataEnd for Hipc {
    /// Words through the raw data, as `encode` lays them out.
    fn data_at_after_encode(&self) -> usize {
        let special = self.pid.is_some() || !self.copy.is_empty() || !self.moves.is_empty();
        2 + special as usize * (1 + 2 * self.pid.is_some() as usize + self.copy.len() + self.moves.len())
            + 2 * self.x.len()
            + 3 * (self.a.len() + self.b.len() + self.w.len())
            + self.data.len()
    }
}

std::thread_local! {
    static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Records what a handler saw (recorder server objects call this).
pub fn log(s: String) {
    LOG.with(|l| l.borrow_mut().push(s));
}

/// Everything handlers recorded since the last call.
pub fn take_log() -> Vec<String> {
    LOG.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

/// An in buffer as a handler logs it: its bytes.
pub fn in_buf<const I: bool, const O: bool, const M: bool, const P: bool, const F: bool, const A: bool, const S: bool, const D: bool, T>(
    b: &nx::ipc::sf::Buffer<'_, I, O, M, P, F, A, S, D, T>,
) -> String {
    if b.get_size() == 0 {
        return "[]".into();
    }
    let s = unsafe { std::slice::from_raw_parts(b.get_address(), b.get_size()) };
    format!("{s:02x?}")
}

/// An out buffer as a handler logs it (its size), after filling it with `fill`.
pub fn out_buf<const I: bool, const O: bool, const M: bool, const P: bool, const F: bool, const A: bool, const S: bool, const D: bool, T>(
    b: &nx::ipc::sf::Buffer<'_, I, O, M, P, F, A, S, D, T>,
    fill: u8,
) -> String {
    if b.get_size() > 0 {
        unsafe { std::ptr::write_bytes(b.get_address(), fill, b.get_size()) };
    }
    format!("out[{:#x}]", b.get_size())
}

/// The X descriptors of a reply with the bytes each points to.
pub fn reply_x(reply: &Hipc) -> Vec<(u8, Vec<u8>)> {
    reply
        .x
        .iter()
        .map(|x| {
            let data = if x.size == 0 { vec![] } else { unsafe { std::slice::from_raw_parts(x.addr as *const u8, x.size as usize) }.to_vec() };
            (x.index, data)
        })
        .collect()
}

/// Little-endian bytes of a list of integers, for raw data expectations.
#[macro_export]
macro_rules! le {
    ($($v:expr),* $(,)?) => {{
        let mut v: Vec<u8> = Vec::new();
        $( v.extend_from_slice(&$v.to_le_bytes()); )*
        v
    }};
}
