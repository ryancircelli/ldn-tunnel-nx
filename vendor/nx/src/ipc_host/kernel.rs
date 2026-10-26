//! A model of what Horizon's kernel does with an IPC message, for the host build (`ipc_host.rs`).
//!
//! Client side: `svcSendSyncRequest` hands the thread's message buffer to [`set_remote`]'s
//! closure (the "service"), after recording a copy in [`sent`].
//!
//! Server side: [`deliver`] queues a request as its client wrote it (descriptors and raw data,
//! X data given separately). `svcReplyAndReceive` then does what Mesosphere's
//! `KServerSession::ReceiveRequest` does with it (Atmosphere `kern_k_server_session.cpp`):
//! - copies the header, special header, X/A/B/W descriptors and raw data words into the
//!   server's message buffer, and nothing after them: the client's C descriptors (receive list)
//!   are not delivered, the words there are the server's own (zeroed here, as observed);
//! - writes the client's process id when the request asks for one;
//! - places each X descriptor's data into the receive list the server left in its message
//!   buffer (`ReceiveList::GetBuffer`): mode 2, one buffer, each piece 0x10-aligned after the
//!   previous; mode n > 2, n - 2 entries chosen by the descriptor's index, so an index with no
//!   entry fails the request (ResultNotFound to the server, ResultOutOfResource to the client);
//!   then rewrites the descriptor's address to where the data landed.
//!
//! The reply (a `svcReplyAndReceive` with a reply target) is recorded in [`replies`] as is.
//! Every thread has its own model, so tests run in parallel.

use crate::result::{ResultBase, ResultCode, ResultSuccess};
use crate::svc::{self, Handle};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cell::RefCell;

pub const MSG_SIZE: usize = 0x100;
pub type Msg = [u8; MSG_SIZE];

/// A request as the client's message buffer held it, for [`deliver`].
pub struct Incoming {
    /// Session handle the request arrives on.
    pub handle: Handle,
    /// Header through raw data (anything after that, e.g. C descriptors, is not delivered).
    pub words: Vec<u32>,
    /// The data of each X descriptor, in descriptor order (its length must be the size field).
    pub x_data: Vec<Vec<u8>>,
    /// What the kernel writes into the process id slot when the request sends one.
    pub process_id: u64,
}

/// The receive list a server offered on one receive: (mode, [(address, size)]).
pub type ReceiveList = (u32, Vec<(usize, usize)>);

#[derive(Default)]
struct Kernel {
    remote: Option<Box<dyn FnMut(&mut Msg) -> ResultCode>>,
    sent: Vec<Msg>,
    incoming: VecDeque<Incoming>,
    replies: Vec<Msg>,
    receive_lists: Vec<ReceiveList>,
    undeliverable: u32,
}

std::thread_local! {
    static KERNEL: RefCell<Kernel> = RefCell::new(Kernel::default());
}

fn with<T>(f: impl FnOnce(&mut Kernel) -> T) -> T {
    KERNEL.with(|k| f(&mut k.borrow_mut()))
}

fn msg_buffer() -> &'static mut Msg {
    unsafe { &mut (*crate::thread::get_thread_local_region()).msg_buffer }
}

/// The service behind every client handle of this thread.
pub fn set_remote(f: impl FnMut(&mut Msg) -> ResultCode + 'static) {
    with(|k| k.remote = Some(Box::new(f)));
}

/// Every request sent with `svcSendSyncRequest` so far, as sent.
pub fn sent() -> Vec<Msg> {
    with(|k| k.sent.clone())
}

/// Queues a request for the server under test.
pub fn deliver(incoming: Incoming) {
    with(|k| k.incoming.push_back(incoming));
}

/// Every reply the server under test sent so far.
pub fn replies() -> Vec<Msg> {
    with(|k| k.replies.clone())
}

/// The receive list of every receive so far.
pub fn receive_lists() -> Vec<ReceiveList> {
    with(|k| k.receive_lists.clone())
}

/// Requests the kernel could not deliver (failed to their client).
pub fn undeliverable() -> u32 {
    with(|k| k.undeliverable)
}

/// `len` zeroed bytes at an address below 2^36, never freed: X descriptors only carry 42
/// address bits (36 of them before the high field), host heap and stack addresses do not fit.
pub fn low_alloc(len: usize) -> *mut u8 {
    unsafe extern "C" {
        fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    }
    const PROT_READ_WRITE: i32 = 0x3;
    const MAP_PRIVATE_ANONYMOUS: i32 = 0x02 | 0x20;
    static NEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0x1_0000_0000);
    let len = len.max(1).next_multiple_of(0x1000);
    let hint = NEXT.fetch_add(len + 0x1000, core::sync::atomic::Ordering::Relaxed);
    let p = unsafe { mmap(hint as *mut u8, len, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, -1, 0) };
    assert!(p as isize != -1 && (p as usize) < (1 << 36), "low_alloc: mmap gave {p:p}");
    p
}

pub fn unsupported(name: &str) -> ! {
    panic!("svc {name} is not modelled on the host (ipc_host::kernel)")
}

pub fn close_handle(_handle: Handle) -> ResultCode {
    ResultSuccess::make()
}

pub fn reset_signal(_handle: Handle) -> ResultCode {
    ResultSuccess::make()
}

/// Waiters of `sync::Mutex`es, (tag address, waiter's tag), shared by all threads.
static ARBITER: std::sync::Mutex<Vec<(usize, u32)>> = std::sync::Mutex::new(Vec::new());
static ARBITER_WAKE: std::sync::Condvar = std::sync::Condvar::new();
const HANDLE_WAIT_MASK: u32 = 0x4000_0000;

fn tag_at(tag_location: *const u8) -> &'static core::sync::atomic::AtomicU32 {
    unsafe { &*(tag_location as *const core::sync::atomic::AtomicU32) }
}

/// svcArbitrateLock as Mesosphere's KConditionVariable::WaitForAddress: unless the lock word
/// still says `owner` with waiters, return at once; else sleep until an unlock hands the lock
/// to this thread (writes `tag` into the word).
pub fn arbitrate_lock(owner: Handle, tag_location: *const u8, tag: u32) -> ResultCode {
    let addr = tag_location as usize;
    let mut waiters = ARBITER.lock().unwrap();
    if tag_at(tag_location).load(core::sync::atomic::Ordering::Acquire) != owner | HANDLE_WAIT_MASK {
        return ResultSuccess::make();
    }
    waiters.push((addr, tag));
    while waiters.contains(&(addr, tag)) {
        waiters = ARBITER_WAKE.wait(waiters).unwrap();
    }
    ResultSuccess::make()
}

/// svcArbitrateUnlock as KConditionVariable::SignalToAddress: hand the lock to the first
/// waiter (its tag, plus the wait bit if others still wait), or release it.
pub fn arbitrate_unlock(tag_location: *const u8) -> ResultCode {
    let addr = tag_location as usize;
    let mut waiters = ARBITER.lock().unwrap();
    let next = match waiters.iter().position(|w| w.0 == addr) {
        Some(i) => {
            let (_, tag) = waiters.remove(i);
            tag | if waiters.iter().any(|w| w.0 == addr) { HANDLE_WAIT_MASK } else { 0 }
        }
        None => 0,
    };
    tag_at(tag_location).store(next, core::sync::atomic::Ordering::Release);
    ARBITER_WAKE.notify_all();
    ResultSuccess::make()
}

/// A new session: (server, client) handles 0x2000.., 0x3000...
pub fn create_session(out_server: *mut Handle, out_client: *mut Handle) -> ResultCode {
    static NEXT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        *out_server = 0x2000 + n;
        *out_client = 0x3000 + n;
    }
    ResultSuccess::make()
}

pub fn send_sync_request(_handle: Handle) -> ResultCode {
    let msg = msg_buffer();
    let mut remote = with(|k| {
        k.sent.push(*msg);
        k.remote.take()
    })
    .unwrap_or_else(|| panic!("send_sync_request: no remote set (ipc_host::kernel::set_remote)"));
    let rc = remote(msg);
    with(|k| k.remote = Some(remote));
    rc
}

/// Signals the session the next queued request arrives on.
pub fn wait_synchronization(
    out_index: *mut i32,
    handles: *const Handle,
    handle_count: u32,
    _timeout: i64,
) -> ResultCode {
    let handles = unsafe { core::slice::from_raw_parts(handles, handle_count as usize) };
    let next = with(|k| k.incoming.front().map(|i| i.handle))
        .unwrap_or_else(|| panic!("wait_synchronization: no request queued (ipc_host::kernel::deliver)"));
    let index = handles
        .iter()
        .position(|&h| h == next)
        .unwrap_or_else(|| panic!("wait_synchronization: {next:#x} is not among {handles:x?}"));
    unsafe { *out_index = index as i32 };
    ResultSuccess::make()
}

pub fn reply_and_receive(
    out_index: *mut i32,
    handles: *const Handle,
    handle_count: u32,
    reply_target: Handle,
    _timeout: i64,
) -> ResultCode {
    let msg = msg_buffer();
    if reply_target != 0 {
        with(|k| k.replies.push(*msg));
    }
    if handle_count == 0 {
        return svc::rc::ResultTimedOut::make();
    }
    let handle = unsafe { *handles };
    let incoming = with(|k| k.incoming.pop_front())
        .unwrap_or_else(|| panic!("reply_and_receive: no request queued"));
    assert_eq!(incoming.handle, handle, "request queued for another session");
    unsafe { *out_index = 0 };
    let list = read_receive_list(msg);
    with(|k| k.receive_lists.push(list.clone()));
    match receive(msg, &incoming, &list) {
        Ok(()) => ResultSuccess::make(),
        Err(rc) => {
            with(|k| k.undeliverable += 1);
            rc
        }
    }
}

fn word(msg: &Msg, i: usize) -> u32 {
    u32::from_le_bytes(msg[i * 4..i * 4 + 4].try_into().unwrap())
}

fn set_word(msg: &mut Msg, i: usize, v: u32) {
    msg[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
}

/// Word index past the raw data of the message's own header (where a receive list sits by
/// default), from the header and special header alone.
fn words_through_raw_data(words: &[u32]) -> usize {
    let (h0, h1) = (words[0], words[1]);
    let mut n = 2;
    if h1 >> 31 != 0 {
        let special = words[2];
        n += 1 + 2 * (special & 1) as usize + ((special >> 1) & 0xF) as usize + ((special >> 5) & 0xF) as usize;
    }
    n += 2 * ((h0 >> 16) & 0xF) as usize;
    n += 3 * (((h0 >> 20) & 0xF) + ((h0 >> 24) & 0xF) + ((h0 >> 28) & 0xF)) as usize;
    n + (h1 & 0x3FF) as usize
}

fn read_receive_list(msg: &Msg) -> ReceiveList {
    let words: Vec<u32> = (0..MSG_SIZE / 4).map(|i| word(msg, i)).collect();
    let mode = (words[1] >> 10) & 0xF;
    let offset = ((words[1] >> 20) & 0x7FF) as usize;
    let at = if offset != 0 { offset } else { words_through_raw_data(&words) };
    let count = match mode {
        0 | 1 => 0,
        2 => 1,
        n => n as usize - 2,
    };
    let entries = (0..count)
        .map(|e| {
            let (lo, hi) = (words[at + 2 * e], words[at + 2 * e + 1]);
            ((lo as usize) | (((hi & 0xFFFF) as usize) << 32), (hi >> 16) as usize)
        })
        .collect();
    (mode, entries)
}

fn receive(msg: &mut Msg, incoming: &Incoming, list: &ReceiveList) -> Result<(), ResultCode> {
    let words = &incoming.words;
    let len = words_through_raw_data(words);
    assert!(len <= words.len() && len <= MSG_SIZE / 4, "request shorter than its header says");
    // The server's buffer: our words, then whatever it held (zero).
    msg.fill(0);
    for (i, w) in words[..len].iter().enumerate() {
        set_word(msg, i, *w);
    }
    let (h0, h1) = (words[0], words[1]);
    let mut at = 2;
    if h1 >> 31 != 0 {
        let special = words[2];
        at += 1;
        if special & 1 != 0 {
            set_word(msg, at, incoming.process_id as u32);
            set_word(msg, at + 1, (incoming.process_id >> 32) as u32);
            at += 2;
        }
        at += ((special >> 1) & 0xF) as usize + ((special >> 5) & 0xF) as usize;
    }
    let x_count = ((h0 >> 16) & 0xF) as usize;
    assert_eq!(incoming.x_data.len(), x_count, "one x_data entry per X descriptor");
    let (mode, entries) = list;
    let mut key = 0usize; // single-buffer mode: bytes used so far
    for (i, data) in incoming.x_data.iter().enumerate() {
        let w = at + 2 * i;
        let bits = word(msg, w);
        let (index, size) = ((bits & 0x3F) as usize, (bits >> 16) as usize);
        assert_eq!(data.len(), size, "X descriptor {i}: data length != size field");
        let dest = if size == 0 {
            0
        } else {
            match *mode {
                2 => {
                    let (addr, cap) = entries[0];
                    let buf = (addr + key).next_multiple_of(0x10);
                    if buf + size > addr + cap {
                        return Err(svc::rc::ResultNotFound::make());
                    }
                    key = buf + size - addr;
                    buf
                }
                n if n > 2 => match entries.get(index) {
                    Some(&(addr, cap)) if cap >= size => addr,
                    _ => return Err(svc::rc::ResultNotFound::make()),
                },
                _ => return Err(svc::rc::ResultNotFound::make()),
            }
        };
        if size > 0 {
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dest as *mut u8, size) };
        }
        let addr_bits = (((dest >> 36) & 0x3F) << 6 | ((dest >> 32) & 0xF) << 12) as u32;
        set_word(msg, w, (bits & 0xFFFF_003F) | addr_bits);
        set_word(msg, w + 1, dest as u32);
    }
    Ok(())
}
