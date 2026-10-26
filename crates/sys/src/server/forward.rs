//! Asynchronous forwarding of a MitM'd request to the real service, so a call
//! that blocks inside the real service (Recv, Accept, Poll...) never blocks our
//! server thread. See README.md for where this sits in the design.
// Raw IPC/SVC calls (async forwarding, handle plumbing); each block carries a SAFETY comment.
#![allow(unsafe_code)]

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use nx::ipc::{self, cmif};
use nx::result::{Result, ResultCode};
use nx::svc;
use nx::sync::Mutex;

/// Size of an IPC message (the TLS message area).
pub const MSG_SIZE: usize = 0x100;

/// svcSendAsyncRequestWithUserBuffer wants a page-aligned, page-sized buffer.
#[repr(C, align(0x1000))]
struct Page([u8; 0x1000]);

/// One request in flight to the real service.
///
/// The kernel reads `data` when the real service receives the request and
/// writes `page` and `recv` when it replies, so all three stay put until
/// `event` signals. Dropping an unfinished forward parks them in ORPHANS (see Drop).
pub struct Forward {
    page: Box<Page>,
    /// Copies of the request's X (pointer) data; the request's X descriptors point here.
    data: Vec<u8>,
    /// Receive list of the forwarded request: X data of the reply lands here.
    recv: Vec<u8>,
    event: svc::Handle,
    /// finish() ran, so the kernel is done with the buffers. The server manager resets
    /// `event` before resuming, so the event alone cannot tell a finished forward apart.
    done: bool,
}

/// Copies the request currently in the TLS message buffer.
pub fn snapshot() -> [u8; MSG_SIZE] {
    let mut msg = [0u8; MSG_SIZE];
    // SAFETY: the TLS message buffer is MSG_SIZE bytes, owned by this thread.
    unsafe { core::ptr::copy_nonoverlapping(ipc::get_msg_buffer(), msg.as_mut_ptr(), MSG_SIZE) };
    msg
}

impl Forward {
    /// Sends `msg` (a request as received from our client, see [`snapshot`]) to
    /// `session`. `recv_size` bounds the X data of the reply (our pointer buffer size).
    pub fn start(msg: &[u8; MSG_SIZE], session: svc::Handle, recv_size: usize) -> Result<Self> {
        reap_orphans();
        let mut page = Box::new(Page([0; 0x1000]));
        page.0[..MSG_SIZE].copy_from_slice(msg);
        let words = page.0.as_mut_ptr().cast::<u32>();

        // The X data still sits in the server manager's pointer buffer, which
        // the next request overwrites; the real service may read it later.
        // SAFETY: `words` is the 0x100-byte message copied above; every index
        // read or written is checked against it by `send_statics`.
        let statics = unsafe { send_statics(words) };
        // SAFETY: descriptor indices from `send_statics` are inside the message.
        let total = statics.clone().map(|i| unsafe { x_size(words, i) }).sum();
        let mut data = vec![0u8; total];
        let mut offset = 0;
        for i in statics {
            // SAFETY: as above for the descriptor; its source address/size were
            // validated by the kernel when it copied our client's X data into
            // our pointer buffer, and `data` has room for every descriptor.
            unsafe {
                let size = x_size(words, i);
                let dst = data.as_mut_ptr().add(offset);
                core::ptr::copy_nonoverlapping(x_address(words, i), dst, size);
                set_x_address(words, i, dst);
                offset = offset.saturating_add(size);
            }
        }

        let mut recv = vec![0u8; recv_size];
        // SAFETY: the message is a whole CMIF request in a buffer of at least
        // 0x100 bytes; `recv` outlives the request (owned by the Forward).
        unsafe {
            cmif::server::prepare_mitm_forward(page.0.as_mut_ptr(), recv.as_mut_ptr(), recv.len())
        };

        // SAFETY: `page` is page-aligned and one page long, and stays allocated
        // until the kernel signals `event` (or forever, see Drop).
        let event = unsafe { svc::send_async_request_with_user_data(&mut page.0, session)? };
        Ok(Self {
            page,
            data,
            recv,
            event,
            done: false,
        })
    }

    /// Signals once the real service has replied.
    pub fn event(&self) -> svc::Handle {
        self.event
    }

    /// Copies the reply into the TLS message buffer, ready for the server
    /// manager to send to our client. Call only after `event` signalled. The
    /// reply's X descriptors point into this Forward, so keep it alive until
    /// that reply has been sent.
    pub fn finish(&mut self) -> Result<()> {
        self.done = true;
        let words = self.page.0.as_ptr().cast::<u32>();
        // SAFETY: the kernel has finished with the page (event signalled).
        unsafe {
            // A failed async request comes back as an all-zero header followed
            // by the result (Horizon's MessageBuffer::SetAsyncResult).
            if *words == 0 && *words.add(1) == 0 {
                return Err(ResultCode::new(*words.add(2)));
            }
            core::ptr::copy_nonoverlapping(self.page.0.as_ptr(), ipc::get_msg_buffer(), MSG_SIZE);
        }
        Ok(())
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        if !self.done && svc::wait_synchronization_one(self.event, 0).is_err() {
            // Still in flight (our client went away mid-call): the kernel may yet write
            // these, so they wait in ORPHANS until the real service replies.
            let orphan = Orphan {
                _page: core::mem::replace(&mut self.page, Box::new(Page([0; 0x1000]))),
                _data: core::mem::take(&mut self.data),
                _recv: core::mem::take(&mut self.recv),
                event: self.event,
            };
            ORPHANS.lock().push(orphan);
            return; // the orphan owns the event now
        }
        let _ = svc::close_handle(self.event);
    }
}

/// Buffers of an abandoned forward, kept until its reply event signals.
struct Orphan {
    _page: Box<Page>,
    _data: Vec<u8>,
    _recv: Vec<u8>,
    event: svc::Handle,
}

impl Drop for Orphan {
    fn drop(&mut self) {
        let _ = svc::close_handle(self.event);
    }
}

static ORPHANS: Mutex<Vec<Orphan>> = Mutex::new(Vec::new());

/// Frees abandoned forwards whose real call has ended (the kernel is done with them).
fn reap_orphans() {
    ORPHANS.lock().retain(|o| svc::wait_synchronization_one(o.event, 0).is_err());
}

/// The CMIF result and output raw data of the reply in the TLS message
/// buffer, or None if it isn't a well-formed CMIF reply (domain or not).
pub fn reply_raw() -> Option<(u32, [u8; 16])> {
    ldn_tunnel_core::hipc::reply_raw(&snapshot())
}

// --- HIPC header walking (see switchbrew "IPC_Marshalling") ---
//
// Contract of every `unsafe fn` below: `words` points at a whole MSG_SIZE message (64 readable
// u32; the first three are read before `layout` has checked anything), and an index `i` comes
// from `send_statics`, which only yields descriptors `layout` proved lie inside the message.

/// Word index of the first X descriptor and the data section's (start, length) in words.
unsafe fn layout(words: *const u32) -> Option<(usize, usize, usize)> {
    let max = MSG_SIZE / 4;
    // SAFETY (all reads): the caller passes a MSG_SIZE message; indices are checked.
    unsafe {
        let h0 = *words;
        let h1 = *words.add(1);
        let mut i = 2usize;
        if h1 >> 31 != 0 {
            let special = *words.add(2);
            i = i.saturating_add(1);
            if special & 1 != 0 {
                i = i.saturating_add(2);
            }
            // Nibbles: at most 15 + 15 words.
            i = i.saturating_add(((special >> 1) & 0xF) as usize).saturating_add(((special >> 5) & 0xF) as usize);
        }
        let x_start = i;
        let x = ((h0 >> 16) & 0xF) as usize;
        let abw = [20, 24, 28].map(|s| ((h0 >> s) & 0xF) as usize).iter().sum::<usize>();
        // All terms are tiny (nibbles, 10 bits): saturating only so overflow is impossible by construction.
        let data_start = x_start.saturating_add(x.saturating_mul(2)).saturating_add(abw.saturating_mul(3));
        let data_words = (h1 & 0x3FF) as usize;
        (data_start.saturating_add(data_words) <= max).then_some((x_start, data_start, data_words))
    }
}

/// Word indices of the X descriptors (empty if the header is malformed).
unsafe fn send_statics(words: *const u32) -> core::iter::StepBy<core::ops::Range<usize>> {
    // SAFETY: forwarded to the caller. A header `layout` accepts keeps every
    // descriptor (and the data after them) inside the message.
    let count = match unsafe { layout(words) } {
        Some((x_start, _, _)) => x_start..x_start.saturating_add(unsafe { x_count(words) }.saturating_mul(2)),
        None => 0..0,
    };
    count.step_by(2)
}

unsafe fn x_count(words: *const u32) -> usize {
    // SAFETY: forwarded to the caller.
    unsafe { ((*words >> 16) & 0xF) as usize }
}

unsafe fn x_size(words: *const u32, i: usize) -> usize {
    // SAFETY: forwarded to the caller (i is a descriptor index from send_statics).
    unsafe { (*words.add(i) >> 16) as usize }
}

unsafe fn x_address(words: *const u32, i: usize) -> *const u8 {
    // SAFETY: forwarded to the caller.
    unsafe {
        let w0 = *words.add(i) as usize;
        let low = *words.add(i.saturating_add(1)) as usize;
        (low | ((w0 >> 12) & 0xF) << 32 | ((w0 >> 6) & 0x7) << 36) as *const u8
    }
}

unsafe fn set_x_address(words: *mut u32, i: usize, address: *const u8) {
    let a = address as usize;
    // SAFETY: forwarded to the caller.
    unsafe {
        let w0 = *words.add(i) & !(0xF << 12 | 0x7 << 6);
        *words.add(i) = w0 | (((a >> 32) & 0xF) << 12) as u32 | (((a >> 36) & 0x7) << 6) as u32;
        *words.add(i.saturating_add(1)) = a as u32;
    }
}
