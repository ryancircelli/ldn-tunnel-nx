//! Fixed-size FIFO of variable-length datagrams (port of C++ `PacketRing`).
//!
//! Records are stored back to back as `[u16 len][Meta][payload]` in one
//! `heapless::Deque<u8, N>`, so a 100-byte keepalive costs 114 bytes, not an
//! MTU-sized slot. A push that does not fit drops the oldest records (UDP).

use heapless::Deque;

/// Addressing kept with each datagram, all Ryujinx format / host order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
}

const META: usize = 12;
const HDR: usize = 2 + META;

impl Meta {
    fn encode(self, len: u16) -> [u8; HDR] {
        let mut b = [0u8; HDR];
        let parts: [&[u8]; 5] = [
            &len.to_le_bytes(),
            &self.src_ip.to_le_bytes(),
            &self.src_port.to_le_bytes(),
            &self.dst_ip.to_le_bytes(),
            &self.dst_port.to_le_bytes(),
        ];
        for (d, s) in b.iter_mut().zip(parts.into_iter().flatten()) {
            *d = *s;
        }
        b
    }

    fn decode(b: [u8; HDR]) -> (u16, Self) {
        let [l0, l1, a0, a1, a2, a3, p0, p1, d0, d1, d2, d3, q0, q1] = b;
        let meta = Self {
            src_ip: u32::from_le_bytes([a0, a1, a2, a3]),
            src_port: u16::from_le_bytes([p0, p1]),
            dst_ip: u32::from_le_bytes([d0, d1, d2, d3]),
            dst_port: u16::from_le_bytes([q0, q1]),
        };
        (u16::from_le_bytes([l0, l1]), meta)
    }
}

pub struct PacketRing<const N: usize> {
    buf: Deque<u8, N>,
    count: usize,
    payload_bytes: usize,
}

impl<const N: usize> PacketRing<N> {
    pub const fn new() -> Self {
        Self { buf: Deque::new(), count: 0, payload_bytes: 0 }
    }

    /// Appends a datagram, dropping the oldest ones to make room. Returns how
    /// many were dropped, or `None` (nothing changed) if it can never fit.
    pub fn push(&mut self, meta: Meta, data: &[u8]) -> Option<usize> {
        let len = u16::try_from(data.len()).ok()?;
        let need = HDR.checked_add(data.len()).filter(|&n| n <= N)?;
        let mut dropped = 0usize;
        while N.saturating_sub(self.buf.len()) < need && self.pop() {
            dropped = dropped.saturating_add(1);
        }
        for b in meta.encode(len).iter().chain(data) {
            // Cannot fail: `need` bytes are free.
            let _ = self.buf.push_back(*b);
        }
        self.count = self.count.saturating_add(1);
        self.payload_bytes = self.payload_bytes.saturating_add(data.len());
        Some(dropped)
    }

    fn header(&self) -> Option<(u16, Meta)> {
        if self.count == 0 {
            return None;
        }
        let mut h = [0u8; HDR];
        for (d, s) in h.iter_mut().zip(self.buf.iter()) {
            *d = *s;
        }
        Some(Meta::decode(h))
    }

    /// Copies the oldest datagram's first `out.len()` bytes out without
    /// removing it; returns its full length and meta.
    pub fn front(&self, out: &mut [u8]) -> Option<(usize, Meta)> {
        let (len, meta) = self.header()?;
        for (d, s) in out.iter_mut().zip(self.buf.iter().skip(HDR).take(usize::from(len))) {
            *d = *s;
        }
        Some((usize::from(len), meta))
    }

    /// Removes the oldest datagram; false if empty.
    pub fn pop(&mut self) -> bool {
        let Some((len, _)) = self.header() else { return false };
        for _ in 0..HDR.saturating_add(usize::from(len)) {
            self.buf.pop_front();
        }
        self.count = self.count.saturating_sub(1);
        self.payload_bytes = self.payload_bytes.saturating_sub(usize::from(len));
        true
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.count = 0;
        self.payload_bytes = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn count(&self) -> usize {
        self.count
    }
    /// Sum of queued payload lengths (FIONREAD).
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
}
