//! Pure logic of ldn-tunnel. `no_std`, no allocator, no I/O: every module here
//! runs under `cargo test` on the host and is driven by the Horizon shell
//! (`crates/sys`) on the console.
#![no_std]
#![forbid(unsafe_code)]

pub mod ident;
pub mod config;
pub mod dns;
pub mod hipc;
pub mod ldn;
pub mod conn;
pub mod logring;
pub mod update;
pub mod update_pubkey;
pub mod whitelist;
pub mod packet_buffer;
pub mod protocol;
pub mod router;
pub mod wire;
pub mod ws;
pub mod cfg_types;
pub mod ldn_types;
pub mod notify;
pub mod compat;

/// `fmt::Write` into a byte slice; fails (writing nothing) once a string does not fit.
pub(crate) struct SliceWriter<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}

impl core::fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.pos.saturating_add(s.len());
        self.buf.get_mut(self.pos..end).ok_or(core::fmt::Error)?.copy_from_slice(s.as_bytes());
        self.pos = end;
        Ok(())
    }
}
