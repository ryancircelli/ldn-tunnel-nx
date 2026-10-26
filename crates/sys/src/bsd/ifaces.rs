//! The bsd:u interface as the MitM serves it (commands of the C++
//! ibsd_mitm_service.hpp, ids as on Horizon). Commands not listed here
//! (7 Sysctl, 23 ShutdownAllSockets, 27 DuplicateSocket, 28-32 ...) are
//! forwarded untouched by the service layer.
//!
//! Wire rules this follows (nx-derive):
//! - raw inputs are read in declaration order with natural alignment, so the
//!   order below is the libnx struct order;
//! - raw inputs come before buffers, because an out AutoSelect buffer reads its
//!   u16 size from just after the raw data;
//! - every int is a plain i32/u32: a MitM must pass through values it does not
//!   know, so no enums or bit sets here.
//!
//! Outputs are (ret, errno[, length]) as the real bsd:u returns them; ret < 0
//! means failure with errno.

use ldn_tunnel_core::compat::BSD_REGISTER_CLIENT_SHARED;
use nx::ipc::sf::{CopyHandle, InAutoSelectBuffer, OutAutoSelectBuffer, ProcessId};
use nx::ipc::sf::{Request, Response};

use crate::compat;

/// LibraryConfigData / BsdInitConfig: the client's buffer sizing (32 bytes).
#[derive(Copy, Clone, Debug, Default, Request, Response)]
#[repr(C)]
pub struct LibraryConfig {
    pub version: u32,
    pub tcp_tx_buf_size: u32,
    pub tcp_rx_buf_size: u32,
    pub tcp_tx_buf_max_size: u32,
    pub tcp_rx_buf_max_size: u32,
    pub udp_tx_buf_size: u32,
    pub udp_rx_buf_size: u32,
    pub sb_efficiency: u32,
}

/// Select's timeout (24 bytes, at offset 8 after nfds). `is_null`: wait forever.
#[derive(Copy, Clone, Debug, Default, Request, Response)]
#[repr(C)]
pub struct SelectTimeval {
    pub sec: i64,
    pub usec: i64,
    pub is_null: bool,
}

/// One entry of Poll's fd buffers (not an IPC parameter: the buffers are bytes).
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

// These cross IPC as raw bytes; the sizes are the bsd:u ABI.
const _: () = assert!(size_of::<LibraryConfig>() == 32);
const _: () = assert!(size_of::<SelectTimeval>() == 24);
const _: () = assert!(size_of::<PollFd>() == 8);
const _: () = assert!(size_of::<FdSet>() == 128);

/// fd_set as Select carries it: 1024 bits.
pub type FdSet = [u64; 16];

#[nx::ipc::sf::ipc_trait]
pub trait BsdMitm {
    /// In: config(32) + pid placeholder(8) + tmem size(8); the pid comes from
    /// the kernel. The transfer memory handle is copied into our process.
    #[ipc_rid(0)]
    fn register_client(
        &mut self,
        config: LibraryConfig,
        pid: ProcessId,
        tmem_size: u64,
        tmem: CopyHandle,
    ) -> u64;

    #[ipc_rid(2)]
    fn socket(&mut self, domain: i32, ty: i32, protocol: i32) -> (i32, i32);

    #[ipc_rid(3)]
    fn socket_exempt(&mut self, domain: i32, ty: i32, protocol: i32) -> (i32, i32);

    #[ipc_rid(5)]
    fn select(
        &mut self,
        nfds: i32,
        timeout: SelectTimeval,
        readfds_in: InAutoSelectBuffer<u8>,
        writefds_in: InAutoSelectBuffer<u8>,
        errorfds_in: InAutoSelectBuffer<u8>,
        readfds_out: OutAutoSelectBuffer<u8>,
        writefds_out: OutAutoSelectBuffer<u8>,
        errorfds_out: OutAutoSelectBuffer<u8>,
    ) -> (i32, i32);

    #[ipc_rid(6)]
    fn poll(
        &mut self,
        nfds: i32,
        timeout: i32,
        fds_in: InAutoSelectBuffer<u8>,
        fds_out: OutAutoSelectBuffer<u8>,
    ) -> (i32, i32);

    #[ipc_rid(8)]
    fn recv(&mut self, fd: i32, flags: i32, buf: OutAutoSelectBuffer<u8>) -> (i32, i32);

    #[ipc_rid(9)]
    fn recv_from(
        &mut self,
        fd: i32,
        flags: i32,
        buf: OutAutoSelectBuffer<u8>,
        addr: OutAutoSelectBuffer<u8>,
    ) -> (i32, i32, u32);

    #[ipc_rid(10)]
    fn send(&mut self, fd: i32, flags: i32, buf: InAutoSelectBuffer<u8>) -> (i32, i32);

    #[ipc_rid(11)]
    fn send_to(
        &mut self,
        fd: i32,
        flags: i32,
        buf: InAutoSelectBuffer<u8>,
        addr: InAutoSelectBuffer<u8>,
    ) -> (i32, i32);

    #[ipc_rid(12)]
    fn accept(&mut self, fd: i32, addr: OutAutoSelectBuffer<u8>) -> (i32, i32, u32);

    #[ipc_rid(13)]
    fn bind(&mut self, fd: i32, addr: InAutoSelectBuffer<u8>) -> (i32, i32);

    #[ipc_rid(14)]
    fn connect(&mut self, fd: i32, addr: InAutoSelectBuffer<u8>) -> (i32, i32);

    #[ipc_rid(15)]
    fn get_peer_name(&mut self, fd: i32, addr: OutAutoSelectBuffer<u8>) -> (i32, i32, u32);

    #[ipc_rid(16)]
    fn get_sock_name(&mut self, fd: i32, addr: OutAutoSelectBuffer<u8>) -> (i32, i32, u32);

    #[ipc_rid(17)]
    fn get_sock_opt(
        &mut self,
        fd: i32,
        level: i32,
        optname: i32,
        optval: OutAutoSelectBuffer<u8>,
    ) -> (i32, i32, u32);

    #[ipc_rid(18)]
    fn listen(&mut self, fd: i32, backlog: i32) -> (i32, i32);

    #[ipc_rid(19)]
    fn ioctl(
        &mut self,
        fd: i32,
        request: u32,
        bufcount: u32,
        in1: InAutoSelectBuffer<u8>,
        in2: InAutoSelectBuffer<u8>,
        in3: InAutoSelectBuffer<u8>,
        in4: InAutoSelectBuffer<u8>,
        out1: OutAutoSelectBuffer<u8>,
        out2: OutAutoSelectBuffer<u8>,
        out3: OutAutoSelectBuffer<u8>,
        out4: OutAutoSelectBuffer<u8>,
    ) -> (i32, i32);

    #[ipc_rid(20)]
    fn fcntl(&mut self, fd: i32, cmd: i32, arg: i32) -> (i32, i32);

    #[ipc_rid(21)]
    fn set_sock_opt(
        &mut self,
        fd: i32,
        level: i32,
        optname: i32,
        optval: InAutoSelectBuffer<u8>,
    ) -> (i32, i32);

    #[ipc_rid(22)]
    fn shutdown(&mut self, fd: i32, how: i32) -> (i32, i32);

    #[ipc_rid(24)]
    fn write(&mut self, fd: i32, buf: InAutoSelectBuffer<u8>) -> (i32, i32);

    #[ipc_rid(25)]
    fn read(&mut self, fd: i32, buf: OutAutoSelectBuffer<u8>) -> (i32, i32);

    #[ipc_rid(26)]
    fn close(&mut self, fd: i32) -> (i32, i32);

    /// RegisterClient without the transfer memory.
    #[ipc_rid(33)]
    #[version(compat::since(BSD_REGISTER_CLIENT_SHARED))]
    fn register_client_shared(
        &mut self,
        config: LibraryConfig,
        pid: ProcessId,
        tmem_size: u64,
    ) -> u64;
}
