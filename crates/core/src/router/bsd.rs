//! The slice of the bsd:u ABI the router needs: `sockaddr_in`, errno values,
//! flags and option numbers (Nintendo/FreeBSD numbering).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// `sockaddr_in` exactly as the game passes it (BSD layout with `sin_len`).
///
/// `sin_port` and `sin_addr` are in **network byte order**, in what the game
/// passes and in everything the router stores or returns. LDN IPs elsewhere
/// (ProxyInfo, ProxyConfig, `Router::local_ip`) are in **Ryujinx format**:
/// big-endian read as u32, `10.114.0.1 == 0x0A72_0001`. Cross only through
/// [`SockAddrIn::addr_ryujinx`] / [`SockAddrIn::from_ryujinx`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct SockAddrIn {
    pub sin_len: u8,
    pub sin_family: u8,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}
const _: () = assert!(size_of::<SockAddrIn>() == 16);

pub const AF_INET: u8 = 2;

impl SockAddrIn {
    /// An AF_INET address from a Ryujinx-format IP and a host-order port.
    pub const fn from_ryujinx(ip: u32, port: u16) -> Self {
        Self { sin_len: 16, sin_family: AF_INET, sin_port: port.to_be(), sin_addr: ip.to_be(), sin_zero: [0; 8] }
    }
    /// The IP in Ryujinx format.
    pub const fn addr_ryujinx(&self) -> u32 {
        u32::from_be(self.sin_addr)
    }
    /// The port in host order.
    pub const fn port(&self) -> u16 {
        u16::from_be(self.sin_port)
    }
    /// Reads an AF_INET address from an IPC buffer (any alignment). `None`
    /// when it is short or another family: the call is then not ours.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        Self::read_from_prefix(buf).ok().map(|(a, _)| a).filter(|a| a.sin_family == AF_INET)
    }
}

/// errno values bsd:u returns (FreeBSD numbering, as `ryu_ldn::bsd::BsdErrno`).
pub mod errno {
    pub const EBADF: i32 = 9;
    pub const EAGAIN: i32 = 11;
    pub const ENOMEM: i32 = 12;
    pub const EINVAL: i32 = 22;
    pub const EDESTADDRREQ: i32 = 89;
    pub const EMSGSIZE: i32 = 90;
    pub const ENOPROTOOPT: i32 = 92;
    pub const EADDRINUSE: i32 = 98;
    pub const ENETDOWN: i32 = 100;
    pub const ENETUNREACH: i32 = 101;
    pub const ENOTCONN: i32 = 107;
}

pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
/// socket() type flag: start non-blocking.
pub const SOCK_NONBLOCK: i32 = 0x2000_0000;
/// Strips SOCK_NONBLOCK / SOCK_CLOEXEC from a socket() type.
pub const SOCK_TYPE_MASK: i32 = 0x0FFF_FFFF;

pub const MSG_PEEK: i32 = 0x2;
pub const MSG_DONTWAIT: i32 = 0x80;

pub const F_SETFL: i32 = 4;
pub const O_NONBLOCK: i32 = 0x4;
pub const FIONBIO: u32 = 0x8004_667E;
pub const FIONREAD: u32 = 0x4004_667F;

pub const SOL_SOCKET: i32 = 0xFFFF;
pub const SO_BROADCAST: i32 = 0x0020;
pub const SO_RCVTIMEO: i32 = 0x1006;
pub const SO_ERROR: i32 = 0x1007;
pub const SO_TYPE: i32 = 0x1008;

pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

/// SO_RCVTIMEO's 64-bit `struct timeval` (16 bytes) in nanoseconds; 0 = none.
pub fn timeval_ns(optval: &[u8]) -> Option<i64> {
    let (sec, rest) = i64::read_from_prefix(optval).ok()?;
    let (usec, _) = i64::read_from_prefix(rest).ok()?;
    Some(sec.saturating_mul(1_000_000_000).saturating_add(usec.saturating_mul(1000)).max(0))
}
