//! Hostname -> IPv4 for the relay (port of network/dns_wrap.cpp). Horizon's resolver
//! (`sfdnsres`, behind libnx's getaddrinfo) crashed the C++ module from boot2, so this
//! asks the DNS server directly over our own UDP socket. Codec: `ldn_tunnel_core::dns`.
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use core::net::Ipv4Addr;

use ldn_tunnel_core::dns::{self, DnsError};
use nx::ipc::sf::ProcessId;
use nx::service::new_service_object;

use super::ipc::{INifmGeneralClient, INifmStaticClient, NifmStatic};
use super::socket::{NetError, UdpSocket};

/// Google DNS, the C++ module's last resort.
const FALLBACK: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
/// dns_wrap.cpp: 3 attempts (server 1, server 2, then the last one again), 1.5 s each.
const ATTEMPTS: usize = 3;
const ATTEMPT_TIMEOUT_MS: u64 = 1500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The name does not exist or has no A record (retrying will not help).
    NoName,
    /// Bad hostname.
    BadName,
    /// No usable answer from any server (timeouts, SERVFAIL, socket errors).
    Failed,
}

/// The DNS servers of the current connection (nifm), then [`FALLBACK`]; no duplicates.
fn servers() -> Vec<Ipv4Addr> {
    let mut out = Vec::with_capacity(3);
    let nifm = new_service_object::<NifmStatic>()
        .and_then(|s| s.create_general_service(ProcessId::new()))
        .and_then(|g| g.get_current_ip_config_info());
    let mut add = |ip: Ipv4Addr| {
        if !ip.is_unspecified() && !out.contains(&ip) {
            out.push(ip);
        }
    };
    match nifm {
        Ok(info) => info.dns().into_iter().for_each(&mut add),
        Err(rc) => log!(Warning, "dns: nifm ip config unavailable ({rc:?}), using {FALLBACK}"),
    }
    add(FALLBACK);
    out
}

/// IP literals are returned as they are; names are asked of each server in turn.
pub fn resolve(host: &str) -> Result<Ipv4Addr, ResolveError> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let servers = servers();
    let mut last = DnsError::ServerFailure;
    for attempt in 0..ATTEMPTS {
        let Some(&server) = servers.get(attempt).or(servers.last()) else { break };
        match query(host, server) {
            Ok(ip) => {
                log!(Info, "dns: {host} -> {ip} (server {server}, attempt {})", attempt.saturating_add(1));
                return Ok(ip);
            }
            Err(Ok(e @ (DnsError::NoName | DnsError::BadName))) => {
                log!(Warning, "dns: {host}: {e:?} from {server}");
                return Err(if e == DnsError::NoName { ResolveError::NoName } else { ResolveError::BadName });
            }
            Err(Ok(e)) => {
                last = e;
                log!(Warning, "dns: {host}: {e:?} from {server}");
            }
            Err(Err(e)) => log!(Warning, "dns: {host}: {e:?} asking {server}"),
        }
    }
    log!(Error, "dns: {host} not resolved (last answer {last:?})");
    Err(ResolveError::Failed)
}

/// One query to one server: the IP, a DNS-level error (`Err(Ok)`) or a socket error.
fn query(host: &str, server: Ipv4Addr) -> Result<Ipv4Addr, Result<DnsError, NetError>> {
    let id = u16::from_ne_bytes(super::rng::bytes());
    let mut buf = [0u8; dns::MAX_MESSAGE];
    let n = dns::build_query(host, id, &mut buf).map_err(Ok)?;
    // Step logs: which bsd call fails (an Ipc error means the bsd:s session itself broke).
    let step = |what: &'static str| move |e: NetError| {
        log!(Warning, "dns: {what} failed: {e:?}");
        Err(e)
    };
    let sock = UdpSocket::new().map_err(step("socket"))?;
    sock.send_to(buf.get(..n).unwrap_or_default(), server, dns::PORT).map_err(step("send_to"))?;
    let deadline = crate::state::uptime_ms().saturating_add(ATTEMPT_TIMEOUT_MS);
    loop {
        let left = deadline.saturating_sub(crate::state::uptime_ms());
        if left == 0 {
            return Err(Err(NetError::TimedOut));
        }
        let (len, from, port) = sock.recv_from(&mut buf, left as i32).map_err(step("recv_from"))?;
        if from != server || port != dns::PORT {
            continue; // stray datagram: keep waiting for ours
        }
        match dns::parse_response(buf.get(..len).unwrap_or_default(), id) {
            Err(DnsError::NotOurs) => continue,
            r => return r.map_err(Ok),
        }
    }
}
