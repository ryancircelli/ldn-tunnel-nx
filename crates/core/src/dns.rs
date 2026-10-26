//! Minimal DNS A-record codec (port of the query builder and response parser in
//! `network/dns_wrap.cpp`). The shell sends the query over its own UDP socket: libnx-style
//! `getaddrinfo` goes through `sfdnsres`, which crashed the C++ module from boot2.

use core::net::Ipv4Addr;

/// Classic DNS over UDP limit; what both the query and the reply buffers need.
pub const MAX_MESSAGE: usize = 512;
pub const PORT: u16 = 53;

const HEADER: usize = 12;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// Bad hostname, or `out` too small.
    BadName,
    /// Not a reply to our query (wrong id, not a response): keep waiting.
    NotOurs,
    /// Reply cut short or inconsistent.
    Malformed,
    /// TC bit: the answer did not fit in UDP. Retry (another server).
    Truncated,
    /// NXDOMAIN or no A record: retrying cannot help.
    NoName,
    /// SERVFAIL, REFUSED or any other RCODE.
    ServerFailure,
}

/// Writes a recursive A/IN query for `host` with `id` into `out`; returns its length.
pub fn build_query(host: &str, id: u16, out: &mut [u8]) -> Result<usize, DnsError> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return Err(DnsError::BadName);
    }
    let mut w = Writer { out, at: 0 };
    // id, flags RD, QDCOUNT 1, AN/NS/AR 0
    w.put(&id.to_be_bytes())?;
    w.put(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])?;
    for label in host.split('.') {
        let len = u8::try_from(label.len()).map_err(|_| DnsError::BadName)?;
        if len == 0 || len > 63 {
            return Err(DnsError::BadName);
        }
        w.put(&[len])?;
        w.put(label.as_bytes())?;
    }
    w.put(&[0])?;
    w.put(&TYPE_A.to_be_bytes())?;
    w.put(&CLASS_IN.to_be_bytes())?;
    Ok(w.at)
}

struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, b: &[u8]) -> Result<(), DnsError> {
        let end = self.at.checked_add(b.len()).ok_or(DnsError::BadName)?;
        self.out.get_mut(self.at..end).ok_or(DnsError::BadName)?.copy_from_slice(b);
        self.at = end;
        Ok(())
    }
}

/// First A record in the reply to query `id`. CNAME answers before it are skipped (the
/// resolver puts the chain and its final A records in the answer section).
pub fn parse_response(msg: &[u8], id: u16) -> Result<Ipv4Addr, DnsError> {
    let mut r = Reader { msg, at: 0 };
    let (rid, flags) = (r.u16()?, r.u16()?);
    if rid != id || flags & 0x8000 == 0 {
        return Err(DnsError::NotOurs);
    }
    if flags & 0x0200 != 0 {
        return Err(DnsError::Truncated);
    }
    match flags & 0x000F {
        0 => {}
        3 => return Err(DnsError::NoName),
        _ => return Err(DnsError::ServerFailure),
    }
    let (qd, an) = (r.u16()?, r.u16()?);
    r.at = HEADER;
    for _ in 0..qd {
        r.skip_name()?;
        r.skip(4)?;
    }
    for _ in 0..an {
        r.skip_name()?;
        let (rtype, class) = (r.u16()?, r.u16()?);
        r.skip(4)?; // TTL
        let len = usize::from(r.u16()?);
        let start = r.at;
        r.skip(len)?;
        if rtype == TYPE_A && class == CLASS_IN && len == 4 {
            let b = msg.get(start..r.at).ok_or(DnsError::Malformed)?;
            let ip: [u8; 4] = b.try_into().map_err(|_| DnsError::Malformed)?;
            return Ok(Ipv4Addr::from(ip));
        }
    }
    Err(DnsError::NoName)
}

struct Reader<'a> {
    msg: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn skip(&mut self, n: usize) -> Result<(), DnsError> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.msg.len()).ok_or(DnsError::Malformed)?;
        self.at = end;
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, DnsError> {
        let b = *self.msg.get(self.at).ok_or(DnsError::Malformed)?;
        self.skip(1)?;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, DnsError> {
        Ok(u16::from(self.u8()?) << 8 | u16::from(self.u8()?))
    }

    /// Labels up to the root label, or up to a compression pointer (2 bytes, ends the name).
    fn skip_name(&mut self) -> Result<(), DnsError> {
        loop {
            match self.u8()? {
                0 => return Ok(()),
                l if l & 0xC0 == 0xC0 => return self.skip(1),
                l if l & 0xC0 == 0 => self.skip(usize::from(l))?,
                _ => return Err(DnsError::Malformed), // 0x40 / 0x80: reserved label types
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn query(host: &str) -> Vec<u8> {
        let mut out = [0u8; MAX_MESSAGE];
        let n = build_query(host, 0xBEEF, &mut out).unwrap();
        out[..n].to_vec()
    }

    #[test]
    fn query_bytes() {
        let q = query("relay.example.com");
        let mut want = Vec::from([0xBE, 0xEF, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        want.extend_from_slice(b"\x05relay\x07example\x03com\x00\x00\x01\x00\x01");
        assert_eq!(q, want);
        assert_eq!(query("relay.example.com."), want); // trailing root dot
    }

    #[test]
    fn query_rejects_bad_names() {
        let mut out = [0u8; MAX_MESSAGE];
        for bad in ["", ".", "a..b", ".a", &"x".repeat(64), &"a.".repeat(128)] {
            assert_eq!(build_query(bad, 1, &mut out), Err(DnsError::BadName), "{bad:?}");
        }
        assert_eq!(build_query("example.com", 1, &mut out[..20]), Err(DnsError::BadName));
        assert!(build_query(&"x".repeat(63), 1, &mut out).is_ok());
    }

    /// Reply to `query("relay.example.com")`: a CNAME (compressed name), then an A record.
    fn reply(flags: u16, an: u16) -> Vec<u8> {
        let mut m = query("relay.example.com");
        m[2..4].copy_from_slice(&flags.to_be_bytes());
        m[6..8].copy_from_slice(&an.to_be_bytes());
        // CNAME relay.example.com -> x.example.com (pointer to "example.com" at offset 18)
        m.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, b'x', 0xC0, 18]);
        // A x.example.com = 203.0.113.7 (pointer to the CNAME target at offset 47)
        m.extend_from_slice(&[0xC0, 47, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7]);
        m
    }

    #[test]
    fn parses_first_a_after_cname() {
        assert_eq!(parse_response(&reply(0x8180, 2), 0xBEEF), Ok(Ipv4Addr::new(203, 0, 113, 7)));
    }

    #[test]
    fn errors() {
        assert_eq!(parse_response(&reply(0x8180, 2), 0xBEEE), Err(DnsError::NotOurs));
        assert_eq!(parse_response(&reply(0x0100, 2), 0xBEEF), Err(DnsError::NotOurs)); // a query
        assert_eq!(parse_response(&reply(0x8380, 2), 0xBEEF), Err(DnsError::Truncated));
        assert_eq!(parse_response(&reply(0x8183, 0), 0xBEEF), Err(DnsError::NoName));
        assert_eq!(parse_response(&reply(0x8182, 0), 0xBEEF), Err(DnsError::ServerFailure));
        assert_eq!(parse_response(&reply(0x8185, 0), 0xBEEF), Err(DnsError::ServerFailure));
        assert_eq!(parse_response(&reply(0x8180, 1), 0xBEEF), Err(DnsError::NoName)); // CNAME only
        let full = reply(0x8180, 2);
        for cut in 0..full.len() {
            assert!(parse_response(&full[..cut], 0xBEEF).is_err(), "cut at {cut}");
        }
        let mut long = reply(0x8180, 2);
        long[6..8].copy_from_slice(&3u16.to_be_bytes()); // claims a third answer, A comes first
        assert!(parse_response(&long, 0xBEEF).is_ok());
    }

    #[test]
    fn random_input_never_panics() {
        let mut x = 0x1234_5678u32;
        let mut buf = [0u8; 64];
        for _ in 0..20_000 {
            for b in buf.iter_mut() {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                *b = x as u8;
            }
            buf[0] = 0xBE;
            buf[1] = 0xEF;
            buf[2] |= 0x80;
            let _ = parse_response(&buf[..(x as usize % 64)], 0xBEEF);
        }
    }
}
