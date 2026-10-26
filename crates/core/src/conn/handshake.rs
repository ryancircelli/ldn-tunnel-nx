//! WebSocket upgrade request and response check (port of `WssClient::upgrade` in
//! `network/wss_client.cpp` and `ws::compute_accept`). Pure: the shell supplies 16 random
//! bytes for the key and moves the bytes over the TLS stream.
use core::fmt::Write;

use base64::{Engine, engine::general_purpose::STANDARD};
use sha1::{Digest, Sha1};

use crate::SliceWriter;
use crate::ws::{UpgradeResult, check_upgrade_response};

/// Base64 of the 16 random key bytes.
pub const KEY_LEN: usize = 24;
/// Base64 of a SHA-1 digest.
pub const ACCEPT_LEN: usize = 28;
/// RFC 6455 section 1.3.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Longest `Authorization` value plus request line the C++ buffer (640 bytes) allowed for.
pub const MAX_REQUEST: usize = 640;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// `out` cannot hold the request.
    BufferTooSmall,
    /// A host, path or token with a control character or space would split the header block.
    BadInput,
}

/// `Sec-WebSocket-Key` for the 16 random bytes.
pub fn encode_key(random: &[u8; 16]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    let _ = STANDARD.encode_slice(random, &mut key); // 16 bytes encode to exactly 24
    key
}

/// `Sec-WebSocket-Accept` the server must answer for `key` (RFC 6455: SHA-1 of key + GUID).
pub fn compute_accept(key: &[u8; KEY_LEN]) -> [u8; ACCEPT_LEN] {
    let mut sha = Sha1::new();
    sha.update(key);
    sha.update(GUID);
    let digest = sha.finalize();
    let mut accept = [0u8; ACCEPT_LEN];
    let _ = STANDARD.encode_slice(digest.as_slice(), &mut accept); // 20 bytes encode to exactly 28
    accept
}

fn clean(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_graphic())
}

/// The upgrade request, byte for byte what the C++ sends:
/// `Host` omits the port for 443, an empty path is `/`, the token goes out as
/// `Authorization: Bearer <token>`. Returns the length written to `out`.
pub fn build_request(
    host: &str,
    port: u16,
    path: &str,
    token: &str,
    key: &[u8; KEY_LEN],
    out: &mut [u8],
) -> Result<usize, BuildError> {
    let path = if path.is_empty() { "/" } else { path };
    let key = core::str::from_utf8(key).map_err(|_| BuildError::BadInput)?;
    if host.is_empty() || !clean(host) || !clean(path) || !clean(token) {
        return Err(BuildError::BadInput);
    }
    let mut c = SliceWriter { buf: out, pos: 0 };
    let r = if port == 443 {
        write!(c, "GET {path} HTTP/1.1\r\nHost: {host}\r\n")
    } else {
        write!(c, "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n")
    }
    .and_then(|()| {
        write!(
            c,
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\nAuthorization: Bearer {token}\r\n\r\n"
        )
    });
    r.map(|()| c.pos).map_err(|_| BuildError::BufferTooSmall)
}

/// Length of the response head (up to and including the blank line) if `buf` holds it.
pub fn head_len(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p.saturating_add(4))
}

/// Validate a complete response head against the accept value from [`compute_accept`].
/// Returns the verdict and the HTTP status.
pub fn check_response(head: &[u8], accept: &[u8; ACCEPT_LEN]) -> (UpgradeResult, u32) {
    check_upgrade_response(head, accept)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;
    use std::{format, string::String};

    #[test]
    fn rfc6455_accept_vector() {
        // RFC 6455 section 1.3
        let key = *b"dGhlIHNhbXBsZSBub25jZQ==";
        assert_eq!(&compute_accept(&key), b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn key_is_base64_of_random() {
        assert_eq!(&encode_key(b"the sample nonce"), b"dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(&encode_key(&[0; 16]), b"AAAAAAAAAAAAAAAAAAAAAA==");
    }

    const KEY: [u8; KEY_LEN] = *b"dGhlIHNhbXBsZSBub25jZQ==";

    fn req(host: &str, port: u16, path: &str, token: &str) -> String {
        let mut out = [0u8; MAX_REQUEST];
        let n = build_request(host, port, path, token, &KEY, &mut out).unwrap();
        String::from_utf8(out[..n].to_vec()).unwrap()
    }

    #[test]
    fn golden_request() {
        assert_eq!(
            req("relay.example.com", 443, "/ws", "s3cret"),
            "GET /ws HTTP/1.1\r\nHost: relay.example.com\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\nAuthorization: Bearer s3cret\r\n\r\n"
        );
        // Non-443 port in Host, empty path becomes "/"
        assert!(req("h.example", 8443, "", "t").starts_with("GET / HTTP/1.1\r\nHost: h.example:8443\r\n"));
    }

    #[test]
    fn rejects_injection_and_small_buffers() {
        let mut out = [0u8; MAX_REQUEST];
        for (h, p, t) in [("h\r\nX: y", "/", "t"), ("h", "/ a", "t"), ("h", "/", "t\nX: y"), ("", "/", "t")] {
            assert_eq!(build_request(h, 443, p, t, &KEY, &mut out), Err(BuildError::BadInput));
        }
        let n = build_request("h", 443, "/", "t", &KEY, &mut out).unwrap();
        for cap in [0, 1, n - 1] {
            assert_eq!(build_request("h", 443, "/", "t", &KEY, &mut out[..cap]), Err(BuildError::BufferTooSmall));
        }
        assert!(build_request("h", 443, "/", "t", &KEY, &mut out[..n]).is_ok());
    }

    #[test]
    fn response_validation() {
        let accept = compute_accept(&KEY);
        let a = core::str::from_utf8(&accept).unwrap();
        let ok = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {a}\r\n\r\n");
        assert_eq!(head_len(ok.as_bytes()), Some(ok.len()));
        assert_eq!(check_response(ok.as_bytes(), &accept), (UpgradeResult::Ok, 101));
        let bad = ok.replace(&a[..4], "AAAA");
        assert_eq!(check_response(bad.as_bytes(), &accept).0, UpgradeResult::BadAccept);
        assert_eq!(check_response(b"HTTP/1.1 404 Not Found\r\n\r\n", &accept), (UpgradeResult::NotSwitching, 404));
        assert_eq!(head_len(b"HTTP/1.1 101\r\n\r"), None);
    }
}
