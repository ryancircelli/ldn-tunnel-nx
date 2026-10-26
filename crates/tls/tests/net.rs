//! Live network tests: `cargo test --features std`. Need outbound TCP 443.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)] // test code
use embedded_io::{Read, Write};
use embedded_io_adapters::std::FromStd;
use ldn_tunnel_tls::{Error, connect};
use rustls::CertificateError as C;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

const ROOTS: &str = include_str!("roots.pem");

type Res = Result<ldn_tunnel_tls::TlsStream<FromStd<TcpStream>>, Error<std::io::Error>>;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn open(addr: &str, host: &str, roots: &str, now: u64) -> Res {
    let tcp = TcpStream::connect((addr, 443)).unwrap();
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(15))).unwrap();
    connect(host, roots.as_bytes(), FromStd::new(tcp), now, rustls_rustcrypto::provider().secure_random)
}

fn get_status(host: &str) {
    let mut tls = open(host, host, ROOTS, now()).unwrap_or_else(|e| panic!("{host}: {e:?}"));
    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).unwrap();
    let mut buf = [0u8; 64];
    let mut got = Vec::new();
    while !got.windows(2).any(|w| w == b"\r\n") {
        let n = tls.read(&mut buf).unwrap();
        assert!(n > 0, "{host}: eof before status line");
        got.extend_from_slice(&buf[..n]);
    }
    let line = String::from_utf8_lossy(&got);
    let line = line.lines().next().unwrap();
    println!("{host}: {line}");
    assert!(line.starts_with("HTTP/1.1 "), "{host}: {line}");
    // `Connection: close`: read the whole response across records until the peer's close_notify.
    loop {
        match tls.read(&mut buf).unwrap() {
            0 => break,
            n => got.extend_from_slice(&buf[..n]),
        }
    }
    println!("{host}: {} bytes until close_notify", got.len());
    tls.close().unwrap();
}

fn cert_err(r: Res) -> C {
    match r {
        Err(Error::Tls(rustls::Error::InvalidCertificate(c))) => c,
        Err(e) => panic!("expected a certificate error, got {e:?}"),
        Ok(_) => panic!("handshake succeeded but must fail"),
    }
}

#[test]
fn cloudflare_com() {
    get_status("cloudflare.com");
}

#[test]
fn workers_dev() {
    get_status("workers.dev");
}

/// RSA chain (Let's Encrypt → ISRG Root X1 cross-sign), exercises the RSA verify path.
#[test]
fn badssl_com_rsa_chain() {
    get_status("badssl.com");
}

#[test]
fn wrong_hostname_fails() {
    let e = cert_err(open("wrong.host.badssl.com", "wrong.host.badssl.com", ROOTS, now()));
    assert!(matches!(e, C::NotValidForName | C::NotValidForNameContext { .. }), "{e:?}");
}

#[test]
fn bundle_without_needed_root_fails() {
    // Only ISRG Root X1: cloudflare.com chains to GTS Root R4.
    let isrg_only = &ROOTS[..ROOTS.find("SSL.com Root Certification Authority RSA").unwrap()];
    assert_eq!(cert_err(open("cloudflare.com", "cloudflare.com", isrg_only, now())), C::UnknownIssuer);
}

#[test]
fn empty_or_garbage_bundle_is_rejected() {
    assert!(matches!(open("cloudflare.com", "cloudflare.com", "", now()), Err(Error::BadCaBundle)));
    let broken = "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n";
    assert!(matches!(open("cloudflare.com", "cloudflare.com", broken, now()), Err(Error::BadCaBundle)));
}

#[test]
fn clock_is_enforced() {
    let year = 365 * 24 * 3600;
    let e = cert_err(open("cloudflare.com", "cloudflare.com", ROOTS, now() + 10 * year));
    assert!(matches!(e, C::Expired | C::ExpiredContext { .. }), "{e:?}");
    let e = cert_err(open("cloudflare.com", "cloudflare.com", ROOTS, 0));
    assert!(matches!(e, C::NotValidYet | C::NotValidYetContext { .. }), "{e:?}");
}

#[test]
fn badssl_expired_and_self_signed_fail() {
    cert_err(open("expired.badssl.com", "expired.badssl.com", ROOTS, now()));
    cert_err(open("self-signed.badssl.com", "self-signed.badssl.com", ROOTS, now()));
}
