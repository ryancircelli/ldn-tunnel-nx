//! Self-hosted relay behind a private CA (e.g. Caddy's local CA): the SD-card bundle is the only
//! trust store. Root -> intermediate -> leaf generated per run, served by a local rustls listener.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)] // test code
use embedded_io::{Read, Write};
use embedded_io_adapters::std::FromStd;
use ldn_tunnel_tls::{Error, connect};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::CertificateError as C;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

const PUBLIC_ROOTS: &str = include_str!("roots.pem");

struct Pki {
    root_pem: String,
    chain: Vec<CertificateDer<'static>>,
    key: KeyPair,
}

fn ca(name: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p
}

fn new_pki() -> Pki {
    let root = CertifiedIssuer::self_signed(ca("Test Private Root"), KeyPair::generate().unwrap()).unwrap();
    let inter =
        CertifiedIssuer::signed_by(ca("Test Intermediate"), KeyPair::generate().unwrap(), &root).unwrap();
    let mut leaf = CertificateParams::new(vec!["relay.test".into(), "127.0.0.1".into()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&key, &inter).unwrap();
    Pki { root_pem: root.pem(), chain: vec![leaf.der().clone(), inter.der().clone()], key }
}

/// Serves one TLS connection on 127.0.0.1: answers "ping" with "pong". Returns the port.
fn serve(pki: &Pki) -> u16 {
    let key = PrivateKeyDer::Pkcs8(pki.key.serialize_der().into());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.chain.clone(), key)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(Arc::new(cfg)).unwrap(), tcp);
        let mut buf = [0u8; 4];
        // Errors are expected in the negative cases (the client aborts the handshake).
        if tls.read_exact(&mut buf).is_ok() && &buf == b"ping" {
            let _ = tls.write_all(b"pong");
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    port
}

fn session(pki: &Pki, host: &str, bundle: &str) -> Result<(), Error<std::io::Error>> {
    let tcp = TcpStream::connect(("127.0.0.1", serve(pki))).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let rng = rustls_rustcrypto::provider().secure_random;
    let mut tls = connect(host, bundle.as_bytes(), FromStd::new(tcp), now, rng)?;
    tls.write_all(b"ping")?;
    let mut buf = [0u8; 4];
    tls.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"pong");
    assert_eq!(tls.read(&mut buf)?, 0, "close_notify ends the stream");
    tls.close()?;
    Ok(())
}

fn cert_err(r: Result<(), Error<std::io::Error>>) -> C {
    match r {
        Err(Error::Tls(rustls::Error::InvalidCertificate(c))) => c,
        other => panic!("expected a certificate error, got {other:?}"),
    }
}

#[test]
fn private_root_in_bundle_is_trusted() {
    let pki = new_pki();
    session(&pki, "relay.test", &pki.root_pem).unwrap();
    // Mixed with the public roots, as an SD bundle with one extra root would be.
    session(&pki, "relay.test", &format!("{PUBLIC_ROOTS}\n{}", pki.root_pem)).unwrap();
}

#[test]
fn ip_literal_host_checks_ip_san() {
    let pki = new_pki();
    session(&pki, "127.0.0.1", &pki.root_pem).unwrap();
    let e = cert_err(session(&pki, "127.0.0.2", &pki.root_pem));
    assert!(matches!(e, C::NotValidForName | C::NotValidForNameContext { .. }), "{e:?}");
}

#[test]
fn private_root_missing_fails() {
    let pki = new_pki();
    assert_eq!(cert_err(session(&pki, "relay.test", PUBLIC_ROOTS)), C::UnknownIssuer);
    // A different private root with the same name but another key is not a substitute.
    let other = new_pki();
    assert_eq!(cert_err(session(&pki, "relay.test", &other.root_pem)), C::BadSignature);
}

#[test]
fn private_root_hostname_mismatch_fails() {
    let pki = new_pki();
    let e = cert_err(session(&pki, "other.test", &pki.root_pem));
    assert!(matches!(e, C::NotValidForName | C::NotValidForNameContext { .. }), "{e:?}");
}
