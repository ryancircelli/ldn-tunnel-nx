//! Static memory of the core types, and core paths on small thread stacks. Run:
//! `cargo test -p ldn-tunnel-core --test sizes -- --nocapture`
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
use core::mem::size_of;

use ldn_tunnel_core::conn::Conn;
use ldn_tunnel_core::ldn::Session;
use ldn_tunnel_core::logring::LogRing;
use ldn_tunnel_core::router::Router;
use ldn_tunnel_core::whitelist::Whitelist;

#[test]
fn print_sizes() {
    println!("size_of Router        = {}", size_of::<Router>());
    println!("size_of Session       = {}", size_of::<Session>());
    println!("size_of Conn<16384>   = {}", size_of::<Conn<16384>>());
    println!("size_of Conn<131072>  = {}", size_of::<Conn<131072>>());
    println!("size_of LogRing       = {}", size_of::<LogRing>());
    println!("size_of Whitelist     = {}", size_of::<Whitelist>());
    // The module must stay far below its 1.5 MiB budget.
    assert!(size_of::<Router>() + size_of::<Session>() + size_of::<Conn<16384>>() < 400 * 1024);
}

/// Runs `f` on a host thread with a `kib` KiB stack. Host threads have a guard page, so
/// an overflow aborts the test binary. Debug host frames are larger than the device's
/// release frames, so passing here leaves margin on the console.
fn on_stack(kib: usize, f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new().stack_size(kib * 1024).spawn(f).unwrap().join().unwrap();
}

/// The router runs on the 48 KiB bsd:u thread stack, ~8 KiB of which the IPC server
/// already uses (a 32 KB temporary in `create_bound` once overran the 32 KiB stack of
/// the time into ldn:u's). The proxy path must fit 16 KiB.
#[test]
fn proxy_path_fits_a_small_stack() {
    use ldn_tunnel_core::router::bsd::{MSG_DONTWAIT, SOCK_DGRAM};
    use ldn_tunnel_core::router::{Decision, RecvDecision, SockAddrIn, socket_key};
    use ldn_tunnel_core::wire::{ProxyDataHeader, ProxyInfo};

    const ME: u32 = 0x0A72_0001;
    let mut router = Box::new(Router::new());
    let path = move || {
        let r = &mut *router;
        let key = socket_key(1, 3);
        r.set_proxy_config(ME, 0xFFFF_0000);
        assert!(r.on_socket(key, 2, SOCK_DGRAM, 0));
        assert_eq!(r.on_bind(key, &SockAddrIn::from_ryujinx(0, 12345), false), Decision::ReplyAndForward(0));
        let peer = SockAddrIn::from_ryujinx(0x0A72_0002, 12345);
        assert!(matches!(r.on_sendto(key, b"hi", Some(&peer)), Decision::Emit { .. }));
        let info = ProxyInfo { source_ipv4: 0x0A72_0002, source_port: 12345, dest_ipv4: ME, dest_port: 12345, protocol: 17 };
        assert_eq!(r.on_proxy_data(&ProxyDataHeader { info, data_length: 2 }, b"yo"), 1);
        let mut buf = [0u8; 64];
        assert!(matches!(r.on_recvfrom(key, &mut buf, MSG_DONTWAIT), RecvDecision::Data { len: 2, .. }));
    };
    on_stack(16, path);
}

/// The relay thread (the 128 KiB main thread) verifies update manifests (P-256 ECDSA)
/// and resolves the relay host. Both must fit half of it.
#[test]
fn update_verify_and_dns_fit_half_the_relay_stack() {
    use ldn_tunnel_core::dns;
    use ldn_tunnel_core::update::{
        ManifestResult, SIGNED_LEN, UNSIGNED_LEN, UPDATE_MANIFEST_FORMAT, UPDATE_MANIFEST_MAGIC, check_manifest,
    };
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let pubkey: [u8; 65] = key.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap();
    let mut m = vec![0u8; SIGNED_LEN];
    m[0..4].copy_from_slice(&UPDATE_MANIFEST_MAGIC.to_le_bytes());
    m[4..8].copy_from_slice(&UPDATE_MANIFEST_FORMAT.to_le_bytes());
    let sig: Signature = key.sign(&m[..UNSIGNED_LEN]);
    m[UNSIGNED_LEN..].copy_from_slice(&sig.to_bytes());
    on_stack(64, move || {
        // Zero blob sizes: past the signature check, then BadSizes.
        assert_eq!(check_manifest(&m, &pubkey, 1, 0, 0).unwrap_err(), ManifestResult::BadSizes);
        let mut q = [0u8; dns::MAX_MESSAGE];
        let n = dns::build_query("relay.example.com", 0x1234, &mut q).unwrap();
        // The query echoed back as an answer-less reply: parsed to the end, no A record.
        q[2] |= 0x80;
        assert!(dns::parse_response(&q[..n], 0x1234).is_err());
    });
}
