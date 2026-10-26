//! Peak heap of one session (handshake + request + response): the console's heap budget check.
//! `cargo test --features std --test heap -- --nocapture`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)] // test code
#![allow(unsafe_code)] // counting GlobalAlloc: the trait is unsafe to implement
use embedded_io::{Read, Write};
use embedded_io_adapters::std::FromStd;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(live, Relaxed);
        // SAFETY: same layout contract as our caller's.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        // SAFETY: p/l came from our alloc, i.e. from System.
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

#[test]
fn peak_heap_per_session() {
    let roots = include_bytes!("roots.pem");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let tcp = std::net::TcpStream::connect(("cloudflare.com", 443)).unwrap();
    let rng = rustls_rustcrypto::provider().secure_random;
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let mut tls = ldn_tunnel_tls::connect("cloudflare.com", roots, FromStd::new(tcp), now, rng).unwrap();
    let handshake_peak = PEAK.load(Relaxed) - base;
    let steady = LIVE.load(Relaxed) - base;
    tls.write_all(b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = [0u8; 512];
    while tls.read(&mut buf).unwrap() > 0 {}
    tls.close().unwrap();
    let peak = PEAK.load(Relaxed) - base;
    println!("heap: handshake peak {handshake_peak} B, established {steady} B, session peak {peak} B");
    assert!(peak < 256 * 1024, "session peak {peak} B over the 256 KiB budget");
}

/// Stack of a full handshake (RSA/ECDSA verify included) on a small thread stack, like a
/// console thread (128 KiB passes unoptimised; release needed 48 KiB on x86_64, DNS included).
/// `LDN_TLS_STACK` overrides the size to probe the floor.
#[test]
fn handshake_fits_small_stack() {
    let stack = std::env::var("LDN_TLS_STACK").map_or(128 * 1024, |s| s.parse().unwrap());
    let t = std::thread::Builder::new().stack_size(stack).spawn(|| {
        let roots = include_bytes!("roots.pem");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        for host in ["cloudflare.com", "badssl.com"] {
            let tcp = std::net::TcpStream::connect((host, 443)).unwrap();
            let rng = rustls_rustcrypto::provider().secure_random;
            ldn_tunnel_tls::connect(host, roots, FromStd::new(tcp), now, rng).unwrap().close().unwrap();
        }
    });
    t.unwrap().join().unwrap();
}
