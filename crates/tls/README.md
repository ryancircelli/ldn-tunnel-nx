# ldn-tunnel-tls

Blocking TLS client for the console's WebSocket-over-TLS link to the relay: **rustls 0.23**
(no_std + alloc, unbuffered API) with the **RustCrypto provider** (`rustls-rustcrypto`), driven over any
`embedded_io::{Read, Write}` transport. Pure Rust, `#![forbid(unsafe_code)]`, no C.

```rust
let mut tls = ldn_tunnel_tls::connect(host, ca_pem, socket, now_unix_secs, &CSRNG)?;
tls.write_all(b"GET /ws HTTP/1.1\r\n...")?;     // embedded_io::Write
let n = tls.read(&mut buf)?;                   // embedded_io::Read, Ok(0) after close_notify
let socket = tls.close()?;                     // sends close_notify, hands the transport back
```

- `ca_pem` is the **only** trust store (the SD-card PEM; text between certificates is ignored). Public
  roots, a private CA root (Caddy's local CA) or both. Nothing is compiled in. Bad PEM or no root ->
  `Error::BadCaBundle`.
- `host` is a DNS name (SNI + DNS SAN check) or an IP literal (no SNI, IP SAN check). Name
  verification is always on.
- `now_unix_secs` feeds certificate validity (the console must have network time).
- `rng: &'static dyn SecureRandom`: the shell implements it over Horizon `csrng`.
- TLS 1.3 and 1.2 (ECDHE + AEAD suites only), X25519/P-256/P-384, ECDSA/RSA/RSA-PSS/Ed25519 chains.

## Proof

| what | command | result |
|---|---|---|
| host tests | `cargo test --features std` (in `crates/tls`) | 14 pass |
| target | `cargo +nightly build -p ldn-tunnel-tls --target aarch64-nintendo-switch-freestanding -Zbuild-std=core,alloc --release` | builds, no C toolchain/Docker needed |

Host tests (`tests/`): `net.rs` (live: cloudflare.com, workers.dev, badssl.com RSA chain, each to the
peer's close_notify; wrong hostname, bundle without the needed root, empty/garbage bundle, clock
enforced both ways, badssl expired + self-signed), `private_ca.rs` (offline: generated root ->
intermediate -> leaf on a local listener; trusted alone or appended to the public roots, IP-literal
host, missing root, look-alike root, hostname mismatch), `heap.rs` (peak heap, small-stack handshake).
`tests/roots.pem` = the relay kit's `CA_ROOTS` cut from curl's cacert.pem 2026-10-20.

## Numbers (aarch64 target, opt-level s, LTO)

- **Code**: ~525 KB `.text+.rodata` for one session behind one exported symbol (staticlib probe linked
  with `--gc-sections`; includes the core/alloc parts it uses). rustls ~150 KB, rustls-rustcrypto ~55 KB,
  RSA (num-bigint-dig + rsa) ~70 KB, two rustls-webpki copies (0.102 via rustls-rustcrypto, 0.103 via
  rustls) ~30 KB.
- **Heap**: ~32 KB peak during a handshake, ~30 KB per established session (18.4 KB is the receive
  buffer for one max-size record), ~34 KB peak per session with traffic. Plus the parsed roots.
- **Stack**: a handshake overflows 32 KiB and passes 48 KiB (x86_64 release, DNS included); 128 KiB
  in an unoptimised build. Give the relay thread >= 64 KiB.

## Why this stack

| | (a) embedded-tls 0.19 | (b) rustls + rustls-rustcrypto (chosen) | (c) mbedtls 2.28 via FFI |
|---|---|---|---|
| builds for target | yes (`rustpki,rsa,p384`, pure Rust) | yes, pure Rust | not tried: devkitPro's lib expects newlib/libnx (calloc, time, ...) which the pure-Rust `nx` shell lacks |
| multi-root | **no**: verifier holds one CA; the `webpki` verifier passes no intermediates (TODO in source) and pulls ring (C) | yes (RootCertStore) | yes |
| TLS 1.3 | 1.3 only, P-256 key share only | 1.3 + 1.2 | 1.2 only (TLS 1.3 is mbedtls 3.x) |
| maintenance | active (2026-06), ~66k recent dl | rustls: the Rust standard; provider is alpha (2024-04), RustCrypto org, ~180k recent dl | 2.28 is EOL |

embedded-tls fails the security floor without hand-writing a chain verifier; mbedtls means C, an EOL
branch and libc glue. rustls gives full webpki chain + name checks out of the box.

## Open risks

- `rustls-rustcrypto` is an unaudited alpha. Path validation is rustls-webpki (mainstream); the alpha
  part is the glue to RustCrypto primitives (AES-GCM, ChaCha20, P-256/384, X25519, RSA verify). Swap
  to `rustls`' `ring` provider (C, needs the Docker gcc) if it ever misbehaves; the API does not change.
- RustCrypto picks AES/SHA/PMULL hardware paths from compile-time target features (`+crypto` is in the
  target spec); on hardware check the handshake time.
- `getrandom` is compiled with `custom` on Horizon only so `rand_core::OsRng` (unused) builds. If the
  final link reports `__getrandom_custom` undefined, register Horizon csrng with
  `getrandom::register_custom_getrandom!` in `crates/sys`.
- Clock: a console without network time (year 2000-ish) fails every handshake with `NotValidYet`.
  The shell should log that error distinctly.
- Let's Encrypt now issues from ISRG Root YE/YR (cross-signed by X1/X2); fine with the current list, but
  add the new roots to the relay kit's `CA_ROOTS` before X1/X2 cross-signs expire.
