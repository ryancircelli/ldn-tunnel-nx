//! getrandom 0.2's "custom" backend (crates/tls enables it for Horizon): the
//! `rustls_rustcrypto` default provider still links `OsRng`, so `__getrandom_custom` must
//! exist. We pass our own `SecureRandom` to rustls, but if anything does call it, it gets
//! csrng too.
// SAFETY: the only unsafe here is inside getrandom's `register_custom_getrandom!` expansion
// (`#[no_mangle]` + building the slice from the pointer/length getrandom hands it), which
// is the crate's documented way to plug in a backend. Our function is safe code.
#![allow(unsafe_code)]

fn csrng(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    super::rng::fill(buf).map_err(|_| getrandom::Error::UNSUPPORTED)
}

getrandom::register_custom_getrandom!(csrng);
