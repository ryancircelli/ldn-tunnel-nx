//! Cryptographic randomness from Horizon's `csrng` service (spl), for rustls and for the
//! WebSocket masking keys / handshake nonce.
#![forbid(unsafe_code)]

use ldn_tunnel_tls::{GetRandomFailed, SecureRandom};
use nx::ipc::sf::Buffer;
use nx::result::Result;
use nx::service::new_service_object;
use nx::service::spl::{IRandomClient, RandomService};
use nx::sync::Mutex;

/// The session opens on first use and stays open.
static SERVICE: Mutex<Option<RandomService>> = Mutex::new(None);

/// `&CSRNG` is the `&'static dyn SecureRandom` that `ldn_tunnel_tls::connect` takes.
#[derive(Debug)]
pub struct Csrng;

pub static CSRNG: Csrng = Csrng;

/// Fills `buf` from csrng.
// ponytail: one IPC per call (a frame mask is one call per sent packet); pool the bytes
// if that ever shows up in send latency.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    let mut svc = SERVICE.lock();
    if svc.is_none() {
        *svc = Some(new_service_object::<RandomService>()?);
    }
    match svc.as_ref() {
        Some(s) => s.generate_random_bytes(Buffer::from_mut_array(buf)),
        None => Ok(()), // just set above
    }
}

/// Random bytes, or zeros if csrng fails. Only for values where predictability costs
/// nothing but robustness (WebSocket masks under TLS, backoff jitter); never for keys.
pub fn bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    let _ = fill(&mut b);
    b
}

impl SecureRandom for Csrng {
    fn fill(&self, buf: &mut [u8]) -> core::result::Result<(), GetRandomFailed> {
        fill(buf).map_err(|_| GetRandomFailed)
    }
}
