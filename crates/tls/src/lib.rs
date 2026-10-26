//! Blocking TLS 1.2/1.3 client for the console's relay connection.
//!
//! rustls (no_std + alloc, unbuffered API) with the RustCrypto provider, over any
//! [`embedded_io`] byte transport (the Horizon BSD socket on the console, `TcpStream` in tests).
//! The server chain is verified by rustls-webpki against the CA bundle given to [`connect`],
//! including the hostname.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use embedded_io::{ErrorKind, ErrorType, Read, Write};
use rustls::client::UnbufferedClientConnection;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};
use rustls::{ClientConfig, RootCertStore};

pub use rustls::crypto::{GetRandomFailed, SecureRandom};

/// Largest TLS record on the wire: header + 2^14 plaintext + 2048 expansion (TLS 1.2 bound).
const MAX_RECORD: usize = 5 + 16384 + 2048;
/// Plaintext bytes encrypted per `write` call (one full record).
const MAX_PLAIN: usize = 16384;

#[derive(Debug)]
pub enum Error<E> {
    /// The transport failed.
    Io(E),
    /// Handshake, certificate or record-layer failure (includes untrusted chain and wrong hostname).
    Tls(rustls::Error),
    /// The CA bundle has a malformed PEM block or no usable root certificate.
    BadCaBundle,
    /// `host` is neither a DNS name nor an IP literal.
    BadHostname,
    /// The transport hit EOF without a TLS close_notify (truncation).
    UnexpectedEof,
    /// The connection is closed for writing, or rustls refused to encode (sequence exhaustion).
    Closed,
}

impl<E> From<rustls::Error> for Error<E> {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}

impl<E: embedded_io::Error> embedded_io::Error for Error<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Io(e) => e.kind(),
            Self::UnexpectedEof | Self::Closed => ErrorKind::BrokenPipe,
            Self::BadHostname => ErrorKind::InvalidInput,
            Self::Tls(_) | Self::BadCaBundle => ErrorKind::InvalidData,
        }
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl<E: core::fmt::Debug> core::error::Error for Error<E> {}

/// Certificate validity is checked against the time given to [`connect`].
#[derive(Debug)]
struct FixedTime(UnixTime);

impl rustls::time_provider::TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.0)
    }
}

/// Parses a PEM bundle (text between certificates is ignored) into trust anchors.
fn roots<E>(ca_pem: &[u8]) -> Result<RootCertStore, Error<E>> {
    let mut store = RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(ca_pem) {
        store.add(der.map_err(|_| Error::BadCaBundle)?).map_err(|_| Error::BadCaBundle)?;
    }
    if store.is_empty() {
        return Err(Error::BadCaBundle);
    }
    Ok(store)
}

/// Opens a TLS session to `host` over `transport` and completes the handshake.
///
/// - `host`: DNS name (sent as SNI, checked against the certificate's DNS SANs) or IP literal
///   (no SNI, checked against its IP SANs). Name verification cannot be turned off.
/// - `ca_pem`: the only trust store (PEM text from the SD card: public roots and/or a private CA
///   root such as Caddy's). Nothing is compiled in.
/// - `now_unix_secs`: wall-clock time for certificate validity (the console's network clock).
/// - `rng`: cryptographically secure randomness (Horizon `csrng` on the console).
pub fn connect<T: Read + Write>(
    host: &str,
    ca_pem: &[u8],
    transport: T,
    now_unix_secs: u64,
    rng: &'static dyn SecureRandom,
) -> Result<TlsStream<T>, Error<T::Error>> {
    let name = ServerName::try_from(host).map_err(|_| Error::BadHostname)?.to_owned();
    let provider = CryptoProvider { secure_random: rng, ..rustls_rustcrypto::provider() };
    let time = FixedTime(UnixTime::since_unix_epoch(core::time::Duration::from_secs(now_unix_secs)));
    let config = ClientConfig::builder_with_details(Arc::new(provider), Arc::new(time))
        .with_safe_default_protocol_versions()? // TLS 1.3 and 1.2, nothing older
        .with_root_certificates(roots(ca_pem)?)
        .with_no_client_auth();
    let mut stream = TlsStream {
        conn: UnbufferedClientConnection::new(Arc::new(config), name)?,
        io: transport,
        rx: vec![0; MAX_RECORD],
        rx_len: 0,
        tx: Vec::new(),
        plain: Vec::new(),
        plain_pos: 0,
        peer_closed: false,
    };
    stream.run(Goal::Handshake)?;
    Ok(stream)
}

#[derive(Clone, Copy)]
enum Goal<'a> {
    Handshake,
    Read,
    Write(&'a [u8]),
    Close,
}

/// An established TLS session. Implements [`embedded_io::Read`] / [`embedded_io::Write`].
pub struct TlsStream<T> {
    conn: UnbufferedClientConnection,
    io: T,
    /// Received ciphertext not yet consumed by rustls (`rx[..rx_len]`).
    rx: Vec<u8>,
    rx_len: usize,
    /// Ciphertext waiting to be sent.
    tx: Vec<u8>,
    /// Decrypted bytes not yet returned to the caller (`plain[plain_pos..]`).
    plain: Vec<u8>,
    plain_pos: usize,
    peer_closed: bool,
}

impl<T: Read + Write> TlsStream<T> {
    /// Sends close_notify and returns the transport (the caller closes the socket).
    pub fn close(mut self) -> Result<T, Error<T::Error>> {
        self.run(Goal::Close)?;
        Ok(self.io)
    }

    /// Drives rustls until `goal` is met. Returns the plaintext bytes consumed for `Goal::Write`.
    fn run(&mut self, goal: Goal<'_>) -> Result<usize, Error<T::Error>> {
        loop {
            let mut need_input = false;
            let mut done = None;
            let Some(input) = self.rx.get_mut(..self.rx_len) else {
                return Err(Error::Closed); // unreachable: rx_len <= rx.len() is kept below
            };
            let UnbufferedStatus { mut discard, state } = self.conn.process_tls_records(input);
            match state? {
                ConnectionState::ReadTraffic(mut records) => {
                    while let Some(record) = records.next_record() {
                        let record = record?;
                        discard = discard.saturating_add(record.discard);
                        self.plain.extend_from_slice(record.payload);
                    }
                }
                ConnectionState::EncodeTlsData(mut enc) => append(&mut self.tx, |b| {
                    enc.encode(b).map_err(|e| match e {
                        EncodeError::InsufficientSize(s) => Some(s.required_size),
                        _ => None,
                    })
                })?,
                ConnectionState::TransmitTlsData(t) => {
                    send(&mut self.io, &mut self.tx)?;
                    t.done();
                }
                ConnectionState::BlockedHandshake => need_input = true,
                ConnectionState::PeerClosed => self.peer_closed = true,
                ConnectionState::Closed => match goal {
                    Goal::Read | Goal::Close => done = Some(0),
                    Goal::Handshake | Goal::Write(_) => return Err(Error::Closed),
                },
                ConnectionState::WriteTraffic(mut w) => match goal {
                    Goal::Handshake => done = Some(0),
                    Goal::Read => {
                        if self.plain_pos < self.plain.len() || self.peer_closed {
                            done = Some(0);
                        } else {
                            need_input = true;
                        }
                    }
                    Goal::Write(data) => {
                        let chunk = data.get(..MAX_PLAIN).unwrap_or(data);
                        append(&mut self.tx, |b| w.encrypt(chunk, b).map_err(insufficient))?;
                        send(&mut self.io, &mut self.tx)?;
                        done = Some(chunk.len());
                    }
                    Goal::Close => {
                        append(&mut self.tx, |b| w.queue_close_notify(b).map_err(insufficient))?;
                        send(&mut self.io, &mut self.tx)?;
                        done = Some(0);
                    }
                },
                _ => return Err(Error::Closed), // early data / future states: never negotiated
            }
            // rustls never discards more than it was given; clamp so a bug cannot panic copy_within.
            let discard = discard.min(self.rx_len);
            self.rx.copy_within(discard..self.rx_len, 0);
            self.rx_len = self.rx_len.saturating_sub(discard);
            if let Some(n) = done {
                return Ok(n);
            }
            if need_input {
                let free = self.rx.get_mut(self.rx_len..).unwrap_or_default();
                if free.is_empty() {
                    // Cannot happen with rustls' record size checks; never spin on a full buffer.
                    return Err(Error::Tls(rustls::Error::General("record exceeds buffer".into())));
                }
                match self.io.read(free).map_err(Error::Io)? {
                    0 => return Err(Error::UnexpectedEof),
                    n => self.rx_len = self.rx_len.saturating_add(n),
                }
            }
        }
    }
}

fn insufficient(e: EncryptError) -> Option<usize> {
    match e {
        EncryptError::InsufficientSize(s) => Some(s.required_size),
        _ => None,
    }
}

/// Appends what `f` writes to `tx`, retrying with more room when `f` reports `Some(required)`.
fn append<E>(
    tx: &mut Vec<u8>,
    mut f: impl FnMut(&mut [u8]) -> Result<usize, Option<usize>>,
) -> Result<(), Error<E>> {
    let start = tx.len();
    let mut room = 1024;
    loop {
        tx.resize(start.saturating_add(room), 0);
        match f(tx.get_mut(start..).unwrap_or_default()) {
            Ok(n) => {
                tx.truncate(start.saturating_add(n));
                return Ok(());
            }
            Err(Some(required)) if required > room => room = required,
            Err(_) => {
                tx.truncate(start);
                return Err(Error::Closed);
            }
        }
    }
}

fn send<T: Write>(io: &mut T, tx: &mut Vec<u8>) -> Result<(), Error<T::Error>> {
    io.write_all(tx).map_err(Error::Io)?;
    io.flush().map_err(Error::Io)?;
    tx.clear();
    Ok(())
}

impl<T: Read + Write> ErrorType for TlsStream<T> {
    type Error = Error<T::Error>;
}

impl<T: Read + Write> Read for TlsStream<T> {
    /// Returns decrypted bytes; `Ok(0)` once the peer sent close_notify.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.plain_pos == self.plain.len() {
            self.plain.clear();
            self.plain_pos = 0;
            self.run(Goal::Read)?;
        }
        let pending = self.plain.get(self.plain_pos..).unwrap_or_default();
        let n = pending.len().min(buf.len());
        for (d, s) in buf.iter_mut().zip(pending) {
            *d = *s;
        }
        self.plain_pos = self.plain_pos.saturating_add(n);
        Ok(n)
    }
}

impl<T: Read + Write> Write for TlsStream<T> {
    /// Encrypts and sends up to one record (16 KiB) of `buf`.
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.run(Goal::Write(buf))
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(()) // write() sends each record before returning
    }
}
