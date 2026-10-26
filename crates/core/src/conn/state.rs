//! Relay connection state machine and the sans-IO [`Conn`] (port of
//! `network/connection_state.cpp` and the connect/handshake/keepalive parts of
//! `network/client.cpp`).
//!
//! The shell owns the socket and the TLS stream and drives [`Conn`] with bytes and time:
//!
//! ```text
//! conn.connect(now);                              // wants a connection
//! loop {
//!     match conn.poll(now, mask, &mut out) {
//!         Action::Open     => open TCP+TLS; then conn.opened(..) -> write the request,
//!                             or conn.open_failed()
//!         Action::Send(n)  => tls.write_all(&out[..n])
//!         Action::Drop     => close the socket (the Conn already scheduled a retry)
//!         Action::Idle     => break
//!     }
//! }
//! // when TLS bytes arrive:
//! let mut rest = &rx[..n];
//! while !rest.is_empty() {
//!     let used = conn.on_bytes(rest);
//!     rest = &rest[used..];
//!     while let Some((id, payload)) = conn.next_packet() { /* dispatch */ }
//! }
//! // a read error or EOF: conn.transport_lost()
//! ```
//!
//! Every frame the console sends is masked with a key the caller draws from a CSPRNG.
use zerocopy::IntoBytes;

use super::handshake::{self, ACCEPT_LEN, BuildError};
use super::reconnect::{Reconnect, ReconnectConfig};
use crate::packet_buffer::{BufferResult, append, consume, peek_packet_info};
use crate::protocol::{HEADER_SIZE, MAX_PACKET_SIZE, decode_header, encode_header as ldn_header};
use crate::wire::{DisconnectMessage, NetworkErrorCode, PacketId};
use crate::ws::{
    HeadStatus, MAX_CONTROL_PAYLOAD, OPCODE_BINARY, OPCODE_CLOSE, OPCODE_PING, OPCODE_PONG, UpgradeResult,
    WsDecoder, WsStatus, apply_mask, close_code, close_echo, encode_header as ws_header,
};

/// Smallest `out` buffer [`Conn::poll`] needs (Initialize or a control frame plus headers).
pub const MIN_OUT: usize = 160;

// ---------------------------------------------------------------------------------------
// Connection state machine (connection_state.cpp)
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// Idle, or gave up after the last retry.
    Disconnected,
    Connecting,
    /// Upgrade done, Initialize not sent yet.
    Connected,
    /// Initialize sent, waiting for the relay's answer.
    Handshaking,
    Ready,
    /// Waiting before the next attempt.
    Backoff,
    Retrying,
    Disconnecting,
    /// Unrecoverable (version mismatch); leaves only through `connect` or `close`.
    Error,
}

impl ConnectionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Handshaking => "Handshaking",
            Self::Ready => "Ready",
            Self::Backoff => "Backoff",
            Self::Retrying => "Retrying",
            Self::Disconnecting => "Disconnecting",
            Self::Error => "Error",
        }
    }

    /// TCP/TLS/WebSocket is up (`is_connected` in the C++).
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected | Self::Handshaking | Self::Ready)
    }

    pub const fn is_transitioning(self) -> bool {
        matches!(
            self,
            Self::Connecting | Self::Handshaking | Self::Retrying | Self::Disconnecting | Self::Backoff
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionEvent {
    Connect,
    ConnectSuccess,
    ConnectFailed,
    HandshakeStarted,
    HandshakeSuccess,
    HandshakeFailed,
    Disconnect,
    ConnectionLost,
    BackoffExpired,
    RetryRequested,
    FatalError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionResult {
    Success,
    InvalidTransition,
    AlreadyInState,
}

/// The C++ transition table, state by state.
const fn target(from: ConnectionState, ev: ConnectionEvent) -> Option<ConnectionState> {
    use ConnectionEvent as E;
    use ConnectionState as S;
    Some(match (from, ev) {
        (S::Disconnected, E::Connect | E::RetryRequested) => S::Connecting,
        (S::Connecting | S::Retrying, E::ConnectSuccess) => S::Connected,
        (S::Connecting | S::Retrying, E::ConnectFailed) => S::Backoff,
        (S::Connecting | S::Retrying | S::Backoff, E::Disconnect) => S::Disconnected,
        (S::Connecting | S::Connected | S::Handshaking | S::Ready | S::Backoff | S::Retrying, E::FatalError) => {
            S::Error
        }
        (S::Connected, E::HandshakeStarted) => S::Handshaking,
        (S::Connected | S::Handshaking, E::HandshakeSuccess) => S::Ready,
        (S::Connected | S::Handshaking, E::HandshakeFailed) => S::Backoff,
        (S::Connected | S::Handshaking | S::Ready, E::Disconnect) => S::Disconnecting,
        (S::Connected | S::Handshaking | S::Ready, E::ConnectionLost) => S::Backoff,
        (S::Backoff, E::BackoffExpired | E::RetryRequested) => S::Retrying,
        (S::Disconnecting, E::ConnectSuccess | E::ConnectFailed | E::ConnectionLost | E::FatalError) => {
            S::Disconnected
        }
        (S::Error, E::Disconnect) => S::Disconnected,
        (S::Error, E::RetryRequested) => S::Connecting,
        _ => return None,
    })
}

/// `ConnectionStateMachine`: the table plus the retry counter.
#[derive(Clone, Copy, Debug)]
pub struct StateMachine {
    state: ConnectionState,
    retry_count: u32,
}

impl StateMachine {
    pub const fn new() -> Self {
        Self { state: ConnectionState::Disconnected, retry_count: 0 }
    }

    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    pub const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Jump without a transition (`force_state`).
    pub const fn force_state(&mut self, s: ConnectionState) {
        self.state = s;
    }

    pub fn process_event(&mut self, ev: ConnectionEvent) -> TransitionResult {
        use ConnectionEvent as E;
        use ConnectionState as S;
        if (self.state == S::Disconnected && ev == E::Disconnect) || (self.state == S::Ready && ev == E::ConnectSuccess)
        {
            return TransitionResult::AlreadyInState;
        }
        let Some(to) = target(self.state, ev) else {
            return TransitionResult::InvalidTransition;
        };
        if matches!(to, S::Retrying | S::Connecting) && matches!(self.state, S::Backoff | S::Retrying) {
            self.retry_count = self.retry_count.saturating_add(1);
        }
        if to == S::Ready {
            self.retry_count = 0;
        }
        self.state = to;
        TransitionResult::Success
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------------------
// Conn
// ---------------------------------------------------------------------------------------

/// Why the connection went down; kept for the status screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// TCP or TLS did not come up, or the request could not be built.
    OpenFailed,
    /// No upgrade completed within `connect_timeout_ms`.
    ConnectTimeout,
    /// The relay answered the upgrade with this HTTP status (it uses 404 for any auth failure).
    UpgradeRejected(u32),
    /// The upgrade response was malformed or its accept key wrong.
    UpgradeInvalid,
    /// Bad WebSocket frame, bad LDN header, or an oversized upgrade response.
    Protocol,
    /// The relay sent a WebSocket Close frame (close code attached).
    PeerClosed(u16),
    /// The shell reported a read/write error or EOF.
    Transport,
    /// Nothing received or sent for `silence_timeout_ms`.
    Silent,
    /// No answer to Initialize within `handshake_timeout_ms`.
    HandshakeTimeout,
    /// NetworkError during the handshake (code in [`Conn::last_error`]).
    HandshakeRejected,
    /// NetworkError VersionMismatch: retrying cannot help.
    VersionMismatch,
    /// Disconnect packet during the handshake.
    ServerDisconnected,
}

/// Timers and identity. [`ConnConfig::new`] has the C++ defaults.
#[derive(Clone, Copy, Debug)]
pub struct ConnConfig {
    /// Sent in Initialize (the C++ sends a fixed pattern; any 16 bytes work).
    pub client_id: [u8; 16],
    pub mac: [u8; 6],
    /// TCP + TLS + upgrade, from the moment `poll` says `Open`.
    pub connect_timeout_ms: u64,
    pub handshake_timeout_ms: u64,
    /// Ready, and nothing received or sent for this long = dead (see [`Failure::Silent`]).
    pub silence_timeout_ms: u64,
    pub reconnect: ReconnectConfig,
}

impl ConnConfig {
    pub const fn new(client_id: [u8; 16], mac: [u8; 6]) -> Self {
        Self {
            client_id,
            mac,
            connect_timeout_ms: 5000,
            handshake_timeout_ms: 5000,
            // The relay pings an idle console every 10 s, which we echo.
            silence_timeout_ms: 30_000,
            reconnect: ReconnectConfig::RELAY,
        }
    }
}

/// What the relay assigned in its Initialize answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: [u8; 16],
    pub mac: [u8; 6],
}

/// What the shell must do next ([`Conn::poll`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Idle,
    /// Open TCP + TLS to the relay, then call [`Conn::opened`] or [`Conn::open_failed`].
    Open,
    /// Write `out[..n]` to the stream.
    Send(usize),
    /// Close the socket now. The retry (or the give-up) is already scheduled.
    Drop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// No stream.
    Closed,
    /// Request written, collecting the HTTP response head.
    Upgrading,
    /// WebSocket frames.
    Open,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Closing {
    No,
    SendDisconnect,
    SendClose,
    Teardown,
}

#[derive(Clone, Copy, Debug)]
struct Control {
    opcode: u8,
    len: u8,
    data: [u8; MAX_CONTROL_PAYLOAD],
}

/// `N` is the reassembly buffer: the largest relay packet that is delivered. Bigger ones are
/// skipped (the decoder drops their bytes). 16 KiB is plenty for every LDN packet.
pub struct Conn<const N: usize> {
    cfg: ConnConfig,
    sm: StateMachine,
    rec: Reconnect,
    phase: Phase,
    buf: [u8; N],
    len: usize,
    /// Size of the packet last handed out by `next_packet`, dropped on the next call.
    taken: usize,
    dec: WsDecoder,
    accept: [u8; ACCEPT_LEN],
    open_issued: bool,
    /// Start of the current connect / handshake / backoff wait.
    since_ms: u64,
    backoff_ms: u32,
    last_rx_ms: u64,
    last_tx_ms: u64,
    rx_dirty: bool,
    tx_dirty: bool,
    reply: Option<Control>,
    ping_echo: Option<u8>,
    loss: Option<Failure>,
    closing: Closing,
    session: Option<Session>,
    failure: Option<Failure>,
    last_error: Option<NetworkErrorCode>,
}

impl<const N: usize> Conn<N> {
    pub const fn new(cfg: ConnConfig) -> Self {
        Self {
            rec: Reconnect::new(cfg.reconnect),
            cfg,
            sm: StateMachine::new(),
            phase: Phase::Closed,
            buf: [0; N],
            len: 0,
            taken: 0,
            dec: WsDecoder::ZERO,
            accept: [0; ACCEPT_LEN],
            open_issued: false,
            since_ms: 0,
            backoff_ms: 0,
            last_rx_ms: 0,
            last_tx_ms: 0,
            rx_dirty: false,
            tx_dirty: false,
            reply: None,
            ping_echo: None,
            loss: None,
            closing: Closing::No,
            session: None,
            failure: None,
            last_error: None,
        }
    }

    pub const fn state(&self) -> ConnectionState {
        self.sm.state()
    }

    pub const fn is_ready(&self) -> bool {
        matches!(self.sm.state(), ConnectionState::Ready)
    }

    /// Failed attempts since the last good handshake.
    pub const fn retry_count(&self) -> u32 {
        self.rec.retry_count()
    }

    /// Delay chosen for the current backoff, in ms.
    pub const fn backoff_ms(&self) -> u32 {
        self.backoff_ms
    }

    /// Why the last connection ended, until the next handshake succeeds.
    pub const fn failure(&self) -> Option<Failure> {
        self.failure
    }

    /// Last NetworkError code seen during a handshake.
    pub const fn last_error(&self) -> Option<NetworkErrorCode> {
        self.last_error
    }

    pub const fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// A relay Ping is waiting to be echoed by the next `poll`.
    pub const fn ping_pending(&self) -> bool {
        self.ping_echo.is_some()
    }

    /// Clock of the last byte received and sent (as of the last `poll`).
    pub const fn last_io_ms(&self) -> (u64, u64) {
        (self.last_rx_ms, self.last_tx_ms)
    }

    fn reset_stream(&mut self) {
        self.phase = Phase::Closed;
        self.len = 0;
        self.taken = 0;
        self.dec.reset();
        self.reply = None;
        self.ping_echo = None;
        self.session = None;
    }

    /// Ask for a connection. Valid from Disconnected (idle or gave up), Error and Backoff
    /// (cancels the wait and starts over with a fresh retry budget). `false` otherwise.
    pub fn connect(&mut self, now_ms: u64) -> bool {
        use ConnectionEvent as E;
        match self.sm.state() {
            ConnectionState::Backoff => {
                self.sm.process_event(E::Disconnect);
                self.rec.reset();
            }
            ConnectionState::Error => self.rec.reset(),
            _ => {}
        }
        let ev = if self.sm.state() == ConnectionState::Error { E::RetryRequested } else { E::Connect };
        if self.sm.process_event(ev) != TransitionResult::Success {
            return false;
        }
        self.reset_stream();
        self.loss = None;
        self.closing = Closing::No;
        self.open_issued = false;
        self.since_ms = now_ms;
        true
    }

    /// Graceful local close: a Disconnect packet and a WebSocket Close (when Ready), then
    /// `Drop`; the state ends in Disconnected with no retry. Also cancels Connecting,
    /// Backoff and Error.
    pub fn close(&mut self) {
        self.closing = Closing::SendDisconnect;
    }

    /// The shell could not bring TCP/TLS up.
    pub fn open_failed(&mut self) {
        self.fail(Failure::OpenFailed);
    }

    /// The stream broke (read/write error, EOF).
    pub fn transport_lost(&mut self) {
        self.fail(Failure::Transport);
    }

    /// TCP + TLS are up after `Action::Open`: build the upgrade request into `out`
    /// (`random` = 16 fresh random bytes for `Sec-WebSocket-Key`) and start collecting the
    /// response. The shell writes `out[..n]`.
    pub fn opened(
        &mut self,
        host: &str,
        port: u16,
        path: &str,
        token: &str,
        random: &[u8; 16],
        out: &mut [u8],
    ) -> Result<usize, BuildError> {
        if !self.open_issued
            || self.phase != Phase::Closed
            || !matches!(self.sm.state(), ConnectionState::Connecting | ConnectionState::Retrying)
        {
            return Err(BuildError::BadInput);
        }
        let key = handshake::encode_key(random);
        match handshake::build_request(host, port, path, token, &key, out) {
            Ok(n) => {
                self.accept = handshake::compute_accept(&key);
                self.phase = Phase::Upgrading;
                self.len = 0;
                self.tx_dirty = true;
                Ok(n)
            }
            Err(e) => {
                self.fail(Failure::OpenFailed);
                Err(e)
            }
        }
    }

    fn fail(&mut self, f: Failure) {
        if self.loss.is_none() {
            self.loss = Some(f);
        }
        self.phase = Phase::Closed;
    }

    // ---- receive -------------------------------------------------------------------

    /// Feed bytes read from the stream; returns how many were taken. It takes everything
    /// unless the reassembly buffer is full of whole packets: drain them with
    /// [`next_packet`](Self::next_packet) and feed the rest again. After a failure the
    /// rest is discarded (and counted as taken); `poll` reports `Drop`.
    pub fn on_bytes(&mut self, data: &[u8]) -> usize {
        self.release();
        if !data.is_empty() {
            self.rx_dirty = true;
        }
        let mut used = 0usize;
        while let Some(rest) = data.get(used..).filter(|r| !r.is_empty()) {
            if self.loss.is_some() {
                return data.len();
            }
            match self.phase {
                Phase::Closed => return data.len(),
                Phase::Upgrading => used = used.saturating_add(self.feed_upgrade(rest)),
                Phase::Open => {
                    if self.dec.check_head(&self.buf, &mut self.len).0 == HeadStatus::Invalid {
                        self.fail(Failure::Protocol);
                        return data.len();
                    }
                    let free = N.saturating_sub(self.len);
                    if free == 0 {
                        // Full: must hold a whole packet for next_packet. If not, stuck.
                        if peek_packet_info(self.buf.get(..self.len).unwrap_or_default()).0 != BufferResult::Success {
                            self.fail(Failure::Protocol);
                            return data.len();
                        }
                        break;
                    }
                    let take = rest.len().min(free);
                    let (st, n) = self.dec.consume(&mut self.buf, &mut self.len, rest.get(..take).unwrap_or_default());
                    used = used.saturating_add(n);
                    match st {
                        WsStatus::Ok => {}
                        WsStatus::Control => self.on_control(),
                        WsStatus::ProtocolError | WsStatus::Overflow => {
                            self.fail(Failure::Protocol);
                            return data.len();
                        }
                    }
                }
            }
        }
        used
    }

    fn feed_upgrade(&mut self, rest: &[u8]) -> usize {
        for (i, b) in rest.iter().enumerate() {
            if append(&mut self.buf, &mut self.len, core::slice::from_ref(b)) != BufferResult::Success {
                self.fail(Failure::Protocol);
                return rest.len();
            }
            if self.buf.get(..self.len).is_some_and(|s| s.ends_with(b"\r\n\r\n")) {
                let head = self.buf.get(..self.len).unwrap_or_default();
                let (verdict, status) = handshake::check_response(head, &self.accept);
                self.len = 0;
                match verdict {
                    UpgradeResult::Ok => {
                        self.dec.reset();
                        self.phase = Phase::Open;
                        self.sm.process_event(ConnectionEvent::ConnectSuccess);
                    }
                    UpgradeResult::NotSwitching => self.fail(Failure::UpgradeRejected(status)),
                    _ => self.fail(Failure::UpgradeInvalid),
                }
                return i.saturating_add(1);
            }
        }
        rest.len()
    }

    fn on_control(&mut self) {
        let payload = self.dec.control_payload();
        match self.dec.frame_opcode {
            OPCODE_PING => {
                let mut c = Control { opcode: OPCODE_PONG, len: payload.len() as u8, data: [0; MAX_CONTROL_PAYLOAD] };
                if let Some(d) = c.data.get_mut(..payload.len()) {
                    d.copy_from_slice(payload);
                }
                self.reply = Some(c);
            }
            OPCODE_CLOSE => {
                let echo = close_echo(payload);
                let mut c = Control { opcode: OPCODE_CLOSE, len: echo.len() as u8, data: [0; MAX_CONTROL_PAYLOAD] };
                if let Some(d) = c.data.get_mut(..echo.len()) {
                    d.copy_from_slice(echo);
                }
                let code = close_code(payload);
                self.reply = Some(c);
                self.fail(Failure::PeerClosed(code));
            }
            _ => {} // Pong: nothing to do, we never ping
        }
    }

    fn release(&mut self) {
        if self.taken > 0 {
            consume(&mut self.buf, &mut self.len, self.taken);
            self.taken = 0;
        }
    }

    /// The next packet for the LDN layer: its id and payload (without the 12-byte header),
    /// valid until the next call to `next_packet` or `on_bytes`. Ping, the handshake answer
    /// and unknown ids are handled or skipped here. Nothing is delivered before the
    /// Initialize has been sent (state Handshaking or Ready).
    pub fn next_packet(&mut self) -> Option<(PacketId, &[u8])> {
        let (id, size) = self.advance()?;
        Some((id, self.buf.get(HEADER_SIZE..size).unwrap_or_default()))
    }

    fn advance(&mut self) -> Option<(PacketId, usize)> {
        self.release();
        loop {
            if self.phase != Phase::Open
                || self.loss.is_some()
                || !matches!(self.sm.state(), ConnectionState::Handshaking | ConnectionState::Ready)
            {
                return None;
            }
            let head = self.buf.get(..self.len).unwrap_or_default();
            let (res, size) = peek_packet_info(head);
            match res {
                BufferResult::Success => {}
                BufferResult::NoCompletePacket => return None,
                _ => {
                    self.fail(Failure::Protocol);
                    return None;
                }
            }
            let (_, header) = decode_header(head);
            self.taken = size;
            let raw = header.type_;
            match PacketId::from_raw(raw) {
                Some(id) if !self.internal(id, size) => return Some((id, size)),
                _ => self.release(), // handled here, or an id this build does not know
            }
        }
    }

    /// Packets the connection layer consumes itself. `true` = consumed.
    fn internal(&mut self, id: PacketId, size: usize) -> bool {
        let payload = self.buf.get(HEADER_SIZE..size).unwrap_or_default();
        if id == PacketId::Ping {
            // requester 0 = the relay's ping: echo it. 1 = answer to a ping of ours (we send none).
            if let [0, n, ..] = payload {
                self.ping_echo = Some(*n);
            }
            return true;
        }
        if self.sm.state() != ConnectionState::Handshaking {
            return false;
        }
        match id {
            PacketId::Initialize => {
                if let Some((sid, rest)) = payload.split_first_chunk::<16>()
                    && let Some((mac, _)) = rest.split_first_chunk::<6>()
                {
                    self.session = Some(Session { id: *sid, mac: *mac });
                }
                self.handshake_done();
                true
            }
            PacketId::SyncNetwork => {
                self.handshake_done();
                true
            }
            PacketId::NetworkError => {
                let code = <[u8; 4]>::try_from(payload.get(..4).unwrap_or_default())
                    .ok()
                    .map_or(NetworkErrorCode::Unknown, |b| {
                        NetworkErrorCode::from_raw(i32::from_le_bytes(b)).unwrap_or(NetworkErrorCode::Unknown)
                    });
                self.last_error = Some(code);
                self.fail(if matches!(code, NetworkErrorCode::VersionTooLow | NetworkErrorCode::VersionTooHigh) {
                    Failure::VersionMismatch
                } else {
                    Failure::HandshakeRejected
                });
                true
            }
            PacketId::Disconnect => {
                self.fail(Failure::ServerDisconnected);
                true
            }
            _ => false, // other packets during the handshake go to the LDN layer
        }
    }

    fn handshake_done(&mut self) {
        self.sm.process_event(ConnectionEvent::HandshakeSuccess);
        self.rec.reset();
        self.failure = None;
        self.last_error = None;
    }

    // ---- send ----------------------------------------------------------------------

    /// One masked WebSocket binary frame holding the LDN packet `id` + `payload`, written to
    /// `out`; returns its length, or 0 if there is no WebSocket yet, the packet exceeds the
    /// protocol maximum, or `out` is too small. Payload sizes: see [`frame_packet`].
    pub fn send_packet(&mut self, id: PacketId, payload: &[u8], mask: [u8; 4], out: &mut [u8]) -> usize {
        if self.phase != Phase::Open || !self.sm.state().is_connected() {
            return 0;
        }
        self.tx_dirty = true;
        frame_packet(id.raw(), payload, mask, out)
    }

    // ---- poll ----------------------------------------------------------------------

    /// Advance timers and produce the next thing to do. `mask` = fresh random bytes (they mask
    /// the frame written to `out` and seed the backoff jitter). Call until `Idle`; `out` should
    /// be at least [`MIN_OUT`] bytes.
    pub fn poll(&mut self, now_ms: u64, mask: [u8; 4], out: &mut [u8]) -> Action {
        if core::mem::take(&mut self.rx_dirty) {
            self.last_rx_ms = now_ms;
        }
        if core::mem::take(&mut self.tx_dirty) {
            self.last_tx_ms = now_ms;
        }

        if let Some(c) = self.reply {
            let n = control_frame(c.opcode, c.data.get(..c.len as usize).unwrap_or_default(), mask, out);
            if n == 0 {
                return Action::Idle;
            }
            self.reply = None;
            self.last_tx_ms = now_ms;
            return Action::Send(n);
        }
        if let Some(id) = self.ping_echo {
            let n = frame_packet(PacketId::Ping.raw(), &[0, id], mask, out);
            if n == 0 {
                return Action::Idle;
            }
            self.ping_echo = None;
            self.last_tx_ms = now_ms;
            return Action::Send(n);
        }
        if self.closing != Closing::No {
            return self.poll_closing(now_ms, mask, out);
        }
        if let Some(f) = self.loss.take() {
            self.apply_loss(now_ms, f, u32::from_le_bytes(mask));
            return Action::Drop;
        }

        match self.sm.state() {
            ConnectionState::Connecting | ConnectionState::Retrying => {
                if !self.open_issued {
                    self.open_issued = true;
                    self.since_ms = now_ms;
                    return Action::Open;
                }
                if now_ms.saturating_sub(self.since_ms) >= self.cfg.connect_timeout_ms {
                    self.apply_loss(now_ms, Failure::ConnectTimeout, u32::from_le_bytes(mask));
                    return Action::Drop;
                }
            }
            ConnectionState::Connected => {
                let mut init = [0u8; 22];
                let (id, mac) = init.split_at_mut(16);
                id.copy_from_slice(&self.cfg.client_id);
                mac.copy_from_slice(&self.cfg.mac);
                let n = frame_packet(PacketId::Initialize.raw(), &init, mask, out);
                if n == 0 {
                    return Action::Idle;
                }
                self.sm.process_event(ConnectionEvent::HandshakeStarted);
                self.since_ms = now_ms;
                self.last_rx_ms = now_ms;
                self.last_tx_ms = now_ms;
                return Action::Send(n);
            }
            ConnectionState::Handshaking => {
                if now_ms.saturating_sub(self.since_ms) >= self.cfg.handshake_timeout_ms {
                    self.apply_loss(now_ms, Failure::HandshakeTimeout, u32::from_le_bytes(mask));
                    return Action::Drop;
                }
            }
            ConnectionState::Ready => {
                let quiet = |t: u64| now_ms.saturating_sub(t) >= self.cfg.silence_timeout_ms;
                if quiet(self.last_rx_ms) && quiet(self.last_tx_ms) {
                    self.apply_loss(now_ms, Failure::Silent, u32::from_le_bytes(mask));
                    return Action::Drop;
                }
            }
            ConnectionState::Backoff => {
                if now_ms.saturating_sub(self.since_ms) >= u64::from(self.backoff_ms) {
                    self.sm.process_event(ConnectionEvent::BackoffExpired);
                    self.open_issued = true;
                    self.since_ms = now_ms;
                    self.reset_stream();
                    return Action::Open;
                }
            }
            ConnectionState::Disconnected | ConnectionState::Disconnecting | ConnectionState::Error => {}
        }
        Action::Idle
    }

    fn poll_closing(&mut self, now_ms: u64, mask: [u8; 4], out: &mut [u8]) -> Action {
        if self.closing == Closing::SendDisconnect {
            self.closing = Closing::SendClose;
            if self.sm.state() == ConnectionState::Ready && self.phase == Phase::Open {
                let n = frame_packet(PacketId::Disconnect.raw(), DisconnectMessage { disconnect_ip: 0 }.as_bytes(), mask, out);
                if n > 0 {
                    self.last_tx_ms = now_ms;
                    return Action::Send(n);
                }
            }
        }
        if self.closing == Closing::SendClose {
            self.closing = Closing::Teardown;
            if self.phase == Phase::Open {
                // 1000 = normal closure
                let n = control_frame(OPCODE_CLOSE, &[0x03, 0xE8], mask, out);
                if n > 0 {
                    return Action::Send(n);
                }
            }
        }
        self.closing = Closing::No;
        self.loss = None;
        self.reset_stream();
        self.sm.process_event(ConnectionEvent::Disconnect);
        self.sm.process_event(ConnectionEvent::ConnectionLost); // Disconnecting -> Disconnected
        self.rec.reset();
        Action::Drop
    }

    fn apply_loss(&mut self, now_ms: u64, f: Failure, rand: u32) {
        use ConnectionEvent as E;
        use ConnectionState as S;
        self.failure = Some(f);
        self.reset_stream();
        let ev = match (self.sm.state(), f) {
            (_, Failure::VersionMismatch) => E::FatalError,
            (S::Connecting | S::Retrying, _) => E::ConnectFailed,
            (
                S::Connected | S::Handshaking,
                Failure::HandshakeTimeout | Failure::HandshakeRejected | Failure::ServerDisconnected,
            ) => E::HandshakeFailed,
            _ => E::ConnectionLost,
        };
        self.sm.process_event(ev);
        if self.sm.state() != S::Backoff {
            return;
        }
        let seed = rand ^ self.rec.retry_count().wrapping_add(1).wrapping_mul(2_654_435_761);
        match self.rec.next_retry(seed) {
            Some(d) => {
                self.backoff_ms = d;
                self.since_ms = now_ms;
            }
            None => {
                // out of attempts: give up (Backoff -> Disconnected), fresh budget next time
                self.sm.process_event(E::Disconnect);
                self.rec.reset();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------------------

/// Mask `body` (already placed after the header at `out[hdr_len..]`) and return the total.
fn write_frame(opcode: u8, mask: [u8; 4], out: &mut [u8], body_len: usize, fill: impl FnOnce(&mut [u8])) -> usize {
    let (hdr, hn) = ws_header(opcode, body_len, Some(&mask));
    let total = hn.saturating_add(body_len);
    let Some(frame) = out.get_mut(..total) else { return 0 };
    let (h, body) = frame.split_at_mut(hn);
    h.copy_from_slice(hdr.get(..hn).unwrap_or_default());
    fill(body);
    apply_mask(body, &mask);
    total
}

/// One masked binary WebSocket frame holding the LDN packet `type_` + `payload`. 0 if the
/// packet (header + payload) reaches `MAX_PACKET_SIZE`, which the relay (like LdnServer) answers
/// by closing the socket with 1002, or if `out` is too small.
pub fn frame_packet(type_: u8, payload: &[u8], mask: [u8; 4], out: &mut [u8]) -> usize {
    if HEADER_SIZE.saturating_add(payload.len()) >= MAX_PACKET_SIZE {
        return 0;
    }
    write_frame(OPCODE_BINARY, mask, out, HEADER_SIZE.saturating_add(payload.len()), |body| {
        ldn_header(body, type_, payload.len() as i32);
        if let Some(d) = body.get_mut(HEADER_SIZE..) {
            d.copy_from_slice(payload);
        }
    })
}

/// A masked control frame (`payload` at most 125 bytes).
fn control_frame(opcode: u8, payload: &[u8], mask: [u8; 4], out: &mut [u8]) -> usize {
    if payload.len() > MAX_CONTROL_PAYLOAD {
        return 0;
    }
    write_frame(opcode, mask, out, payload.len(), |body| body.copy_from_slice(payload))
}
