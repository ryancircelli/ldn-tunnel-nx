//! The `ldn:u` session (C++ `ICommunicationService`) as sans-IO logic: the
//! LDN state machine, the relay handshake, request/reply waits, network info
//! fix-ups and the idle timeout. No IPC, threads, sockets, clocks or
//! allocation: the shell feeds IPC calls, relay packets and the time in, and
//! drains [`Action`]s out. The contract is in `ldn/README.md`.
//!
//! Ported from `sysmodule/source/ldn/ldn_icommunication.cpp` (+ the state
//! machine, network timeout and helpers) and the parts of
//! `network/client.cpp` the LDN side relies on (handshake, ping echo).
//! Not ported: P2P/UPnP, passphrase, TCP proxy (`Proxy{Connect,Disconnect}`
//! packets are logged as unsupported).

use core::fmt::{self, Write as _};
use core::mem::size_of;

use heapless::{Deque, String, Vec};
use zerocopy::{FromBytes, FromZeros, IntoBytes};

use crate::ldn_types::{
    network_info_to_config, network_info_to_security_parameter, scan_filter_flag,
};
use crate::wire::{
    AddressList, ConnectPrivateRequest, ConnectRequest, CreateAccessPointPrivateRequest,
    CreateAccessPointRequest, DisconnectMessage, InitializeMessage, IntentId, MacAddress,
    NetworkConfig, NetworkErrorMessage, NetworkInfo, PacketId, PingMessage, ProtocolType,
    ProxyConfig, ProxyDataHeader, ProxyInfo, RejectRequest, ScanFilterFull, SecurityConfig,
    SecurityParameter, SessionId, UserConfig,
};

#[cfg(test)]
mod tests;
pub mod shell;

pub const NODE_COUNT_MAX: usize = 8;
pub const ADVERTISE_DATA_MAX: usize = 384;
/// C++ `MAX_SCAN_RESULTS`.
pub const SCAN_RESULTS_MAX: usize = 8;
/// Largest payload the session sends (`ConnectRequest`).
pub const MAX_PAYLOAD: usize = size_of::<ConnectRequest>();
pub const LOG_TEXT_MAX: usize = 120;

/// Ryujinx `NetworkTimeout` (InactiveTimeout): drop the relay link this long after leaving a room.
pub const IDLE_TIMEOUT_MS: u64 = 6000;
/// Per phase of bringing the link up: transport open, then Initialize reply (C++ handshake wait).
pub const LINK_TIMEOUT_MS: u64 = 5000;
const SCAN_TIMEOUT_MS: u64 = 1000;
const CONNECT_TIMEOUT_MS: u64 = 5000;
/// Ryujinx FailureTimeout, used by the Private variants.
const PRIVATE_TIMEOUT_MS: u64 = 4000;
const REJECT_TIMEOUT_MS: u64 = 6000;

/// Outbox capacity. Logs only take the first `OUTBOX - OUTBOX_RESERVED` slots,
/// so the effects of one call always fit when the shell drains after every call.
/// ponytail: every Action is as big as the largest Send (~1.3 KB), so this is
/// ~17 KB per session; split payloads into their own slot if memory gets tight.
const OUTBOX: usize = 12;
const OUTBOX_RESERVED: usize = 6;

const NETWORK_ERROR_PORT_UNREACHABLE: i32 = 1;
/// MAC the C++ client starts from (02:00:5E:00:53:01); the relay assigns the real one.
const INITIAL_MAC: [u8; 6] = [0x02, 0x00, 0x5E, 0x00, 0x53, 0x01];

pub use crate::ldn_types::{CommState, DisconnectReason, NodeStateChange};

/// nn::ldn results (module 203, shown as 2203-NNNN); the value is the description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum LdnError {
    DeviceNotAvailable = 16,
    InvalidState = 32,
    ConnectFailure = 64,
    ConnectNotFound = 65,
    ConnectTimeout = 66,
    ConnectRejected = 67,
    InvalidArgument = 96,
    VersionTooLow = 113,
    VersionTooHigh = 114,
    TooManyPlayers = 144,
}

impl LdnError {
    pub const MODULE: u32 = 203;

    /// The Horizon result code (`MAKERESULT(203, description)`).
    pub const fn result_code(self) -> u32 {
        Self::MODULE | ((self as u32) << 9)
    }
}

/// Result of a failed Connect from the relay's NetworkError wire code (0: none
/// was sent, the wait timed out). C++ `helpers::ConnectFailureDescription`.
pub const fn connect_failure(wire_error: i32) -> LdnError {
    match wire_error {
        0 | 7 => LdnError::ConnectTimeout,
        2 => LdnError::TooManyPlayers,
        3 => LdnError::VersionTooLow,
        4 => LdnError::VersionTooHigh,
        5 => LdnError::ConnectFailure,
        6 => LdnError::ConnectNotFound,
        8 => LdnError::ConnectRejected,
        _ => LdnError::DeviceNotAvailable,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Error,
    Warn,
    Info,
}

pub type Payload = Vec<u8, MAX_PAYLOAD>;
pub type LogText = String<LOG_TEXT_MAX>;

/// Effects for the shell, drained with [`Session::next_action`] after every call.
#[allow(clippy::large_enum_variant)] // see OUTBOX
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Send one relay packet: LdnHeader(`id`, payload length) + `payload`.
    Send {
        id: PacketId,
        payload: Payload,
    },
    /// Signal the game's state-change event (AttachStateChangeEvent).
    StateChanged,
    /// Our virtual IP and mask (Ryujinx format) for the proxy-socket router.
    ProxyConfig {
        ip: u32,
        mask: u32,
    },
    /// Open the relay transport, then call `on_relay_open` (or `on_relay_closed` on failure).
    RelayConnect,
    /// Close the relay transport and reset the router. Do not call `on_relay_closed` for it.
    RelayDisconnect,
    Log {
        level: Level,
        text: LogText,
    },
    /// The pending request finished: fetch it with [`Session::take_reply`].
    ReplyReady,
}

/// Returned by the requests that wait on the relay: the reply arrives later
/// through [`Action::ReplyReady`] + [`Session::take_reply`].
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct Pending;

/// A ProxyData packet for the router, borrowed from the bytes given to `on_packet`.
#[derive(Debug, PartialEq, Eq)]
pub struct ProxyDataIn<'a> {
    pub info: ProxyInfo,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    Down,
    /// RelayConnect sent, waiting for `on_relay_open`.
    Opening {
        deadline: u64,
    },
    /// Passphrase + Initialize sent, waiting for the Initialize reply.
    Handshaking {
        deadline: u64,
    },
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Scan,
    CreateNetwork,
    Connect,
    Reject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The awaited reply arrived.
    Reply,
    /// A NetworkError (other than wire code 1) arrived.
    Error,
    Timeout,
    /// The link never came up, so the request was never sent.
    NoLink,
}

struct Request {
    op: Op,
    id: PacketId,
    payload: Payload,
    timeout_ms: u64,
    /// `None` while waiting for the link; set when the request goes out.
    deadline: Option<u64>,
}

/// One `ldn:u` session (one per `CreateUserLocalCommunicationService`).
pub struct Session {
    state: CommState,
    link: Link,
    /// LocalCommunicationId used when the game passes -1 or 0 (the program id).
    local_communication_id: u64,
    network_info: NetworkInfo,
    /// Ryujinx `_networkConnected`: we are in a room on the relay.
    network_connected: bool,
    prev_node_connected: [bool; NODE_COUNT_MAX],
    disconnect_reason: DisconnectReason,
    /// Reason from a relay Reject, applied by the Disconnect that follows.
    pending_reject_reason: Option<DisconnectReason>,
    /// Our virtual IP and mask from ProxyConfig (Ryujinx format); 0 = none.
    ipv4: u32,
    mask: u32,
    /// Scene the game asked for; the relay may report 0.
    expected_scene_id: u16,
    scan_results: Vec<NetworkInfo, SCAN_RESULTS_MAX>,
    advertise_data: Vec<u8, ADVERTISE_DATA_MAX>,
    /// Wire code of the last NetworkError (Ryujinx `_lastError`); 0 = none.
    last_network_error: i32,
    /// Idle timeout deadline (Ryujinx NetworkTimeout); `None` = disabled.
    idle_deadline: Option<u64>,
    /// Id and MAC from the last Initialize reply, sent back on reconnect.
    relay_id: [u8; 16],
    mac: [u8; 6],
    request: Option<Request>,
    reply: Option<Result<(), LdnError>>,
    outbox: Deque<Action, OUTBOX>,
}

macro_rules! log {
    ($s:expr, $level:ident, $($arg:tt)*) => {
        push_log(&mut $s.outbox, Level::$level, format_args!($($arg)*))
    };
}

impl Session {
    pub fn new(local_communication_id: u64) -> Self {
        Self {
            state: CommState::None,
            link: Link::Down,
            local_communication_id,
            network_info: NetworkInfo::new_zeroed(),
            network_connected: false,
            prev_node_connected: [false; NODE_COUNT_MAX],
            disconnect_reason: DisconnectReason::None,
            pending_reject_reason: None,
            ipv4: 0,
            mask: 0,
            expected_scene_id: 0,
            scan_results: Vec::new(),
            advertise_data: Vec::new(),
            last_network_error: 0,
            idle_deadline: None,
            relay_id: [0; 16],
            mac: INITIAL_MAC,
            request: None,
            reply: None,
            outbox: Deque::new(),
        }
    }

    // ------------------------------------------------------------ outbox

    /// Next effect for the shell. Drain until `None` after every call.
    pub fn next_action(&mut self) -> Option<Action> {
        self.outbox.pop_front()
    }

    /// The result of the request that returned [`Pending`], once [`Action::ReplyReady`] was emitted.
    pub fn take_reply(&mut self) -> Option<Result<(), LdnError>> {
        self.reply.take()
    }

    /// Earliest time [`Session::poll`] has something to do.
    pub fn next_deadline(&self) -> Option<u64> {
        let link = match self.link {
            Link::Opening { deadline } | Link::Handshaking { deadline } => Some(deadline),
            Link::Down | Link::Ready => None,
        };
        [
            link,
            self.request.as_ref().and_then(|r| r.deadline),
            self.idle_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn push(&mut self, action: Action) {
        // Cannot fail while the shell drains after every call (see OUTBOX).
        let _ = self.outbox.push_back(action);
    }

    fn send(&mut self, id: PacketId, bytes: &[u8]) {
        let payload = Payload::from_slice(bytes).unwrap_or_default();
        self.push(Action::Send { id, payload });
    }

    // ------------------------------------------------------------ queries

    pub fn state(&self) -> CommState {
        self.state
    }

    /// GetNetworkInfo.
    pub fn network_info(&self) -> &NetworkInfo {
        &self.network_info
    }

    /// GetIpv4Address: our virtual IP and mask while the relay link is up, else
    /// `None` and the shell answers with the console's own address (nifm).
    pub fn get_ipv4_address(&self) -> Option<(u32, u32)> {
        (self.link == Link::Ready && self.ipv4 != 0).then_some((self.ipv4, self.mask))
    }

    pub fn get_disconnect_reason(&self) -> DisconnectReason {
        self.disconnect_reason
    }

    pub fn get_security_parameter(&self) -> SecurityParameter {
        network_info_to_security_parameter(&self.network_info)
    }

    pub fn get_network_config(&self) -> NetworkConfig {
        network_info_to_config(&self.network_info)
    }

    /// GetNetworkInfoLatestUpdate: node state changes since the last call for
    /// the first `count` nodes (the game's buffer length; entries past 8 are
    /// the shell's to zero). Read [`Session::network_info`] for the info.
    pub fn get_network_info_latest_update(
        &mut self,
        count: usize,
    ) -> [NodeStateChange; NODE_COUNT_MAX] {
        let mut out = [NodeStateChange::None; NODE_COUNT_MAX];
        let nodes = self.network_info.ldn.nodes;
        for ((change, prev), node) in out
            .iter_mut()
            .zip(self.prev_node_connected.iter_mut())
            .zip(nodes.iter())
            .take(count)
        {
            let now = node.is_connected != 0;
            *change = match (*prev, now) {
                (false, true) => NodeStateChange::Connect,
                (true, false) => NodeStateChange::Disconnect,
                _ => NodeStateChange::None,
            };
            *prev = now;
        }
        out
    }

    /// Networks found by the last Scan (read after its reply; ScanPrivate is Scan).
    pub fn scan_results(&self) -> &[NetworkInfo] {
        &self.scan_results
    }

    /// Our node index in the network (matched by IP), or 0xFF when not found.
    pub fn local_node_id(&self) -> u8 {
        let nodes = self.network_info.ldn.nodes;
        nodes
            .iter()
            .position(|n| n.is_connected != 0 && n.ipv4_address == self.ipv4)
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or(0xFF)
    }

    pub fn is_relay_ready(&self) -> bool {
        self.link == Link::Ready
    }

    // ------------------------------------------------------------ IPC: lifecycle

    /// Initialize / InitializeSystem2.
    pub fn initialize(&mut self) -> Result<(), LdnError> {
        self.transition(&[CommState::None], CommState::Initialized)?;
        self.disconnect_reason = DisconnectReason::None;
        Ok(())
    }

    /// Finalize, and what the shell runs when the game closes the session.
    /// Drops a pending request without a reply.
    pub fn finalize(&mut self, now: u64) {
        self.request = None;
        self.reply = None;
        self.leave_network(now);
        self.link_down(now, true);
        if self.state != CommState::None {
            self.state = CommState::None;
            self.push(Action::StateChanged);
        }
        self.network_info = NetworkInfo::new_zeroed();
        self.prev_node_connected = [false; NODE_COUNT_MAX];
        self.expected_scene_id = 0;
    }

    /// SetProtocol (cmd 106): Ryujinx accepts 1 and 3.
    pub fn set_protocol(&mut self, protocol: u32) -> Result<(), LdnError> {
        log!(self, Info, "SetProtocol({protocol})");
        if protocol == 1 || protocol == 3 {
            Ok(())
        } else {
            Err(LdnError::InvalidArgument)
        }
    }

    // ------------------------------------------------------------ IPC: access point

    /// Also starts the relay link in the background; a failure there is not
    /// reported (CreateNetwork retries).
    pub fn open_access_point(&mut self, now: u64) -> Result<(), LdnError> {
        self.transition(&[CommState::Initialized], CommState::AccessPoint)?;
        self.ensure_link(now);
        Ok(())
    }

    pub fn close_access_point(&mut self, now: u64) -> Result<(), LdnError> {
        self.leave_network(now);
        self.link_down(now, true);
        self.transition(
            &[CommState::AccessPoint, CommState::AccessPointCreated],
            CommState::Initialized,
        )?;
        self.expected_scene_id = 0;
        Ok(())
    }

    /// CreateNetwork: the request (with the advertise data set so far) goes out
    /// once the link is up; replies InvalidState on any failure, like Ryujinx.
    pub fn create_network(
        &mut self,
        security: &SecurityConfig,
        user: &UserConfig,
        network: &NetworkConfig,
        now: u64,
    ) -> Result<Pending, LdnError> {
        self.idle_deadline = None;
        self.check_can_request(CommState::AccessPoint)?;
        self.expected_scene_id = network.intent_id.scene_id;
        let mut req = CreateAccessPointRequest::new_zeroed();
        req.security_config = *security;
        req.user_config = *user;
        req.network_config = self.request_network_config(network);
        let mut payload = Payload::from_slice(req.as_bytes()).unwrap_or_default();
        let _ = payload.extend_from_slice(&self.advertise_data); // 188 + 384 fits
        Ok(self.start(
            Op::CreateNetwork,
            PacketId::CreateAccessPoint,
            payload,
            CONNECT_TIMEOUT_MS,
            now,
        ))
    }

    /// CreateNetworkPrivate. `address_list` is the game's optional buffer.
    pub fn create_network_private(
        &mut self,
        security: &SecurityConfig,
        parameter: &SecurityParameter,
        user: &UserConfig,
        network: &NetworkConfig,
        address_list: Option<&AddressList>,
        now: u64,
    ) -> Result<Pending, LdnError> {
        self.idle_deadline = None;
        self.check_can_request(CommState::AccessPoint)?;
        self.expected_scene_id = network.intent_id.scene_id;
        let mut req = CreateAccessPointPrivateRequest::new_zeroed();
        req.security_config = *security;
        req.security_parameter = *parameter;
        req.user_config = *user;
        req.network_config = self.request_network_config(network);
        if let Some(list) = address_list {
            req.address_list = *list;
        }
        let payload = Payload::from_slice(req.as_bytes()).unwrap_or_default();
        Ok(self.start(
            Op::CreateNetwork,
            PacketId::CreateAccessPointPrivate,
            payload,
            PRIVATE_TIMEOUT_MS,
            now,
        ))
    }

    pub fn destroy_network(&mut self, now: u64) -> Result<(), LdnError> {
        self.transition(&[CommState::AccessPointCreated], CommState::AccessPoint)?;
        // Tell the relay the room is gone (Ryujinx AccessPoint.Dispose).
        self.leave_network(now);
        self.expected_scene_id = 0;
        Ok(())
    }

    /// Kept for CreateNetwork; forwarded only while in a room (Ryujinx).
    pub fn set_advertise_data(&mut self, data: &[u8]) {
        let n = data.len().min(ADVERTISE_DATA_MAX);
        self.advertise_data =
            Vec::from_slice(data.get(..n).unwrap_or_default()).unwrap_or_default();
        if self.network_connected && self.link == Link::Ready {
            let data = self.advertise_data.clone();
            self.send(PacketId::SetAdvertiseData, &data);
        }
    }

    /// Forwarded only while in a room (Ryujinx).
    pub fn set_station_accept_policy(&mut self, policy: u8) {
        if self.network_connected && self.link == Link::Ready {
            self.send(PacketId::SetAcceptPolicy, &[policy]);
        }
    }

    /// Reject: only the host of a created room may.
    pub fn reject(&mut self, node_id: u32, now: u64) -> Result<Pending, LdnError> {
        if self.state != CommState::AccessPointCreated
            || !self.network_connected
            || self.link != Link::Ready
            || self.request.is_some()
        {
            return Err(LdnError::InvalidState);
        }
        let req = RejectRequest {
            node_id,
            disconnect_reason: DisconnectReason::Rejected as u32,
        };
        let payload = Payload::from_slice(req.as_bytes()).unwrap_or_default();
        Ok(self.start(
            Op::Reject,
            PacketId::Reject,
            payload,
            REJECT_TIMEOUT_MS,
            now,
        ))
    }

    // ------------------------------------------------------------ IPC: station

    /// Also starts the relay link in the background (Scan/Connect retry).
    pub fn open_station(&mut self, now: u64) -> Result<(), LdnError> {
        self.transition(&[CommState::Initialized], CommState::Station)?;
        self.ensure_link(now);
        Ok(())
    }

    /// Keeps the relay link: games open/close stations while scanning, and the
    /// idle timeout drops it later.
    pub fn close_station(&mut self, now: u64) -> Result<(), LdnError> {
        self.transition(
            &[CommState::Station, CommState::StationConnected],
            CommState::Initialized,
        )?;
        self.leave_network(now);
        self.expected_scene_id = 0;
        Ok(())
    }

    /// Scan / ScanPrivate, in any state. Always replies Ok: an unreachable
    /// relay, an error or a timeout leave [`Session::scan_results`] empty or partial.
    pub fn scan(&mut self, filter: &ScanFilterFull, now: u64) -> Result<Pending, LdnError> {
        if self.request.is_some() {
            return Err(LdnError::InvalidState);
        }
        let mut f = *filter;
        let flag = f.flag;
        f.flag = flag | scan_filter_flag::LOCAL_COMMUNICATION_ID; // only this game's rooms
        f.network_id.intent_id = IntentId {
            local_communication_id: self
                .real_local_communication_id(filter.network_id.intent_id.local_communication_id),
            reserved1: 0,
            scene_id: filter.network_id.intent_id.scene_id,
            reserved2: 0,
        };
        f.reserved = [0; 16];
        self.expected_scene_id = filter.network_id.intent_id.scene_id;
        log!(
            self,
            Info,
            "scan: flag {:#x} lcid {:016X} scene {} type {}",
            { f.flag },
            { f.network_id.intent_id.local_communication_id },
            { f.network_id.intent_id.scene_id },
            { f.network_type }
        );
        let payload = Payload::from_slice(f.as_bytes()).unwrap_or_default();
        Ok(self.start(Op::Scan, PacketId::Scan, payload, SCAN_TIMEOUT_MS, now))
    }

    /// Connect to a network from the scan results.
    pub fn connect(
        &mut self,
        security: &SecurityConfig,
        user: &UserConfig,
        local_communication_version: u32,
        option: u32,
        network: &NetworkInfo,
        now: u64,
    ) -> Result<Pending, LdnError> {
        self.idle_deadline = None;
        self.check_can_request(CommState::Station)?;
        self.expected_scene_id = network.network_id.intent_id.scene_id;
        let mut req = ConnectRequest::new_zeroed();
        req.security_config = *security;
        req.user_config = *user;
        req.local_communication_version = local_communication_version;
        req.option_unknown = option;
        req.network_info = *network;
        req.network_info.network_id.intent_id.local_communication_id =
            self.real_local_communication_id(network.network_id.intent_id.local_communication_id);
        let payload = Payload::from_slice(req.as_bytes()).unwrap_or_default();
        Ok(self.start(
            Op::Connect,
            PacketId::Connect,
            payload,
            CONNECT_TIMEOUT_MS,
            now,
        ))
    }

    #[allow(clippy::too_many_arguments)] // the IPC arguments + now
    pub fn connect_private(
        &mut self,
        security: &SecurityConfig,
        parameter: &SecurityParameter,
        user: &UserConfig,
        local_communication_version: u32,
        option: u32,
        network: &NetworkConfig,
        now: u64,
    ) -> Result<Pending, LdnError> {
        self.idle_deadline = None;
        self.check_can_request(CommState::Station)?;
        self.expected_scene_id = network.intent_id.scene_id;
        let req = ConnectPrivateRequest {
            security_config: *security,
            security_parameter: *parameter,
            user_config: *user,
            local_communication_version,
            option_unknown: option,
            network_config: self.request_network_config(network),
        };
        let payload = Payload::from_slice(req.as_bytes()).unwrap_or_default();
        Ok(self.start(
            Op::Connect,
            PacketId::ConnectPrivate,
            payload,
            PRIVATE_TIMEOUT_MS,
            now,
        ))
    }

    pub fn disconnect(&mut self, now: u64) -> Result<(), LdnError> {
        self.transition(&[CommState::StationConnected], CommState::Station)?;
        self.leave_network(now);
        self.disconnect_reason = DisconnectReason::User;
        self.expected_scene_id = 0;
        Ok(())
    }

    // ------------------------------------------------------------ relay side

    /// The transport asked for by [`Action::RelayConnect`] is open: start the handshake.
    pub fn on_relay_open(&mut self, now: u64) {
        if !matches!(self.link, Link::Opening { .. }) {
            log!(self, Warn, "relay open while not connecting, ignored");
            return;
        }
        self.link = Link::Handshaking {
            deadline: now.saturating_add(LINK_TIMEOUT_MS),
        };
        // An empty passphrase first (public rooms), as the C++ client does.
        self.send(PacketId::Passphrase, &[0; 128]);
        let init = InitializeMessage {
            id: SessionId {
                data: self.relay_id,
            },
            mac_address: MacAddress { data: self.mac },
        };
        self.send(PacketId::Initialize, init.as_bytes());
    }

    /// The shell's `Conn` finished the Initialize exchange itself (it sends Initialize and
    /// swallows the reply), so the link is up: `id` and `mac` are what the relay assigned
    /// ([`crate::conn::Session`]). Use this instead of [`Session::on_relay_open`] with `Conn`: the
    /// relay ignores a second Initialize, which would leave this session handshaking until its timeout.
    /// The passphrase is not sent; the relay's default is the empty one.
    pub fn on_relay_ready(&mut self, now: u64, id: [u8; 16], mac: [u8; 6]) {
        if !matches!(self.link, Link::Opening { .. }) {
            log!(self, Warn, "relay ready while not connecting, ignored");
            return;
        }
        self.relay_id = id;
        self.mac = mac;
        self.link = Link::Ready;
        log!(self, Info, "relay handshake done");
        if self.request.as_ref().is_some_and(|r| r.deadline.is_none()) {
            self.send_request(now);
        }
    }

    /// The transport closed or failed to open (not after [`Action::RelayDisconnect`]).
    pub fn on_relay_closed(&mut self, now: u64) {
        log!(self, Warn, "relay link lost");
        self.link_down(now, false);
    }

    /// Timers: link setup, request timeouts, the idle timeout.
    pub fn poll(&mut self, now: u64) {
        if let Link::Opening { deadline } | Link::Handshaking { deadline } = self.link
            && now >= deadline
        {
            log!(self, Error, "relay link timed out");
            self.link_down(now, true);
        }
        if self
            .request
            .as_ref()
            .and_then(|r| r.deadline)
            .is_some_and(|d| now >= d)
        {
            self.complete(Outcome::Timeout, now);
        }
        if self.idle_deadline.is_some_and(|d| now >= d) {
            self.idle_deadline = None;
            // A pending request still needs the link; its completion re-arms the timer.
            if !self.network_connected && self.link != Link::Down && self.request.is_none() {
                log!(self, Info, "inactivity timeout, closing the relay link");
                self.link_down(now, true);
            }
        }
    }

    /// One relay -> console packet (`id` = LdnHeader type, `data` = payload).
    /// Returns game data for the router; every other effect goes to the outbox.
    pub fn on_packet<'a>(&mut self, id: u8, data: &'a [u8], now: u64) -> Option<ProxyDataIn<'a>> {
        let Some(id) = PacketId::from_raw(id) else {
            log!(self, Warn, "unknown packet type {id}");
            return None;
        };
        if matches!(self.link, Link::Handshaking { .. }) {
            match id {
                PacketId::Initialize => {
                    if let Ok((msg, _)) = InitializeMessage::read_from_prefix(data) {
                        self.relay_id = msg.id.data;
                        self.mac = msg.mac_address.data;
                    }
                    self.link = Link::Ready;
                    log!(self, Info, "relay handshake done");
                    if self.request.as_ref().is_some_and(|r| r.deadline.is_none()) {
                        self.send_request(now);
                    }
                    return None;
                }
                PacketId::NetworkError | PacketId::Disconnect => {
                    let code = NetworkErrorMessage::read_from_prefix(data)
                        .map_or(0, |(m, _)| m.error_code);
                    log!(self, Error, "relay refused the handshake ({id:?} {code})");
                    self.link_down(now, true);
                    return None;
                }
                _ => {}
            }
        }
        match id {
            PacketId::Connected => self.on_connected(data, now),
            PacketId::SyncNetwork => self.on_sync_network(data),
            PacketId::Disconnect => {
                if self.network_connected {
                    self.room_lost(now);
                    // The relay tells the players of a closed room but keeps them in it until
                    // they leave; until then it refuses CreateAccessPoint (NetworkError Unknown).
                    self.send(PacketId::Disconnect, DisconnectMessage { disconnect_ip: 0 }.as_bytes());
                }
            }
            PacketId::Reject => {
                let reason = RejectRequest::read_from_prefix(data)
                    .ok()
                    .and_then(|(r, _)| DisconnectReason::from_u32(r.disconnect_reason))
                    .unwrap_or(DisconnectReason::Rejected);
                // Reason 0 (None) is no reason: the room-lost default applies (C++/Ryujinx).
                self.pending_reject_reason = (reason != DisconnectReason::None).then_some(reason);
                log!(self, Info, "rejected by the host ({reason:?})");
            }
            PacketId::RejectReply => {
                if self.waiting_for(Op::Reject) {
                    self.complete(Outcome::Reply, now);
                }
            }
            PacketId::Ping => {
                if let Ok((ping, _)) = PingMessage::read_from_prefix(data)
                    && ping.requester == 0
                    && self.link != Link::Down
                {
                    self.send(PacketId::Ping, &[0, ping.id]);
                }
            }
            PacketId::NetworkError => self.on_network_error(data, now),
            PacketId::ScanReply => {
                // Only while scanning: a late reply must not change the results the game was given.
                if !self.waiting_for(Op::Scan) {
                    return None;
                }
                if let Ok((mut info, _)) = NetworkInfo::read_from_prefix(data) {
                    self.fix_network_info(&mut info);
                    if self.scan_results.push(info).is_err() {
                        log!(self, Warn, "scan results full, network ignored");
                    }
                }
            }
            PacketId::ScanReplyEnd => {
                if self.waiting_for(Op::Scan) {
                    log!(self, Info, "scan: {} rooms from the relay", self.scan_results.len());
                    self.complete(Outcome::Reply, now);
                }
            }
            PacketId::ProxyConfig => {
                if let Ok((config, _)) = ProxyConfig::read_from_prefix(data) {
                    self.ipv4 = config.proxy_ip;
                    self.mask = config.proxy_subnet_mask;
                    log!(self, Info, "virtual ip {:08X}/{:08X}", self.ipv4, self.mask);
                    self.push(Action::ProxyConfig {
                        ip: self.ipv4,
                        mask: self.mask,
                    });
                }
            }
            PacketId::ProxyData => return parse_proxy_data(data),
            PacketId::ProxyConnect | PacketId::ProxyConnectReply | PacketId::ProxyDisconnect => {
                log!(self, Warn, "TCP proxy unsupported, {id:?} dropped");
            }
            PacketId::ExternalProxy
            | PacketId::ExternalProxyToken
            | PacketId::ExternalProxyState => {
                log!(self, Info, "P2P unsupported, {id:?} ignored");
            }
            // Handshake leftovers, console -> relay ids, and the update/log
            // extensions (routed elsewhere by the shell).
            _ => {}
        }
        None
    }

    // ------------------------------------------------------------ internals

    /// C++ LdnStateMachine: only the listed states may move to `to`
    /// (already being there is an error too); signals the state event.
    fn transition(&mut self, from: &[CommState], to: CommState) -> Result<(), LdnError> {
        if !from.contains(&self.state) {
            return Err(LdnError::InvalidState);
        }
        self.state = to;
        self.push(Action::StateChanged);
        Ok(())
    }

    fn real_local_communication_id(&self, id: i64) -> i64 {
        // Games may pass -1 or 0 and let the SDK fill in the NACP value.
        if id == -1 || id == 0 {
            self.local_communication_id as i64
        } else {
            id
        }
    }

    fn request_network_config(&self, network: &NetworkConfig) -> NetworkConfig {
        NetworkConfig {
            intent_id: IntentId {
                local_communication_id: self
                    .real_local_communication_id(network.intent_id.local_communication_id),
                reserved1: 0,
                scene_id: network.intent_id.scene_id,
                reserved2: 0,
            },
            channel: network.channel,
            node_count_max: network.node_count_max,
            reserved1: 0,
            local_communication_version: network.local_communication_version,
            reserved2: [0; 10],
        }
    }

    fn check_can_request(&self, state: CommState) -> Result<(), LdnError> {
        if self.state != state || self.request.is_some() {
            Err(LdnError::InvalidState)
        } else {
            Ok(())
        }
    }

    fn waiting_for(&self, op: Op) -> bool {
        self.request
            .as_ref()
            .is_some_and(|r| r.op == op && r.deadline.is_some())
    }

    fn ensure_link(&mut self, now: u64) {
        if self.link == Link::Down {
            self.link = Link::Opening {
                deadline: now.saturating_add(LINK_TIMEOUT_MS),
            };
            self.push(Action::RelayConnect);
        }
    }

    fn start(
        &mut self,
        op: Op,
        id: PacketId,
        payload: Payload,
        timeout_ms: u64,
        now: u64,
    ) -> Pending {
        self.reply = None;
        self.request = Some(Request {
            op,
            id,
            payload,
            timeout_ms,
            deadline: None,
        });
        if self.link == Link::Ready {
            self.send_request(now);
        } else {
            self.ensure_link(now);
        }
        Pending
    }

    /// The link is up: move the state (as the C++ does after ConnectToServer) and send.
    fn send_request(&mut self, now: u64) {
        let Some(mut req) = self.request.take() else {
            return;
        };
        let moved = match req.op {
            Op::CreateNetwork => {
                self.transition(&[CommState::AccessPoint], CommState::AccessPointCreated)
            }
            Op::Connect => self.transition(&[CommState::Station], CommState::StationConnected),
            Op::Scan | Op::Reject => Ok(()),
        };
        if let Err(e) = moved {
            self.finish(Err(e));
            return;
        }
        match req.op {
            // PrepareForResponse: only an error that answers this request counts.
            Op::CreateNetwork | Op::Connect => self.last_network_error = 0,
            Op::Scan => self.scan_results.clear(),
            Op::Reject => {}
        }
        let payload = core::mem::take(&mut req.payload);
        self.push(Action::Send {
            id: req.id,
            payload,
        });
        req.deadline = Some(now.saturating_add(req.timeout_ms));
        self.request = Some(req);
    }

    fn finish(&mut self, result: Result<(), LdnError>) {
        self.reply = Some(result);
        self.push(Action::ReplyReady);
    }

    /// End the pending request (C++ WaitForResponse + the caller's epilogue).
    fn complete(&mut self, outcome: Outcome, now: u64) {
        let Some(req) = self.request.take() else {
            return;
        };
        let result = match (req.op, outcome) {
            (Op::Scan, Outcome::Reply | Outcome::Timeout) => {
                if outcome == Outcome::Timeout {
                    log!(
                        self,
                        Warn,
                        "scan timed out, {} networks",
                        self.scan_results.len()
                    );
                }
                self.idle_deadline = Some(now.saturating_add(IDLE_TIMEOUT_MS));
                Ok(())
            }
            (Op::Scan, Outcome::Error | Outcome::NoLink) => {
                self.scan_results.clear();
                Ok(())
            }
            // A Connected handled before the error or timeout still counts.
            (Op::CreateNetwork | Op::Connect, _)
                if self.network_connected || outcome == Outcome::Reply =>
            {
                self.idle_deadline = None;
                self.push(Action::StateChanged);
                Ok(())
            }
            (Op::CreateNetwork, _) => {
                log!(self, Error, "create network failed ({outcome:?})");
                self.revert(CommState::AccessPointCreated, CommState::AccessPoint);
                self.leave_network(now);
                Err(LdnError::InvalidState)
            }
            (Op::Connect, Outcome::NoLink) => Err(LdnError::DeviceNotAvailable),
            (Op::Connect, _) => {
                log!(
                    self,
                    Error,
                    "connect failed ({outcome:?}, error {})",
                    self.last_network_error
                );
                self.revert(CommState::StationConnected, CommState::Station);
                self.leave_network(now);
                Err(connect_failure(core::mem::take(
                    &mut self.last_network_error,
                )))
            }
            (Op::Reject, Outcome::Reply) if core::mem::take(&mut self.last_network_error) == 0 => {
                Ok(())
            }
            (Op::Reject, _) => Err(LdnError::InvalidState),
        };
        self.finish(result);
    }

    fn revert(&mut self, from: CommState, to: CommState) {
        if self.state == from {
            self.state = to;
            self.push(Action::StateChanged);
        }
    }

    /// Bring the link down; `close` asks the shell to close the transport.
    fn link_down(&mut self, now: u64, close: bool) {
        if self.link == Link::Down {
            return;
        }
        if close {
            self.push(Action::RelayDisconnect);
        }
        self.link = Link::Down;
        self.ipv4 = 0;
        self.mask = 0;
        // Ryujinx OnDisconnected -> DisconnectInternal.
        if self.network_connected {
            self.room_lost(now);
        }
        match self.request.as_ref().map(|r| r.deadline) {
            Some(None) => self.complete(Outcome::NoLink, now),
            Some(Some(_)) => self.complete(Outcome::Timeout, now),
            None => {}
        }
    }

    /// Leave the room ourselves (Ryujinx DisconnectNetwork).
    fn leave_network(&mut self, now: u64) {
        let was_connected = self.network_connected;
        self.network_connected = false;
        self.network_info = NetworkInfo::new_zeroed();
        self.prev_node_connected = [false; NODE_COUNT_MAX];
        if !was_connected {
            return;
        }
        if self.link == Link::Ready {
            self.send(
                PacketId::Disconnect,
                DisconnectMessage { disconnect_ip: 0 }.as_bytes(),
            );
        }
        self.idle_deadline = Some(now.saturating_add(IDLE_TIMEOUT_MS));
    }

    /// The relay removed us from the room (host left, kicked) or the link died.
    fn room_lost(&mut self, now: u64) {
        self.network_connected = false;
        self.network_info = NetworkInfo::new_zeroed();
        self.prev_node_connected = [false; NODE_COUNT_MAX];
        let is_host = self.state == CommState::AccessPointCreated;
        self.disconnect_reason = self.pending_reject_reason.take().unwrap_or(if is_host {
            DisconnectReason::DestroyedBySystem
        } else {
            DisconnectReason::DestroyedByUser
        });
        log!(self, Info, "left the room ({:?})", self.disconnect_reason);
        match self.state {
            CommState::AccessPointCreated => {
                self.revert(CommState::AccessPointCreated, CommState::AccessPoint)
            }
            CommState::StationConnected => {
                self.revert(CommState::StationConnected, CommState::Station)
            }
            _ => self.push(Action::StateChanged),
        }
        self.idle_deadline = Some(now.saturating_add(IDLE_TIMEOUT_MS));
    }

    fn on_connected(&mut self, data: &[u8], now: u64) {
        if !matches!(
            self.state,
            CommState::AccessPointCreated | CommState::StationConnected
        ) {
            // Answers a request that already failed: leave instead of
            // becoming a phantom node.
            log!(self, Warn, "late Connected, leaving the room");
            if self.link == Link::Ready {
                self.send(
                    PacketId::Disconnect,
                    DisconnectMessage { disconnect_ip: 0 }.as_bytes(),
                );
            }
            return;
        }
        match NetworkInfo::read_from_prefix(data) {
            Ok((mut info, _)) => {
                self.fix_network_info(&mut info);
                self.network_info = info;
                self.network_connected = true;
                self.pending_reject_reason = None;
                let (count, max) = (
                    self.network_info.ldn.node_count,
                    self.network_info.ldn.node_count_max,
                );
                let local = self.local_node_id();
                log!(
                    self,
                    Info,
                    "connected: {count}/{max} nodes, local node {local}"
                );
                // Wakes the game's poll loop while the request is still in flight (Ryujinx NetworkChange).
                self.push(Action::StateChanged);
            }
            // The C++ treats it as the reply all the same.
            Err(_) => log!(self, Error, "Connected too short ({} bytes)", data.len()),
        }
        if self.request.as_ref().is_some_and(|r| {
            matches!(r.op, Op::CreateNetwork | Op::Connect) && r.deadline.is_some()
        }) {
            self.complete(Outcome::Reply, now);
        }
    }

    fn on_sync_network(&mut self, data: &[u8]) {
        if !self.network_connected {
            return; // not in a room: nothing to update
        }
        if let Ok((mut info, _)) = NetworkInfo::read_from_prefix(data) {
            self.fix_network_info(&mut info);
            self.network_info = info;
            self.push(Action::StateChanged);
        }
    }

    fn on_network_error(&mut self, data: &[u8], now: u64) {
        let code = NetworkErrorMessage::read_from_prefix(data)
            .ok()
            .map(|(m, _)| m.error_code);
        if code == Some(NETWORK_ERROR_PORT_UNREACHABLE) {
            // Upstream PortUnreachable: a note about P2P, Connected follows. Not a reply.
            log!(self, Info, "relay: P2P port unreachable (ignored)");
            return;
        }
        if let Some(code) = code {
            self.last_network_error = code;
        }
        log!(self, Error, "relay NetworkError {code:?}");
        if self.request.as_ref().is_some_and(|r| r.deadline.is_some()) {
            self.complete(Outcome::Error, now);
        }
    }

    /// Clamp what the game will walk, and undo what the relay reports
    /// differently from real hardware.
    fn fix_network_info(&self, info: &mut NetworkInfo) {
        let ldn = &mut info.ldn;
        let (size, max, count) = (ldn.advertise_data_size, ldn.node_count_max, ldn.node_count);
        ldn.advertise_data_size = size.min(ADVERTISE_DATA_MAX as u16);
        ldn.node_count_max = max.min(NODE_COUNT_MAX as u8);
        ldn.node_count = count.min(ldn.node_count_max);
        // The relay may create rooms with sceneId 0; the game filters on its own.
        if self.expected_scene_id != 0 {
            info.network_id.intent_id.scene_id = self.expected_scene_id;
        }
        if self.local_communication_id != 0 {
            info.network_id.intent_id.local_communication_id = self.local_communication_id as i64;
        }
        // Real LDN never reports channel 0; games (MK8DX) wait forever on it.
        if info.common.channel == 0 {
            info.common.channel = 6;
        }
    }
}

/// Logs only use the unreserved part of the outbox (see OUTBOX). A free
/// function so the format arguments may borrow other fields of the session.
fn push_log(outbox: &mut Deque<Action, OUTBOX>, level: Level, args: fmt::Arguments<'_>) {
    if outbox.len() >= OUTBOX.saturating_sub(OUTBOX_RESERVED) {
        return;
    }
    let mut text = LogText::new();
    let _ = text.write_fmt(args); // truncated if longer
    let _ = outbox.push_back(Action::Log { level, text });
}

fn parse_proxy_data(data: &[u8]) -> Option<ProxyDataIn<'_>> {
    let (header, rest) = ProxyDataHeader::read_from_prefix(data).ok()?;
    let payload = rest.get(..usize::try_from(header.data_length).ok()?)?;
    let protocol = header.info.protocol;
    if protocol != ProtocolType::Tcp.raw() && protocol != ProtocolType::Udp.raw() {
        return None;
    }
    Some(ProxyDataIn {
        info: header.info,
        payload,
    })
}
