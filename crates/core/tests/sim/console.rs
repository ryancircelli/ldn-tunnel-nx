//! A simulated console: `Conn` + `Session` + `Router` wired the way the shell wires them.
use std::collections::VecDeque;

use ldn_tunnel_core::conn::{Action as ConnAction, Conn, ConnConfig, ConnectionState};
use ldn_tunnel_core::ldn::{Action as LdnAction, LdnError, Session};
use ldn_tunnel_core::router::bsd::{MSG_DONTWAIT, SOCK_DGRAM};
use ldn_tunnel_core::router::{Decision, RecvDecision, Router, SockAddrIn, socket_key};
use ldn_tunnel_core::wire::{PacketId, ProxyDataHeader};
use zerocopy::IntoBytes;

use super::relay::{Relay, TOKEN};

pub const PROGRAM_ID: u64 = 0x0100_0000_0000_1234;

pub struct Console {
    pub conn: Box<Conn<16384>>,
    pub session: Box<Session>,
    pub router: Box<Router>,
    /// Transport connection on the relay, if open.
    pub link: Option<usize>,
    pub client_id: [u8; 16],
    pub mac: [u8; 6],
    /// Results of finished pending requests, oldest first.
    pub replies: VecDeque<Result<(), LdnError>>,
    pub state_changes: u32,
    pub logs: Vec<String>,
    rng: u64,
    out: Vec<u8>,
    /// The session asked for a link and has not been told it is up.
    wants_link: bool,
    /// The session closed the transport itself: its Drop is not a loss.
    closing: bool,
}

impl Console {
    pub fn new(n: u8) -> Self {
        let client_id = [0x10 + n; 16];
        let mac = [2, 0, 0x5E, 0, 0x53, n];
        Self {
            conn: Box::new(Conn::new(ConnConfig::new(client_id, mac))),
            session: Box::new(Session::new(PROGRAM_ID)),
            router: Box::new(Router::new()),
            link: None,
            client_id,
            mac,
            replies: VecDeque::new(),
            state_changes: 0,
            logs: vec![],
            rng: 0x9E37_79B9_7F4A_7C15 ^ u64::from(n),
            out: vec![0; 20_000],
            wants_link: false,
            closing: false,
        }
    }

    fn mask(&mut self) -> [u8; 4] {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng as u32).to_le_bytes()
    }

    /// Send one LDN packet to the relay; false if there is no WebSocket.
    pub fn tx(&mut self, relay: &mut Relay, id: PacketId, payload: &[u8]) -> bool {
        let mask = self.mask();
        let n = self.conn.send_packet(id, payload, mask, &mut self.out);
        match (n, self.link) {
            (0, _) | (_, None) => false,
            (n, Some(l)) => {
                relay.rx(l, &self.out[..n]);
                true
            }
        }
    }

    /// Run everything that is ready; true if anything happened.
    pub fn pump(&mut self, relay: &mut Relay, now: u64) -> bool {
        let mut did = false;
        loop {
            let mut step = false;
            self.session.poll(now);
            step |= self.drain_session(relay, now);
            if self.wants_link && matches!(self.conn.state(), ConnectionState::Disconnected | ConnectionState::Error) {
                step |= self.conn.connect(now);
            }
            step |= self.drive_conn(relay, now);
            step |= self.read_relay(relay, now);
            if self.wants_link && self.conn.is_ready() {
                let s = *self.conn.session().unwrap();
                self.wants_link = false;
                self.session.on_relay_ready(now, s.id, s.mac);
                step = true;
            }
            if !step {
                return did;
            }
            did = true;
        }
    }

    fn drive_conn(&mut self, relay: &mut Relay, now: u64) -> bool {
        let mut did = false;
        loop {
            let mask = self.mask();
            match self.conn.poll(now, mask, &mut self.out) {
                ConnAction::Idle => return did,
                ConnAction::Open => {
                    let link = relay.connect();
                    self.link = Some(link);
                    let mut random = [0u8; 16];
                    random[..4].copy_from_slice(&self.mask());
                    random[4..8].copy_from_slice(&self.mask());
                    let mut req = [0u8; 640];
                    let n = self.conn.opened("relay.example.com", 443, "/ldn", TOKEN, &random, &mut req).unwrap();
                    relay.rx(link, &req[..n]);
                }
                ConnAction::Send(n) => relay.rx(self.link.unwrap(), &self.out[..n]),
                ConnAction::Drop => {
                    if let Some(l) = self.link.take() {
                        relay.close(l);
                    }
                    if !core::mem::take(&mut self.closing) {
                        // lost, or never came up: tell the session; the room is gone with the link
                        self.session.on_relay_closed(now);
                        self.router.reset();
                        self.wants_link = false;
                        self.drain_session(relay, now);
                    }
                }
            }
            did = true;
        }
    }

    fn read_relay(&mut self, relay: &mut Relay, now: u64) -> bool {
        let Some(l) = self.link else { return false };
        let bytes = relay.take(l);
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let used = self.conn.on_bytes(rest);
            rest = &rest[used..];
            while let Some((id, payload)) = self.conn.next_packet() {
                if let Some(p) = self.session.on_packet(id.raw(), payload, now) {
                    let header = ProxyDataHeader { info: p.info, data_length: p.payload.len() as u32 };
                    self.router.on_proxy_data(&header, p.payload);
                }
            }
            self.drain_session(relay, now);
            if used == 0 {
                break;
            }
        }
        !bytes.is_empty()
    }

    fn drain_session(&mut self, relay: &mut Relay, now: u64) -> bool {
        let mut did = false;
        while let Some(a) = self.session.next_action() {
            did = true;
            match a {
                LdnAction::Send { id, payload } => {
                    assert!(self.tx(relay, id, &payload), "session sent {id:?} with no link");
                }
                LdnAction::StateChanged => self.state_changes += 1,
                LdnAction::ProxyConfig { ip, mask } => self.router.set_proxy_config(ip, mask),
                LdnAction::RelayConnect => self.wants_link = true,
                LdnAction::RelayDisconnect => {
                    self.router.reset();
                    self.wants_link = false;
                    self.closing = true;
                    self.conn.close();
                }
                LdnAction::Log { text, .. } => self.logs.push(text.as_str().to_string()),
                LdnAction::ReplyReady => {
                    let r = self.session.take_reply().expect("ReplyReady without a reply");
                    self.replies.push_back(r);
                }
            }
        }
        let _ = now;
        did
    }

    // ---- the game's sockets (bsd:u, UDP) ------------------------------------------------

    fn key(fd: i32) -> u64 {
        socket_key(1, fd)
    }

    pub fn socket(&mut self, fd: i32) {
        assert!(self.router.on_socket(Self::key(fd), 2, SOCK_DGRAM, 0));
    }

    /// bind(INADDR_ANY, port).
    pub fn bind(&mut self, fd: i32, port: u16) {
        let d = self.router.on_bind(Self::key(fd), &SockAddrIn::from_ryujinx(0, port), false);
        assert_eq!(d, Decision::ReplyAndForward(0));
    }

    /// sendto; returns what the game sees (bytes sent or -errno).
    pub fn sendto(&mut self, relay: &mut Relay, fd: i32, data: &[u8], ip: u32, port: u16) -> i32 {
        let dest = SockAddrIn::from_ryujinx(ip, port);
        match self.router.on_sendto(Self::key(fd), data, Some(&dest)) {
            Decision::Emit { header, payload } => {
                let mut msg = header.as_bytes().to_vec();
                msg.extend_from_slice(payload);
                if self.tx(relay, PacketId::ProxyData, &msg) { payload.len() as i32 } else { -101 }
            }
            Decision::Reply(r) => r,
            d => panic!("unexpected {d:?}"),
        }
    }

    /// Non-blocking recvfrom: the datagram and its sender, or None.
    pub fn recvfrom(&mut self, fd: i32) -> Option<(Vec<u8>, SockAddrIn)> {
        let mut buf = [0u8; 2000];
        match self.router.on_recvfrom(Self::key(fd), &mut buf, MSG_DONTWAIT) {
            RecvDecision::Data { len, from } => Some((buf[..len].to_vec(), from)),
            RecvDecision::Reply(-11) => None,
            d => panic!("unexpected {d:?}"),
        }
    }
}
