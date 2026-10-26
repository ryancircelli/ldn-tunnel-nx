//! A tiny fake relay: relay.ts's packet sequences for the scenarios in `sim.rs`, at the frame level
//! (no sockets). One `link` per transport connection, like one WebSocket each.
use ldn_tunnel_core::conn::handshake;
use ldn_tunnel_core::ldn_types::scan_filter_flag;
use ldn_tunnel_core::protocol::{HEADER_SIZE, encode_header};
use ldn_tunnel_core::wire::*;
use ldn_tunnel_core::ws::{OPCODE_BINARY, apply_mask, encode_header as ws_header};
use zerocopy::{FromBytes, FromZeros, IntoBytes};

pub const NETWORK_BASE: u32 = 0x0A72_0000;
pub const NETWORK_MASK: u32 = 0xFFFF_0000;
pub const BROADCAST: u32 = 0x0A72_FFFF;
pub const TOKEN: &str = "tok";

/// One LDN packet the relay received.
#[derive(Clone, Debug)]
pub struct Rx {
    pub link: usize,
    pub type_: u8,
    pub payload: Vec<u8>,
}

#[derive(Default)]
struct Peer {
    open: bool,
    upgraded: bool,
    init: bool,
    sid: [u8; 16],
    mac: [u8; 6],
    ip: u32,
    game: Option<usize>,
    out: Vec<u8>,
}

struct Game {
    info: NetworkInfo,
    owner: usize,
    players: Vec<usize>,
    closed: bool,
    /// dhcp.ts: the next address to hand out, and the ones taken.
    next_ip: u32,
    taken: Vec<u32>,
}

impl Game {
    /// dhcp.ts requestIp: `next` cycles through the /16 (skipping .0.0 and the broadcast), so a
    /// freed address is not handed out again until the cycle comes round.
    fn request_ip(&mut self) -> u32 {
        let cycle = |n: u32| {
            let mut n = n;
            loop {
                n = NETWORK_BASE | ((n + 1) & !NETWORK_MASK);
                if n != NETWORK_BASE && n != BROADCAST {
                    return n;
                }
            }
        };
        while self.taken.contains(&self.next_ip) {
            self.next_ip = cycle(self.next_ip);
        }
        let ip = self.next_ip;
        self.taken.push(ip);
        self.next_ip = cycle(ip);
        ip
    }
}

#[derive(Default)]
pub struct Relay {
    /// Every packet received, in order.
    pub log: Vec<Rx>,
    /// Answer the next Connect with this NetworkError instead of the real logic.
    pub force_connect_error: Option<NetworkErrorCode>,
    peers: Vec<Peer>,
    games: Vec<Game>,
}

fn frame(type_: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; HEADER_SIZE + payload.len()];
    encode_header(&mut p, type_, payload.len() as i32);
    p[HEADER_SIZE..].copy_from_slice(payload);
    let (h, n) = ws_header(OPCODE_BINARY, p.len(), None);
    let mut f = h[..n].to_vec();
    f.extend_from_slice(&p);
    f
}

impl Relay {
    pub fn game_count(&self) -> usize {
        self.games.iter().filter(|g| !g.closed || !g.players.is_empty()).count()
    }

    pub fn packets(&self, link: usize) -> Vec<&Rx> {
        self.log.iter().filter(|r| r.link == link).collect()
    }

    /// A new transport connection.
    pub fn connect(&mut self) -> usize {
        self.peers.push(Peer { open: true, ..Peer::default() });
        self.peers.len() - 1
    }

    /// Bytes the relay wants to write to `link`.
    pub fn take(&mut self, link: usize) -> Vec<u8> {
        core::mem::take(&mut self.peers[link].out)
    }

    /// The transport died (or the console closed it).
    pub fn close(&mut self, link: usize) {
        if !self.peers[link].open {
            return;
        }
        self.disconnect_from_game(link);
        self.peers[link].open = false;
    }

    /// The relay's idle ping (relay.ts `alarm`): requester 0, echoed by the console.
    pub fn ping(&mut self, link: usize, id: u8) {
        self.send(link, PacketId::Ping.raw(), &[0, id]);
    }

    fn send(&mut self, link: usize, type_: u8, payload: &[u8]) {
        if self.peers[link].open {
            self.peers[link].out.extend(frame(type_, payload));
        }
    }

    fn error(&mut self, link: usize, code: NetworkErrorCode) {
        self.send(link, PacketId::NetworkError.raw(), &(code.raw()).to_le_bytes());
    }

    /// Bytes from the console: the upgrade request first, then masked client frames.
    pub fn rx(&mut self, link: usize, mut b: &[u8]) {
        if !self.peers[link].open {
            return;
        }
        if !self.peers[link].upgraded {
            let resp = accept(b);
            self.peers[link].out.extend(resp);
            self.peers[link].upgraded = true;
            return;
        }
        while !b.is_empty() {
            assert_eq!(b[0] & 0x80, 0x80, "FIN");
            assert_eq!(b[1] & 0x80, 0x80, "client frames are masked");
            let (len, mut at) = match b[1] & 0x7F {
                126 => (u16::from_be_bytes([b[2], b[3]]) as usize, 4),
                127 => (u64::from_be_bytes(b[2..10].try_into().unwrap()) as usize, 10),
                n => (n as usize, 2),
            };
            let mask: [u8; 4] = b[at..at + 4].try_into().unwrap();
            at += 4;
            let mut p = b[at..at + len].to_vec();
            apply_mask(&mut p, &mask);
            let opcode = b[0] & 0x0F;
            b = &b[at + len..];
            if opcode != OPCODE_BINARY {
                continue; // pong / close: nothing to do
            }
            assert_eq!(&p[..4], b"RLDN", "magic");
            assert_eq!(p[5], 1, "version");
            let n = i32::from_le_bytes(p[8..12].try_into().unwrap()) as usize;
            assert_eq!(p.len(), HEADER_SIZE + n, "dataSize == message length - 12");
            let payload = p[HEADER_SIZE..].to_vec();
            self.log.push(Rx { link, type_: p[4], payload: payload.clone() });
            self.handle(link, p[4], &payload);
        }
    }

    fn handle(&mut self, link: usize, type_: u8, payload: &[u8]) {
        let Some(id) = PacketId::from_raw(type_) else { return };
        let (init, in_game) = (self.peers[link].init, self.peers[link].game.is_some());
        match id {
            PacketId::Initialize if !init => {
                let Ok((m, _)) = InitializeMessage::read_from_prefix(payload) else { return };
                let _ = m;
                let p = &mut self.peers[link];
                p.sid = [0x40 + link as u8; 16];
                p.mac = [2, 0, 0x5E, 0, 0, 1 + link as u8];
                p.init = true;
                let reply = InitializeMessage { id: SessionId { data: p.sid }, mac_address: MacAddress { data: p.mac } };
                self.send(link, PacketId::Initialize.raw(), reply.as_bytes());
            }
            PacketId::CreateAccessPoint => {
                let Ok((r, adv)) = CreateAccessPointRequest::read_from_prefix(payload) else { return };
                if in_game || !init {
                    return self.error(link, NetworkErrorCode::Unknown);
                }
                self.create(link, &r, adv);
            }
            PacketId::Connect => {
                let Ok((r, _)) = ConnectRequest::read_from_prefix(payload) else { return };
                if let Some(code) = self.force_connect_error.take() {
                    return self.error(link, code);
                }
                self.connect_to(link, &r);
            }
            PacketId::Scan => self.scan(link, payload),
            PacketId::Disconnect if payload.len() >= 4 => self.disconnect_from_game(link),
            PacketId::ProxyData if in_game => self.route(link, payload),
            _ => {} // Passphrase, Ping, DebugLog, ...
        }
    }

    fn create(&mut self, link: usize, r: &CreateAccessPointRequest, adv: &[u8]) {
        let nc = r.network_config;
        let mut info = NetworkInfo::new_zeroed();
        info.network_id.intent_id.local_communication_id = nc.intent_id.local_communication_id;
        info.network_id.intent_id.scene_id = nc.intent_id.scene_id;
        info.network_id.session_id = SessionId { data: [0xA0 + self.games.len() as u8; 16] };
        info.common.channel = nc.channel;
        info.common.link_level = 3;
        info.common.network_type = 2;
        info.common.mac_address = MacAddress { data: self.peers[link].mac };
        info.common.ssid.length = 32;
        info.common.ssid.name[..32].copy_from_slice(b"12345678123456781234567812345678");
        info.ldn.security_mode = r.security_config.security_mode;
        info.ldn.node_count_max = nc.node_count_max;
        info.ldn.advertise_data_size = adv.len() as u16;
        info.ldn.advertise_data[..adv.len()].copy_from_slice(adv);
        let mut me = NodeInfo::new_zeroed();
        me.mac_address = MacAddress { data: self.peers[link].mac };
        me.is_connected = 1;
        me.user_name = r.user_config.user_name;
        me.local_communication_version = nc.local_communication_version;
        self.games.push(Game { info, owner: link, players: vec![], closed: false, next_ip: NETWORK_BASE + 1, taken: vec![] });
        let g = self.games.len() - 1;
        self.join(link, g, me);
    }

    fn connect_to(&mut self, link: usize, r: &ConnectRequest) {
        let want = r.network_info.network_id.session_id;
        let Some(g) = self.games.iter().position(|g| !g.closed && g.info.network_id.session_id == want) else {
            return self.error(link, NetworkErrorCode::ConnectNotFound);
        };
        let nodes = self.games[g].info.ldn.nodes;
        let host_version = nodes[0].local_communication_version;
        let version = r.local_communication_version;
        if version > u32::from(host_version) {
            return self.error(link, NetworkErrorCode::VersionTooHigh);
        }
        if version < u32::from(host_version) {
            return self.error(link, NetworkErrorCode::VersionTooLow);
        }
        let mut node = NodeInfo::new_zeroed();
        node.mac_address = MacAddress { data: self.peers[link].mac };
        node.is_connected = 1;
        node.user_name = r.user_config.user_name;
        node.local_communication_version = version as u16;
        if !self.join(link, g, node) {
            self.error(link, NetworkErrorCode::TooManyPlayers);
        }
    }

    /// HostedGame.Connect: ProxyConfig to the joiner, SyncNetwork to the others, Connected to the joiner.
    fn join(&mut self, link: usize, g: usize, mut node: NodeInfo) -> bool {
        let ldn = self.games[g].info.ldn;
        let Some(node_id) = ldn.nodes.iter().position(|n| n.is_connected == 0) else { return false };
        if self.games[g].closed || ldn.node_count == ldn.node_count_max {
            return false;
        }
        let ip = self.games[g].request_ip();
        self.peers[link].ip = ip;
        let cfg = ProxyConfig { proxy_ip: ip, proxy_subnet_mask: NETWORK_MASK };
        self.send(link, PacketId::ProxyConfig.raw(), cfg.as_bytes());
        node.ipv4_address = ip;
        node.node_id = node_id as u8;
        let game = &mut self.games[g];
        game.info.ldn.node_count += 1;
        game.info.ldn.nodes[node_id] = node;
        self.sync(g);
        self.games[g].players.push(link);
        self.peers[link].game = Some(g);
        let info = self.games[g].info;
        self.send(link, PacketId::Connected.raw(), info.as_bytes());
        true
    }

    fn sync(&mut self, g: usize) {
        let (info, players) = (self.games[g].info, self.games[g].players.clone());
        for p in players {
            self.send(p, PacketId::SyncNetwork.raw(), info.as_bytes());
        }
    }

    fn scan(&mut self, link: usize, payload: &[u8]) {
        let Ok((f, _)) = ScanFilterFull::read_from_prefix(payload) else { return };
        let mut hits = vec![];
        for (i, g) in self.games.iter().enumerate() {
            let have = g.info.network_id.intent_id;
            let want = f.network_id.intent_id;
            let flag = f.flag;
            if g.closed || g.players.is_empty() || self.peers[link].game == Some(i) {
                continue;
            }
            if flag & scan_filter_flag::LOCAL_COMMUNICATION_ID != 0
                && have.local_communication_id != want.local_communication_id
            {
                continue;
            }
            if flag & scan_filter_flag::SCENE_ID != 0 && have.scene_id != want.scene_id {
                continue;
            }
            if flag & scan_filter_flag::SESSION_ID != 0 && g.info.network_id.session_id != f.network_id.session_id {
                continue;
            }
            if flag & scan_filter_flag::NETWORK_TYPE != 0 && u32::from(g.info.common.network_type) != f.network_type & 0xFF {
                continue;
            }
            hits.push(g.info);
        }
        for info in hits {
            self.send(link, PacketId::ScanReply.raw(), info.as_bytes());
        }
        self.send(link, PacketId::ScanReplyEnd.raw(), &[]);
    }

    /// LdnSession.DisconnectFromGame: leave, and a host leaving closes the game.
    fn disconnect_from_game(&mut self, link: usize) {
        let Some(g) = self.peers[link].game.take() else { return };
        let ip = self.peers[link].ip;
        self.games[g].players.retain(|&p| p != link);
        self.games[g].taken.retain(|&t| t != ip);
        let ldn = &mut self.games[g].info.ldn;
        // every slot, as relay.ts leave() does since the ghost-node fix
        for n in ldn.nodes.iter_mut().filter(|n| n.is_connected != 0 && n.ipv4_address == ip) {
            ldn.node_count -= 1;
            n.is_connected = 0;
        }
        self.sync(g);
        if self.games[g].owner == link && !self.games[g].closed {
            self.games[g].closed = true;
            for p in self.games[g].players.clone() {
                self.send(p, PacketId::Disconnect.raw(), &[0; 4]);
            }
        }
    }

    /// HostedGame.RouteMessage (unicast and broadcast; a broadcast includes the sender).
    fn route(&mut self, link: usize, payload: &[u8]) {
        let Ok((mut h, _)) = ProxyDataHeader::read_from_prefix(payload) else { return };
        let ip = self.peers[link].ip;
        if h.info.source_ipv4 == 0 {
            h.info.source_ipv4 = ip;
        } else if h.info.source_ipv4 != ip {
            return;
        }
        let mut msg = payload.to_vec();
        msg[..20].copy_from_slice(h.as_bytes());
        let dest = h.info.dest_ipv4;
        let g = self.peers[link].game.unwrap();
        for p in self.games[g].players.clone() {
            if dest == BROADCAST || self.peers[p].ip == dest {
                self.send(p, PacketId::ProxyData.raw(), &msg);
            }
        }
    }
}

/// Check the upgrade request line by line and answer 101.
fn accept(req: &[u8]) -> Vec<u8> {
    let text = core::str::from_utf8(req).unwrap();
    let lines: Vec<&str> = text.split("\r\n").collect();
    assert!(lines[0].starts_with("GET /") && lines[0].ends_with(" HTTP/1.1"));
    assert!(lines.contains(&"Upgrade: websocket"));
    assert!(lines.contains(&"Connection: Upgrade"));
    assert!(lines.contains(&"Sec-WebSocket-Version: 13"));
    assert!(lines.contains(&format!("Authorization: Bearer {TOKEN}").as_str()));
    let key = lines.iter().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap();
    let accept = handshake::compute_accept(key.as_bytes().try_into().unwrap());
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        core::str::from_utf8(&accept).unwrap()
    )
    .into_bytes()
}
