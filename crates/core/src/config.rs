//! `config.ini` parser and serializer (port of `sysmodule/source/config/config.cpp`).
//!
//! Semantics kept from the C++: `;`/`#` comments, unknown sections and keys ignored, a bad
//! value leaves the default (or the previous value), over-long strings are truncated to the
//! C++ maximum lengths, UTF-8 BOM skipped. Dropped for ldn-tunnel: passphrase, use_passphrase,
//! disable_p2p, transport (WSS only), ping_interval, `[perf]`.
use core::fmt::{self, Write};
use heapless::String;

use crate::SliceWriter;
use crate::ident;
use crate::notify::NotifyConfig;

pub const MAX_HOST_LENGTH: usize = 128;
pub const MAX_PATH_LENGTH: usize = 64;
pub const TOKEN_LENGTH: usize = 64;
pub const MAX_CA_FILE_LENGTH: usize = 128;
/// C++ line buffer is 512 bytes (511 kept).
const MAX_LINE: usize = 511;
/// HidNpadButton_ZR.
pub const DEFAULT_REAL_WIRELESS_BUTTON: u64 = 1 << 9;

/// Update channel; discriminants match the wire value (`UpdateCheckRequest.channel`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    Off = 0,
    Stable = 1,
    Test = 2,
}

impl Channel {
    const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Stable => "stable",
            Self::Test => "test",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Server {
    pub host: String<MAX_HOST_LENGTH>,
    pub port: u16,
    pub path: String<MAX_PATH_LENGTH>,
    /// Secret: empty or exactly 64 lowercase hex characters. Never log it.
    pub token: String<TOKEN_LENGTH>,
    pub ca_file: String<MAX_CA_FILE_LENGTH>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ldn {
    pub enabled: bool,
    /// HidNpadButton mask held at launch for real Local Wireless (0 = none).
    pub real_wireless_button: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Debug {
    pub enabled: bool,
    pub level: u32,
    /// Key `remote_log`: also send log lines to the relay.
    pub remote: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub channel: Channel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub server: Server,
    pub ldn: Ldn,
    pub debug: Debug,
    pub update: Update,
    pub notifications: NotifyConfig,
}

// The token must never reach a log through `{:?}`.
impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("path", &self.path)
            .field("token", &if self.token.is_empty() { "<unset>" } else { "<redacted>" })
            .field("ca_file", &self.ca_file)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut ca_file = String::new();
        // Fits: CONFIG_DIR + "/ca.pem" is far below 128 bytes.
        let _ = write!(ca_file, "{}/ca.pem", ident::CONFIG_DIR);
        let mut path = String::new();
        let _ = path.push_str("/ldn");
        Self {
            server: Server { host: String::new(), port: 443, path, token: String::new(), ca_file },
            ldn: Ldn { enabled: true, real_wireless_button: DEFAULT_REAL_WIRELESS_BUTTON },
            debug: Debug { enabled: false, level: 1, remote: false },
            update: Update { channel: Channel::Stable },
            notifications: NotifyConfig::default(),
        }
    }
}

const BUTTONS: [(&str, u64); 16] = [
    ("A", 1 << 0),
    ("B", 1 << 1),
    ("X", 1 << 2),
    ("Y", 1 << 3),
    ("L", 1 << 6),
    ("R", 1 << 7),
    ("ZL", 1 << 8),
    ("ZR", 1 << 9),
    ("PLUS", 1 << 10),
    ("MINUS", 1 << 11),
    ("LSTICK", 1 << 4),
    ("RSTICK", 1 << 5),
    ("DLEFT", 1 << 12),
    ("DUP", 1 << 13),
    ("DRIGHT", 1 << 14),
    ("DDOWN", 1 << 15),
];

fn button_bit(name: &str) -> Option<u64> {
    BUTTONS.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|&(_, b)| b)
}

/// `none` or names joined with `+`; any unknown name rejects the whole value.
fn parse_buttons(value: &str) -> Option<u64> {
    let v = value.trim_matches([' ', '\t']);
    if v.eq_ignore_ascii_case("none") {
        return Some(0);
    }
    let mut mask = 0;
    for part in v.split('+') {
        mask |= button_bit(part.trim_matches([' ', '\t']))?;
    }
    Some(mask)
}

fn parse_bool(value: &str) -> Option<bool> {
    if value == "1" || value.eq_ignore_ascii_case("true") {
        Some(true)
    } else if value == "0" || value.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

/// Truncating copy (on a char boundary), like the C++ `safe_strcpy`.
fn set_str<const N: usize>(dst: &mut String<N>, src: &str) {
    dst.clear();
    for c in src.chars() {
        if dst.push(c).is_err() {
            break;
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Section {
    None,
    Server,
    Ldn,
    Debug,
    Update,
    Notifications,
    Unknown,
}

impl Config {
    /// Applies `data` on top of `self` (start from `Config::default()`). Returns how many
    /// values were rejected (the overlay may show the count); rejected values change nothing.
    pub fn parse(&mut self, data: &[u8]) -> u32 {
        let data = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
        let mut bad = 0u32;
        let mut section = Section::None;
        for raw in data.split(|&b| b == b'\n' || b == b'\r') {
            let raw = raw.get(..MAX_LINE).unwrap_or(raw);
            let Ok(line) = core::str::from_utf8(raw) else { continue };
            let line = line.trim_matches([' ', '\t']);
            if line.is_empty() || line.starts_with([';', '#']) {
                continue;
            }
            if line.starts_with('[') {
                section = match line {
                    "[server]" => Section::Server,
                    "[ldn]" => Section::Ldn,
                    "[debug]" => Section::Debug,
                    "[update]" => Section::Update,
                    "[notifications]" => Section::Notifications,
                    _ => Section::Unknown,
                };
                continue;
            }
            let Some((key, value)) = line.split_once('=') else { continue };
            let (key, value) = (key.trim_matches([' ', '\t']), value.trim_matches([' ', '\t']));
            if !self.apply(section, key, value) {
                bad = bad.saturating_add(1);
            }
        }
        bad
    }

    /// false = known key with an invalid value.
    fn apply(&mut self, section: Section, key: &str, value: &str) -> bool {
        match (section, key) {
            (Section::Server, "host") => set_str(&mut self.server.host, value),
            (Section::Server, "port") => match value.parse() {
                Ok(p) => self.server.port = p,
                Err(_) => return false,
            },
            (Section::Server, "path") => set_str(&mut self.server.path, value),
            (Section::Server, "token") => {
                self.server.token.clear();
                if value.len() != TOKEN_LENGTH || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return value.is_empty();
                }
                for c in value.chars() {
                    let _ = self.server.token.push(c.to_ascii_lowercase());
                }
            }
            (Section::Server, "ca_file") => set_str(&mut self.server.ca_file, value),
            (Section::Ldn, "enabled") => return parse_bool(value).map(|v| self.ldn.enabled = v).is_some(),
            (Section::Ldn, "real_wireless_button") => {
                return parse_buttons(value).map(|v| self.ldn.real_wireless_button = v).is_some();
            }
            (Section::Debug, "enabled") => return parse_bool(value).map(|v| self.debug.enabled = v).is_some(),
            (Section::Debug, "level") => match value.parse() {
                Ok(l) => self.debug.level = l,
                Err(_) => return false,
            },
            (Section::Debug, "remote_log") => return parse_bool(value).map(|v| self.debug.remote = v).is_some(),
            (Section::Update, "channel") => {
                self.update.channel = if value.eq_ignore_ascii_case("stable") {
                    Channel::Stable
                } else if value.eq_ignore_ascii_case("test") {
                    Channel::Test
                } else if value.eq_ignore_ascii_case("off") {
                    Channel::Off
                } else {
                    return false;
                };
            }
            (Section::Notifications, "updates") => {
                return parse_bool(value).map(|v| self.notifications.updates = v).is_some();
            }
            (Section::Notifications, "game_start") => {
                return parse_bool(value).map(|v| self.notifications.game_start = v).is_some();
            }
            (Section::Notifications, "connection") => {
                return parse_bool(value).map(|v| self.notifications.connection = v).is_some();
            }
            _ => {}
        }
        true
    }

    /// Re-emits the whole file with comments into `out`. Returns the length, or 0 if `out`
    /// is too small (the caller must not save a truncated file). Contains the token.
    pub fn write_to(&self, out: &mut [u8]) -> usize {
        let mut w = SliceWriter { buf: out, pos: 0 };
        self.emit(&mut w).map_or(0, |()| w.pos)
    }

    fn emit(&self, w: &mut SliceWriter<'_>) -> fmt::Result {
        let s = &self.server;
        write!(
            w,
            "; {name} config. Contains your secret relay token: never share or post this file.\n\
             ; Lines starting with ; or # are comments. Saving settings from the overlay rewrites\n\
             ; this file. Related files live in {dir}/:\n\
             ; gamelist.txt (games routed through the relay), ca.pem (relay certificate roots).\n\
             \n\
             [server]\n\
             ; Your relay's address (your Cloudflare Worker). Empty = never connect.\n\
             host = {host}\n\
             ; Relay port (443 = encrypted web traffic).\n\
             port = {port}\n\
             ; Address on the relay that Switches connect to: wss://<host><path>.\n\
             path = {path}\n\
             ; Secret per-console token: 64 hex characters, issued by your relay.\n\
             token = {token}\n\
             ; Certificates used to check that the relay is really yours before the token is sent.\n\
             ca_file = {ca}\n\
             \n\
             [ldn]\n\
             ; 1 = games' Local Wireless goes through the relay; 0 = real Local Wireless only.\n\
             enabled = {ldn}\n\
             ; Button(s) held while launching a game to use real Local Wireless for that game.\n\
             ; Names: A B X Y L R ZL ZR PLUS MINUS LSTICK RSTICK DLEFT DUP DRIGHT DDOWN;\n\
             ; combine with +, e.g. ZL+ZR; or none. Avoid L and R (Atmosphere reads them at launch).\n\
             real_wireless_button = ",
            name = ident::NAME,
            dir = ident::CONFIG_DIR,
            host = s.host,
            port = s.port,
            path = s.path,
            token = s.token,
            ca = s.ca_file,
            ldn = u8::from(self.ldn.enabled),
        )?;
        let mut first = true;
        for (name, bit) in BUTTONS {
            if self.ldn.real_wireless_button & bit != 0 {
                write!(w, "{}{name}", if first { "" } else { "+" })?;
                first = false;
            }
        }
        if first {
            w.write_str("none")?;
        }
        write!(
            w,
            "\n\n[debug]\n\
             ; 1 = write a log to {log}.\n\
             enabled = {den}\n\
             ; 0 errors, 1 warnings, 2 normal activity, 3 everything.\n\
             level = {lvl}\n\
             ; 1 = also send log lines to the relay (for testing).\n\
             remote_log = {rem}\n\
             \n\
             [update]\n\
             ; Releases this Switch installs by itself: stable, test or off.\n\
             channel = {ch}\n\
             \n\
             [notifications]\n\
             ; Short messages shown by Ultrahand while a game runs (1 = on, 0 = off).\n\
             ; Update ready / updated.\n\
             updates = {nu}\n\
             ; Online play on or off when a game starts local wireless.\n\
             game_start = {ng}\n\
             ; Connected / connection lost / reconnected during a game.\n\
             connection = {nc}\n",
            log = ident::LOG_PATH,
            den = u8::from(self.debug.enabled),
            lvl = self.debug.level,
            rem = u8::from(self.debug.remote),
            ch = self.update.channel.name(),
            nu = u8::from(self.notifications.updates),
            ng = u8::from(self.notifications.game_start),
            nc = u8::from(self.notifications.connection),
        )
    }
}


#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    extern crate std;
    use super::*;
    use std::{format, vec::Vec};

    const TOKEN: &str = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef";

    fn parse(s: &str) -> (Config, u32) {
        let mut c = Config::default();
        let bad = c.parse(s.as_bytes());
        (c, bad)
    }

    #[test]
    fn defaults() {
        let c = Config::default();
        assert_eq!(c.server.port, 443);
        assert_eq!(c.server.path.as_str(), "/ldn");
        assert_eq!(c.server.ca_file.as_str(), "sdmc:/config/ldn-tunnel/ca.pem");
        assert!(c.ldn.enabled && c.ldn.real_wireless_button == 1 << 9);
        assert!(!c.debug.enabled && c.debug.level == 1 && !c.debug.remote);
        assert_eq!(c.update.channel, Channel::Stable);
        assert_eq!(c.notifications, NotifyConfig::default());
    }

    #[test]
    fn parses_keys_and_ignores_junk() {
        let text = format!(
            "\u{feff}; c\r\n# c\r\n[server]\r\n host = r.example.workers.dev \r\nport=8443\ntoken = {TOKEN}\nbogus=1\n\
             [ldn]\nenabled = FALSE\nreal_wireless_button = zl + zr\n[nope]\nhost=x\n\
             [debug]\nenabled=true\nlevel=3\nremote_log=1\n[update]\nchannel = Test\nline without equals\n\
             [notifications]\nupdates=0\ngame_start = true\nconnection=FALSE\n"
        );
        let (c, bad) = parse(&text);
        assert_eq!(bad, 0);
        assert_eq!(c.server.host.as_str(), "r.example.workers.dev");
        assert_eq!(c.server.port, 8443);
        assert_eq!(c.server.token.as_str(), TOKEN.to_ascii_lowercase());
        assert!(!c.ldn.enabled);
        assert_eq!(c.ldn.real_wireless_button, (1 << 8) | (1 << 9));
        assert!(c.debug.enabled && c.debug.remote && c.debug.level == 3);
        assert_eq!(c.update.channel, Channel::Test);
        assert_eq!(c.notifications, NotifyConfig { updates: false, game_start: true, connection: false });
    }

    #[test]
    fn bad_values_keep_defaults() {
        let (c, bad) = parse(
            "[server]\nport=99999\ntoken=short\n[ldn]\nenabled=maybe\nreal_wireless_button=ZR+Q\n\
             [debug]\nlevel=x\n[update]\nchannel=beta\n[notifications]\nupdates=2\n",
        );
        assert_eq!(bad, 7);
        assert_eq!(c, Config::default());
        // Keys outside any section are ignored.
        assert_eq!(parse("enabled=0\n").0, Config::default());
    }

    #[test]
    fn long_strings_truncate() {
        let long = "h".repeat(300);
        let (c, _) = parse(&format!("[server]\nhost={long}\npath={long}\nca_file={long}\n"));
        assert_eq!(c.server.host.len(), MAX_HOST_LENGTH);
        assert_eq!(c.server.path.len(), MAX_PATH_LENGTH);
        assert_eq!(c.server.ca_file.len(), MAX_CA_FILE_LENGTH);
    }

    #[test]
    fn roundtrip_and_small_buffer() {
        let mut c = Config::default();
        c.server.host.push_str("a.b.c").unwrap();
        c.server.token.push_str(&TOKEN.to_ascii_lowercase()).unwrap();
        c.ldn.real_wireless_button = 0;
        c.debug.level = 2;
        c.update.channel = Channel::Off;
        c.notifications.game_start = false;
        let mut buf = [0u8; 4096];
        let n = c.write_to(&mut buf);
        assert!(n > 0);
        let (back, bad) = parse(core::str::from_utf8(&buf[..n]).unwrap());
        assert_eq!(bad, 0);
        assert_eq!(back, c);
        assert_eq!(c.write_to(&mut buf[..n - 1]), 0);
        assert!(!format!("{c:?}").contains(&TOKEN.to_ascii_lowercase()));
    }

    #[test]
    fn dist_template_is_the_default_serialization() {
        let mut c = Config::default();
        c.server.host.push_str("<your-relay>.workers.dev").unwrap();
        let mut buf = [0u8; 4096];
        let n = c.write_to(&mut buf);
        // UPDATE_DIST=1 cargo test regenerates the template.
        if std::env::var_os("UPDATE_DIST").is_some() {
            std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/../../dist/config.ini"), &buf[..n]).unwrap();
        }
        let want = include_str!("../../../dist/config.ini");
        assert_eq!(core::str::from_utf8(&buf[..n]).unwrap(), want);
        let (back, _) = parse(want);
        assert_eq!(back, c);
    }

    #[test]
    fn random_input_does_not_panic() {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let alphabet = b"[]=;# \t\r\n\xEF\xBB\xBFserverldnhostportlevel01";
        for round in 0..2000 {
            let len = (next() % 700) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| if round % 2 == 0 { next() as u8 } else { alphabet[(next() as usize) % alphabet.len()] })
                .collect();
            let mut c = Config::default();
            c.parse(&bytes);
            let mut out = [0u8; 4096];
            let _ = c.write_to(&mut out);
        }
    }
}
