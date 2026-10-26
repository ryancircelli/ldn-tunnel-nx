//! On-screen toasts shown by Ultrahand while a game runs with the overlay closed.
//!
//! Sans-IO: the shell feeds module events into [`Notifier::on_event`], calls
//! [`Notifier::poll`] from its loop (≤ 1 s period is plenty) and writes every
//! [`Toast`] it gets as an Ultrahand API notification file
//! ([`Toast::write_json`] into [`NOTIFY_DIR`]/[`file_name`]). See
//! `docs/notifications.md` for the mechanism and the verified Ultrahand sources.

use core::fmt::Write as _;

use heapless::String;

use crate::cfg_types::{NOTIFY_CONNECTION, NOTIFY_GAME_START, NOTIFY_UPDATES};
use crate::ident;

/// Ultrahand polls this directory every 300 ms for `*.notify` JSON files and
/// deletes each file after showing it (libultrahand ≥ 2.1.0).
pub const NOTIFY_DIR: &str = "sdmc:/config/ultrahand/notifications";
/// A relay state must hold this long before it is announced.
pub const STABLE_MS: u64 = 5_000;
/// Toast text capacity in bytes. Ultrahand draws a 448 px wide box with at most
/// 4 wrapped lines (~20–25 Latin glyphs a line at font 24); 64 bytes fits with
/// room to spare and keeps the version string intact.
pub const TEXT_MAX: usize = 64;
/// How long Ultrahand keeps the toast up (its own default; clamped 500..=30000).
pub const DURATION_MS: u32 = 4_000;

/// User-toggleable toast groups (`[notifications]` in config.ini).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Updates,
    GameStart,
    Connection,
}

/// `[notifications]` section of config.ini (`Config::notifications`): `updates`,
/// `game_start`, `connection`, all on by default. `bits`/`from_bits` use the
/// cfg IPC bitmask (`cfg_types::NOTIFY_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyConfig {
    pub updates: bool,
    pub game_start: bool,
    pub connection: bool,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self { updates: true, game_start: true, connection: true }
    }
}

impl NotifyConfig {
    pub const fn bits(self) -> u32 {
        (if self.updates { NOTIFY_UPDATES } else { 0 })
            | (if self.game_start { NOTIFY_GAME_START } else { 0 })
            | (if self.connection { NOTIFY_CONNECTION } else { 0 })
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self {
            updates: bits & NOTIFY_UPDATES != 0,
            game_start: bits & NOTIFY_GAME_START != 0,
            connection: bits & NOTIFY_CONNECTION != 0,
        }
    }

    const fn allows(self, cat: Category) -> bool {
        match cat {
            Category::Updates => self.updates,
            Category::GameStart => self.game_start,
            Category::Connection => self.connection,
        }
    }
}

/// What the module does for a whitelisted game that just opened ldn:u.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LdnMode {
    /// Local wireless goes over the relay.
    Online,
    /// ZR held at launch: real local wireless, module stays out.
    Bypass,
    /// LDN disabled in config.ini.
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// A verified update is staged and needs a restart.
    UpdateStaged,
    /// First boot on a new build (the shell compares against the last-run version).
    UpdatedTo(&'a str),
    /// A whitelisted game opened ldn:u (the shell only sends whitelisted titles).
    GameStarted { pid: u64, mode: LdnMode },
    /// The game process went away (ldn:u session closed / process exit).
    GameExited { pid: u64 },
    /// Relay link state as seen by the relay client.
    Relay { up: bool },
}

pub type Text = String<TEXT_MAX>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toast {
    pub category: Category,
    pub text: Text,
}

impl Toast {
    fn new(category: Category, parts: &[&str]) -> Self {
        let mut text = Text::new();
        // Truncate on a char boundary instead of failing on overflow.
        for c in parts.iter().flat_map(|p| p.chars()) {
            if text.push(c).is_err() {
                break;
            }
        }
        Self { category, text }
    }

    /// Ultrahand API notification JSON:
    /// `{"text":"…","title":"ldn-tunnel","duration":4000}`. Returns the byte
    /// length written, or `None` if `out` is too small (256 bytes always fits).
    pub fn write_json(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Buf { out, len: 0 };
        w.raw("{\"text\":\"")?;
        w.escaped(&self.text)?;
        w.raw("\",\"title\":\"")?;
        w.escaped(ident::NAME)?;
        w.raw("\",\"duration\":")?;
        let mut n = String::<10>::new();
        write!(n, "{DURATION_MS}").ok()?;
        w.raw(&n)?;
        w.raw("}")?;
        Some(w.len)
    }
}

struct Buf<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Buf<'_> {
    fn raw(&mut self, s: &str) -> Option<()> {
        let end = self.len.checked_add(s.len())?;
        self.out.get_mut(self.len..end)?.copy_from_slice(s.as_bytes());
        self.len = end;
        Some(())
    }

    fn escaped(&mut self, s: &str) -> Option<()> {
        for c in s.chars() {
            match c {
                '"' => self.raw("\\\"")?,
                '\\' => self.raw("\\\\")?,
                '\n' => self.raw("\\n")?,
                c if c.is_control() => {}
                c => self.raw(c.encode_utf8(&mut [0; 4]))?,
            }
        }
        Some(())
    }
}

/// File name for the `seq`-th toast: `<PROGRAM_ID_HEX>-<seq>.notify`. The part
/// before the first `-` is Ultrahand's app id (per-app mute flag
/// `flags/notifications/<id>.flag`, icon `assets/notifications/<id>.rgba`), so
/// it must not contain `-`; the program id hex never does.
pub fn file_name(seq: u32) -> String<40> {
    let mut s = String::new();
    // 16 + 1 + 10 + 7 bytes < 40: cannot fail.
    let _ = write!(s, "{}-{seq}.notify", ident::PROGRAM_ID_HEX);
    s
}

#[derive(Clone, Copy, Debug)]
struct Session {
    pid: u64,
    start_ms: u64,
    /// Last announced relay state in this session (`None`: nothing yet).
    announced: Option<bool>,
}

/// Turns module events into debounced, deduplicated toasts.
#[derive(Debug)]
pub struct Notifier {
    cfg: NotifyConfig,
    update: Option<Toast>,
    game: Option<Toast>,
    staged_done: bool,
    updated_done: bool,
    last_pid: Option<u64>,
    session: Option<Session>,
    relay_up: bool,
    relay_since: u64,
}

impl Notifier {
    pub const fn new(cfg: NotifyConfig) -> Self {
        Self {
            cfg,
            update: None,
            game: None,
            staged_done: false,
            updated_done: false,
            last_pid: None,
            session: None,
            relay_up: false,
            relay_since: 0,
        }
    }

    /// Takes effect at the next `poll`; pending toasts of a now-disabled
    /// category are dropped.
    pub fn set_config(&mut self, cfg: NotifyConfig) {
        self.cfg = cfg;
    }

    pub const fn config(&self) -> NotifyConfig {
        self.cfg
    }

    pub fn on_event(&mut self, event: Event<'_>, now_ms: u64) {
        match event {
            Event::UpdateStaged if !self.staged_done => {
                self.staged_done = true;
                self.update = Some(Toast::new(Category::Updates, &["Update ready - restart ldn-tunnel in the overlay"]));
            }
            Event::UpdatedTo(version) if !self.updated_done => {
                self.updated_done = true;
                self.update = Some(Toast::new(Category::Updates, &["Updated to ", version]));
            }
            Event::GameStarted { pid, mode } if self.last_pid != Some(pid) => {
                self.last_pid = Some(pid);
                let text = match mode {
                    LdnMode::Online => "Online play on",
                    LdnMode::Bypass => "Off (real wireless)",
                    LdnMode::Disabled => "Off (disabled)",
                };
                self.game = Some(Toast::new(Category::GameStart, &[text]));
                self.session = (mode == LdnMode::Online).then_some(Session { pid, start_ms: now_ms, announced: None });
            }
            Event::GameExited { pid } => {
                if self.session.is_some_and(|s| s.pid == pid) {
                    self.session = None;
                }
            }
            Event::Relay { up } if up != self.relay_up => {
                self.relay_up = up;
                self.relay_since = now_ms;
            }
            _ => {}
        }
    }

    /// Next toast to show, at most one per call. Call until `None` or once per tick.
    pub fn poll(&mut self, now_ms: u64) -> Option<Toast> {
        let cfg = self.cfg;
        for slot in [&mut self.update, &mut self.game] {
            if let Some(t) = slot.take().filter(|t| cfg.allows(t.category)) {
                return Some(t);
            }
        }
        let up = self.relay_up;
        let s = self.session.as_mut()?;
        // Measured from session start too, so "Connected" never lands on top of
        // the game-start toast.
        let stable_from = self.relay_since.max(s.start_ms);
        if now_ms.saturating_sub(stable_from) < STABLE_MS || s.announced == Some(up) {
            return None;
        }
        let text = match (s.announced, up) {
            (None, true) => "Connected",
            (Some(false), true) => "Reconnected",
            (Some(true), false) => "Connection lost",
            // Never connected in this session: nothing was lost.
            _ => return None,
        };
        s.announced = Some(up);
        cfg.connection.then(|| Toast::new(Category::Connection, &[text]))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::panic)]
mod tests {
    use super::*;

    fn drain(n: &mut Notifier, now: u64) -> heapless::Vec<Text, 8> {
        let mut v = heapless::Vec::new();
        while let Some(t) = n.poll(now) {
            v.push(t.text).unwrap();
        }
        v
    }

    fn texts(n: &mut Notifier, now: u64) -> heapless::Vec<&'static str, 8> {
        let mut out = heapless::Vec::new();
        for t in drain(n, now) {
            let s = [
                "Update ready - restart ldn-tunnel in the overlay",
                "Online play on",
                "Off (real wireless)",
                "Off (disabled)",
                "Connected",
                "Connection lost",
                "Reconnected",
            ]
            .into_iter()
            .find(|s| *s == t.as_str())
            .unwrap_or("other");
            out.push(s).unwrap();
        }
        out
    }

    fn online(pid: u64) -> Event<'static> {
        Event::GameStarted { pid, mode: LdnMode::Online }
    }

    #[test]
    fn updates_once_each() {
        let mut n = Notifier::new(NotifyConfig::default());
        n.on_event(Event::UpdatedTo("1.4.0"), 0);
        assert_eq!(drain(&mut n, 0).as_slice(), ["Updated to 1.4.0"]);
        n.on_event(Event::UpdatedTo("1.4.0"), 1);
        n.on_event(Event::UpdateStaged, 2);
        n.on_event(Event::UpdateStaged, 3);
        assert_eq!(texts(&mut n, 3).as_slice(), ["Update ready - restart ldn-tunnel in the overlay"]);
        assert!(n.poll(10_000).is_none());
    }

    #[test]
    fn long_version_truncates() {
        let mut n = Notifier::new(NotifyConfig::default());
        let v = "9.9.9-ééééééééééééééééééééééééééééééééééééééééééééééé";
        n.on_event(Event::UpdatedTo(v), 0);
        let t = n.poll(0).unwrap();
        assert!(t.text.len() <= TEXT_MAX && t.text.starts_with("Updated to 9.9.9-é"));
    }

    #[test]
    fn game_start_modes_and_pid_dedupe() {
        let mut n = Notifier::new(NotifyConfig::default());
        n.on_event(online(7), 0);
        n.on_event(online(7), 10); // the game reopens ldn:u
        assert_eq!(texts(&mut n, 10).as_slice(), ["Online play on"]);
        n.on_event(Event::GameStarted { pid: 8, mode: LdnMode::Bypass }, 20);
        assert_eq!(texts(&mut n, 20).as_slice(), ["Off (real wireless)"]);
        n.on_event(Event::GameStarted { pid: 9, mode: LdnMode::Disabled }, 30);
        assert_eq!(texts(&mut n, 30).as_slice(), ["Off (disabled)"]);
    }

    #[test]
    fn connection_needs_session_and_stability() {
        let mut n = Notifier::new(NotifyConfig::default());
        n.on_event(Event::Relay { up: true }, 0);
        assert!(drain(&mut n, 60_000).is_empty()); // no game: silent
        n.on_event(online(1), 60_000);
        assert_eq!(texts(&mut n, 60_000).as_slice(), ["Online play on"]);
        assert!(drain(&mut n, 64_999).is_empty()); // up since boot, but session is 4.999 s old
        assert_eq!(texts(&mut n, 65_000).as_slice(), ["Connected"]);
        n.on_event(Event::Relay { up: false }, 70_000);
        assert!(drain(&mut n, 74_999).is_empty());
        assert_eq!(texts(&mut n, 75_000).as_slice(), ["Connection lost"]);
        n.on_event(Event::Relay { up: true }, 80_000);
        n.on_event(Event::Relay { up: true }, 82_000); // repeat must not restart the timer
        assert_eq!(texts(&mut n, 85_000).as_slice(), ["Reconnected"]);
        n.on_event(Event::GameExited { pid: 1 }, 90_000);
        n.on_event(Event::Relay { up: false }, 90_000);
        assert!(drain(&mut n, 200_000).is_empty());
    }

    #[test]
    fn flap_collapses_to_nothing() {
        let mut n = Notifier::new(NotifyConfig::default());
        n.on_event(online(1), 0);
        n.on_event(Event::Relay { up: true }, 0);
        assert_eq!(texts(&mut n, 5_000).as_slice(), ["Online play on", "Connected"]);
        n.on_event(Event::Relay { up: false }, 10_000);
        assert!(drain(&mut n, 12_000).is_empty());
        n.on_event(Event::Relay { up: true }, 13_000);
        assert!(drain(&mut n, 60_000).is_empty());
    }

    #[test]
    fn down_before_first_connect_is_silent() {
        let mut n = Notifier::new(NotifyConfig::default());
        n.on_event(online(1), 0);
        drain(&mut n, 0);
        assert!(drain(&mut n, 60_000).is_empty());
        n.on_event(Event::Relay { up: true }, 60_000);
        assert_eq!(texts(&mut n, 65_000).as_slice(), ["Connected"]);
    }

    #[test]
    fn bypass_and_disabled_have_no_connection_toasts() {
        for mode in [LdnMode::Bypass, LdnMode::Disabled] {
            let mut n = Notifier::new(NotifyConfig::default());
            n.on_event(Event::GameStarted { pid: 1, mode }, 0);
            n.on_event(Event::Relay { up: true }, 0);
            assert_eq!(drain(&mut n, 60_000).len(), 1);
        }
    }

    #[test]
    fn toggles_filter_each_category() {
        let off = NotifyConfig { updates: false, game_start: false, connection: false };
        let mut n = Notifier::new(off);
        n.on_event(Event::UpdateStaged, 0);
        n.on_event(online(1), 0);
        n.on_event(Event::Relay { up: true }, 0);
        assert!(drain(&mut n, 10_000).is_empty());
        // Re-enabling does not replay old transitions.
        n.set_config(NotifyConfig::default());
        assert!(drain(&mut n, 20_000).is_empty());
        n.on_event(Event::Relay { up: false }, 20_000);
        assert_eq!(texts(&mut n, 25_000).as_slice(), ["Connection lost"]);

        let only_conn = NotifyConfig::from_bits(0b100);
        assert_eq!(only_conn, NotifyConfig { updates: false, game_start: false, connection: true });
        assert_eq!(only_conn.bits(), 0b100);
        assert_eq!(NotifyConfig::default().bits(), 0b111);
    }

    #[test]
    fn json_and_file_name() {
        let t = Toast::new(Category::Updates, &["a\"b\\c\nd\u{7}é"]);
        let mut buf = [0u8; 256];
        let n = t.write_json(&mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..n]).unwrap(),
            "{\"text\":\"a\\\"b\\\\c\\nd\u{e9}\",\"title\":\"ldn-tunnel\",\"duration\":4000}"
        );
        assert!(t.write_json(&mut buf[..20]).is_none());
        // Worst case: 64 quotes escape to 128 bytes, still fits 256.
        let worst = Toast::new(Category::Updates, &["\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""]);
        assert!(worst.write_json(&mut buf).is_some());
        let f = file_name(u32::MAX);
        assert_eq!(f.as_str(), "420000004C444E54-4294967295.notify");
        assert!(!ident::PROGRAM_ID_HEX.contains('-'));
    }

    /// Random event sequences: no panic, every event yields at most one toast,
    /// connection toasts are at least STABLE_MS apart and alternate sensibly.
    #[test]
    fn random_sequences() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..2_000 {
            let mut n = Notifier::new(NotifyConfig::from_bits(rnd() as u32));
            let mut now = rnd() % 1_000_000;
            let mut last_conn: Option<(u64, Text)> = None;
            for _ in 0..200 {
                now += rnd() % 8_000;
                let r = rnd();
                let mode = [LdnMode::Online, LdnMode::Bypass, LdnMode::Disabled][(r % 3) as usize];
                let ev = match (r >> 8) % 7 {
                    0 => Event::UpdateStaged,
                    1 => Event::UpdatedTo("2.0.0"),
                    2 => Event::GameStarted { pid: (r >> 16) % 4, mode },
                    3 => Event::GameExited { pid: (r >> 16) % 4 },
                    _ => Event::Relay { up: r & (1 << 30) != 0 },
                };
                if r & (0xF << 40) == 0 {
                    n.set_config(NotifyConfig::from_bits((r >> 20) as u32));
                    if let Some((_, prev)) = &mut last_conn {
                        prev.clear(); // transitions while muted were not shown
                    }
                }
                if let (Event::GameStarted { .. }, Some((_, prev))) = (ev, &mut last_conn) {
                    prev.clear(); // a new session may say "Connected" again
                }
                n.on_event(ev, now);
                let mut own = 0;
                while let Some(t) = n.poll(now) {
                    assert!(n.config().allows(t.category));
                    if t.category == Category::Connection {
                        if let Some((at, prev)) = &last_conn {
                            assert!(now - at >= STABLE_MS, "connection toasts too close");
                            assert_ne!(prev, &t.text);
                        }
                        last_conn = Some((now, t.text));
                    } else {
                        own += 1;
                    }
                }
                assert!(own <= 1, "one event produced {own} toasts");
            }
        }
    }
}
