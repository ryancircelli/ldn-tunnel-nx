//! Overlay state and the dashboard's logic: init/version/dirty (was app/overlay_state.hpp),
//! saving (app/config_actions.hpp, auto_save_controller.hpp, save_backoff.hpp), the rows the
//! dashboard polls, and the module restart sequence. Side effects go through [`Os`]: libnx on the
//! console (src/ffi.rs + overlay/source/platform.c), a fake in the tests.

use core::ffi::c_char;
use core::fmt::Write as _;

use heapless::String;
use ldn_tunnel_core::cfg_types::{
    ConnectionStatus, NOTIFY_CONNECTION, NOTIFY_GAME_START, NOTIFY_UPDATES, RC_BUSY,
    SETUP_NEEDS_RESTART, SETUP_ROLLED_BACK,
};

use crate::cfg::{self, Dispatch, Rc};
use crate::text::{self, Color, GREEN, GREY, ORANGE, WHITE};

/// MAKERESULT(Module_Libnx, LibnxError_NotInitialized): no ldnt:cfg session.
pub const RC_NOT_OPEN: Rc = 345 | (8 << 9);

/// What the overlay asks of the system. `dispatch` is only called with a session open.
pub trait Os: Dispatch {
    /// Open ldnt:cfg without blocking (sm is asked first); 0 or why not.
    fn cfg_open(&mut self) -> Rc;
    fn cfg_close(&mut self);
    /// ldnt:cfg is registered in sm.
    fn cfg_registered(&mut self) -> bool;
    /// Has an IP address (or nifm is unavailable).
    fn online(&mut self) -> bool;
    /// Pid of the running application (game), asked of pm.
    fn app_pid(&mut self) -> Option<u64>;
    fn program_id(&mut self, pid: u64) -> Option<u64>;
    /// gamelist.txt lists the program.
    fn in_game_list(&mut self, program_id: u64) -> bool;
    fn module_running(&mut self) -> bool;
    /// pm:shell TerminateProcess: what HOME > Close does.
    fn terminate_process(&mut self, pid: u64) -> Rc;
    fn terminate_module(&mut self);
    fn launch_module(&mut self) -> Rc;
    /// Monotonic milliseconds.
    fn now_ms(&mut self) -> u64;
    /// Local time as "%b %d, %H:%M" into `out`; the length, 0 when it cannot.
    fn local_time(&mut self, unix: u32, out: &mut [u8]) -> usize;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum LdntInit {
    Uninit,
    Error,
    Loaded,
}

/// Banner the dashboard shows first (setup only a restart finishes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum LdntBanner {
    None,
    /// "Restart once more to finish setup": reboots the console.
    Reboot,
    /// "Update failed: restart to undo it": restarts the module.
    UndoUpdate,
}

/// A notification toggle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum LdntNotify {
    Updates,
    GameStart,
    Connection,
}

impl LdntNotify {
    pub const fn bit(self) -> u32 {
        match self {
            Self::Updates => NOTIFY_UPDATES,
            Self::GameStart => NOTIFY_GAME_START,
            Self::Connection => NOTIFY_CONNECTION,
        }
    }
}

/// One MiniListItem value. `set` false: leave the row as it is.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct LdntRow {
    pub set: bool,
    /// NUL-terminated.
    pub text: [c_char; 32],
    /// RGB888 hex, empty: keep the color.
    pub color: [c_char; 8],
}

impl LdntRow {
    pub const EMPTY: Self = Self {
        set: false,
        text: [0; 32],
        color: [0; 8],
    };

    pub fn put(&mut self, text: &str, color: &str) {
        self.set = true;
        copy_c(&mut self.text, text.as_bytes());
        copy_c(&mut self.color, color.as_bytes());
    }

    #[cfg(test)]
    pub fn text(&self) -> std::string::String {
        let b: std::vec::Vec<u8> = self
            .text
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        std::string::String::from_utf8(b).unwrap_or_default()
    }
}

/// What the dashboard shows; filled by [`Dashboard`], applied by MainDashboardGui.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct LdntDashView {
    pub relay: LdntRow,
    pub game: LdntRow,
    pub players: LdntRow,
    pub ldn_state: LdntRow,
    pub update: LdntRow,
    pub built: LdntRow,
    /// The restart row that was pressed last (0 banner, 1 Updates section).
    pub restart_slot: u8,
    pub restart: LdntRow,
    pub subtitle: [c_char; 128],
}

impl LdntDashView {
    pub const EMPTY: Self = Self {
        relay: LdntRow::EMPTY,
        game: LdntRow::EMPTY,
        players: LdntRow::EMPTY,
        ldn_state: LdntRow::EMPTY,
        update: LdntRow::EMPTY,
        built: LdntRow::EMPTY,
        restart_slot: 0,
        restart: LdntRow::EMPTY,
        subtitle: [0; 128],
    };
}

/// `ldnt_dash_update` result bits.
pub const LDNT_DASH_SWAP: u32 = 1 << 0;
pub const LDNT_DASH_ROWS: u32 = 1 << 1;
pub const LDNT_DASH_RESTART: u32 = 1 << 2;

/// NUL-terminated copy of `s` for constants: a string that does not fit fails the build.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub const fn c_name<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    assert!(b.len() < N);
    let mut out = [0u8; N];
    let mut i = 0;
    while i < b.len() {
        out[i] = b[i];
        i += 1;
    }
    out
}

/// Copies as much of `src` as fits and NUL-terminates.
pub fn copy_c(dst: &mut [c_char], src: &[u8]) {
    let n = src.len().min(dst.len().saturating_sub(1));
    for (d, &s) in dst.iter_mut().zip(src.iter().take(n)) {
        *d = s as c_char;
    }
    if let Some(end) = dst.get_mut(n) {
        *end = 0;
    }
}

/// Overlay-wide state (one per overlay run).
pub struct App {
    pub init: LdntInit,
    /// NUL-terminated module version for the frame headers.
    pub version: [u8; 32],
    /// [`text::short_version`] of `version`, NUL-terminated.
    pub short_version: [u8; 17],
    dirty: bool,
    open: bool,
}

impl App {
    #[allow(clippy::new_without_default)] // const, for the static in src/ffi.rs
    pub const fn new() -> Self {
        Self {
            init: LdntInit::Uninit,
            version: c_name("Unknown"),
            short_version: c_name("Unknown"),
            dirty: false,
            open: false,
        }
    }

    fn set_version(&mut self, v: &[u8]) {
        let v = text::c_str(v);
        let n = v.len().min(31);
        self.version = [0; 32];
        if let (Some(d), Some(s)) = (self.version.get_mut(..n), v.get(..n)) {
            d.copy_from_slice(s);
        }
        let short = text::short_version(&self.version);
        self.short_version = [0; 17];
        if let Some(d) = self.short_version.get_mut(..short.len()) {
            d.copy_from_slice(short.as_bytes());
        }
    }

    /// `os` when the ldnt:cfg session is open.
    pub fn cfg<'a, O: Os>(&self, os: &'a mut O) -> Result<&'a mut O, Rc> {
        if self.open { Ok(os) } else { Err(RC_NOT_OPEN) }
    }

    fn open<O: Os>(&mut self, os: &mut O) -> bool {
        if !self.open {
            self.open = os.cfg_open() == 0;
        }
        self.open
    }

    fn close<O: Os>(&mut self, os: &mut O) {
        if self.open {
            os.cfg_close();
            self.open = false;
        }
    }

    /// Overlay start: open ldnt:cfg and read the module version.
    pub fn init<O: Os>(&mut self, os: &mut O) {
        self.init = LdntInit::Uninit;
        if !self.open(os) {
            self.init = LdntInit::Error;
            return;
        }
        match cfg::version(os) {
            Ok(v) => self.set_version(&v),
            Err(_) => self.set_version(b"Unknown"),
        }
        self.init = LdntInit::Loaded;
    }

    /// Overlay exit: closing must not lose changes.
    pub fn exit<O: Os>(&mut self, os: &mut O) {
        if self.init == LdntInit::Loaded {
            self.save_if_dirty(os);
            self.close(os);
        }
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    /// After a setter succeeded: SaveConfig persists it.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn save<O: Os>(&mut self, os: &mut O) -> bool {
        if self.init != LdntInit::Loaded {
            return false;
        }
        let saved = self.cfg(os).and_then(cfg::save_config) == Ok(true);
        if saved {
            self.dirty = false;
        }
        saved
    }

    pub fn reload<O: Os>(&mut self, os: &mut O) -> bool {
        self.init == LdntInit::Loaded && self.cfg(os).and_then(cfg::reload_config) == Ok(true)
    }

    /// Exit / leaving a page.
    pub fn save_if_dirty<O: Os>(&mut self, os: &mut O) -> bool {
        !self.dirty || self.save(os)
    }

    pub fn banner<O: Os>(&self, os: &mut O) -> LdntBanner {
        let setup = self.cfg(os).and_then(cfg::setup_status).unwrap_or(0);
        if setup & SETUP_NEEDS_RESTART != 0 {
            LdntBanner::Reboot
        } else if setup & SETUP_ROLLED_BACK != 0 {
            LdntBanner::UndoUpdate
        } else {
            LdntBanner::None
        }
    }

    pub fn notify_flags<O: Os>(&self, os: &mut O) -> Result<u32, Rc> {
        self.cfg(os).and_then(cfg::notify_flags)
    }

    /// Notification toggle: read, change one bit, write; dirty on success.
    pub fn set_notify<O: Os>(&mut self, os: &mut O, which: LdntNotify, on: bool) -> bool {
        let Ok(cur) = self.notify_flags(os) else {
            return false;
        };
        let flags = if on {
            cur | which.bit()
        } else {
            cur & !which.bit()
        };
        let ok = self
            .cfg(os)
            .and_then(|d| cfg::set_notify_flags(d, flags))
            .is_ok();
        if ok {
            self.mark_dirty();
        }
        ok
    }

    /// Advanced settings: relay host, green while connected.
    pub fn server_row<O: Os>(&self, os: &mut O, row: &mut LdntRow) {
        row.set = false;
        if self.init != LdntInit::Loaded {
            return;
        }
        let Ok(addr) = self.cfg(os).and_then(cfg::server_address) else {
            return;
        };
        let status = self.cfg(os).and_then(cfg::connection_status);
        let connected = matches!(status, Ok(s) if s == ConnectionStatus::Connected as u32 || s == ConnectionStatus::Ready as u32);
        row.put(
            &text::server_host(&addr.host),
            if connected { GREEN } else { GREY },
        );
    }

    fn is_game_active<O: Os>(&self, os: &mut O) -> bool {
        self.cfg(os).and_then(cfg::is_game_active).unwrap_or(false)
    }
}

/// Frame-based auto-save: a save DELAY_FRAMES frames into continuous dirty state; ~10 s
/// back-off after a failed one so a broken SD card is not hit every second; "Saved!" for ~2 s.
pub struct AutoSave {
    wait: u32,
    backoff: u32,
    confirm: u32,
}

impl AutoSave {
    #[allow(clippy::new_without_default)] // const, for the static in src/ffi.rs
    pub const fn new() -> Self {
        Self {
            wait: 0,
            backoff: 0,
            confirm: 0,
        }
    }

    pub(crate) const DELAY_FRAMES: u32 = 60;
    pub(crate) const FAIL_BACKOFF_FRAMES: u32 = 600;
    pub(crate) const CONFIRM_FRAMES: u32 = 120;

    fn due(&mut self, dirty: bool) -> bool {
        if !dirty {
            self.wait = 0;
            self.backoff = 0;
            return false;
        }
        if self.backoff > 0 {
            self.backoff = self.backoff.saturating_sub(1);
            return false;
        }
        self.wait = self.wait.saturating_add(1);
        if self.wait >= Self::DELAY_FRAMES {
            self.wait = 0;
            return true;
        }
        false
    }

    /// Once per frame.
    pub fn update<O: Os>(&mut self, app: &mut App, os: &mut O) {
        // Skip mid-session auto-save while a game uses LDN; the exit and page-leave saves still
        // run. IPC only when a save is actually due.
        if self.due(app.dirty()) && !app.is_game_active(os) {
            if app.save(os) {
                self.confirm = Self::CONFIRM_FRAMES;
            } else {
                self.backoff = Self::FAIL_BACKOFF_FRAMES;
            }
        }
        self.confirm = self.confirm.saturating_sub(1);
    }

    pub fn indicator(&self, dirty: bool) -> &'static str {
        if self.confirm > 0 {
            "Saved!"
        } else if dirty {
            "\u{26A0} Unsaved changes"
        } else {
            ""
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    ClosingGame,
    Releasing,
    Stopping,
    Connecting,
}

/// Hot restart of the module (e.g. after an update was staged on the SD card), as
/// ovl-sysmodules does: stop it and launch it again through pm:shell; also starts it when it
/// isn't running. A running game holds ldn:u/bsd:u sessions through our MITM, so it is closed
/// first. Two presses; the first says when the second closes the game.
pub struct Restart {
    phase: Phase,
    deadline: u64,
    slot: u8,
    armed: [bool; 2],
    warned: [bool; 2],
}

/// The text a step leaves on the pressed row.
type Text = String<32>;

fn txt(s: &str) -> Option<Text> {
    let mut t = Text::new();
    let _ = t.push_str(s);
    Some(t)
}

fn txt_rc(s: &str, rc: Rc) -> Option<Text> {
    let mut t = Text::new();
    let _ = write!(t, "{s} (0x{rc:X})");
    Some(t)
}

enum Step {
    None,
    Text(Text),
    Swap,
}

impl Restart {
    const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            deadline: 0,
            slot: 1,
            armed: [false; 2],
            warned: [false; 2],
        }
    }

    fn finish(&mut self, text: &str) -> Option<Text> {
        self.phase = Phase::Idle;
        txt(text)
    }

    fn wait<O: Os>(&mut self, os: &mut O, phase: Phase, ms: u64) {
        self.phase = phase;
        self.deadline = os.now_ms().saturating_add(ms);
    }

    /// A on a restart row (`slot` 0 or 1): the text for that row, if it changes.
    fn press<O: Os>(&mut self, app: &mut App, os: &mut O, slot: u8) -> Option<Text> {
        let i = usize::from(slot.min(1));
        if self.phase != Phase::Idle {
            return None;
        }
        let game = os.app_pid().is_some();
        // A game that started in between re-arms with the warning.
        let (Some(armed), Some(warned)) = (self.armed.get_mut(i), self.warned.get_mut(i)) else {
            return None;
        };
        if !*armed || (game && !*warned) {
            *armed = true;
            *warned = game;
            return txt(if game {
                "Closes the game!"
            } else {
                "Press A again"
            });
        }
        *armed = false;
        self.slot = slot.min(1);
        if game && let Some(pid) = os.app_pid() {
            // What HOME > Close does: unsaved progress is lost.
            if os.terminate_process(pid) != 0 {
                return self.finish("Can't close game");
            }
            self.wait(os, Phase::ClosingGame, 5000);
            return txt("Closing game...");
        }
        self.stop_module(app, os, true)
    }

    /// Stop the module ([`Self::step`] launches it again). None only when the module is busy and
    /// this isn't the last try.
    fn stop_module<O: Os>(&mut self, app: &mut App, os: &mut O, last_try: bool) -> Option<Text> {
        if os.module_running() {
            // sm never drops a dead process's MITMs (the next bsd:u open would abort sm), so the
            // module unregisters them itself before pm may kill it.
            app.save_if_dirty(os);
            match app.cfg(os).and_then(cfg::prepare_restart) {
                Ok(()) => {}
                Err(RC_BUSY) if !last_try => return None,
                Err(RC_BUSY) => return self.finish("Still in use"),
                Err(rc) => {
                    self.phase = Phase::Idle;
                    return txt_rc("Can't restart", rc);
                }
            }
        } else if os.cfg_registered() {
            // Died after registering: its stale MITMs are still in sm.
            return self.finish("Restart the Switch");
        }
        // Our ldnt:cfg session dies with the module: let go of it.
        app.close(os);
        app.init = LdntInit::Error;
        os.terminate_module(); // fails if not running: fine
        self.wait(os, Phase::Stopping, 3000);
        txt("Restarting...")
    }

    /// Once per frame (`frame`: the dashboard's poll counter).
    fn step<O: Os>(&mut self, app: &mut App, os: &mut O, frame: u32) -> Step {
        let late = os.now_ms() > self.deadline;
        let text = match self.phase {
            Phase::Idle => None,
            Phase::ClosingGame => {
                if os.app_pid().is_some() {
                    if late {
                        self.finish("Game didn't close")
                    } else {
                        None
                    }
                } else {
                    self.wait(os, Phase::Releasing, 3000);
                    None
                }
            }
            // The module lets go of the closed game's sessions a moment after it exits; until
            // then PrepareRestart says busy. ~4 tries a second.
            Phase::Releasing if frame.is_multiple_of(15) => self.stop_module(app, os, late),
            Phase::Releasing => None,
            // pm refuses to launch a program it still tracks: wait for the exit.
            Phase::Stopping if os.module_running() => {
                if late {
                    self.finish("Didn't stop")
                } else {
                    None
                }
            }
            Phase::Stopping => match os.launch_module() {
                0 => {
                    self.wait(os, Phase::Connecting, 10000);
                    None
                }
                rc => {
                    self.phase = Phase::Idle;
                    txt_rc("Start failed", rc)
                }
            },
            // ldnt:cfg shows up 1-3 s after launch; opening asks sm first, so a try never
            // blocks. ~4 tries a second.
            Phase::Connecting if !frame.is_multiple_of(15) => None,
            Phase::Connecting => {
                if app.open(os) {
                    if let Ok(v) = cfg::version(os) {
                        app.set_version(&v);
                        app.init = LdntInit::Loaded;
                        self.phase = Phase::Idle;
                        return Step::Swap; // restart done: the overlay closes
                    }
                    app.close(os);
                }
                if late {
                    self.finish("Not responding")
                } else {
                    None
                }
            }
        };
        text.map_or(Step::None, Step::Text)
    }
}

/// State of one MainDashboardGui.
pub struct Dashboard {
    frame: u32,
    status: u32,
    relay: &'static str,
    info: String<16>,
    game_program_id: u64,
    game_supported: bool,
    autosave: AutoSave,
    restart: Restart,
}

/// Poll the module every POLL_FRAMES (~0.5 s): each ldnt:cfg call is a round trip.
const POLL_FRAMES: u32 = 30;

impl Dashboard {
    #[allow(clippy::new_without_default)] // const, for the static in src/ffi.rs
    pub const fn new() -> Self {
        Self {
            frame: 0,
            status: ConnectionStatus::Disconnected as u32,
            relay: "Not running",
            info: String::new(),
            game_program_id: 0,
            game_supported: false,
            autosave: AutoSave::new(),
            restart: Restart::new(),
        }
    }

    pub fn press<O: Os>(
        &mut self,
        app: &mut App,
        os: &mut O,
        slot: u8,
        view: &mut LdntDashView,
    ) -> bool {
        let Some(t) = self.restart.press(app, os, slot) else {
            return false;
        };
        view.restart_slot = slot.min(1);
        view.restart.put(&t, "");
        true
    }

    /// Once per frame: `LDNT_DASH_*` bits. After SWAP the C++ replaces the dashboard.
    pub fn update<O: Os>(
        &mut self,
        app: &mut App,
        os: &mut O,
        view: &mut LdntDashView,
        ldn_row: bool,
    ) -> u32 {
        let mut out = 0;
        match self.restart.step(app, os, self.frame) {
            Step::Swap => return LDNT_DASH_SWAP,
            Step::Text(t) => {
                view.restart_slot = self.restart.slot;
                view.restart.put(&t, "");
                out |= LDNT_DASH_RESTART;
            }
            Step::None => {}
        }
        let poll = self.frame.is_multiple_of(POLL_FRAMES);
        self.frame = self.frame.wrapping_add(1);
        if poll && self.refresh(app, os, view, ldn_row) {
            out |= LDNT_DASH_ROWS;
        }
        self.autosave.update(app, os);
        let sub = text::subtitle(self.relay, self.autosave.indicator(app.dirty()), &self.info);
        copy_c(&mut view.subtitle, sub.as_bytes());
        out
    }

    /// Re-read every row (also on R). False when there is nothing to show.
    pub fn refresh<O: Os>(
        &mut self,
        app: &App,
        os: &mut O,
        view: &mut LdntDashView,
        ldn_row: bool,
    ) -> bool {
        for row in [
            &mut view.relay,
            &mut view.game,
            &mut view.players,
            &mut view.ldn_state,
            &mut view.update,
            &mut view.built,
        ] {
            row.set = false;
        }
        if app.init != LdntInit::Loaded || app.cfg(os).is_err() {
            return false;
        }
        if let Ok(s) = app.cfg(os).and_then(cfg::connection_status) {
            self.status = s;
        }
        // Failure reason while the link is down; never contains the token.
        let transport = app
            .cfg(os)
            .and_then(cfg::transport_status)
            .unwrap_or([0; 64]);
        // No IP: games fall back to real local wireless (nifm is best effort).
        let online = os.online();
        let (relay, color) = text::relay(self.status, &transport, online);
        self.relay = relay;
        view.relay.put(relay, color);

        if ldn_row && let Ok(s) = app.cfg(os).and_then(cfg::ldn_state) {
            let (t, c) = text::ldn_state(s);
            view.ldn_state.put(t, c);
        }

        // The module routes only games in gamelist.txt; pm answers even when the module can't.
        let mut game: (&str, Color) = ("None", GREY);
        if let Some(program_id) = os.app_pid().and_then(|pid| os.program_id(pid)) {
            if program_id != self.game_program_id {
                self.game_program_id = program_id;
                self.game_supported = os.in_game_list(program_id);
            }
            game = if app.is_game_active(os) {
                ("Online", GREEN)
            } else if self.game_supported {
                ("Supported", WHITE)
            } else {
                ("Not supported", ORANGE)
            };
        }
        view.game.put(game.0, game.1);

        let setup = app.cfg(os).and_then(cfg::setup_status).unwrap_or(0);
        if let Ok(up) = app.cfg(os).and_then(cfg::update_status) {
            let (t, c) = text::update(setup, &up);
            view.update.put(&t, c);
            // The build number is the build's Unix time.
            let mut when = [0u8; 24];
            let n = if up.running_build != 0 {
                os.local_time(up.running_build, &mut when)
            } else {
                0
            };
            match when.get(..n) {
                Some(w) if n > 0 => view.built.put(core::str::from_utf8(w).unwrap_or("?"), ""),
                _ => view.built.put("Developer build", ""),
            }
        }

        let players = app
            .cfg(os)
            .and_then(cfg::session_info)
            .ok()
            .and_then(|si| text::players(&si));
        view.players.put(players.as_deref().unwrap_or("--"), "");
        self.info = players.unwrap_or_default();
        true
    }
}
