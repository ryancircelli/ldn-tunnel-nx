//! The dashboard, saving and the restart sequence against a fake module and pm.

use std::string::String;
use std::vec::Vec;
use std::{format, vec};

use ldn_tunnel_core::cfg_types::*;
use zerocopy::{FromZeros, IntoBytes};

use crate::app::*;
use crate::cfg::{Dispatch, Rc};

const RC_FAIL: Rc = 0xBEEF;

struct Fake {
    now: u64,
    open_rc: Rc,
    registered: bool,
    online: bool,
    game: Option<u64>,
    listed: bool,
    module: bool,
    stubborn: bool,
    terminate_rc: Rc,
    launch_rc: Rc,
    /// PrepareRestart replies, front first; then 0.
    prepare: Vec<Rc>,
    save: u32,
    flags: u32,
    setup: u32,
    status: u32,
    transport: &'static [u8],
    update: UpdateStatusIpc,
    session: SessionInfoIpc,
    game_active: u32,
    /// GetVersion fails.
    no_version: bool,
    log: Vec<String>,
}

impl Fake {
    fn new() -> Self {
        Self {
            now: 1000,
            open_rc: 0,
            registered: true,
            online: true,
            game: None,
            listed: true,
            module: true,
            stubborn: false,
            terminate_rc: 0,
            launch_rc: 0,
            prepare: vec![],
            save: ConfigResult::Success as u32,
            flags: NOTIFY_UPDATES,
            setup: 0,
            status: 0,
            transport: b"",
            update: UpdateStatusIpc::new_zeroed(),
            session: SessionInfoIpc::default(),
            game_active: 0,
            no_version: false,
            log: vec![],
        }
    }

    fn take(&mut self) -> Vec<String> {
        core::mem::take(&mut self.log)
    }
}

fn put(out: &mut [u8], v: &[u8]) {
    out[..v.len()].copy_from_slice(v);
}

impl Dispatch for Fake {
    fn dispatch(&mut self, cmd: u32, input: &[u8], out: &mut [u8]) -> Rc {
        let arg = input
            .get(..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()));
        match arg {
            Some(v) => self.log.push(format!("cmd {cmd} {v:#x}")),
            None => self.log.push(format!("cmd {cmd}")),
        }
        match cmd {
            0 if self.no_version => return RC_FAIL,
            0 => put(out, b"v0.2.0-3-g1234567abc\0"),
            1 => put(out, &self.status.to_le_bytes()),
            3 => put(out, &self.game_active.to_le_bytes()),
            4 => put(out, &3u32.to_le_bytes()),
            5 => put(out, self.session.as_bytes()),
            13 => put(out, &self.save.to_le_bytes()),
            25 => put(out, self.transport),
            26 => put(out, self.update.as_bytes()),
            28 => put(out, &self.flags.to_le_bytes()),
            29 => self.flags = arg.unwrap(),
            30 => put(out, &self.setup.to_le_bytes()),
            31 => {
                let rc = if self.prepare.is_empty() {
                    0
                } else {
                    self.prepare.remove(0)
                };
                if rc == 0 {
                    self.registered = false;
                }
                return rc;
            }
            _ => {}
        }
        0
    }
}

impl Os for Fake {
    fn cfg_open(&mut self) -> Rc {
        self.log.push("open".into());
        if self.registered {
            self.open_rc
        } else {
            RC_FAIL
        }
    }
    fn cfg_close(&mut self) {
        self.log.push("close".into());
    }
    fn cfg_registered(&mut self) -> bool {
        self.registered
    }
    fn online(&mut self) -> bool {
        self.online
    }
    fn app_pid(&mut self) -> Option<u64> {
        self.game
    }
    fn program_id(&mut self, pid: u64) -> Option<u64> {
        Some(pid + 0x0100_0000_0000_0000)
    }
    fn in_game_list(&mut self, program_id: u64) -> bool {
        self.log.push(format!("gamelist {program_id:#x}"));
        self.listed
    }
    fn module_running(&mut self) -> bool {
        self.module
    }
    fn terminate_process(&mut self, pid: u64) -> Rc {
        self.log.push(format!("terminate_process {pid}"));
        self.terminate_rc
    }
    fn terminate_module(&mut self) {
        self.log.push("terminate_module".into());
        self.module = self.stubborn;
    }
    fn launch_module(&mut self) -> Rc {
        self.log.push("launch_module".into());
        if self.launch_rc == 0 {
            self.module = true;
            self.registered = true;
        }
        self.launch_rc
    }
    fn now_ms(&mut self) -> u64 {
        self.now
    }
    fn local_time(&mut self, unix: u32, out: &mut [u8]) -> usize {
        let s = format!("t{unix}");
        put(out, s.as_bytes());
        s.len()
    }
}

fn loaded() -> (App, Fake) {
    let mut app = App::new();
    let mut os = Fake::new();
    app.init(&mut os);
    os.take();
    (app, os)
}

fn c(s: &[core::ffi::c_char]) -> String {
    String::from_utf8(
        s.iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect(),
    )
    .unwrap()
}

#[test]
fn init() {
    let mut app = App::new();
    let mut os = Fake::new();
    os.registered = false;
    app.init(&mut os);
    assert_eq!(
        (app.init, &app.version[..8]),
        (LdntInit::Error, &b"Unknown\0"[..])
    );
    let (app, _) = loaded();
    assert_eq!(app.init, LdntInit::Loaded);
    assert_eq!(&app.version[..21], b"v0.2.0-3-g1234567abc\0");
    assert_eq!(&app.short_version, b"v0.2.0+1234567\0\0\0");
    let mut os = Fake::new();
    os.no_version = true;
    let mut app = App::new();
    app.init(&mut os);
    assert_eq!(
        (app.init, &app.version[..8]),
        (LdntInit::Loaded, &b"Unknown\0"[..])
    );
}

#[test]
fn save_and_exit() {
    let (mut app, mut os) = loaded();
    assert!(app.save_if_dirty(&mut os));
    assert!(os.take().is_empty(), "clean: no IPC");
    app.mark_dirty();
    os.save = ConfigResult::IoError as u32;
    assert!(!app.save_if_dirty(&mut os));
    assert!(app.dirty());
    os.take();
    os.save = 0;
    app.exit(&mut os);
    assert_eq!(os.take(), ["cmd 13", "close"]);
    assert!(!app.dirty());
}

#[test]
fn auto_save_waits_backs_off_and_confirms() {
    let (mut app, mut os) = loaded();
    let mut a = AutoSave::new();
    app.mark_dirty();
    os.save = ConfigResult::IoError as u32;
    for _ in 0..AutoSave::DELAY_FRAMES - 1 {
        a.update(&mut app, &mut os);
    }
    assert!(os.take().is_empty());
    assert_eq!(a.indicator(app.dirty()), "\u{26A0} Unsaved changes");
    a.update(&mut app, &mut os);
    assert_eq!(os.take(), ["cmd 3", "cmd 13"], "game check, then the save");
    // failed: no attempt for FAIL_BACKOFF_FRAMES + DELAY_FRAMES
    for _ in 0..AutoSave::FAIL_BACKOFF_FRAMES + AutoSave::DELAY_FRAMES - 1 {
        a.update(&mut app, &mut os);
    }
    assert!(os.take().is_empty());
    // a game in a session: skipped, no save
    os.game_active = 1;
    a.update(&mut app, &mut os);
    assert_eq!(os.take(), ["cmd 3"]);
    os.game_active = 0;
    os.save = 0;
    for _ in 0..AutoSave::DELAY_FRAMES {
        a.update(&mut app, &mut os);
    }
    assert_eq!(os.take(), ["cmd 3", "cmd 13"]);
    assert_eq!(a.indicator(app.dirty()), "Saved!");
    for _ in 0..AutoSave::CONFIRM_FRAMES {
        a.update(&mut app, &mut os);
    }
    assert_eq!(a.indicator(app.dirty()), "");
}

#[test]
fn notifications() {
    let (mut app, mut os) = loaded();
    assert!(app.set_notify(&mut os, LdntNotify::Connection, true));
    assert_eq!(os.flags, NOTIFY_UPDATES | NOTIFY_CONNECTION);
    assert!(app.set_notify(&mut os, LdntNotify::Updates, false));
    assert_eq!(os.flags, NOTIFY_CONNECTION);
    assert!(app.dirty());
    assert_eq!(os.take(), ["cmd 28", "cmd 29 0x5", "cmd 28", "cmd 29 0x4"]);
}

#[test]
fn banner() {
    let (app, mut os) = loaded();
    assert_eq!(app.banner(&mut os), LdntBanner::None);
    os.setup = SETUP_ROLLED_BACK | SETUP_NEW_BUILD;
    assert_eq!(app.banner(&mut os), LdntBanner::UndoUpdate);
    os.setup |= SETUP_NEEDS_RESTART;
    assert_eq!(app.banner(&mut os), LdntBanner::Reboot);
}

#[test]
fn dashboard_rows() {
    let (mut app, mut os) = loaded();
    let mut d = Dashboard::new();
    let mut v = LdntDashView::EMPTY;
    os.status = ConnectionStatus::Connecting as u32;
    os.transport = b"DNS failed\0";
    os.game = Some(7);
    os.update.channel = 1;
    os.update.running_build = 1_761_400_000;
    os.session = SessionInfoIpc {
        node_count: 2,
        max_nodes: 8,
        local_node_id: 0,
        is_host: 1,
        reserved: [0; 4],
    };
    assert_eq!(d.update(&mut app, &mut os, &mut v, true), LDNT_DASH_ROWS);
    assert_eq!(
        (v.relay.text(), c(&v.relay.color)),
        ("Relay not found".into(), "FF4444".into())
    );
    assert_eq!(v.ldn_state.text(), "AP Created");
    assert_eq!(
        (v.game.text(), c(&v.game.color)),
        ("Supported".into(), "FFFFFF".into())
    );
    assert_eq!(v.update.text(), "Up to date");
    assert_eq!(v.built.text(), "t1761400000");
    assert_eq!(v.players.text(), "2/8 (host)");
    assert_eq!(c(&v.subtitle), "\u{25CF} Relay not found | 2/8 (host)");
    assert_eq!(
        os.take(),
        [
            "cmd 1",
            "cmd 25",
            "cmd 4",
            "gamelist 0x100000000000007",
            "cmd 3",
            "cmd 30",
            "cmd 26",
            "cmd 5"
        ]
    );
    // polls every 30 frames; the gamelist is read once per game
    for _ in 1..30 {
        assert_eq!(d.update(&mut app, &mut os, &mut v, false), 0);
    }
    assert!(os.take().is_empty());
    os.game_active = 1;
    os.update.running_build = 0;
    os.session.node_count = 0;
    assert_eq!(d.update(&mut app, &mut os, &mut v, false), LDNT_DASH_ROWS);
    assert!(!v.ldn_state.set);
    assert_eq!(v.game.text(), "Online");
    assert_eq!(v.built.text(), "Developer build");
    assert_eq!(v.players.text(), "--");
    assert_eq!(c(&v.subtitle), "\u{25CF} Relay not found");
    assert!(!os.take().iter().any(|l| l.starts_with("gamelist")));
    // not loaded: nothing
    app.init = LdntInit::Error;
    assert!(!d.refresh(&app, &mut os, &mut v, true));
    assert!(!v.relay.set);
}

/// Steps until the restart row changes or the dashboard swaps; the frame count is the timeout.
fn run(
    d: &mut Dashboard,
    app: &mut App,
    os: &mut Fake,
    v: &mut LdntDashView,
    frames: u32,
) -> Option<String> {
    for _ in 0..frames {
        os.now += 16;
        let r = d.update(app, os, v, false);
        if r & LDNT_DASH_SWAP != 0 {
            return Some("SWAP".into());
        }
        if r & LDNT_DASH_RESTART != 0 {
            return Some(v.restart.text());
        }
    }
    None
}

fn press(
    d: &mut Dashboard,
    app: &mut App,
    os: &mut Fake,
    v: &mut LdntDashView,
    slot: u8,
) -> Option<String> {
    d.press(app, os, slot, v).then(|| v.restart.text())
}

#[test]
fn restart_without_game() {
    let (mut app, mut os) = loaded();
    let (mut d, mut v) = (Dashboard::new(), LdntDashView::EMPTY);
    app.mark_dirty();
    assert_eq!(
        press(&mut d, &mut app, &mut os, &mut v, 1).as_deref(),
        Some("Press A again")
    );
    assert!(os.take().is_empty());
    assert_eq!(
        press(&mut d, &mut app, &mut os, &mut v, 1).as_deref(),
        Some("Restarting...")
    );
    assert_eq!(v.restart_slot, 1);
    assert_eq!(
        os.take(),
        ["cmd 13", "cmd 31", "close", "terminate_module"],
        "saved first"
    );
    assert_eq!(app.init, LdntInit::Error);
    // a press while it runs does nothing
    assert_eq!(press(&mut d, &mut app, &mut os, &mut v, 0), None);
    assert_eq!(
        run(&mut d, &mut app, &mut os, &mut v, 2000).as_deref(),
        Some("SWAP")
    );
    let log = os.take();
    assert_eq!(log[0], "launch_module");
    assert_eq!(&log[log.len() - 2..], ["open", "cmd 0"]);
    assert_eq!(app.init, LdntInit::Loaded);
    assert_eq!(&app.short_version[..15], b"v0.2.0+1234567\0");
}

#[test]
fn restart_closes_the_game_first() {
    let (mut app, mut os) = loaded();
    let (mut d, mut v) = (Dashboard::new(), LdntDashView::EMPTY);
    assert_eq!(
        press(&mut d, &mut app, &mut os, &mut v, 0).as_deref(),
        Some("Press A again")
    );
    // a game started in between: re-armed with the warning
    os.game = Some(9);
    assert_eq!(
        press(&mut d, &mut app, &mut os, &mut v, 0).as_deref(),
        Some("Closes the game!")
    );
    assert_eq!(
        press(&mut d, &mut app, &mut os, &mut v, 0).as_deref(),
        Some("Closing game...")
    );
    assert_eq!(os.take(), ["terminate_process 9"]);
    assert_eq!(run(&mut d, &mut app, &mut os, &mut v, 30), None);
    os.game = None;
    // the module still holds the closed game's sessions for a moment
    os.prepare = vec![RC_BUSY, RC_BUSY];
    assert_eq!(
        run(&mut d, &mut app, &mut os, &mut v, 60).as_deref(),
        Some("Restarting...")
    );
    assert_eq!(v.restart_slot, 0);
    assert_eq!(
        os.take().iter().filter(|l| *l == "cmd 31").count(),
        3,
        "retried at frame % 15"
    );
    assert_eq!(
        run(&mut d, &mut app, &mut os, &mut v, 2000).as_deref(),
        Some("SWAP")
    );
}

#[test]
fn restart_failures() {
    let fresh = || {
        let (app, os) = loaded();
        (app, os, Dashboard::new(), LdntDashView::EMPTY)
    };
    let twice = |d: &mut Dashboard, app: &mut App, os: &mut Fake, v: &mut LdntDashView| {
        press(d, app, os, v, 1);
        press(d, app, os, v, 1)
    };

    let (mut app, mut os, mut d, mut v) = fresh();
    os.game = Some(9);
    os.terminate_rc = RC_FAIL;
    assert_eq!(
        twice(&mut d, &mut app, &mut os, &mut v).as_deref(),
        Some("Can't close game")
    );

    let (mut app, mut os, mut d, mut v) = fresh();
    os.game = Some(9);
    twice(&mut d, &mut app, &mut os, &mut v);
    assert_eq!(
        run(&mut d, &mut app, &mut os, &mut v, 400).as_deref(),
        Some("Game didn't close")
    );

    // busy past the 3 s deadline
    let (mut app, mut os, mut d, mut v) = fresh();
    os.game = Some(9);
    twice(&mut d, &mut app, &mut os, &mut v);
    os.game = None;
    os.prepare = vec![RC_BUSY; 1000];
    assert_eq!(
        run(&mut d, &mut app, &mut os, &mut v, 400).as_deref(),
        Some("Still in use")
    );

    let (mut app, mut os, mut d, mut v) = fresh();
    os.prepare = vec![0x1234];
    assert_eq!(
        twice(&mut d, &mut app, &mut os, &mut v).as_deref(),
        Some("Can't restart (0x1234)")
    );
    assert_eq!(
        app.init,
        LdntInit::Loaded,
        "still talking to the old module"
    );

    let (mut app, mut os, mut d, mut v) = fresh();
    os.module = false; // crashed after registering
    assert_eq!(
        twice(&mut d, &mut app, &mut os, &mut v).as_deref(),
        Some("Restart the Switch")
    );

    let (mut app, mut os, mut d, mut v) = fresh();
    os.stubborn = true;
    twice(&mut d, &mut app, &mut os, &mut v);
    assert_eq!(
        run(&mut d, &mut app, &mut os, &mut v, 400).as_deref(),
        Some("Didn't stop")
    );

    let (mut app, mut os, mut d, mut v) = fresh();
    os.launch_rc = 0x2a8;
    twice(&mut d, &mut app, &mut os, &mut v);
    assert_eq!(
        run(&mut d, &mut app, &mut os, &mut v, 10).as_deref(),
        Some("Start failed (0x2A8)")
    );

    let (mut app, mut os, mut d, mut v) = fresh();
    os.open_rc = RC_FAIL;
    twice(&mut d, &mut app, &mut os, &mut v);
    assert_eq!(
        run(&mut d, &mut app, &mut os, &mut v, 1000).as_deref(),
        Some("Not responding")
    );

    // not running and not registered: just start it (no PrepareRestart, no session)
    let mut app = App::new();
    let mut os = Fake::new();
    os.registered = false;
    os.module = false;
    app.init(&mut os);
    os.take();
    let (mut d, mut v) = (Dashboard::new(), LdntDashView::EMPTY);
    assert_eq!(
        twice(&mut d, &mut app, &mut os, &mut v).as_deref(),
        Some("Restarting...")
    );
    assert_eq!(os.take(), ["terminate_module"]);
    os.registered = true;
    assert_eq!(
        run(&mut d, &mut app, &mut os, &mut v, 100).as_deref(),
        Some("SWAP")
    );
}
