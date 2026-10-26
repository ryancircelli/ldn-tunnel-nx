//! The C ABI: `ldnt_*` (called by the C++ screens, declared in include/ldn_tunnel_overlay.h)
//! and the `ldnt_os_*` libnx shims it calls (overlay/source/platform.c, which includes the
//! header, so the C compiler checks those definitions against the declarations below).
#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};

use ldn_tunnel_core::ident::{CFG_SERVICE, GAMELIST_PATH, PROGRAM_ID_HEX};
use ldn_tunnel_core::whitelist;

use crate::app::{
    App, Dashboard, LdntBanner, LdntDashView, LdntInit, LdntNotify, LdntRow, Os, c_name,
};
use crate::cfg::{self, Dispatch, Rc};

unsafe extern "C" {
    fn ldnt_os_cfg_open(name: *const c_char) -> u32;
    fn ldnt_os_cfg_close();
    fn ldnt_os_cfg_registered(name: *const c_char) -> bool;
    fn ldnt_os_cfg_dispatch(
        cmd: u32,
        input: *const c_void,
        in_len: u32,
        out: *mut c_void,
        out_len: u32,
    ) -> u32;
    fn ldnt_os_online() -> bool;
    fn ldnt_os_app_pid(pid: *mut u64) -> bool;
    fn ldnt_os_program_id(pid: u64, program_id: *mut u64) -> bool;
    fn ldnt_os_program_running(program_id: u64) -> bool;
    fn ldnt_os_terminate_process(pid: u64) -> u32;
    fn ldnt_os_terminate_program(program_id: u64);
    fn ldnt_os_launch_program(program_id: u64) -> u32;
    fn ldnt_os_ms() -> u64;
    fn ldnt_os_local_time(unix: u32, out: *mut c_char, len: usize) -> usize;
    // newlib
    fn fopen(path: *const c_char, mode: *const c_char) -> *mut c_void;
    fn fgets(buf: *mut c_char, len: c_int, f: *mut c_void) -> *mut c_char;
    fn fclose(f: *mut c_void) -> c_int;
}

/// Rust panics abort the overlay (the lints keep panics out of this crate).
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        fn abort() -> !;
    }
    unsafe { abort() }
}

const CFG_NAME: [u8; 9] = c_name(CFG_SERVICE);
const GAMELIST: [u8; 40] = c_name(GAMELIST_PATH);
const MODULE_ID: u64 = match u64::from_str_radix(PROGRAM_ID_HEX, 16) {
    Ok(v) => v,
    Err(_) => panic!("PROGRAM_ID_HEX"),
};

struct Hos;

impl Dispatch for Hos {
    fn dispatch(&mut self, cmd: u32, input: &[u8], out: &mut [u8]) -> Rc {
        // Every cfg_types reply and argument is under 256 bytes.
        unsafe {
            ldnt_os_cfg_dispatch(
                cmd,
                input.as_ptr().cast(),
                input.len() as u32,
                out.as_mut_ptr().cast(),
                out.len() as u32,
            )
        }
    }
}

impl Os for Hos {
    fn cfg_open(&mut self) -> Rc {
        unsafe { ldnt_os_cfg_open(CFG_NAME.as_ptr().cast()) }
    }
    fn cfg_close(&mut self) {
        unsafe { ldnt_os_cfg_close() }
    }
    fn cfg_registered(&mut self) -> bool {
        unsafe { ldnt_os_cfg_registered(CFG_NAME.as_ptr().cast()) }
    }
    fn online(&mut self) -> bool {
        unsafe { ldnt_os_online() }
    }
    fn app_pid(&mut self) -> Option<u64> {
        let mut pid = 0;
        unsafe { ldnt_os_app_pid(&mut pid) }.then_some(pid)
    }
    fn program_id(&mut self, pid: u64) -> Option<u64> {
        let mut id = 0;
        unsafe { ldnt_os_program_id(pid, &mut id) }.then_some(id)
    }
    fn in_game_list(&mut self, program_id: u64) -> bool {
        // Same rule as the module (whitelist::line_id). Without the file the module routes no game either.
        let f = unsafe { fopen(GAMELIST.as_ptr().cast(), c"r".as_ptr()) };
        if f.is_null() {
            return false;
        }
        let mut line = [0u8; 64];
        let mut found = false;
        while !found && !unsafe { fgets(line.as_mut_ptr().cast(), 64, f) }.is_null() {
            let l = crate::text::c_str(&line);
            let l = l.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(l);
            found = whitelist::line_id(l.split(|&b| b == b'\n' || b == b'\r').next().unwrap_or(l))
                == program_id;
        }
        unsafe { fclose(f) };
        found
    }
    fn module_running(&mut self) -> bool {
        unsafe { ldnt_os_program_running(MODULE_ID) }
    }
    fn terminate_process(&mut self, pid: u64) -> Rc {
        unsafe { ldnt_os_terminate_process(pid) }
    }
    fn terminate_module(&mut self) {
        unsafe { ldnt_os_terminate_program(MODULE_ID) }
    }
    fn launch_module(&mut self) -> Rc {
        unsafe { ldnt_os_launch_program(MODULE_ID) }
    }
    fn now_ms(&mut self) -> u64 {
        unsafe { ldnt_os_ms() }
    }
    fn local_time(&mut self, unix: u32, out: &mut [u8]) -> usize {
        unsafe { ldnt_os_local_time(unix, out.as_mut_ptr().cast(), out.len()) }
    }
}

struct State {
    app: App,
    dash: Dashboard,
}

struct Global(UnsafeCell<State>);
// ponytail: the overlay calls in from its one GUI thread only; a lock if that ever changes.
unsafe impl Sync for Global {}
static STATE: Global = Global(UnsafeCell::new(State {
    app: App::new(),
    dash: Dashboard::new(),
}));

/// The state; no ldnt_* calls another, so the borrow is never aliased.
fn state() -> &'static mut State {
    unsafe { &mut *STATE.0.get() }
}

fn app() -> &'static mut App {
    &mut state().app
}

/// Opens ldnt:cfg and reads the module version (run inside tsl::hlp::doWithSmSession).
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_init() {
    app().init(&mut Hos);
}

/// Saves unsaved changes and closes ldnt:cfg.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_exit() {
    app().exit(&mut Hos);
}

#[unsafe(no_mangle)]
pub extern "C" fn ldnt_status() -> LdntInit {
    app().init
}

/// Module version for frame headers (NUL-terminated, static).
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_version() -> *const c_char {
    app().version.as_ptr().cast()
}

/// The version cut to 16 characters ("v0.1.0+7576a92").
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_short_version() -> *const c_char {
    app().short_version.as_ptr().cast()
}

/// Save now if there are unsaved changes (closing, leaving a page). True when nothing is unsaved.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_save_if_dirty() -> bool {
    app().save_if_dirty(&mut Hos)
}

#[unsafe(no_mangle)]
pub extern "C" fn ldnt_reload_config() -> bool {
    app().reload(&mut Hos)
}

#[unsafe(no_mangle)]
pub extern "C" fn ldnt_check_for_updates() {
    let _ = app().cfg(&mut Hos).and_then(cfg::check_for_updates);
}

#[unsafe(no_mangle)]
pub extern "C" fn ldnt_setup_banner() -> LdntBanner {
    app().banner(&mut Hos)
}

/// Writes `*out` and returns true when the module answered.
fn get(out: *mut bool, v: Result<bool, Rc>) -> bool {
    match (v, unsafe { out.as_mut() }) {
        (Ok(v), Some(out)) => {
            *out = v;
            true
        }
        _ => false,
    }
}

/// Sets dirty on success.
fn set(r: Result<(), Rc>) -> bool {
    let ok = r.is_ok();
    if ok {
        app().mark_dirty();
    }
    ok
}

#[unsafe(no_mangle)]
pub extern "C" fn ldnt_debug_enabled(out: *mut bool) -> bool {
    get(out, app().cfg(&mut Hos).and_then(cfg::debug_enabled))
}

#[unsafe(no_mangle)]
pub extern "C" fn ldnt_set_debug_enabled(on: bool) -> bool {
    set(app()
        .cfg(&mut Hos)
        .and_then(|d| cfg::set_debug_enabled(d, on)))
}

#[unsafe(no_mangle)]
pub extern "C" fn ldnt_ldn_enabled(out: *mut bool) -> bool {
    get(out, app().cfg(&mut Hos).and_then(cfg::ldn_enabled))
}

#[unsafe(no_mangle)]
pub extern "C" fn ldnt_set_ldn_enabled(on: bool) -> bool {
    set(app()
        .cfg(&mut Hos)
        .and_then(|d| cfg::set_ldn_enabled(d, on)))
}

/// Log level 0-3 (Error, Warning, Info, Verbose); -1 when unknown.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_debug_level() -> i32 {
    match app().cfg(&mut Hos).and_then(cfg::debug_level) {
        Ok(l @ 0..=3) => l as i32,
        _ => -1,
    }
}

/// Marks dirty even when the module refused (as the C++ did).
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_set_debug_level(level: u32) {
    let app = app();
    if let Ok(d) = app.cfg(&mut Hos) {
        let _ = cfg::set_debug_level(d, level);
        app.mark_dirty();
    }
}

/// The module serves notification settings (else the menu is greyed out).
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_notifications_available() -> bool {
    app().notify_flags(&mut Hos).is_ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn ldnt_notify_enabled(which: LdntNotify) -> bool {
    app()
        .notify_flags(&mut Hos)
        .is_ok_and(|f| f & which.bit() != 0)
}

/// False (and nothing changed) when the module refused.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_set_notify(which: LdntNotify, on: bool) -> bool {
    app().set_notify(&mut Hos, which, on)
}

/// Advanced settings: the relay row.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_server_row(row: *mut LdntRow) {
    if let Some(row) = unsafe { row.as_mut() } {
        app().server_row(&mut Hos, row);
    }
}

/// "Restart ldn-tunnel", or "Start ldn-tunnel" when the module isn't running.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_restart_label() -> *const c_char {
    let label: &'static core::ffi::CStr = if Hos.module_running() {
        c"Restart ldn-tunnel"
    } else {
        c"Start ldn-tunnel"
    };
    label.as_ptr()
}

/// A new MainDashboardGui: fresh poll counter, caches and restart rows.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_dash_new() {
    state().dash = Dashboard::new();
}

/// Once per frame; `LDNT_DASH_*` bits. After LDNT_DASH_SWAP (restart done), close the overlay.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_dash_update(view: *mut LdntDashView, ldn_row: bool) -> u32 {
    let State { app, dash } = state();
    match unsafe { view.as_mut() } {
        Some(view) => dash.update(app, &mut Hos, view, ldn_row),
        None => 0,
    }
}

/// Re-read every row now (R). False when there is nothing to show.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_dash_refresh(view: *mut LdntDashView, ldn_row: bool) -> bool {
    let State { app, dash } = state();
    match unsafe { view.as_mut() } {
        Some(view) => dash.refresh(app, &mut Hos, view, ldn_row),
        None => false,
    }
}

/// A on a restart row (`slot` 0: banner, 1: Updates section / not-running screen). True when
/// `view.restart` holds new text for that row.
#[unsafe(no_mangle)]
pub extern "C" fn ldnt_restart_press(slot: u8, view: *mut LdntDashView) -> bool {
    let State { app, dash } = state();
    match unsafe { view.as_mut() } {
        Some(view) => dash.press(app, &mut Hos, slot, view),
        None => false,
    }
}
