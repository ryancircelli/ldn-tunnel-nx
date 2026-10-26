//! config.ini and gamelist.txt on the SD card (port of the I/O half of `config/config.cpp`
//! and `game_whitelist.cpp`); parsing and serializing are `core::config` / `core::whitelist`.
//!
//! Saves are tmp + delete + rename (Horizon cannot rename onto a file); a save cut after
//! the delete leaves a complete `.tmp` that the next load renames in.
#![forbid(unsafe_code)]

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;

use heapless::String;
use ldn_tunnel_core::cfg_types::ConfigResult;
use ldn_tunnel_core::config::Config;
use ldn_tunnel_core::ident;
use ldn_tunnel_core::whitelist::Whitelist;
use nx::sync::Mutex;

use crate::fs_util;

/// Far above a real config.ini (~1.5 KiB); the rest of a bigger file is ignored.
const MAX_CONFIG_FILE: usize = 16 * 1024;
/// Serialized config with every string at its maximum is ~2.3 KiB.
const SAVE_BUF: usize = 4 * 1024;
/// 8192 ids × ~19 bytes per line, with room for comments.
const MAX_GAMELIST_FILE: usize = 256 * 1024;

/// The live config (`None` until the first load). Holds the relay token: never log it whole.
static CONFIG: Mutex<Option<Config>> = Mutex::new(None);
static WHITELIST: Mutex<Whitelist> = Mutex::new(Whitelist::new());

/// A copy of the live config.
pub fn get() -> Config {
    CONFIG.lock().clone().unwrap_or_default()
}

/// Changes the live config in memory (SaveConfig persists it).
pub fn update<R>(f: impl FnOnce(&mut Config) -> R) -> R {
    f(CONFIG.lock().get_or_insert_with(Config::default))
}

fn tmp_path() -> String<80> {
    let mut s = String::new();
    let _ = write!(s, "{}.tmp", ident::CONFIG_PATH);
    s
}

/// Overwrites the buffer before it is freed (it held the relay token).
fn wipe(mut buf: Vec<u8>) {
    buf.fill(0);
    core::hint::black_box(&buf);
}

/// Boot: writes the commented default config.ini if there is none, then loads it.
pub fn load_at_boot() -> ConfigResult {
    let created = (!fs_util::recover_tmp(&tmp_path(), ident::CONFIG_PATH)).then(|| save_config(&Config::default()));
    let r = reload();
    match created {
        Some(ConfigResult::Success) => log!(Info, "config: created default {}", ident::CONFIG_PATH),
        Some(e) => log!(Error, "config: cannot create {}: {e:?}", ident::CONFIG_PATH),
        None => {}
    }
    r
}

/// Defaults + config.ini into the live config (on any failure the defaults stay, as in
/// the C++ ReloadConfig), and applies `[debug]` to the logger.
pub fn reload() -> ConfigResult {
    let mut cfg = Config::default();
    let (result, bad) = read_into(&mut cfg);
    crate::log::configure(&cfg.debug);
    crate::state::STATE.set_notify_config(cfg.notifications);
    *CONFIG.lock() = Some(cfg);
    if bad > 0 {
        log!(Warning, "config: {bad} invalid value(s) in config.ini kept their defaults");
    }
    result
}

/// Result and the number of rejected values.
fn read_into(cfg: &mut Config) -> (ConfigResult, u32) {
    if !fs_util::recover_tmp(&tmp_path(), ident::CONFIG_PATH) {
        return (ConfigResult::FileNotFound, 0);
    }
    let Ok(size) = fs_util::file_size(ident::CONFIG_PATH) else { return (ConfigResult::IoError, 0) };
    let mut buf = vec![0u8; size.min(MAX_CONFIG_FILE)];
    let result = match fs_util::read_into(ident::CONFIG_PATH, &mut buf) {
        Ok(n) => (ConfigResult::Success, cfg.parse(buf.get(..n).unwrap_or(&[]))),
        Err(_) => (ConfigResult::IoError, 0),
    };
    wipe(buf);
    result
}

/// Writes the live config to config.ini.
pub fn save() -> ConfigResult {
    save_config(&get())
}

fn save_config(cfg: &Config) -> ConfigResult {
    let mut buf = vec![0u8; SAVE_BUF];
    let n = cfg.write_to(&mut buf);
    let tmp = tmp_path();
    let ok = n > 0
        && fs_util::create_dir_all(ident::CONFIG_DIR).is_ok()
        && fs_util::delete(&tmp).is_ok()
        && fs_util::write_new(&tmp, buf.get(..n).unwrap_or(&[])).is_ok();
    wipe(buf);
    if !ok {
        let _ = fs_util::delete(&tmp);
        return ConfigResult::IoError;
    }
    match fs_util::replace(&tmp, ident::CONFIG_PATH) {
        Ok(()) => ConfigResult::Success,
        Err(_) => ConfigResult::IoError,
    }
}

/// (Re)loads gamelist.txt. Returns the number of ids; a missing file leaves the list empty.
pub fn load_whitelist() -> usize {
    let mut wl = WHITELIST.lock();
    let Ok(size) = fs_util::file_size(ident::GAMELIST_PATH) else {
        *wl = Whitelist::new();
        log!(Warning, "whitelist: {} missing, no game is routed", ident::GAMELIST_PATH);
        return 0;
    };
    let mut buf = vec![0u8; size.min(MAX_GAMELIST_FILE)];
    let n = fs_util::read_into(ident::GAMELIST_PATH, &mut buf).unwrap_or(0);
    let overflow = wl.load(buf.get(..n).unwrap_or(&[]));
    if overflow > 0 {
        log!(Warning, "whitelist: {overflow} ids beyond the {} limit ignored", ldn_tunnel_core::whitelist::MAX_ENTRIES);
    }
    log!(Info, "whitelist: {} games from {}", wl.len(), ident::GAMELIST_PATH);
    wl.len()
}

pub fn is_whitelisted(program_id: u64) -> bool {
    WHITELIST.lock().contains(program_id)
}
