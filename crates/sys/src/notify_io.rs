//! Writes toasts as Ultrahand API notification files (docs/notifications.md section 3).
//!
//! Only when `notify::NOTIFY_DIR` exists (Ultrahand installed; its folders are never
//! created here). Each file is written as `<name>.tmp` and renamed to `<name>.notify`,
//! so Ultrahand's scanner never reads a half-written file.
#![forbid(unsafe_code)]

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

use heapless::String;
use ldn_tunnel_core::ident;
use ldn_tunnel_core::notify::{self, Category, NOTIFY_DIR, Toast};
use nx::fs::DirectoryEntryType;
use nx::sync::Mutex;

use crate::fs_util;
use crate::state::STATE;

type Path = String<128>;

/// Per-boot counter, seeded from the system tick at boot so names never repeat across boots.
static SEQ: AtomicU32 = AtomicU32::new(0);
/// File of the last Connection toast: deleted before the next one if still unshown
/// (a stale "Connection lost" must not pop up after "Reconnected").
static LAST_CONNECTION: Mutex<Option<String<40>>> = Mutex::new(None);

fn full(name: &str) -> Path {
    let mut p = Path::new();
    let _ = write!(p, "{NOTIFY_DIR}/{name}");
    p
}

/// Boot: seed the counter and delete our own unshown leftovers (Tesla Menu, or API
/// notifications off).
pub fn boot() {
    SEQ.store(nx::arm::get_system_tick() as u32, Relaxed);
    let mut prefix: String<20> = String::new();
    let _ = write!(prefix, "{}-", ident::PROGRAM_ID_HEX);
    let _ = fs_util::for_each_entry(NOTIFY_DIR, |name, ty| {
        if ty == DirectoryEntryType::File && name.starts_with(prefix.as_str()) {
            let _ = fs_util::delete(&full(name));
        }
    });
}

/// Writes every toast that is due. Call about once a second.
pub fn pump() {
    while let Some(t) = STATE.poll_toast() {
        write(&t);
    }
}

fn write(t: &Toast) {
    if !fs_util::dir_exists(NOTIFY_DIR) {
        return;
    }
    let mut json = [0u8; 256];
    let Some(n) = t.write_json(&mut json) else { return };
    let name = notify::file_name(SEQ.fetch_add(1, Relaxed));
    if t.category == Category::Connection
        && let Some(old) = LAST_CONNECTION.lock().replace(name.clone())
    {
        let _ = fs_util::delete(&full(&old));
    }
    let path = full(&name);
    let mut tmp = path.clone();
    let _ = tmp.push_str(".tmp");
    let ok = fs_util::delete(&tmp).is_ok()
        && fs_util::write_new(&tmp, json.get(..n).unwrap_or(&[])).is_ok()
        && fs_util::rename(&tmp, &path).is_ok();
    if ok {
        log!(Info, "notify: {}", t.text);
    } else {
        let _ = fs_util::delete(&tmp);
        log!(Warning, "notify: could not write {path}");
    }
}
