//! File logger at `ident::LOG_PATH` (port of `debug/log.cpp`) plus the remote-log ring.
//!
//! `log!(Info, "fmt {}", x)` anywhere in crates/sys. Levels and switches come from
//! config.ini `[debug]` (`enabled`, `level` 0–3, `remote_log`). The file opens on
//! the first line, is written without a per-line SD sync, flushed every 2 s and
//! closed after 5 s idle by [`maintain`] (the C++ log maintenance thread), and
//! rotated to `<log>.1` at 1 MiB. With `remote_log` on, lines also go into
//! `core::logring` for the relay client to drain with [`with_remote_ring`].
#![forbid(unsafe_code)]

use core::fmt::{self, Write as _};
use core::sync::atomic::{AtomicU8, Ordering::Relaxed};

use heapless::String;
use ldn_tunnel_core::config;
use ldn_tunnel_core::ident;
use ldn_tunnel_core::logring::{self, LogRing};
pub use ldn_tunnel_core::logring::Level;
use nx::fs::FileAccessor;
use nx::sync::Mutex;

use crate::fs_util;
use crate::state::uptime_ms;

const MAX_FILE_SIZE: usize = 1024 * 1024;
const IDLE_CLOSE_MS: u64 = 5_000;

/// `log!(Info, "...", args)`; levels: Error, Warning, Info, Verbose.
macro_rules! log {
    ($level:ident, $($arg:tt)*) => {
        $crate::log::write($crate::log::Level::$level, format_args!($($arg)*))
    };
}

struct Logger {
    file: Option<FileAccessor>,
    size: usize,
    last_write_ms: u64,
    header_written: bool,
    to_file: bool,
    remote: bool,
    ring: LogRing,
}

static LOGGER: Mutex<Logger> = Mutex::new(Logger {
    file: None,
    size: 0,
    last_write_ms: 0,
    header_written: false,
    to_file: false,
    remote: false,
    ring: LogRing::new(),
});

/// Highest level that is logged + 1; 0 = logging off. Read without the lock.
static THRESHOLD: AtomicU8 = AtomicU8::new(0);

/// Applies `[debug]`. Before the first call nothing is logged.
pub fn configure(d: &config::Debug) {
    let level = d.level.min(Level::Verbose as u32) as u8;
    let mut l = LOGGER.lock();
    l.to_file = d.enabled;
    l.remote = d.remote;
    if !d.enabled {
        l.close();
    }
    THRESHOLD.store(if d.enabled || d.remote { level.saturating_add(1) } else { 0 }, Relaxed);
}

fn tag(level: Level) -> &'static str {
    match level {
        Level::Error => "ERROR",
        Level::Warning => "WARN",
        Level::Info => "INFO",
        Level::Verbose => "VERBOSE",
    }
}

/// Fills up to capacity and silently drops the rest (a long line is cut, not lost).
struct Line(String<{ logring::LINE_LEN }>);

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            if self.0.push(c).is_err() {
                break;
            }
        }
        Ok(())
    }
}

pub fn write(level: Level, args: fmt::Arguments<'_>) {
    if level as u8 >= THRESHOLD.load(Relaxed) {
        return;
    }
    let now = uptime_ms();
    let mut line = Line(String::new());
    let _ = write!(line, "[{:6}.{:03}] [{}] {args}", now / 1000, now % 1000, tag(level));
    let mut l = LOGGER.lock();
    if l.remote {
        l.ring.push(&line.0);
    }
    if l.to_file {
        l.append(&line.0, now);
    }
}

impl Logger {
    fn append(&mut self, line: &str, now: u64) {
        if self.file.is_none() {
            self.open();
        }
        let Some(f) = self.file.as_mut() else { return };
        let ok = f.write_array::<u8, false>(line.as_bytes()).and_then(|()| f.write_array::<u8, false>(b"\n"));
        self.size = self.size.saturating_add(line.len()).saturating_add(1);
        self.last_write_ms = now;
        // Over the cap (or a failed write): close; the next line reopens and rotates.
        if ok.is_err() || self.size >= MAX_FILE_SIZE {
            self.close();
        }
    }

    fn open(&mut self) {
        let _ = fs_util::create_dir_all(ident::CONFIG_DIR);
        let mut size = fs_util::file_size(ident::LOG_PATH).unwrap_or(0);
        if size >= MAX_FILE_SIZE {
            let mut old: String<80> = String::new();
            let _ = write!(old, "{}.1", ident::LOG_PATH);
            let _ = fs_util::replace(ident::LOG_PATH, &old);
            size = 0;
        }
        let Ok(mut f) = fs_util::open_append(ident::LOG_PATH) else { return };
        if !self.header_written {
            let mut h: String<80> = String::new();
            let _ = write!(h, "\n=== {} {} log started ===\n", ident::NAME, crate::update_io::VERSION);
            if f.write_array::<u8, true>(h.as_bytes()).is_ok() {
                size = size.saturating_add(h.len());
                self.header_written = true;
            }
        }
        self.size = size;
        self.last_write_ms = uptime_ms();
        self.file = Some(f);
    }

    fn close(&mut self) {
        if let Some(f) = self.file.take() {
            let _ = f.flush();
        }
    }
}

/// Every ~2 s from the maintenance thread: close after 5 s idle, else flush
/// (caps what a crash loses to one period).
pub fn maintain() {
    let mut l = LOGGER.lock();
    let idle = uptime_ms().saturating_sub(l.last_write_ms) >= IDLE_CLOSE_MS;
    if idle {
        l.close();
    } else if let Some(f) = &l.file {
        let _ = f.flush();
    }
}

/// For the relay thread's DebugLog (0xC0) flush (`RemoteLog::next_payload`). Lock order:
/// the relay's link lock may be held here; `f` must not log.
pub fn with_remote_ring<R>(f: impl FnOnce(&mut LogRing) -> R) -> R {
    f(&mut LOGGER.lock().ring)
}

/// Panic path: appends straight to the file. `try_lock` so a panic raised while
/// the logger is held cannot deadlock; the open handle is closed first so the
/// fresh open is not refused. Skipped when the lock is taken.
pub fn panic_line(args: fmt::Arguments<'_>) {
    let Some(mut l) = LOGGER.try_lock() else { return };
    l.close();
    let mut line = Line(String::new());
    let _ = write!(line, "panic: {args}");
    let _ = fs_util::create_dir_all(ident::CONFIG_DIR);
    let _ = fs_util::append_line(ident::LOG_PATH, &line.0);
}
