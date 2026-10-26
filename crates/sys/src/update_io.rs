//! Update staging, install swap and boot-time probation on the SD card (port of
//! `update/update_swap.cpp`). Manifest checks and the state-file codecs are
//! `core::update`; this file is the fs half.
//!
//! The relay thread drives a download (`core::conn::update_dl`, 0xC1–0xC4) through
//! [`Stager`] (`begin` resumes a partial `.new`, `append`, `verify`) and [`install_staged`].
//!
//! On-disk state in `ident::UPDATE_STATE_DIR`: `probation` ("build=<n>\nboots=<k>\n",
//! boots=0 at install, bumped by boot_check, deleted by mark_healthy) and `rejected`
//! ("<build>\n", the build the last rollback removed). Swapped files: `ident::EXEFS_PATH`
//! and `ident::OVERLAY_PATH`, each with `.new` and `.bak`. config.ini is never touched.
//!
//! Power-loss states (same as the C++): a file absent with its `.new` present (cut
//! between its two renames) is renamed in by boot_check; for exefs.nsp nothing boots to
//! do that, so that short window needs a PC (absent, never corrupt). Rollback restores
//! the overlay first and exefs last, after writing `rejected`.
#![forbid(unsafe_code)]

use alloc::vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

use heapless::String;
use ldn_tunnel_core::ident;
use ldn_tunnel_core::notify::Event;
use ldn_tunnel_core::update::{self, PUBKEY_LEN, Status, UPDATE_MAX_BLOB_SIZE, UpdateManifest};
use nx::fs::FileAccessor;
use nx::sync::Mutex;
use sha2::{Digest, Sha256};

use crate::fs_util;
use crate::state::STATE;

/// Build number of this binary (`LDNT_BUILD` at compile time; 0 = developer build,
/// which never auto-updates).
pub const RUNNING_BUILD: u32 = parse_build(option_env!("LDNT_BUILD"));
/// Version string of this binary (`LDNT_VERSION`, e.g. the git describe; else the crate version).
pub const VERSION: &str = match option_env!("LDNT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};
/// Publisher key (`LDNT_UPDATE_PUBKEY`, 130 hex chars = uncompressed P-256 point).
/// Unset: all zeros, which no signature verifies against, so updates are refused.
pub const PUBLIC_KEY: [u8; PUBKEY_LEN] = parse_key(option_env!("LDNT_UPDATE_PUBKEY"));

#[allow(clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)] // const-evaluated at build time: a bad env var is a compile error, never a runtime panic
const fn parse_build(s: Option<&str>) -> u32 {
    let Some(s) = s else { return 0 };
    let b = s.as_bytes();
    let mut v = 0u32;
    let mut i = 0;
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "LDNT_BUILD must be a decimal number");
        v = v * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    v
}

#[allow(clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)] // const-evaluated at build time: a bad env var is a compile error, never a runtime panic
const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("LDNT_UPDATE_PUBKEY must be hex"),
    }
}

#[allow(clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)] // const-evaluated at build time: a bad env var is a compile error, never a runtime panic
const fn parse_key(s: Option<&str>) -> [u8; PUBKEY_LEN] {
    let mut k = [0u8; PUBKEY_LEN];
    let Some(s) = s else { return k };
    let b = s.as_bytes();
    assert!(b.len() == PUBKEY_LEN * 2, "LDNT_UPDATE_PUBKEY must be 130 hex characters");
    let mut i = 0;
    while i < PUBKEY_LEN {
        k[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    k
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Exefs,
    Overlay,
}

/// Install and rollback order: exefs.nsp (what boots) always last.
const SWAP_ORDER: [Which; 2] = [Which::Overlay, Which::Exefs];

const fn blob_path(w: Which) -> &'static str {
    match w {
        Which::Exefs => ident::EXEFS_PATH,
        Which::Overlay => ident::OVERLAY_PATH,
    }
}

type Path = String<128>;

fn path(base: &str, suffix: &str) -> Path {
    let mut p = Path::new();
    let _ = write!(p, "{base}{suffix}"); // longest: UPDATE_STATE_DIR + "/probation.tmp", < 128
    p
}

/// Hash and size the manifest names for `which`.
pub fn blob(m: &UpdateManifest, which: Which) -> ([u8; 32], u32) {
    match which {
        Which::Exefs => (m.exefs_sha256, m.exefs_size),
        Which::Overlay => (m.overlay_sha256, m.overlay_size),
    }
}

// ---------------------------------------------------------------- state files

const PROBATION: &str = "/probation";
const REJECTED: &str = "/rejected";

fn write_state(name: &str, text: &str) -> bool {
    let (p, tmp) = (path(ident::UPDATE_STATE_DIR, name), path(&path(ident::UPDATE_STATE_DIR, name), ".tmp"));
    let ok = fs_util::create_dir_all(ident::UPDATE_STATE_DIR).is_ok()
        && fs_util::delete(&tmp).is_ok()
        && fs_util::write_new(&tmp, text.as_bytes()).is_ok();
    if !ok {
        let _ = fs_util::delete(&tmp);
        return false;
    }
    fs_util::replace(&tmp, &p).is_ok()
}

/// Finishes a write_state cut after its delete, then reads.
fn read_state<'a>(name: &str, buf: &'a mut [u8]) -> &'a [u8] {
    let (p, tmp) = (path(ident::UPDATE_STATE_DIR, name), path(&path(ident::UPDATE_STATE_DIR, name), ".tmp"));
    fs_util::recover_tmp(&tmp, &p);
    let n = fs_util::read_into(&p, buf).unwrap_or(0);
    buf.get(..n).unwrap_or(&[])
}

/// tmp first: a leftover complete tmp would otherwise be renamed back in.
fn clear_state(name: &str) {
    let p = path(ident::UPDATE_STATE_DIR, name);
    let _ = fs_util::delete(&path(&p, ".tmp"));
    let _ = fs_util::delete(&p);
}

// ---------------------------------------------------------------- status / boot

static STATUS: Mutex<Status> = Mutex::new(Status {
    running_build: RUNNING_BUILD,
    staged_build: 0,
    rejected_build: 0,
    on_probation: false,
    rolled_back: false,
});
/// One install per boot (download thread only).
static INSTALL_ATTEMPTED: AtomicBool = AtomicBool::new(false);

pub fn get_status() -> Status {
    STATUS.get_val()
}

/// Once at boot, after the SD mount and before any service registers. Returns true
/// if this boot rolled back and must stand down (no ldn:u / bsd:u).
pub fn boot_check() -> bool {
    let _ = fs_util::create_dir_all(ident::UPDATE_STATE_DIR);
    let mut buf = [0u8; 64];
    let rejected = update::parse_rejected(read_state(REJECTED, &mut buf));
    STATUS.lock().rejected_build = rejected;

    let Some(pr) = update::parse_probation(read_state(PROBATION, &mut buf)) else {
        clear_state(PROBATION); // absent or torn
        return false;
    };

    // Cut between the two renames of an install: the .new was verified before it began.
    for w in SWAP_ORDER {
        let (file, fresh) = (blob_path(w), path(blob_path(w), ".new"));
        if !fs_util::exists(file) && fs_util::exists(&fresh) {
            let _ = fs_util::rename(&fresh, file);
            log!(Warning, "update: finished an interrupted install of {file}");
        }
    }

    if pr.build != RUNNING_BUILD {
        // The exefs swap never happened (or a build was copied by hand): nothing to judge.
        log!(Info, "update: probation for build {} but running {RUNNING_BUILD}: cleared", pr.build);
        clear_state(PROBATION);
        return false;
    }

    if pr.boots == 0 {
        // First boot of a freshly installed build.
        write_state(PROBATION, &update::format_probation(pr.build, 1));
        STATUS.lock().on_probation = true;
        STATE.first_boot_of_build.store(true, Relaxed);
        STATE.notify_event(Event::UpdatedTo(VERSION));
        return false;
    }

    // The previous boot of this build never reached healthy.
    if !SWAP_ORDER.iter().any(|&w| fs_util::exists(&path(blob_path(w), ".bak"))) {
        log!(Warning, "update: build {} never got healthy but there is no backup to restore", pr.build);
        clear_state(PROBATION);
        return false;
    }
    // rejected first: once exefs is restored, the running-build check above skips this.
    write_state(REJECTED, &update::format_rejected(pr.build));
    for w in SWAP_ORDER {
        let (file, bak) = (blob_path(w), path(blob_path(w), ".bak"));
        if fs_util::exists(&bak) && fs_util::delete(file).is_ok() {
            let _ = fs_util::rename(&bak, file);
        }
    }
    clear_state(PROBATION);
    log!(Error, "update: build {} failed its probation; previous build restored, restart to run it", pr.build);
    let mut st = STATUS.lock();
    st.rejected_build = pr.build;
    st.rolled_back = true;
    true
}

/// Ends this boot's probation (a probation written by install_staged is the next boot's).
pub fn mark_healthy() {
    let mut st = STATUS.lock();
    if st.on_probation {
        clear_state(PROBATION);
        st.on_probation = false;
        log!(Info, "update: build {RUNNING_BUILD} healthy");
    }
}

// ---------------------------------------------------------------- staging

/// Streams one blob into `<file>.new`; [`Stager::verify`] re-reads and hashes it.
/// Dropping a Stager closes the file and keeps a partial `.new` for resume.
pub struct Stager {
    file: Option<FileAccessor>,
    which: Which,
    /// 0 = no begin().
    size: u32,
    written: u32,
    sha256: [u8; 32],
}

impl Default for Stager {
    fn default() -> Self {
        Self::new()
    }
}

impl Stager {
    pub const fn new() -> Self {
        Self { file: None, which: Which::Exefs, size: 0, written: 0, sha256: [0; 32] }
    }

    /// Opens (or resumes) `<file>.new`. Returns the offset to continue from, `None` on failure.
    /// A shorter `.new` is resumed as is; a prefix of some other blob fails verify and starts over.
    pub fn begin(&mut self, which: Which, sha256: &[u8; 32], size: u32) -> Option<u32> {
        self.file = None;
        self.size = 0;
        if size == 0 || size > UPDATE_MAX_BLOB_SIZE {
            return None;
        }
        let p = path(blob_path(which), ".new");
        let have = match fs_util::file_size(&p) {
            Ok(h) if h < size as usize => h,
            _ => {
                fs_util::delete(&p).ok()?;
                0
            }
        };
        self.file = Some(fs_util::open_append(&p).ok()?); // positioned at the end = `have`
        self.which = which;
        self.size = size;
        self.written = have as u32; // < size
        self.sha256 = *sha256;
        Some(self.written)
    }

    /// Sequential write, flushed (a resume continues from a size that is on the card).
    pub fn append(&mut self, data: &[u8]) -> bool {
        let room = self.size.saturating_sub(self.written) as usize;
        let Some(f) = self.file.as_mut().filter(|_| data.len() <= room) else { return false };
        if f.write_array::<u8, true>(data).is_err() {
            return false;
        }
        self.written = self.written.saturating_add(data.len() as u32);
        true
    }

    /// Closes the file, checks size and SHA-256. False also deletes `.new`.
    pub fn verify(&mut self) -> bool {
        self.file = None;
        if self.size == 0 {
            return false;
        }
        let p = path(blob_path(self.which), ".new");
        if file_hash_is(&p, self.size, &self.sha256) {
            return true;
        }
        log!(Warning, "update: {p} failed its hash check, deleted");
        let _ = fs_util::delete(&p);
        self.size = 0;
        false
    }
}

fn file_hash_is(p: &str, size: u32, want: &[u8; 32]) -> bool {
    if fs_util::file_size(p).ok() != Some(size as usize) {
        return false;
    }
    let Ok(mut f) = fs_util::open_read(p) else { return false };
    let mut buf = vec![0u8; 4096]; // heap, not the download thread's stack
    let mut h = Sha256::new();
    let mut left = size as usize;
    while left > 0 {
        let n = left.min(buf.len());
        let Some(chunk) = buf.get_mut(..n) else { return false };
        match f.read_array(chunk) {
            Ok(got) if got > 0 => {
                h.update(chunk.get(..got).unwrap_or(&[]));
                left = left.saturating_sub(got);
            }
            _ => return false,
        }
    }
    h.finalize().as_slice() == want
}

// ---------------------------------------------------------------- install

/// Both `.new` files verified: swap them in and start the probation. Order, each step
/// durable before the next: write `probation` (build, boots=0) → for the overlay then
/// exefs: delete `.bak`, rename file → `.bak`, rename `.new` → file.
pub fn install_staged(m: &UpdateManifest) -> bool {
    // .bak must always be a build that reached healthy: one install per boot and none
    // while this boot's own probation is open.
    if STATUS.lock().on_probation || INSTALL_ATTEMPTED.load(Relaxed) {
        return false;
    }
    for w in SWAP_ORDER {
        if fs_util::file_size(&path(blob_path(w), ".new")).ok() != Some(blob(m, w).1 as usize) {
            return false;
        }
    }
    INSTALL_ATTEMPTED.store(true, Relaxed);
    let build = m.build;
    if !write_state(PROBATION, &update::format_probation(build, 0)) {
        return false;
    }
    for w in SWAP_ORDER {
        let (file, bak, fresh) = (blob_path(w), path(blob_path(w), ".bak"), path(blob_path(w), ".new"));
        if fs_util::delete(&bak).is_err()
            || (fs_util::exists(file) && fs_util::rename(file, &bak).is_err())
            || fs_util::rename(&fresh, file).is_err()
        {
            log!(Error, "update: install of build {build} stopped at {file}");
            return false;
        }
    }
    STATUS.lock().staged_build = build;
    log!(Info, "update: build {build} installed, active after a restart");
    STATE.notify_event(Event::UpdateStaged);
    true
}
