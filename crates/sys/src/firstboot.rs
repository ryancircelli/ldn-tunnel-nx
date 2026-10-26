//! Every boot, before any service registers: disable conflicting LDN MITM modules
//! (docs/migration.md). Their `flags/boot2.flag` is renamed, never deleted, so the
//! user can undo it by renaming it back. The renamed module is still running this
//! boot, so `STATE.needs_restart` is set and the LDN MITMs stay off until a restart.
#![forbid(unsafe_code)]

use core::fmt::Write as _;
use core::sync::atomic::Ordering::Relaxed;

use heapless::String;
use ldn_tunnel_core::ident;
use nx::fs::DirectoryEntryType;

use crate::fs_util;
use crate::state::STATE;

/// ryu_ldn_nx and the older ldn_mitm share this program id.
const CONFLICTING: [&str; 1] = ["4200000000000010"];
const CONTENTS: &str = "sdmc:/atmosphere/contents";

type Path = String<128>;

pub fn run() {
    for id in CONFLICTING {
        let mut flag = Path::new();
        let _ = write!(flag, "{CONTENTS}/{id}/flags/boot2.flag");
        if fs_util::exists(&flag) {
            disable(id, &flag);
        }
    }
    log_other_ldn_mitms();
}

fn disable(id: &str, flag: &str) {
    // A marker from an earlier run (the user re-enabled the module) is kept too:
    // the first free name of `.ldn-tunnel-disabled`, `.ldn-tunnel-disabled.2`, ...
    for n in 1..=9 {
        let mut to = Path::new();
        let _ = write!(to, "{flag}.{}-disabled", ident::NAME);
        if n > 1 {
            let _ = write!(to, ".{n}");
        }
        if fs_util::exists(&to) {
            continue;
        }
        match fs_util::rename(flag, &to) {
            Ok(()) => {
                STATE.needs_restart.store(true, Relaxed);
                log!(Warning, "firstboot: disabled conflicting LDN module {id} ({flag} -> {to}); restart once to finish setup");
            }
            Err(rc) => log!(Error, "firstboot: cannot disable {id}: rename {flag} failed ({rc:?})"),
        }
        return;
    }
    log!(Error, "firstboot: cannot disable {id}: too many old {}-disabled markers", ident::NAME);
}

/// Any other module that MITMs ldn:u: log only, do not touch.
fn log_other_ldn_mitms() {
    let _ = fs_util::for_each_entry(CONTENTS, |name, ty| {
        if ty != DirectoryEntryType::Directory || name == ident::PROGRAM_ID_HEX || CONFLICTING.contains(&name) {
            return;
        }
        let mut lst = Path::new();
        let _ = write!(lst, "{CONTENTS}/{name}/mitm.lst");
        let mut buf = [0u8; 256];
        let Ok(n) = fs_util::read_into(&lst, &mut buf) else { return };
        let ldn = buf.get(..n).unwrap_or(&[]).split(|&b| b == b'\n').any(|l| l.trim_ascii() == b"ldn:u");
        let mut flag = Path::new();
        let _ = write!(flag, "{CONTENTS}/{name}/flags/boot2.flag");
        if ldn && fs_util::exists(&flag) {
            log!(Warning, "firstboot: {name} also MITMs ldn:u (left alone); disable it if LDN misbehaves");
        }
    });
}
