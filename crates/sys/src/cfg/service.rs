//! `ldnt:cfg` command bodies (port of `config/config_ipc_service.cpp`): runtime state
//! from `STATE`, settings from the live config (`config_io`), update state from `update_io`.
//! Setters change memory only; SaveConfig (13) writes config.ini.
#![forbid(unsafe_code)]

use core::fmt::Write as _;
use core::sync::atomic::Ordering::Relaxed;

use heapless::String;
use ldn_tunnel_core::cfg_types::{ConfigResult, HOST_LEN, ServerAddressIpc, SessionInfoIpc, UpdateStatusIpc};
use ldn_tunnel_core::notify::NotifyConfig;
use ldn_tunnel_core::ident;
use nx::ipc::sf::sm::{IUserInterfaceClient as _, ServiceName};
use nx::result::{Result, ResultCode};
use nx::service::sm::UserInterface;

use super::ifaces::{Cfg, ICfgServiceServer, TransportStatusBuf, VersionBuf};
use crate::config_io;
use crate::ldn::ifaces::Raw;
use crate::state::{STATE, check};
use crate::update_io;

/// Rejected input (the C++ returned sf::ResultNotSupported): module 431, description 3100.
const RESULT_INVALID_VALUE: ResultCode = ResultCode::new(crate::ldn::rc::MODULE | (3100 << 9));
/// PrepareRestart while a game holds our ldn:u / bsd:u sessions: module 431, description 3101.
const RESULT_IN_USE: ResultCode = ResultCode::new(crate::ldn::rc::MODULE | (3101 << 9));

/// `0.1.0` (dev build) or `0.1.0+b<build>`, NUL-padded into `N` bytes.
fn version<const N: usize>() -> [u8; N] {
    let mut s: String<64> = String::new();
    let _ = write!(s, "{}", update_io::VERSION);
    if update_io::RUNNING_BUILD != 0 {
        let _ = write!(s, "+b{}", update_io::RUNNING_BUILD);
    }
    let mut out = [0u8; N];
    for (d, b) in out.iter_mut().take(N.saturating_sub(1)).zip(s.bytes()) {
        *d = b;
    }
    out
}

/// IPC string: NUL-terminated inside the buffer, UTF-8, no control characters.
fn ipc_str(buf: &[u8]) -> Option<&str> {
    let end = buf.iter().position(|&b| b == 0)?;
    let s = core::str::from_utf8(buf.get(..end)?).ok()?;
    (!s.chars().any(char::is_control)).then_some(s)
}

fn level_name(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

impl ICfgServiceServer for Cfg {
    fn get_version(&mut self) -> Result<VersionBuf> {
        Ok(version())
    }

    fn get_connection_status(&mut self) -> Result<u32> {
        Ok(STATE.connection())
    }

    fn is_service_active(&mut self) -> Result<u32> {
        Ok(1)
    }

    fn is_game_active(&mut self) -> Result<u32> {
        Ok(u32::from(STATE.game_active()))
    }

    fn get_ldn_state(&mut self) -> Result<u32> {
        Ok(STATE.ldn_state.load(Relaxed))
    }

    fn get_session_info(&mut self) -> Result<Raw<SessionInfoIpc>> {
        Ok(Raw(STATE.session_info()))
    }

    fn get_active_process_id(&mut self) -> Result<u64> {
        Ok(STATE.active_pid())
    }

    fn get_debug_enabled(&mut self) -> Result<u32> {
        Ok(u32::from(config_io::get().debug.enabled))
    }

    fn set_debug_enabled(&mut self, enabled: u32) -> Result<()> {
        let d = config_io::update(|c| {
            c.debug.enabled = enabled != 0;
            c.debug.clone()
        });
        crate::log::configure(&d);
        log!(Info, "cfg: debug log {}", level_name(d.enabled));
        Ok(())
    }

    fn get_debug_level(&mut self) -> Result<u32> {
        Ok(config_io::get().debug.level)
    }

    fn set_debug_level(&mut self, level: u32) -> Result<()> {
        let d = config_io::update(|c| {
            c.debug.level = level.min(3);
            c.debug.clone()
        });
        crate::log::configure(&d);
        log!(Info, "cfg: debug level {}", d.level);
        Ok(())
    }

    fn save_config(&mut self) -> Result<Raw<ConfigResult>> {
        let r = config_io::save();
        log!(Info, "cfg: SaveConfig -> {r:?}");
        Ok(Raw(r))
    }

    fn reload_config(&mut self) -> Result<Raw<ConfigResult>> {
        let r = config_io::reload();
        log!(Info, "cfg: ReloadConfig -> {r:?}");
        Ok(Raw(r))
    }

    fn get_server_address(&mut self) -> Result<Raw<ServerAddressIpc>> {
        let c = config_io::get();
        let mut out = ServerAddressIpc { host: [0; HOST_LEN], port: c.server.port, padding: 0 };
        // A host longer than the IPC field is cut (the C++ did the same).
        for (d, b) in out.host.iter_mut().take(HOST_LEN - 1).zip(c.server.host.bytes()) {
            *d = b;
        }
        Ok(Raw(out))
    }

    fn set_server_address(&mut self, address: Raw<ServerAddressIpc>) -> Result<()> {
        let a = address.0;
        let host_buf = a.host;
        let Some(host) = ipc_str(&host_buf) else {
            log!(Warning, "cfg: SetServerAddress rejected (unterminated or control characters)");
            return Err(RESULT_INVALID_VALUE);
        };
        let port = a.port;
        config_io::update(|c| {
            c.server.host.clear();
            let _ = c.server.host.push_str(host); // 63 bytes always fit in 128
            c.server.port = port;
        });
        log!(Info, "cfg: server {host}:{port}");
        Ok(())
    }

    fn get_ldn_enabled(&mut self) -> Result<u32> {
        Ok(u32::from(config_io::get().ldn.enabled))
    }

    fn set_ldn_enabled(&mut self, enabled: u32) -> Result<()> {
        config_io::update(|c| c.ldn.enabled = enabled != 0);
        log!(Info, "cfg: LDN {}", level_name(enabled != 0));
        Ok(())
    }

    fn get_transport_status(&mut self) -> Result<TransportStatusBuf> {
        Ok(STATE.transport_status())
    }

    fn get_update_status(&mut self) -> Result<Raw<UpdateStatusIpc>> {
        let st = update_io::get_status();
        Ok(Raw(UpdateStatusIpc {
            running_build: st.running_build,
            staged_build: st.staged_build,
            rejected_build: st.rejected_build,
            on_probation: u8::from(st.on_probation),
            rolled_back: u8::from(st.rolled_back),
            channel: config_io::get().update.channel as u8,
            check_state: STATE.update_check.load(Relaxed),
            version: version(),
            download: STATE.update_download.load(Relaxed),
        }))
    }

    fn check_for_updates(&mut self) -> Result<()> {
        STATE.update_check.store(check::CHECKING, Relaxed);
        STATE.update_check_requested.store(true, Relaxed);
        log!(Info, "cfg: update check requested");
        Ok(())
    }

    fn get_notify_flags(&mut self) -> Result<u32> {
        Ok(config_io::get().notifications.bits())
    }

    fn set_notify_flags(&mut self, flags: u32) -> Result<()> {
        let n = NotifyConfig::from_bits(flags); // unknown bits dropped
        config_io::update(|c| c.notifications = n);
        STATE.set_notify_config(n);
        log!(Info, "cfg: notify flags {:#x}", n.bits());
        Ok(())
    }

    fn get_setup_status(&mut self) -> Result<u32> {
        Ok(STATE.setup_status())
    }

    /// Atmosphere's sm never drops a dead process's MITMs or (nx detaches its sm client)
    /// services: killed with them installed, the next bsd:u open aborts sm on the dead query
    /// session, and a relaunch cannot install them again. So they go here, from our own
    /// process. Afterwards new sessions get the real services; the module keeps running
    /// without its MITMs until pm terminates it.
    fn prepare_restart(&mut self) -> Result<()> {
        if STATE.in_use() {
            log!(Info, "cfg: PrepareRestart refused: a game uses the module");
            return Err(RESULT_IN_USE);
        }
        // ponytail: a game starting between this check and the uninstall still gets our
        // MITM session and loses it to the restart; sm offers no atomic check-and-uninstall.
        let sm = nx::service::new_named_port_object::<UserInterface>()?;
        for name in ["ldn:u", "bsd:u"] {
            // Not installed (rolled-back boot, restart pending) is fine.
            if let Err(rc) = sm.atmosphere_uninstall_mitm(ServiceName::new(name)) {
                log!(Info, "cfg: {name} MITM not uninstalled: {rc:?}");
            }
        }
        sm.unregister_service(ServiceName::new(ident::CFG_SERVICE))?;
        log!(Info, "cfg: MITMs and {} off sm, ready to be restarted", ident::CFG_SERVICE);
        // pm kills us right after this reply: write out what the log holds.
        crate::log::maintain();
        Ok(())
    }
}
