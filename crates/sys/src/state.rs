//! Process-wide runtime state, readable and writable from any thread (`STATE`).
//!
//! Scalars are atomics; the few multi-field values sit behind nx `Mutex`es that
//! are only held for a copy. The ldn:u / bsd:u / relay / updater code writes it,
//! `ldnt:cfg` reads it for the overlay.
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering::Relaxed};

use ldn_tunnel_core::cfg_types::{ConnectionStatus, SessionInfoIpc, TRANSPORT_STATUS_LEN};
use ldn_tunnel_core::notify::{Event, Notifier, NotifyConfig, Toast};
use nx::sync::Mutex;

/// `UpdateStatusIpc.check_state`.
pub mod check {
    pub const IDLE: u8 = 0;
    pub const CHECKING: u8 = 1;
    pub const FAILED: u8 = 2;
}

pub struct SharedState {
    /// `ConnectionStatus` as u32 (relay client).
    connection: AtomicU32,
    /// `CommState` as u32 (ldn:u state machine).
    pub ldn_state: AtomicU32,
    /// Process id of the game holding ldn:u, 0 = none.
    active_pid: AtomicU64,
    session: Mutex<SessionInfoIpc>,
    transport: Mutex<[u8; TRANSPORT_STATUS_LEN]>,
    /// firstboot disabled a conflicting module: it is still loaded this boot.
    pub needs_restart: AtomicBool,
    /// boot_check rolled back an update: run without the LDN MITMs this boot.
    pub update_stand_down: AtomicBool,
    /// Firmware below `compat::MIN_HOS` (crates/sys/src/compat.rs): no LDN MITMs.
    pub fw_too_old: AtomicBool,
    /// This is the first boot of a build the updater installed.
    pub first_boot_of_build: AtomicBool,
    /// `check::*` of the updater thread.
    pub update_check: AtomicU8,
    /// 0 = not downloading, else percent + 1.
    pub update_download: AtomicU8,
    /// CheckForUpdates was called; the updater thread takes it with `swap(false)`.
    pub update_check_requested: AtomicBool,
    /// ldn:u + bsd:u sessions a game holds through our MITMs (a restart of the module breaks them).
    pub mitm_sessions: AtomicU32,
    notifier: Mutex<Notifier>,
}

pub static STATE: SharedState = SharedState {
    connection: AtomicU32::new(ConnectionStatus::Disconnected as u32),
    ldn_state: AtomicU32::new(0),
    active_pid: AtomicU64::new(0),
    session: Mutex::new(SessionInfoIpc { node_count: 0, max_nodes: 0, local_node_id: 0, is_host: 0, reserved: [0; 4] }),
    transport: Mutex::new([0; TRANSPORT_STATUS_LEN]),
    needs_restart: AtomicBool::new(false),
    update_stand_down: AtomicBool::new(false),
    fw_too_old: AtomicBool::new(false),
    first_boot_of_build: AtomicBool::new(false),
    update_check: AtomicU8::new(check::IDLE),
    update_download: AtomicU8::new(0),
    update_check_requested: AtomicBool::new(false),
    mitm_sessions: AtomicU32::new(0),
    // Defaults until config_io loads `[notifications]`.
    notifier: Mutex::new(Notifier::new(NotifyConfig { updates: true, game_start: true, connection: true })),
};

impl SharedState {
    pub fn connection(&self) -> u32 {
        self.connection.load(Relaxed)
    }

    pub fn set_connection(&self, s: ConnectionStatus) {
        self.connection.store(s as u32, Relaxed);
    }

    pub fn active_pid(&self) -> u64 {
        self.active_pid.load(Relaxed)
    }

    pub fn game_active(&self) -> bool {
        self.active_pid() != 0
    }

    /// `Some(pid)`: a game opened ldn:u. `None`: it left; clears the session view (C++ SetGameActive(false)).
    pub fn set_game(&self, pid: Option<u64>) {
        self.active_pid.store(pid.unwrap_or(0), Relaxed);
        if pid.is_none() {
            self.ldn_state.store(0, Relaxed);
            self.session.set(SessionInfoIpc::default());
        }
    }

    pub fn session_info(&self) -> SessionInfoIpc {
        self.session.get_val()
    }

    pub fn set_session_info(&self, info: SessionInfoIpc) {
        self.session.set(info);
    }

    pub fn transport_status(&self) -> [u8; TRANSPORT_STATUS_LEN] {
        self.transport.get_val()
    }

    /// Truncated to 63 bytes (always NUL-terminated for the overlay).
    pub fn set_transport_status(&self, s: &str) {
        let mut buf = [0u8; TRANSPORT_STATUS_LEN];
        let n = s.len().min(TRANSPORT_STATUS_LEN - 1);
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), s.as_bytes().get(..n)) {
            dst.copy_from_slice(src);
        }
        self.transport.set(buf);
    }

    /// May the ldn:u / bsd:u MITMs be registered this boot?
    pub fn ldn_services_allowed(&self) -> bool {
        !self.needs_restart.load(Relaxed)
            && !self.update_stand_down.load(Relaxed)
            && !self.fw_too_old.load(Relaxed)
    }

    /// Feeds a toast-worthy event (game start/exit, relay up/down, update staged).
    pub fn notify_event(&self, event: Event<'_>) {
        self.notifier.lock().on_event(event, uptime_ms());
    }

    /// Applies config.ini `[notifications]` (config_io keeps the stored copy).
    pub fn set_notify_config(&self, cfg: NotifyConfig) {
        self.notifier.lock().set_config(cfg);
    }

    /// A game uses the module: restarting it now would break the game's ldn:u / bsd:u.
    pub fn in_use(&self) -> bool {
        self.game_active() || self.mitm_sessions.load(Relaxed) != 0
    }

    /// `GetSetupStatus` (cfg 30): bit 0 needs_restart, bit 1 update rolled back this
    /// boot, bit 2 first boot of a new build, bit 3 a game uses the module (no restart).
    pub fn setup_status(&self) -> u32 {
        u32::from(self.needs_restart.load(Relaxed))
            | u32::from(self.update_stand_down.load(Relaxed)) << 1
            | u32::from(self.first_boot_of_build.load(Relaxed)) << 2
            | u32::from(self.in_use()) << 3
    }

    /// Next toast due now (notify_io drains this about once a second).
    pub fn poll_toast(&self) -> Option<Toast> {
        self.notifier.lock().poll(uptime_ms())
    }
}

/// Milliseconds since boot (system tick; 19.2 MHz on the Switch).
pub fn uptime_ms() -> u64 {
    // nx's get_system_tick_as_nanos divides by freq / 1e9, which is 0 here: not usable.
    let freq = nx::arm::get_system_tick_frequency().max(1);
    let t = u128::from(nx::arm::get_system_tick());
    u64::try_from(t.saturating_mul(1000).checked_div(u128::from(freq)).unwrap_or(0)).unwrap_or(u64::MAX)
}
