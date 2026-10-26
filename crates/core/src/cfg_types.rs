//! Wire types of the `ldnt:cfg` service the overlay talks to.
//!
//! Command ids are the C++ `ryu:cfg` ids, kept so the overlay's IPC client
//! only changes its service name:
//!
//! | id | command            | reply                   |
//! |----|--------------------|-------------------------|
//! | 0  | GetVersion         | `[u8; 32]`              |
//! | 1  | GetConnectionStatus| `u32` ([`ConnectionStatus`]) |
//! | 2  | IsServiceActive    | `u32`                   |
//! | 3  | IsGameActive       | `u32`                   |
//! | 4  | GetLdnState        | `u32` (`CommState`)     |
//! | 5  | GetSessionInfo     | [`SessionInfoIpc`]      |
//! | 8  | GetActiveProcessId | `u64`                   |
//! | 9  | GetDebugEnabled    | `u32`                   |
//! | 10 | SetDebugEnabled    | in `u32`                |
//! | 11 | GetDebugLevel      | `u32`                   |
//! | 12 | SetDebugLevel      | in `u32`                |
//! | 13 | SaveConfig         | [`ConfigResult`]        |
//! | 14 | ReloadConfig       | [`ConfigResult`]        |
//! | 15 | GetServerAddress   | [`ServerAddressIpc`]    |
//! | 16 | SetServerAddress   | in [`ServerAddressIpc`] |
//! | 17 | GetLdnEnabled      | `u32`                   |
//! | 18 | SetLdnEnabled      | in `u32`                |
//! | 25 | GetTransportStatus | `[u8; 64]`              |
//! | 26 | GetUpdateStatus    | [`UpdateStatusIpc`]     |
//! | 27 | CheckForUpdates    | -                       |
//! | 28 | GetNotifyFlags     | `u32`: bit 0 updates, 1 game_start, 2 connection (`NotifyConfig::bits`) |
//! | 29 | SetNotifyFlags     | in `u32` (unknown bits ignored; persisted by SaveConfig) |
//! | 30 | GetSetupStatus     | `u32`: bit 0 needs_restart, 1 update rolled back this boot, 2 first boot of a new build, 3 a game uses the module |
//! | 31 | PrepareRestart     | - ; takes our MITMs and `ldnt:cfg` off sm so pm may terminate the module. Fails with 0x183BAF (module 431, desc 3101) while a game uses it (bit 3) |
//!
//! RESERVED, never reused and not served: 6 (GetLastRtt), 7 (ForceReconnect),
//! 19/20 (Get/SetDisableP2p), 21-24 (Get/SetUsePassphrase, Get/SetPassphrase).
//! They return an unknown-command error.

use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// `sm` session limit of the service (the overlay holds one).
pub const CFG_MAX_SESSIONS: i32 = 2;
pub const VERSION_LEN: usize = 32;
pub const TRANSPORT_STATUS_LEN: usize = 64;
pub const HOST_LEN: usize = 64;

/// Notification toggles as a `u32` bitmask (`[notifications]` in config.ini,
/// `notify::NotifyConfig::bits`), for Get/SetNotifyFlags (28/29). Unknown bits
/// are ignored on set and zero on get.
pub const NOTIFY_UPDATES: u32 = 1 << 0;
pub const NOTIFY_GAME_START: u32 = 1 << 1;
pub const NOTIFY_CONNECTION: u32 = 1 << 2;

/// Command ids of the table above, for the overlay's client (crates/overlay). The module's
/// `#[ipc_rid]`s (crates/sys/src/cfg/ifaces.rs) are checked against these in crates/ipc-tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Cmd {
    GetVersion = 0,
    GetConnectionStatus = 1,
    IsServiceActive = 2,
    IsGameActive = 3,
    GetLdnState = 4,
    GetSessionInfo = 5,
    GetActiveProcessId = 8,
    GetDebugEnabled = 9,
    SetDebugEnabled = 10,
    GetDebugLevel = 11,
    SetDebugLevel = 12,
    SaveConfig = 13,
    ReloadConfig = 14,
    GetServerAddress = 15,
    SetServerAddress = 16,
    GetLdnEnabled = 17,
    SetLdnEnabled = 18,
    GetTransportStatus = 25,
    GetUpdateStatus = 26,
    CheckForUpdates = 27,
    GetNotifyFlags = 28,
    SetNotifyFlags = 29,
    GetSetupStatus = 30,
    PrepareRestart = 31,
}

/// GetSetupStatus (30) bits (crates/sys/src/state.rs `setup_status`).
pub const SETUP_NEEDS_RESTART: u32 = 1 << 0;
pub const SETUP_ROLLED_BACK: u32 = 1 << 1;
pub const SETUP_NEW_BUILD: u32 = 1 << 2;
pub const SETUP_BUSY: u32 = 1 << 3;

/// PrepareRestart (31) while a game uses the module: module 431, description 3101
/// (crates/sys/src/cfg/service.rs `RESULT_IN_USE`).
pub const RC_BUSY: u32 = 431 | (3101 << 9);
const _: () = assert!(RC_BUSY == 0x183BAF);

/// Relay connection state shown by the overlay (`GetConnectionStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(u32)]
pub enum ConnectionStatus {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Ready = 3,
    Error = 4,
}

/// Result of SaveConfig / ReloadConfig.
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(u32)]
pub enum ConfigResult {
    Success = 0,
    FileNotFound = 1,
    ParseError = 2,
    IoError = 3,
    InvalidValue = 4,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct SessionInfoIpc {
    pub node_count: u8,
    pub max_nodes: u8,
    pub local_node_id: u8,
    pub is_host: u8,
    pub reserved: [u8; 4],
}
const _: () = assert!(size_of::<SessionInfoIpc>() == 8);

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ServerAddressIpc {
    pub host: [u8; HOST_LEN],
    pub port: u16,
    pub padding: u16,
}
const _: () = assert!(size_of::<ServerAddressIpc>() == 68);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct UpdateStatusIpc {
    /// 0 = developer build.
    pub running_build: u32,
    /// Installed, waiting for a restart (0 = none).
    pub staged_build: u32,
    /// Build the last rollback removed (0 = none).
    pub rejected_build: u32,
    pub on_probation: u8,
    pub rolled_back: u8,
    /// 0 off, 1 stable, 2 test.
    pub channel: u8,
    /// 0 idle, 1 checking, 2 last check failed.
    pub check_state: u8,
    /// NUL-padded running version.
    pub version: [u8; 31],
    /// 0 = not downloading, else percent + 1.
    pub download: u8,
}
const _: () = assert!(size_of::<UpdateStatusIpc>() == 48);
