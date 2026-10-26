//! Every name that changes on a rename lives here and nowhere else.
//! (The overlay (overlay/source) and the relay (relay/src/core/invite.ts) keep their own copies.)

/// Package / crate / config-dir name.
pub const NAME: &str = "ldn-tunnel";
/// Atmosphere program id of the sysmodule (contents/<PROGRAM_ID_HEX>/).
pub const PROGRAM_ID_HEX: &str = "420000004C444E54";
pub const CONFIG_DIR: &str = "sdmc:/config/ldn-tunnel";
pub const CONFIG_PATH: &str = "sdmc:/config/ldn-tunnel/config.ini";
pub const GAMELIST_PATH: &str = "sdmc:/config/ldn-tunnel/gamelist.txt";
pub const LOG_PATH: &str = "sdmc:/config/ldn-tunnel/ldn-tunnel.log";
pub const UPDATE_STATE_DIR: &str = "sdmc:/config/ldn-tunnel/update";
pub const EXEFS_PATH: &str = "sdmc:/atmosphere/contents/420000004C444E54/exefs.nsp";
pub const OVERLAY_PATH: &str = "sdmc:/switch/.overlays/ldn-tunnel.ovl";
/// Custom IPC service the overlay talks to (sm names are at most 8 bytes).
pub const CFG_SERVICE: &str = "ldnt:cfg";
/// Value of UpdateCheckRequest.reserved[0]: tells the relay which module asks
/// (0 = the C++ ryu_ldn_nx, which always sends zero).
pub const UPDATE_MODULE_ID: u8 = 1;
