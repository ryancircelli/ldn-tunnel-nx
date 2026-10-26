//! Client side of `ldnt:cfg`: one function per command, ids and layouts from
//! `ldn_tunnel_core::cfg_types` (the module serves the same types). The bytes go through
//! [`Dispatch`]: libnx `serviceDispatchImpl` on the console (overlay/source/platform.c),
//! the real server object in crates/ipc-tests.

use ldn_tunnel_core::cfg_types::{
    Cmd, ConfigResult, HOST_LEN, ServerAddressIpc, SessionInfoIpc, TRANSPORT_STATUS_LEN,
    UpdateStatusIpc, VERSION_LEN,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// A Horizon result code; 0 is success.
pub type Rc = u32;

/// One CMIF request: `input` as the raw data, the reply's raw data into `out`.
pub trait Dispatch {
    fn dispatch(&mut self, cmd: u32, input: &[u8], out: &mut [u8]) -> Rc;
}

fn get<T: FromBytes + IntoBytes, D: Dispatch + ?Sized>(d: &mut D, cmd: Cmd) -> Result<T, Rc> {
    let mut v = T::new_zeroed();
    match d.dispatch(cmd as u32, &[], v.as_mut_bytes()) {
        0 => Ok(v),
        rc => Err(rc),
    }
}

fn send<T: IntoBytes + Immutable, D: Dispatch + ?Sized>(
    d: &mut D,
    cmd: Cmd,
    v: &T,
) -> Result<(), Rc> {
    match d.dispatch(cmd as u32, v.as_bytes(), &mut []) {
        0 => Ok(()),
        rc => Err(rc),
    }
}

/// NUL-terminated whatever the module sent.
fn terminated<const N: usize>(mut s: [u8; N]) -> [u8; N] {
    if let Some(last) = s.last_mut() {
        *last = 0;
    }
    s
}

pub fn version<D: Dispatch + ?Sized>(d: &mut D) -> Result<[u8; VERSION_LEN], Rc> {
    get(d, Cmd::GetVersion).map(terminated)
}
/// Raw `ConnectionStatus`.
pub fn connection_status<D: Dispatch + ?Sized>(d: &mut D) -> Result<u32, Rc> {
    get(d, Cmd::GetConnectionStatus)
}
pub fn is_game_active<D: Dispatch + ?Sized>(d: &mut D) -> Result<bool, Rc> {
    get::<u32, _>(d, Cmd::IsGameActive).map(|v| v != 0)
}
/// Raw `CommState`.
pub fn ldn_state<D: Dispatch + ?Sized>(d: &mut D) -> Result<u32, Rc> {
    get(d, Cmd::GetLdnState)
}
pub fn session_info<D: Dispatch + ?Sized>(d: &mut D) -> Result<SessionInfoIpc, Rc> {
    get(d, Cmd::GetSessionInfo)
}
pub fn debug_enabled<D: Dispatch + ?Sized>(d: &mut D) -> Result<bool, Rc> {
    get::<u32, _>(d, Cmd::GetDebugEnabled).map(|v| v != 0)
}
pub fn set_debug_enabled<D: Dispatch + ?Sized>(d: &mut D, on: bool) -> Result<(), Rc> {
    send(d, Cmd::SetDebugEnabled, &u32::from(on))
}
pub fn debug_level<D: Dispatch + ?Sized>(d: &mut D) -> Result<u32, Rc> {
    get(d, Cmd::GetDebugLevel)
}
pub fn set_debug_level<D: Dispatch + ?Sized>(d: &mut D, level: u32) -> Result<(), Rc> {
    send(d, Cmd::SetDebugLevel, &level)
}
/// Ok(true) when the module wrote config.ini.
pub fn save_config<D: Dispatch + ?Sized>(d: &mut D) -> Result<bool, Rc> {
    get::<u32, _>(d, Cmd::SaveConfig).map(|r| r == ConfigResult::Success as u32)
}
/// Ok(true) when the module read config.ini.
pub fn reload_config<D: Dispatch + ?Sized>(d: &mut D) -> Result<bool, Rc> {
    get::<u32, _>(d, Cmd::ReloadConfig).map(|r| r == ConfigResult::Success as u32)
}
pub fn server_address<D: Dispatch + ?Sized>(d: &mut D) -> Result<ServerAddressIpc, Rc> {
    get::<ServerAddressIpc, _>(d, Cmd::GetServerAddress).map(|mut a| {
        a.host = terminated::<HOST_LEN>(a.host);
        a
    })
}
pub fn ldn_enabled<D: Dispatch + ?Sized>(d: &mut D) -> Result<bool, Rc> {
    get::<u32, _>(d, Cmd::GetLdnEnabled).map(|v| v != 0)
}
pub fn set_ldn_enabled<D: Dispatch + ?Sized>(d: &mut D, on: bool) -> Result<(), Rc> {
    send(d, Cmd::SetLdnEnabled, &u32::from(on))
}
/// Relay link state or failure reason; never the token.
pub fn transport_status<D: Dispatch + ?Sized>(d: &mut D) -> Result<[u8; TRANSPORT_STATUS_LEN], Rc> {
    get(d, Cmd::GetTransportStatus).map(terminated)
}
pub fn update_status<D: Dispatch + ?Sized>(d: &mut D) -> Result<UpdateStatusIpc, Rc> {
    get::<UpdateStatusIpc, _>(d, Cmd::GetUpdateStatus).map(|mut s| {
        s.version = terminated(s.version);
        s
    })
}
pub fn check_for_updates<D: Dispatch + ?Sized>(d: &mut D) -> Result<(), Rc> {
    send(d, Cmd::CheckForUpdates, &())
}
/// `cfg_types::NOTIFY_*` bits; errors on a module without notifications.
pub fn notify_flags<D: Dispatch + ?Sized>(d: &mut D) -> Result<u32, Rc> {
    get(d, Cmd::GetNotifyFlags)
}
pub fn set_notify_flags<D: Dispatch + ?Sized>(d: &mut D, flags: u32) -> Result<(), Rc> {
    send(d, Cmd::SetNotifyFlags, &flags)
}
/// `cfg_types::SETUP_*` bits.
pub fn setup_status<D: Dispatch + ?Sized>(d: &mut D) -> Result<u32, Rc> {
    get(d, Cmd::GetSetupStatus)
}
/// Takes our MITMs and ldnt:cfg off sm; `cfg_types::RC_BUSY` while a game uses the module.
pub fn prepare_restart<D: Dispatch + ?Sized>(d: &mut D) -> Result<(), Rc> {
    send(d, Cmd::PrepareRestart, &())
}
