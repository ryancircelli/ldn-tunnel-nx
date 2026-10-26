//! nx interface definition of `ldnt:cfg` (command ids from the C++ `ryu:cfg`;
//! ids 6, 7 and 19-24 are reserved, see `ldn_tunnel_core::cfg_types`).
//! 28-30 (Get/SetNotifyFlags, GetSetupStatus) are new in ldn-tunnel (docs/notifications.md),
//! 31 (PrepareRestart) too.
//! Bodies: `super::service`.

use ldn_tunnel_core::cfg_types::{
    CFG_MAX_SESSIONS, ConfigResult, ServerAddressIpc, SessionInfoIpc, TRANSPORT_STATUS_LEN,
    UpdateStatusIpc, VERSION_LEN,
};
use ldn_tunnel_core::ident::CFG_SERVICE;
use nx::ipc::sf::sm::ServiceName;
use nx::ipc::server::{IServerObject, IService, ISessionObject, ServerContext};
use nx::ipc::CommandProtocol;
use nx::result::Result;

use crate::ldn::ifaces::Raw;

/// ipc_trait return types must be paths, hence the aliases.
pub type VersionBuf = [u8; VERSION_LEN];
pub type TransportStatusBuf = [u8; TRANSPORT_STATUS_LEN];

#[nx::ipc::sf::ipc_trait]
pub trait CfgService {
    #[ipc_rid(0)]
    fn get_version(&mut self) -> VersionBuf;
    #[ipc_rid(1)]
    fn get_connection_status(&mut self) -> u32;
    #[ipc_rid(2)]
    fn is_service_active(&mut self) -> u32;
    #[ipc_rid(3)]
    fn is_game_active(&mut self) -> u32;
    #[ipc_rid(4)]
    fn get_ldn_state(&mut self) -> u32;
    #[ipc_rid(5)]
    fn get_session_info(&mut self) -> Raw<SessionInfoIpc>;
    #[ipc_rid(8)]
    fn get_active_process_id(&mut self) -> u64;
    #[ipc_rid(9)]
    fn get_debug_enabled(&mut self) -> u32;
    #[ipc_rid(10)]
    fn set_debug_enabled(&mut self, enabled: u32);
    #[ipc_rid(11)]
    fn get_debug_level(&mut self) -> u32;
    #[ipc_rid(12)]
    fn set_debug_level(&mut self, level: u32);
    #[ipc_rid(13)]
    fn save_config(&mut self) -> Raw<ConfigResult>;
    #[ipc_rid(14)]
    fn reload_config(&mut self) -> Raw<ConfigResult>;
    #[ipc_rid(15)]
    fn get_server_address(&mut self) -> Raw<ServerAddressIpc>;
    #[ipc_rid(16)]
    fn set_server_address(&mut self, address: Raw<ServerAddressIpc>);
    #[ipc_rid(17)]
    fn get_ldn_enabled(&mut self) -> u32;
    #[ipc_rid(18)]
    fn set_ldn_enabled(&mut self, enabled: u32);
    #[ipc_rid(25)]
    fn get_transport_status(&mut self) -> TransportStatusBuf;
    #[ipc_rid(26)]
    fn get_update_status(&mut self) -> Raw<UpdateStatusIpc>;
    #[ipc_rid(27)]
    fn check_for_updates(&mut self);
    /// Bit 0 updates, bit 1 game_start, bit 2 connection (`NotifyConfig::bits`).
    #[ipc_rid(28)]
    fn get_notify_flags(&mut self) -> u32;
    /// Unknown bits are ignored. In memory until SaveConfig.
    #[ipc_rid(29)]
    fn set_notify_flags(&mut self, flags: u32);
    /// Bit 0 needs_restart, bit 1 update rolled back this boot, bit 2 first boot of a new
    /// build, bit 3 a game uses the module (PrepareRestart would refuse).
    #[ipc_rid(30)]
    fn get_setup_status(&mut self) -> u32;
    /// Call before pm terminates the module: takes our ldn:u / bsd:u MITMs and ldnt:cfg off
    /// sm. Fails (busy) while a game uses the module. See `service::prepare_restart`.
    #[ipc_rid(31)]
    fn prepare_restart(&mut self);
}

/// One session of the overlay.
#[derive(Default)]
pub struct Cfg;

impl ISessionObject for Cfg {
    fn try_handle_request_by_id(
        &mut self,
        req_id: u32,
        protocol: CommandProtocol,
        ctx: &mut ServerContext,
    ) -> Option<Result<()>> {
        <Self as ICfgServiceServer>::try_handle_request_by_id(self, req_id, protocol, ctx)
    }
}

impl IServerObject for Cfg {
    fn new() -> Self {
        Self
    }
}

impl IService for Cfg {
    fn get_name() -> ServiceName {
        ServiceName::new(CFG_SERVICE)
    }

    fn get_max_sesssions() -> i32 {
        CFG_MAX_SESSIONS
    }
}
