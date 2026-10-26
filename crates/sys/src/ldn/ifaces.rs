//! nx interface definitions for `ldn:u` (MITM), `IUserLocalCommunicationService`
//! and `IClientProcessMonitor`. Command ids, buffer kinds and version gates
//! follow the C++ module (and switchbrew "LDN services"). The server objects
//! and command bodies are in service.rs and monitor.rs.
//!
//! Buffer mapping used (HIPC type bits in brackets):
//! - NetworkInfo out/in (C++ `LargeData`): fixed-size pointer buffer [0x1A / 0x19]
//! - Scan result array: auto-select out buffer [0x22]
//! - NodeLatestUpdate array: out pointer buffer [0x0A]
//! - SetAdvertiseData: auto-select in buffer [0x21]
//! - CreateNetworkPrivate address list: in pointer buffer [0x09]
//! - everything else is raw data. Scan: `channel` u16, 6 pad bytes, then `ScanFilter` at offset 8
//!   (the filter is 8-aligned in the SDK; hardware logs showed it read 6 bytes early at offset 2)

use ldn_tunnel_core::compat::LDN_SET_PROTOCOL;
use ldn_tunnel_core::ldn_types::{
    ConnectNetworkData, ConnectPrivateData, CreateNetworkConfig,
    CreateNetworkPrivateConfig, NetworkConfig, NetworkInfo, NodeLatestUpdate, ScanFilter,
    SecurityParameter,
};
use nx::ipc::sf::{self, ProcessId};
use nx::ipc::server::ServerContext;
use nx::ipc::{client, server, CommandContext, DataWalker};
use nx::result::Result;

use crate::compat;


/// Raw-data wrapper for a plain `Copy` struct from the core crate (orphan
/// rules stop us implementing nx's parameter traits on those directly).
/// `repr(transparent)`, so it aligns exactly like `T`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Raw<T: Copy>(pub T);

impl<T: Copy> client::RequestCommandParameter for Raw<T> {
    fn before_request_write(
        _raw: &Self,
        walker: &mut DataWalker,
        _ctx: &mut CommandContext,
    ) -> Result<()> {
        walker.advance::<T>();
        Ok(())
    }

    fn before_send_sync_request(
        raw: &Self,
        walker: &mut DataWalker,
        _ctx: &mut CommandContext,
    ) -> Result<()> {
        walker.advance_set(raw.0);
        Ok(())
    }
}

impl<T: Copy> client::ResponseCommandParameter<Raw<T>> for Raw<T> {
    fn after_response_read(walker: &mut DataWalker, _ctx: &mut CommandContext) -> Result<Self> {
        Ok(Self(walker.advance_get()))
    }
}

impl<T: Copy> server::RequestCommandParameter<'_, Raw<T>> for Raw<T> {
    fn after_request_read(ctx: &mut ServerContext<'_>) -> Result<Self> {
        Ok(Self(ctx.raw_data_walker.advance_get()))
    }
}

impl<T: Copy> server::ResponseCommandParameter for Raw<T> {
    type CarryState = ();

    fn before_response_write(_raw: &Self, ctx: &mut ServerContext) -> Result<()> {
        ctx.raw_data_walker.advance::<T>();
        Ok(())
    }

    fn after_response_write(raw: Self, _carry: (), ctx: &mut ServerContext) -> Result<()> {
        ctx.raw_data_walker.advance_set(raw.0);
        Ok(())
    }
}

/// `ldn:u` as seen through the MITM.
#[nx::ipc::sf::ipc_trait]
pub trait LdnMitmService {
    #[ipc_rid(0)]
    #[return_session]
    fn create_user_local_communication_service(&mut self) -> Communication;
    #[ipc_rid(1)]
    #[return_session]
    fn create_client_process_monitor(&mut self) -> ClientProcessMonitor;
}

/// `IUserLocalCommunicationService`.
#[nx::ipc::sf::ipc_trait]
#[default_client]
pub trait Communication {
    #[ipc_rid(0)]
    fn get_state(&mut self) -> u32;
    #[ipc_rid(1)]
    fn get_network_info(&mut self, out: sf::OutFixedPointerBuffer<'_, NetworkInfo>);
    #[ipc_rid(2)]
    fn get_ipv4_address(&mut self) -> (u32, u32);
    #[ipc_rid(3)]
    fn get_disconnect_reason(&mut self) -> u32;
    #[ipc_rid(4)]
    fn get_security_parameter(&mut self) -> Raw<SecurityParameter>;
    #[ipc_rid(5)]
    fn get_network_config(&mut self) -> Raw<NetworkConfig>;
    #[ipc_rid(100)]
    fn attach_state_change_event(&mut self) -> sf::CopyHandle;
    #[ipc_rid(101)]
    fn get_network_info_latest_update(
        &mut self,
        info: sf::OutFixedPointerBuffer<'_, NetworkInfo>,
        updates: sf::OutPointerBuffer<'_, NodeLatestUpdate>,
    );
    #[ipc_rid(102)]
    fn scan(
        &mut self,
        channel: u16,
        pad: Raw<[u8; 6]>,
        filter: Raw<ScanFilter>,
        networks: sf::OutAutoSelectBuffer<'_, NetworkInfo>,
    ) -> u32;
    #[ipc_rid(103)]
    fn scan_private(
        &mut self,
        channel: u16,
        pad: Raw<[u8; 6]>,
        filter: Raw<ScanFilter>,
        networks: sf::OutAutoSelectBuffer<'_, NetworkInfo>,
    ) -> u32;
    #[ipc_rid(104)]
    fn set_wireless_controller_restriction(&mut self);
    #[ipc_rid(106)]
    #[version(compat::since(LDN_SET_PROTOCOL))]
    fn set_protocol(&mut self, protocol: u32);
    #[ipc_rid(200)]
    fn open_access_point(&mut self);
    #[ipc_rid(201)]
    fn close_access_point(&mut self);
    #[ipc_rid(202)]
    fn create_network(&mut self, config: Raw<CreateNetworkConfig>);
    #[ipc_rid(203)]
    fn create_network_private(
        &mut self,
        config: Raw<CreateNetworkPrivateConfig>,
        // libnx sends count * 0xC bytes, not the full 8-entry list: take bytes.
        addresses: sf::InPointerBuffer<'_, u8>,
    );
    #[ipc_rid(204)]
    fn destroy_network(&mut self);
    #[ipc_rid(205)]
    fn reject(&mut self, node_id: u32);
    #[ipc_rid(206)]
    fn set_advertise_data(&mut self, data: sf::InAutoSelectBuffer<'_, u8>);
    #[ipc_rid(207)]
    fn set_station_accept_policy(&mut self, policy: u8);
    #[ipc_rid(208)]
    fn add_accept_filter_entry(&mut self);
    #[ipc_rid(209)]
    fn clear_accept_filter(&mut self);
    #[ipc_rid(300)]
    fn open_station(&mut self);
    #[ipc_rid(301)]
    fn close_station(&mut self);
    #[ipc_rid(302)]
    fn connect(
        &mut self,
        data: Raw<ConnectNetworkData>,
        network: sf::InFixedPointerBuffer<'_, NetworkInfo>,
    );
    #[ipc_rid(303)]
    fn connect_private(&mut self, data: Raw<ConnectPrivateData>);
    #[ipc_rid(304)]
    fn disconnect(&mut self);
    #[ipc_rid(400)]
    fn initialize(&mut self, process_id: ProcessId);
    #[ipc_rid(401)]
    fn finalize(&mut self);
    #[ipc_rid(402)]
    fn initialize_system2(&mut self, unk: u64, process_id: ProcessId);
}

/// `IClientProcessMonitor` (FW 18.0.0+ games register through it).
#[nx::ipc::sf::ipc_trait]
#[default_client]
pub trait ClientProcessMonitor {
    #[ipc_rid(0)]
    fn register_client(&mut self, process_id: ProcessId);
}
