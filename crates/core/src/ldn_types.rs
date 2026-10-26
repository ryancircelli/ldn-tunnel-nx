//! Nintendo LDN structures (the ones `wire.rs` lacks; the rest is re-exported from it,
//! one definition per struct) as the games see them through `ldn:u`
//! (switchbrew "LDN services"). Layouts and sizes match the C++ module's
//! `ldn_types.hpp`; each size is asserted at compile time.
//!
//! All types are plain bytes (`zerocopy`), so they can be copied straight to
//! and from IPC buffers and relay packets. C++ `__attribute__((packed))`
//! structs are `repr(C, packed)` here; the others are `repr(C)` and the
//! derives prove they have no padding.

use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub use crate::wire::{
    AddressEntry, AddressList, CommonNetworkInfo, IntentId, LdnNetworkInfo, MacAddress, NetworkConfig,
    NetworkId, NetworkInfo, NodeInfo, ScanFilterFull as ScanFilter, SecurityConfig, SecurityParameter,
    SessionId, Ssid, UserConfig,
};

macro_rules! size_assert {
    ($t:ty, $n:expr) => {
        const _: () = assert!(size_of::<$t>() == $n);
    };
}

// ---------------------------------------------------------------- enums

/// LDN communication state (`GetState` result).
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(u32)]
pub enum CommState {
    None = 0,
    Initialized = 1,
    AccessPoint = 2,
    AccessPointCreated = 3,
    Station = 4,
    StationConnected = 5,
    Error = 6,
}

impl CommState {
    pub const fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::None,
            1 => Self::Initialized,
            2 => Self::AccessPoint,
            3 => Self::AccessPointCreated,
            4 => Self::Station,
            5 => Self::StationConnected,
            6 => Self::Error,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Initialized => "Initialized",
            Self::AccessPoint => "AccessPoint",
            Self::AccessPointCreated => "AccessPointCreated",
            Self::Station => "Station",
            Self::StationConnected => "StationConnected",
            Self::Error => "Error",
        }
    }
}

/// Why the network went away (`GetDisconnectReason` result).
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(u32)]
pub enum DisconnectReason {
    None = 0,
    User = 1,
    SystemRequest = 2,
    DestroyedByUser = 3,
    DestroyedBySystem = 4,
    Rejected = 5,
    SignalLost = 6,
}

impl DisconnectReason {
    pub const fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::None,
            1 => Self::User,
            2 => Self::SystemRequest,
            3 => Self::DestroyedByUser,
            4 => Self::DestroyedBySystem,
            5 => Self::Rejected,
            6 => Self::SignalLost,
            _ => return None,
        })
    }
}

/// `NodeLatestUpdate::state_change` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(u8)]
pub enum NodeStateChange {
    None = 0,
    Connect = 1,
    Disconnect = 2,
    DisconnectAndConnect = 3,
}

/// Bits of `ScanFilter::flag`.
pub mod scan_filter_flag {
    pub const LOCAL_COMMUNICATION_ID: u32 = 1 << 0;
    pub const SESSION_ID: u32 = 1 << 1;
    pub const NETWORK_TYPE: u32 = 1 << 2;
    pub const SSID: u32 = 1 << 4;
    pub const SCENE_ID: u32 = 1 << 5;
    pub const INTENT_ID: u32 = LOCAL_COMMUNICATION_ID | SCENE_ID;
    pub const NETWORK_ID: u32 = INTENT_ID | SESSION_ID;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct CreateNetworkConfig {
    pub security_config: SecurityConfig,
    pub user_config: UserConfig,
    pub unk: [u8; 4],
    pub network_config: NetworkConfig,
}
size_assert!(CreateNetworkConfig, 152);

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ConnectNetworkData {
    pub security_config: SecurityConfig,
    pub user_config: UserConfig,
    pub local_communication_version: u32,
    pub option: u32,
}
size_assert!(ConnectNetworkData, 124);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct NodeLatestUpdate {
    pub state_change: u8,
    pub unk: [u8; 7],
}
size_assert!(NodeLatestUpdate, 8);

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct CreateNetworkPrivateConfig {
    pub security_config: SecurityConfig,
    pub security_parameter: SecurityParameter,
    pub user_config: UserConfig,
    pub unk: [u8; 4],
    pub network_config: NetworkConfig,
}
size_assert!(CreateNetworkPrivateConfig, 184);

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct ConnectPrivateData {
    pub security_config: SecurityConfig,
    pub security_parameter: SecurityParameter,
    pub user_config: UserConfig,
    pub local_communication_version: u32,
    pub option: u32,
    pub pad: [u8; 4],
    pub network_config: NetworkConfig,
}
size_assert!(ConnectPrivateData, 192);

/// C++ `NetworkInfo2NetworkConfig`.
pub fn network_info_to_config(info: &NetworkInfo) -> NetworkConfig {
    let ldn = info.ldn;
    NetworkConfig {
        intent_id: info.network_id.intent_id,
        channel: info.common.channel,
        node_count_max: ldn.node_count_max,
        reserved1: 0,
        local_communication_version: ldn.nodes.first().map_or(0, |n| n.local_communication_version),
        reserved2: [0; 10],
    }
}

/// C++ `NetworkInfo2SecurityParameter`.
pub fn network_info_to_security_parameter(info: &NetworkInfo) -> SecurityParameter {
    SecurityParameter { data: info.ldn.security_parameter, session_id: info.network_id.session_id.data }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::FromZeros;

    #[test]
    fn config_from_network_info() {
        let mut ni = NetworkInfo::new_zeroed();
        ni.ldn.node_count_max = 4;
        ni.common.channel = 6;
        let c = network_info_to_config(&ni);
        assert_eq!((c.node_count_max, { c.channel }), (4, 6));
        assert_eq!({ network_info_to_security_parameter(&ni).data }, [0; 16]);
    }
}
