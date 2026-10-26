//! Client definitions for the two Horizon services nx does not wrap: `nifm` (for the DNS
//! servers of the current connection) and `time` (wall clock for certificate checks).
//! Command ids and layouts follow libnx (`nifm.c`, `time.c`) and switchbrew.
#![forbid(unsafe_code)]

use nx::ipc::sf::{self, ipc_trait, Request, Response};
use nx::ipc::sf::sm::ServiceName;
use nx::result::Result;
use nx::service::IService;

/// `IGeneralService::GetCurrentIpConfigInfo` out data, 0x16 bytes packed (libnx):
/// `{u8, u32 addr, u32 mask, u32 gateway}` then `{u8, u32 dns1, u32 dns2}`, addresses in
/// network byte order. Kept as bytes so nothing depends on packed-field alignment.
#[derive(Clone, Copy, Request, Response)]
#[repr(C)]
pub struct IpConfigInfo {
    pub raw: [u8; 0x16],
}

impl IpConfigInfo {
    /// Primary and secondary DNS server (0.0.0.0 when unset).
    pub fn dns(&self) -> [core::net::Ipv4Addr; 2] {
        let at = |o: usize| {
            let b = self.raw.get(o..o.saturating_add(4)).and_then(|s| <[u8; 4]>::try_from(s).ok()).unwrap_or_default();
            core::net::Ipv4Addr::from(b)
        };
        [at(0x0E), at(0x12)]
    }
}

/// `nifm:a` (what the C++ module used): `IStaticService`.
#[ipc_trait]
#[default_client]
pub trait NifmStatic {
    /// CreateGeneralService (3.0.0+): u64 reserved = the pid placeholder, sends the pid.
    #[ipc_rid(5)]
    #[return_session]
    fn create_general_service(&self, pid: sf::ProcessId) -> NifmGeneral;
}

#[ipc_trait]
#[default_client]
pub trait NifmGeneral {
    #[ipc_rid(15)]
    fn get_current_ip_config_info(&self) -> IpConfigInfo;
}

impl IService for NifmStatic {
    fn get_name() -> ServiceName {
        ServiceName::new("nifm:a")
    }
    fn as_domain() -> bool {
        false
    }
    fn post_initialize(&mut self) -> Result<()> {
        Ok(())
    }
}

/// `time:u`: `IStaticService`.
#[ipc_trait]
#[default_client]
pub trait TimeStatic {
    #[ipc_rid(0)]
    #[return_session]
    fn get_standard_user_system_clock(&self) -> SystemClock;
    #[ipc_rid(1)]
    #[return_session]
    fn get_standard_network_system_clock(&self) -> SystemClock;
}

/// `ISystemClock`.
#[ipc_trait]
#[default_client]
pub trait SystemClock {
    /// POSIX seconds.
    #[ipc_rid(0)]
    fn get_current_time(&self) -> i64;
}

impl IService for TimeStatic {
    fn get_name() -> ServiceName {
        ServiceName::new("time:u")
    }
    fn as_domain() -> bool {
        false
    }
    fn post_initialize(&mut self) -> Result<()> {
        Ok(())
    }
}
