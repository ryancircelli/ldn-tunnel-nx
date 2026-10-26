//! The console's own IP address from `nifm:u` (nx has no nifm client): the
//! GetIpv4Address fallback and the "online?" check, as the C++ module did
//! with libnx's nifmGetCurrentIpConfigInfo.
//!
//! Never call it from ShouldMitm: opening the service goes through sm, and sm
//! is blocked waiting for our ShouldMitm answer.
#![forbid(unsafe_code)]

use nx::ipc::sf::{ProcessId, sm};
use nx::result::Result;
use nx::service;
use nx::sync::Mutex;

use super::ifaces::Raw;

/// `IpAddressSetting` + `DnsSetting`, packed (0x16 bytes), as nifm returns them.
/// Addresses are in network byte order.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct IpConfigInfo {
    is_automatic: u8,
    address: u32,
    subnet_mask: u32,
    gateway: u32,
    dns_is_automatic: u8,
    primary_dns: u32,
    secondary_dns: u32,
}
const _: () = assert!(size_of::<IpConfigInfo>() == 0x16);

#[nx::ipc::sf::ipc_trait]
#[default_client]
pub trait NifmUser {
    /// CreateGeneralService (3.0.0+): a reserved u64 (the pid placeholder) + send-pid.
    #[ipc_rid(5)]
    #[return_session]
    fn create_general_service(&self, process_id: ProcessId) -> NifmGeneral;
}

#[nx::ipc::sf::ipc_trait]
#[default_client]
pub trait NifmGeneral {
    #[ipc_rid(15)]
    fn get_current_ip_config_info(&self) -> Raw<IpConfigInfo>;
}

impl service::IService for NifmUser {
    fn get_name() -> sm::ServiceName {
        sm::ServiceName::new("nifm:u")
    }

    fn as_domain() -> bool {
        false
    }

    fn post_initialize(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Opened by [`open`] before the ldn:u MITM installs and kept for good; reopened only
/// after a session (kernel) error.
static GENERAL: Mutex<Option<NifmGeneral>> = Mutex::new(None);

/// Kernel result module: the session itself failed, not nifm's answer.
const KERNEL_MODULE: u32 = 1;

/// Opens the nifm session. Call on the ldn:u thread before it installs its MITM: an sm call
/// from that thread once installed can deadlock with sm's ShouldMitm query to it
/// (nx `ServerManager::mitm_sm`).
pub fn open() -> Result<()> {
    let mut g = GENERAL.lock();
    if g.is_none() {
        *g = Some(service::new_service_object::<NifmUser>()?.create_general_service(ProcessId::new())?);
    }
    Ok(())
}

/// `(address, mask)` in Ryujinx format (big-endian read as u32, like the
/// session's), or nifm's error (no network: nifm fails the call).
pub fn current_ip() -> Result<(u32, u32)> {
    let mut g = GENERAL.lock();
    let general = match g.take() {
        Some(general) => general,
        // ponytail: sm call on the ldn:u thread (see `open`); only after a kernel error.
        None => service::new_service_object::<NifmUser>()?.create_general_service(ProcessId::new())?,
    };
    let r = general.get_current_ip_config_info();
    // nifm's own errors ("no network") keep the session; a dead session is dropped.
    if !matches!(&r, Err(rc) if rc.get_module() == KERNEL_MODULE) {
        *g = Some(general);
    }
    let Raw(info) = r?;
    Ok((u32::from_be(info.address), u32::from_be(info.subnet_mask)))
}
