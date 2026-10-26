//! Boot-time firmware / Atmosphère detection. The decisions themselves are in
//! `ldn_tunnel_core::compat`; docs/compatibility.md says how to add a new firmware.
#![forbid(unsafe_code)]

use alloc::format;

use ldn_tunnel_core::compat::{self, Atmosphere, Support, Ver};
use nx::ipc::sf::ipc_trait;
use nx::ipc::sf::sm::ServiceName;
use nx::result::Result;
use nx::service::{IService, new_service_object};
use nx::version::{Version, VersionInterval};

use crate::state::STATE;

/// spl GetConfig item that Atmosphère's secure monitor answers (libstratosphere spl_types.hpp).
const EXOSPHERE_API_VERSION: u32 = 65000;

/// `spl:` (`IGeneralInterface`), only for Atmosphère's version.
#[ipc_trait]
#[default_client]
pub trait Spl {
    #[ipc_rid(0)]
    fn get_config(&self, item: u32) -> u64;
}

impl IService for Spl {
    fn get_name() -> ServiceName {
        ServiceName::new("spl:")
    }
    fn as_domain() -> bool {
        false
    }
    fn post_initialize(&mut self) -> Result<()> {
        Ok(())
    }
}

const fn nx_ver(v: Ver) -> Version {
    Version::new(v.0, v.1, v.2)
}

/// An nx `#[version(..)]` gate: `v` and later.
pub const fn since(v: Ver) -> VersionInterval {
    VersionInterval::from(nx_ver(v))
}

/// The running firmware (nx reads it from set:sys at process start).
fn hos() -> Ver {
    let v = nx::version::get_version();
    (v.major, v.minor, v.micro)
}

fn atmosphere() -> Option<Atmosphere> {
    let spl = new_service_object::<Spl>().ok()?;
    spl.get_config(EXOSPHERE_API_VERSION).ok().map(compat::atmosphere)
}

/// Logs the versions and turns the MITMs off on firmware below `compat::MIN_HOS`.
pub fn check() {
    let hos = hos();
    match atmosphere() {
        Some(a) => log!(
            Info,
            "compat: HOS {}, Atmosphere {} (target {})",
            nx_ver(hos),
            nx_ver(a.version),
            nx_ver(a.target)
        ),
        // ponytail: warn only; sm refuses the MITM registration itself without Atmosphère.
        None => log!(Warning, "compat: HOS {}, Atmosphere not detected", nx_ver(hos)),
    }
    match compat::support(hos) {
        Support::Tested => {}
        Support::Untested => log!(
            Warning,
            "compat: firmware newer than tested ({}.x); running anyway",
            compat::TESTED_HOS_MAJOR
        ),
        Support::TooOld => {
            let min = nx_ver(compat::MIN_HOS);
            log!(Error, "compat: firmware below {min}: ldn:u/bsd:u stay off");
            STATE.fw_too_old.store(true, core::sync::atomic::Ordering::Relaxed);
            STATE.set_transport_status(&format!("Firmware too old (needs {min}+)"));
        }
    }
}
