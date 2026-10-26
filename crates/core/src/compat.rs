//! Horizon firmware / Atmosphère compatibility: every version-dependent decision of the
//! module, in one place. Detection runs at boot in `crates/sys/src/compat.rs`;
//! docs/compatibility.md says how to add a new firmware.
//!
//! Versions are `(major, minor, micro)` tuples, which compare in that order.

/// A Horizon or Atmosphère version.
pub type Ver = (u8, u8, u8);

/// Lowest firmware the MITMs install on. Below 12.0.0 sm speaks CMIF instead of TIPC
/// (switchbrew "Services API"). nx keeps a CMIF path, but every IPC fix in
/// docs/nx-patches was written and run against TIPC sm only.
pub const MIN_HOS: Ver = (12, 0, 0);

/// Newest firmware major run on hardware (docs/testing.md). Newer runs, with a warning.
pub const TESTED_HOS_MAJOR: u8 = 23;

/// ldn:u `IUserLocalCommunicationService` 106 SetProtocol, 18.0.0+ (switchbrew "LDN services").
pub const LDN_SET_PROTOCOL: Ver = (18, 0, 0);

/// bsd:u 33 RegisterClientShared (RegisterClient without transfer memory), 10.0.0+.
pub const BSD_REGISTER_CLIENT_SHARED: Ver = (10, 0, 0);

/// How the module treats the running firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    /// Below [`MIN_HOS`]: the MITMs stay off, the console runs untouched.
    TooOld,
    /// Within the tested range.
    Tested,
    /// Newer than [`TESTED_HOS_MAJOR`]: runs, logs a warning.
    Untested,
}

pub fn support(hos: Ver) -> Support {
    if hos < MIN_HOS {
        Support::TooOld
    } else if hos.0 > TESTED_HOS_MAJOR {
        Support::Untested
    } else {
        Support::Tested
    }
}

/// Atmosphère's version and the firmware it was told it runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Atmosphere {
    pub version: Ver,
    pub target: Ver,
}

/// Decodes spl GetConfig(ExosphereApiVersion = 65000): Atmosphère `ApiInfo`
/// (libstratosphere ams_types.hpp): bits 56/48/40 major/minor/micro, 32 master key,
/// 0-31 target firmware as `major << 24 | minor << 16 | micro << 8 | relstep`.
pub fn atmosphere(api_info: u64) -> Atmosphere {
    let [major, minor, micro, _key, t_major, t_minor, t_micro, _relstep] = api_info.to_be_bytes();
    Atmosphere { version: (major, minor, micro), target: (t_major, t_minor, t_micro) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_range() {
        assert_eq!(support((11, 0, 1)), Support::TooOld);
        assert_eq!(support((12, 0, 0)), Support::Tested);
        assert_eq!(support((23, 0, 1)), Support::Tested);
        assert_eq!(support((24, 0, 0)), Support::Untested);
    }

    #[test]
    fn decodes_atmosphere_api_info() {
        // Atmosphère 1.12.1, master key 0x13, target 23.0.1 relstep 0.
        let raw = 0x01_0C_01_13_17_00_01_00u64;
        assert_eq!(atmosphere(raw), Atmosphere { version: (1, 12, 1), target: (23, 0, 1) });
    }
}
