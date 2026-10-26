//! Wall-clock time for certificate validity, from Horizon's `time:u` service.
#![forbid(unsafe_code)]

use nx::service::new_service_object;

use super::ipc::{ISystemClockClient, ITimeStaticClient, TimeStatic};

/// 2024-01-01: anything earlier is a clock that was never set (a fresh console counts
/// from 2000-ish), and every certificate check against it fails with `NotValidYet`.
const PLAUSIBLE: i64 = 1_704_067_200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The network clock (NTP-synced by the system).
    Network,
    /// The user clock (set by hand, or synced from the network if that option is on).
    User,
}

/// Unix seconds for the TLS handshake: the user clock (the one System Settings shows, which
/// the owner can check and fix), else the network clock. The network clock can be plausible
/// but stale on consoles that never reach Nintendo's time server. `None` when neither gives a
/// plausible time: TLS would fail, so the caller logs that and waits.
pub fn unix_now() -> Option<(u64, Source)> {
    let svc = new_service_object::<TimeStatic>().ok()?;
    let read = |net: bool| {
        let clock = if net {
            svc.get_standard_network_system_clock()
        } else {
            svc.get_standard_user_system_clock()
        };
        clock.and_then(|c| c.get_current_time()).ok().filter(|&t| t >= PLAUSIBLE)
    };
    let (t, src) = match read(false) {
        Some(t) => (t, Source::User),
        None => (read(true)?, Source::Network),
    };
    Some((t as u64, src))
}
