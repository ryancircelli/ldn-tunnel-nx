//! The Horizon-free decision of the `ldn:u` shell (crates/sys/src/ldn), here
//! so it runs under `cargo test`.

use crate::notify::LdnMode;

/// What a whitelisted game gets when it opens `ldn:u`. `keys_held` are the
/// buttons held at launch (Atmosphere's override status, `MitmProcessInfo`);
/// `button_mask` is `[ldn] real_wireless_button` (0 = never bypass), all held.
pub fn launch_mode(enabled: bool, button_mask: u64, keys_held: u64) -> LdnMode {
    if !enabled {
        LdnMode::Disabled
    } else if button_mask != 0 && keys_held & button_mask == button_mask {
        LdnMode::Bypass
    } else {
        LdnMode::Online
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_mode_needs_every_button_of_the_mask() {
        const ZR: u64 = 1 << 9;
        const ZL: u64 = 1 << 8;
        assert_eq!(launch_mode(true, ZR, ZR), LdnMode::Bypass);
        assert_eq!(launch_mode(true, ZR, ZR | ZL), LdnMode::Bypass);
        assert_eq!(launch_mode(true, ZR | ZL, ZR), LdnMode::Online);
        assert_eq!(launch_mode(true, 0, u64::MAX), LdnMode::Online);
        assert_eq!(launch_mode(false, ZR, ZR), LdnMode::Disabled);
    }
}
