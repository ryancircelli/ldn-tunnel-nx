//! Plain-language text for the module's status values (was overlay/source/utils/formatters.hpp
//! and the snprintf calls of the dashboard). Values shown in a MiniListItem stay short
//! (~20 characters): a long value leaves the whole row blank.

use core::fmt::Write as _;

use heapless::String;
use ldn_tunnel_core::cfg_types::{
    ConnectionStatus, SETUP_NEEDS_RESTART, SETUP_ROLLED_BACK, SessionInfoIpc, UpdateStatusIpc,
};
use ldn_tunnel_core::ldn_types::CommState;

/// RGB888 hex for tsl::RGB888.
pub type Color = &'static str;
pub const WHITE: Color = "FFFFFF";
pub const GREEN: Color = "00FF00";
pub const YELLOW: Color = "FFFF00";
pub const ORANGE: Color = "FFAA00";
pub const RED: Color = "FF4444";
pub const GREY: Color = "888888";

/// Row text plus its color.
pub type Status = (&'static str, Color);

/// The bytes before the first NUL.
pub fn c_str(s: &[u8]) -> &[u8] {
    s.split(|&b| b == 0).next().unwrap_or(s)
}

/// Relay row: GetConnectionStatus plus GetTransportStatus, which holds the failure reason while
/// the link is down (crates/sys/src/relay_thread.rs open() and status(), crates/sys/src/main.rs).
/// Unknown reasons fall back to the status. `online`: false when the console has no IP address.
pub fn relay(status: u32, transport: &[u8], online: bool) -> Status {
    const REASONS: [(&str, Status); 9] = [
        ("Restart once to finish setup", ("Restart needed", ORANGE)),
        ("Server not configured", ("No invite installed", RED)),
        ("Rejected: check token", ("Invite rejected", RED)),
        ("Waiting for network time", ("Syncing clock...", YELLOW)),
        ("DNS failed", ("Relay not found", RED)),
        ("TCP connect failed", ("Relay unreachable", RED)),
        ("TLS: check date and time", ("Check date and time", RED)),
        ("TLS handshake failed", ("Secure link failed", RED)),
        ("CA file missing", ("ca.pem missing", RED)),
    ];
    if status == ConnectionStatus::Ready as u32 {
        return ("Connected", GREEN);
    }
    if !online {
        return ("No internet", RED);
    }
    let transport = c_str(transport);
    if let Some((_, shown)) = REASONS
        .iter()
        .find(|(reason, _)| reason.as_bytes() == transport)
    {
        return *shown;
    }
    match status {
        s if s == ConnectionStatus::Connecting as u32
            || s == ConnectionStatus::Connected as u32 =>
        {
            ("Connecting...", YELLOW)
        }
        // The module's only unrecoverable state: relay and module disagree on the protocol version.
        s if s == ConnectionStatus::Error as u32 => ("Check for updates", RED),
        // The relay link is only up while a game plays over it.
        _ => ("Idle", GREY),
    }
}

/// LDN state row (debug logging on).
pub fn ldn_state(state: u32) -> Status {
    match CommState::from_u32(state) {
        Some(CommState::None) => ("None", GREY),
        Some(CommState::Initialized) => ("Initialized", GREY),
        Some(CommState::AccessPoint) => ("Access Point", YELLOW),
        Some(CommState::AccessPointCreated) => ("AP Created", GREEN),
        Some(CommState::Station) => ("Station", YELLOW),
        Some(CommState::StationConnected) => ("Connected", GREEN),
        Some(CommState::Error) => ("Error", RED),
        None => ("Unknown", GREY),
    }
}

/// Update row from GetSetupStatus and GetUpdateStatus.
pub fn update(setup: u32, up: &UpdateStatusIpc) -> (String<32>, Color) {
    let (text, color) = if setup & SETUP_NEEDS_RESTART != 0 {
        ("Restart needed", ORANGE)
    } else if up.staged_build != 0 {
        ("Restart ldn-tunnel", GREEN)
    } else if up.rolled_back != 0 || setup & SETUP_ROLLED_BACK != 0 {
        ("Restart ldn-tunnel", ORANGE)
    } else if up.download != 0 {
        let mut s = String::new();
        let _ = write!(s, "Downloading {}%", up.download.saturating_sub(1).min(100));
        return (s, WHITE);
    } else if up.check_state == 1 {
        ("Checking...", WHITE)
    } else if up.check_state == 2 {
        ("Check failed", WHITE)
    } else if up.on_probation != 0 {
        ("Trying new version", WHITE)
    } else if up.channel == 0 {
        ("Off", WHITE)
    } else if up.channel == 2 {
        ("Up to date (test)", WHITE)
    } else {
        ("Up to date", WHITE)
    };
    let mut s = String::new();
    let _ = s.push_str(text);
    (s, color)
}

/// Players row: "2/8 (host)", None outside a session.
pub fn players(si: &SessionInfoIpc) -> Option<String<16>> {
    if si.node_count == 0 {
        return None;
    }
    let mut s = String::new();
    let host = if si.is_host != 0 { " (host)" } else { "" };
    let _ = write!(s, "{}/{}{host}", si.node_count, si.max_nodes);
    Some(s)
}

/// Short but keeps the hash (a long value leaves the row blank): "v0.1.0-3-g7576a92" ->
/// "v0.1.0+7576a92"; at most 16 bytes.
pub fn short_version(full: &[u8]) -> String<16> {
    let full = c_str(full);
    let hash = full.windows(2).position(|w| w == b"-g");
    let dash = full.iter().position(|&b| b == b'-');
    let mut out = String::new();
    let parts: [&[u8]; 3] = match (hash, dash) {
        (Some(h), Some(d)) => {
            let hash = full.get(h.saturating_add(2)..).unwrap_or(&[]);
            [
                full.get(..d).unwrap_or(&[]),
                b"+",
                hash.get(..7).unwrap_or(hash),
            ]
        }
        _ => [full, b"", b""],
    };
    for &b in parts.iter().flat_map(|p| p.iter()) {
        if out.push(char::from(b)).is_err() {
            break;
        }
    }
    out
}

/// Relay host for the settings page: host only, "Not set" when empty, cut to 13 + "..." past 16.
pub fn server_host(host: &[u8]) -> String<16> {
    let host = c_str(host);
    let mut out = String::new();
    let (shown, tail): (&[u8], &str) = match host.len() {
        0 => (b"Not set", ""),
        n if n <= 16 => (host, ""),
        _ => (host.get(..13).unwrap_or(host), "..."),
    };
    for &b in shown {
        let _ = out.push(char::from(b));
    }
    let _ = out.push_str(tail);
    out
}

/// Dashboard subtitle: "● relay — indicator | players".
pub fn subtitle(relay: &str, indicator: &str, info: &str) -> String<128> {
    let mut s = String::new();
    let _ = write!(s, "\u{25CF} {relay}");
    if !indicator.is_empty() {
        let _ = write!(s, " \u{2014} {indicator}");
    }
    if !info.is_empty() {
        let _ = write!(s, " | {info}");
    }
    s
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use zerocopy::FromZeros;

    #[test]
    fn relay_rows() {
        let ready = ConnectionStatus::Ready as u32;
        let connecting = ConnectionStatus::Connecting as u32;
        assert_eq!(relay(ready, b"DNS failed\0", false), ("Connected", GREEN));
        assert_eq!(
            relay(connecting, b"DNS failed\0junk", false),
            ("No internet", RED)
        );
        assert_eq!(
            relay(connecting, b"DNS failed\0junk", true),
            ("Relay not found", RED)
        );
        assert_eq!(relay(0, b"CA file missing", true), ("ca.pem missing", RED));
        assert_eq!(relay(0, b"DNS failed (x)\0", true), ("Idle", GREY));
        assert_eq!(
            relay(ConnectionStatus::Connected as u32, b"\0", true),
            ("Connecting...", YELLOW)
        );
        assert_eq!(
            relay(ConnectionStatus::Error as u32, b"", true),
            ("Check for updates", RED)
        );
        assert_eq!(relay(99, b"", true), ("Idle", GREY));
    }

    #[test]
    fn ldn_rows() {
        assert_eq!(ldn_state(3), ("AP Created", GREEN));
        assert_eq!(ldn_state(4), ("Station", YELLOW));
        assert_eq!(ldn_state(6), ("Error", RED));
        assert_eq!(ldn_state(7), ("Unknown", GREY));
    }

    #[test]
    fn update_rows() {
        let mut up = UpdateStatusIpc::new_zeroed();
        let row = |setup, up: &UpdateStatusIpc| {
            let (s, c) = update(setup, up);
            (std::string::String::from(s.as_str()), c)
        };
        assert_eq!(row(0, &up), ("Off".into(), WHITE));
        up.channel = 2;
        assert_eq!(row(0, &up), ("Up to date (test)".into(), WHITE));
        up.channel = 1;
        assert_eq!(row(0, &up), ("Up to date".into(), WHITE));
        up.on_probation = 1;
        assert_eq!(row(0, &up).0, "Trying new version");
        up.check_state = 2;
        assert_eq!(row(0, &up).0, "Check failed");
        up.check_state = 1;
        assert_eq!(row(0, &up).0, "Checking...");
        up.download = 1;
        assert_eq!(row(0, &up).0, "Downloading 0%");
        up.download = 255;
        assert_eq!(row(0, &up).0, "Downloading 100%");
        assert_eq!(
            row(SETUP_ROLLED_BACK, &up),
            ("Restart ldn-tunnel".into(), ORANGE)
        );
        up.staged_build = 5;
        assert_eq!(
            row(SETUP_ROLLED_BACK, &up),
            ("Restart ldn-tunnel".into(), GREEN)
        );
        assert_eq!(
            row(SETUP_NEEDS_RESTART, &up),
            ("Restart needed".into(), ORANGE)
        );
    }

    #[test]
    fn player_rows() {
        let mut si = SessionInfoIpc::default();
        assert_eq!(players(&si), None);
        si.node_count = 2;
        si.max_nodes = 8;
        assert_eq!(players(&si).unwrap().as_str(), "2/8");
        si.is_host = 1;
        si.node_count = 10;
        si.max_nodes = 255;
        assert_eq!(players(&si).unwrap().as_str(), "10/255 (host)");
    }

    #[test]
    fn versions() {
        assert_eq!(
            short_version(b"v0.1.0-3-g7576a92\0").as_str(),
            "v0.1.0+7576a92"
        );
        assert_eq!(
            short_version(b"v0.1.0-3-g7576a92ffff-dirty").as_str(),
            "v0.1.0+7576a92"
        );
        assert_eq!(
            short_version(b"0.1.0+b1761400000\0").as_str(),
            "0.1.0+b176140000"
        );
        assert_eq!(short_version(b"Unknown").as_str(), "Unknown");
        assert_eq!(short_version(b"v0.1.0-rc1").as_str(), "v0.1.0-rc1");
        assert_eq!(
            short_version(b"v10.20.30-rc1-4-gabcdef0").as_str(),
            "v10.20.30+abcdef"
        );
    }

    #[test]
    fn hosts() {
        assert_eq!(server_host(b"\0").as_str(), "Not set");
        assert_eq!(
            server_host(b"relay.example.org").as_str(),
            "relay.example..."
        );
        assert_eq!(
            server_host(b"relay.example.co\0x").as_str(),
            "relay.example.co"
        );
    }

    #[test]
    fn subtitles() {
        assert_eq!(subtitle("Idle", "", "").as_str(), "\u{25CF} Idle");
        assert_eq!(
            subtitle("Idle", "Saved!", "2/8").as_str(),
            "\u{25CF} Idle \u{2014} Saved! | 2/8"
        );
    }
}
