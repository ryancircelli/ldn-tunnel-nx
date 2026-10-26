/**
 * @file formatters.hpp
 * @brief Plain-language text for the module's status values.
 *
 * Values shown in a MiniListItem stay short (~20 characters): a long value
 * leaves the whole row blank.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */
#pragma once

#include <cstring>

#include "ldn_tunnel_ipc.h"

namespace ldn_tunnel::overlay {

/** @brief Row text plus its color (RGB888 hex for tsl::RGB888). */
struct StatusText {
    const char* text;
    const char* color;
};

constexpr const char* Green = "00FF00";
constexpr const char* Yellow = "FFFF00";
constexpr const char* Orange = "FFAA00";
constexpr const char* Red = "FF4444";
constexpr const char* Grey = "888888";

/**
 * @brief Relay row: GetConnectionStatus plus GetTransportStatus, which holds the
 * failure reason while the link is down (crates/sys/src/relay_thread.rs open()
 * and status(), crates/sys/src/main.rs). Unknown reasons fall back to the status.
 * @param online false when the console has no IP address.
 */
inline StatusText RelayStatus(LdnTunnelConnectionStatus status, const char* transport, bool online) {
    if (status == LdnTunnelStatus_Ready) return {"Connected", Green};
    if (!online) return {"No internet", Red};
    static constexpr struct { const char* reason; StatusText shown; } Reasons[] = {
        {"Restart once to finish setup", {"Restart needed", Orange}},
        {"Server not configured", {"No invite installed", Red}},
        {"Rejected: check token", {"Invite rejected", Red}},
        {"Waiting for network time", {"Syncing clock...", Yellow}},
        {"DNS failed", {"Relay not found", Red}},
        {"TCP connect failed", {"Relay unreachable", Red}},
        {"TLS: check date and time", {"Check date and time", Red}},
        {"TLS handshake failed", {"Secure link failed", Red}},
        {"CA file missing", {"ca.pem missing", Red}},
    };
    for (const auto& r : Reasons) {
        if (strcmp(transport, r.reason) == 0) return r.shown;
    }
    switch (status) {
        case LdnTunnelStatus_Connecting:
        case LdnTunnelStatus_Connected: return {"Connecting...", Yellow};
        // The module's only unrecoverable state: relay and module disagree on the protocol version.
        case LdnTunnelStatus_Error: return {"Check for updates", Red};
        // The relay link is only up while a game plays over it.
        default: return {"Idle", Grey};
    }
}

/** @brief Color for a LdnTunnelState (debug row). */
inline const char* LdnStateColor(LdnTunnelState state) {
    switch (state) {
        case LdnTunnelState_AccessPointCreated:
        case LdnTunnelState_StationConnected: return Green;
        case LdnTunnelState_AccessPoint:
        case LdnTunnelState_Station: return Yellow;
        case LdnTunnelState_Error: return Red;
        default: return Grey;
    }
}

} // namespace ldn_tunnel::overlay
