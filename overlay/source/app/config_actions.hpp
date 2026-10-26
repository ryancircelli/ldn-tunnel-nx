/**
 * @file config_actions.hpp
 * @brief Standalone config save/reload helper functions.
 *
 * Extracted from auto_save_controller.hpp to avoid dependency on the
 * AutoSaveController class. Used by AdvancedSettingsGui.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */
#pragma once

#include <switch.h>

#include "ldn_tunnel_ipc.h"
#include "app/overlay_state.hpp"

/** @brief Save config via IPC. Returns true on success. */
inline bool DoSaveConfig() {
    if (OverlayState::Instance().GetStatus() != OverlayState::InitStatus::Loaded) return false;
    LdnTunnelConfigService* svc = ldnTunnelGetService();
    if (!svc) return false;
    LdnTunnelConfigResult result;
    Result rc = ldnTunnelSaveConfig(svc, &result);
    if (R_SUCCEEDED(rc) && result == LdnTunnelConfigResult_Success) {
        OverlayState::Instance().MarkSaved();
        return true;
    }
    return false;
}

/** @brief Reload config from disk via IPC. Returns true on success. */
inline bool DoReloadConfig() {
    if (OverlayState::Instance().GetStatus() != OverlayState::InitStatus::Loaded) return false;
    LdnTunnelConfigService* svc = ldnTunnelGetService();
    if (!svc) return false;
    LdnTunnelConfigResult result;
    Result rc = ldnTunnelReloadConfig(svc, &result);
    return R_SUCCEEDED(rc) && result == LdnTunnelConfigResult_Success;
}

/** @brief Save now if there are unsaved changes (exit / leaving a page). */
inline bool SaveIfDirty() {
    if (!OverlayState::Instance().IsDirty()) return true;
    return DoSaveConfig();
}
