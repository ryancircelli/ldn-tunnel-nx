/**
 * @file ldn_tunnel_ipc.c
 * @brief IPC client implementation for ldn-tunnel sysmodule
 *
 * Connects to the standalone ldnt:cfg IPC service provided by the sysmodule.
 * Command ids and struct layouts mirror crates/core/src/cfg_types.rs; 6, 7 and 19-24 are reserved (dropped).
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */

#include "ldn_tunnel_ipc.h"
#include <string.h>

/**
 * IPC Command IDs for ldnt:cfg service
 *
 * These match the ConfigCmd enum in config_ipc_service.hpp.
 */
enum {
    // Sysmodule Status (0-8)
    LdntCfgCmd_GetVersion          = 0,
    LdntCfgCmd_GetConnectionStatus = 1,
    LdntCfgCmd_IsServiceActive     = 2,
    LdntCfgCmd_IsGameActive        = 3,
    LdntCfgCmd_GetLdnState         = 4,
    LdntCfgCmd_GetSessionInfo      = 5,
    LdntCfgCmd_GetActiveProcessId  = 8,

    // Sysmodule General Settings (9-14)
    LdntCfgCmd_GetDebugEnabled     = 9,
    LdntCfgCmd_SetDebugEnabled     = 10,
    LdntCfgCmd_GetDebugLevel       = 11,
    LdntCfgCmd_SetDebugLevel       = 12,
    LdntCfgCmd_SaveConfig          = 13,
    LdntCfgCmd_ReloadConfig        = 14,

    // Sysmodule Configuration Manager (15-18)
    LdntCfgCmd_GetServerAddress    = 15,
    LdntCfgCmd_SetServerAddress    = 16,
    LdntCfgCmd_GetLdnEnabled       = 17,
    LdntCfgCmd_SetLdnEnabled       = 18,
    LdntCfgCmd_GetTransportStatus  = 25,
    LdntCfgCmd_GetUpdateStatus     = 26,
    LdntCfgCmd_CheckForUpdates     = 27,
    LdntCfgCmd_GetSetupStatus      = 30,
    LdntCfgCmd_PrepareRestart      = 31,
    LdntCfgCmd_GetNotifyFlags      = 28,
    LdntCfgCmd_SetNotifyFlags      = 29,
};

/// Global service handle
static LdnTunnelConfigService g_ldntCfgService;
static bool g_ldntCfgInitialized = false;

/// Atmosphere's sm extension HasService (cmd 65100). libnx has no wrapper:
/// HOS 12+ talks tipc to sm, older firmware cmif.
static Result ldnTunnelHasService(bool* out, SmServiceName name) {
    if (hosversionAtLeast(12, 0, 0)) {
        return tipcDispatchInOut(smGetServiceSessionTipc(), 65100, name, *out);
    }
    return serviceDispatchInOut(smGetServiceSession(), 65100, name, *out);
}

Result ldnTunnelInitialize(void) {
    if (g_ldntCfgInitialized) {
        return 0;  // Already initialized
    }

    // smGetService blocks until the name is registered, so a missing sysmodule
    // would freeze the overlay. Ask sm first; the caller shows "not running".
    bool has_service = false;
    Result rc = ldnTunnelHasService(&has_service, smEncodeName("ldnt:cfg"));
    if (R_FAILED(rc)) {
        return rc;
    }
    if (!has_service) {
        return MAKERESULT(Module_Libnx, LibnxError_NotFound);
    }

    rc = smGetService(&g_ldntCfgService.s, "ldnt:cfg");
    if (R_SUCCEEDED(rc)) {
        g_ldntCfgInitialized = true;
    }
    return rc;
}

void ldnTunnelExit(void) {
    if (g_ldntCfgInitialized) {
        serviceClose(&g_ldntCfgService.s);
        g_ldntCfgInitialized = false;
    }
}

LdnTunnelConfigService* ldnTunnelGetService(void) {
    return g_ldntCfgInitialized ? &g_ldntCfgService : NULL;
}

//=============================================================================
// Sysmodule Status Commands (0-8)
//=============================================================================

Result ldnTunnelGetVersion(LdnTunnelConfigService* s, char* version) {
    char version_buf[32];
    Result rc = serviceDispatchOut(&s->s, LdntCfgCmd_GetVersion, version_buf);
    if (R_SUCCEEDED(rc)) {
        memcpy(version, version_buf, 32);
        version[31] = '\0';  // Ensure null termination
    }
    return rc;
}

Result ldnTunnelGetConnectionStatus(LdnTunnelConfigService* s, LdnTunnelConnectionStatus* status) {
    u32 out_status;
    Result rc = serviceDispatchOut(&s->s, LdntCfgCmd_GetConnectionStatus, out_status);
    if (R_SUCCEEDED(rc)) {
        *status = (LdnTunnelConnectionStatus)out_status;
    }
    return rc;
}

Result ldnTunnelIsGameActive(LdnTunnelConfigService* s, u32* active) {
    return serviceDispatchOut(&s->s, LdntCfgCmd_IsGameActive, *active);
}

Result ldnTunnelGetLdnState(LdnTunnelConfigService* s, LdnTunnelState* state) {
    u32 out_state;
    Result rc = serviceDispatchOut(&s->s, LdntCfgCmd_GetLdnState, out_state);
    if (R_SUCCEEDED(rc)) {
        *state = (LdnTunnelState)out_state;
    }
    return rc;
}

Result ldnTunnelGetSessionInfo(LdnTunnelConfigService* s, LdnTunnelSessionInfo* info) {
    return serviceDispatchOut(&s->s, LdntCfgCmd_GetSessionInfo, *info);
}

//=============================================================================
// Sysmodule General Settings Commands (9-14)
//=============================================================================

Result ldnTunnelGetDebugEnabled(LdnTunnelConfigService* s, u32* enabled) {
    return serviceDispatchOut(&s->s, LdntCfgCmd_GetDebugEnabled, *enabled);
}

Result ldnTunnelSetDebugEnabled(LdnTunnelConfigService* s, u32 enabled) {
    return serviceDispatchIn(&s->s, LdntCfgCmd_SetDebugEnabled, enabled);
}

Result ldnTunnelGetDebugLevel(LdnTunnelConfigService* s, u32* level) {
    return serviceDispatchOut(&s->s, LdntCfgCmd_GetDebugLevel, *level);
}

Result ldnTunnelSetDebugLevel(LdnTunnelConfigService* s, u32 level) {
    return serviceDispatchIn(&s->s, LdntCfgCmd_SetDebugLevel, level);
}

Result ldnTunnelSaveConfig(LdnTunnelConfigService* s, LdnTunnelConfigResult* result) {
    u32 out_result;
    Result rc = serviceDispatchOut(&s->s, LdntCfgCmd_SaveConfig, out_result);
    if (R_SUCCEEDED(rc)) {
        *result = (LdnTunnelConfigResult)out_result;
    }
    return rc;
}

Result ldnTunnelReloadConfig(LdnTunnelConfigService* s, LdnTunnelConfigResult* result) {
    u32 out_result;
    Result rc = serviceDispatchOut(&s->s, LdntCfgCmd_ReloadConfig, out_result);
    if (R_SUCCEEDED(rc)) {
        *result = (LdnTunnelConfigResult)out_result;
    }
    return rc;
}

//=============================================================================
// Sysmodule Configuration Manager Commands (15-18)
//=============================================================================

Result ldnTunnelGetServerAddress(LdnTunnelConfigService* s, char* host, u16* port) {
    struct {
        char host[64];
        u16 port;
        u16 padding;
    } out;

    Result rc = serviceDispatchOut(&s->s, LdntCfgCmd_GetServerAddress, out);
    if (R_SUCCEEDED(rc)) {
        memcpy(host, out.host, 64);
        host[63] = '\0';
        *port = out.port;
    }
    return rc;
}

Result ldnTunnelGetLdnEnabled(LdnTunnelConfigService* s, u32* enabled) {
    return serviceDispatchOut(&s->s, LdntCfgCmd_GetLdnEnabled, *enabled);
}

Result ldnTunnelSetLdnEnabled(LdnTunnelConfigService* s, u32 enabled) {
    return serviceDispatchIn(&s->s, LdntCfgCmd_SetLdnEnabled, enabled);
}

Result ldnTunnelGetTransportStatus(LdnTunnelConfigService* s, char* status) {
    char status_buf[64];
    Result rc = serviceDispatchOut(&s->s, LdntCfgCmd_GetTransportStatus, status_buf);
    if (R_SUCCEEDED(rc)) {
        memcpy(status, status_buf, 64);
        status[63] = '\0';
    }
    return rc;
}

Result ldnTunnelGetUpdateStatus(LdnTunnelConfigService* s, LdnTunnelUpdateStatus* status) {
    LdnTunnelUpdateStatus buf;
    Result rc = serviceDispatchOut(&s->s, LdntCfgCmd_GetUpdateStatus, buf);
    if (R_SUCCEEDED(rc)) {
        memcpy(status, &buf, sizeof(buf));
        status->version[sizeof(status->version) - 1] = '\0';
    }
    return rc;
}

const char* ldnTunnelStateToString(LdnTunnelState state) {
    switch (state) {
        case LdnTunnelState_None:               return "None";
        case LdnTunnelState_Initialized:        return "Initialized";
        case LdnTunnelState_AccessPoint:        return "Access Point";
        case LdnTunnelState_AccessPointCreated: return "AP Created";
        case LdnTunnelState_Station:            return "Station";
        case LdnTunnelState_StationConnected:   return "Connected";
        case LdnTunnelState_Error:              return "Error";
        default:                             return "Unknown";
    }
}

Result ldnTunnelCheckForUpdates(LdnTunnelConfigService* s) {
    return serviceDispatch(&s->s, LdntCfgCmd_CheckForUpdates);
}

Result ldnTunnelGetNotifyFlags(LdnTunnelConfigService* s, u32* flags) {
    return serviceDispatchOut(&s->s, LdntCfgCmd_GetNotifyFlags, *flags);
}

Result ldnTunnelSetNotifyFlags(LdnTunnelConfigService* s, u32 flags) {
    return serviceDispatchIn(&s->s, LdntCfgCmd_SetNotifyFlags, flags);
}

Result ldnTunnelGetSetupStatus(LdnTunnelConfigService* s, u32* bits) {
    return serviceDispatchOut(&s->s, LdntCfgCmd_GetSetupStatus, *bits);
}

Result ldnTunnelPrepareRestart(LdnTunnelConfigService* s) {
    return serviceDispatch(&s->s, LdntCfgCmd_PrepareRestart);
}

bool ldnTunnelRegistered(void) {
    bool has = false;
    return R_SUCCEEDED(ldnTunnelHasService(&has, smEncodeName("ldnt:cfg"))) && has;
}
