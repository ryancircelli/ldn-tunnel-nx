/**
 * @file ldn_tunnel_ipc.h
 * @brief IPC client for ldn-tunnel sysmodule
 *
 * Provides functions to communicate with the ldn-tunnel sysmodule
 * for retrieving status information and changing configuration.
 *
 * ## Service Name
 * The sysmodule exposes a standalone IPC service: ldnt:cfg
 *
 * ## IPC Command IDs (ldnt:cfg service)
 *
 * Command ids and struct layouts mirror crates/core/src/cfg_types.rs; 6, 7 and 19-24 are reserved (dropped).
 *
 * ### Sysmodule Status (0-8)
 *
 * | ID | Command            | Description                       |
 * |----|--------------------|-----------------------------------|
 * | 0  | GetVersion         | Get sysmodule version string      |
 * | 1  | GetConnectionStatus | Get current connection state      |
 * | 2  | IsServiceActive    | Ping to check service is running  |
 * | 3  | IsGameActive       | Check if game is using LDN        |
 * | 4  | GetLdnState        | Get current LDN CommState (0-6)   |
 * | 5  | GetSessionInfo     | Get session info struct           |
 * | 8  | GetActiveProcessId | Get PID of active game (debug)     |
 *
 * ### Sysmodule General Settings (9-14)
 *
 * | ID | Command            | Description                       |
 * |----|--------------------|-----------------------------------|
 * | 9  | GetDebugEnabled    | Check debug logging state         |
 * | 10 | SetDebugEnabled    | Toggle debug logging              |
 * | 11 | GetDebugLevel      | Get log verbosity (0-3)           |
 * | 12 | SetDebugLevel      | Set log verbosity                 |
 * | 13 | SaveConfig         | Persist config to SD card         |
 * | 14 | ReloadConfig       | Reload config from SD card        |
 *
 * ### Sysmodule Configuration Manager (15-18)
 *
 * | ID | Command            | Description                       |
 * |----|--------------------|-----------------------------------|
 * | 15 | GetServerAddress   | Get server host and port          |
 * | 16 | SetServerAddress   | Set server host and port          |
 * | 17 | GetLdnEnabled      | Check if LDN emulation is on      |
 * | 18 | SetLdnEnabled      | Toggle LDN emulation              |
 *
 * ### Transport (25)
 *
 * | ID | Command            | Description                       |
 * |----|--------------------|-----------------------------------|
 * | 25 | GetTransportStatus | Relay connection / TLS error text |
 *
 * ### Update (26)
 *
 * | ID | Command            | Description                       |
 * |----|--------------------|-----------------------------------|
 * | 26 | GetUpdateStatus    | Auto-update state (48-byte struct) |
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */

#pragma once
#include <switch.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Connection status enumeration
 */
typedef enum {
    LdnTunnelStatus_Disconnected = 0,   ///< Not connected to server
    LdnTunnelStatus_Connecting = 1,     ///< Connection in progress
    LdnTunnelStatus_Connected = 2,     ///< Connected, handshake pending
    LdnTunnelStatus_Ready = 3,          ///< Fully connected and ready
    LdnTunnelStatus_Error = 4,          ///< Connection error
} LdnTunnelConnectionStatus;

/**
 * @brief LDN communication state
 *
 * Mirrors the CommState enum from the sysmodule.
 */
typedef enum {
    LdnTunnelState_None = 0,               ///< Not initialized
    LdnTunnelState_Initialized = 1,        ///< Initialized, ready to open AP or Station
    LdnTunnelState_AccessPoint = 2,        ///< Access point mode, ready to create network
    LdnTunnelState_AccessPointCreated = 3, ///< Network created, accepting connections
    LdnTunnelState_Station = 4,            ///< Station mode, ready to scan/connect
    LdnTunnelState_StationConnected = 5,   ///< Connected to a network
    LdnTunnelState_Error = 6,              ///< Error state
} LdnTunnelState;

/**
 * @brief Session information structure
 *
 * Contains runtime information about the current LDN session.
 */
typedef struct {
    u8 node_count;      ///< Current number of nodes in session
    u8 max_nodes;       ///< Maximum nodes allowed in session
    u8 local_node_id;   ///< This node's ID in the session
    u8 is_host;         ///< 1 if this node is the host, 0 otherwise
    u8 reserved[4];     ///< Reserved for future use
} LdnTunnelSessionInfo;

/**
 * @brief Auto-update status (mirrors UpdateStatusIpc in the sysmodule)
 */
typedef struct {
    u32 running_build;   ///< 0 = developer build
    u32 staged_build;    ///< Installed, waiting for a restart (0 = none)
    u32 rejected_build;  ///< Build the last rollback removed (0 = none)
    u8 on_probation;     ///< 1 if this boot's build has not proven itself yet
    u8 rolled_back;      ///< 1 if this boot restored the previous build
    u8 channel;          ///< 0 off, 1 stable, 2 test
    u8 check_state;      ///< 0 idle, 1 checking, 2 last check failed
    char version[31];    ///< Git describe of the running build
    u8 download;         ///< 0 = not downloading, else percent + 1
} LdnTunnelUpdateStatus;
_Static_assert(sizeof(LdnTunnelUpdateStatus) == 48, "UpdateStatusIpc size");

/**
 * @brief Configuration service handle
 */
typedef struct {
    Service s;
} LdnTunnelConfigService;

/**
 * @brief Configuration operation result
 */
typedef enum {
    LdnTunnelConfigResult_Success = 0,
    LdnTunnelConfigResult_FileNotFound = 1,
    LdnTunnelConfigResult_ParseError = 2,
    LdnTunnelConfigResult_IoError = 3,
    LdnTunnelConfigResult_InvalidValue = 4,
} LdnTunnelConfigResult;

/**
 * @brief Initialize connection to ldnt:cfg service
 *
 * This opens a connection to the standalone ldnt:cfg service.
 * Call ldnTunnelExit() when done.
 *
 * @return Result code (0 on success)
 */
Result ldnTunnelInitialize(void);

/**
 * @brief Close connection to ldnt:cfg service
 */
void ldnTunnelExit(void);

/**
 * @brief Get the configuration service handle
 *
 * @return Pointer to internal service (valid after ldnTunnelInitialize)
 */
LdnTunnelConfigService* ldnTunnelGetService(void);

//=============================================================================
// Sysmodule Status Commands (0-8)
//=============================================================================

/**
 * @brief Get sysmodule version string
 *
 * @param s Configuration service
 * @param version Output buffer (at least 32 bytes)
 * @return Result code
 */
Result ldnTunnelGetVersion(LdnTunnelConfigService* s, char* version);

/**
 * @brief Get current connection status
 *
 * @param s Configuration service
 * @param status Output status
 * @return Result code
 */
Result ldnTunnelGetConnectionStatus(LdnTunnelConfigService* s, LdnTunnelConnectionStatus* status);

/**
 * @brief Check if a game is actively using LDN
 *
 * @param s Configuration service
 * @param active Output: 1 if game is active, 0 otherwise
 * @return Result code
 */
Result ldnTunnelIsGameActive(LdnTunnelConfigService* s, u32* active);

/**
 * @brief Get current LDN communication state
 *
 * @param s Configuration service
 * @param state Output LDN state
 * @return Result code
 */
Result ldnTunnelGetLdnState(LdnTunnelConfigService* s, LdnTunnelState* state);

/**
 * @brief Get session information
 *
 * @param s Configuration service
 * @param info Output session info structure
 * @return Result code
 */
Result ldnTunnelGetSessionInfo(LdnTunnelConfigService* s, LdnTunnelSessionInfo* info);

//=============================================================================
// Sysmodule General Settings Commands (9-14)
//=============================================================================

/**
 * @brief Get debug logging state
 *
 * @param s Configuration service
 * @param enabled Output: 1 if enabled, 0 if disabled
 * @return Result code
 */
Result ldnTunnelGetDebugEnabled(LdnTunnelConfigService* s, u32* enabled);

/**
 * @brief Enable/disable debug logging
 *
 * @param s Configuration service
 * @param enabled 1 to enable, 0 to disable
 * @return Result code
 */
Result ldnTunnelSetDebugEnabled(LdnTunnelConfigService* s, u32 enabled);

/**
 * @brief Get debug level (0-3)
 *
 * @param s Configuration service
 * @param level Output level (0=Error, 1=Warn, 2=Info, 3=Verbose)
 * @return Result code
 */
Result ldnTunnelGetDebugLevel(LdnTunnelConfigService* s, u32* level);

/**
 * @brief Set debug level (0-3)
 *
 * @param s Configuration service
 * @param level Level (0=Error, 1=Warn, 2=Info, 3=Verbose)
 * @return Result code
 */
Result ldnTunnelSetDebugLevel(LdnTunnelConfigService* s, u32 level);

/**
 * @brief Save configuration to file
 *
 * @param s Configuration service
 * @param result Output operation result
 * @return Result code
 */
Result ldnTunnelSaveConfig(LdnTunnelConfigService* s, LdnTunnelConfigResult* result);

/**
 * @brief Reload configuration from file
 *
 * @param s Configuration service
 * @param result Output operation result
 * @return Result code
 */
Result ldnTunnelReloadConfig(LdnTunnelConfigService* s, LdnTunnelConfigResult* result);

//=============================================================================
// Sysmodule Configuration Manager Commands (15-18)
//=============================================================================

/**
 * @brief Get configured server address
 *
 * @param s Configuration service
 * @param host Output host buffer (at least 64 bytes)
 * @param port Output port
 * @return Result code
 */
Result ldnTunnelGetServerAddress(LdnTunnelConfigService* s, char* host, u16* port);

/**
 * @brief Get LDN enabled state
 *
 * @param s Configuration service
 * @param enabled Output: 1 if enabled, 0 if disabled
 * @return Result code
 */
Result ldnTunnelGetLdnEnabled(LdnTunnelConfigService* s, u32* enabled);

/**
 * @brief Set LDN enabled state
 *
 * @param s Configuration service
 * @param enabled 1 to enable, 0 to disable
 * @return Result code
 */
Result ldnTunnelSetLdnEnabled(LdnTunnelConfigService* s, u32 enabled);

/**
 * @brief Get the relay transport status
 *
 * Connection state or TLS error reason, e.g. "Secure (TLSv1.2)" or
 * "TLS: certificate not trusted (ca_file)". Never contains the token.
 *
 * @param s Configuration service
 * @param status Output buffer (at least 64 bytes)
 * @return Result code
 */
Result ldnTunnelGetTransportStatus(LdnTunnelConfigService* s, char* status);

/**
 * @brief Get the auto-update status
 *
 * @param s Configuration service
 * @param status Output struct
 * @return Result code
 */
Result ldnTunnelGetUpdateStatus(LdnTunnelConfigService* s, LdnTunnelUpdateStatus* status);

/**
 * @brief Start an update check now
 */
Result ldnTunnelCheckForUpdates(LdnTunnelConfigService* s);

#define LDNT_NOTIFY_UPDATES    (1u << 0)
#define LDNT_NOTIFY_GAME_START (1u << 1)
#define LDNT_NOTIFY_CONNECTION (1u << 2)
/** @brief Get notification category bitmask (cmd 28). Errors if the module lacks it. */
Result ldnTunnelGetNotifyFlags(LdnTunnelConfigService* s, u32* flags);
/** @brief Set notification category bitmask (cmd 29). */
Result ldnTunnelSetNotifyFlags(LdnTunnelConfigService* s, u32 flags);

#define LDNT_SETUP_NEEDS_RESTART (1u << 0)  ///< "Restart once to finish setup"
#define LDNT_SETUP_ROLLED_BACK   (1u << 1)  ///< update rolled back this boot
#define LDNT_SETUP_NEW_BUILD     (1u << 2)  ///< first boot of a new build
/** @brief Get setup/restart bitmask (cmd 30). Errors on a module without it. */
Result ldnTunnelGetSetupStatus(LdnTunnelConfigService* s, u32* bits);
#define LDNT_SETUP_BUSY          (1u << 3)  ///< a game holds our ldn:u/bsd:u sessions

/// rc of PrepareRestart while a game holds our sessions (module 431, desc 3101).
#define LDNT_RC_BUSY MAKERESULT(431, 3101)  // 0x183BAF
/**
 * @brief Cmd 31: drop our MITMs and ldnt:cfg from sm so pm can terminate the
 * module safely (sm never cleans up a dead process's MITMs). Terminate only
 * after this returned 0.
 */
Result ldnTunnelPrepareRestart(LdnTunnelConfigService* s);
/// Whether ldnt:cfg is registered in sm (Atmosphere HasService).
bool ldnTunnelRegistered(void);

/**
 * @brief Convert LDN state to human-readable string
 *
 * @param state LDN state value
 * @return Static string describing the state
 */
const char* ldnTunnelStateToString(LdnTunnelState state);

#ifdef __cplusplus
}
#endif
