/**
 * @file main_dashboard_gui.cpp
 * @brief Implementation of the main dashboard overlay screen.
 *
 * Dashboard: connection/LDN/session/game/transport, update status,
 * restart hint, and navigation to advanced settings and notifications.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */

#include "views/connection/main_dashboard_gui.hpp"
#include "views/settings/notifications_gui.hpp"
#include "views/settings/advanced_settings_gui.hpp"
#include "utils/formatters.hpp"
#include "app/overlay_state.hpp"
#include "app/config_actions.hpp"

#include "ldn_tunnel_ipc.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

namespace {
constexpr u64 ModuleProgramId = 0x420000004C444E54;  // ldn-tunnel sysmodule

bool ModuleRunning() {
    u64 pid = 0;
    return R_SUCCEEDED(pmdmntGetProcessId(&pid, ModuleProgramId));
}

// Any application (game) running. Asked of pm, not the module, so it holds
// even when the module is hung. Games hold ldn:u/bsd:u sessions through our
// MITM; killing the module under them would break the game.
bool GameRunning() {
    u64 pid = 0;
    return R_SUCCEEDED(pmdmntGetApplicationProcessId(&pid));
}

u64 TicksIn(u64 ms) { return armGetSystemTick() + armNsToTicks(ms * 1000000); }

// Same rule as the module's whitelist (crates/core/src/whitelist.rs): one hex
// id per line, optional 0x, anything after the digits ignored.
bool InGameList(u64 programId) {
    FILE* f = fopen("sdmc:/config/ldn-tunnel/gamelist.txt", "r");
    if (!f) return false;  // the module routes no game without it either
    char line[64];
    bool found = false;
    while (!found && fgets(line, sizeof(line), f)) {
        const char* p = line;
        if (static_cast<unsigned char>(p[0]) == 0xEF) p += 3;  // UTF-8 BOM
        found = strtoull(p, nullptr, 16) == programId;
    }
    fclose(f);
    return found;
}

tsl::elm::MiniListItem* MakeRebootItem(const char* label) {
    // A normal restart (games get to save first). Two presses so a stray A
    // mid-game can't close the game.
    auto item = new tsl::elm::MiniListItem(label);
    item->setValue(">");
    item->setClickListener([item, armed = false](u64 keys) mutable {
        if (!(keys & HidNpadButton_A)) return false;
        if (!armed) {
            armed = true;
            item->setValue("Press A again");
            return true;
        }
        if (R_SUCCEEDED(spsmInitialize())) {
            spsmShutdown(true);
            spsmExit();
        }
        return true;
    });
    return item;
}
}  // namespace

MainDashboardGui::MainDashboardGui() = default;

tsl::elm::Element* MainDashboardGui::createUI() {
    auto frame = new tsl::elm::OverlayFrame("ldn-tunnel", OverlayState::Instance().GetVersion());
    m_frame = frame;
    auto list = new tsl::elm::List();

    if (OverlayState::Instance().GetStatus() == OverlayState::InitStatus::Error) {
        list->addItem(new tsl::elm::ListItem("ldn-tunnel is not running"));
        list->addItem(new tsl::elm::ListItem("Just installed? Restart the Switch"));
        list->addItem(MakeRestartModuleItem());
        frame->setContent(list);
        return frame;
    }
    if (OverlayState::Instance().GetStatus() == OverlayState::InitStatus::Uninit) {
        list->addItem(new tsl::elm::ListItem("Initializing..."));
        frame->setContent(list);
        return frame;
    }

    // Setup that only a restart finishes (cmd 30): first on screen.
    u32 setup = 0;
    if (LdnTunnelConfigService* svc = ldnTunnelGetService()) {
        if (R_FAILED(ldnTunnelGetSetupStatus(svc, &setup))) setup = 0;
    }
    if (setup & LDNT_SETUP_NEEDS_RESTART) {
        list->addItem(MakeRebootItem("Restart once more to finish setup"));
    } else if (setup & LDNT_SETUP_ROLLED_BACK) {
        list->addItem(MakeRebootItem("Update failed: restart to undo it"));
    }

    BuildConnectionSection(list);
    BuildUpdateSection(list);
    BuildNavSection(list);

    frame->setContent(list);
    return frame;
}

void MainDashboardGui::BuildConnectionSection(tsl::elm::List* list) {
    list->addItem(new tsl::elm::CategoryHeader("Connection"));
    m_statusItem = new tsl::elm::MiniListItem("Relay", "...");
    list->addItem(m_statusItem);
    m_gameItem = new tsl::elm::MiniListItem("Game", "...");
    list->addItem(m_gameItem);
    m_sessionItem = new tsl::elm::MiniListItem("Players", "--");
    list->addItem(m_sessionItem);
    // Raw LDN state only with debug logging on (Advanced settings).
    u32 debug = 0;
    LdnTunnelConfigService* svc = ldnTunnelGetService();
    if (svc && R_SUCCEEDED(ldnTunnelGetDebugEnabled(svc, &debug)) && debug) {
        m_ldnStateItem = new tsl::elm::MiniListItem("LDN state", "...");
        list->addItem(m_ldnStateItem);
    }
}

void MainDashboardGui::BuildNavSection(tsl::elm::List* list) {
    list->addItem(new tsl::elm::CategoryHeader("Settings"));
    auto advancedItem = new tsl::elm::MiniListItem("Advanced settings");
    advancedItem->setValue(">");
    advancedItem->setClickListener([](u64 keys) {
        if (keys & HidNpadButton_A) { tsl::changeTo<AdvancedSettingsGui>(); return true; }
        return false;
    });
    list->addItem(advancedItem);
    // Greyed out (not openable) when the module has no notification IPC.
    m_notifyNav = new tsl::elm::MiniListItem("Notifications");
    m_notifyNav->setValue(NotificationsAvailable() ? ">" : "unavailable");
    m_notifyNav->setValueColor(NotificationsAvailable() ? tsl::RGB888("FFFFFF") : tsl::RGB888("888888"));
    m_notifyNav->setClickListener([](u64 keys) {
        if ((keys & HidNpadButton_A) && NotificationsAvailable()) { tsl::changeTo<NotificationsGui>(); return true; }
        return false;
    });
    list->addItem(m_notifyNav);
}

void MainDashboardGui::BuildUpdateSection(tsl::elm::List* list) {
    list->addItem(new tsl::elm::CategoryHeader("Updates"));
    // Short (a long value leaves the row blank) but keeps the hash: "v0.1.0-3-g7576a92" -> "v0.1.0+7576a92".
    const char* full = OverlayState::Instance().GetVersion();
    char version[17];
    const char* hash = strstr(full, "-g");
    const char* dash = strchr(full, '-');
    if (hash && dash) snprintf(version, sizeof(version), "%.*s+%.7s", (int)(dash - full), full, hash + 2);
    else snprintf(version, sizeof(version), "%.16s", full);
    m_versionItem = new tsl::elm::MiniListItem("Version", version);
    list->addItem(m_versionItem);
    m_builtItem = new tsl::elm::MiniListItem("Built", "...");
    list->addItem(m_builtItem);
    m_updateItem = new tsl::elm::MiniListItem("Update", "...");
    list->addItem(m_updateItem);
    auto checkItem = new tsl::elm::MiniListItem("Check for updates");
    checkItem->setValue(">");
    checkItem->setClickListener([](u64 keys) {
        if (!(keys & HidNpadButton_A)) return false;
        if (LdnTunnelConfigService* svc = ldnTunnelGetService()) ldnTunnelCheckForUpdates(svc);
        return true;
    });
    list->addItem(checkItem);
    list->addItem(MakeRebootItem("Restart Switch"));
    list->addItem(MakeRestartModuleItem());
}

// Hot reload (e.g. after an update was staged on the SD card): stop the
// module and launch it again through pm:shell, as ovl-sysmodules does. Also
// starts it when it isn't running (crashed, or never came up).
tsl::elm::MiniListItem* MainDashboardGui::MakeRestartModuleItem() {
    auto item = new tsl::elm::MiniListItem(ModuleRunning() ? "Restart ldn-tunnel" : "Start ldn-tunnel");
    item->setValue(">");
    item->setClickListener([this, item, armed = false](u64 keys) mutable {
        if (!(keys & HidNpadButton_A)) return false;
        if (m_restart != Restart::Idle) return true;
        if (GameRunning()) {
            armed = false;
            item->setValue("Close the game first");
            return true;
        }
        if (!armed) {
            armed = true;
            item->setValue("Press A again");
            return true;
        }
        armed = false;
        if (ModuleRunning()) {
            // sm never drops a dead process's MITMs (the next bsd:u open would abort
            // sm), so the module unregisters them itself before pm may kill it.
            SaveIfDirty();
            LdnTunnelConfigService* svc = ldnTunnelGetService();
            Result rc = svc ? ldnTunnelPrepareRestart(svc) : MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
            if (R_FAILED(rc)) {
                char text[32];
                if (rc == LDNT_RC_BUSY) snprintf(text, sizeof(text), "Close the game first");
                else snprintf(text, sizeof(text), "Can't restart (0x%X)", rc);
                item->setValue(text);
                return true;
            }
        } else if (ldnTunnelRegistered()) {
            // Died after registering: its stale MITMs are still in sm.
            item->setValue("Restart the Switch");
            return true;
        }
        // Our ldnt:cfg session dies with the module: let go of it.
        ldnTunnelExit();
        OverlayState::Instance().SetStatus(OverlayState::InitStatus::Error);
        m_restartItem = item;
        item->setValue("Restarting...");
        if (R_SUCCEEDED(pmshellInitialize())) {
            pmshellTerminateProgram(ModuleProgramId);  // fails if not running: fine
            pmshellExit();
        }
        m_restart = Restart::Stopping;
        m_restartDeadline = TicksIn(3000);
        return true;
    });
    return item;
}

void MainDashboardGui::FinishRestart(const char* text) {
    m_restartItem->setValue(text);
    m_restart = Restart::Idle;
}

bool MainDashboardGui::StepRestart() {
    const bool late = armGetSystemTick() > m_restartDeadline;
    if (m_restart == Restart::Stopping) {
        // pm refuses to launch a program it still tracks: wait for the exit.
        if (ModuleRunning()) {
            if (late) FinishRestart("Didn't stop");
            return false;
        }
        const NcmProgramLocation loc{.program_id = ModuleProgramId, .storageID = NcmStorageId_None};
        u64 pid = 0;
        Result rc = pmshellInitialize();
        if (R_SUCCEEDED(rc)) {
            rc = pmshellLaunchProgram(0, &loc, &pid);
            pmshellExit();
        }
        if (R_FAILED(rc)) {
            char text[32];
            snprintf(text, sizeof(text), "Start failed (0x%X)", rc);
            FinishRestart(text);
            return false;
        }
        m_restart = Restart::Connecting;
        m_restartDeadline = TicksIn(10000);
        return false;
    }
    // Connecting: ldnt:cfg shows up 1-3 s after launch. ldnTunnelInitialize
    // asks sm first, so a try never blocks; ~4 tries a second.
    if (m_restart != Restart::Connecting || (m_refreshCounter % 15) != 0) return false;
    if (R_SUCCEEDED(ldnTunnelInitialize())) {
        char version[32];
        if (R_SUCCEEDED(ldnTunnelGetVersion(ldnTunnelGetService(), version))) {
            auto& state = OverlayState::Instance();
            state.SetVersion(version);
            state.SetStatus(OverlayState::InitStatus::Loaded);
            tsl::swapTo<MainDashboardGui>();  // rebuild: new version in the header; `this` is gone
            return true;
        }
        ldnTunnelExit();
    }
    if (late) FinishRestart("Not responding");
    return false;
}

void MainDashboardGui::RefreshConnectionValues() {
    if (OverlayState::Instance().GetStatus() != OverlayState::InitStatus::Loaded) return;
    LdnTunnelConfigService* svc = ldnTunnelGetService();
    if (!svc) return;
    using namespace ldn_tunnel::overlay;

    if (m_statusItem) {
        LdnTunnelConnectionStatus st = LdnTunnelStatus_Disconnected;
        if (R_SUCCEEDED(ldnTunnelGetConnectionStatus(svc, &st))) m_cachedStatus = st;
        // Failure reason while the link is down; never contains the token.
        char transport[64] = "";
        if (R_FAILED(ldnTunnelGetTransportStatus(svc, transport))) transport[0] = '\0';
        // No IP: games fall back to real local wireless (nifm is best effort).
        u32 ip = 0;
        const bool online = !serviceIsActive(nifmGetServiceSession_StaticService())
            || (R_SUCCEEDED(nifmGetCurrentIpAddress(&ip)) && ip != 0);
        const StatusText relay = RelayStatus(m_cachedStatus, transport, online);
        m_cachedRelayText = relay.text;
        m_statusItem->setValue(relay.text);
        m_statusItem->setValueColor(tsl::RGB888(relay.color));
    }
    if (m_ldnStateItem) {
        LdnTunnelState ls;
        if (R_SUCCEEDED(ldnTunnelGetLdnState(svc, &ls))) {
            m_ldnStateItem->setValue(ldnTunnelStateToString(ls));
            m_ldnStateItem->setValueColor(tsl::RGB888(LdnStateColor(ls)));
        }
    }
    if (m_gameItem) {
        // The module routes only games in gamelist.txt; pm answers even when the module can't.
        u64 pid = 0, programId = 0;
        u32 active = 0;
        StatusText game{"None", Grey};
        if (R_SUCCEEDED(pmdmntGetApplicationProcessId(&pid)) && R_SUCCEEDED(pmdmntGetProgramId(&programId, pid))) {
            if (programId != m_gameProgramId) {
                m_gameProgramId = programId;
                m_gameSupported = InGameList(programId);
            }
            if (R_SUCCEEDED(ldnTunnelIsGameActive(svc, &active)) && active) game = {"Online", Green};
            else game = m_gameSupported ? StatusText{"Supported", "FFFFFF"} : StatusText{"Not supported", Orange};
        }
        m_gameItem->setValue(game.text);
        m_gameItem->setValueColor(tsl::RGB888(game.color));
    }
    if (m_updateItem) {
        u32 setup = 0;
        if (R_FAILED(ldnTunnelGetSetupStatus(svc, &setup))) setup = 0;
        LdnTunnelUpdateStatus up;
        if (R_SUCCEEDED(ldnTunnelGetUpdateStatus(svc, &up))) {
            char text[32];
            const char* color = "FFFFFF";
            if (setup & LDNT_SETUP_NEEDS_RESTART) {
                snprintf(text, sizeof(text), "Restart needed");
                color = Orange;
            } else if (up.staged_build != 0) {
                snprintf(text, sizeof(text), "Restart to install");
                color = Green;
            } else if (up.rolled_back || (setup & LDNT_SETUP_ROLLED_BACK)) {
                snprintf(text, sizeof(text), "Rolled back: restart");
                color = Orange;
            } else if (up.download != 0) {
                snprintf(text, sizeof(text), "Downloading %u%%", up.download > 100 ? 100u : up.download - 1u);
            } else if (up.check_state == 1) {
                snprintf(text, sizeof(text), "Checking...");
            } else if (up.check_state == 2) {
                snprintf(text, sizeof(text), "Check failed");
            } else if (up.on_probation) {
                snprintf(text, sizeof(text), "Trying new version");
            } else if (up.channel == 0) {
                snprintf(text, sizeof(text), "Off");
            } else {
                snprintf(text, sizeof(text), "Up to date%s", up.channel == 2 ? " (test)" : "");
            }
            m_updateItem->setValue(text);
            m_updateItem->setValueColor(tsl::RGB888(color));
            // The build number is the build's Unix time.
            if (m_builtItem) {
                char when[24] = "Developer build";
                const time_t built = up.running_build;
                const struct tm* tm = built != 0 ? localtime(&built) : nullptr;
                if (tm) strftime(when, sizeof(when), "%b %d, %H:%M", tm);
                m_builtItem->setValue(when);
            }
        }
    }
    {
        char buf[16] = "--";
        LdnTunnelSessionInfo si;
        const bool inSession = R_SUCCEEDED(ldnTunnelGetSessionInfo(svc, &si)) && si.node_count > 0;
        if (inSession) snprintf(buf, sizeof(buf), "%u/%u%s", si.node_count, si.max_nodes, si.is_host ? " (host)" : "");
        if (m_sessionItem) m_sessionItem->setValue(buf);
        m_cachedInfoSubtitle = inSession ? buf : "";
    }
}

void MainDashboardGui::update() {
    if (StepRestart()) return;
    // Poll the module every PollFrames (~0.5 s): each ldnt:cfg call is a round trip.
    if ((m_refreshCounter++ % PollFrames) == 0) RefreshConnectionValues();
    m_autoSaveController.Update(OverlayState::Instance().IsDirty());

    if (m_frame) {
        std::string subtitle = "● " + m_cachedRelayText;
        std::string indicator = m_autoSaveController.GetIndicatorText();
        if (!indicator.empty()) subtitle += " — " + indicator;
        if (!m_cachedInfoSubtitle.empty()) subtitle += " | " + m_cachedInfoSubtitle;
        m_frame->setSubtitle(subtitle);
    }
}

bool MainDashboardGui::handleInput(u64 keysDown, u64, const HidTouchState&,
                                   HidAnalogStickState, HidAnalogStickState) {
    if (keysDown & HidNpadButton_R) { RefreshConnectionValues(); return true; }
    return false;
}
