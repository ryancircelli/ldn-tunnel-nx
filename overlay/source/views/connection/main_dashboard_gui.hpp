/**
 * @file main_dashboard_gui.hpp
 * @brief Main dashboard overlay screen (connection, updates, nav).
 *
 * Displays:
 * - Setup banner when only a restart can finish setup
 * - Connection section: relay, game, players (LDN state with debug on)
 * - Updates section, then navigation to settings
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */
#pragma once

#include <tesla.hpp>

#include "app/auto_save_controller.hpp"
#include "ldn_tunnel_ipc.h"

class MainDashboardGui : public tsl::Gui {
public:
    MainDashboardGui();
    virtual tsl::elm::Element* createUI() override;
    virtual void update() override;
    virtual bool handleInput(u64 keysDown, u64 keysHeld,
                             const HidTouchState& touchPos,
                             HidAnalogStickState joyStickPosLeft,
                             HidAnalogStickState joyStickPosRight) override;

private:
    void BuildConnectionSection(tsl::elm::List* list);
    void BuildUpdateSection(tsl::elm::List* list);
    void BuildNavSection(tsl::elm::List* list);

    void RefreshConnectionValues();
    tsl::elm::MiniListItem* MakeRestartModuleItem();
    /** @brief Advance a module restart; true once this Gui was swapped out. */
    bool StepRestart();
    void FinishRestart(const char* text);

    tsl::elm::OverlayFrame* m_frame = nullptr;

    tsl::elm::MiniListItem* m_statusItem = nullptr;
    tsl::elm::MiniListItem* m_updateItem = nullptr;
    tsl::elm::MiniListItem* m_versionItem = nullptr;
    tsl::elm::MiniListItem* m_builtItem = nullptr;
    tsl::elm::MiniListItem* m_ldnStateItem = nullptr;
    tsl::elm::MiniListItem* m_sessionItem = nullptr;
    tsl::elm::MiniListItem* m_gameItem = nullptr;
    tsl::elm::MiniListItem* m_notifyNav = nullptr;
    tsl::elm::MiniListItem* m_restartItem = nullptr;

    enum class Restart { Idle, Stopping, Connecting };
    Restart m_restart = Restart::Idle;
    u64 m_restartDeadline = 0;  ///< armGetSystemTick() value


    static constexpr u32 PollFrames = 30;
    u32 m_refreshCounter = 0;
    LdnTunnelConnectionStatus m_cachedStatus = LdnTunnelStatus_Disconnected;
    AutoSaveController m_autoSaveController;

    /** @brief Relay text and player count from RefreshConnectionValues, for the update() subtitle. */
    std::string m_cachedRelayText = "Not running";
    std::string m_cachedInfoSubtitle;
    /** @brief Running game and whether gamelist.txt has it (read once per game). */
    u64 m_gameProgramId = 0;
    bool m_gameSupported = false;
};
