/**
 * @file main_dashboard_gui.hpp
 * @brief Main dashboard overlay screen (connection, updates, nav).
 *
 * Displays:
 * - Setup banner when only a restart can finish setup
 * - Connection section: relay, game, players (LDN state with debug on)
 * - Updates section, then navigation to settings
 *
 * The values, auto-save and the module restart sequence come from crates/overlay
 * (ldnt_dash_*); this class only builds and updates the rows.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */
#pragma once

#include <tesla.hpp>

#include "ldn_tunnel_overlay.h"

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

    void ApplyRows();
    /** @brief Restart row; slot 0 is the banner, 1 the Updates section / not-running screen. */
    tsl::elm::MiniListItem* MakeRestartModuleItem(u8 slot, const char* label = nullptr);

    tsl::elm::OverlayFrame* m_frame = nullptr;

    tsl::elm::MiniListItem* m_statusItem = nullptr;
    tsl::elm::MiniListItem* m_updateItem = nullptr;
    tsl::elm::MiniListItem* m_builtItem = nullptr;
    tsl::elm::MiniListItem* m_ldnStateItem = nullptr;
    tsl::elm::MiniListItem* m_sessionItem = nullptr;
    tsl::elm::MiniListItem* m_gameItem = nullptr;
    tsl::elm::MiniListItem* m_restartItems[2] = {nullptr, nullptr};

    LdntDashView m_view{};
};
