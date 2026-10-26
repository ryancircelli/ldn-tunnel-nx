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

namespace {
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

void Apply(tsl::elm::MiniListItem* item, const LdntRow& row) {
    if (!item || !row.set) return;
    item->setValue(row.text);
    if (row.color[0]) item->setValueColor(tsl::RGB888(row.color));
}
}  // namespace

MainDashboardGui::MainDashboardGui() { ldnt_dash_new(); }

tsl::elm::Element* MainDashboardGui::createUI() {
    auto frame = new tsl::elm::OverlayFrame("ldn-tunnel", ldnt_version());
    m_frame = frame;
    auto list = new tsl::elm::List();

    if (ldnt_status() == LdntInit_Error) {
        list->addItem(new tsl::elm::ListItem("ldn-tunnel is not running"));
        list->addItem(new tsl::elm::ListItem("Just installed? Restart the Switch"));
        list->addItem(MakeRestartModuleItem(1));
        frame->setContent(list);
        return frame;
    }
    if (ldnt_status() == LdntInit_Uninit) {
        list->addItem(new tsl::elm::ListItem("Initializing..."));
        frame->setContent(list);
        return frame;
    }

    // Setup that only a restart finishes (cmd 30): first on screen.
    switch (ldnt_setup_banner()) {
        case LdntBanner_Reboot: list->addItem(MakeRebootItem("Restart once more to finish setup")); break;
        case LdntBanner_UndoUpdate: list->addItem(MakeRestartModuleItem(0, "Update failed: restart to undo it")); break;
        default: break;
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
    bool debug = false;
    if (ldnt_debug_enabled(&debug) && debug) {
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
    const bool available = ldnt_notifications_available();
    auto notifyNav = new tsl::elm::MiniListItem("Notifications");
    notifyNav->setValue(available ? ">" : "unavailable");
    notifyNav->setValueColor(available ? tsl::RGB888("FFFFFF") : tsl::RGB888("888888"));
    notifyNav->setClickListener([](u64 keys) {
        if ((keys & HidNpadButton_A) && ldnt_notifications_available()) { tsl::changeTo<NotificationsGui>(); return true; }
        return false;
    });
    list->addItem(notifyNav);
}

void MainDashboardGui::BuildUpdateSection(tsl::elm::List* list) {
    list->addItem(new tsl::elm::CategoryHeader("Updates"));
    list->addItem(new tsl::elm::MiniListItem("Version", ldnt_short_version()));
    m_builtItem = new tsl::elm::MiniListItem("Built", "...");
    list->addItem(m_builtItem);
    m_updateItem = new tsl::elm::MiniListItem("Update", "...");
    list->addItem(m_updateItem);
    auto checkItem = new tsl::elm::MiniListItem("Check for updates");
    checkItem->setValue(">");
    checkItem->setClickListener([](u64 keys) {
        if (!(keys & HidNpadButton_A)) return false;
        ldnt_check_for_updates();
        return true;
    });
    list->addItem(checkItem);
    list->addItem(MakeRestartModuleItem(1));
}

// Restart (or start) the module; the sequence is ldnt_restart_press / ldnt_dash_update.
tsl::elm::MiniListItem* MainDashboardGui::MakeRestartModuleItem(u8 slot, const char* label) {
    auto item = new tsl::elm::MiniListItem(label ? label : ldnt_restart_label());
    item->setValue(">");
    m_restartItems[slot] = item;
    item->setClickListener([this, slot](u64 keys) {
        if (!(keys & HidNpadButton_A)) return false;
        if (ldnt_restart_press(slot, &m_view)) m_restartItems[slot]->setValue(m_view.restart.text);
        return true;
    });
    return item;
}

void MainDashboardGui::ApplyRows() {
    Apply(m_statusItem, m_view.relay);
    Apply(m_ldnStateItem, m_view.ldn_state);
    Apply(m_gameItem, m_view.game);
    Apply(m_updateItem, m_view.update);
    Apply(m_builtItem, m_view.built);
    Apply(m_sessionItem, m_view.players);
}

void MainDashboardGui::update() {
    const u32 changed = ldnt_dash_update(&m_view, m_ldnStateItem != nullptr);
    if (changed & LDNT_DASH_SWAP) {
        // Restarted: close the overlay so the next open starts fresh on the new module.
        tsl::Overlay::get()->close();
        return;
    }
    if (changed & LDNT_DASH_RESTART) Apply(m_restartItems[m_view.restart_slot], m_view.restart);
    if (changed & LDNT_DASH_ROWS) ApplyRows();
    if (m_frame) m_frame->setSubtitle(m_view.subtitle);
}

bool MainDashboardGui::handleInput(u64 keysDown, u64, const HidTouchState&,
                                   HidAnalogStickState, HidAnalogStickState) {
    if (keysDown & HidNpadButton_R) {
        if (ldnt_dash_refresh(&m_view, m_ldnStateItem != nullptr)) ApplyRows();
        return true;
    }
    return false;
}
