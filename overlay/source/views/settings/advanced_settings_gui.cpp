/**
 * @file advanced_settings_gui.cpp
 * @brief Implementation of the advanced settings overlay screen.
 *
 * Server info, LDN settings and debug toggles.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */

#include "views/settings/advanced_settings_gui.hpp"

#include "ldn_tunnel_overlay.h"

AdvancedSettingsGui::AdvancedSettingsGui() {
}

AdvancedSettingsGui::~AdvancedSettingsGui() {
    // Leaving the page (back, or the overlay closing) must not lose changes
    ldnt_save_if_dirty();
}

tsl::elm::Element* AdvancedSettingsGui::createUI() {
    auto frame = new tsl::elm::OverlayFrame("Advanced Settings", ldnt_version());
    auto list = new tsl::elm::List();

    if (ldnt_status() == LdntInit_Error) {
        list->addItem(new tsl::elm::ListItem("ldn-tunnel is not running"));
        frame->setContent(list);
        return frame;
    }
    if (ldnt_status() == LdntInit_Uninit) {
        list->addItem(new tsl::elm::ListItem("Initializing..."));
        frame->setContent(list);
        return frame;
    }

    BuildServerSection(list);
    BuildLdnSection(list);
    BuildDebugSection(list);

    frame->setContent(list);
    return frame;
}

void AdvancedSettingsGui::BuildServerSection(tsl::elm::List* list) {
    list->addItem(new tsl::elm::CategoryHeader("Relay : set in config.ini"));
    m_serverItem = new tsl::elm::MiniListItem("Relay", "...");
    list->addItem(m_serverItem);
}

void AdvancedSettingsGui::BuildLdnSection(tsl::elm::List* list) {
    list->addItem(new tsl::elm::CategoryHeader("Local Wireless : applies when a game starts it"));
    m_ldnToggle = new tsl::elm::ToggleListItem("Play over the relay", true);
    bool enabled;
    if (ldnt_ldn_enabled(&enabled)) m_ldnToggle->setState(enabled);
    m_ldnToggle->setStateChangedListener([this](bool on) {
        if (!ldnt_set_ldn_enabled(on)) m_ldnToggle->setState(!on);
    });
    list->addItem(m_ldnToggle);
    auto reload = new tsl::elm::MiniListItem("Reload config.ini");
    reload->setValue(">");
    reload->setClickListener([reload](u64 keys) {
        if (!(keys & HidNpadButton_A)) return false;
        reload->setValue(ldnt_reload_config() ? "Reloaded" : "Failed");
        return true;
    });
    list->addItem(reload);
}

void AdvancedSettingsGui::BuildDebugSection(tsl::elm::List* list) {
    list->addItem(new tsl::elm::CategoryHeader("Debug"));
    m_debugToggle = new tsl::elm::ToggleListItem("Write a log file", false);
    bool debugEnabled;
    if (ldnt_debug_enabled(&debugEnabled)) m_debugToggle->setState(debugEnabled);
    m_debugToggle->setStateChangedListener([this](bool enabled) {
        if (!ldnt_set_debug_enabled(enabled)) m_debugToggle->setState(!enabled);
    });
    list->addItem(m_debugToggle);
    m_debugLevelBar = new tsl::elm::NamedStepTrackBar("\uE142",
        {"Error", "Warning", "Info", "Verbose"}, true, "Log detail");
    if (int level = ldnt_debug_level(); level >= 0) m_debugLevelBar->setProgress(static_cast<u8>(level));
    m_debugLevelBar->setValueChangedListener([](u8 progress) { ldnt_set_debug_level(progress); });
    list->addItem(m_debugLevelBar);
}


void AdvancedSettingsGui::RefreshServerAddress() {
    if (!m_serverItem) return;
    LdntRow row;
    ldnt_server_row(&row);
    if (!row.set) return;
    m_serverItem->setValue(row.text);
    m_serverItem->setValueColor(tsl::RGB888(row.color));
}

void AdvancedSettingsGui::update() {
    m_refreshCounter++;
    if (m_refreshCounter >= 30) {
        m_refreshCounter = 0;
        // Always refresh server address (read-only display, not affected by edit locks)
        RefreshServerAddress();
    }
}

bool AdvancedSettingsGui::handleInput(u64 keysDown, u64 keysHeld,
                                       const HidTouchState& touchPos,
                                       HidAnalogStickState joyStickPosLeft,
                                       HidAnalogStickState joyStickPosRight) {
    if (keysDown & HidNpadButton_R) { RefreshServerAddress(); return true; }
    return false;
}
