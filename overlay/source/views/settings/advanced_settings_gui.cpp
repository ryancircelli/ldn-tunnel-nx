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
#include "app/config_actions.hpp"
#include "app/overlay_state.hpp"

#include "ldn_tunnel_ipc.h"

#include <cstdio>
#include <cstring>

AdvancedSettingsGui::AdvancedSettingsGui() {
}

AdvancedSettingsGui::~AdvancedSettingsGui() {
    // Leaving the page (back, or the overlay closing) must not lose changes
    SaveIfDirty();
}

tsl::elm::Element* AdvancedSettingsGui::createUI() {
    auto frame = new tsl::elm::OverlayFrame("Advanced Settings", OverlayState::Instance().GetVersion());
    auto list = new tsl::elm::List();

    if (OverlayState::Instance().GetStatus() == OverlayState::InitStatus::Error) {
        list->addItem(new tsl::elm::ListItem("ldn-tunnel is not running"));
        frame->setContent(list);
        return frame;
    }
    if (OverlayState::Instance().GetStatus() == OverlayState::InitStatus::Uninit) {
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
    LdnTunnelConfigService* svc = ldnTunnelGetService();
    u32 enabled;
    if (svc && R_SUCCEEDED(ldnTunnelGetLdnEnabled(svc, &enabled))) m_ldnToggle->setState(enabled != 0);
    m_ldnToggle->setStateChangedListener([this](bool on) {
        LdnTunnelConfigService* s = ldnTunnelGetService();
        if (!s) return;
        if (R_FAILED(ldnTunnelSetLdnEnabled(s, on ? 1 : 0))) { m_ldnToggle->setState(!on); return; }
        OverlayState::Instance().MarkDirty();
    });
    list->addItem(m_ldnToggle);
    auto reload = new tsl::elm::MiniListItem("Reload config.ini");
    reload->setValue(">");
    reload->setClickListener([reload](u64 keys) {
        if (!(keys & HidNpadButton_A)) return false;
        reload->setValue(DoReloadConfig() ? "Reloaded" : "Failed");
        return true;
    });
    list->addItem(reload);
}

void AdvancedSettingsGui::BuildDebugSection(tsl::elm::List* list) {
    list->addItem(new tsl::elm::CategoryHeader("Debug"));
    m_debugToggle = new tsl::elm::ToggleListItem("Write a log file", false);
    LdnTunnelConfigService* svc = ldnTunnelGetService();
    if (svc) {
        u32 debugEnabled;
        if (R_SUCCEEDED(ldnTunnelGetDebugEnabled(svc, &debugEnabled))) m_debugToggle->setState(debugEnabled != 0);
    }
    m_debugToggle->setStateChangedListener([this](bool enabled) {
        LdnTunnelConfigService* svc = ldnTunnelGetService();
        if (svc) {
            Result rc = ldnTunnelSetDebugEnabled(svc, enabled ? 1 : 0);
            if (R_FAILED(rc)) {
                m_debugToggle->setState(!enabled);
                return;
            }
            OverlayState::Instance().MarkDirty();
        }
    });
    list->addItem(m_debugToggle);
    m_debugLevelBar = new tsl::elm::NamedStepTrackBar("\uE142",
        {"Error", "Warning", "Info", "Verbose"}, true, "Log detail");
    if (svc) {
        u32 level;
        if (R_SUCCEEDED(ldnTunnelGetDebugLevel(svc, &level)) && level <= 3)
            m_debugLevelBar->setProgress(static_cast<u8>(level));
    }
    m_debugLevelBar->setValueChangedListener([](u8 progress) {
        LdnTunnelConfigService* svc = ldnTunnelGetService();
        if (svc) { ldnTunnelSetDebugLevel(svc, static_cast<u32>(progress)); OverlayState::Instance().MarkDirty(); }
    });
    list->addItem(m_debugLevelBar);
}


void AdvancedSettingsGui::RefreshServerAddress() {
    if (OverlayState::Instance().GetStatus() != OverlayState::InitStatus::Loaded) return;
    LdnTunnelConfigService* svc = ldnTunnelGetService();
    if (!svc || !m_serverItem) return;
    char host[64];
    u16 port;
    if (R_SUCCEEDED(ldnTunnelGetServerAddress(svc, host, &port))) {
        // Host only, and short: a long value leaves the row blank.
        char buf[17];
        if (strlen(host) < sizeof(buf)) snprintf(buf, sizeof(buf), "%s", host[0] ? host : "Not set");
        else snprintf(buf, sizeof(buf), "%.13s...", host);
        m_serverItem->setValue(buf);
        // Color: green if connected, grey if disconnected
        LdnTunnelConnectionStatus status;
        if (R_SUCCEEDED(ldnTunnelGetConnectionStatus(svc, &status)) &&
            (status == LdnTunnelStatus_Connected || status == LdnTunnelStatus_Ready)) {
            m_serverItem->setValueColor(tsl::RGB888("00FF00"));
        } else {
            m_serverItem->setValueColor(tsl::RGB888("888888"));
        }
    }
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
