/**
 * @file notifications_gui.cpp
 * @brief Notifications submenu implementation.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */

#include "views/settings/notifications_gui.hpp"
#include "app/config_actions.hpp"
#include "app/overlay_state.hpp"

NotificationsGui::~NotificationsGui() {
    SaveIfDirty();  // leaving the page must not lose changes
}

void NotificationsGui::AddToggle(tsl::elm::List* list, const char* label, u32 bit) {
    LdnTunnelConfigService* svc = ldnTunnelGetService();
    u32 flags = 0;
    if (svc) ldnTunnelGetNotifyFlags(svc, &flags);
    auto toggle = new tsl::elm::ToggleListItem(label, (flags & bit) != 0);
    toggle->setStateChangedListener([toggle, bit](bool on) {
        LdnTunnelConfigService* s = ldnTunnelGetService();
        u32 cur = 0;
        if (!s || R_FAILED(ldnTunnelGetNotifyFlags(s, &cur))) { toggle->setState(!on); return; }
        cur = on ? (cur | bit) : (cur & ~bit);
        if (R_FAILED(ldnTunnelSetNotifyFlags(s, cur))) { toggle->setState(!on); return; }
        OverlayState::Instance().MarkDirty();
    });
    list->addItem(toggle);
}

tsl::elm::Element* NotificationsGui::createUI() {
    auto frame = new tsl::elm::OverlayFrame("Notifications", OverlayState::Instance().GetVersion());
    auto list = new tsl::elm::List();
    list->addItem(new tsl::elm::CategoryHeader("Show a message when..."));
    AddToggle(list, "Updates", LDNT_NOTIFY_UPDATES);
    AddToggle(list, "Game start", LDNT_NOTIFY_GAME_START);
    AddToggle(list, "Connection", LDNT_NOTIFY_CONNECTION);
    frame->setContent(list);
    return frame;
}
