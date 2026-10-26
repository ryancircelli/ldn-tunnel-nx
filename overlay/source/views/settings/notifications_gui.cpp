/**
 * @file notifications_gui.cpp
 * @brief Notifications submenu implementation.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */

#include "views/settings/notifications_gui.hpp"

NotificationsGui::~NotificationsGui() {
    ldnt_save_if_dirty();  // leaving the page must not lose changes
}

void NotificationsGui::AddToggle(tsl::elm::List* list, const char* label, LdntNotify which) {
    auto toggle = new tsl::elm::ToggleListItem(label, ldnt_notify_enabled(which));
    toggle->setStateChangedListener([toggle, which](bool on) {
        if (!ldnt_set_notify(which, on)) toggle->setState(!on);
    });
    list->addItem(toggle);
}

tsl::elm::Element* NotificationsGui::createUI() {
    auto frame = new tsl::elm::OverlayFrame("Notifications", ldnt_version());
    auto list = new tsl::elm::List();
    list->addItem(new tsl::elm::CategoryHeader("Show a message when..."));
    AddToggle(list, "Updates", LdntNotify_Updates);
    AddToggle(list, "Game start", LdntNotify_GameStart);
    AddToggle(list, "Connection", LdntNotify_Connection);
    frame->setContent(list);
    return frame;
}
