/**
 * @file notifications_gui.hpp
 * @brief Notifications submenu: three toggles (updates, game start, connection).
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */
#pragma once

#include <tesla.hpp>

#include "ldn_tunnel_overlay.h"

class NotificationsGui : public tsl::Gui {
public:
    NotificationsGui() = default;
    ~NotificationsGui();
    virtual tsl::elm::Element* createUI() override;

private:
    void AddToggle(tsl::elm::List* list, const char* label, LdntNotify which);
};
