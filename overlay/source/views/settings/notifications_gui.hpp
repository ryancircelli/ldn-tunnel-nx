/**
 * @file notifications_gui.hpp
 * @brief Notifications submenu: three toggles (updates, game start, connection).
 *
 * Talks to ldnt:cfg commands 28/29.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */
#pragma once

#include <tesla.hpp>

#include "ldn_tunnel_ipc.h"

/** @brief True when the module answers GetNotifyFlags (else the menu is greyed out). */
inline bool NotificationsAvailable() {
    LdnTunnelConfigService* svc = ldnTunnelGetService();
    u32 flags;
    return svc && R_SUCCEEDED(ldnTunnelGetNotifyFlags(svc, &flags));
}

class NotificationsGui : public tsl::Gui {
public:
    NotificationsGui() = default;
    ~NotificationsGui();
    virtual tsl::elm::Element* createUI() override;

private:
    void AddToggle(tsl::elm::List* list, const char* label, u32 bit);
};
