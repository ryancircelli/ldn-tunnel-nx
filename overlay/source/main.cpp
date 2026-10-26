/**
 * @file main.cpp
 * @brief Entry point for the ldn-tunnel Tesla Overlay.
 *
 * Opens ldnt:cfg and reads the module version (crates/overlay, ldnt_init), then loads the
 * MainDashboardGui as the initial screen.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */

#define TESLA_INIT_IMPL
#include <tesla.hpp>
#include "ldn_tunnel_overlay.h"
#include "views/connection/main_dashboard_gui.hpp"

class LdnTunnelOverlay : public tsl::Overlay {
public:
    virtual void initServices() override {
        tsl::hlp::doWithSmSession([&] {
            ldnt_init();
            // Best effort: only feeds the "No internet" hint
            if (ldnt_status() == LdntInit_Loaded) m_nifm = R_SUCCEEDED(nifmInitialize(NifmServiceType_User));
        });
    }
    virtual void exitServices() override {
        if (m_nifm) nifmExit();
        ldnt_exit();  // closing the overlay must not lose changes
    }
    virtual void onShow() override {}
    virtual void onHide() override { ldnt_save_if_dirty(); }
    virtual std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<MainDashboardGui>();
    }
private:
    bool m_nifm = false;
};

int main(int argc, char** argv) {
    return tsl::loop<LdnTunnelOverlay>(argc, argv);
}
