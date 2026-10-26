/**
 * @file main.cpp
 * @brief Entry point for the ldn-tunnel Tesla Overlay.
 *
 * Initializes the ldnt:cfg IPC service, queries the sysmodule version,
 * and loads the MainDashboardGui as the initial screen.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */

#define TESLA_INIT_IMPL
#include <tesla.hpp>
#include "ldn_tunnel_ipc.h"
#include "app/config_actions.hpp"
#include "app/overlay_state.hpp"
#include "views/connection/main_dashboard_gui.hpp"

class LdnTunnelOverlay : public tsl::Overlay {
public:
    virtual void initServices() override {
        auto& state = OverlayState::Instance();
        state.SetStatus(OverlayState::InitStatus::Uninit);
        tsl::hlp::doWithSmSession([&] {
            Result rc = ldnTunnelInitialize();
            if (R_FAILED(rc)) { state.SetStatus(OverlayState::InitStatus::Error); return; }
            LdnTunnelConfigService* svc = ldnTunnelGetService();
            if (svc) {
                char version[32];
                rc = ldnTunnelGetVersion(svc, version);
                state.SetVersion(R_SUCCEEDED(rc) ? version : "Unknown");
            }
            state.SetStatus(OverlayState::InitStatus::Loaded);
            // Best effort: only feeds the "No internet" hint
            m_nifm = R_SUCCEEDED(nifmInitialize(NifmServiceType_User));
        });

    }
    virtual void exitServices() override {
        if (m_nifm) nifmExit();
        if (OverlayState::Instance().GetStatus() == OverlayState::InitStatus::Loaded) {
            SaveIfDirty();  // closing the overlay must not lose changes
            ldnTunnelExit();
        }
    }
    virtual void onShow() override {}
    virtual void onHide() override { SaveIfDirty(); }
    virtual std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<MainDashboardGui>();
    }
private:
    bool m_nifm = false;
};

int main(int argc, char** argv) {
    return tsl::loop<LdnTunnelOverlay>(argc, argv);
}
