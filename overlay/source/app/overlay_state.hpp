/**
 * @file overlay_state.hpp
 * @brief Singleton holding the overlay's global state (init status, version, dirty flag).
 *
 * Not thread-safe: the overlay runs on a single thread.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */
#pragma once

#include <cstdio>

class OverlayState {
public:
    enum class InitStatus { Uninit, Error, Loaded };

    static OverlayState& Instance() {
        static OverlayState s_instance;
        return s_instance;
    }

    InitStatus GetStatus() const { return m_status; }
    void SetStatus(InitStatus s) { m_status = s; }

    const char* GetVersion() const { return m_version; }
    void SetVersion(const char* v) { snprintf(m_version, sizeof(m_version), "%s", v ? v : "Unknown"); }

    bool IsDirty() const { return m_dirty; }
    void MarkDirty() { m_dirty = true; }
    void MarkSaved() { m_dirty = false; }

private:
    OverlayState() = default;
    InitStatus m_status = InitStatus::Uninit;
    char m_version[32] = "Unknown";
    bool m_dirty = false;
};
