/**
 * @file save_backoff.hpp
 * @brief Frame-based schedule for auto-save with back-off after failures
 *
 * Pure logic (no libnx), unit-tested on the host. Due() says when to attempt
 * a save: AutoSaveDelayFrames of continuous dirty state. After a failed save
 * the next attempt waits FailBackoffFrames, so a broken SD card is not hit
 * with create/write/delete cycles every second.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */
#pragma once

#include <cstdint>

class SaveBackoff {
public:
    static constexpr uint32_t AutoSaveDelayFrames = 60;   // ~1 s at 60 fps
    static constexpr uint32_t FailBackoffFrames = 600;    // ~10 s

    /** @brief Call once per frame. True when a save attempt should be made now. */
    bool Due(bool dirty) {
        if (!dirty) {
            m_wait = 0;
            m_backoff = 0;
            return false;
        }
        if (m_backoff > 0) {
            m_backoff--;
            return false;
        }
        if (++m_wait >= AutoSaveDelayFrames) {
            m_wait = 0;
            return true;
        }
        return false;
    }

    /** @brief The attempt failed: wait FailBackoffFrames before the next one. */
    void Failed() { m_backoff = FailBackoffFrames; }

private:
    uint32_t m_wait = 0;
    uint32_t m_backoff = 0;
};
