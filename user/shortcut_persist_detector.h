/*
 * shortcut_persist_detector.h - Startup-folder shortcut persistence
 * detector (T1547.009).
 *
 * Complements persistence_chain (which only records "a file appeared
 * under Startup") by scoring the shortcut-construction plane:
 *   - WScript.Shell CreateShortcut targeting a Startup folder     -> 90
 *   - FILE_CREATE / FILE_RENAME of .lnk/.url under Startup        -> 90
 *   - copy/move/xcopy of .lnk/.url into Startup                   -> 80
 *   - WScript.Shell object constructed with a Startup path        -> 65
 *
 * Ordinary Explorer browsing of the Startup folder and non-shortcut
 * documents dropped there stay silent (chain detector still sees them).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SHORTCUT_PERSIST_DETECTOR_H
#define EDR_SHORTCUT_PERSIST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ShortcutPersistDetector {
public:
    ShortcutPersistDetector(bool enabled, uint32_t minScore,
                            uint32_t dedupWindowSeconds,
                            size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_SHORTCUT_PERSIST_DETECTOR_H */
