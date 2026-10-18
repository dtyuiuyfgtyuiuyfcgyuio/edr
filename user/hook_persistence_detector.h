/*
 * hook_persistence_detector.h - Hook-based persistence detector (T1546).
 *
 * Scores REG_WRITE events for registry-borne execution hooks:
 *   - T1546.008  Accessibility features backdoor: a Debugger value set on
 *                an accessibility binary (sethc/utilman/osk/magnify/
 *                narrator/displayswitch/atbroker). Score 85 MALICIOUS.
 *   - T1546.012  Image File Execution Options injection: any other
 *                non-empty Debugger value. Script interpreters or
 *                user-writable payload paths -> 75 MALICIOUS; anything
 *                else -> 60 SUSPICIOUS.
 *   - T1546.015  COM object hijack: InprocServer32/LocalServer32 default
 *                value under a Classes\CLSID key. HKCU hive with
 *                user-writable or relative target -> 75 MALICIOUS;
 *                HKCU with other path -> 65 SUSPICIOUS; HKLM pointing
 *                into a user-writable location -> 70 SUSPICIOUS; HKLM
 *                pointing at system locations is benign (no score).
 *
 * Empty values never score. Alerts are deduplicated per registry key
 * inside the dedup window so repeated collector observations of one
 * hook yield a single alert.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_HOOK_PERSISTENCE_DETECTOR_H
#define EDR_HOOK_PERSISTENCE_DETECTOR_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class HookPersistenceDetector {
public:
    HookPersistenceDetector(bool enabled, uint32_t minScore,
                            uint32_t dedupWindowSeconds,
                            size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* technique = "";
        const char* reason = "";
    };

    bool Analyze(const std::string& key, const std::string& value,
                 Finding* out) const;
    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_set<std::string> m_accessibilityImages;
    /* reg_key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_HOOK_PERSISTENCE_DETECTOR_H */
