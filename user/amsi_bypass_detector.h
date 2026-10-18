/*
 * amsi_bypass_detector.h - AMSI bypass detector (T1562.001).
 *
 * Graded, deduplicated detection of the act of bypassing the
 * Anti-Malware Scan Interface. Complements the existing coverage:
 *   - rule EDR-050 is a static binary regex that fires on any mention
 *     of AmsiUtils/AmsiScanBuffer/amsiInitFailed in script text;
 *   - ApiHookDetector observes inline hooks on AMSI APIs at runtime;
 *   - AmsiEnricher USES AMSI to scan content and never sees a bypass
 *     that disabled it.
 * This detector grades the behavior across both faces (command line
 * one-liners and PowerShell script blocks):
 *   - AmsiInitFailed flag patch via reflection (SetValue/$false) -> 90
 *   - amsi.dll / AmsiScanBuffer memory-stub patch pair           -> 85
 *   - well-known bypass helper invocation (Disable-Amsi,
 *     Bypass-Amsi, ...)                                           -> 80
 *   - [Ref].Assembly.GetType(...AmsiUtils...) reflection prep    -> 75
 *   - bare amsiInitFailed / AmsiScanBuffer reference             -> 60
 *
 * Face selection follows the house contract: kCommandLine first, then
 * kScriptBlockText for POWERSHELL_SCRIPT events, then kImage.
 *
 * Alerts are deduplicated per normalized text prefix inside the dedup
 * window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_AMSI_BYPASS_DETECTOR_H
#define EDR_AMSI_BYPASS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class AmsiBypassDetector {
public:
    AmsiBypassDetector(bool enabled, uint32_t minScore,
                       uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_AMSI_BYPASS_DETECTOR_H */
