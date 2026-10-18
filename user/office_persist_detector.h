/*
 * office_persist_detector.h - Office application-startup persistence
 * detector (T1137 / T1137.001 / T1137.002 / T1137.006).
 *
 * Scores the Office add-in / template / VBA-project plane that survives
 * reboot independently of Run keys:
 *   - VBAProject.OTM write / copy into Outlook                    -> 90
 *   - COM add-in registry under Office\...\Addins + LoadBehavior  -> 90
 *   - Word STARTUP .wll drop                                      -> 85
 *   - Excel XLSTART .xlam/.xla/.xll drop or OPEN/OPEN1 value      -> 85
 *   - Outlook WebAddins / homepage hijack                         -> 80
 *   - Application.AddIns.Add / Register-ExcelAddin                -> 80
 *   - generic Office\Addins registry write without LoadBehavior   -> 75
 *
 * Read-only listing of STARTUP/XLSTART and ordinary WinWord/Excel
 * launches stay silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_OFFICE_PERSIST_DETECTOR_H
#define EDR_OFFICE_PERSIST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class OfficePersistDetector {
public:
    OfficePersistDetector(bool enabled, uint32_t minScore,
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

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_OFFICE_PERSIST_DETECTOR_H */
