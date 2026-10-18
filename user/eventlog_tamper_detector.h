/*
 * eventlog_tamper_detector.h - Windows event log tampering detector
 * (T1070.001 Clear Windows Event Logs / T1562.002 Disable Windows Event Logging).
 *
 * Scores PROCESS_START command lines and POWERSHELL_SCRIPT bodies that
 * clear or disable event log channels:
 *   - wevtutil cl Security / Clear-EventLog -LogName Security   -> 90
 *   - wevtutil sl <channel> /e:false (disable channel)         -> 85
 *   - wevtutil cl <any> / Clear-EventLog (generic) / Remove-EventLog -> 75
 *   - wevtutil gl / wevtutil gli (enumeration, low)            -> 55
 *   - auditpol /clear (audit policy wipe)                       -> 80
 *
 * Boundary-safe needles: "wevtutil " with trailing space, "clear-eventlog"
 * as substring, "/e:false" exact. Case-insensitive via lowered copy.
 * Dedup with score-upgrade widening (new higher score bypasses cooldown).
 *
 * Thread-safety: no internal sync; only EventBus consumer thread calls Enrich.
 */
#ifndef EDR_EVENTLOG_TAMPER_DETECTOR_H
#define EDR_EVENTLOG_TAMPER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class EventlogTamperDetector {
public:
    EventlogTamperDetector(bool enabled, uint32_t minScore,
                           uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
    size_t StateCount() const { return m_state.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };
    struct DedupEntry {
        uint64_t ts100ns = 0;
        uint32_t score = 0;
    };
    bool Analyze(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string, DedupEntry> m_state;
    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr
#endif
