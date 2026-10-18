/*
 * dcsync_detector.h - DCSync / domain credential replication detector
 * (T1003.006).
 *
 * Attackers abuse the DRSUAPI replication protocol to impersonate a
 * domain controller and pull password hashes for all accounts. This
 * detector scores PROCESS_START command lines and POWERSHELL_SCRIPT
 * bodies for DCSync tooling:
 *   - mimikatz lsadump::dcsync              -> 90
 *   - impacket secretsdump.py -just-dc*     -> 85
 *   - Invoke-DCSync (PowerShell)            -> 85
 *   - standalone dcsync.py / pydcsync       -> 80
 *
 * Alerts are deduplicated per normalized command text inside the dedup
 * window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_DCSYNC_DETECTOR_H
#define EDR_DCSYNC_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DcsyncDetector {
public:
    DcsyncDetector(bool enabled, uint32_t minScore,
                   uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string tool;
    };

    bool AnalyzeCommandLine(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_DCSYNC_DETECTOR_H */
