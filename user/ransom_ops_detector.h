/*
 * ransom_ops_detector.h - Business-destruction precursor detector.
 *
 * Complements the anti-recovery RansomPrecursorDetector (shadow copy /
 * backup / recovery / logs). This detector scores the *business
 * disruption* plane that ransomware operators touch in the same
 * preparation phase (T1489 service stop / T1070.004 task deletion /
 * T1490 startup wipe / T1562.001 defensive process kill):
 *   - stopping a recognized security / database / backup / VSS service
 *     (sc stop / net stop / Stop-Service / sc config start= disabled) -> 75
 *     two at once 85, three or more 90
 *   - deleting scheduled tasks (schtasks /delete)                     -> 65
 *   - force-killing a defensive process (taskkill /f)                 -> 70
 *   - removing startup Run/RunOnce entries via reg delete or
 *     Remove-ItemProperty                                            -> 70
 *   - disabling VSS/backup/eventlog services via config               -> 75
 *   Combos of 2+ distinct signals within one command escalate +15.
 *
 * Single-event scorer with per-signal dedup (see shadow_copy_detector).
 */
#ifndef EDR_RANSOM_OPS_DETECTOR_H
#define EDR_RANSOM_OPS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class RansomOpsDetector {
public:
    RansomOpsDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    bool AnalyzeCommand(const std::string& lower, uint32_t* score,
                        std::string* signals) const;
    void Stamp(Event& event, uint32_t score, const std::string& signals);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_RANSOM_OPS_DETECTOR_H */
