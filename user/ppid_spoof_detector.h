/*
 * ppid_spoof_detector.h - Parent-PID spoofing detector (T1134.004).
 *
 * Detects processes whose reported parent-child relationship deviates
 * from the expected Windows parentage model:
 *
 *   - Critical system binaries spawned by unexpected parents
 *     (svchost.exe must be a child of services.exe; lsass.exe must be
 *     a child of winlogon.exe; etc.)                          -> 90
 *   - User-mode process reporting PID 0 or PID 4 as parent
 *     without being a known kernel-mode binary                 -> 60
 *
 * The detector maintains a bounded dedup set keyed on "parent\x1Fchild"
 * basename pairs so repeated legitimate spawns are not re-alerted.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PPID_SPOOF_DETECTOR_H
#define EDR_PPID_SPOOF_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PpidSpoofDetector {
public:
    PpidSpoofDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& parentImage,
                 const std::string& childImage, uint32_t ppid,
                 Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* lowercase "child_basename" -> allowed parent basenames set. */
    std::unordered_map<std::string, std::unordered_set<std::string>>
        m_expectedParents;
    /* lowercase "parent\x1Fchild" -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_PPID_SPOOF_DETECTOR_H */
