/*
 * time_change_detector.h - System time-change evasion detector.
 *
 * Consumes EDR_EVT_SYSTEM_TIME_CHANGE events emitted from Windows Security
 * event 4616 (System Time Changed). Host clock manipulation is a temporal
 * anti-analysis technique (adjacent to T1070.006): rollbacks defeat
 * certificate validity windows and break time-based correlation; large
 * forward jumps distort retention and scheduling.
 *
 * Classification (FILETIME 100ns ticks):
 *  - |delta| <= tolerance_seconds      -> ignored entirely (NTP-scale sync)
 *  - new < previous - tolerance        -> "time_rollback"       (weight 65)
 *  - delta >= big_jump_seconds         -> "large_forward_jump"   (weight 45)
 *  - otherwise                         -> "time_shift"           (weight 30)
 * A second rollback inside the correlation window adds +15 (escalates a
 * single rollback to MALICIOUS).
 */
#ifndef EDR_TIME_CHANGE_DETECTOR_H
#define EDR_TIME_CHANGE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class TimeChangeDetector {
public:
    TimeChangeDetector(bool enabled, uint32_t windowSeconds,
                       size_t stateCapacity, uint32_t toleranceSeconds,
                       uint32_t bigJumpSeconds);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

private:
    struct HostState {
        std::unordered_set<std::string> mechanisms;
        uint32_t changeCount = 0;
        uint32_t rollbackCount = 0;
        uint64_t lastSeen100ns = 0;
    };

    static bool ParseTickString(const std::string& text, uint64_t& out);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const HostState& state) const;
    std::string MechanismList(const HostState& state) const;
    void WriteState(Event& event, const HostState& state,
                    int64_t deltaSeconds);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity; /* host-level state is bounded by design */
    uint64_t m_tolerance100ns;
    uint64_t m_bigJump100ns;
    HostState m_host;
};

} // namespace edr

#endif /* EDR_TIME_CHANGE_DETECTOR_H */
