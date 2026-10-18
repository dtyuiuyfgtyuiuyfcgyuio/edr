/*
 * remote_exec_detector.h - Remote command-execution detector
 * (T1021.002 / T1021.006 / T1053.005).
 *
 * Attackers move laterally by running commands on remote hosts via
 * admin tooling. This detector scores PROCESS_START command lines for
 * the remote-execution verbs (complementary to the port-based
 * lateral_movement correlator):
 *   - PsExec to a remote host                       -> 80
 *   - wmic /node:<host> process call create ...     -> 75
 *   - winrs -r:<host> command                       -> 75
 *   - sc \\<host> create (remote service)           -> 75
 *   - schtasks /create /run with /s <host>          -> 70
 *
 * Local-only uses of the same tools (no remote target marker) are out of
 * scope to keep false positives low.
 *
 * Alerts are deduplicated per signal key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_REMOTE_EXEC_DETECTOR_H
#define EDR_REMOTE_EXEC_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class RemoteExecDetector {
public:
    RemoteExecDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_REMOTE_EXEC_DETECTOR_H */
