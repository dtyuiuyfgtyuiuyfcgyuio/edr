/*
 * named_pipe_abuse_detector.h - Suspicious named-pipe IPC detector.
 *
 * Consumes NAMED_PIPE events from the Kernel-File ETW collector. The
 * detector is intentionally opt-in because named pipes are common Windows
 * infrastructure; it raises only when a pipe name or its cross-process
 * activity provides additional abuse context.
 */
#ifndef EDR_NAMED_PIPE_ABUSE_DETECTOR_H
#define EDR_NAMED_PIPE_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class NamedPipeAbuseDetector {
public:
    NamedPipeAbuseDetector(bool enabled, uint32_t minScore,
                           uint32_t windowSeconds, size_t stateCapacity,
                           uint32_t minDistinctPids,
                           uint32_t dedupWindowSeconds);

    static bool Inspects(uint16_t type);
    void Enrich(Event& event);
    size_t StateCount() const { return m_states.size(); }

private:
    struct State {
        uint64_t lastSeen100ns = 0;
        uint64_t lastAlert100ns = 0;
        uint32_t operationCount = 0;
        uint32_t connectedCount = 0;
        std::unordered_set<std::string> pids;
    };

    void PurgeExpired(uint64_t now100ns);

    bool m_enabled;
    uint32_t m_minScore;
    uint32_t m_windowSeconds;
    uint64_t m_window100ns;
    size_t m_stateCapacity;
    uint32_t m_minDistinctPids;
    uint64_t m_dedupWindow100ns;
    std::unordered_map<std::string, State> m_states;
};

} // namespace edr

#endif /* EDR_NAMED_PIPE_ABUSE_DETECTOR_H */
