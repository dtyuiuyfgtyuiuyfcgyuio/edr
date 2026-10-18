/*
 * rdp_chain_detector.h - RDP session activity chain detector.
 *
 * Correlates repeated RDP session events by source IP and user within a
 * rolling window. When the same source repeatedly logs on or reconnects, the
 * current event is stamped with rdp_chain_score / rdp_chain_count /
 * rdp_chain_sources / rdp_chain_window_seconds / rdp_chain_verdict.
 */
#ifndef EDR_RDP_CHAIN_DETECTOR_H
#define EDR_RDP_CHAIN_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class RdpChainDetector {
public:
    RdpChainDetector(bool enabled, uint32_t windowSeconds,
                     size_t stateCapacity, uint32_t minDistinctSources);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_sessions.size(); }

private:
    struct SourceInfo {
        uint64_t lastSeen100ns = 0;
    };

    struct SessionState {
        std::unordered_map<std::string, SourceInfo> sources;
        uint32_t lastFlaggedCount = 0;
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const SessionState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minDistinctSources;
    std::unordered_map<std::string, SessionState> m_sessions;
};

} // namespace edr

#endif /* EDR_RDP_CHAIN_DETECTOR_H */
