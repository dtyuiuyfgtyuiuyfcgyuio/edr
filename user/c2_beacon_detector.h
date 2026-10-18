/*
 * c2_beacon_detector.h - C2 beacon detector.
 *
 * Correlates NET_CONNECT events per (pid, image basename) key into a rolling
 * window of destination endpoints. When at least minRepeatEndpoints distinct
 * endpoints each show at least minConnectionsPerEndpoint connections within
 * windowSeconds, the current event is stamped with c2_beacon_score/
 * c2_beacon_repeat_connections/c2_beacon_destinations/c2_beacon_window_seconds.
 * State is a bounded, time-expiring LRU; expired endpoints are swept lazily on
 * every Enrich and a key whose endpoints all expire is dropped so its flag
 * resets. Enrichment is best-effort and never throws.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_C2_BEACON_DETECTOR_H
#define EDR_C2_BEACON_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class C2BeaconDetector {
public:
    C2BeaconDetector(bool enabled, uint32_t windowSeconds,
                     size_t stateCapacity, uint32_t minRepeatEndpoints,
                     uint32_t minConnectionsPerEndpoint);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct EndpointInfo {
        uint32_t count = 0;
        uint64_t lastSeen100ns = 0;
    };

    struct KeyState {
        std::unordered_map<std::string, EndpointInfo> endpoints;
        bool flagged = false;
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const KeyState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minRepeatEndpoints;
    uint32_t m_minConnectionsPerEndpoint;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_C2_BEACON_DETECTOR_H */
