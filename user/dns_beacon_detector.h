/*
 * dns_beacon_detector.h - DNS beaconing / DGA domain enrichment detector.
 *
 * Lexical DGA evidence is independent of process identity and is stamped on
 * eligible DNS_QUERY events. Beacon correlation uses a strict event-time
 * sliding window and requires source and either
 * PID plus exact process start time or a valid nonzero process GUID. Weak or
 * contradictory identities are never used as a fallback. The optional
 * endpoint field scopes remote events; its absence denotes local telemetry.
 * Image is optional validated display metadata, not part of the identity key.
 *
 * Per-key observations are bounded by a global 100,000-entry budget. When the
 * global budget is full, the least recently observed other key is evicted as
 * a whole. If the current key alone owns the budget, its oldest observation
 * is discarded and counters become a lower bound until that timestamp ages
 * out; this can suppress a detection or delay rearming under sustained load,
 * but cannot inflate counts. The configured query and entropy thresholds up
 * to 100,000 remain reachable for one key.
 *
 * State is also bounded by the configured key capacity (clamped to 65,536).
 * Same-band alerts are suppressed; a score may be emitted on first
 * qualification and again when it crosses the 10 and 20 score bands. The
 * detector rearms only after the strict-window evidence no longer qualifies.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_DNS_BEACON_DETECTOR_H
#define EDR_DNS_BEACON_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DnsBeaconDetector {
public:
    DnsBeaconDetector(bool enabled, uint32_t windowSeconds,
                      size_t stateCapacity, uint32_t minQueryCount,
                      uint32_t minHighEntropyCount);

    void Enrich(Event& event);

    /* True only for DNS_QUERY events. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct Observation {
        uint64_t timestamp100ns = 0;
        bool highEntropy = false;
    };

    struct KeyState {
        std::deque<Observation> observations;
        uint32_t totalCount = 0;
        uint32_t highEntropyCount = 0;
        int emittedBand = -1;
        uint64_t latestTimestamp100ns = 0;
        uint64_t lastSeenWall100ns = 0;
        uint64_t discardedThrough100ns = 0;
    };

    using StateMap = std::unordered_map<std::string, KeyState>;

    void EraseState(StateMap::iterator it);
    void EvictOldestKey(StateMap::iterator except);
    void MakeObservationRoom(StateMap::iterator current);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minQueryCount;
    uint32_t m_minHighEntropyCount;
    size_t m_totalObservations = 0;
    StateMap m_keys;
};

} // namespace edr

#endif /* EDR_DNS_BEACON_DETECTOR_H */
