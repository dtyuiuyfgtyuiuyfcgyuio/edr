/*
 * nonstandard_port_egress_detector.h - Outbound egress shape detector
 * (T1095 Non-Application Layer Protocol, T1571 Non-Standard Port).
 *
 * Correlates NET_CONNECT events per (pid, image basename) key inside a
 * rolling window and scores the *shape* of a process's outbound traffic,
 * never a single connection. The signals are deliberately shape-only:
 *
 *   unusual_port  one destination port outside the well-known list
 *   many_hosts    many distinct destination IPs in one window
 *   many_ports    many distinct destination ports in one window
 *   raw_protocol  non-application-layer transport or a classic
 *                 raw/beacon port
 *   high_volume   sustained outbound connection count in one window
 *
 * A lone connection to a high or random port is routine and stays silent:
 * the score only reaches the house 55 SUSPICIOUS floor when a breadth or
 * volume signal is combined with a non-standard port or a raw transport,
 * so ordinary browser and updater fan-out never alerts. Shape, not
 * identity - no image name, path or signature is consulted.
 *
 * Complements TunnelToolDetector (T1572/T1090), which scores known tunnel
 * and proxy tools at process start and never looks at traffic, and
 * DohAbuseDetector (T1071.004), which scores DNS-over-HTTPS resolvers.
 * Together they cover covert channels whose tool identity is unknown or
 * absent, which is where T1095 and T1571 were previously unobserved.
 *
 * State is a bounded, time-expiring map; expired actors are swept lazily
 * and reset their window. Enrichment is best-effort and never throws.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_NONSTANDARD_PORT_EGRESS_DETECTOR_H
#define EDR_NONSTANDARD_PORT_EGRESS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class NonstandardPortEgressDetector {
public:
    NonstandardPortEgressDetector(bool enabled, uint32_t minScore,
                                  uint32_t windowSeconds,
                                  uint32_t dedupWindowSeconds,
                                  size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_actors.size(); }

private:
    struct ActorState {
        std::unordered_set<std::string> hosts;
        std::unordered_set<int> ports;
        uint32_t connections = 0;
        bool unusualPortSeen = false;
        bool rawProtocolSeen = false;
        uint64_t windowStart100ns = 0;
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
        uint32_t lastStampScore = 0;
    };

    void ResetWindow(ActorState& state, uint64_t now100ns) const;
    void PurgeExpired(uint64_t now100ns);
    void Stamp(Event& event, uint32_t score, const std::string& signals,
               const ActorState& state) const;

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_window100ns;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string, ActorState> m_actors;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_NONSTANDARD_PORT_EGRESS_DETECTOR_H */
