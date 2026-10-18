/*
 * port_scan_detector.h - Destination-port sweep detector (T1046).
 *
 * Correlates NET_CONNECT events per (pid, image basename) key. When any
 * single destination IP is contacted on at least minDistinctPorts distinct
 * ports inside windowSeconds, the current event is stamped with
 * port_scan_score / port_scan_port_count / port_scan_target /
 * port_scan_sample_ports / port_scan_window_seconds.
 *
 * Distinct from C2BeaconDetector (repeat connections to the same endpoints)
 * and LateralMovementDetector (many hosts on a fixed lateral-port set).
 * Counting ports per destination IP avoids browser/CDN host fan-out and
 * BitTorrent peer meshes, which open many IPs on one or two ports.
 *
 * State is a bounded, time-expiring LRU; expired destinations are swept
 * lazily on every Enrich and a key whose destinations all expire is dropped
 * so its flag resets. Enrichment is best-effort and never throws.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PORT_SCAN_DETECTOR_H
#define EDR_PORT_SCAN_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PortScanDetector {
public:
    PortScanDetector(bool enabled, uint32_t windowSeconds,
                     size_t stateCapacity, uint32_t minDistinctPorts);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct DestState {
        std::set<uint16_t> ports;
        uint64_t lastSeen100ns = 0;
    };

    struct KeyState {
        std::unordered_map<std::string, DestState> dests;
        bool flagged = false;
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const std::string& targetIp,
                    const DestState& dest);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minDistinctPorts;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_PORT_SCAN_DETECTOR_H */
