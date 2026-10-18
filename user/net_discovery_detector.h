/*
 * net_discovery_detector.h - Network discovery burst detector
 * (T1018 Remote System Discovery / T1049 System Network Connections
 * Discovery).
 *
 * Scores PROCESS_START command lines and POWERSHELL_SCRIPT bodies that
 * enumerate network topology or connection state:
 *
 *   - netstat with PID correlation (-o)                       -> 70
 *   - AD reconnaissance (nltest /dclist, /domain_trusts,
 *     net group /domain)                                      -> 60
 *   - single enumeration commands (net view, plain netstat,
 *     Get-NetTCPConnection, arp -a)                           -> 55
 *   - same-category enumeration burst hitting >= burstThreshold
 *     distinct targets inside windowSeconds (ping sweeps count
 *     only toward the burst)                                  -> 80
 *
 * Complements DiscoveryReconDetector: that one correlates *several
 * distinct reconnaissance categories* in a host-wide window; this one
 * fires on a *single-category* enumeration burst (e.g. a ping sweep or
 * repeated net view against many hosts) and on high-signal single
 * commands.
 *
 * The detector keeps per-category detail sets for the burst window plus
 * a bounded dedup map so repeated legitimate spawns are not re-alerted.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_NET_DISCOVERY_DETECTOR_H
#define EDR_NET_DISCOVERY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class NetDiscoveryDetector {
public:
    NetDiscoveryDetector(bool enabled, uint32_t minScore,
                         uint32_t windowSeconds, uint32_t burstThreshold,
                         uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    /* Classify lowered text into a category; extracts a burst detail
     * (target host/ip or command variant). Returns false when the text
     * is not network discovery. */
    bool Classify(const std::string& lower, std::string* category,
                  std::string* detail, uint32_t* baseScore) const;
    bool Analyze(const Event& event, Finding* out);
    void Stamp(Event& event, const Finding& finding) const;

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_window100ns;
    uint32_t m_burstThreshold;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* category -> (detail -> last seen ts100ns). Category set is fixed
     * (netview/netstat/adrecon/ping/arp); inner maps are capacity-bound. */
    struct CategoryState {
        std::unordered_map<std::string, uint64_t> details;
    };
    std::unordered_map<std::string, CategoryState> m_categories;
    /* "category\x1Fdetail" / "category\x1F!burst" -> ts100ns of last alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_NET_DISCOVERY_DETECTOR_H */
