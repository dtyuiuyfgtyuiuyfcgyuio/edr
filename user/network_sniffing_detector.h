/*
 * network_sniffing_detector.h - Network sniffing / capture tool detector
 * (MITRE T1040).
 *
 * Flags capture-plane activity on the command/script faces:
 *   - netsh trace start / pktmon start (built-in capture)       -> 85
 *   - wireshark / tshark / dumpcap / tcpdump / windump /         -> 80
 *     netsniff-ng packet capture suites
 *   - NPcap / WinPcap driver installation (msiexec / pnputil)    -> 75
 *   - PowerShell raw-socket capture via SIO_RCVALL               -> 80
 *   - netsh trace convert (ETL -> pcap conversion of captures)   -> 60
 *   - klist-style read-only status queries are never scored
 *
 * 55+ alerted; 75+ malicious.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_NETWORK_SNIFFING_DETECTOR_H
#define EDR_NETWORK_SNIFFING_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class NetworkSniffingDetector {
public:
    NetworkSniffingDetector(bool enabled, uint32_t minScore,
                            uint32_t dedupWindowSeconds,
                            size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_NETWORK_SNIFFING_DETECTOR_H */
