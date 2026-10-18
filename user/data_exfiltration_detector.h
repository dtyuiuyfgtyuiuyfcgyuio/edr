/*
 * data_exfiltration_detector.h - Data exfiltration detector (MITRE T1048).
 *
 * Correlates multiple exfiltration indicators:
 *  - High volume of outbound network connections to external IPs
 *  - DNS tunneling: many queries to same domain with high-entropy labels
 *  - Bulk file reads followed by outbound network connections
 *  - Connections to known cloud storage / file-sharing endpoints
 * Events are stamped with data_exfil_* fields when confirmed.
 */
#ifndef EDR_DATA_EXFILTRATION_DETECTOR_H
#define EDR_DATA_EXFILTRATION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DataExfiltrationDetector {
public:
    DataExfiltrationDetector(bool enabled, uint32_t windowSeconds,
                             size_t stateCapacity,
                             uint32_t dnsTunnelThreshold);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        uint32_t outboundConnections = 0;
        uint32_t dnsTunnelQueries = 0;
        uint32_t bulkFileReads = 0;
        std::unordered_set<std::string> externalDestinations;
        std::unordered_set<std::string> tunnelDomains;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsExternalIp(const std::string& ip);
    static bool IsHighEntropyDomain(const std::string& domain);
    static bool IsCloudStorageDomain(const std::string& domain);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    std::string DestList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_dnsTunnelThreshold;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_DATA_EXFILTRATION_DETECTOR_H */
