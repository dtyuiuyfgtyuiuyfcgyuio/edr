/*
 * cryptominer_detector.h - Cryptocurrency miner detector (MITRE T1496).
 *
 * Detects cryptomining activity through multiple signals:
 *  - Network connections to known mining pool domains/IPs
 *  - DNS queries to mining pool domains
 *  - Process starts of known mining binaries
 *  - Stratum protocol connections (port 3333, 4444, 14444, 14433)
 * Events are stamped with crypto_miner_* fields when confirmed.
 */
#ifndef EDR_CRYPTOMINER_DETECTOR_H
#define EDR_CRYPTOMINER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class CryptominerDetector {
public:
    CryptominerDetector(bool enabled, uint32_t windowSeconds,
                        size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        bool sawPoolDomain = false;
        bool sawPoolIp = false;
        bool sawStratumPort = false;
        bool sawMinerBinary = false;
        std::unordered_set<std::string> poolDomains;
        std::unordered_set<std::string> poolIps;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsKnownMiningPoolDomain(const std::string& domain);
    static bool IsKnownMinerBinary(const std::string& image);
    static bool IsStratumPort(const std::string& port);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    std::string PoolDomainList(const ProcState& state) const;
    std::string PoolIpList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_CRYPTOMINER_DETECTOR_H */
