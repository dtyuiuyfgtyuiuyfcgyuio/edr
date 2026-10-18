/*
 * discovery_recon_detector.h - Host-wide discovery/reconnaissance correlation.
 *
 * Classifies PROCESS_START command lines into common Windows discovery
 * techniques (system, account, domain, network, share, process, security
 * software, registry, scheduled task). When minTechniques distinct
 * techniques are seen inside windowSeconds, the current event is stamped
 * with discovery_score / discovery_techniques / discovery_count /
 * discovery_window_seconds and a verdict.
 *
 * Individual commands can be benign; the detector only fires when several
 * distinct reconnaissance categories appear in a short host-wide window.
 */
#ifndef EDR_DISCOVERY_RECON_DETECTOR_H
#define EDR_DISCOVERY_RECON_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

std::string ClassifyDiscoveryTechnique(const std::string& image,
                                       const std::string& commandLine);

class DiscoveryReconDetector {
public:
    DiscoveryReconDetector(bool enabled, uint32_t windowSeconds,
                           size_t stateCapacity, uint32_t minTechniques,
                           uint32_t dedupSeconds);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct TechniqueInfo {
        uint64_t lastSeen100ns = 0;
    };

    struct KeyState {
        std::unordered_map<std::string, TechniqueInfo> techniques;
        uint32_t lastFlaggedCount = 0;
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const KeyState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minTechniques;
    uint64_t m_dedup100ns;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_DISCOVERY_RECON_DETECTOR_H */
