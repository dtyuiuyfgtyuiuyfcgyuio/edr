#ifndef EDR_SILVERFOX_DETECTOR_H
#define EDR_SILVERFOX_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "event_bus.h"

namespace edr {

class SilverFoxDetector {
public:
    SilverFoxDetector(bool enabled, uint32_t correlationWindowSeconds,
                      size_t stateCapacity);

    bool LoadIndicators(const std::string& path, std::string& error);
    void Enrich(Event& event);

    size_t IndicatorCount() const { return m_indicators.size(); }
    bool Enabled() const { return m_enabled; }

private:
    enum class IndicatorType { Sha256, CertificateSha256, Domain, Ipv4 };

    struct Indicator {
        std::string id;
        IndicatorType type = IndicatorType::Sha256;
        std::string value;
        std::string confidence;
        std::string sourceUrl;
        std::string observedAt;
    };

    struct ProcessState {
        uint64_t lastSeen100ns = 0;
        std::string identity;
        int score = 0;
        std::vector<std::string> signals;
    };

    void PurgeExpired(uint64_t now100ns);
    void StoreState(uint32_t pid, ProcessState state);

    bool m_enabled;
    uint64_t m_window100ns;
    size_t m_stateCapacity;
    std::vector<Indicator> m_indicators;
    std::unordered_map<uint32_t, ProcessState> m_states;
};

} // namespace edr

#endif // EDR_SILVERFOX_DETECTOR_H
