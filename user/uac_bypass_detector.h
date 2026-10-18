/*
 * uac_bypass_detector.h - UAC bypass chain detector.
 *
 * Correlates recent writes to well-known UAC bypass registry locations with
 * the launch of auto-elevation binaries (fodhelper, eventvwr, computerdefaults,
 * sdclt). When an elevated binary starts while a bypass key write is still
 * inside the rolling window, the PROCESS_START event is stamped with
 * uac_bypass_* fields.
 */
#ifndef EDR_UAC_BYPASS_DETECTOR_H
#define EDR_UAC_BYPASS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class UacBypassDetector {
public:
    UacBypassDetector(bool enabled, uint32_t windowSeconds,
                      size_t stateCapacity, uint32_t minDistinctKeys);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_recentKeys.size(); }

private:
    struct KeyInfo {
        uint64_t lastSeen100ns = 0;
    };

    bool IsBypassKey(const std::string& key) const;
    bool IsElevatedBinary(const std::string& image) const;
    void PurgeExpired(uint64_t now100ns);
    uint32_t DistinctRecentKeys(uint64_t now100ns);
    void WriteState(Event& event, uint32_t count, uint32_t score,
                    const std::vector<std::string>& keys);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minDistinctKeys;
    std::unordered_map<std::string, KeyInfo> m_recentKeys;
};

} // namespace edr

#endif /* EDR_UAC_BYPASS_DETECTOR_H */
