/*
 * defense_evasion_detector.h - Host-wide defense-evasion correlation.
 *
 * Correlates process-start commands and defensive telemetry events that
 * impair Windows Defender, other security services, ETW telemetry, or
 * audit logs. When minTechniques distinct techniques are seen inside
 * windowSeconds, the current event is stamped with
 * defense_evasion_score / defense_evasion_techniques /
 * defense_evasion_count / defense_evasion_window_seconds and a verdict.
 *
 * The detector is host-wide because attackers often chain several signed
 * system binaries to disable different defensive layers.
 */
#ifndef EDR_DEFENSE_EVASION_DETECTOR_H
#define EDR_DEFENSE_EVASION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

std::string ClassifyDefenseEvasionEvent(const Event& event);

class DefenseEvasionDetector {
public:
    DefenseEvasionDetector(bool enabled, uint32_t windowSeconds,
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

#endif /* EDR_DEFENSE_EVASION_DETECTOR_H */
