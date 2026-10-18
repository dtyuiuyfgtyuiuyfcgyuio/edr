/*
 * anti_forensics_detector.h - Anti-forensics / log-clearing detector
 * (MITRE T1070.002).
 *
 * Consumes AUDIT_LOG events produced by the security log parser:
 *  - 1102 Security log cleared        -> "security_log_cleared" (weight 55)
 *  - 1100 Event log service shut down -> "security_audit_stopped" (weight 20)
 *  - 4719 Audit policy changed        -> "audit_policy_changed" (weight 30)
 *  - 1104 Security log now full       -> "security_log_full"    (weight 15)
 *
 * State is keyed by acting subject account. A single clear is already
 * alert-worthy (55 = SUSPICIOUS); repeated clears or combinations within
 * the correlation window escalate to 75+ (MALICIOUS). Events are stamped
 * with anti_forensics_* fields.
 */
#ifndef EDR_ANTI_FORENSICS_DETECTOR_H
#define EDR_ANTI_FORENSICS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class AntiForensicsDetector {
public:
    AntiForensicsDetector(bool enabled, uint32_t windowSeconds,
                          size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_actors.size(); }

private:
    struct ActorState {
        std::unordered_set<std::string> mechanisms;
        uint32_t clearCount = 0;
        uint64_t lastSeen100ns = 0;
    };

    static std::string LowerAscii(std::string value);
    std::string ActorKey(const Event& event) const;
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ActorState& state) const;
    std::string MechanismList(const ActorState& state) const;
    void WriteState(Event& event, const ActorState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<std::string, ActorState> m_actors;
};

} // namespace edr

#endif /* EDR_ANTI_FORENSICS_DETECTOR_H */
