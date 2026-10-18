/*
 * privileged_group_detector.h - Privileged-group membership modification
 * detector (MITRE T1098 / T1078.002).
 *
 * Consumes ACCOUNT_CHANGE events carrying operation_type GROUP_MEMBER_ADD,
 * emitted from Security log 4728/4732/4756 (member added to a security-
 * enabled global/local/universal group). The actor (subject) who added the
 * member is the correlation key.
 *
 * Additions to sensitive groups score 60 and alert immediately:
 *   Administrators, Domain Admins, Enterprise Admins, Schema Admins,
 *   Backup Operators, Account Operators, Server Operators,
 *   Remote Desktop Users.
 * A second sensitive add inside the window (+20) or group-mod churn
 * (+10 at 4 total adds) escalates into the MALICIOUS band. Non-sensitive
 * additions only stamp once at least 3 accumulate in the window (score 30,
 * hunting visibility below the alerting band).
 */
#ifndef EDR_PRIVILEGED_GROUP_DETECTOR_H
#define EDR_PRIVILEGED_GROUP_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PrivilegedGroupDetector {
public:
    PrivilegedGroupDetector(bool enabled, uint32_t windowSeconds,
                            size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_actors.size(); }

private:
    struct ActorState {
        std::unordered_set<std::string> groups;
        uint32_t sensitiveAdds = 0;
        uint32_t totalAdds = 0;
        uint64_t lastSeen100ns = 0;
    };

    static std::string LowerAscii(std::string value);
    static bool IsSensitiveGroup(const std::string& groupName);
    std::string ActorKey(const Event& event) const;
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ActorState& state) const;
    std::string GroupList(const ActorState& state) const;
    void WriteState(Event& event, const ActorState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<std::string, ActorState> m_actors;
};

} // namespace edr

#endif /* EDR_PRIVILEGED_GROUP_DETECTOR_H */
