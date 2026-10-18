/*
 * privilege_escalation_detector.h - Privilege escalation detector
 * (MITRE T1134 / T1068).
 *
 * Correlates escalation indicators:
 *  - Service install with LocalSystem account and suspicious binary path
 *  - Token manipulation: access to other process with duplicate-handle rights
 *  - Privilege escalation via suspicious parent-child: low-priv parent
 *    spawning elevated child
 *  - Suspicious DLL sideloading into elevated processes
 * Events are stamped with priv_esc_* fields when confirmed.
 */
#ifndef EDR_PRIVILEGE_ESCALATION_DETECTOR_H
#define EDR_PRIVILEGE_ESCALATION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PrivilegeEscalationDetector {
public:
    PrivilegeEscalationDetector(bool enabled, uint32_t windowSeconds,
                                 size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        bool sawServiceInstall = false;
        bool sawTokenManipulation = false;
        bool sawPrivilegedChild = false;
        bool sawDllSideload = false;
        bool sawSuspiciousPrivilege = false;
        std::string detail;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsLocalSystemService(const std::string& account);
    static bool IsSuspiciousServicePath(const std::string& path);
    static bool IsSuspiciousPrivilege(const std::string& privileges);
    static bool HasDuplicateHandleAccess(const std::string& accessMask);
    static bool IsElevatedImage(const std::string& image);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    std::string TechniqueList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_PRIVILEGE_ESCALATION_DETECTOR_H */
