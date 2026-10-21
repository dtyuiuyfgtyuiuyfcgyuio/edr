/*
 * privilege_escalation_detector.h - Privilege escalation detector
 * (MITRE T1134 / T1543.003 / T1574.001).
 *
 * Correlates escalation indicators:
 *  - Service install with a suspicious binary path
 *  - Token manipulation: access to other process with duplicate-handle rights
 *  - Suspicious DLL sideloading into elevated processes
 * Signals are heuristics, not proof of successful elevation. Cross-event
 * scores require a reliable process instance, source and endpoint scope.
 * Without that identity only the current event's signal is stamped.
 */
#ifndef EDR_PRIVILEGE_ESCALATION_DETECTOR_H
#define EDR_PRIVILEGE_ESCALATION_DETECTOR_H

#include <cstddef>
#include <array>
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
        std::array<uint64_t, 5> signalTimes{};
    };

    static bool IsSuspiciousServicePath(const std::string& path);
    static bool IsSuspiciousPrivilege(const std::string& privileges);
    static bool HasDuplicateHandleAccess(const std::string& accessMask);
    static bool IsElevatedImage(const std::string& image);
    void PurgeExpired(uint64_t now100ns);
    void ExpireSignals(ProcState& state, uint64_t now100ns) const;
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    std::string TechniqueList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<std::string, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_PRIVILEGE_ESCALATION_DETECTOR_H */
