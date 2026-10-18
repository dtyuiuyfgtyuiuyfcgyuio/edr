/*
 * registry_persistence_detector.h - Registry-based persistence detector (MITRE T1547).
 *
 * Detects adversaries establishing persistence via Windows Registry modifications.
 * Monitors REG_WRITE events for known persistence registry keys:
 *  - Run/RunOnce keys (T1547.001)
 *  - Image File Execution Options (IFEO) Debugger (T1546.012)
 *  - Winlogon Shell/Userinit (T1547.004)
 *  - AppInit_DLLs (T1574.002)
 *  - LSA Security Packages (T1546.008)
 *  - COM hijacking (T1546.008)
 *  - Service registrations (T1543.003)
 *  - WMI event subscriptions (T1546.003)
 * Events are stamped with registry_persistence_* fields when confirmed.
 */
#ifndef EDR_REGISTRY_PERSISTENCE_DETECTOR_H
#define EDR_REGISTRY_PERSISTENCE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class RegistryPersistenceDetector {
public:
    RegistryPersistenceDetector(bool enabled, uint32_t windowSeconds,
                                size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        std::unordered_set<std::string> mechanisms;
        std::unordered_set<std::string> regKeys;
        uint32_t persistenceCount = 0;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsPersistenceRegistryKey(const std::string& regKey,
                                         std::string& mechanism);
    static bool IsSuspiciousServicePath(const std::string& imagePath);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state) const;
    std::string MechanismList(const ProcState& state) const;
    std::string KeyList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state,
                    const std::string& mechanism);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_REGISTRY_PERSISTENCE_DETECTOR_H */
