/*
 * anti_analysis_detector.h - Anti-analysis / sandbox evasion detector
 * (MITRE T1497).
 *
 * Detects malware attempting to evade analysis environments:
 *  - VM/sandbox detection commands (process starts with VM-check args)
 *  - Debugger detection (IsDebuggerPresent, NtQueryInformationProcess)
 *  - Sleep bombing / timing-based evasion (long sleeps in script execution)
 *  - System information queries indicating VM checks
 *  - Suspicious parent processes: analysis tools as parent
 * Events are stamped with anti_analysis_* fields when confirmed.
 */
#ifndef EDR_ANTI_ANALYSIS_DETECTOR_H
#define EDR_ANTI_ANALYSIS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class AntiAnalysisDetector {
public:
    AntiAnalysisDetector(bool enabled, uint32_t windowSeconds,
                         size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        bool sawVmCheck = false;
        bool sawDebuggerCheck = false;
        bool sawSleepBomb = false;
        bool sawAnalysisToolParent = false;
        bool sawSysInfoQuery = false;
        uint64_t lastSeen100ns = 0;
    };

    static bool HasVmDetectionArgs(const std::string& cmdLine);
    static bool HasDebuggerDetectionArgs(const std::string& cmdLine);
    static bool HasSleepBombArgs(const std::string& cmdLine);
    static bool IsAnalysisToolParent(const std::string& image);
    static bool IsSysInfoQuery(const std::string& cmdLine);
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

#endif /* EDR_ANTI_ANALYSIS_DETECTOR_H */
