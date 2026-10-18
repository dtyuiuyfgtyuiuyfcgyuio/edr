/*
 * timestomp_detector.h - File timestamp tampering detector (T1070.006).
 *
 * Scores PROCESS_START command lines, POWERSHELL_SCRIPT bodies, and
 * Sysmon Event ID 2 FILE_INTEGRITY telemetry that alter file times to
 * blend in with surrounding legitimate files:
 *   - Sysmon reports a file creation-time change                 -> 95
 *   - timestomp.exe / similar dedicated tools invoked directly  -> 85
 *   - PowerShell (Get-Item $f).LastWriteTime= /
 *     CreationTime= / LastAccessTime= assignment                -> 70
 *   - [IO.File]::SetLastWriteTime/SetCreationTime/
 *     SetLastAccessTime .NET calls                              -> 70
 *   - touch-style cmd built-ins are not covered (no such builtin)
 *
 * Only deliberate time-setting on executables/documents is scored;
 * bulk-copy tools that preserve times (robocopy /COPYALL) are out of
 * scope to avoid backup-job false positives.
 *
 * Alerts are deduplicated per normalized command prefix inside the
 * dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_TIMESTOMP_DETECTOR_H
#define EDR_TIMESTOMP_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class TimestompDetector {
public:
    TimestompDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, Finding* out) const;
    bool AnalyzeSysmonFileTime(const Event& event, Finding* out,
                               std::string* key) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_TIMESTOMP_DETECTOR_H */
