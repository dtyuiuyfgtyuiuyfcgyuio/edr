/*
 * powershell_download_execute_detector.h - PowerShell download-then-execute
 * chain detector.
 *
 * Correlates repeated PowerShell process starts by the same parent process.
 * When a PowerShell process launches another suspicious child within the
 * window and the command line contains download/execution markers, the event
 * is stamped with powershell_download_execute_* fields.
 */
#ifndef EDR_POWERSHELL_DOWNLOAD_EXECUTE_DETECTOR_H
#define EDR_POWERSHELL_DOWNLOAD_EXECUTE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PowerShellDownloadExecuteDetector {
public:
    PowerShellDownloadExecuteDetector(bool enabled, uint32_t windowSeconds,
                                      size_t stateCapacity,
                                      uint32_t minDistinctScripts);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_parents.size(); }

private:
    struct ScriptInfo {
        uint64_t lastSeen100ns = 0;
    };

    struct ParentState {
        std::unordered_map<std::string, ScriptInfo> scripts;
        uint32_t lastFlaggedCount = 0;
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const ParentState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minDistinctScripts;
    std::unordered_map<std::string, ParentState> m_parents;
};

} // namespace edr

#endif /* EDR_POWERSHELL_DOWNLOAD_EXECUTE_DETECTOR_H */
