/*
 * history_tamper_detector.h - Command-history tamper detector
 * (T1070.003 Clear Command History, T1562.003 Impair Command History
 * Logging).
 *
 * Both techniques target the same artifact - the shell history that an
 * investigator reads first - either by destroying it after the fact or by
 * disabling capture up front:
 *   - Set-PSReadLineOption -HistorySaveStyle SaveNothing            -> 90
 *   - HistorySavePath redirected to nul / a throwaway path           -> 85
 *   - ConsoleHost_history.txt deleted or truncated (command plane or
 *     FILE_DELETE of the file itself)                               -> 85
 *   - Clear-History / doskey /reinstall (in-memory buffer only)      -> 75
 *   - bare reference to the history file with no destructive verb     -> 60
 *
 * Disabling capture outranks deleting the file: it makes every later
 * command in the session invisible rather than removing a fixed record.
 * Read-only inspection (Get-Content, Get-PSReadLineOption, Get-History)
 * stays silent. Complements anti_forensics, which covers the Windows
 * event-log plane (1102 / 1100 / 4719).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_HISTORY_TAMPER_DETECTOR_H
#define EDR_HISTORY_TAMPER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class HistoryTamperDetector {
public:
    HistoryTamperDetector(bool enabled, uint32_t minScore,
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
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_HISTORY_TAMPER_DETECTOR_H */
