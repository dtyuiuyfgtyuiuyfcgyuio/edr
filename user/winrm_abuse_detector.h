/*
 * winrm_abuse_detector.h - WinRM remote-execution abuse detector
 * (T1021.006).
 *
 * lateral_movement covers the network plane (5985/5986 connects); this
 * detector covers the command/script execution plane:
 *   - winrs.exe invocation                                     -> 85
 *   - PowerShell New-PSSession / Enter-PSSession /
 *     Invoke-Command with -ComputerName                        -> 80
 *   - winrm invoke / winrm create against a remote (-r:)        -> 75
 *   - winrm quickconfig (listener enablement)                   -> 60
 *
 * Local-only winrm identify / help output is never scored.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_WINRM_ABUSE_DETECTOR_H
#define EDR_WINRM_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class WinrmAbuseDetector {
public:
    WinrmAbuseDetector(bool enabled, uint32_t minScore,
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

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_WINRM_ABUSE_DETECTOR_H */
