/*
 * shadow_copy_detector.h - System-restore suppression detector (T1490).
 *
 * Ransomware and destructive operators delete Volume Shadow Copies and
 * disable recovery before detonating so victims cannot roll back. This
 * detector scores PROCESS_START command lines that:
 *   - delete all shadow copies  (vssadmin delete shadows /all)     -> 90
 *   - delete a volume's shadow copies (vssadmin delete shadows
 *     /for=<vol>)                                                  -> 75
 *   - delete shadow storage via WMI (wmic shadowcopy delete /
 *     shadowcopy call delete)                                      -> 75
 *   - remove shadow copies via PowerShell (Get-WmiObject
 *     Win32_ShadowCopy | Remove-WmiObject / .Delete())             -> 70
 *   - delete the backup catalog (wbadmin delete catalog)           -> 70
 *   - disable boot recovery (bcdedit recoveryenabled no)           -> 60
 *
 * Combining shadow deletion with recovery-disable escalates to 95.
 * The anti_forensics detector already covers log/audit clearing; this
 * detector is the filesystem-restore plane (T1490).
 *
 * Alerts are deduplicated per signal key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SHADOW_COPY_DETECTOR_H
#define EDR_SHADOW_COPY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ShadowCopyDetector {
public:
    ShadowCopyDetector(bool enabled, uint32_t minScore,
                       uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool AnalyzeCommand(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_SHADOW_COPY_DETECTOR_H */
