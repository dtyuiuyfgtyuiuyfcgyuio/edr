/*
 * motw_bypass_detector.h - Mark-of-the-Web removal detector
 * (T1553.005 Mark-of-the-Web Bypass).
 *
 * Scores command/script/registry activity that strips or disables the
 * zone-information provenance so downloaded payloads dodge SmartScreen
 * and attachment-manager prompts:
 *   - PowerShell Unblock-File on a payload path                 -> 75
 *   - del/stream deletion of :Zone.Identifier ADS               -> 85
 *   - dir /r enumeration of ADS (recon for the step above)      -> 55
 *   - registry: Attachment Manager SaveZoneInformation=2
 *     ("never save" MOTW) under Policies\Attachments            -> 90
 *
 * Read-only `Get-Item -Stream Zone.Identifier` inspection stays silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_MOTW_BYPASS_DETECTOR_H
#define EDR_MOTW_BYPASS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class MotwBypassDetector {
public:
    MotwBypassDetector(bool enabled, uint32_t minScore,
                       uint32_t dedupWindowSeconds,
                       size_t stateCapacity);

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

#endif /* EDR_MOTW_BYPASS_DETECTOR_H */
