/*
 * acl_abuse_detector.h - File/directory permission abuse detector
 * (T1222.001 / T1222.002).
 *
 * Flags command/script-plane activity that weakens ACLs or seizes
 * ownership to prepare for staging, hiding, or tampering:
 *   - icacls ... /grant Everyone:(F|M), /inheritance:r, /reset   -> 75-85
 *   - takeown /f ...                                              -> 70
 *   - cacls /e /p /g /r                                           -> 75
 *   - PowerShell Set-Acl / Get-Acl + SetAccessRule / RemoveAccessRule
 *     on user-writable or system-sensitive paths                 -> 70-85
 *
 * Read-only ACL inspection is not scored. 55+ alerted; 75+ malicious.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_ACL_ABUSE_DETECTOR_H
#define EDR_ACL_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class AclAbuseDetector {
public:
    AclAbuseDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_ACL_ABUSE_DETECTOR_H */