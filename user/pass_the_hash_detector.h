/*
 * pass_the_hash_detector.h - Pass-the-Hash / credential reuse detector
 * (T1550.002).
 *
 * After harvesting NTLM hashes, attackers replay them against remote hosts
 * instead of cracking them. This detector scores PROCESS_START command
 * lines for PTH tooling:
 *   - mimikatz sekurlsa::pth with /ntlm hash                 -> 90
 *   - Impacket psexec/wmiexec/smbexec/atexec/dcomexec -hashes -> 85
 *   - evil-winrm -H <ntlm hash>                               -> 85
 *   - crackmapexec smb -H / --hashes                          -> 80
 *   - samba pth-winexe / pth-net / pth-smbclient tools        -> 75
 *
 * Alerts are deduplicated per signal key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PASS_THE_HASH_DETECTOR_H
#define EDR_PASS_THE_HASH_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PassTheHashDetector {
public:
    PassTheHashDetector(bool enabled, uint32_t minScore,
                        uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string tool;
    };

    bool AnalyzeCommandLine(const std::string& lower, Finding* out) const;
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

#endif /* EDR_PASS_THE_HASH_DETECTOR_H */
