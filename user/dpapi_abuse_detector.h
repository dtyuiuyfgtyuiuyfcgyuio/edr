/*
 * dpapi_abuse_detector.h - DPAPI credential abuse detector
 * (T1555 / T1003 credential-access family).
 *
 * Grades the act of attacking Windows DPAPI-protected secret stores
 * across the command plane and PowerShell script blocks:
 *   - SharpDPAPI / SharpChrome / mimikatz "dpapi::" module        -> 90
 *   - DPAPI + masterkey export/unprotect primitives               -> 85
 *   - Browser credential store path + decryption context          -> 75
 *     (Chrome Login Data / Local State, Firefox logins.json /
 *     key4.db) paired with dpapi/decrypt primitives
 *   - vaultcmd listing credential vaults                          -> 65
 *   - cmdkey /list enumeration                                    -> 60
 *
 * Face selection follows the house contract: kCommandLine first, then
 * kScriptBlockText for POWERSHELL_SCRIPT events, then kImage.
 *
 * Alerts are deduplicated per normalized text prefix inside the dedup
 * window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_DPAPI_ABUSE_DETECTOR_H
#define EDR_DPAPI_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DpapiAbuseDetector {
public:
    DpapiAbuseDetector(bool enabled, uint32_t minScore,
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
    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_DPAPI_ABUSE_DETECTOR_H */
