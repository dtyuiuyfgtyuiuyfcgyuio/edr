/*
 * cert_abuse_detector.h - Certificate trust abuse detector
 * (T1553.004 install root certificate; T1552.004 private keys).
 *
 * Grades the act of subverting or exploiting the Windows trust store
 * across the command plane and PowerShell script blocks:
 *   - certutil -addstore / -enterprise -addstore into Root (or
 *     Import-Certificate into Cert:\LocalMachine\Root)             -> 90
 *   - private-key export pair (certutil -exportPfx / pvk2pfx /
 *     Export-PfxCertificate)                                       -> 70
 *   - self-signed certificate creation (New-SelfSignedCertificate,
 *     makecert)                                                    -> 60
 *
 * Download faces (-urlcache/-verifyctl fetches) stay covered by the
 * existing EDR rules that already alert on them.
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
#ifndef EDR_CERT_ABUSE_DETECTOR_H
#define EDR_CERT_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class CertAbuseDetector {
public:
    CertAbuseDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_CERT_ABUSE_DETECTOR_H */
