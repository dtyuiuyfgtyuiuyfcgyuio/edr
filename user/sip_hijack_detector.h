/*
 * sip_hijack_detector.h - Subject Interface Package / trust provider
 * hijack detector (T1553.003 SIP and Trust Provider Hijacking).
 *
 * Scores registry and command/script activity that repoints Windows
 * signature verification at an attacker DLL, so unsigned payloads report
 * as validly signed:
 *   - CryptSIPDllVerifyIndirectData / GetSignedDataMsg / IsMyFileType
 *     Dll or FuncName repointed                                   -> 90
 *   - Providers\Trust\FinalPolicy / Initialization repointed       -> 90
 *   - OID\EncodingType 0\CryptSIPDll* subtree write                -> 90
 *   - SIP registration tooling (regsvr32 of a SIP provider DLL)    -> 75
 *
 * Read-only inspection (reg query / Get-ItemProperty) stays silent.
 * Complements cert_abuse, which covers the root-store / private-key
 * plane rather than the verification-provider plane.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SIP_HIJACK_DETECTOR_H
#define EDR_SIP_HIJACK_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class SipHijackDetector {
public:
    SipHijackDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_SIP_HIJACK_DETECTOR_H */
