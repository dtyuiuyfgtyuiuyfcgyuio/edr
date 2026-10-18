/*
 * as_rep_roast_detector.h - AS-REP roasting detector (T1558.004).
 *
 * Watches Kerberos TGT requests (security event 4768). Accounts that do
 * not require pre-authentication accept an AS-REQ without a PA-ENC-
 * TIMESTAMP; the TGT returned is encrypted with the account's own hash,
 * which an attacker can brute-force offline (AS-REP roasting). The
 * parser surfaces PreAuthType on the TGT_REQUEST logon event: normal
 * requests carry 15, roastable requests carry 0.
 *
 * Scoring per source IP + account within the window:
 *   1 request with PreAuthType 0  -> 65 SUSPICIOUS (weak config touched)
 *   2 repeated requests            -> 80 MALICIOUS  (extraction attempt)
 *   3+ repeated requests           -> 90 MALICIOUS
 * Host-wide: 3+ distinct no-preauth accounts requested in the window
 * escalates to 85 MALICIOUS (mass sweep).
 *
 * Thread-safety: single EventBus consumer thread only (see main.cpp).
 */
#ifndef EDR_AS_REP_ROAST_DETECTOR_H
#define EDR_AS_REP_ROAST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class AsRepRoastDetector {
public:
    AsRepRoastDetector(bool enabled, uint32_t windowSeconds,
                       size_t stateCapacity, uint32_t dedupSeconds);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_requesters.size(); }

private:
    struct RequesterState {
        uint32_t count = 0;
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
        uint32_t lastAlertedCount = 0;
        uint64_t lastTouchedSequence = 0;
        std::string displayTarget;
    };

    void WriteState(Event& event, const std::string& sourceIp,
                    const RequesterState& state) const;
    void EvictLeastRecentlyTouched(size_t capacity);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint64_t m_dedup100ns;
    uint64_t m_touchSequence = 0;

    /* requester key (srcIp|account) -> request state. */
    std::unordered_map<std::string, RequesterState> m_requesters;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_AS_REP_ROAST_DETECTOR_H */
