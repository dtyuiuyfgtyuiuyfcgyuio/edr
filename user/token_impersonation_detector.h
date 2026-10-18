/*
 * token_impersonation_detector.h - Access-token impersonation detector
 * (T1134.001 / T1134.002).
 *
 * Detects command/script-plane use of token impersonation tooling and
 * native token APIs. Existing privilege_escalation detection covers the
 * process/handle correlation plane; this detector covers the explicit
 * operator intent visible in commands and script blocks.
 */
#ifndef EDR_TOKEN_IMPERSONATION_DETECTOR_H
#define EDR_TOKEN_IMPERSONATION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class TokenImpersonationDetector {
public:
    TokenImpersonationDetector(bool enabled, uint32_t minScore,
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
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_TOKEN_IMPERSONATION_DETECTOR_H */
