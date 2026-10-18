/*
 * ticket_cache_abuse_detector.h - Pass-the-ticket / ticket cache abuse
 * detector (T1550.003).
 *
 * Flags command/script-plane activity that injects or purges Kerberos
 * tickets and manipulates ticket cache artifacts:
 *   - kerberos::ptt / Rubeus ptt / Pass-The-Ticket tooling         -> 90
 *   - klist purge (often used to clear the cache before/after PTT)  -> 65
 *   - .kirbi / .ccache ticket-file references or copies             -> 70-75
 *   - ticket cache env/config hints such as KRB5CCNAME               -> 60
 *
 * Read-only ticket listing is not scored. 55+ alerted; 75+ malicious.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_TICKET_CACHE_ABUSE_DETECTOR_H
#define EDR_TICKET_CACHE_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class TicketCacheAbuseDetector {
public:
    TicketCacheAbuseDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_TICKET_CACHE_ABUSE_DETECTOR_H */