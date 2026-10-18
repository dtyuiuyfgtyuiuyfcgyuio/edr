/*
 * rdp_session_hijack_detector.h - RDP session hijacking detector (T1563.002).
 *
 * The built-in tscon.exe tool attaches an existing interactive session to
 * another terminal session. Running as SYSTEM (or with high privilege),
 * an attacker can use it to silently take over a user's logged-in RDP
 * session. This detector scores PROCESS_START command lines for tscon.exe:
 *   - tscon with /password:<cred> (explicit credential re-use)     -> 100
 *   - tscon <session> /dest:<name> (cross-session attach)          ->  90
 *   - any other tscon invocation (session switching tooling)       ->  75
 *
 * The rdp_chain detector correlates RDP logon events; this detector is the
 * command/control plane of the same lateral-movement technique.
 *
 * Alerts are deduplicated per signal key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_RDP_SESSION_HIJACK_DETECTOR_H
#define EDR_RDP_SESSION_HIJACK_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class RdpSessionHijackDetector {
public:
    RdpSessionHijackDetector(bool enabled, uint32_t minScore,
                             uint32_t dedupWindowSeconds,
                             size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string session;
        std::string dest;
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

#endif /* EDR_RDP_SESSION_HIJACK_DETECTOR_H */
