/*
 * forced_auth_detector.h - Forced-authentication / credential-coercion
 * detector (T1187).
 *
 * Attackers trick privileged Windows hosts into authenticating to an
 * attacker-controlled SMB listener to capture NTLMv2 hashes for relay or
 * offline cracking. This detector scores PROCESS_START command lines for
 * coercion tooling and UNC coercion verbs:
 *   - PetitPotam / SpoolSample / PrinterBug / SpoolFool   -> 90
 *   - Responder (-i) / Inveigh                             -> 85
 *   - net use / pushd / start to a \\<ip> UNC path         -> 55
 *
 * UNC coercion requires an IP-address target (not a hostname) to keep
 * false positives low; even then it is a low-confidence signal.
 *
 * Alerts are deduplicated per signal key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_FORCED_AUTH_DETECTOR_H
#define EDR_FORCED_AUTH_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ForcedAuthDetector {
public:
    ForcedAuthDetector(bool enabled, uint32_t minScore,
                       uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string target;
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

#endif /* EDR_FORCED_AUTH_DETECTOR_H */
