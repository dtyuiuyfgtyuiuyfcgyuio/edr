/*
 * logon_brute_force_detector.h - Logon brute-force detector.
 *
 * Correlates LOGON_FAILURE events (Security 4625) per (src_ip, target_user)
 * key into a rolling window. When at least minFailures failed logons occur for
 * the same source IP and target user within windowSeconds, the current event
 * is stamped with logon_brute_score/logon_brute_failures/
 * logon_brute_target_user/logon_brute_src_ip/logon_brute_window_seconds and the
 * key's failure counter resets, so each alert represents a fresh batch of at
 * least minFailures failures. A per-key cooldown (dedupSeconds, 0 disables)
 * additionally delays the next stamp, bounding alert volume on a sustained
 * attack; even with the cooldown off, emission cannot exceed one alert per
 * minFailures failures.
 *
 * Events without a usable source IP (local interactive logons report "-") or
 * without a target user are skipped, so local keyboard mistakes do not
 * accumulate. State is a bounded, time-expiring LRU; keys idle beyond the
 * window are swept lazily on every Enrich. Enrichment is best-effort and never
 * throws.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_LOGON_BRUTE_FORCE_DETECTOR_H
#define EDR_LOGON_BRUTE_FORCE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LogonBruteForceDetector {
public:
    LogonBruteForceDetector(bool enabled, uint32_t windowSeconds,
                            size_t stateCapacity, uint32_t minFailures,
                            uint32_t dedupSeconds);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct KeyState {
        uint32_t failures = 0;
        uint64_t suppressUntil100ns = 0;
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const KeyState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minFailures;
    uint64_t m_dedup100ns;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_LOGON_BRUTE_FORCE_DETECTOR_H */
