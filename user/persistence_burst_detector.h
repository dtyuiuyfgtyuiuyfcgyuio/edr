/*
 * persistence_burst_detector.h - Mass-persistence ransomware precursor.
 *
 * Beyond the anti-recovery techniques tracked by RansomPrecursorDetector,
 * ransomware and wipers deploy themselves by bulk-modifying persistence
 * surfaces in a short window: creating services, writing Run/RunOnce
 * startup keys, registering scheduled tasks and WMI subscriptions. This
 * detector aggregates those events host-wide and stamps the current event
 * when the windowed weight crosses the threshold.
 *
 * Per-event weights (deduplicated per concrete key inside the window):
 *   - service create / modify                         -> 35
 *   - Run / RunOnce startup-key write                 -> 30
 *   - WMI event subscription / persistence filter     -> 25
 *   - scheduled task register / delete                -> 20
 *   - >= 4 distinct mechanisms in the window          -> +20
 *
 * 55+ SUSPICIOUS; 75+ MALICIOUS. The stamp re-emits when the windowed
 * weight grows, or after the dedup interval.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PERSISTENCE_BURST_DETECTOR_H
#define EDR_PERSISTENCE_BURST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PersistenceBurstDetector {
public:
    PersistenceBurstDetector(bool enabled, uint32_t windowSeconds,
                             size_t stateCapacity, uint32_t minScore,
                             uint32_t dedupSeconds);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_state.size(); }

private:
    struct KeyState {
        /* concrete persistence key -> last seen ts100ns. */
        std::unordered_map<std::string, uint64_t> keys;
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
        uint32_t lastWeight = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    bool Classify(const Event& event, std::string* concreteKey,
                  uint32_t* weight, std::string* mechanism) const;
    void WriteState(Event& event, const KeyState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minScore;
    uint64_t m_dedup100ns;
    std::unordered_map<std::string, KeyState> m_state;
};

} // namespace edr

#endif /* EDR_PERSISTENCE_BURST_DETECTOR_H */
