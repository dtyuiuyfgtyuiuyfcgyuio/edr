/*
 * canary_detector.h - Scores canary (honeypot) file interactions.
 *
 * Consumes FILE_INTEGRITY events flagged with field "canary"="true"
 * (emitted by CanaryManager) and stamps a high-confidence verdict:
 *   - accessed  -> 60  SUSPICIOUS
 *   - modified  -> 80  MALICIOUS
 *   - removed   -> 90  MALICIOUS
 *
 * Any other action ("added", baseline noise) is ignored. Repeated alerts
 * for the same path inside the dedup window are suppressed so one touch
 * yields one alert even though the collector keeps polling.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_CANARY_DETECTOR_H
#define EDR_CANARY_DETECTOR_H

#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class CanaryDetector {
public:
    CanaryDetector(bool enabled, uint32_t dedupWindowSeconds,
                   size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    void Stamp(Event& event, uint32_t score, const std::string& path);

    bool m_enabled;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* fim_path -> ts100ns of the last stamped alert for that canary. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_CANARY_DETECTOR_H */
