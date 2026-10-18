/*
 * handle_guard_detector.h - High-risk process/thread handle access detector.
 *
 * This is an opt-in enrichment layer for HANDLE_OPEN events emitted by the
 * driver ObRegisterCallbacks path. It scores combinations of rights commonly
 * used for memory injection, credential access, or thread hijacking.
 */
#ifndef EDR_HANDLE_GUARD_DETECTOR_H
#define EDR_HANDLE_GUARD_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class HandleGuardDetector {
public:
    HandleGuardDetector(bool enabled, uint32_t minScore,
                        uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        std::string signals;
    };

    bool Analyze(const std::string& objectType, uint32_t accessMask,
                 Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_HANDLE_GUARD_DETECTOR_H */
