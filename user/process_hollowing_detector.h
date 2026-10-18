/*
 * process_hollowing_detector.h - Process hollowing detector.
 *
 * Masquerading/staging proxy over PROCESS_START events: a protected system
 * binary basename (svchost.exe, lsass.exe, ...) launched from outside the
 * trusted system directory prefixes, optionally staged in a user-writable
 * location or spawned by an unusual parent, is scored and the event is
 * stamped with hollow_score/hollow_reasons/hollow_base/hollow_path/
 * hollow_parent. This is a path/parent heuristic proxy only; it makes no
 * claim about the process address space. State is a bounded, time-expiring
 * LRU keyed by pid@lowercase-full-image-path that suppresses duplicate
 * stamps within the dedup window. Enrichment is best-effort and never
 * throws.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PROCESS_HOLLOWING_DETECTOR_H
#define EDR_PROCESS_HOLLOWING_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ProcessHollowingDetector {
public:
    ProcessHollowingDetector(bool enabled, uint32_t minScore,
                             uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct KeyState {
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_PROCESS_HOLLOWING_DETECTOR_H */
