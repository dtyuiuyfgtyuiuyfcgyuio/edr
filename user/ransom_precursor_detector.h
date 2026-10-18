/*
 * ransom_precursor_detector.h - Ransomware precursor correlation.
 *
 * Classifies PROCESS_START command lines into host-wide anti-recovery
 * techniques (shadow-copy delete, backup catalog wipe, recovery disable,
 * event-log clear, USN journal delete, free-space wipe). When at least
 * minTechniques distinct techniques fire inside windowSeconds, the current
 * event is stamped with ransom_precursor_score / ransom_precursor_techniques
 * / ransom_precursor_count / ransom_precursor_window_seconds.
 *
 * Correlation is host-wide (not per-pid) because ransomware typically
 * launches several signed system binaries. Time rollback on a later event
 * is rejected so a late-arriving older record cannot borrow future
 * techniques. The stamp re-emits when the technique count grows.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_RANSOM_PRECURSOR_DETECTOR_H
#define EDR_RANSOM_PRECURSOR_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

/* Pure classifier: technique name, or empty when the event is not a
 * recognized precursor. Image may be a full path or basename. */
std::string ClassifyRansomPrecursor(const std::string& image,
                                    const std::string& commandLine);

class RansomPrecursorDetector {
public:
    RansomPrecursorDetector(bool enabled, uint32_t windowSeconds,
                            size_t stateCapacity, uint32_t minTechniques,
                            uint32_t dedupSeconds);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct TechniqueInfo {
        uint64_t lastSeen100ns = 0;
    };

    struct KeyState {
        std::unordered_map<std::string, TechniqueInfo> techniques;
        uint32_t lastFlaggedCount = 0;
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const KeyState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minTechniques;
    uint64_t m_dedup100ns;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_RANSOM_PRECURSOR_DETECTOR_H */
