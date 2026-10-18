/*
 * clipboard_theft_detector.h - Clipboard collection behavior detector.
 *
 * Correlates CLIPBOARD_ACCESS events per process and flags repeated text
 * reads, unusual readers, and known collection-tool images. This is an
 * opt-in enrichment layer; it never captures or stores clipboard contents.
 */
#ifndef EDR_CLIPBOARD_THEFT_DETECTOR_H
#define EDR_CLIPBOARD_THEFT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ClipboardTheftDetector {
public:
    ClipboardTheftDetector(bool enabled, uint32_t minScore,
                           uint32_t windowSeconds, size_t stateCapacity,
                           uint32_t minReads, uint32_t dedupWindowSeconds);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_states.size(); }

private:
    struct State {
        uint64_t lastSeen100ns = 0;
        uint64_t lastAlert100ns = 0;
        uint32_t accessCount = 0;
        uint32_t textReadCount = 0;
    };

    void PurgeExpired(uint64_t now100ns);

    bool m_enabled;
    uint32_t m_minScore;
    uint32_t m_windowSeconds;
    uint64_t m_window100ns;
    size_t m_stateCapacity;
    uint32_t m_minReads;
    uint64_t m_dedupWindow100ns;
    std::unordered_map<uint32_t, State> m_states;
};

} // namespace edr

#endif /* EDR_CLIPBOARD_THEFT_DETECTOR_H */
