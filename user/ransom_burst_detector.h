/*
 * ransom_burst_detector.h - Ransomware burst (bulk file creation) detector.
 *
 * Correlates FILE_CREATE events per attribution key into a rolling window.
 * When at least minFileCount file creations showing at least
 * minDistinctExtensions distinct extensions occur within windowSeconds, the
 * current event is stamped with bulk_file_score/bulk_file_count/
 * bulk_file_extensions/bulk_file_window_seconds. State is a bounded,
 * time-expiring LRU; expired keys are swept lazily on every Enrich and a
 * dropped key's flag resets so the threshold must be re-met before fields are
 * emitted again. Enrichment is best-effort and never throws.
 *
 * Attribution: events with a pid and image are keyed as "pid:<pid>@<image
 * basename>"; events without a pid (e.g. the directory-watch collector) fall
 * back to "dir:<lowercased directory of file_path>"; events with neither are
 * skipped. The extension of a file is the lowercased text after the last '.'
 * in the file basename; a basename with no '.' contributes its full basename
 * as the extension, so every extensionless file counts as a distinct
 * extension.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_RANSOM_BURST_DETECTOR_H
#define EDR_RANSOM_BURST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class RansomBurstDetector {
public:
    RansomBurstDetector(bool enabled, uint32_t windowSeconds,
                        size_t stateCapacity, uint32_t minFileCount,
                        uint32_t minDistinctExtensions);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct KeyState {
        uint32_t count = 0;
        std::set<std::string> extensions;
        bool flagged = false;
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const KeyState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minFileCount;
    uint32_t m_minDistinctExtensions;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_RANSOM_BURST_DETECTOR_H */