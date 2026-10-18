/*
 * behavior_baseline_detector.h - Learned behavior baseline (opt-in).
 *
 * Learns a per-image baseline of three observation categories and stamps
 * deviations only after the training window closes:
 *   - child image basenames observed on PROCESS_START (parent_image -> image)
 *   - write directories observed on FILE_CREATE (directory of target_path /
 *     file_path)
 *   - network endpoints observed on NET_CONNECT (dst_ip:dst_port)
 *
 * Lifecycle per key (image basename): the first sighting seeds the entry and
 * starts training; observations inside the training window are learned;
 * after trainingSeconds the baseline freezes and unseen observations of any
 * category become deviations. A deviation marks its category with a
 * timestamp; the stamped score is the sum of the categories whose marks are
 * still inside windowSeconds (child 40, dir 30, endpoint 30, capped 100).
 * A stamp is written only when the event itself contributed a fresh mark, the
 * score reaches minScore and the key is outside its dedup window. After
 * freezing the baseline never learns again, so legitimate environment change
 * is handled by per-entry maxAgeDays retraining or by removing the baseline
 * file. The basename key deliberately groups same-named binaries from
 * different paths; this detector cannot distinguish those executables.
 *
 * Pollution protection: a PROCESS_START event whose chain_score reaches
 * pollutionScore freezes learning for that key during its current age cycle.
 * A maxAgeDays reset starts a clean training cycle. Suspicious activity must
 * not extend the baseline it is trying to hide inside.
 *
 * Persistence: optional JSON file (empty path = memory only). Save writes a
 * uniquely named temp file and atomically replaces the target; load rejects
 * unreadable, malformed or wrong-version files without publishing partial
 * state. Last-seen event time is retained at 100ns precision to reject replay
 * across restarts. Expired observations are discarded and retrained. Both
 * directions are bounded by stateCapacity, per-category maxObservations and
 * an overall file size cap.
 *
 * This is heuristic deviation evidence: a single new child (40), a new write
 * directory (30) or a new endpoint (30) alone never reaches the default 55
 * floor, and even combined categories describe deviation, not confirmed
 * compromise. The detector never requests terminate/isolate/quarantine.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp). Save is called after the
 * consumer has joined during shutdown.
 */
#ifndef EDR_BEHAVIOR_BASELINE_DETECTOR_H
#define EDR_BEHAVIOR_BASELINE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class BehaviorBaselineDetector {
public:
    struct Options {
        bool enabled = false;
        uint32_t trainingSeconds = 86400;
        uint32_t windowSeconds = 3600;
        uint32_t dedupSeconds = 600;
        size_t stateCapacity = 4096;
        uint32_t minScore = 55;
        uint32_t pollutionScore = 75;
        size_t maxObservations = 64;
        uint32_t maxAgeDays = 30;
        std::string baselinePath; /* empty = memory only */
    };

    explicit BehaviorBaselineDetector(const Options& options);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects. */
    static bool Inspects(uint16_t type) {
        return type == EDR_EVT_PROCESS_START ||
               type == EDR_EVT_FILE_CREATE ||
               type == EDR_EVT_NET_CONNECT;
    }

    size_t StateCount() const { return m_entries.size(); }
    size_t LoadedEntries() const { return m_loadedEntries; }

    /* Persist the learned baseline (memory-only when the path is empty).
     * Returns false without touching the target on any failure. */
    bool Save();
    const std::string& LastError() const { return m_lastError; }

private:
    struct Entry {
        std::set<std::string> children;
        std::set<std::string> dirs;
        std::set<std::string> endpoints;
        uint64_t firstSeen100ns = 0;
        uint64_t lastSeen100ns = 0;
        uint64_t lastDeviation100ns = 0;
        uint32_t lastDeviationScore = 0; /* ephemeral dedup promotion state */
        uint64_t childDeviation100ns = 0;
        uint64_t dirDeviation100ns = 0;
        uint64_t endpointDeviation100ns = 0;
        bool trained = false;
        bool polluted = false;
    };

    void LearnProcessStart(Entry& entry, Event& event, uint64_t now,
                           bool trained, const std::string& key);
    void LearnFileCreate(Entry& entry, Event& event, uint64_t now,
                         bool trained, const std::string& key);
    void LearnNetConnect(Entry& entry, Event& event, uint64_t now,
                         bool trained, const std::string& key);
    void EvaluateDeviation(Entry& entry, Event& event, uint64_t now,
                           const std::string& key, bool freshChild,
                           bool freshDir, bool freshEndpoint);
    bool Polluted(const Event& event) const;
    bool Load();
    std::string Serialize() const;
    static bool ContainsNul(const std::string& value) {
        return value.find('\0') != std::string::npos;
    }
    static bool BoundedValue(const std::string& value) {
        return !value.empty() && value.size() <= 512 && !ContainsNul(value);
    }

    Options m_options;
    std::unordered_map<std::string, Entry> m_entries;
    size_t m_loadedEntries = 0;
    std::string m_lastError;
};

} // namespace edr

#endif /* EDR_BEHAVIOR_BASELINE_DETECTOR_H */
