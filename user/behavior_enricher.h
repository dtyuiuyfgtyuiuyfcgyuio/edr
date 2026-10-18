/*
 * behavior_enricher.h - Event-driven behavior enrichment.
 *
 * Runs inside the dispatch sink before the rule engine: enriches PROCESS_START
 * events with a parent/child chain score (chain_score/chain_reasons) and
 * PROCESS_READ events with LSASS read-burst totals
 * (lsass_read_burst_bytes/lsass_read_burst_count). State is a bounded,
 * time-expiring LRU over (parent_image, child_image) counts plus per-reader
 * LSASS burst accumulators. Expired entries are swept lazily at most once per
 * window. Enrichment is best-effort and never throws.
 *
 * Thread-safety: this class has no internal synchronization and must only be
 * called from the single EventBus consumer thread (see main.cpp).
 */
#ifndef EDR_BEHAVIOR_ENRICHER_H
#define EDR_BEHAVIOR_ENRICHER_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class BehaviorEnricher {
public:
    BehaviorEnricher(size_t stateCapacity, uint32_t windowSeconds,
                     uint32_t lsassBurstWindowSeconds,
                     uint64_t lsassBurstThresholdBytes);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types (e.g. DNS, REG, FILE). */
    static bool Inspects(uint16_t type) {
        return type == EDR_EVT_PROCESS_START ||
               type == EDR_EVT_PROCESS_READ;
    }

    size_t ParentChildCount() const { return m_parentChild.size(); }

private:
    struct CountEntry {
        uint64_t lastSeen100ns = 0;
        uint64_t count = 0;
    };
    struct BurstEntry {
        uint64_t windowStart100ns = 0;
        uint64_t bytes = 0;
        uint64_t count = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void EnrichProcessStart(Event& event, uint64_t now100ns);
    void EnrichLsassRead(Event& event, uint64_t now100ns);

    size_t m_stateCapacity;
    uint64_t m_window100ns;
    uint64_t m_lsassWindow100ns;
    uint64_t m_lsassThresholdBytes;
    uint64_t m_lastPurge100ns = 0;
    std::unordered_map<std::string, CountEntry> m_parentChild;
    std::unordered_map<uint32_t, BurstEntry> m_lsassBursts;
};

} // namespace edr

#endif /* EDR_BEHAVIOR_ENRICHER_H */
