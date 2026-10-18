/*
 * lolbin_chain_detector.h - Multi-LOLBin parent chain detector.
 *
 * Correlates starts by a strong parent process instance (PID+creation time or
 * endpoint/producer-scoped opaque identity). Missing/weak parent identities
 * are not accumulated. Counts distinct suspicious children launched within a
 * rolling window. When the chain reaches minDistinctChildren, the current
 * event is stamped with lolbin_chain_score / lolbin_chain_count /
 * lolbin_chain_children / lolbin_chain_window_seconds / lolbin_chain_verdict.
 *
 * The detector is focused on living-off-the-land children and complements,
 * rather than duplicates, the existing parent-child and attack-chain
 * detectors.
 */
#ifndef EDR_LOLBIN_CHAIN_DETECTOR_H
#define EDR_LOLBIN_CHAIN_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LolbinChainDetector {
public:
    LolbinChainDetector(bool enabled, uint32_t windowSeconds,
                        size_t stateCapacity, uint32_t minDistinctChildren);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_parents.size(); }

private:
    struct ChildInfo {
        uint64_t lastSeen100ns = 0;
    };

    struct ParentState {
        std::unordered_map<std::string, ChildInfo> children;
        uint32_t lastFlaggedCount = 0;
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const ParentState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minDistinctChildren;
    std::unordered_map<std::string, ParentState> m_parents;
};

} // namespace edr

#endif /* EDR_LOLBIN_CHAIN_DETECTOR_H */
