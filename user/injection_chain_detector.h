/*
 * injection_chain_detector.h - Cross-process injection chain detector.
 *
 * Correlates PROCESS_ACCESS/MEMORY_WRITE/SECTION_MAP/THREAD_CREATE/APC_INJECT/
 * CONTEXT_CHANGE/PROCESS_READ/HANDLE_DUPLICATE events per (source_pid,
 * target_pid) pair into a monotonic ACCESS -> WRITE -> EXECUTE -> READ chain
 * with an accumulating score. inject_chain_score/inject_chain_stage/
 * inject_chain_reasons/inject_target_image are emitted only when the score is
 * at least minTransitionScore; zero emits every scored update. State is a
 * bounded, time-expiring LRU; expired chains are swept lazily at most once per
 * window. Enrichment is best-effort and never throws.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_INJECTION_CHAIN_DETECTOR_H
#define EDR_INJECTION_CHAIN_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class InjectionChainDetector {
public:
    InjectionChainDetector(size_t stateCapacity, uint32_t windowSeconds,
                           uint32_t minTransitionScore = 0);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_chains.size(); }

private:
    enum class Stage : uint8_t { NONE, ACCESS, WRITE, EXECUTE, READ, NETWORK };

    static const char* StageName(Stage stage);

    struct Chain {
        Stage stage = Stage::NONE;
        int score = 0;
        std::vector<std::string> reasons;
        std::string targetImage;
        uint64_t lastSeen100ns = 0;
    };

    struct PairHash {
        size_t operator()(const std::pair<uint32_t, uint32_t>& key) const
            noexcept {
            return (static_cast<size_t>(key.first) << 32) | key.second;
        }
    };

    void PurgeExpired(uint64_t now100ns);
    void RaiseStage(Chain& chain, Stage stage, int points,
                    const char* reason);
    void WriteState(Event& event, const Chain& chain);

    size_t m_stateCapacity;
    uint64_t m_window100ns;
    uint32_t m_minTransitionScore;
    uint64_t m_lastPurge100ns = 0;
    std::unordered_map<std::pair<uint32_t, uint32_t>, Chain, PairHash>
        m_chains;
};

} // namespace edr

#endif /* EDR_INJECTION_CHAIN_DETECTOR_H */
