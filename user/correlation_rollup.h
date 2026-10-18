/*
 * correlation_rollup.h - Publish the kill-chain roll-up back onto the bus.
 *
 * CorrelationEngine::Observe() returns a CorrelationAnnotation (incident id,
 * stage, tactic list, score, alert count, stage count) but deliberately does
 * not touch the originating event: that event is a `const Event*` which is
 * only valid during dispatch. Without a writer, those numbers were only ever
 * printed to stderr, so no rule could see a campaign as a whole and EDR-443
 * (>=4 distinct tactics and score >=85) had no producer at all.
 *
 * This component is that writer. It takes the annotation the caller already
 * has and, when the incident crosses the configured campaign band, pushes a
 * synthetic EDR_EVT_INCIDENT_CORRELATED event carrying the correlated_* field
 * family. The rule engine then evaluates it like any collected event, so the
 * analyst gets one critical alert describing campaign shape instead of only
 * the isolated alerts that built it.
 *
 * Emission policy: an incident is announced once it reaches the band, and
 * re-announced only when it demonstrably grows (a further distinct tactic, or
 * a score at least 10 points higher). A stable incident that keeps repeating
 * the same tactic does not re-alert.
 *
 * Loop safety: the published event carries no process or path identity, and
 * the alert callback must skip Observe() for events IsRollup() recognizes.
 * Otherwise every roll-up would fold into correlation as a new alert and the
 * incident graph would feed on itself. Response is never attached here -
 * correlation stays a pure observer.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Publish (from the rule alert callback in main.cpp).
 */
#ifndef EDR_CORRELATION_ROLLUP_H
#define EDR_CORRELATION_ROLLUP_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>

#include "correlation_engine.h"
#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class CorrelationRollup {
public:
    CorrelationRollup(bool enabled, uint32_t minStageCount, int minScore,
                      size_t stateCapacity);

    void SetBus(EventBus* bus) { m_bus = bus; }

    /* Announce `annotation` when its incident crosses the campaign band.
     * `origin` supplies the timestamp and endpoint identity of the alert that
     * produced this roll-up. Returns true when an event was published. */
    bool Publish(const CorrelationAnnotation& annotation, const Event& origin);

    /* True for events this component published. The alert callback uses it to
     * keep roll-ups out of the correlator. */
    static bool IsRollup(const Event& event);

    uint64_t PublishedCount() const { return m_published; }
    size_t TrackedCount() const { return m_last.empty() ? 0 : m_last.size(); }

private:
    struct Band {
        uint32_t stageCount = 0;
        int scoreDecade = 0;
    };

    bool m_enabled;
    uint32_t m_minStageCount;
    int m_minScore;
    size_t m_capacity;
    int m_scoreDecadeStep;
    EventBus* m_bus = nullptr;
    std::unordered_map<std::string, Band> m_last;
    std::deque<std::string> m_order;
    uint64_t m_published = 0;
};

} // namespace edr

#endif /* EDR_CORRELATION_ROLLUP_H */
