/*
 * correlation_rollup.cpp - see correlation_rollup.h for the policy.
 */
#include "correlation_rollup.h"

#include <cstdio>

#include "correlation_engine.h"
#include "edr_event.h"
#include "event_bus.h"

namespace edr {
namespace {

constexpr const char* kRollupSource = "correlation";
constexpr int kDefaultScoreDecadeStep = 10;

std::string ToString(uint64_t value) { return std::to_string(value); }

} // namespace

CorrelationRollup::CorrelationRollup(bool enabled, uint32_t minStageCount,
                                     int minScore, size_t stateCapacity)
    : m_enabled(enabled),
      m_minStageCount(minStageCount < 2 ? 2 : minStageCount),
      m_minScore(minScore < 0 ? 0 : (minScore > 100 ? 100 : minScore)),
      m_capacity(stateCapacity == 0 ? 1 : stateCapacity),
      m_scoreDecadeStep(kDefaultScoreDecadeStep) {}

bool CorrelationRollup::IsRollup(const Event& event) {
    return event.type == EDR_EVT_INCIDENT_CORRELATED;
}

bool CorrelationRollup::Publish(const CorrelationAnnotation& annotation,
                                const Event& origin) {
    if (!m_enabled || m_bus == nullptr) return false;
    if (annotation.incidentId.empty()) return false;
    if (annotation.stageCount < m_minStageCount || annotation.score < m_minScore)
        return false;

    const Band band{annotation.stageCount, annotation.score / m_scoreDecadeStep};
    auto found = m_last.find(annotation.incidentId);
    /* Read the previous band before touching the map: inserting below can
     * rehash and invalidate `found`. */
    const bool known = found != m_last.end();
    if (known) {
        /* Only announce growth: a new distinct tactic, or a materially higher
         * score. Repeating the same campaign shape must not re-alert. */
        if (band.stageCount <= found->second.stageCount &&
            band.scoreDecade <= found->second.scoreDecade)
            return false;
    }

    Event ev;
    ev.type = EDR_EVT_INCIDENT_CORRELATED;
    ev.disposition = EventDisposition::ReportAndEvaluate;
    ev.source = kRollupSource;
    /* Inherit the alert's clock so the incident lands in the same window the
     * correlator used; never stamp a fresh wall-clock time here. */
    ev.ts100ns = origin.ts100ns;
    ev.fields[field::kType] = "INCIDENT_CORRELATED";
    ev.fields[field::kSource] = kRollupSource;
    ev.fields[field::kTimestampProvenance] =
        origin.fields.count(field::kTimestampProvenance)
            ? origin.fields.at(field::kTimestampProvenance)
            : "inherited";
    ev.fields[field::kCorrelatedIncidentId] = annotation.incidentId;
    ev.fields[field::kCorrelatedStage] = annotation.stage;
    ev.fields[field::kCorrelatedTactics] = annotation.tactics;
    ev.fields[field::kCorrelatedScore] = ToString(static_cast<uint64_t>(annotation.score));
    ev.fields[field::kCorrelatedAlertCount] = ToString(annotation.alertCount);
    ev.fields[field::kCorrelatedStageCount] = ToString(annotation.stageCount);

    const std::string endpoint = origin.fields.count(field::kEndpointId)
                                     ? origin.fields.at(field::kEndpointId)
                                     : std::string();
    if (!endpoint.empty()) ev.fields[field::kEndpointId] = endpoint;

    if (!m_bus->Push(ev)) return false;

    /* Record the announcement only once it is actually queued, so a rejected
     * push (overflow) leaves the incident free to retry on the next alert. */
    if (!known && m_last.size() >= m_capacity) {
        m_last.erase(m_order.front());
        m_order.pop_front();
    }
    m_last[annotation.incidentId] = band;
    if (!known) m_order.push_back(annotation.incidentId);

    ++m_published;
    std::fprintf(stderr,
                 "[edr] correlation roll-up %s (tactics=%u, score=%d, "
                 "alerts=%u)\n",
                 annotation.incidentId.c_str(),
                 static_cast<unsigned>(annotation.stageCount), annotation.score,
                 static_cast<unsigned>(annotation.alertCount));
    return true;
}

} // namespace edr
