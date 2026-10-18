/*
 * correlation_engine.h - Alert correlation into incidents + kill-chain graph.
 *
 * The rule engine emits one alert per matching rule per event. That is the
 * right granularity for triage but the wrong granularity for an operator:
 * a single intrusion produces dozens of alerts that are really one incident.
 * This engine sits after the rule engine and folds related alerts into
 * incidents, then exposes the incident as a kill-chain graph suitable for
 * visualization.
 *
 * Correlation model
 * -----------------
 * Two alerts belong to the same incident when they share at least one
 * endpoint-scoped strong process-instance identity or an exact endpoint-local
 * file path, and arrive within the correlation window. Bare PID, image
 * basename, account name, and remote-host values are deliberately not
 * correlation keys: they are too weak to prove a shared actor or endpoint.
 *
 * Each incident keeps the distinct ATT&CK tactics observed, ordered by first
 * sighting, which is the kill-chain stage sequence. Incidents are bounded and
 * time-expiring; an incident that has been quiet for longer than the window
 * is closed and only kept if it reached alerting severity.
 *
 * This is a *pure correlator*: it never calls the rule engine, never touches
 * the response channel, and never blocks. It annotates events with the
 * incident identity so downstream consumers can group by it, and it hands
 * completed incidents to a callback so the Agent can emit a single
 * roll-up alert per incident.
 *
 * Thread-safety: no internal synchronization. Only the single EventBus
 * consumer thread calls Observe (see main.cpp); the callback is invoked from
 * that same thread, so it must not block.
 */
#ifndef EDR_CORRELATION_ENGINE_H
#define EDR_CORRELATION_ENGINE_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "event_bus.h"
#include "rule_engine.h"

namespace edr {

/* One node in the incident kill-chain graph. */
struct IncidentStage {
    std::string tactic;     /* ATT&CK tactic as reported by the rule */
    std::string ruleId;     /* first rule that evidenced this tactic */
    std::string severity;   /* highest severity seen for this tactic */
    uint64_t firstSeen100ns = 0;
    uint64_t lastSeen100ns = 0;
    uint32_t alertCount = 0;
};

struct Incident {
    std::string id;             /* stable per-incident identifier */
    std::string host;           /* endpoint identity used to scope this chain */
    std::string primaryImage;   /* image of the first correlated alert */
    std::string primaryUser;    /* account of the first correlated alert */
    uint64_t firstSeen100ns = 0;
    uint64_t lastSeen100ns = 0;
    uint32_t alertCount = 0;
    int score = 0;              /* 0..100 severity/breadth roll-up */
    std::string severity;       /* highest alert severity in the incident */
    std::vector<std::string> rules;
    std::vector<std::string> tactics;
    std::vector<IncidentStage> stages;
};

/* Correlation result for one observed alert. The engine returns this rather
 * than mutating the alert's event: the alert holds a `const Event*` that is
 * only valid during dispatch, so the caller (which owns the event) applies
 * these fields if it wants them on the wire. */
struct CorrelationAnnotation {
    std::string incidentId;
    std::string stage;      /* first tactic of the alert, empty when unmapped */
    std::string tactics;    /* comma-separated incident tactic list */
    int score = 0;
    uint32_t alertCount = 0;
    uint32_t stageCount = 0;
};

class CorrelationEngine {
public:
    using IncidentCallback = std::function<void(const Incident&)>;
    using RunIdFn = std::function<std::string()>;

    CorrelationEngine(bool enabled, uint32_t windowSeconds,
                      size_t stateCapacity, uint32_t minAlertsToClose,
                      RunIdFn runIdFn = {},
                      std::string localEndpointId = {});

    /* A trusted endpoint_id event field overrides this fallback for that
     * event. Otherwise the injected label or local computer name is used. */

    /* Fold one alert into the incident graph. Returns the incident identity
     * derived for this alert, which the caller may attach to the event. Work
     * is bounded by stateCapacity. */
    CorrelationAnnotation Observe(const Alert& alert);

    void SetIncidentCallback(IncidentCallback callback) {
        m_callback = std::move(callback);
    }

    /* Invoked the first time an incident is created, before any of its later
     * alerts arrive. Lets a sink persist a chain while it is still unfolding
     * instead of only when (and if) it later closes - a short-lived intrusion
     * that never reaches minAlertsToClose would otherwise leave no record. */
    void SetIncidentOpenedCallback(IncidentCallback callback) {
        m_openedCallback = std::move(callback);
    }

    /* Number of open (still-correlating) incidents. */
    size_t IncidentCount() const { return m_incidents.size(); }

    /* Snapshot of open incidents, newest first, for on-demand reporting. */
    std::vector<Incident> Snapshot(size_t limit) const;

    /* Flush incidents that have been quiet for longer than the window and
     * invoke the callback for each. Called periodically by the Agent so a
     * finished incident still produces its roll-up. */
    void FlushExpired(uint64_t now100ns);

private:
    struct EntityIndex {
        std::string incidentId;
        uint64_t lastSeen100ns = 0;
    };

    struct IncidentState {
        Incident incident;
        std::unordered_map<std::string, size_t> stageIndex; /* tactic -> stages[] */
    };

    struct ProcessAlias {
        std::string strongKey;
        uint64_t lastSeen100ns = 0; /* last strong evidence, not partial use */
    };

    /* Non-const: strong evidence learns/poisons the process-identity alias
     * registry (see m_identityAlias). */
    std::vector<std::string> EntitiesOf(const Alert& alert, uint64_t now100ns);
    void PurgeExpired(uint64_t now100ns);
    void EvictOldestAlias();
    void EvictOldest();
    void Emit(const IncidentState& state);
    void Retire(const std::string& incidentId);

    /* Fold `sourceId` into `targetId` and retire the source. An alert that
     * bridges two live incidents (e.g. a process from chain X touching a
     * file from chain Y) must not leave Y orphaned, so every incident the
     * alert touches is merged rather than only the first. Returns false when
     * either incident is gone. */
    bool MergeIncidents(const std::string& targetId, const std::string& sourceId);

    /* Point every entity currently resolving to `sourceId` at `targetId`.
     * Used after a merge so previously-indexed pivots keep working. */
    void ReindexEntities(const std::string& sourceId,
                         const std::string& targetId);

    bool m_enabled;
    uint64_t m_window100ns;
    size_t m_stateCapacity;
    uint32_t m_minAlertsToClose;
    uint64_t m_sequence = 0;
    uint64_t m_latestTime100ns = 0;
    std::string m_runId;
    std::string m_localEndpointId;
    IncidentCallback m_callback;
    IncidentCallback m_openedCallback;
    std::unordered_map<std::string, IncidentState> m_incidents;
    std::unordered_map<std::string, EntityIndex> m_entities;
    /* Process-identity alias registry: scoped alias key -> strong
     * "proc:ep|pid@creation" entity key and last strong evidence time.
     * Bounded by stateCapacity and expired independently of incidents.
     * An empty strongKey marks a POISONED
     * identity: two distinct strong processes claimed it (PID reuse /
     * identity spoof), so every key derived from it is blocked (fail
     * closed) until restart. */
    std::unordered_map<std::string, ProcessAlias> m_identityAlias;
    std::unordered_set<std::string> m_blockedEntities;
    /* At stateCapacity conflicts, stop opaque correlation for this lifetime
     * instead of either growing the poison ledger or forgetting conflicts. */
    bool m_opaqueAliasesDisabled = false;
};

/* Serialize an incident's kill-chain graph to one JSON object (UTF-8). The
 * shape is deliberately flat so the console can render it directly:
 *   { id, host, image, user, severity, score, alertCount,
 *     firstSeen100ns, lastSeen100ns,
 *     stages: [ {tactic, rule, severity, alertCount, firstSeen100ns,
 *                lastSeen100ns} ], rules: [...], tactics: [...] } */
std::string IncidentToJson(const Incident& incident);

} // namespace edr

#endif /* EDR_CORRELATION_ENGINE_H */
