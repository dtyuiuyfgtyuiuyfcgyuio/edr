/*
 * password_spray_detector.h - Distributed-account password-spray detector.
 *
 * Correlates remote Security 4625 failures by source IP. A source is stamped
 * when it reaches both a total-failure threshold and a distinct-account
 * threshold inside the configured rolling window. A later successful 4624
 * for one of those accounts is stamped as a high-confidence compromise
 * follow-through signal for a separately bounded period.
 *
 * Only remote logon types 3 (network), 8 (network cleartext), and 10 (RDP) are
 * considered. Local/loopback sources, machine accounts, and unattributable
 * events are ignored. Per-source observations, source count, emitted account
 * summaries, and alert frequency are all bounded by configuration/constants.
 * Source timestamps must be monotonic per normalized source; a rollback is
 * rejected before mutation so delayed events cannot borrow future evidence.
 * A new follow-through episode starts only on a rising threshold crossing
 * (the source must first fall below threshold), so later failures cannot
 * silently extend an expired success window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PASSWORD_SPRAY_DETECTOR_H
#define EDR_PASSWORD_SPRAY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PasswordSprayDetector {
public:
    /**
     * Constructs a detector with explicit, bounded correlation parameters.
     *
     * @param enabled Whether Enrich inspects events. Disabled detectors
     *     leave events and internal state untouched.
     * @param windowSeconds Rolling source-time window for 4625 failures.
     * @param stateCapacity Maximum number of source-IP keys retained.
     * @param minFailures Minimum failures required to stamp a spray.
     * @param minDistinctUsers Minimum distinct accounts required to stamp.
     * @param successFollowupSeconds Fixed-length window, measured from the
     *     original episode start, during which a matching 4624 is stamped.
     * @param dedupSeconds Spray-alert cooldown. Zero disables cooldown.
     * @param maxFailuresPerSource Per-source observation and spray-user cap.
     */
    PasswordSprayDetector(bool enabled, uint32_t windowSeconds,
                          size_t stateCapacity, uint32_t minFailures,
                          uint32_t minDistinctUsers,
                          uint32_t successFollowupSeconds,
                          uint32_t dedupSeconds,
                          size_t maxFailuresPerSource);

    /**
     * Enriches eligible remote LOGON_FAILURE / LOGON events with
     * password_spray_* fields when thresholds are met.
     *
     * @param event Event mutated in place. Ineligible events are unchanged.
     */
    void Enrich(Event& event);

    /**
     * Reports whether Enrich inspects the given normalized event type.
     *
     * @param type EDR event type from edr_event.h.
     * @returns true only for EDR_EVT_LOGON.
     */
    static bool Inspects(uint16_t type);

    /**
     * @returns Number of retained source-IP keys. For tests only.
     */
    size_t StateCount() const { return m_sources.size(); }

    /**
     * Counts retained failure observations for a source after IP
     * canonicalization.
     *
     * @param sourceIp Raw or already-normalized source address.
     * @returns Observation count, or 0 when the source is rejected or absent.
     */
    size_t ObservationCount(const std::string& sourceIp) const;

private:
    struct FailureObservation {
        uint64_t ts100ns = 0;
        std::string user;
    };

    struct SourceState {
        std::deque<FailureObservation> failures;
        std::unordered_map<std::string, uint32_t> userCounts;
        std::unordered_set<std::string> sprayUsers;
        std::unordered_set<std::string> reportedSuccessUsers;
        uint32_t sprayFailureCount = 0;
        uint64_t episodeStartedAt100ns = 0;
        uint64_t suppressUntil100ns = 0;
        uint64_t lastSeen100ns = 0;
        uint64_t lastTouchedSequence = 0;
        bool thresholdLatched = false;
    };

    void PruneFailures(SourceState& state, uint64_t now100ns) const;
    void AppendFailure(SourceState& state, const std::string& user,
                       uint64_t now100ns) const;
    void ClearEpisode(SourceState& state) const;
    void WriteFailureState(Event& event, const std::string& sourceIp,
                           const SourceState& state) const;
    void WriteSuccessState(Event& event, const std::string& sourceIp,
                           const std::string& user,
                           const SourceState& state,
                           uint64_t now100ns) const;

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minFailures;
    uint32_t m_minDistinctUsers;
    uint64_t m_successFollowup100ns;
    uint64_t m_dedup100ns;
    size_t m_maxFailuresPerSource;
    uint64_t m_touchSequence = 0;
    std::unordered_map<std::string, SourceState> m_sources;
};

} // namespace edr

#endif /* EDR_PASSWORD_SPRAY_DETECTOR_H */
