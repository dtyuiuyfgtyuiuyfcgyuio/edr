/*
 * doh_abuse_detector.h - DNS-over-HTTPS abuse detector
 * (MITRE T1071.004 DNS / T1090 proxying).
 *
 * Detects processes resolving known DNS-over-HTTPS resolver endpoints,
 * a common channel for malware to bypass local DNS monitoring:
 *  - Queries to well-known DoH provider hostnames
 *  - Non-browser processes touching DoH endpoints
 *  - Repeated DoH endpoint lookups within the correlation window
 *  - Bootstrap bursts across multiple distinct DoH providers
 * Events are stamped with doh_abuse_* fields as investigation signals;
 * a resolver hostname lookup alone does not confirm an encrypted DoH session.
 */
#ifndef EDR_DOH_ABUSE_DETECTOR_H
#define EDR_DOH_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DohAbuseDetector {
public:
    DohAbuseDetector(bool enabled, uint32_t windowSeconds,
                     size_t stateCapacity, uint32_t minRepeatCount);
    DohAbuseDetector(const DohAbuseDetector&) = delete;
    DohAbuseDetector& operator=(const DohAbuseDetector&) = delete;
    DohAbuseDetector(DohAbuseDetector&&) = delete;
    DohAbuseDetector& operator=(DohAbuseDetector&&) = delete;

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct KeyState;
    using ObservationTimeIndex = std::multimap<uint64_t, KeyState*>;
    using LastSeenIndex = std::multimap<uint64_t, const std::string*>;

    struct Observation {
        uint64_t timestamp100ns = 0;
        std::string endpoint;
        bool nonBrowser = false;
        ObservationTimeIndex::iterator timeIndex;
    };

    struct KeyState {
        std::deque<Observation> observations;
        uint64_t latestTimestamp100ns = 0;
        uint64_t lastSeen100ns = 0;
        const std::string* mapKey = nullptr;
        LastSeenIndex::iterator lastSeenIndex;
        bool hasLastSeenIndex = false;
    };

    static const std::unordered_set<std::string>& KnownEndpoints();
    static std::string EndpointFor(const std::string& queryName);
    static bool IsBrowserOrSystem(const std::string& image);
    void PurgeExpired(uint64_t now100ns);
    void EraseState(std::unordered_map<std::string, KeyState>::iterator state);
    void DropOldestObservation();
    void EvictOldestState();
    void TouchState(KeyState& state, uint64_t timestamp100ns);
    uint32_t ComputeScore(size_t queryCount, size_t endpointCount,
                          bool sawNonBrowser, bool aggregate) const;
    std::string SignalList(size_t queryCount, size_t endpointCount,
                          bool sawNonBrowser, bool aggregate) const;
    void WriteState(Event& event, const KeyState& state, bool aggregate) const;

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minRepeatCount;
    std::unordered_map<std::string, KeyState> m_keys;
    ObservationTimeIndex m_observationTimeIndex;
    LastSeenIndex m_lastSeenIndex;
    size_t m_totalObservations = 0;
};

} // namespace edr

#endif /* EDR_DOH_ABUSE_DETECTOR_H */
