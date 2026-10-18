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
 * Events are stamped with doh_abuse_* fields when confirmed.
 */
#ifndef EDR_DOH_ABUSE_DETECTOR_H
#define EDR_DOH_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
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

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct KeyState {
        uint32_t queryCount = 0;
        std::unordered_set<std::string> endpoints;
        bool sawNonBrowser = false;
        uint64_t lastSeen100ns = 0;
    };

    static const std::unordered_set<std::string>& KnownEndpoints();
    static std::string EndpointFor(const std::string& queryName);
    static bool IsBrowserOrSystem(const std::string& image);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const KeyState& state) const;
    std::string SignalList(const KeyState& state) const;
    void WriteState(Event& event, const KeyState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minRepeatCount;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_DOH_ABUSE_DETECTOR_H */
