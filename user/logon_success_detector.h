/*
 * logon_success_detector.h - Single-account password-guessing success follow-up.
 *
 * A remote success following minFailures remote failures is correlated by
 * normalized source IP, event source/endpoint, and normalized domain account.
 * The event receives a score and bounded correlation summary; no response is
 * requested. One successful login consumes the matching failure state.
 */
#ifndef EDR_LOGON_SUCCESS_DETECTOR_H
#define EDR_LOGON_SUCCESS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LogonSuccessDetector {
public:
    LogonSuccessDetector(bool enabled, uint32_t windowSeconds,
                         size_t stateCapacity, uint32_t minFailures);

    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
    size_t StateCount() const { return m_states.size(); }

private:
    struct KeyState {
        std::deque<uint64_t> failures100ns;
        uint64_t lastEvent100ns = 0;
        uint64_t lastSeen100ns = 0;
    };

    void EvictOldest(const std::string& preserveKey);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minFailures;
    std::unordered_map<std::string, KeyState> m_states;
};

} // namespace edr

#endif /* EDR_LOGON_SUCCESS_DETECTOR_H */
