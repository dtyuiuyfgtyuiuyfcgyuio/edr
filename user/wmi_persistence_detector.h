/*
 * wmi_persistence_detector.h - WMI event subscription persistence detector.
 *
 * Tracks WMI temporary/permanent event subscriptions, filter-to-consumer
 * bindings, and provider loads. When a later process start matches an image,
 * command-line token, or script path referenced by a recent subscription
 * payload, the PROCESS_START event is stamped with wmi_persistence_* fields.
 */
#ifndef EDR_WMI_PERSISTENCE_DETECTOR_H
#define EDR_WMI_PERSISTENCE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class WmiPersistenceDetector {
public:
    WmiPersistenceDetector(bool enabled, uint32_t windowSeconds,
                           size_t stateCapacity, uint32_t minMatches);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_subscriptions.size(); }

private:
    struct SubscriptionInfo {
        std::string payload;
        uint64_t lastSeen100ns = 0;
    };

    bool IsSubscriptionOperation(const std::string& operation) const;
    void RecordSubscription(const Event& event, uint64_t now100ns);
    void PurgeExpired(uint64_t now100ns);
    bool PayloadMatches(const std::string& payload, const Event& event) const;
    void WriteState(Event& event, uint32_t matches, uint32_t score,
                    const std::vector<std::string>& matched);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minMatches;
    std::unordered_map<std::string, SubscriptionInfo> m_subscriptions;
};

} // namespace edr

#endif /* EDR_WMI_PERSISTENCE_DETECTOR_H */
