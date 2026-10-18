/*
 * firewall_rule_detector.h - Windows Firewall rule tamper detector (T1562.004).
 *
 * Detects adversaries adding, modifying, or disabling firewall rules to
 * enable inbound/outbound access for malware or remote tooling. Consumes
 * FIREWALL_RULE events emitted by the firewall monitor collector
 * (enable_firewall_monitor). Each rule change is scored independently.
 */
#ifndef EDR_FIREWALL_RULE_DETECTOR_H
#define EDR_FIREWALL_RULE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class FirewallRuleDetector {
public:
    FirewallRuleDetector();

    void Enrich(Event& event);

    static bool Inspects(uint16_t type) { return type == EDR_EVT_FIREWALL_RULE; }

    static uint32_t ScoreEvent(const Event& event, std::string& signals);

private:
    static bool IsSensitiveApp(const std::string& app);
};

} // namespace edr

#endif /* EDR_FIREWALL_RULE_DETECTOR_H */
