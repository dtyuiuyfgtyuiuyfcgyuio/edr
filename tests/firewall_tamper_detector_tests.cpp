#include "firewall_tamper_detector_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "firewall_tamper_detector.h"

namespace {
#define FW_CHECK(value) Check((value), #value, __LINE__)
void Check(bool value, const char* expression, int line) {
    if (!value) throw std::runtime_error("firewall tamper test failed at line " +
        std::to_string(line) + ": " + expression);
}
edr::Event Rule(const char* change, const char* action, const char* dir,
               const char* port, uint64_t time) {
    edr::Event event;
    event.type = EDR_EVT_FIREWALL_RULE;
    event.ts100ns = time;
    event.fields[edr::field::kFirewallAction] = change;
    event.fields[edr::field::kFirewallRuleName] = "Allow Remote Tool";
    event.fields[edr::field::kFirewallRuleAction] = action;
    event.fields[edr::field::kFirewallDir] = dir;
    event.fields[edr::field::kFirewallLocalPort] = port;
    event.fields[edr::field::kFirewallEnabled] = "true";
    return event;
}
void TestHighRiskAllow() {
    edr::FirewallTamperDetector detector(true, 300, 128);
    edr::Event event = Rule("added", "allow", "in", "3389", 1000000000ULL);
    detector.Enrich(event);
    FW_CHECK(event.fields.at(edr::field::kFirewallTamperScore) == "60");
    FW_CHECK(event.fields.at(edr::field::kFirewallTamperVerdict) == "SUSPICIOUS");
}
void TestRemovedRule() {
    edr::FirewallTamperDetector detector(true, 300, 128);
    edr::Event event = Rule("removed", "block", "out", "80", 2000000000ULL);
    detector.Enrich(event);
    FW_CHECK(event.fields.at(edr::field::kFirewallTamperScore) == "35");
}
void TestDisabled() {
    edr::FirewallTamperDetector detector(false, 300, 128);
    edr::Event event = Rule("added", "allow", "in", "any", 1);
    detector.Enrich(event);
    FW_CHECK(event.fields.find(edr::field::kFirewallTamperScore) == event.fields.end());
}
}
void RunFirewallTamperDetectorTests() {
    TestHighRiskAllow();
    TestRemovedRule();
    TestDisabled();
}
