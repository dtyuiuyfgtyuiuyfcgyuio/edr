/*
 * firewall_rule_detector_tests.cpp - Unit tests for FirewallRuleDetector
 * (T1562.004).
 *
 * The detector consumes FIREWALL_RULE events from the firewall monitor
 * collector and scores each rule change independently (no dedup state).
 * Verdict strings follow this detector family's uppercase house style
 * (MALICIOUS / SUSPICIOUS); scores below 55 stamp the score only.
 */
#include "firewall_rule_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "firewall_rule_detector.h"

namespace {

#define FW_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "firewall rule detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event RuleEvent(const char* action, const char* dir,
                     const char* ruleAction) {
    edr::Event event;
    event.type = EDR_EVT_FIREWALL_RULE;
    event.ts100ns = 10000000ULL;
    event.fields[edr::field::kType] = "FIREWALL_RULE";
    event.fields[edr::field::kFirewallAction] = action;
    event.fields[edr::field::kFirewallRuleName] = "Test-Rule";
    if (dir != nullptr) event.fields[edr::field::kFirewallDir] = dir;
    if (ruleAction != nullptr)
        event.fields[edr::field::kFirewallRuleAction] = ruleAction;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kFirewallRuleScore);
    return it == event.fields.end() ? "" : it->second;
}

std::string Verdict(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kFirewallRuleVerdict);
    return it == event.fields.end() ? "" : it->second;
}

std::string Signals(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kFirewallRuleSignals);
    return it == event.fields.end() ? "" : it->second;
}

bool Contains(const std::string& text, const char* needle) {
    return text.find(needle) != std::string::npos;
}

} // namespace

void RunFirewallRuleDetectorTests() {
    std::fprintf(stderr, "[firewall-rule] TestInspects\n");
    {
        FW_CHECK(edr::FirewallRuleDetector::Inspects(EDR_EVT_FIREWALL_RULE));
        FW_CHECK(!edr::FirewallRuleDetector::Inspects(EDR_EVT_PROCESS_START));

        /* A non-firewall event is left untouched. */
        edr::FirewallRuleDetector detector;
        edr::Event other;
        other.type = EDR_EVT_PROCESS_START;
        other.fields[edr::field::kType] = "PROCESS_START";
        detector.Enrich(other);
        FW_CHECK(Score(other).empty());
    }
    std::fprintf(stderr, "[firewall-rule] TestInboundAllowRdpSensitiveApp\n");
    {
        /* inbound allow 25 + RDP 25 + sensitive app 20 = 70 SUSPICIOUS. */
        edr::FirewallRuleDetector detector;
        edr::Event event = RuleEvent("added", "in", "allow");
        event.fields[edr::field::kFirewallLocalPort] = "3389";
        event.fields[edr::field::kFirewallApp] =
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        detector.Enrich(event);
        FW_CHECK(Score(event) == "70");
        FW_CHECK(Verdict(event) == "SUSPICIOUS");
        FW_CHECK(Contains(Signals(event), "firewall_added"));
        FW_CHECK(Contains(Signals(event), "_inbound"));
        FW_CHECK(Contains(Signals(event), "_rdp"));
        FW_CHECK(Contains(Signals(event), "_sensitive_app"));
    }
    std::fprintf(stderr, "[firewall-rule] TestAnyProtocolMalicious\n");
    {
        /* inbound allow 25 + RDP 25 + any protocol 20 + app 20 = 90. */
        edr::FirewallRuleDetector detector;
        edr::Event event = RuleEvent("added", "in", "allow");
        event.fields[edr::field::kFirewallProtocol] = "any";
        event.fields[edr::field::kFirewallRemotePort] = "3389";
        event.fields[edr::field::kFirewallApp] = "C:\\Tools\\ngrok.exe";
        detector.Enrich(event);
        FW_CHECK(Score(event) == "90");
        FW_CHECK(Verdict(event) == "MALICIOUS");
        FW_CHECK(Contains(Signals(event), "_any_protocol"));
    }
    std::fprintf(stderr, "[firewall-rule] TestWideOpenRule\n");
    {
        /* No port/app/service at all: allow-everything rule.
         * inbound allow 25 + wide-open 20 = 45 -> score only. */
        edr::FirewallRuleDetector detector;
        edr::Event event = RuleEvent("added", "in", "allow");
        detector.Enrich(event);
        FW_CHECK(Score(event) == "45");
        FW_CHECK(Verdict(event).empty());
        FW_CHECK(Signals(event).empty());
    }
    std::fprintf(stderr, "[firewall-rule] TestOutboundLowerWeight\n");
    {
        /* Outbound allow weighs less than inbound (15 vs 25). */
        edr::FirewallRuleDetector detector;
        edr::Event event = RuleEvent("added", "out", "allow");
        event.fields[edr::field::kFirewallLocalPort] = "8443";
        detector.Enrich(event);
        FW_CHECK(Score(event) == "15");
        FW_CHECK(Verdict(event).empty());
    }
    std::fprintf(stderr, "[firewall-rule] TestBlockRuleRemoval\n");
    {
        /* Removing a block rule weakens the firewall (25); removing any
         * other rule is lower signal (10). */
        edr::FirewallRuleDetector detector;
        edr::Event removedBlock = RuleEvent("removed", "in", "block");
        detector.Enrich(removedBlock);
        FW_CHECK(Score(removedBlock) == "25");

        edr::Event removedAllow = RuleEvent("removed", "in", "allow");
        detector.Enrich(removedAllow);
        FW_CHECK(Score(removedAllow) == "10");
    }
    std::fprintf(stderr, "[firewall-rule] TestBlockAddNotScoredAsAllow\n");
    {
        /* Adding a block rule is hardening: no allow/wide-open weight. */
        edr::FirewallRuleDetector detector;
        edr::Event event = RuleEvent("added", "in", "block");
        event.fields[edr::field::kFirewallProtocol] = "any";
        detector.Enrich(event);
        FW_CHECK(Score(event).empty());
        FW_CHECK(Verdict(event).empty());
    }
    std::fprintf(stderr, "[firewall-rule] all passed\n");
}
