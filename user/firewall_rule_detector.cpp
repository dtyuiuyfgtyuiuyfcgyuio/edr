/*
 * firewall_rule_detector.cpp - See firewall_rule_detector.h.
 */
#include "firewall_rule_detector.h"

#include <cctype>
#include <string>
#include <vector>

namespace edr {
namespace {

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

} // namespace

FirewallRuleDetector::FirewallRuleDetector() {}

bool FirewallRuleDetector::IsSensitiveApp(const std::string& app) {
    if (app.empty()) return false;
    const std::string lower = LowerAscii(app);
    /* Binaries commonly abused for C2 / remote tooling. */
    return lower.find("powershell") != std::string::npos ||
           lower.find("pwsh") != std::string::npos ||
           lower.find("cmd.exe") != std::string::npos ||
           lower.find("mshta") != std::string::npos ||
           lower.find("rundll32") != std::string::npos ||
           lower.find("regsvr32") != std::string::npos ||
           lower.find("wscript") != std::string::npos ||
           lower.find("cscript") != std::string::npos ||
           lower.find("anydesk") != std::string::npos ||
           lower.find("teamviewer") != std::string::npos ||
           lower.find("ngrok") != std::string::npos ||
           lower.find("chisel") != std::string::npos ||
           lower.find("frp") != std::string::npos ||
           lower.find("ncat") != std::string::npos ||
           lower.find("netcat") != std::string::npos ||
           lower.find("socat") != std::string::npos ||
           lower.find("plink") != std::string::npos ||
           lower.find("ssh.exe") != std::string::npos;
}

uint32_t FirewallRuleDetector::ScoreEvent(const Event& event,
                                          std::string& signals) {
    const std::string action =
        LowerAscii(FieldValue(event, field::kFirewallAction));
    const std::string dir = LowerAscii(FieldValue(event, field::kFirewallDir));
    const std::string ruleAction =
        LowerAscii(FieldValue(event, field::kFirewallRuleAction));
    const std::string protocol =
        LowerAscii(FieldValue(event, field::kFirewallProtocol));
    const std::string localPort =
        LowerAscii(FieldValue(event, field::kFirewallLocalPort));
    const std::string remotePort =
        LowerAscii(FieldValue(event, field::kFirewallRemotePort));
    const std::string app = FieldValue(event, field::kFirewallApp);
    const std::string service =
        LowerAscii(FieldValue(event, field::kFirewallService));

    const bool isAllow = ruleAction.empty() || ruleAction == "allow";
    uint32_t score = 0;
    if (action == "added" || action == "modified") {
        if (isAllow) {
            if (dir == "in") score += 25;
            else if (dir == "out") score += 15;
            else score += 20;
        }

        /* RDP enablement: port 3389 or RDP service. */
        if (localPort == "3389" || remotePort == "3389" ||
            service.find("termservices") != std::string::npos ||
            service.find("remote desktop") != std::string::npos) {
            score += 25;
        }
        /* Rule permitting every protocol/port (allow rules only). */
        if (isAllow &&
            (protocol == "any" ||
             (localPort.empty() && remotePort.empty() && app.empty() &&
              service.empty()))) {
            score += 20;
        }
        /* Sensitive binaries allowed to reach the network. */
        if (IsSensitiveApp(app)) score += 20;
    } else if (action == "removed") {
        /* Removing an existing block rule weakens the firewall. */
        if (ruleAction == "block") score += 25;
        else score += 10;
    }

    if (score >= 55) {
        signals = "firewall_" + action;
        if (dir == "in") signals += "_inbound";
        else if (dir == "out") signals += "_outbound";
        if (isAllow) signals += "_allow";
        if (localPort == "3389" || remotePort == "3389") signals += "_rdp";
        if (IsSensitiveApp(app)) signals += "_sensitive_app";
        if (protocol == "any") signals += "_any_protocol";
    }
    return score;
}

void FirewallRuleDetector::Enrich(Event& event) {
    if (!Inspects(event.type)) return;
    std::string signals;
    const uint32_t score = ScoreEvent(event, signals);
    if (score == 0) return;
    event.fields[field::kFirewallRuleScore] = std::to_string(score);
    if (!signals.empty()) {
        event.fields[field::kFirewallRuleSignals] = signals;
    }
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kFirewallRuleVerdict] = verdict;
    }
}

} // namespace edr
