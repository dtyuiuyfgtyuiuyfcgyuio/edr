/*
 * local_account_detector.cpp - See local_account_detector.h.
 */
#include "local_account_detector.h"

#include <cctype>
#include <string>

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

LocalAccountDetector::LocalAccountDetector() {}

bool LocalAccountDetector::IsPrivilegedGroup(const std::string& group) {
    const std::string lower = LowerAscii(group);
    return lower == "administrators" || lower == "domain admins" ||
           lower == "enterprise admins" || lower == "backup operators" ||
           lower == "remote desktop users" || lower == "dnsadmins" ||
           lower == "print operators" || lower == "account operators" ||
           lower == "server operators";
}

bool LocalAccountDetector::IsSuspiciousUser(const std::string& name) {
    if (name.empty()) return false;
    const std::string lower = LowerAscii(name);
    return lower == "admin" || lower == "administrator" ||
           lower == "guest" || lower == "temp" || lower == "test" ||
           lower.find("svc") == 0 || lower.find("adm") == 0 ||
           lower.find("backup") == 0;
}

uint32_t LocalAccountDetector::ScoreEvent(const Event& event,
                                         std::string& signals) {
    const std::string type =
        LowerAscii(FieldValue(event, field::kAccountType));
    const std::string action =
        LowerAscii(FieldValue(event, field::kAccountAction));
    const std::string enabled =
        LowerAscii(FieldValue(event, field::kAccountEnabled));
    const std::string name = FieldValue(event, field::kAccountName);
    const std::string group = FieldValue(event, field::kGroupName);
    const std::string groupAction =
        LowerAscii(FieldValue(event, field::kGroupAction));
    const std::string member = FieldValue(event, field::kGroupMember);
    const std::string fullName = FieldValue(event, field::kAccountFullName);

    uint32_t score = 0;
    if (type == "user") {
        if (action == "added") score += 25;
        if (IsSuspiciousUser(name)) score += 30;
        if (LowerAscii(fullName).find("admin") != std::string::npos)
            score += 10;
        /* Enabling a previously disabled account is often an attacker step. */
        if (enabled == "true" && action == "modified") score += 25;
    } else if (type == "group") {
        if (groupAction == "added") score += 20;
        if (groupAction == "removed") score += 10;
        if (IsPrivilegedGroup(group)) score += 35;
        if (IsSuspiciousUser(member)) score += 15;
    }

    if (score >= 55) {
        const std::string signalAction = type == "group" ? groupAction : action;
        signals = "account_" + type + "_" + signalAction;
        if (type == "group") {
            if (IsPrivilegedGroup(group)) signals += "_privileged_group";
        } else {
            if (IsSuspiciousUser(name)) signals += "_suspicious_user";
            if (enabled == "true") signals += "_enabled";
        }
    }
    return score;
}

void LocalAccountDetector::Enrich(Event& event) {
    if (!Inspects(event.type)) return;
    std::string signals;
    const uint32_t score = ScoreEvent(event, signals);
    if (score == 0) return;
    event.fields[field::kLocalAccountScore] = std::to_string(score);
    if (!signals.empty()) {
        event.fields[field::kLocalAccountSignals] = signals;
    }
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kLocalAccountVerdict] = verdict;
    }
}

} // namespace edr
