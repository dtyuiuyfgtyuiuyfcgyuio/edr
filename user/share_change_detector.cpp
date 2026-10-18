/*
 * share_change_detector.cpp - See share_change_detector.h.
 */
#include "share_change_detector.h"

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

ShareChangeDetector::ShareChangeDetector() {}

bool ShareChangeDetector::IsSensitivePath(const std::string& path) {
    if (path.empty()) return false;
    const std::string lower = LowerAscii(path);
    /* Drive roots and system/user directories are common staging targets. */
    if (lower.size() == 2 && lower[1] == ':') return true;          /* C: */
    if (lower.size() == 3 && lower[1] == ':' && lower[2] == '\\') return true;
    if (lower == "\\\\" || lower == "\\\\*" || lower == "*") return true;
    return lower.find("\\windows\\") != std::string::npos ||
           lower.find("\\users\\") != std::string::npos ||
           lower.find("\\documents and settings\\") != std::string::npos ||
           lower.find("\\programdata\\") != std::string::npos ||
           lower.find("\\temp\\") != std::string::npos ||
           lower.find("\\public\\") != std::string::npos ||
           lower.find("\\inetpub\\") != std::string::npos ||
           lower.find("\\sysvol\\") != std::string::npos;
}

uint32_t ShareChangeDetector::ScoreEvent(const Event& event,
                                         std::string& signals) {
    const std::string action =
        LowerAscii(FieldValue(event, field::kShareAction));
    const std::string name = LowerAscii(FieldValue(event, field::kShareName));
    const std::string path = FieldValue(event, field::kSharePath);
    const std::string type = LowerAscii(FieldValue(event, field::kShareType));

    uint32_t score = 0;
    if (action == "added") {
        score += 20;
        /* Administrative / hidden shares are rarely created by users. */
        if (name.find('$') != std::string::npos) score += 25;
        /* Share over a sensitive or root directory. */
        if (IsSensitivePath(path)) score += 30;
        /* Print shares and IPC pipe shares are benign. */
        if (type == "print" || type == "ipc") {
            score = 0;
            signals.clear();
            return 0;
        }
    } else if (action == "modified") {
        /* Print and IPC shares churn constantly; changes are benign. */
        if (type == "print" || type == "ipc") return 0;
        score += 10;
        if (IsSensitivePath(path)) score += 30;
    } else if (action == "removed") {
        /* Removing shares could clean up lateral-movement artifacts. */
        if (name.find('$') != std::string::npos) score += 10;
        else score += 15;
    }

    if (score >= 55) {
        signals = "share_" + action;
        if (name.find('$') != std::string::npos) signals += "_hidden";
        if (IsSensitivePath(path)) signals += "_sensitive_path";
        if (type == "disk") signals += "_disk";
    }
    return score;
}

void ShareChangeDetector::Enrich(Event& event) {
    if (!Inspects(event.type)) return;
    std::string signals;
    const uint32_t score = ScoreEvent(event, signals);
    if (score == 0) return;
    event.fields[field::kShareChangeScore] = std::to_string(score);
    if (!signals.empty()) {
        event.fields[field::kShareChangeSignals] = signals;
    }
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kShareChangeVerdict] = verdict;
    }
}

} // namespace edr
