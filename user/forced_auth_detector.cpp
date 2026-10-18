/*
 * forced_auth_detector.cpp - See forced_auth_detector.h.
 */
#include "forced_auth_detector.h"

#include <algorithm>
#include <cctype>
#include <initializer_list>

namespace edr {
namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (Contains(value, needle)) return true;
    }
    return false;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* True when the text contains a \\<d.d.d.d> UNC target with an IPv4
 * address (as opposed to a hostname), which is the coercion signature. */
bool HasUncIpv4Target(const std::string& lower) {
    size_t pos = 0;
    while ((pos = lower.find("\\\\", pos)) != std::string::npos) {
        size_t j = pos + 2;
        size_t k = j;
        int dots = 0;
        while (k < lower.size() &&
               ((lower[k] >= '0' && lower[k] <= '9') || lower[k] == '.')) {
            if (lower[k] == '.') ++dots;
            ++k;
        }
        if (k > j && dots == 3) return true;
        pos = k;
    }
    return false;
}

} // namespace

ForcedAuthDetector::ForcedAuthDetector(bool enabled, uint32_t minScore,
                                       uint32_t dedupWindowSeconds,
                                       size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool ForcedAuthDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool ForcedAuthDetector::AnalyzeCommandLine(const std::string& lower,
                                            Finding* out) const {
    if (Contains(lower, "petitpotam")) {
        *out = Finding{90, "petitpotam", "petitpotam"};
        return true;
    }
    if (Contains(lower, "spoolsample")) {
        *out = Finding{90, "spoolsample", "spoolsample"};
        return true;
    }
    if (Contains(lower, "printerbug") || Contains(lower, "spoolfool")) {
        *out = Finding{90, "printerbug", "printerbug"};
        return true;
    }
    if (Contains(lower, "responder") &&
        ContainsAny(lower, {"-i ", "-i="})) {
        *out = Finding{85, "responder", "responder"};
        return true;
    }
    if (Contains(lower, "inveigh")) {
        *out = Finding{85, "inveigh", "inveigh"};
        return true;
    }

    /* UNC credential coercion: net use / pushd / start / copy to a
     * \\<ip> target. Only the coercion verbs + IPv4 target combination
     * is treated as suspicious. */
    if (HasUncIpv4Target(lower)) {
        if (ContainsAny(lower, {"net use", "pushd \\", "start \\",
                                "copy \\", "xcopy \\"})) {
            *out = Finding{55, "unc_credential_coercion", "unc"};
            return true;
        }
    }

    return false;
}

void ForcedAuthDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kForcedAuthScore] = std::to_string(finding.score);
    const std::string verdict =
        finding.score >= 75 ? "MALICIOUS" : "SUSPICIOUS";
    event.fields[field::kForcedAuthVerdict] = verdict;
    event.fields[field::kForcedAuthSignals] = finding.signal;
    if (!finding.target.empty()) {
        event.fields[field::kForcedAuthTargets] = finding.target;
    }
}

void ForcedAuthDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!AnalyzeCommandLine(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    const uint64_t now = event.ts100ns;
    const std::string key = finding.signal;
    auto it = m_lastAlert.find(key);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
