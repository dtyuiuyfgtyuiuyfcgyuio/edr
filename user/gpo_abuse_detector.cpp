/*
 * gpo_abuse_detector.cpp - Group Policy modification detector
 * (T1484.001).
 */
#include "gpo_abuse_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool IsGpoInspectionOnly(const std::string& lower) {
    /* Read-only inventory never scores. */
    if (Contains(lower, "gpresult") ||
        Contains(lower, "get-gpo") ||
        Contains(lower, "get-gplink") ||
        Contains(lower, "get-gpreport") ||
        Contains(lower, "gpupdate")) {
        return !Contains(lower, "new-gpo") &&
               !Contains(lower, "set-gp") &&
               !Contains(lower, "remove-gp") &&
               !Contains(lower, "new-gplink");
    }
    return false;
}

bool IsPolicyArtifact(const std::string& lower) {
    return Contains(lower, "registry.pol") ||
           Contains(lower, "gpt.ini") ||
           Contains(lower, "scripts.ini") ||
           Contains(lower, "psscripts.ini");
}

} // namespace

GpoAbuseDetector::GpoAbuseDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool GpoAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool GpoAbuseDetector::Analyze(const std::string& lower,
                               Finding* out) const {
    if (IsGpoInspectionOnly(lower)) return false;

    if (Contains(lower, "sharpgpoabuse") ||
        Contains(lower, "powergpoabuse")) {
        *out = Finding{90, "GPO abuse tooling"};
        return true;
    }

    if (IsPolicyArtifact(lower) &&
        (Contains(lower, "sysvol") ||
         Contains(lower, "grouppolicy") ||
         Contains(lower, "group policy") ||
         Contains(lower, "copy") ||
         Contains(lower, "xcopy") ||
         Contains(lower, "robocopy") ||
         Contains(lower, "move ") ||
         Contains(lower, "set-content") ||
         Contains(lower, "out-file"))) {
        *out = Finding{85, "GPO policy artifact staged"};
        return true;
    }

    if (Contains(lower, "new-gpo") ||
        Contains(lower, "set-gpregistryvalue") ||
        Contains(lower, "set-gppermission") ||
        Contains(lower, "new-gplink") ||
        Contains(lower, "set-gplink") ||
        Contains(lower, "set-gpprefregistryvalue")) {
        *out = Finding{80, "PowerShell GPO modification"};
        return true;
    }

    if (Contains(lower, "lgpo") &&
        (Contains(lower, "/gpo") || Contains(lower, "/parse") ||
         Contains(lower, "import") || Contains(lower, ".pol"))) {
        *out = Finding{80, "lgpo policy import"};
        return true;
    }

    if (Contains(lower, "secedit") && Contains(lower, "/configure")) {
        *out = Finding{75, "secedit /configure policy apply"};
        return true;
    }

    return false;
}

bool GpoAbuseDetector::AnalyzeReg(const std::string& lowerKeyValue,
                                  Finding* out) const {
    const bool groupPolicyKey =
        Contains(lowerKeyValue, "group policy") ||
        Contains(lowerKeyValue, "grouppolicy") ||
        Contains(lowerKeyValue, "\\policies\\microsoft\\windows\\system"
                                "\\scripts") ||
        Contains(lowerKeyValue, "\\microsoft\\windows nt\\currentversion"
                                "\\winlogon\\gpextensions");
    if (!groupPolicyKey) return false;

    *out = Finding{75, "Group Policy registry write"};
    return true;
}

void GpoAbuseDetector::Stamp(Event& event, const Finding& finding,
                             const std::string& key) {
    event.fields[field::kGpoAbuseScore] = std::to_string(finding.score);
    event.fields[field::kGpoAbuseVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kGpoAbuseSignals] = finding.signal;
    event.fields[field::kGpoAbuseText] = key;
}

void GpoAbuseDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    std::string key;

    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        std::string lowerKey = ToLowerAscii(keyIt->second);
        auto valIt = event.fields.find(field::kRegValue);
        if (valIt != event.fields.end())
            lowerKey += " " + ToLowerAscii(valIt->second);
        if (!AnalyzeReg(lowerKey, &finding)) return;
        if (finding.score < m_minScore) return;
        key = lowerKey.substr(0, 160);
    } else {
        std::string text;
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
        if (text.empty()) {
            auto imgIt = event.fields.find(field::kImage);
            if (imgIt == event.fields.end()) return;
            text = imgIt->second;
        }
        const std::string lower = ToLowerAscii(text);
        if (!Analyze(lower, &finding)) return;
        if (finding.score < m_minScore) return;
        key = lower.substr(0, 160);
    }

    const uint64_t now = event.ts100ns;
    auto it = m_lastAlert.find(key);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                "[edr-gpo-abuse] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
