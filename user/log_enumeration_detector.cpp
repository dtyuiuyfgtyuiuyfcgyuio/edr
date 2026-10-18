/*
 * log_enumeration_detector.cpp - See log_enumeration_detector.h.
 */
#include "log_enumeration_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

/* Inventory enumeration shapes (the whole log list). */
const char* const kEnumerationShapes[] = {
    "wevtutil el",
    "wevtutil.exe el",
    "get-winevent -listlog",
    "get-eventlog -list",
};

/* Per-log configuration / provider shapes. */
const char* const kConfigShapes[] = {
    "wevtutil gl",
    "wevtutil.exe gl",
    "get-winevent -listprovider",
};

/* Channels whose enumeration is a pre-tamper sizing step. */
const char* const kSecurityChannels[] = {
    "security",
    "sysmon",
    "defender",
    "microsoft-windows-powershell",
    "winrm",
    "terminal services",
    "applocker",
    "codeintegrity",
    "smbclient",
    "wdac",
};

bool HasAny(const std::string& lower, const char* const needles[],
            size_t count, const char** matched) {
    for (size_t i = 0; i < count; ++i) {
        if (Contains(lower, needles[i])) {
            if (matched != nullptr) *matched = needles[i];
            return true;
        }
    }
    return false;
}

} // namespace

LogEnumerationDetector::LogEnumerationDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool LogEnumerationDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool LogEnumerationDetector::AnalyzeCommandText(
        const std::string& lower, Finding* out) const {
    const char* tool = nullptr;
    const bool enumerates =
        HasAny(lower, kEnumerationShapes,
               sizeof(kEnumerationShapes) / sizeof(kEnumerationShapes[0]),
               &tool);
    const bool configures =
        !enumerates &&
        HasAny(lower, kConfigShapes,
               sizeof(kConfigShapes) / sizeof(kConfigShapes[0]), &tool);
    if (!enumerates && !configures) return false;

    const char* channel = nullptr;
    const bool targeted =
        HasAny(lower, kSecurityChannels,
               sizeof(kSecurityChannels) / sizeof(kSecurityChannels[0]),
               &channel);

    /* Tier 75: the query names a defensive channel. */
    if (targeted) {
        *out = Finding{75, "security_log_targeting", tool, channel};
        return true;
    }

    /* Tier 65: bulk inventory enumeration. */
    if (enumerates) {
        *out = Finding{65, "event_log_enumeration", tool, ""};
        return true;
    }

    /* Tier 60: per-log configuration read. */
    *out = Finding{60, "log_config_query", tool, ""};
    return true;
}

void LogEnumerationDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kLogEnumerationScore] =
        std::to_string(finding.score);
    event.fields[field::kLogEnumerationVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kLogEnumerationSignals] = finding.signal;
    if (!finding.tool.empty())
        event.fields[field::kLogEnumerationTools] = finding.tool;
    if (!finding.channel.empty())
        event.fields[field::kLogEnumerationChannels] = finding.channel;
}

void LogEnumerationDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script blocks carry the body in kScriptBlockText, never
         * kCommandLine/kImage (house contract). */
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    if (text.empty()) return;

    Finding finding;
    if (!AnalyzeCommandText(ToLowerAscii(text), &finding)) return;

    if (finding.score < m_minScore) return;
    if (finding.score < 55) return; /* sub-verdict: fully silent */

    const std::string key = finding.signal;
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
                "[edr-log-enum] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
