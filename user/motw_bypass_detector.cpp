/*
 * motw_bypass_detector.cpp - Mark-of-the-Web removal detector
 * (T1553.005 Mark-of-the-Web Bypass).
 */
// pi-lens-ignore: clang:pp_file_not_found
#include "motw_bypass_detector.h"

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

} // namespace

MotwBypassDetector::MotwBypassDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool MotwBypassDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE ||
           type == EDR_EVT_FILE_DELETE;
}

bool MotwBypassDetector::Analyze(const std::string& lower,
                                 Finding* out) const {
    /* Registry plane: policy disabling MOTW propagation entirely. */
    if ((Contains(lower, "attachment") &&
         (Contains(lower, "savezoneinformation") ||
          Contains(lower, "scanwithantivirus"))) ||
        (Contains(lower, "policies\\attachments") &&
         Contains(lower, "reg add"))) {
        *out = Finding{90, "attachment manager MOTW policy disabled"};
        return true;
    }

    if (Contains(lower, "unblock-file")) {
        *out = Finding{75, "Unblock-File stripped Mark-of-the-Web"};
        return true;
    }

    if (Contains(lower, ":zone.identifier") ||
        Contains(lower, "zone.identifier")) {
        /* Read-only inspection of the stream stays silent. */
        if (Contains(lower, "get-content") ||
            Contains(lower, "get-item") && !Contains(lower, "|"))
            return false;
        if (Contains(lower, "del ") || Contains(lower, "delete") ||
            Contains(lower, "remove-item") || Contains(lower, "erase") ||
            Contains(lower, ">nul") || Contains(lower, "streams -d")) {
            *out = Finding{85, "Zone.Identifier ADS deleted"};
            return true;
        }
    }

    /* dir /r lists alternate streams - the enumeration precursor to a
     * zone-strip. Scored on its own so it fires without the ADS name
     * appearing in the command line. */
    if (Contains(lower, "dir /r")) {
        *out = Finding{55, "ADS enumeration before zone-strip"};
        return true;
    }

    return false;
}

void MotwBypassDetector::Stamp(Event& event, const Finding& finding,
                               const std::string& key) {
    event.fields[field::kMotwBypassScore] = std::to_string(finding.score);
    event.fields[field::kMotwBypassVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kMotwBypassSignals] = finding.signal;
    event.fields[field::kMotwBypassText] = key;
}

void MotwBypassDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    bool regPlane = false;

    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        text = keyIt->second;
        auto valIt = event.fields.find(field::kRegValue);
        if (valIt != event.fields.end()) {
            if (!text.empty()) text += " ";
            text += valIt->second;
        }
        regPlane = true;
    } else if (event.type == EDR_EVT_FILE_DELETE) {
        auto pathIt = event.fields.find(field::kFilePath);
        if (pathIt != event.fields.end()) text = pathIt->second;
        if (text.empty()) return;
        const std::string lowerPath = ToLowerAscii(text);
        if (!Contains(lowerPath, ":zone.identifier")) return;
        Finding finding{85u, "Zone.Identifier ADS deleted"};
        if (finding.score >= m_minScore)
            Stamp(event, finding, lowerPath.substr(0, 160));
        return;
    } else {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
    }
    if (text.empty()) return;
    (void)regPlane;

    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = lower.substr(0, 160);
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
                "[edr-motw-bypass] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
