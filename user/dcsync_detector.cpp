/*
 * dcsync_detector.cpp - See dcsync_detector.h.
 */
#include "dcsync_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
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

} // namespace

DcsyncDetector::DcsyncDetector(bool enabled, uint32_t minScore,
                               uint32_t dedupWindowSeconds,
                               size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool DcsyncDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool DcsyncDetector::AnalyzeCommandLine(const std::string& lower,
                                        Finding* out) const {
    if (Contains(lower, "lsadump::dcsync")) {
        *out = Finding{90, "mimikatz_dcsync", "mimikatz"};
        return true;
    }
    if (Contains(lower, "secretsdump") &&
        ContainsAny(lower, {"-just-dc", " -dc "})) {
        *out = Finding{85, "secretsdump_dcsync", "impacket"};
        return true;
    }
    if (Contains(lower, "invoke-dcsync")) {
        *out = Finding{85, "invoke_dcsync", "powershell"};
        return true;
    }
    if (ContainsAny(lower, {"dcsync.py", "dcsync.exe", "pydcsync"})) {
        *out = Finding{80, "dcsync_tool", "dcsync"};
        return true;
    }
    return false;
}

void DcsyncDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kDcsyncScore] = std::to_string(finding.score);
    const std::string verdict =
        finding.score >= 75 ? "MALICIOUS" : "SUSPICIOUS";
    event.fields[field::kDcsyncVerdict] = verdict;
    event.fields[field::kDcsyncSignals] = finding.signal;
    if (!finding.tool.empty()) {
        event.fields[field::kDcsyncTools] = finding.tool;
    }
}

void DcsyncDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script bodies live in kScriptBlockText only - Invoke-DCSync is
         * a script-plane token, so skipping this leaves the PS plane
         * blind. */
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!AnalyzeCommandLine(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    /* Dedup on the normalized command text, not the signal category:
     * keying on the category would collapse distinct DCSync commands in
     * the same window into a single alert. */
    const uint64_t now = event.ts100ns;
    const std::string key = lower.substr(0, 160);
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
                "[edr-dcsync] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
