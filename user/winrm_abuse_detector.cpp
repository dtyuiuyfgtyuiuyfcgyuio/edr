/*
 * winrm_abuse_detector.cpp - WinRM remote-execution abuse (T1021.006).
 */
#include "winrm_abuse_detector.h"

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

/* Boundary-checked basename hit: "winrs" or "winrs.exe" preceded by a
 * path separator / quote / operator or string position 0, always
 * followed by whitespace, so prose like "winrssrv" never hits. */
bool InvokesWinrs(const std::string& lower) {
    size_t pos = 0;
    while ((pos = lower.find("winrs", pos)) != std::string::npos) {
        const bool startOk =
            pos == 0 || lower[pos - 1] == '\\' || lower[pos - 1] == '/' ||
            lower[pos - 1] == '"' || lower[pos - 1] == '\'' ||
            lower[pos - 1] == ' ' || lower[pos - 1] == '&' ||
            lower[pos - 1] == '|';
        size_t after = pos + 5;
        if (lower.compare(after, 4, ".exe") == 0) after += 4;
        if (startOk && after < lower.size() &&
            (lower[after] == ' ' || lower[after] == '\t'))
            return true;
        pos += 5;
    }
    return false;
}

} // namespace

WinrmAbuseDetector::WinrmAbuseDetector(bool enabled, uint32_t minScore,
                                       uint32_t dedupWindowSeconds,
                                       size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool WinrmAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool WinrmAbuseDetector::Analyze(const std::string& lower,
                                 Finding* out) const {
    /* winrs.exe: direct remote shell client. */
    if (InvokesWinrs(lower)) {
        *out = Finding{85, "winrs remote shell invoked"};
        return true;
    }

    /* PowerShell remoting cmdlets targeting a remote host. */
    static const char* const kRemotingCmdlets[] = {
        "new-pssession", "enter-pssession", "invoke-command"
    };
    for (const char* cmdlet : kRemotingCmdlets) {
        if (!Contains(lower, cmdlet)) continue;
        if (Contains(lower, "-computername") ||
            Contains(lower, "-cn ") || Contains(lower, "-connectionuri")) {
            *out = Finding{80, "powershell remoting to remote host"};
            return true;
        }
    }

    /* winrm invoke / create against a remote listener. Plain
     * "winrm invoke" without -r is local configuration; still scored
     * lower because it can enumerate/alter remoting config. */
    if (Contains(lower, "winrm invoke") ||
        Contains(lower, "winrm create")) {
        *out = Finding{Contains(lower, "-r:") ? 75u : 65u,
                       "winrm listener/config manipulation"};
        return true;
    }
    if (Contains(lower, "winrm quickconfig")) {
        *out = Finding{60, "winrm quickconfig enablement"};
        return true;
    }
    return false;
}

void WinrmAbuseDetector::Stamp(Event& event, const Finding& finding,
                               const std::string& key) {
    event.fields[field::kWinrmAbuseScore] = std::to_string(finding.score);
    event.fields[field::kWinrmAbuseVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kWinrmAbuseSignals] = finding.signal;
    event.fields[field::kWinrmAbuseCommand] = key;
}

void WinrmAbuseDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script blocks carry the body in kScriptBlockText, never
         * kCommandLine/kImage. */
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
    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    /* Dedup per normalized command prefix. */
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
                "[edr-winrm] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
