/*
 * remote_exec_detector.cpp - See remote_exec_detector.h.
 */
#include "remote_exec_detector.h"

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

/* Boundary-checked "winrs"/"winrs.exe" basename hit, matching the helper
 * in winrm_abuse_detector.cpp so prose such as \\winrssrv01\share never
 * counts as an invocation. */
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

RemoteExecDetector::RemoteExecDetector(bool enabled, uint32_t minScore,
                                       uint32_t dedupWindowSeconds,
                                       size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool RemoteExecDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool RemoteExecDetector::AnalyzeCommandLine(const std::string& lower,
                                            Finding* out) const {
    /* PsExec against a remote target (UNC path \\host). */
    if (Contains(lower, "psexec") && Contains(lower, "\\\\")) {
        *out = Finding{80, "psexec_remote", "psexec"};
        return true;
    }
    /* wmic /node:<host> process call create "cmd ..." */
    if (Contains(lower, "wmic") &&
        ContainsAny(lower, {"/node:", "/node="}) &&
        Contains(lower, "process call create")) {
        *out = Finding{75, "wmic_remote_exec", "wmic"};
        return true;
    }
    /* winrs -r:<host> command. winrm_abuse (EDR-355) scores the same
     * invocation higher on the WinRM-specific plane; this entry keeps the
     * remote-execution inventory complete for operators filtering on
     * remote_exec_score alone. */
    if (InvokesWinrs(lower) &&
        ContainsAny(lower, {"-r:", "-r "})) {
        *out = Finding{75, "winrs_remote", "winrs"};
        return true;
    }
    /* sc \\<host> create/start (remote service). Both the bare and the
     * .exe spellings, with any run of spaces before the UNC target. */
    if (ContainsAny(lower, {"sc \\\\", "sc.exe \\\\", "sc  \\\\"})) {
        *out = Finding{75, "sc_remote_service", "sc"};
        return true;
    }
    /* schtasks /create or /run with a remote host (/s). */
    if (Contains(lower, "schtasks") &&
        ContainsAny(lower, {"/create", "/run"}) &&
        ContainsAny(lower, {"/s ", "/s:", "/s="})) {
        *out = Finding{70, "schtasks_remote", "schtasks"};
        return true;
    }
    return false;
}

void RemoteExecDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kRemoteExecScore] = std::to_string(finding.score);
    const std::string verdict =
        finding.score >= 75 ? "MALICIOUS" : "SUSPICIOUS";
    event.fields[field::kRemoteExecVerdict] = verdict;
    event.fields[field::kRemoteExecSignals] = finding.signal;
    if (!finding.tool.empty()) {
        event.fields[field::kRemoteExecTools] = finding.tool;
    }
}

void RemoteExecDetector::Enrich(Event& event) {
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
    /* Dedup on the normalized command text, not the signal category:
     * keying on the category would collapse distinct remote-execution
     * commands in the same window into a single alert. */
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
                "[edr-remote-exec] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
