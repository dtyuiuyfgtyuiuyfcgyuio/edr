/*
 * history_tamper_detector.cpp - See history_tamper_detector.h
 * (T1070.003 / T1562.003).
 */
#include "history_tamper_detector.h"

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

bool EndsWith(const std::string& value, const char* suffix) {
    const size_t n = std::char_traits<char>::length(suffix);
    return value.size() >= n &&
           value.compare(value.size() - n, n, suffix) == 0;
}

/* The PSReadLine history file, in its common spellings. */
bool MentionsHistoryFile(const std::string& lower) {
    return Contains(lower, "consolehost_history") ||
           Contains(lower, "psreadline\\consolehost") ||
           Contains(lower, ".bash_history") ||
           Contains(lower, "psreadline_history");
}

/* Verbs that destroy or truncate a file. */
bool MentionsDestructiveVerb(const std::string& lower) {
    return Contains(lower, "del ") || Contains(lower, "erase ") ||
           Contains(lower, "remove-item") || Contains(lower, "ri ") ||
           Contains(lower, "rm ") || Contains(lower, "unlink") ||
           Contains(lower, "clear-content") ||
           Contains(lower, "out-null >") || Contains(lower, "> nul") ||
           Contains(lower, ">nul") || Contains(lower, "set-content") ||
           Contains(lower, "sdelete") || Contains(lower, "cipher /w");
}

/* Read-only inspection of the history configuration or file. */
bool IsReadOnly(const std::string& lower) {
    const bool reads = Contains(lower, "get-content") ||
                       Contains(lower, "get-psreadlineoption") ||
                       Contains(lower, "type ") ||
                       Contains(lower, "get-history");
    if (!reads) return false;
    return !MentionsDestructiveVerb(lower) &&
           !Contains(lower, "set-psreadlineoption") &&
           !Contains(lower, "clear-history");
}

} // namespace

HistoryTamperDetector::HistoryTamperDetector(bool enabled, uint32_t minScore,
                                             uint32_t dedupWindowSeconds,
                                             size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool HistoryTamperDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_FILE_DELETE;
}

bool HistoryTamperDetector::Analyze(const std::string& lower,
                                    Finding* out) const {
    if (IsReadOnly(lower)) return false;

    /* Disabling history capture outright: every later command in the
     * session becomes invisible, so this outranks deleting the file. */
    if (Contains(lower, "set-psreadlineoption") &&
        (Contains(lower, "historysavestyle") &&
         (Contains(lower, "savenothing") || Contains(lower, "nothing")))) {
        *out = Finding{90, "PSReadLine history capture disabled"};
        return true;
    }

    /* Destroying the on-disk history file. */
    if (MentionsHistoryFile(lower) && MentionsDestructiveVerb(lower)) {
        *out = Finding{85, "shell history file destroyed"};
        return true;
    }

    /* Clear-History / doskey /reinstall wipe the in-memory buffer. The
     * on-disk file may survive, so this sits below file destruction. */
    if (Contains(lower, "clear-history") ||
        (Contains(lower, "doskey") && Contains(lower, "/reinstall"))) {
        *out = Finding{75, "in-memory command history cleared"};
        return true;
    }

    /* Redirecting the history file to the null device or a throwaway
     * path is a quieter equivalent of disabling capture. The temp path
     * must be matched in its env-var spellings too ($env:TEMP\x.txt and
     * %TEMP%\x.txt have no leading backslash before "temp"). */
    if (Contains(lower, "historysavepath") &&
        (Contains(lower, "nul") || Contains(lower, "/dev/null") ||
         Contains(lower, "\\temp\\") || Contains(lower, "%temp%") ||
         Contains(lower, "$env:temp") || Contains(lower, "\\windows\\temp") ||
         Contains(lower, "$env:tmp") || Contains(lower, "%tmp%"))) {
        *out = Finding{85, "history save path redirected away"};
        return true;
    }

    /* A bare reference to the history file with no destructive verb is
     * still reconnaissance ahead of the steps above. */
    if (MentionsHistoryFile(lower)) {
        *out = Finding{60, "shell history file referenced"};
        return true;
    }

    return false;
}

void HistoryTamperDetector::Stamp(Event& event, const Finding& finding,
                                  const std::string& key) {
    event.fields[field::kHistoryTamperScore] = std::to_string(finding.score);
    event.fields[field::kHistoryTamperVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kHistoryTamperSignals] = finding.signal;
    event.fields[field::kHistoryTamperText] = key;
}

void HistoryTamperDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    if (event.type == EDR_EVT_FILE_DELETE) {
        auto pathIt = event.fields.find(field::kFilePath);
        if (pathIt == event.fields.end()) return;
        const std::string lowerPath = ToLowerAscii(pathIt->second);
        /* Deletion of the history file itself: the delete IS the verb, so
         * the command-plane verb requirement does not apply here. */
        if (!MentionsHistoryFile(lowerPath) &&
            !EndsWith(lowerPath, "consolehost_history.txt"))
            return;
        Finding finding{85, "shell history file deleted"};
        if (finding.score >= m_minScore)
            Stamp(event, finding, lowerPath.substr(0, 160));
        return;
    }

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) return;

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
                "[edr-history-tamper] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
