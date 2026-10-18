/*
 * logon_script_persist_detector.cpp - See
 * logon_script_persist_detector.h (T1037.001 / T1547.014).
 */
#include "logon_script_persist_detector.h"

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

/* Interpreters and payload extensions worth flagging in a StubPath or
 * logon-script value. */
bool MentionsPayload(const std::string& lower) {
    return Contains(lower, ".exe") || Contains(lower, ".dll") ||
           Contains(lower, ".bat") || Contains(lower, ".cmd") ||
           Contains(lower, ".vbs") || Contains(lower, ".js") ||
           Contains(lower, ".ps1") || Contains(lower, ".hta") ||
           Contains(lower, "powershell") || Contains(lower, "cmd.exe") ||
           Contains(lower, "wscript") || Contains(lower, "cscript") ||
           Contains(lower, "rundll32") || Contains(lower, "mshta");
}

/* User-writable locations: a logon script living there is attacker-owned
 * rather than administrator-deployed. */
bool MentionsWritablePath(const std::string& lower) {
    return Contains(lower, "\\temp\\") || Contains(lower, "%temp%") ||
           Contains(lower, "\\appdata\\") || Contains(lower, "%appdata%") ||
           Contains(lower, "\\users\\public") ||
           Contains(lower, "\\programdata\\") ||
           Contains(lower, "\\downloads\\");
}

bool IsReadOnlyQuery(const std::string& lower) {
    const bool reads = Contains(lower, "reg query") ||
                       Contains(lower, "get-itemproperty") ||
                       Contains(lower, "get-childitem") ||
                       Contains(lower, "gpresult");
    if (!reads) return false;
    return !Contains(lower, "reg add") && !Contains(lower, "set-itemproperty") &&
           !Contains(lower, "new-itemproperty") &&
           !Contains(lower, "reg delete");
}

} // namespace

LogonScriptPersistDetector::LogonScriptPersistDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool LogonScriptPersistDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool LogonScriptPersistDetector::Analyze(const std::string& lower,
                                         Finding* out) const {
    if (IsReadOnlyQuery(lower)) return false;

    /* UserInitMprLogonScript: a per-user logon script that runs on every
     * interactive logon and is not shown by the usual autorun UIs. */
    if (Contains(lower, "userinitmprlogonscript")) {
        *out = Finding{90, "UserInitMprLogonScript logon script installed"};
        return true;
    }

    /* Active Setup StubPath: runs once per user at logon, ahead of the
     * shell, and is a classic quiet persistence slot. */
    const bool activeSetup =
        Contains(lower, "active setup\\installed components") ||
        Contains(lower, "activesetup");
    if (activeSetup && Contains(lower, "stubpath")) {
        *out = Finding{90, "Active Setup StubPath persistence"};
        return true;
    }

    /* Group Policy logon/logoff script directory writes. */
    if ((Contains(lower, "\\scripts\\logon") ||
         Contains(lower, "\\scripts\\logoff") ||
         Contains(lower, "scripts\\startup")) &&
        MentionsPayload(lower)) {
        *out = Finding{85, "Group Policy logon script planted"};
        return true;
    }

    /* A StubPath write with no explicit payload token still creates the
     * persistence slot. */
    if (activeSetup) {
        *out = Finding{75, "Active Setup component registered"};
        return true;
    }

    /* Logon script pointed at a user-writable location. */
    if (Contains(lower, "logonscript") && MentionsWritablePath(lower)) {
        *out = Finding{80, "logon script in user-writable path"};
        return true;
    }

    return false;
}

void LogonScriptPersistDetector::Stamp(Event& event, const Finding& finding,
                                       const std::string& key) {
    event.fields[field::kLogonScriptScore] = std::to_string(finding.score);
    event.fields[field::kLogonScriptVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kLogonScriptSignals] = finding.signal;
    event.fields[field::kLogonScriptText] = key;
}

void LogonScriptPersistDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        text = keyIt->second;
        auto valIt = event.fields.find(field::kRegValue);
        if (valIt != event.fields.end()) {
            if (!text.empty()) text += " ";
            text += valIt->second;
        }
    } else {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
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
                "[edr-logon-script] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
