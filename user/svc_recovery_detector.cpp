/*
 * svc_recovery_detector.cpp - Service recovery action hijack detector
 * (T1037.004 / T1543.003).
 */
#include "svc_recovery_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

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

bool MentionsWritableDir(const std::string& lower) {
    return Contains(lower, "\\temp\\") || Contains(lower, "%temp%") ||
           Contains(lower, "\\appdata\\") || Contains(lower, "%appdata%") ||
           Contains(lower, "\\users\\public") ||
           Contains(lower, "\\programdata\\") ||
           Contains(lower, "\\downloads\\") ||
           Contains(lower, "\\desktop\\");
}

bool MentionsInterpreter(const std::string& lower) {
    return Contains(lower, "powershell") || Contains(lower, "pwsh") ||
           Contains(lower, "cmd.exe") || Contains(lower, "cmd /") ||
           Contains(lower, "wscript") || Contains(lower, "cscript") ||
           Contains(lower, "rundll32") || Contains(lower, "mshta") ||
           Contains(lower, "regsvr32");
}

bool IsSystem32Path(const std::string& lower) {
    return Contains(lower, "\\windows\\system32\\") ||
           Contains(lower, "%systemroot%\\system32") ||
           Contains(lower, "%windir%\\system32");
}

bool IsReadOnlyQuery(const std::string& lower) {
    const bool reads = Contains(lower, "sc qfailure") ||
                       Contains(lower, "sc query") ||
                       Contains(lower, "reg query") ||
                       Contains(lower, "get-itemproperty");
    if (!reads) return false;
    return !Contains(lower, "sc failure") && !Contains(lower, "reg add") &&
           !Contains(lower, "set-itemproperty");
}

bool IsTrustedWriter(const std::string& lower) {
    return Contains(lower, "msiexec") || Contains(lower, "trustedinstaller") ||
           Contains(lower, "tiworker") || Contains(lower, "\\servicing\\");
}

bool IsRecoveryKey(const std::string& lower) {
    return Contains(lower, "\\services\\") &&
           (Contains(lower, "failureactions") ||
            Contains(lower, "failurecommand") ||
            Contains(lower, "failureactions") );
}

} // namespace

SvcRecoveryDetector::SvcRecoveryDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_capacity(stateCapacity) {}

/* static */
bool SvcRecoveryDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

/* static */
bool SvcRecoveryDetector::ClassifyPayload(const std::string& data,
                                          Finding* out) {
    if (data.empty()) return false;
    const std::string lower = ToLowerAscii(data);
    if (IsSystem32Path(lower) && !MentionsWritableDir(lower) && !MentionsInterpreter(lower))
        return false;
    if (MentionsInterpreter(lower)) {
        *out = Finding{90, "recovery command is interpreter"};
        return true;
    }
    if (MentionsWritableDir(lower)) {
        *out = Finding{90, "recovery command in writable directory"};
        return true;
    }
    if (Contains(lower, ".exe") || Contains(lower, ".bat") ||
        Contains(lower, ".ps1") || Contains(lower, ".vbs")) {
        if (!IsSystem32Path(lower)) {
            *out = Finding{85, "recovery command outside system32"};
            return true;
        }
    }
    // Generic non-system path
    if (Contains(lower, ":\\") && !IsSystem32Path(lower)) {
        *out = Finding{85, "recovery command with non-system path"};
        return true;
    }
    return false;
}

void SvcRecoveryDetector::Stamp(Event& event, const Finding& finding,
                                const std::string& key) {
    event.fields[field::kSvcRecoveryScore] = std::to_string(finding.score);
    event.fields[field::kSvcRecoveryVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kSvcRecoverySignals] = finding.signal;
    event.fields[field::kSvcRecoveryText] = key;
}

void SvcRecoveryDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        auto valIt = event.fields.find(field::kRegValue);
        std::string keyText;
        if (keyIt != event.fields.end()) keyText = keyIt->second;
        std::string valText;
        if (valIt != event.fields.end()) valText = valIt->second;
        const std::string lowerJoined = ToLowerAscii(keyText + " " + valText);
        if (!IsRecoveryKey(lowerJoined)) return;

        const std::string lowerKey = ToLowerAscii(keyText);
        const std::string lowerVal = ToLowerAscii(valText);

        bool keyNamesSlot = EndsWith(lowerKey, "\\failureactions") ||
                            EndsWith(lowerKey, "\\failurecommand") ||
                            lowerKey == "failureactions" ||
                            lowerKey == "failurecommand";
        bool valNamesSlot = lowerVal == "failureactions" ||
                            lowerVal == "failurecommand";

        Finding finding;
        if (keyNamesSlot && !valText.empty()) {
            if (!ClassifyPayload(valText, &finding)) return;
        } else if (valNamesSlot) {
            if (keyText.empty() || lowerKey.find("\\services\\") == std::string::npos)
                return;
            finding = Finding{75, "recovery slot registered with no payload token"};
        } else {
            if (valText.empty() || !ClassifyPayload(valText, &finding))
                return;
        }

        if (finding.score < m_minScore) return;
        Stamp(event, finding, lowerJoined.substr(0, 160));
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
    bool mentionsScFailure = Contains(lower, "sc failure") || Contains(lower, "sc.exe failure");
    bool mentionsRecovery = Contains(lower, "failureactions") ||
                            Contains(lower, "failurecommand") ||
                            (mentionsScFailure && Contains(lower, "command="));

    if (!mentionsScFailure && !mentionsRecovery) return;
    if (IsReadOnlyQuery(lower)) return;
    if (IsTrustedWriter(lower)) return;

    // Try to extract command after "command=" for scoring
    std::string payload = text;
    size_t cmdPos = lower.find("command=");
    if (cmdPos != std::string::npos) {
        payload = text.substr(cmdPos + 8);
    }

    Finding finding;
    if (!ClassifyPayload(payload, &finding)) {
        // sc failure without extractable payload still creates the slot
        if (mentionsScFailure) {
            finding = Finding{75, "recovery command written with no payload token"};
        } else {
            return;
        }
    }
    if (finding.score < m_minScore) return;

    const std::string key = lower.substr(0, 160);
    const uint64_t now = event.ts100ns;
    auto it = m_state.find(key);
    if (it != m_state.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_capacity > 0 && m_state.size() >= m_capacity) {
            m_state.clear();
            std::fprintf(stderr,
                "[edr-svc-recovery] state capacity %zu reached; dedup reset\n",
                m_capacity);
        }
        m_state.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
