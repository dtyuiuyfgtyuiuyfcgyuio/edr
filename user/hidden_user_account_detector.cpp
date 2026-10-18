/*
 * hidden_user_account_detector.cpp - See hidden_user_account_detector.h.
 */
#include "hidden_user_account_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <vector>

namespace edr {

namespace {

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

/* Split a registry key path into lowered, hive-agnostic segments
 * ("HKLM\SOFTWARE\..." and "\REGISTRY\MACHINE\SOFTWARE\..." both end up
 * as [.., software, ..]) so matching never depends on the prefix
 * spelling (same helper contract as netprovider_persist_detector). */
std::vector<std::string> SplitSegments(const std::string& keyPath) {
    std::vector<std::string> segments;
    std::string current;
    for (const char c : keyPath) {
        if (c == '\\') {
            if (!current.empty()) segments.push_back(ToLowerAscii(current));
            current.clear();
        } else {
            current += c;
        }
    }
    if (!current.empty()) segments.push_back(ToLowerAscii(current));
    return segments;
}

/* Index of the "specialaccounts" -> "userlist" segment pair, or -1. */
int FindSpecialAccountsUserList(const std::vector<std::string>& segments) {
    for (size_t i = 0; i + 1 < segments.size(); ++i) {
        if (segments[i] == "specialaccounts" &&
            segments[i + 1] == "userlist")
            return static_cast<int>(i);
    }
    return -1;
}

/* Command-plane shapes that state the hidden flag explicitly. */
const char* const kZeroDataShapes[] = {
    "/d 0",
    "/d 00000000",
    "/d 0x0",
    "/d 0x00000000",
    "dword:0",
    "-value 0",
    "-value 0x0",
    "= 0",
    "=0",
};

/* Write verbs that can create the value. `reg query` (a read) and
 * `reg delete` (which un-hides the account) deliberately do not match. */
const char* const kWriteVerbs[] = {
    "reg add",
    "new-itemproperty",
    "set-itemproperty",
    "add-itemproperty",
};

/* Parameter markers that name the account being written. */
const char* const kAccountMarkers[] = {
    "/v ",
    "-name ",
    "-property ",
};

std::string ExtractAccount(const std::string& lower) {
    for (const char* marker : kAccountMarkers) {
        const size_t pos = lower.find(marker);
        if (pos == std::string::npos) continue;
        size_t start = pos + std::string(marker).size();
        if (start < lower.size() &&
            (lower[start] == '"' || lower[start] == '\''))
            ++start;
        size_t end = start;
        while (end < lower.size() && lower[end] != ' ' &&
               lower[end] != '"' && lower[end] != '\'')
            ++end;
        if (end > start) return lower.substr(start, end - start);
    }
    return std::string();
}

} // namespace

HiddenUserAccountDetector::HiddenUserAccountDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool HiddenUserAccountDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_REG_WRITE ||
           type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool HiddenUserAccountDetector::AnalyzeRegistry(const std::string& regKey,
                                                const std::string& regValue,
                                                Finding* out) const {
    if (regKey.empty()) return false;
    const std::vector<std::string> segments = SplitSegments(regKey);
    const int idx = FindSpecialAccountsUserList(segments);
    if (idx < 0) return false;

    /* Snapshot shape: the key path carries the account name as its last
     * segment and kRegValue is the value DATA. */
    const bool hasValueName =
        static_cast<size_t>(idx) + 2 < segments.size();
    if (hasValueName) {
        const std::string account = segments.back();
        const std::string data = ToLowerAscii(regValue);
        if (data == "0") {
            *out = Finding{85, "hidden_user_account", account, regKey};
            return true;
        }
        if (data.empty()) {
            *out = Finding{75, "hidden_user_write", account, regKey};
            return true;
        }
        *out = Finding{70, "hidden_user_visible", account, regKey};
        return true;
    }

    /* Driver shape: kRegKey ends at ...\UserList and kRegValue is the
     * value NAME (the account); the kernel event carries no data, so the
     * hidden flag cannot be confirmed. */
    *out = Finding{75, "hidden_user_write", ToLowerAscii(regValue), regKey};
    return true;
}

bool HiddenUserAccountDetector::AnalyzeCommandText(
        const std::string& lower, Finding* out) const {
    if (!Contains(lower, "specialaccounts") || !Contains(lower, "userlist"))
        return false;

    /* Only a WRITE can create the concealment; `reg query` (read) and
     * `reg delete` (un-hide) stay silent. */
    bool writeVerb = false;
    for (const char* verb : kWriteVerbs) {
        if (Contains(lower, verb)) { writeVerb = true; break; }
    }
    if (!writeVerb) return false;

    const std::string account = ExtractAccount(lower);
    for (const char* shape : kZeroDataShapes) {
        if (Contains(lower, shape)) {
            *out = Finding{85, "hidden_user_account", account, ""};
            return true;
        }
    }
    *out = Finding{65, "hidden_user_cmd_write", account, ""};
    return true;
}

void HiddenUserAccountDetector::Stamp(Event& event,
                                      const Finding& finding) {
    event.fields[field::kHiddenUserScore] = std::to_string(finding.score);
    event.fields[field::kHiddenUserVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kHiddenUserSignals] = finding.signal;
    if (!finding.account.empty())
        event.fields[field::kHiddenUserAccounts] = finding.account;
}

void HiddenUserAccountDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    Finding finding;
    bool found = false;
    if (event.type == EDR_EVT_REG_WRITE) {
        found = AnalyzeRegistry(FieldValue(event, field::kRegKey),
                                FieldValue(event, field::kRegValue),
                                &finding);
    } else {
        std::string text = FieldValue(event, field::kCommandLine);
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            /* Script blocks carry the body in kScriptBlockText, never
             * kCommandLine/kImage (house contract). */
            text = FieldValue(event, field::kScriptBlockText);
        }
        if (text.empty()) text = FieldValue(event, field::kImage);
        if (!text.empty())
            found = AnalyzeCommandText(ToLowerAscii(text), &finding);
    }
    if (!found) return;

    if (finding.score < m_minScore) return;
    if (finding.score < 55) return; /* sub-verdict: fully silent */

    /* Dedup per (signal, account): hiding a different account alerts
     * again, re-hiding the same one inside the window does not. */
    std::string key = finding.signal;
    key += "|";
    key += ToLowerAscii(finding.account);
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
                "[edr-hidden-user] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
