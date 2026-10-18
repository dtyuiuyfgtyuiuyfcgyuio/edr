/*
 * acl_abuse_detector.cpp - File/directory permission abuse
 * (T1222.001 / T1222.002).
 */
#include "acl_abuse_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 const char* const needles[], size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (Contains(value, needles[i])) return true;
    }
    return false;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

constexpr const char* kSensitivePaths[] = {
    "\\windows\\", "\\program files", "\\programdata\\",
    "\\users\\public", "\\appdata\\", "\\temp\\",
    "\\system32\\", "\\syswow64\\",
};

constexpr const char* kAclTokens[] = {
    "icacls", "takeown", "cacls", "set-acl", "get-acl",
};

bool IsAclInspectionOnly(const std::string& lower) {
    return Contains(lower, "get-acl") && !Contains(lower, "set-acl") &&
           !Contains(lower, "icacls") && !Contains(lower, "takeown") &&
           !Contains(lower, "cacls");
}

} // namespace

AclAbuseDetector::AclAbuseDetector(bool enabled, uint32_t minScore,
                                   uint32_t dedupWindowSeconds,
                                   size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool AclAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool AclAbuseDetector::Analyze(const std::string& lower,
                               Finding* out) const {
    if (IsAclInspectionOnly(lower)) return false;

    if (Contains(lower, "takeown")) {
        *out = Finding{70, "ownership takeover"};
        return true;
    }

    /* "icacls" contains the substring "cacls" - the legacy-tool match must
     * exclude icacls or every icacls command also lands here. */
    const size_t caclsPos = lower.find("cacls");
    const bool isLegacyCacls =
        caclsPos != std::string::npos &&
        (caclsPos == 0 || lower[caclsPos - 1] != 'i');
    if (isLegacyCacls) {
        if (Contains(lower, "/e") || Contains(lower, "/p") ||
            Contains(lower, "/g") || Contains(lower, "/r")) {
            *out = Finding{75, "legacy acl modification"};
            return true;
        }
        *out = Finding{60, "legacy acl tool invoked"};
        return true;
    }

    if (Contains(lower, "icacls")) {
        /* Bare `icacls <path>` displays the DACL - read-only inspection
         * that must stay silent. Only an action flag constitutes abuse. */
        uint32_t score = 0;
        const char* signal = nullptr;
        if (Contains(lower, "/inheritance:r") ||
            Contains(lower, "/grant everyone") ||
            Contains(lower, "/grant users") ||
            Contains(lower, "/remove:g") ||
            Contains(lower, "/deny everyone") ||
            Contains(lower, "/reset")) {
            score = 75;
            signal = "acl weakening";
        }
        if (Contains(lower, "/grant everyone:(f)") ||
            Contains(lower, "/grant everyone:(m)") ||
            Contains(lower, "/grant users:(f)") ||
            Contains(lower, "/grant users:(m)")) {
            score = 85;
            signal = "broad permission grant";
        }
        if (score == 0) return false;
        *out = Finding{score, signal};
        return true;
    }

    if (Contains(lower, "set-acl") || Contains(lower, "setaccessrule") ||
        Contains(lower, "removeaccessrule") || Contains(lower, "setsecuritydescriptor")) {
        const bool sensitive = ContainsAny(
            lower, kSensitivePaths,
            sizeof(kSensitivePaths) / sizeof(kSensitivePaths[0]));
        *out = Finding{sensitive ? 80u : 70u,
                       sensitive ? "powershell acl change on sensitive path"
                                 : "powershell acl change"};
        return true;
    }

    if (ContainsAny(lower, kAclTokens,
                    sizeof(kAclTokens) / sizeof(kAclTokens[0])) &&
        Contains(lower, "inheritance:r")) {
        *out = Finding{75, "acl inheritance stripped"};
        return true;
    }

    return false;
}

void AclAbuseDetector::Stamp(Event& event, const Finding& finding,
                             const std::string& key) {
    event.fields[field::kAclAbuseScore] = std::to_string(finding.score);
    event.fields[field::kAclAbuseVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kAclAbuseSignals] = finding.signal;
    event.fields[field::kAclAbuseCommand] = key;
}

void AclAbuseDetector::Enrich(Event& event) {
    if (!m_enabled) return;

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
                "[edr-acl-abuse] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr