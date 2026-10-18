/*
 * reg_cred_hunt_detector.cpp - See reg_cred_hunt_detector.h (T1552.002).
 */
#include "reg_cred_hunt_detector.h"

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

bool ContainsAny(const std::string& value, const char* const needles[],
                 size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (Contains(value, needles[i])) return true;
    }
    return false;
}

/* Credential-bearing search strings an operator greps a hive for. */
constexpr const char* kCredentialSelectors[] = {
    "password", "passwd", "pwd", "credential", "secret", "apikey",
    "api_key", "token", "privatekey",
};

/* Registry locations that store reusable secrets in the clear or in a
 * trivially reversible form. */
constexpr const char* kCredentialStores[] = {
    "simontatham\\putty\\sessions", "putty\\sessions",
    "martin prikryl\\winscp", "winscp 2\\sessions",
    "orl\\winvnc3", "tightvnc\\server", "realvnc\\vncserver",
    "snmp\\parameters\\validcommunities",
};

/* Winlogon autologon secrets. */
bool MentionsAutologonSecret(const std::string& lower) {
    return Contains(lower, "defaultpassword") ||
           Contains(lower, "altdefaultpassword");
}

/* Read verbs. A write to the same keys is configuration, not theft. */
bool IsReadVerb(const std::string& lower) {
    return Contains(lower, "reg query") || Contains(lower, "get-itemproperty") ||
           Contains(lower, "get-childitem") || Contains(lower, "get-item ") ||
           Contains(lower, "reg export") || Contains(lower, "gp ") ||
           Contains(lower, "gci ");
}

bool IsWriteVerb(const std::string& lower) {
    return Contains(lower, "reg add") || Contains(lower, "reg delete") ||
           Contains(lower, "set-itemproperty") ||
           Contains(lower, "new-itemproperty") ||
           Contains(lower, "remove-itemproperty");
}

} // namespace

RegCredHuntDetector::RegCredHuntDetector(bool enabled, uint32_t minScore,
                                         uint32_t dedupWindowSeconds,
                                         size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool RegCredHuntDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool RegCredHuntDetector::Analyze(const std::string& lower,
                                  Finding* out) const {
    /* Writes to the same keys are configuration, not credential access;
     * the persistence detectors own that plane. */
    if (IsWriteVerb(lower) && !IsReadVerb(lower)) return false;

    const bool credSelector =
        ContainsAny(lower, kCredentialSelectors,
                    sizeof(kCredentialSelectors) /
                    sizeof(kCredentialSelectors[0]));

    /* reg query ... /f <cred> : an explicit hive-wide secret grep. The
     * /f switch carries the search string, so this is unambiguous. */
    if (Contains(lower, "reg query") && credSelector &&
        (Contains(lower, "/f ") || Contains(lower, "/f\""))) {
        *out = Finding{90, "registry-wide credential search"};
        return true;
    }

    /* PowerShell recursive registry search for a credential pattern. */
    const bool psRegistrySearch =
        (Contains(lower, "hklm:") || Contains(lower, "hkcu:") ||
         Contains(lower, "registry::")) &&
        (Contains(lower, "-recurse") || Contains(lower, "select-string") ||
         Contains(lower, "where-object") || Contains(lower, "-match"));
    if (psRegistrySearch && credSelector) {
        *out = Finding{85, "PowerShell recursive registry credential search"};
        return true;
    }

    /* Winlogon autologon secret read. */
    if (MentionsAutologonSecret(lower) && IsReadVerb(lower)) {
        *out = Finding{85, "Winlogon autologon secret read"};
        return true;
    }

    /* Known third-party credential stores. */
    if (ContainsAny(lower, kCredentialStores,
                    sizeof(kCredentialStores) /
                    sizeof(kCredentialStores[0])) &&
        IsReadVerb(lower)) {
        *out = Finding{80, "third-party credential store read"};
        return true;
    }

    /* Broad read of the Winlogon key itself: autologon secrets live there,
     * so a sweep of the whole key is a weaker but real signal. */
    if (Contains(lower, "currentversion\\winlogon") && IsReadVerb(lower)) {
        *out = Finding{70, "Winlogon key swept for secrets"};
        return true;
    }

    return false;
}

void RegCredHuntDetector::Stamp(Event& event, const Finding& finding,
                                const std::string& key) {
    event.fields[field::kRegCredHuntScore] = std::to_string(finding.score);
    event.fields[field::kRegCredHuntVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kRegCredHuntSignals] = finding.signal;
    event.fields[field::kRegCredHuntText] = key;
}

void RegCredHuntDetector::Enrich(Event& event) {
    if (!m_enabled) return;

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
                "[edr-reg-cred-hunt] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
