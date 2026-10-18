/*
 * token_impersonation_detector.cpp - Access-token impersonation
 * command/script-plane detector (T1134.001 / T1134.002).
 */
#include "token_impersonation_detector.h"

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

TokenImpersonationDetector::TokenImpersonationDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool TokenImpersonationDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool TokenImpersonationDetector::Analyze(const std::string& lower,
                                         Finding* out) const {
    /* Potato-family and explicit token-manipulation tools. mimikatz only
     * counts alongside an explicit token:: command - the binary alone is
     * covered by the credential-dump detectors. Rubeus / pass-the-ticket
     * are kept here as well as in ticket_cache_abuse, which only matches
     * the "rubeus ptt" subcommand form. */
    if (Contains(lower, "godpotato") || Contains(lower, "sweetpotato") ||
        Contains(lower, "juicypotato") || Contains(lower, "roguepotato") ||
        Contains(lower, "printspoofer") || Contains(lower, "incognito.exe") ||
        Contains(lower, "rubeus") || Contains(lower, "passtheticket") ||
        (Contains(lower, "mimikatz") &&
         (Contains(lower, "token::elevate") ||
          Contains(lower, "token::whoami") ||
          Contains(lower, "token::revert")))) {
        *out = Finding{90, "token impersonation tool or command"};
        return true;
    }

    /* API chains exposed by PowerShell Add-Type, C# snippets, or native
     * source launched through a script/build tool. */
    const bool opensToken = Contains(lower, "openprocesstoken") ||
                            Contains(lower, "openprocesstokenex");
    const bool duplicatesToken = Contains(lower, "duplicatetokenex") ||
                                 Contains(lower, "duplicatetoken");
    const bool impersonates = Contains(lower, "impersonateloggedonuser") ||
                              Contains(lower, "setthreadtoken") ||
                              Contains(lower, "impersonate user") ||
                              Contains(lower, "impersonate_logged_on_user");
    const bool createsWithToken = Contains(lower, "createprocesswithtokenw") ||
                                  Contains(lower, "createprocessasuserw") ||
                                  Contains(lower, "createprocesswithlogonw");

    if (opensToken && duplicatesToken && (impersonates || createsWithToken)) {
        *out = Finding{90, "native token duplication and impersonation chain"};
        return true;
    }
    if (duplicatesToken && (impersonates || createsWithToken)) {
        *out = Finding{80, "token duplication followed by impersonation"};
        return true;
    }
    if (impersonates && createsWithToken) {
        *out = Finding{80, "token impersonation process creation"};
        return true;
    }
    if (opensToken && duplicatesToken) {
        *out = Finding{70, "token handle duplication"};
        return true;
    }

    /* PowerShell-native helpers commonly used to acquire or reuse a
     * privileged token. */
    if ((Contains(lower, "invoke-tokenmanipulation") ||
         Contains(lower, "get-system") ||
         Contains(lower, "invoke-impersonation")) &&
        (Contains(lower, "token") || Contains(lower, "impersonat"))) {
        *out = Finding{75, "PowerShell token impersonation helper"};
        return true;
    }

    return false;
}

void TokenImpersonationDetector::Stamp(Event& event, const Finding& finding,
                                       const std::string& key) {
    event.fields[field::kTokenImpersonationScore] = std::to_string(finding.score);
    event.fields[field::kTokenImpersonationVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kTokenImpersonationSignals] = finding.signal;
    event.fields[field::kTokenImpersonationCommand] = key;
}

void TokenImpersonationDetector::Enrich(Event& event) {
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
                "[edr-token-impersonation] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
