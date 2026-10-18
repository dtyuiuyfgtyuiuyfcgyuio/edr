/*
 * password_policy_discovery_detector.cpp - See
 * password_policy_discovery_detector.h.
 */
#include "password_policy_discovery_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

/* Is this character part of a token core? Letters and digits glue a
 * needle into a lookalike word; underscore glues it into an
 * identifier-style name. */
bool IsTokenChar(unsigned char c) {
    return std::isalnum(c) != 0 || c == '_';
}

/* Full token-bounded substring match (same helper contract as
 * llmnr_poison_detector / arp_poison_detector): `needle` (already
 * lowered) only counts when BOTH edges sit on token boundaries:
 *   start - the match begins at position 0 or the character before it is
 *           not a letter/digit (delimiters accepted, same start rule as
 *           the previous HasWordStartBounded helper);
 *   tail  - the match runs to the end of the text or the next character
 *           is not a letter/digit/underscore.
 * The tail rejects letter/digit/underscore continuations
 * ("net accountsx", "net1 accounts_audit") while accepting the
 * delimiters that really follow the command token: dot, space, quote,
 * path separators, hyphen, and end of string. Word-start-only matching
 * missed this tail family. The start edge is what keeps "tenet
 * accounts" from matching the "net accounts" needle - the rule this
 * file's old helper already had. Both edges share the semantics of the
 * HasTokenBounded helpers in llmnr_poison_detector /
 * arp_poison_detector. */
bool HasTokenBounded(const std::string& lower, const char* needle) {
    const std::string stem(needle);
    if (stem.empty() || lower.size() < stem.size()) return false;
    for (size_t pos = lower.find(stem); pos != std::string::npos;
         pos = lower.find(stem, pos + 1)) {
        if (pos != 0 && IsTokenChar(lower[pos - 1])) continue;
        const size_t end = pos + stem.size();
        if (end < lower.size() && IsTokenChar(lower[end])) continue;
        return true;
    }
    return false;
}

/* AD policy cmdlets that exist only to read the password policy. The
 * needles are the LOWERCASED cmdlet names - note "default" sits inside
 * Get-ADDefaultDomainPasswordPolicy. */
const char* const kPolicyCmdlets[] = {
    "get-addefaultdomainpasswordpolicy",
    "get-adfinegrainedpasswordpolicy",
    "get-aduserresultantpasswordpolicy",
    "get-domainpolicy",
};

/* `net accounts` setter flags: their presence means the command MODIFIES
 * the policy, which AccountOpDetector owns - not a discovery. */
const char* const kSetterFlags[] = {
    "/minpwlen",
    "/maxpwage",
    "/minpwage",
    "/uniquepw",
    "/lockoutthreshold",
    "/lockoutduration",
    "/lockoutwindow",
    "/forcelogoff",
};

bool IsNetAccountsRead(const std::string& lower) {
    /* All four command shapes are token bounded on both edges:
     * "tenet accounts" fails the start edge and letter/underscore-glued
     * lookalikes ("net accountsx", "net1 accounts_audit") fail the tail
     * edge, while trailing flags, quotes and end of string pass. */
    if (!HasTokenBounded(lower, "net accounts") &&
        !HasTokenBounded(lower, "net.exe accounts") &&
        !HasTokenBounded(lower, "net1 accounts") &&
        !HasTokenBounded(lower, "net1.exe accounts"))
        return false;
    for (const char* flag : kSetterFlags) {
        if (Contains(lower, flag)) return false;
    }
    return true;
}

} // namespace

PasswordPolicyDiscoveryDetector::PasswordPolicyDiscoveryDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool PasswordPolicyDiscoveryDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool PasswordPolicyDiscoveryDetector::AnalyzeCommandText(
        const std::string& lower, Finding* out) const {
    /* Tier 75: dedicated AD policy cmdlets. */
    for (const char* cmdlet : kPolicyCmdlets) {
        if (Contains(lower, cmdlet)) {
            *out = Finding{75, "domain_password_policy_query", cmdlet};
            return true;
        }
    }

    /* Tier 70 / 65: the built-in `net accounts` read (domain vs local).
     * Setter flags disqualify the event entirely - that is a policy
     * modification, not a discovery. */
    if (IsNetAccountsRead(lower)) {
        if (Contains(lower, "/domain")) {
            *out = Finding{70, "net_accounts_domain_read", "net accounts"};
            return true;
        }
        *out = Finding{65, "net_accounts_read", "net accounts"};
        return true;
    }

    /* Tier 65: secedit /export dumps the local security policy. */
    if (Contains(lower, "secedit") && Contains(lower, "/export")) {
        *out = Finding{65, "secedit_policy_export", "secedit"};
        return true;
    }

    return false;
}

void PasswordPolicyDiscoveryDetector::Stamp(Event& event,
                                            const Finding& finding) {
    event.fields[field::kPasswordPolicyScore] = std::to_string(finding.score);
    event.fields[field::kPasswordPolicyVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kPasswordPolicySignals] = finding.signal;
    if (!finding.tool.empty())
        event.fields[field::kPasswordPolicyTools] = finding.tool;
}

void PasswordPolicyDiscoveryDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script blocks carry the body in kScriptBlockText, never
         * kCommandLine/kImage (house contract). */
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    if (text.empty()) return;

    Finding finding;
    if (!AnalyzeCommandText(ToLowerAscii(text), &finding)) return;

    if (finding.score < m_minScore) return;
    if (finding.score < 55) return; /* sub-verdict: fully silent */

    const std::string key = finding.signal;
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
                "[edr-password-policy] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
