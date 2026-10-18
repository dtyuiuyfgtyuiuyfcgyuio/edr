/*
 * mailbox_delegate_detector.cpp - See mailbox_delegate_detector.h.
 */
#include "mailbox_delegate_detector.h"

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

/* First position at or after `from` where `needle` (already lowered, e.g.
 * "-accessrights") appears in a PowerShell flag shape: followed by a space,
 * colon-bound argument, quote, separator or end of text. Returns npos when
 * absent. FindFlagPos, RegionHasFlagValue, RegionHasFlag and
 * ExtractTarget share this acceptance rule, so "-Id 42" can never
 * satisfy the "-identity" needle's role and "-accessright" can never
 * match inside "-accessrights". */
size_t FindFlagPosFrom(const std::string& lower, const std::string& needle,
                       size_t from) {
    for (size_t pos = lower.find(needle, from); pos != std::string::npos;
         pos = lower.find(needle, pos + 1)) {
        if (pos > 0) {
            const char prev = lower[pos - 1];
            /* The flag must start on a token boundary: a preceding '-'
             * (e.g. "-not-identity") or alnum would make the hit a
             * substring of something else. */
            if (prev == '-' || std::isalnum(static_cast<unsigned char>(prev)))
                continue;
        }
        const size_t end = pos + needle.size();
        if (end >= lower.size()) return pos;
        const char next = lower[end];
        if (next == ' ' || next == '\t' || next == ':' || next == '"' ||
            next == '\'' || next == ',' || next == ';')
            return pos;
    }
    return std::string::npos;
}

size_t FindFlagPos(const std::string& lower, const std::string& needle) {
    return FindFlagPosFrom(lower, needle, 0);
}

/* First word-boundary occurrence of `cmdlet` at or after `from`; npos
 * when absent. The character before the match must sit on a token
 * boundary and the character after must be a separator or end of text.
 * This keeps "set-mailbox" from matching inside
 * "set-mailboxfolderpermission" and "add-mailboxpermission" from
 * matching "Add-MailboxPermissionFake". */
size_t FindCmdletFrom(const std::string& lower, const char* cmdlet,
                      size_t from) {
    const std::string needle = cmdlet;
    for (size_t pos = lower.find(needle, from); pos != std::string::npos;
         pos = lower.find(needle, pos + 1)) {
        if (pos > 0) {
            const char prev = lower[pos - 1];
            const bool prevOk =
                prev == ' ' || prev == '\t' || prev == '"' || prev == '\'' ||
                prev == ';' || prev == ',' || prev == '(' || prev == '|' ||
                prev == '`' || prev == '\n' || prev == '\r';
            if (!prevOk) continue;
        }
        const size_t end = pos + needle.size();
        if (end < lower.size()) {
            const char next = lower[end];
            const bool nextOk =
                next == ' ' || next == '\t' || next == ':' || next == '"' ||
                next == '\'' || next == ',' || next == ';' || next == '(' ||
                next == '|' || next == '\n' || next == '\r';
            if (!nextOk) continue;
        }
        return pos;
    }
    return std::string::npos;
}

bool HasCmdlet(const std::string& lower, const char* cmdlet) {
    return FindCmdletFrom(lower, cmdlet, 0) != std::string::npos;
}

/* Mailbox-delegation cmdlet family: every member opens a new statement
 * scope for flag-value binding. A grant cmdlet's flag region ends at the
 * next family token (which may sit on the far side of a ";", "|" or
 * newline statement separator), so a later Remove-* statement carrying
 * -AccessRights FullAccess can never endorse an earlier Add-* in the
 * same block. The list is deliberately closed: a generic "verb-noun"
 * boundary rule would false-terminate on values like "Send-as". */
const char* const kCmdletBoundaries[] = {
    "add-mailboxpermission",      "add-adpermission",
    "add-recipientpermission",    "add-mailboxfolderpermission",
    "set-mailbox",                "set-mailboxfolderpermission",
    "remove-mailboxpermission",   "remove-adpermission",
    "remove-recipientpermission", "remove-mailboxfolderpermission",
    "get-mailboxpermission",      "get-adpermission",
    "get-recipientpermission",    "get-mailboxfolderpermission",
};

/* Start of the first mailbox-delegation cmdlet token at or after `from`
 * (pass `cmdletPos + 1` to skip the owning occurrence): the earliest
 * family occurrence, or npos when the region runs to the end of text. */
size_t NextCmdletBoundary(const std::string& lower, size_t from) {
    size_t best = std::string::npos;
    for (const char* cmdlet : kCmdletBoundaries) {
        const size_t pos = FindCmdletFrom(lower, cmdlet, from);
        if (pos < best) best = pos;
    }
    return best;
}

/* PowerShell line continuation: a backtick followed by a newline
 * (optionally CRLF) plus the next line's leading indentation is soft
 * whitespace inside a flag's value span - both before the first value
 * character and mid-value. Returns true and advances *i past the whole
 * sequence when a continuation is consumed; a lone backtick (no newline
 * after it) is left untouched. */
bool TrySkipContinuation(const std::string& lower, size_t* i) {
    if (*i >= lower.size() || lower[*i] != '`') return false;
    size_t j = *i + 1;
    if (j < lower.size() && lower[j] == '\r') ++j;
    if (j >= lower.size() || lower[j] != '\n') return false;
    ++j;
    while (j < lower.size() && (lower[j] == ' ' || lower[j] == '\t')) ++j;
    *i = j;
    return true;
}

/* The value span that follows the flag occurrence at `flagPos`, bounded
 * to `regionEnd` (the end of the owning grant cmdlet's region): starts
 * after the flag (skipping the colon binding, spaces, quotes and a
 * backtick line continuation), ends at the next parameter boundary (a
 * run of whitespace followed by '-'), a statement separator, the region
 * end or after 200 characters. Quoted list members are kept in the span
 * so `"FullAccess", "ExternalSharing"` stays one span. */
std::string FlagValueSpan(const std::string& lower, size_t flagPos,
                          size_t flagLen, size_t regionEnd) {
    size_t cur = flagPos + flagLen;
    if (cur < lower.size() && lower[cur] == ':') ++cur;
    /* Leading skip: colon binding, spaces/tabs, quotes. A backtick here
     * opens a line continuation whose newline + next-line indent are
     * soft whitespace (value not yet started), so keep skipping. */
    for (;;) {
        while (cur < lower.size() &&
               (lower[cur] == ' ' || lower[cur] == '\t' ||
                lower[cur] == '"' || lower[cur] == '\''))
            ++cur;
        if (!TrySkipContinuation(lower, &cur)) break;
    }
    const size_t start = cur;
    size_t i = cur;
    while (i < lower.size() && i < regionEnd && i - start < 200) {
        const char c = lower[i];
        /* Mid-value continuation: ` + newline + indent is soft. */
        if (c == '`' && TrySkipContinuation(lower, &i)) continue;
        if (c == ' ' || c == '\t') {
            size_t j = i;
            while (j < lower.size() &&
                   (lower[j] == ' ' || lower[j] == '\t'))
                ++j;
            /* A continuation after the run is soft whitespace too; only
             * a real "-Param" token terminates the value. */
            TrySkipContinuation(lower, &j);
            if (j < lower.size() && lower[j] == '-') break; /* next -Param */
            i = j;
            continue;
        }
        if (c == '\n' || c == '\r' || c == ';') break;
        ++i;
    }
    return lower.substr(start, i - start);
}

/* True when the region [regionBegin, regionEnd) owns a `flag` occurrence
 * (already lowered) whose value span contains `valueNeedle` (also
 * lowered). Flag occurrences are only searched inside the region, so the
 * value of a foreign statement's flag is never seen here. */
bool RegionHasFlagValue(const std::string& lower, size_t regionBegin,
                        size_t regionEnd, const char* flag,
                        const char* valueNeedle) {
    const std::string needle = flag;
    for (size_t pos = FindFlagPosFrom(lower, needle, regionBegin);
         pos != std::string::npos && pos < regionEnd;
         pos = FindFlagPosFrom(lower, needle, pos + 1)) {
        const std::string span =
            FlagValueSpan(lower, pos, needle.size(), regionEnd);
        if (span.find(valueNeedle) != std::string::npos) return true;
    }
    return false;
}

/* Presence-only variant for flags whose bare appearance inside the grant
 * cmdlet's region is the signal (-GrantSendOnBehalfTo). */
bool RegionHasFlag(const std::string& lower, size_t regionBegin,
                   size_t regionEnd, const char* flag) {
    const size_t pos = FindFlagPosFrom(lower, flag, regionBegin);
    return pos != std::string::npos && pos < regionEnd;
}

/* Walks every word-boundary occurrence of `cmdlet` and checks `flag` /
 * `valueNeedle` strictly inside each occurrence's own region
 * ([cmdlet pos, next mailbox-delegation cmdlet token)). Values are never
 * taken across statements: "Add-... -AccessRights ReadPermission" plus a
 * later "Remove-... -AccessRights FullAccess" stays silent, while the
 * mirror shape "Remove-... FullAccess ; Add-... FullAccess" still
 * matches because the Add region owns its own FullAccess value. */
bool AnyCmdletRegionHasFlagValue(const std::string& lower,
                                 const char* cmdlet, const char* flag,
                                 const char* valueNeedle) {
    for (size_t pos = FindCmdletFrom(lower, cmdlet, 0);
         pos != std::string::npos;
         pos = FindCmdletFrom(lower, cmdlet, pos + 1)) {
        const size_t regionEnd = NextCmdletBoundary(lower, pos + 1);
        if (RegionHasFlagValue(lower, pos, regionEnd, flag, valueNeedle))
            return true;
    }
    return false;
}

/* Same region walk for the presence-only flag shape. */
bool AnyCmdletRegionHasFlag(const std::string& lower, const char* cmdlet,
                            const char* flag) {
    for (size_t pos = FindCmdletFrom(lower, cmdlet, 0);
         pos != std::string::npos;
         pos = FindCmdletFrom(lower, cmdlet, pos + 1)) {
        const size_t regionEnd = NextCmdletBoundary(lower, pos + 1);
        if (RegionHasFlag(lower, pos, regionEnd, flag)) return true;
    }
    return false;
}

/* Best-effort extraction of the delegated mailbox identity: the token that
 * follows the first *valid* "-identity" occurrence (same acceptance rule as
 * HasFlag - handles "-Identity jdoe" and "-Identity:jdoe" and strips
 * quotes). The full needle is mandatory: a short "-id" needle would be fed
 * by any neighbouring "-Id <n>" parameter on the same command line.
 * Bounded to 120 characters. */
std::string ExtractTarget(const std::string& lower) {
    const std::string needle = "-identity";
    const size_t pos = FindFlagPos(lower, needle);
    if (pos == std::string::npos) return std::string();
    size_t cur = pos + needle.size();
    if (cur < lower.size() && lower[cur] == ':') ++cur;
    while (cur < lower.size() &&
           (lower[cur] == ' ' || lower[cur] == '\t' ||
            lower[cur] == '"' || lower[cur] == '\''))
        ++cur;
    std::string out;
    while (cur < lower.size() && out.size() < 120) {
        const char c = lower[cur];
        if (c == ' ' || c == '\t' || c == '"' || c == '\'' ||
            c == ';' || c == ',')
            break;
        out += c;
        ++cur;
    }
    return out;
}

} // namespace

MailboxDelegateDetector::MailboxDelegateDetector(bool enabled,
                                                 uint32_t minScore,
                                                 uint32_t dedupWindowSeconds,
                                                 size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool MailboxDelegateDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool MailboxDelegateDetector::Analyze(const std::string& lower,
                                      Finding* out) const {
    /* 85: full-access delegation. Checked first so a script that both
     * grants FullAccess and touches folder permissions reports the
     * highest tier. The flag/value check runs inside each grant cmdlet
     * occurrence's own region, so a later Remove-* statement's
     * -AccessRights value can never endorse the Add-* (values are never
     * taken across statement boundaries). */
    if (AnyCmdletRegionHasFlagValue(lower, "add-mailboxpermission",
                                    "-accessrights", "fullaccess") ||
        AnyCmdletRegionHasFlagValue(lower, "add-mailboxpermission",
                                    "-accessright", "fullaccess") ||
        AnyCmdletRegionHasFlagValue(lower, "add-adpermission",
                                    "-accessrights", "fullaccess") ||
        AnyCmdletRegionHasFlagValue(lower, "add-adpermission",
                                    "-accessright", "fullaccess")) {
        *out = Finding{85, "delegate_full_access_grant",
                       "add-mailboxpermission/add-adpermission",
                       ExtractTarget(lower)};
        return true;
    }
    /* 80: the right to speak as the victim. Add-RecipientPermission
     * -AccessRights SendAs, Set-Mailbox -GrantSendOnBehalfTo and
     * Add-ADPermission -ExtendedRights "Send-as"/"Send As" are one grant
     * semantic across three cmdlet surfaces (merged signal), each bound
     * to the owning grant cmdlet's region. */
    if (AnyCmdletRegionHasFlagValue(lower, "add-recipientpermission",
                                    "-accessrights", "sendas") ||
        AnyCmdletRegionHasFlagValue(lower, "add-adpermission",
                                    "-extendedrights", "send-as") ||
        AnyCmdletRegionHasFlagValue(lower, "add-adpermission",
                                    "-extendedrights", "send as") ||
        AnyCmdletRegionHasFlag(lower, "set-mailbox",
                               "-grantsendonbehalfto")) {
        *out = Finding{80, "delegate_send_as_grant",
                       "add-recipientpermission/set-mailbox/add-adpermission",
                       ExtractTarget(lower)};
        return true;
    }
    /* 65: folder-level delegation regardless of sub-parameters. */
    if (HasCmdlet(lower, "add-mailboxfolderpermission")) {
        *out = Finding{65, "delegate_folder_permission_grant",
                       "add-mailboxfolderpermission", ExtractTarget(lower)};
        return true;
    }
    /* Everything else (Get-* queries, Remove-* remediation, non-grant
     * -AccessRights values, bare Set-Mailbox) carries no grant semantics
     * and stays silent. */
    return false;
}

void MailboxDelegateDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kMailboxDelegateScore] = std::to_string(finding.score);
    /* House verdict contract: >=75 MALICIOUS, >=55 SUSPICIOUS; Analyze
     * never returns below 65 so the verdict field is always written. */
    event.fields[field::kMailboxDelegateVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kMailboxDelegateSignals] = finding.signal;
    event.fields[field::kMailboxDelegateCmdlets] = finding.cmdlet;
    if (!finding.target.empty())
        event.fields[field::kMailboxDelegateTargets] = finding.target;
}

void MailboxDelegateDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    if (event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script blocks carry the body in kScriptBlockText, never
         * kCommandLine/kImage (house contract). */
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    } else if (event.type == EDR_EVT_PROCESS_START) {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty()) {
            auto imgIt = event.fields.find(field::kImage);
            if (imgIt != event.fields.end()) text = imgIt->second;
        }
    } else {
        return;
    }
    if (text.empty()) return;

    const std::string lower = ToLowerAscii(text);
    Finding finding;
    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;
    if (finding.score < 55) return; /* sub-verdict: fully silent */

    const std::string key =
        std::string(finding.signal) + "|" + finding.target;
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
                "[edr-mailbox-delegate] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
