/*
 * mailbox_rule_detector.cpp - See mailbox_rule_detector.h.
 */
#include "mailbox_rule_detector.h"

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

/* First position where `needle` (already lowered, e.g. "-forwardto")
 * appears in a PowerShell call shape: followed by a space, colon-bound
 * argument, quote, separator or end of text. Returns npos when absent.
 * HasFlag and ExtractTarget share this acceptance rule so
 * "-ForwardToFolder" can never be mistaken for a "-ForwardTo" hit or
 * become the source of the extracted forwarding target. */
size_t FindFlagPos(const std::string& lower, const std::string& needle) {
    for (size_t pos = lower.find(needle); pos != std::string::npos;
         pos = lower.find(needle, pos + 1)) {
        const size_t end = pos + needle.size();
        if (end >= lower.size()) return pos;
        const char next = lower[end];
        if (next == ' ' || next == '\t' || next == ':' || next == '"' ||
            next == '\'' || next == ',' || next == ';')
            return pos;
    }
    return std::string::npos;
}

bool HasFlag(const std::string& lower, const std::string& needle) {
    return FindFlagPos(lower, needle) != std::string::npos;
}

bool HasAnyFlag(const std::string& lower, const char* const flags[],
                size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (HasFlag(lower, flags[i])) return true;
    }
    return false;
}

/* Best-effort extraction of the forwarding destination: the token that
 * follows the first *valid* flag occurrence (same acceptance rule as
 * HasFlag - handles "-ForwardTo a@b" and "-ForwardTo:a@b" and strips
 * quotes). Scanning only valid occurrences keeps "-ForwardToFolder" from
 * being read as the value source of "-ForwardTo". Bounded to 120
 * characters. */
std::string ExtractTarget(const std::string& lower,
                          const char* const flags[], size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const std::string needle = flags[i];
        const size_t pos = FindFlagPos(lower, needle);
        if (pos == std::string::npos) continue;
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
        if (!out.empty()) return out;
    }
    return std::string();
}

const char* const kInboxRuleForwardParams[] = {
    "-forwardto", "-redirectto", "-forwardasattachmentto",
};
const char* const kMailboxForwardParams[] = {
    "-forwardingsmtpaddress", "-forwardingaddress",
    "-delivertomailboxandforward",
};

} // namespace

MailboxRuleDetector::MailboxRuleDetector(bool enabled, uint32_t minScore,
                                         uint32_t dedupWindowSeconds,
                                         size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool MailboxRuleDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool MailboxRuleDetector::Analyze(const std::string& lower,
                                  bool fromCommandLine, Finding* out) const {
    if (Contains(lower, "new-inboxrule") || Contains(lower, "set-inboxrule")) {
        if (HasAnyFlag(lower, kInboxRuleForwardParams, 3)) {
            *out = Finding{90, "inbox_rule_external_forward",
                           "new-inboxrule/set-inboxrule",
                           ExtractTarget(lower, kInboxRuleForwardParams, 3)};
            return true;
        }
        /* Full script blocks without forwarding parameters are routine
         * admin tooling (viewing / renaming rules); only the raw command
         * line gets the low-confidence middle tier. */
        if (fromCommandLine) {
            *out = Finding{60, "inbox_rule_cmdlet_command_line",
                           "new-inboxrule/set-inboxrule", std::string()};
            return true;
        }
        return false;
    }
    if (Contains(lower, "set-mailbox")) {
        if (HasAnyFlag(lower, kMailboxForwardParams, 3)) {
            *out = Finding{85, "mailbox_smtp_forward", "set-mailbox",
                           ExtractTarget(lower, kMailboxForwardParams, 3)};
            return true;
        }
        return false;
    }
    return false;
}

void MailboxRuleDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kMailboxRuleScore] = std::to_string(finding.score);
    /* House verdict contract: >=75 MALICIOUS, >=55 SUSPICIOUS; Analyze
     * never returns below 55 so the verdict field is always written. */
    event.fields[field::kMailboxRuleVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kMailboxRuleSignals] = finding.signal;
    event.fields[field::kMailboxRuleCmdlets] = finding.cmdlet;
    if (!finding.target.empty())
        event.fields[field::kMailboxRuleTargets] = finding.target;
}

void MailboxRuleDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    bool fromCommandLine = false;
    std::string text;
    if (event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script blocks carry the body in kScriptBlockText, never
         * kCommandLine/kImage (house contract). */
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    } else if (event.type == EDR_EVT_PROCESS_START) {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) {
            text = cmdIt->second;
            fromCommandLine = true;
        }
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
    if (!Analyze(lower, fromCommandLine, &finding)) return;
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
                "[edr-mailbox-rule] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
