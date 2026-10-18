/*
 * ticket_cache_abuse_detector.cpp - Pass-the-ticket / ticket cache
 * abuse detector (T1550.003).
 */
#include "ticket_cache_abuse_detector.h"

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

bool HasTicketFile(const std::string& lower) {
    return lower.find(".kirbi") != std::string::npos ||
           lower.find(".ccache") != std::string::npos ||
           lower.find("ticket.kirbi") != std::string::npos ||
           lower.find("ticket.ccache") != std::string::npos;
}

bool IsInspectionOnly(const std::string& lower) {
    return Contains(lower, "klist") && Contains(lower, "tickets") &&
           !Contains(lower, "purge") && !HasTicketFile(lower);
}

} // namespace

TicketCacheAbuseDetector::TicketCacheAbuseDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool TicketCacheAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool TicketCacheAbuseDetector::Analyze(const std::string& lower,
                                       Finding* out) const {
    if (Contains(lower, "kerberos::ptt") || Contains(lower, "rubeus ptt") ||
        Contains(lower, "pass-the-ticket") || Contains(lower, "pass the ticket")) {
        *out = Finding{90, "ticket injection tooling"};
        return true;
    }

    if (Contains(lower, "klist") && Contains(lower, "purge")) {
        *out = Finding{65, "ticket cache purge"};
        return true;
    }

    if (HasTicketFile(lower)) {
        const bool copyVerb = Contains(lower, "copy ") || Contains(lower, "xcopy") ||
                              Contains(lower, "move ") || Contains(lower, "type ");
        *out = Finding{copyVerb ? 75u : 70u,
                       copyVerb ? "ticket file copied" : "ticket file referenced"};
        return true;
    }

    if (Contains(lower, "krb5ccname")) {
        *out = Finding{60, "ticket cache environment hint"};
        return true;
    }

    return false;
}

void TicketCacheAbuseDetector::Stamp(Event& event, const Finding& finding,
                                     const std::string& key) {
    event.fields[field::kTicketCacheAbuseScore] = std::to_string(finding.score);
    event.fields[field::kTicketCacheAbuseVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kTicketCacheAbuseSignals] = finding.signal;
    event.fields[field::kTicketCacheAbuseCommand] = key;
}

void TicketCacheAbuseDetector::Enrich(Event& event) {
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
                "[edr-ticket-cache] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr