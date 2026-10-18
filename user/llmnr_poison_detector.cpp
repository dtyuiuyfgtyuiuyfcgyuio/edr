/*
 * llmnr_poison_detector.cpp - See llmnr_poison_detector.h.
 */
#include "llmnr_poison_detector.h"

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

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string BaseName(const std::string& path) {
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

/* Is this character part of a token core? Letters and digits glue a
 * needle into a lookalike word; underscore glues it into a scan/flag
 * style identifier ("mitm6_domain_scan"). */
bool IsTokenChar(unsigned char c) {
    return std::isalnum(c) != 0 || c == '_';
}

/* Full token-bounded substring match: `needle` (already lowered) only
 * counts when BOTH edges sit on token boundaries:
 *   start - the match begins at position 0 or the character before it is
 *           not a letter/digit (delimiters accepted, same start rule as
 *           the previous HasWordStartBounded helper);
 *   tail  - the match runs to the end of the text or the next character
 *           is not a letter/digit/underscore.
 * The tail rejects letter/digit/underscore continuations ("nbns_spoofed",
 * "nbns-poisoned", "mitm6_domain_scan") while accepting the delimiters
 * that really follow a tool token: dot (path and file suffixes
 * ".exe"/".py"/".psd1"), space, quote, path separators, hyphen, and end
 * of string. Word-start-only matching missed this tail family: the
 * "nbns_spoof" needle still fired on "nbns_spoofed". The tail edge also
 * makes flag needles exact: "responder -internet" no longer matches the
 * "responder -i" needle (deliberate - a longer fake flag is not the
 * tool's -i switch). The start edge is what keeps "limitm6xx.exe" away
 * from "mitm6" and vendor "DnsResponder.exe" away from "responder.exe"
 * - both EDR-486 high-band false positives of plain substring matching. */
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

} // namespace

LlmnrPoisonDetector::LlmnrPoisonDetector(bool enabled, uint32_t minScore,
                                         uint32_t dedupWindowSeconds,
                                         size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool LlmnrPoisonDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_NET_LISTENER;
}

bool LlmnrPoisonDetector::AnalyzeListener(const Event& event,
                                          Finding* out) const {
    /* A listener that disappears is history, not an active poisoner. */
    if (FieldValue(event, field::kListenerAction) != "added") return false;
    if (ToLowerAscii(FieldValue(event, field::kListenerProtocol)) != "udp")
        return false;

    const std::string port = FieldValue(event, field::kListenerPort);
    const char* signal = nullptr;
    uint32_t score = 0;
    if (port == "5355") {
        signal = "llmnr_udp_5355_listener";
        score = 85;
    } else if (port == "137") {
        signal = "nbns_udp_137_listener";
        score = 75;
    } else if (port == "5353") {
        signal = "mdns_udp_5353_listener";
        score = 65;
    } else {
        return false;
    }

    /* svchost.exe hosts the genuine LLMNR / NBNS / mDNS responders and
     * mDNSResponder.exe (Bonjour) legitimately owns UDP 5353 where it is
     * installed. An unresolvable owner (kListenerProcess missing) is
     * treated as non-whitelisted: better one reviewable alert than a
     * blind spot. */
    const std::string base =
        ToLowerAscii(BaseName(FieldValue(event, field::kListenerProcess)));
    if (base == "svchost.exe") return false;
    if (base == "mdnsresponder.exe" && port == "5353") return false;

    *out = Finding{score, signal, port, std::string()};
    return true;
}

bool LlmnrPoisonDetector::AnalyzeCommandText(const std::string& lower,
                                             Finding* out) const {
    /* mitm6 is exclusive to this detector (IPv6/DNS takeover). Token
     * bounded on both edges: "limitm6xx.exe" / "submitm6" embed the stem
     * mid-token (start edge) and "mitm6_domain_scan" glues an underscore
     * onto it (tail edge) - neither may fire the 80 tier. */
    if (HasTokenBounded(lower, "mitm6")) {
        *out = Finding{80, "poison_tool_mitm6", std::string(), "mitm6"};
        return true;
    }
    /* inveigh / responder also appear in forced_auth_detector (T1187,
     * score 85 for the coercion plane) - this 75 tier is deliberately
     * staggered so both rules can fire without colliding on a band. */
    if (HasTokenBounded(lower, "inveigh")) {
        *out = Finding{75, "poison_tool_inveigh", std::string(), "inveigh"};
        return true;
    }
    /* responder stems with a token boundary on both edges: the letter
     * before the stem in vendor names such as DnsResponder.exe keeps them
     * silent, while " responder.py" / "\responder.py" / "\"responder.exe\""
     * and "responder -i" still match (the ".py"/".exe" dots are accepted
     * tail delimiters). Bare "responder" (no .py/.exe/" -i") remains
     * silent, and the tail edge rejects longer fake flags:
     * "responder -internet" does not match the "responder -i" needle. */
    if (HasTokenBounded(lower, "responder.py") ||
        HasTokenBounded(lower, "responder.exe") ||
        HasTokenBounded(lower, "responder -i")) {
        *out = Finding{75, "poison_tool_responder", std::string(),
                       "responder"};
        return true;
    }
    /* All four spelling combinations of the nbns tool family: the spoof
     * and poison stems each in underscore and dash form, token bounded on
     * both edges (".\nbns-poison" keeps matching via the "." delimiter;
     * "nbns_spoofed" / "nbns-poisoned" glue a letter onto the stem and
     * stay silent via the tail edge). */
    if (HasTokenBounded(lower, "nbns_spoof") ||
        HasTokenBounded(lower, "nbns_poison") ||
        HasTokenBounded(lower, "nbns-spoof") ||
        HasTokenBounded(lower, "nbns-poison")) {
        *out = Finding{75, "poison_tool_nbns_spoof", std::string(),
                       "nbns_spoof"};
        return true;
    }
    return false;
}

void LlmnrPoisonDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kLlmnrPoisonScore] = std::to_string(finding.score);
    event.fields[field::kLlmnrPoisonVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kLlmnrPoisonSignals] = finding.signal;
    if (!finding.port.empty())
        event.fields[field::kLlmnrPoisonPorts] = finding.port;
    if (!finding.tool.empty())
        event.fields[field::kLlmnrPoisonTools] = finding.tool;
}

void LlmnrPoisonDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    if (event.type == EDR_EVT_NET_LISTENER) {
        if (!AnalyzeListener(event, &finding)) return;
    } else if (event.type == EDR_EVT_PROCESS_START ||
               event.type == EDR_EVT_POWERSHELL_SCRIPT) {
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
            if (imgIt != event.fields.end()) text = imgIt->second;
        }
        if (text.empty()) return;
        if (!AnalyzeCommandText(ToLowerAscii(text), &finding)) return;
    } else {
        return;
    }

    if (finding.score < m_minScore) return;
    if (finding.score < 55) return; /* sub-verdict: fully silent */

    /* Listener plane is state-type: the same protocol|port repeat inside
     * the window never re-alerts (same-key overwrite, no breadth growth);
     * a different port is a different key and passes. Command-plane keys
     * are per tool. */
    std::string key = finding.signal;
    if (!finding.port.empty()) key += "|" + finding.port;
    if (!finding.tool.empty()) key += "|" + finding.tool;
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
                "[edr-llmnr-poison] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
