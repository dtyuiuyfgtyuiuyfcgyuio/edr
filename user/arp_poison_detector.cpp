/*
 * arp_poison_detector.cpp - See arp_poison_detector.h.
 */
#include "arp_poison_detector.h"

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

/* Is this character part of a token core? Letters and digits glue a
 * needle into a lookalike word; underscore glues it into a scan/flag
 * style identifier. */
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
 * The tail rejects letter/digit/underscore continuations ("arpspoofing",
 * "ettercapped", "bettercapped", "arp -fl"/"arp -file" after the flag
 * letter) while accepting the delimiters that really follow a tool token:
 * dot (path and file suffixes ".exe"/".py"), space, quote, path
 * separators, hyphen, and end of string. The start edge is what keeps
 * "xettercap"/"myarpspoof" silent and the "ettercap" needle from firing
 * inside "bettercap" - the same letter-prefix false-positive family as
 * the mitm6/responder lesson in llmnr_poison_detector.cpp. Both files
 * share this helper's semantics. */
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

ArpPoisonDetector::ArpPoisonDetector(bool enabled, uint32_t minScore,
                                     uint32_t dedupWindowSeconds,
                                     size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool ArpPoisonDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool ArpPoisonDetector::AnalyzeCommandText(const std::string& lower,
                                           Finding* out) const {
    /* Tier 80: dedicated ARP poisoner binaries. Token bounded on both
     * edges, so ".exe"/".py" suffixed shapes and any path-separator,
     * quote or whitespace prefix all match while letter-glued lookalikes
     * ("xettercap", "myarpspoof", vendor "DnsCap") stay silent via the
     * start edge and letter-continued words ("ettercapped",
     * "bettercapped", "arpspoofing") stay silent via the tail edge. */
    if (HasTokenBounded(lower, "ettercap")) {
        *out = Finding{80, "arp_poison_tool", "ettercap"};
        return true;
    }
    /* "bettercap" must be checked as its own needle: the "ettercap" stem
     * sits mid-token in it and the start-edge guard above already kept
     * that inner occurrence from matching, so attribution stays
     * "bettercap". */
    if (HasTokenBounded(lower, "bettercap")) {
        *out = Finding{80, "arp_poison_tool", "bettercap"};
        return true;
    }
    if (HasTokenBounded(lower, "arpspoof")) {
        *out = Finding{80, "arp_poison_tool", "arpspoof"};
        return true;
    }

    /* Tier 75: static ARP table load (arp -f [file]), the standard
     * poisoning pre-positioning move. The text is lowered before this
     * point, so "arp -F" / "ARP.EXE -F" collapse into the "-f" needles.
     * Three shapes cover the realistic invocations: bare `arp -f`,
     * full-path `arp.exe -f` and a quoted image path with the flag
     * OUTSIDE the quotes (`"C:\...\arp.exe" -f`) where a quote sits
     * between the binary and the flag. Both token edges gate every
     * needle: letter-glued prefixes ("sharp.exe -f", "arpfile") fail the
     * start edge, and letter-continued flags ("arp -fl", "arp -file")
     * fail the tail edge - the flag token must end right after the "f". */
    if (HasTokenBounded(lower, "arp -f") ||
        HasTokenBounded(lower, "arp.exe -f") ||
        HasTokenBounded(lower, "arp.exe\" -f")) {
        *out = Finding{75, "arp_static_table_load", std::string()};
        return true;
    }
    return false;
}

void ArpPoisonDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kArpPoisonScore] = std::to_string(finding.score);
    event.fields[field::kArpPoisonVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kArpPoisonSignals] = finding.signal;
    if (!finding.tool.empty())
        event.fields[field::kArpPoisonTools] = finding.tool;
}

void ArpPoisonDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    if (event.type == EDR_EVT_PROCESS_START ||
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

    /* Dedup key: signal|tool for the tool tier (a different tool is a
     * different key and passes); plain signal for the static-load tier,
     * so every arp -f/-F/.exe/quoted spelling shares one key. */
    std::string key = finding.signal;
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
                "[edr-arp-poison] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
