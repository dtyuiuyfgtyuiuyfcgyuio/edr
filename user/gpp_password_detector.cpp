/*
 * gpp_password_detector.cpp - See gpp_password_detector.h.
 */
#include "gpp_password_detector.h"

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
 * needle into a lookalike word; underscore glues it into a
 * property/identifier style name ("cpassword_dump"). */
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
 * The tail rejects letter/digit/underscore continuations ("cpassworded",
 * "cpassword_dump") while accepting the delimiters that really follow
 * the token: dot (file suffixes "cpassword.log"), space, quote, path
 * separators, hyphen, and end of string. Word-start-only matching
 * missed this tail family: the "cpassword" needle still fired on
 * "cpassworded". The start edge is what keeps "encpassword" /
 * "mypassword" away from the "cpassword" stem - the rule this file's
 * old helper already had. Both edges share the semantics of the
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

bool HasAnyTokenBounded(const std::string& lower,
                        const char* const needles[], size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (HasTokenBounded(lower, needles[i])) return true;
    }
    return false;
}

/* Ready-made GPP extraction cmdlets (PowerView / PowerSploit lineage). */
const char* const kGppTools[] = {
    "get-gpppassword",
    "get-gppautologon",
    "get-gppdomainpassword",
    "get-gppcachedpassword",
    "get-cachedgpppassword",
};

/* Standalone GPP decryptors. */
const char* const kDecryptTools[] = {
    "gpp-decrypt",
    "gpprefdecrypt",
};

/* Search verbs used to hunt `cpassword` across SYSVOL by hand. */
const char* const kSearchVerbs[] = {
    "findstr",
    "select-string",
    "grep",
    "find",
    "type",
};

/* The GPP XML files that can carry an embedded cpassword. */
const char* const kGppXmlFiles[] = {
    "groups.xml",
    "services.xml",
    "scheduledtasks.xml",
    "printers.xml",
    "drives.xml",
    "datasources.xml",
    "registry.xml",
};

} // namespace

GppPasswordDetector::GppPasswordDetector(bool enabled, uint32_t minScore,
                                         uint32_t dedupWindowSeconds,
                                         size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool GppPasswordDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool GppPasswordDetector::AnalyzeCommandText(const std::string& lower,
                                             Finding* out) const {
    /* Tier 90: one cmdlet enumerates SYSVOL and prints the decrypted
     * passwords. */
    for (const char* tool : kGppTools) {
        if (Contains(lower, tool)) {
            *out = Finding{90, "gpp_password_tool", tool};
            return true;
        }
    }

    /* Tier 85: standalone GPP decryptor. */
    for (const char* tool : kDecryptTools) {
        if (Contains(lower, tool)) {
            *out = Finding{85, "gpp_decrypt_tool", tool};
            return true;
        }
    }

    /* Tier 80: manual hunt - a cpassword token plus a search verb. Both
     * needle families are token bounded on both edges: "cpassworded" /
     * "cpassword_dump" stay silent via the tail edge, and the "find"
     * verb no longer fires inside "findstr" (that token is its own
     * needle in kSearchVerbs). */
    if (HasTokenBounded(lower, "cpassword") &&
        HasAnyTokenBounded(lower, kSearchVerbs,
                           sizeof(kSearchVerbs) /
                               sizeof(kSearchVerbs[0]))) {
        *out = Finding{80, "cpassword_search", "cpassword"};
        return true;
    }

    /* Tier 75: reading a GPP XML out of SYSVOL. */
    if (Contains(lower, "sysvol")) {
        for (const char* file : kGppXmlFiles) {
            if (Contains(lower, file)) {
                *out = Finding{75, "gpp_xml_access", file};
                return true;
            }
        }
    }

    /* Tier 65: a bare cpassword token (parser without a named tool).
     * Token bounded on both edges: ".cpassword" property accessors,
     * "cpassword " and "cpassword\..." keep matching, while
     * "cpassworded" / "cpassword_dump" stay silent via the tail edge. */
    if (HasTokenBounded(lower, "cpassword")) {
        *out = Finding{65, "cpassword_reference", "cpassword"};
        return true;
    }

    return false;
}

void GppPasswordDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kGppPasswordScore] = std::to_string(finding.score);
    event.fields[field::kGppPasswordVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kGppPasswordSignals] = finding.signal;
    if (!finding.indicator.empty())
        event.fields[field::kGppPasswordTools] = finding.indicator;
}

void GppPasswordDetector::Enrich(Event& event) {
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
                "[edr-gpp-password] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
