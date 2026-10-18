/*
 * control_panel_proxy_detector.cpp - See control_panel_proxy_detector.h.
 */
#include "control_panel_proxy_detector.h"

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

/* Full token-bounded substring match: `needle` (already lowered) only
 * counts when BOTH edges sit on token boundaries:
 *   start - the match begins at position 0 or the character before it is
 *           not a letter/digit (delimiters accepted, same start rule as
 *           the previous HasWordStartBounded helper);
 *   tail  - the match runs to the end of the text or the next character
 *           is not a letter/digit/underscore.
 * The tail rejects letter/digit/underscore continuations
 * ("control.exed", "Control_RunDLL2", "Control_RunDLL_Legacy") while
 * accepting the delimiters that really follow the token: dot, space,
 * quote, path separators, hyphen, and end of string. Word-start-only
 * matching missed this tail family. The start edge is what keeps vendor
 * binaries whose name ends in the stem ("connectwisecontrol.exe",
 * "mycontrol.exe") silent - the rule this file's old helper already
 * had. Both edges share the semantics of the HasTokenBounded helpers in
 * llmnr_poison_detector / arp_poison_detector. */
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

/* Locations that mark a dropped payload rather than a system applet:
 * a UNC share, or a user-writable directory. A CPL resolved from a bare
 * applet name or from System32 is a normal Control Panel launch and
 * stays silent. */
const char* const kPayloadLocations[] = {
    "\\\\",                  /* UNC path */
    "\\appdata\\",
    "\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\desktop\\",
};

bool HasAnyLocation(const std::string& lower) {
    for (const char* location : kPayloadLocations) {
        if (Contains(lower, location)) return true;
    }
    return false;
}

} // namespace

ControlPanelProxyDetector::ControlPanelProxyDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool ControlPanelProxyDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool ControlPanelProxyDetector::AnalyzeCommandText(const std::string& lower,
                                                   Finding* out) const {
    /* Token bounded on both edges: "connectwisecontrol.exe" /
     * "mycontrol.exe" stay silent via the start edge (the rule this
     * file's old helper already had) and letter/digit/underscore-glued
     * lookalikes such as "control.exed" stay silent via the tail edge,
     * while `control.exe ...`, `"C:\...\control.exe"` and
     * `control.exed`-free full paths all keep matching (space, quote and
     * the ".exe" dot are accepted tails). */
    const bool controlExe = HasTokenBounded(lower, "control.exe");

    /* Tier 85: control.exe driving an INF - the Install section runs. */
    if (controlExe && Contains(lower, ".inf")) {
        *out = Finding{85, "control_inf_exec", ".inf"};
        return true;
    }

    /* Tier 80: control.exe loading a CPL (arbitrary DLL) that resolves
     * into a user-writable or remote location - a dropped payload, not a
     * system applet. `control.exe main.cpl` and
     * `control.exe C:\Windows\System32\*.cpl` stay silent. */
    if (controlExe && Contains(lower, ".cpl") && HasAnyLocation(lower)) {
        *out = Finding{80, "control_cpl_payload", ".cpl"};
        return true;
    }

    /* Tier 70: the rundll32 shell32.dll,Control_RunDLL <file>.cpl shape,
     * when control.exe itself is not named. Same payload-location rule as
     * the 80 tier, so `Control_RunDLL main.cpl` (a normal applet open)
     * stays silent. The stem is token bounded on both edges. The real
     * shell32 exports Control_RunDLLA / Control_RunDLLW are spelled out
     * as their own needles: the old word-start-only helper matched them
     * by accident (no tail check) and they are genuine exports, not fake
     * long words, so the new tail edge must not silently drop them -
     * non-export glue ("Control_RunDLL2", "Control_RunDLL_Legacy") stays
     * silent via that tail edge. */
    if ((HasTokenBounded(lower, "control_rundll") ||
         HasTokenBounded(lower, "control_rundlla") ||
         HasTokenBounded(lower, "control_rundllw")) &&
        Contains(lower, ".cpl") && HasAnyLocation(lower)) {
        *out = Finding{70, "control_rundll_cpl", ".cpl"};
        return true;
    }

    return false;
}

void ControlPanelProxyDetector::Stamp(Event& event,
                                      const Finding& finding) {
    event.fields[field::kControlPanelScore] = std::to_string(finding.score);
    event.fields[field::kControlPanelVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kControlPanelSignals] = finding.signal;
    if (!finding.indicator.empty())
        event.fields[field::kControlPanelFiles] = finding.indicator;
}

void ControlPanelProxyDetector::Enrich(Event& event) {
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
                "[edr-control-panel] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
