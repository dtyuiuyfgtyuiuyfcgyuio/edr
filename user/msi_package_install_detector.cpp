/*
 * msi_package_install_detector.cpp - See msi_package_install_detector.h.
 */
#include "msi_package_install_detector.h"

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
 * The tail rejects letter/digit/underscore continuations ("msiexecd",
 * "msiexec_silent") while accepting the delimiters that really follow
 * the binary token: dot (the "msiexec.exe" suffix), space, quote, path
 * separators, hyphen, and end of string. Word-start-only matching
 * missed this tail family. The start edge is what keeps "xmsiexec.exe"
 * from matching the "msiexec" stem while `cmd /c msiexec ...` and
 * `"C:\...\msiexec.exe"` do match - the rule this file's old helper
 * already had. Both edges share the semantics of the HasTokenBounded
 * helpers in llmnr_poison_detector / arp_poison_detector. */
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

/* Install verbs that make msiexec run a package's custom actions. The
 * leading space keeps "/i" from matching inside a path or a URL path
 * segment; the quoted forms cover the common PowerShell shape
 * `Start-Process msiexec -ArgumentList '/i','<url>'`. */
const char* const kInstallVerbs[] = {
    " /i",
    " '/i",
    " \"/i",
    " /package",
    " /a ",
};

/* Remote sources: the package is fetched from attacker infrastructure. */
const char* const kRemoteSources[] = {
    "http://",
    "https://",
    "ftp://",
    "\\\\",
};

/* User-writable locations: the package was dropped, not deployed. */
const char* const kStagedLocations[] = {
    "\\appdata\\",
    "\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\desktop\\",
};

bool HasAny(const std::string& lower, const char* const needles[],
            size_t count, const char** matched) {
    for (size_t i = 0; i < count; ++i) {
        if (Contains(lower, needles[i])) {
            if (matched != nullptr) *matched = needles[i];
            return true;
        }
    }
    return false;
}

/* The `.msi` / `.msp` token in the text, for dedup granularity. */
std::string ExtractPackage(const std::string& lower) {
    const size_t pos = lower.find(".msi");
    if (pos == std::string::npos) return std::string();
    size_t start = pos;
    while (start > 0 && lower[start - 1] != ' ' && lower[start - 1] != '"' &&
           lower[start - 1] != '\'')
        --start;
    size_t end = pos + 4;
    while (end < lower.size() && lower[end] != ' ' && lower[end] != '"' &&
           lower[end] != '\'')
        ++end;
    return lower.substr(start, end - start);
}

} // namespace

MsiPackageInstallDetector::MsiPackageInstallDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool MsiPackageInstallDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool MsiPackageInstallDetector::AnalyzeCommandText(
        const std::string& lower, Finding* out) const {
    /* Token bounded on both edges: "xmsiexec.exe" stays silent via the
     * start edge (the rule this file's old helper already had) and
     * letter/underscore-glued lookalikes such as "msiexecd" /
     * "msiexec_silent" stay silent via the tail edge, while
     * `msiexec ...`, `msiexec.exe ...` and `"C:\...\msiexec.exe"` all
     * keep matching (space and the ".exe" dot are accepted tails). */
    if (!HasTokenBounded(lower, "msiexec")) return false;

    /* Only an install verb makes msiexec execute a package. */
    if (!HasAny(lower, kInstallVerbs,
                sizeof(kInstallVerbs) / sizeof(kInstallVerbs[0]), nullptr))
        return false;

    const std::string package = ExtractPackage(lower);

    /* Tier 85: package fetched from a URL or UNC share. */
    const char* source = nullptr;
    if (HasAny(lower, kRemoteSources,
               sizeof(kRemoteSources) / sizeof(kRemoteSources[0]),
               &source)) {
        *out = Finding{85, "msi_remote_install", package, source};
        return true;
    }

    /* Tier 70: package staged in a user-writable location. */
    if (HasAny(lower, kStagedLocations,
               sizeof(kStagedLocations) / sizeof(kStagedLocations[0]),
               &source)) {
        *out = Finding{70, "msi_staged_install", package, source};
        return true;
    }

    /* Program Files / system paths are normal deployments: silent. */
    return false;
}

void MsiPackageInstallDetector::Stamp(Event& event,
                                      const Finding& finding) {
    event.fields[field::kMsiPackageScore] = std::to_string(finding.score);
    event.fields[field::kMsiPackageVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kMsiPackageSignals] = finding.signal;
    if (!finding.package.empty())
        event.fields[field::kMsiPackageFiles] = finding.package;
    if (!finding.source.empty())
        event.fields[field::kMsiPackageSources] = finding.source;
}

void MsiPackageInstallDetector::Enrich(Event& event) {
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

    std::string key = finding.signal;
    key += "|";
    key += finding.package;
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
                "[edr-msi-install] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
