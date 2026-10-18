/*
 * ps_profile_detector.cpp - See ps_profile_detector.h (T1546.013).
 */
#include "ps_profile_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {
namespace {

bool Contains(const std::string& v, const char* n) {
    return v.find(n) != std::string::npos;
}

std::string ToLower(const std::string& t) {
    std::string o = t;
    std::transform(o.begin(), o.end(), o.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return o;
}

/* $PROFILE / $profile.ps1 / $PROFILE.CurrentUserAllHosts, but not
 * $profileFoo (word boundary immediately after the variable name). */
bool HasProfileVariable(const std::string& l) {
    const char kNeedle[] = "$profile";
    const size_t kNeedleLen = sizeof(kNeedle) - 1;
    size_t pos = 0;
    while ((pos = l.find(kNeedle, pos)) != std::string::npos) {
        size_t next = pos + kNeedleLen;
        if (next >= l.size()) return true;
        char c = l[next];
        if (!(std::isalnum((unsigned char)c) || c == '_')) return true;
        pos = next;
    }
    return false;
}

bool HasProfileReference(const std::string& l) {
    return HasProfileVariable(l) || Contains(l, "profile.ps1");
}

bool HasWriteVerb(const std::string& l) {
    static const char* kVerbs[] = {
        "set-content", "add-content", "out-file", "new-item",
        "copy-item", "move-item", "export-", "set-itemproperty",
        "-outfile",
    };
    for (const char* verb : kVerbs)
        if (Contains(l, verb)) return true;
    /* Redirect into the profile: '> $profile' / '>> $profile' / '> $profile'
     * without spaces. PowerShell comparison is -gt, so '>' here is a
     * redirection when a profile reference is present. */
    return Contains(l, ">") && HasProfileVariable(l);
}

bool HasPayloadMarker(const std::string& l) {
    static const char* kMarkers[] = {
        "http://", "https://", "downloadstring", "webclient",
        "invoke-webrequest", "invoke-restmethod", "iwr ", "curl ",
        "wget ", "certutil", "bitsadmin", "start-bitstransfer",
        "-enc", "encodedcommand", "invoke-expression", "iex(", "iex ",
    };
    for (const char* marker : kMarkers)
        if (Contains(l, marker)) return true;
    return false;
}

bool IsAllUsersScope(const std::string& l) {
    return Contains(l, "$pshome") ||
           Contains(l, "program files\\windowspowershell") ||
           Contains(l, "program files\\powershell") ||
           Contains(l, "allusers");
}

} // namespace

PsProfileDetector::PsProfileDetector(bool e, uint32_t min, uint32_t dedup,
                                     size_t cap)
    : m_enabled(e),
      m_minScore(min),
      m_dedupWindow100ns((uint64_t)dedup * kFiletimeTicksPerSecond),
      m_stateCapacity(cap) {}

bool PsProfileDetector::Inspects(uint16_t t) {
    return t == EDR_EVT_PROCESS_START || t == EDR_EVT_POWERSHELL_SCRIPT ||
           t == EDR_EVT_FILE_CREATE || t == EDR_EVT_FILE_RENAME;
}

bool PsProfileDetector::AnalyzeText(const std::string& lower,
                                    Finding* out) const {
    /* Help topic text mentions profiles without touching them. */
    if (Contains(lower, "about_profiles")) return false;
    if (!HasProfileReference(lower)) return false;
    const bool write = HasWriteVerb(lower);
    const bool payload = HasPayloadMarker(lower);
    if (write && payload) {
        *out = {95, "payload staged into PowerShell profile"};
        return true;
    }
    if (write && IsAllUsersScope(lower)) {
        *out = {90, "AllUsers PowerShell profile write"};
        return true;
    }
    if (write) {
        *out = {85, "PowerShell profile write"};
        return true;
    }
    if (payload) {
        *out = {60, "PowerShell profile referenced with payload marker"};
        return true;
    }
    /* Read-only references (Get-Content / Test-Path / notepad / ise /
     * dot-sourcing execution) are normal interpreter usage and stay silent. */
    return false;
}

bool PsProfileDetector::AnalyzeFile(const std::string& lowerPath,
                                    Finding* out) const {
    /* Profile file naming covers profile.ps1 and the per-host variants
     * (Microsoft.PowerShell_profile.ps1, Microsoft.PowerShellISE_profile.ps1,
     * Microsoft.VSCode_profile.ps1). */
    const char kSuffix[] = "profile.ps1";
    const size_t kSuffixLen = sizeof(kSuffix) - 1;
    if (lowerPath.size() < kSuffixLen) return false;
    if (lowerPath.compare(lowerPath.size() - kSuffixLen, kSuffixLen,
                          kSuffix) != 0)
        return false;
    if (Contains(lowerPath, "program files")) {
        *out = {90, "AllUsers PowerShell profile file placed"};
        return true;
    }
    if (Contains(lowerPath, "\\windowspowershell\\") ||
        Contains(lowerPath, "\\powershell\\7\\")) {
        *out = {85, "PowerShell profile file placed"};
        return true;
    }
    /* Profile-named file created outside a profile directory: staging ahead
     * of a move (Temp / Downloads / UNC shares). */
    *out = {75, "PowerShell profile file staged outside profile directory"};
    return true;
}

void PsProfileDetector::Stamp(Event& ev, const Finding& f,
                              const std::string& key) {
    ev.fields[field::kPsProfileScore] = std::to_string(f.score);
    ev.fields[field::kPsProfileVerdict] =
        f.score >= 75 ? "malicious" : "suspicious";
    ev.fields[field::kPsProfileSignals] = f.signal;
    ev.fields[field::kPsProfileText] = key;
}

void PsProfileDetector::Enrich(Event& ev) {
    if (!m_enabled) return;
    Finding f;
    std::string key;
    if (ev.type == EDR_EVT_FILE_CREATE || ev.type == EDR_EVT_FILE_RENAME) {
        auto it = ev.fields.find(field::kFilePath);
        if (it == ev.fields.end() || it->second.empty()) return;
        std::string lower = ToLower(it->second);
        if (!AnalyzeFile(lower, &f)) return;
        key = lower.substr(0, 160);
    } else {
        std::string text;
        auto it = ev.fields.find(field::kCommandLine);
        if (it != ev.fields.end()) text = it->second;
        /* House contract: the PS script body lives ONLY in kScriptBlockText
         * for PS_SCRIPT events, never in kCommandLine/kImage. */
        if (text.empty() && ev.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto s = ev.fields.find(field::kScriptBlockText);
            if (s != ev.fields.end()) text = s->second;
        }
        if (text.empty()) {
            auto img = ev.fields.find(field::kImage);
            if (img != ev.fields.end()) text = img->second;
        }
        if (text.empty()) return;
        std::string lower = ToLower(text);
        if (!AnalyzeText(lower, &f)) return;
        key = lower.substr(0, 160);
    }
    if (f.score < m_minScore) return;
    uint64_t now = ev.ts100ns;
    auto dit = m_lastAlert.find(key);
    if (dit != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= dit->second &&
            now - dit->second < m_dedupWindow100ns)
            return;
        dit->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                         "[edr-ps-profile] state capacity %zu reached; "
                         "dedup reset\n",
                         m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }
    Stamp(ev, f, key);
}

} // namespace edr
