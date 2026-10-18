/*
 * secboot_tamper_detector.cpp - Security-boot stack tampering
 * (VBS / HVCI / Credential Guard disable; T1562.001).
 */
#include "secboot_tamper_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

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

/* Extract the last backslash-separated path component. */
std::string LastComponent(const std::string& path) {
    const size_t pos = path.find_last_of('\\');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

/* Explicit nonzero registry data means hardening, not tampering. */
bool IsZeroishData(const std::string& data) {
    std::string lower = ToLowerAscii(data);
    /* trim */
    while (!lower.empty() && (lower.front() == ' ' || lower.front() == '\t'))
        lower.erase(lower.begin());
    while (!lower.empty() && (lower.back() == ' ' || lower.back() == '\t'))
        lower.pop_back();
    if (lower.empty()) return true;             /* no data carried */
    if (lower == "0" || lower == "0x0" ||
        lower == "(0)" || lower == "dword:00000000")
        return true;
    if (lower.rfind("0x", 0) == 0 &&
        lower.find_first_not_of("0", 2) == std::string::npos)
        return true;
    if (lower.rfind("dword:", 0) == 0 &&
        lower.find_first_not_of("0", 6) == std::string::npos)
        return true;
    return false;
}

} // namespace

SecbootTamperDetector::SecbootTamperDetector(bool enabled,
                                             uint32_t minScore,
                                             uint32_t dedupWindowSeconds,
                                             size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool SecbootTamperDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool SecbootTamperDetector::AnalyzeText(const std::string& lower,
                                        Finding* out) const {
    /* reg add ... /v <name> ... /d 0 : the guarded value name must be
     * present and an explicit zero-data flag nearby. Without /d 0 the
     * command-plane write is still scored at 75 (value name alone is a
     * deliberate weakening on these keys). */
    static const char* const kValueNames[] = {
        "enablevirtualizationbasedsecurity",
        "hypervisorenforcedcodeintegrity",
        "lsacfgflags",
        "requireplatformsecurityfeatures"
    };
    const bool writePlane =
        Contains(lower, "reg add") ||
        Contains(lower, "set-itemproperty") ||
        Contains(lower, "new-itemproperty");
    for (const char* name : kValueNames) {
        if (!writePlane) break;
        if (!Contains(lower, name)) continue;
        *out = Finding{Contains(lower, "/d 0") ||
                           Contains(lower, "0')") || Contains(lower, "\"0\"")
                           ? 80u : 75u,
                       "security-boot policy write via command plane"};
        return true;
    }

    /* PowerShell property assignment shape:
     * Set-ItemProperty -Name EnableVirtualizationBasedSecurity -Value 0
     * or $p.EnableVirtualizationBasedSecurity = 0 . The bare value-name
     * hit above already covers both; nothing extra here. */
    return false;
}

bool SecbootTamperDetector::AnalyzeRegistry(const Event& event,
                                            Finding* out) const {
    auto keyIt = event.fields.find(field::kRegKey);
    auto valIt = event.fields.find(field::kRegValue);
    if (keyIt == event.fields.end() && valIt == event.fields.end())
        return false;

    const std::string regKey =
        keyIt != event.fields.end() ? ToLowerAscii(keyIt->second) : "";
    const std::string regValue =
        valIt != event.fields.end() ? ToLowerAscii(valIt->second) : "";

    /* Candidate value names: match against kRegValue itself AND the
     * last path component of kRegKey (snapshot shape puts the value
     * name in the key path). */
    struct Spec {
        const char* name;
        uint32_t score;
        const char* signal;
    };
    static const Spec kSpecs[] = {
        {"hypervisorenforcedcodeintegrity", 85, "HVCI disabled via registry"},
        {"enablevirtualizationbasedsecurity", 85, "VBS disabled via registry"},
        {"lsacfgflags", 80, "Credential Guard disabled via registry"},
        {"requireplatformsecurityfeatures", 75,
         "VBS platform requirement weakened via registry"},
    };
    for (const Spec& spec : kSpecs) {
        const bool inValue = regValue.find(spec.name) != std::string::npos;
        const bool inKeyPath =
            !regKey.empty() &&
            LastComponent(regKey).find(spec.name) != std::string::npos;
        if (!inValue && !inKeyPath) continue;

        /* Snapshot shapes carry the written data in kRegValue; when the
         * matched text came from there and holds explicit nonzero data,
         * this is hardening - skip. When it came from kRegKey's last
         * component, kRegValue is the data: check it directly. */
        if (inKeyPath && !regValue.empty() && !IsZeroishData(regValue))
            continue;

        *out = Finding{spec.score, spec.signal};
        return true;
    }
    return false;
}

void SecbootTamperDetector::Stamp(Event& event, const Finding& finding,
                                  const std::string& key) {
    event.fields[field::kSecbootTamperScore] =
        std::to_string(finding.score);
    event.fields[field::kSecbootTamperVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kSecbootTamperSignals] = finding.signal;
    event.fields[field::kSecbootTamperCommand] = key;
}

void SecbootTamperDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    if (event.type == EDR_EVT_REG_WRITE) {
        Finding finding;
        if (!AnalyzeRegistry(event, &finding)) return;
        if (finding.score < m_minScore) return;

        const std::string key =
            (event.fields.count(field::kRegKey)
                 ? event.fields.at(field::kRegKey)
                 : std::string()) +
            "|" +
            (event.fields.count(field::kRegValue)
                 ? event.fields.at(field::kRegValue)
                 : std::string());
        const std::string dedupKey = ToLowerAscii(key).substr(0, 160);

        const uint64_t now = event.ts100ns;
        auto it = m_lastAlert.find(dedupKey);
        if (it != m_lastAlert.end()) {
            if (m_dedupWindow100ns != 0 && now >= it->second &&
                now - it->second < m_dedupWindow100ns)
                return;
            it->second = now;
        } else {
            if (m_stateCapacity > 0 &&
                m_lastAlert.size() >= m_stateCapacity) {
                m_lastAlert.clear();
                std::fprintf(stderr,
                    "[edr-secboot] state capacity %zu reached; "
                    "dedup reset\n", m_stateCapacity);
            }
            m_lastAlert.emplace(dedupKey, now);
        }
        Stamp(event, finding, dedupKey);
        return;
    }

    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script blocks carry the body in kScriptBlockText, never
         * kCommandLine/kImage. */
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
    if (!AnalyzeText(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    /* Dedup per normalized command prefix. */
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
                "[edr-secboot] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }
    Stamp(event, finding, key);
}

} // namespace edr
