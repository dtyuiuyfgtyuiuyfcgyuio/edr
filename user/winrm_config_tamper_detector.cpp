/*
 * winrm_config_tamper_detector.cpp - WinRM configuration enablement /
 * trust-broadening detector (T1021.006 preparation plane).
 */
#include "winrm_config_tamper_detector.h"

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

/* Read-only WinRM inspection that must never score. */
bool IsWinrmInspectionOnly(const std::string& lower) {
    const bool winrmMention = Contains(lower, "winrm") ||
                              Contains(lower, "wsman");
    if (!winrmMention) return false;
    return (Contains(lower, "identify") ||
            Contains(lower, "get winrm/config") ||
            Contains(lower, "get wsman")) &&
           !Contains(lower, "set ") && !Contains(lower, "set-item") &&
           !Contains(lower, "quickconfig") &&
           !Contains(lower, "enable-psremoting") &&
           !Contains(lower, "@{");
}

} // namespace

WinrmConfigTamperDetector::WinrmConfigTamperDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool WinrmConfigTamperDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool WinrmConfigTamperDetector::Analyze(const std::string& lower,
                                        Finding* out) const {
    if (IsWinrmInspectionOnly(lower)) return false;

    /* TrustedHosts broadening: wildcard or explicit list. */
    const bool trustedHostsWrite =
        Contains(lower, "trustedhosts") &&
        (Contains(lower, "set-item") || Contains(lower, "set ") ||
         Contains(lower, "@{") || Contains(lower, "reg add"));
    if (trustedHostsWrite) {
        /* A wildcard trust entry accepts connections from any host -
         * the strongest lateral-movement preparation signal. */
        const size_t pos = lower.find("trustedhosts");
        const size_t tail = lower.find('"', pos);
        if ((tail != std::string::npos &&
             lower.find('*', tail) != std::string::npos) ||
            Contains(lower, "@{trustedhosts=\"*\"}") ||
            Contains(lower, "-value *")) {
            *out = Finding{85, "TrustedHosts set to wildcard"};
            return true;
        }
        *out = Finding{80, "TrustedHosts list modified"};
        return true;
    }

    if (Contains(lower, "enable-psremoting")) {
        *out = Finding{75, "PowerShell remoting force-enabled"};
        return true;
    }

    if (Contains(lower, "winrm") &&
        Contains(lower, "quickconfig")) {
        *out = Finding{65, "winrm quickconfig listener enablement"};
        return true;
    }

    return false;
}

void WinrmConfigTamperDetector::Stamp(Event& event,
                                      const Finding& finding,
                                      const std::string& key) {
    event.fields[field::kWinrmConfigTamperScore] =
        std::to_string(finding.score);
    event.fields[field::kWinrmConfigTamperVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kWinrmConfigTamperSignals] = finding.signal;
    event.fields[field::kWinrmConfigTamperText] = key;
}

void WinrmConfigTamperDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;

    /* Registry plane: direct writes to the TrustedHosts value. */
    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        std::string lowerKey = ToLowerAscii(keyIt->second);
        auto valIt = event.fields.find(field::kRegValue);
        if (valIt != event.fields.end()) {
            lowerKey += " " + ToLowerAscii(valIt->second);
        }
        if (lowerKey.find("trustedhosts") == std::string::npos)
            return;
        Finding finding;
        const bool wildcard =
            lowerKey.find("*") != std::string::npos;
        finding.score = wildcard ? 85u : 80u;
        finding.signal = wildcard
            ? "TrustedHosts registry value set to wildcard"
            : "TrustedHosts registry value modified";
        if (finding.score >= m_minScore)
            Stamp(event, finding, lowerKey.substr(0, 160));
        return;
    }

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
                "[edr-winrm-config] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
