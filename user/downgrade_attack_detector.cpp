/*
 * downgrade_attack_detector.cpp - See downgrade_attack_detector.h
 * (T1562.010).
 */
#include "downgrade_attack_detector.h"

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

/* True when a PowerShell host is named anywhere in the text; the version
 * switch alone is ambiguous (many tools take -v for verbosity). */
bool MentionsPowerShell(const std::string& lower) {
    return Contains(lower, "powershell") || Contains(lower, "pwsh");
}

/* Matches a PowerShell -Version 2 downgrade in its accepted spellings:
 * -version 2, -vers 2, -v 2, and the -version:2 colon form. Any 2.x
 * value counts; 3+ is not a logging downgrade. */
bool HasPowerShellV2Switch(const std::string& lower) {
    static const char* kPrefixes[] = {
        "-version", "-versio", "-versi", "-vers", "-ver", "-ve", "-v",
    };
    for (const char* prefix : kPrefixes) {
        size_t pos = 0;
        const size_t prefixLen = std::string(prefix).size();
        while ((pos = lower.find(prefix, pos)) != std::string::npos) {
            size_t i = pos + prefixLen;
            /* Reject a longer switch name that merely starts with this
             * prefix (e.g. -verbose when probing -ver). */
            if (i < lower.size() &&
                std::isalpha(static_cast<unsigned char>(lower[i]))) {
                ++pos;
                continue;
            }
            while (i < lower.size() &&
                   (lower[i] == ' ' || lower[i] == ':' || lower[i] == '='))
                ++i;
            if (i < lower.size() && lower[i] == '2') {
                /* 2 or 2.0, but not 20 / 2019. */
                const size_t after = i + 1;
                if (after >= lower.size() ||
                    !std::isdigit(static_cast<unsigned char>(lower[after])))
                    return true;
            }
            ++pos;
        }
    }
    return false;
}

bool IsReadOnlyQuery(const std::string& lower) {
    const bool reads = Contains(lower, "reg query") ||
                       Contains(lower, "get-smbserverconfiguration") ||
                       Contains(lower, "get-itemproperty") ||
                       Contains(lower, "get-windowsoptionalfeature");
    if (!reads) return false;
    return !Contains(lower, "reg add") && !Contains(lower, "set-") &&
           !Contains(lower, "enable-") && !Contains(lower, "new-item");
}

} // namespace

DowngradeAttackDetector::DowngradeAttackDetector(bool enabled,
                                                 uint32_t minScore,
                                                 uint32_t dedupWindowSeconds,
                                                 size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool DowngradeAttackDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool DowngradeAttackDetector::Analyze(const std::string& lower,
                                      Finding* out) const {
    if (IsReadOnlyQuery(lower)) return false;

    /* PowerShell 2.0 downgrade: the v2 engine predates ScriptBlock
     * logging and AMSI, so this is the canonical logging bypass. */
    if (MentionsPowerShell(lower) && HasPowerShellV2Switch(lower)) {
        *out = Finding{90, "PowerShell v2 engine downgrade"};
        return true;
    }

    /* SMBv1 re-enabled: unsigned, unencrypted, and the transport for a
     * long tail of lateral-movement exploits. The direction must come
     * from the VALUE, never from the parameter name: the cmdlet switch is
     * literally -EnableSMB1Protocol, so it reads as "enable" even when it
     * is being set to $false (hardening). Disabling is checked first. */
    const bool smb1Token = Contains(lower, "smb1protocol") ||
                           Contains(lower, "smb1");
    if (smb1Token) {
        const bool disabling =
            Contains(lower, "$false") || Contains(lower, ":false") ||
            Contains(lower, " false") || Contains(lower, "/d 0") ||
            Contains(lower, "-value 0") ||
            Contains(lower, "disable-feature") ||
            Contains(lower, "disable-windowsoptionalfeature") ||
            Contains(lower, "remove-windowsfeature");
        const bool enabling =
            Contains(lower, "$true") || Contains(lower, ":true") ||
            Contains(lower, " true") || Contains(lower, "/d 1") ||
            Contains(lower, "-value 1") ||
            Contains(lower, "enable-feature") ||
            Contains(lower, "enable-windowsoptionalfeature");
        if (enabling && !disabling) {
            *out = Finding{85, "SMBv1 protocol re-enabled"};
            return true;
        }
    }

    /* Legacy CLR activation lets a v2-targeted assembly load inside a
     * modern host, sidestepping v4 security policy. */
    if (Contains(lower, "uselegacyv2runtimeactivationpolicy") ||
        (Contains(lower, "supportedruntime") &&
         Contains(lower, "v2.0.50727"))) {
        *out = Finding{75, ".NET legacy v2 runtime activation"};
        return true;
    }

    /* Deprecated TLS/SSL versions re-enabled under SCHANNEL. As above,
     * the value carries the direction: the value name is `Enabled`, so a
     * hardening write of Enabled=0 must not be read as an enable. */
    const bool legacyTls = Contains(lower, "ssl 3.0") ||
                           Contains(lower, "ssl 2.0") ||
                           Contains(lower, "tls 1.0");
    if (legacyTls && (Contains(lower, "protocols") ||
                      Contains(lower, "schannel"))) {
        const bool disabling = Contains(lower, "/d 0") ||
                               Contains(lower, "-value 0") ||
                               Contains(lower, "disabledbydefault");
        const bool enabling = Contains(lower, "/d 1") ||
                              Contains(lower, "-value 1");
        if (enabling && !disabling) {
            *out = Finding{70, "deprecated TLS/SSL version re-enabled"};
            return true;
        }
    }

    return false;
}

void DowngradeAttackDetector::Stamp(Event& event, const Finding& finding,
                                    const std::string& key) {
    event.fields[field::kDowngradeAttackScore] =
        std::to_string(finding.score);
    event.fields[field::kDowngradeAttackVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kDowngradeAttackSignals] = finding.signal;
    event.fields[field::kDowngradeAttackText] = key;
}

void DowngradeAttackDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        text = keyIt->second;
        auto valIt = event.fields.find(field::kRegValue);
        if (valIt != event.fields.end()) {
            if (!text.empty()) text += " ";
            text += valIt->second;
        }
    } else {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
        if (text.empty()) {
            auto imgIt = event.fields.find(field::kImage);
            if (imgIt != event.fields.end()) text = imgIt->second;
        }
    }
    if (text.empty()) return;

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
                "[edr-downgrade-attack] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
