/*
 * shadow_copy_detector.cpp - System-restore suppression (T1490).
 */
#include "shadow_copy_detector.h"

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

} // namespace

ShadowCopyDetector::ShadowCopyDetector(bool enabled, uint32_t minScore,
                                       uint32_t dedupWindowSeconds,
                                       size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool ShadowCopyDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool ShadowCopyDetector::AnalyzeCommand(const std::string& lower,
                                        Finding* out) const {
    /* vssadmin delete shadows is the canonical shadow-copy wipe. */
    const bool vssAdminDelete =
        Contains(lower, "vssadmin") && Contains(lower, "delete shadows");
    const bool shadowsAll = Contains(lower, "/all");

    if (vssAdminDelete) {
        *out = Finding{shadowsAll ? 90u : 75u,
            shadowsAll ? "all shadow copies deleted via vssadmin"
                       : "shadow copies deleted via vssadmin"};
        return true;
    }

    /* WMI plane: wmic shadowcopy delete / call delete. */
    if (Contains(lower, "wmic") &&
        (Contains(lower, "shadowcopy delete") ||
         Contains(lower, "shadowcopy call delete") ||
         Contains(lower, "shadowcopy call "))) {
        *out = Finding{75, "shadow copies deleted via wmic"};
        return true;
    }

    /* PowerShell WMI removal: Win32_ShadowCopy piped into
     * Remove-WmiObject or .Delete(). */
    const bool psShadow = Contains(lower, "win32_shadowcopy") ||
                          Contains(lower, "win32_shadowstorage");
    if (psShadow &&
        (Contains(lower, "remove-wmiobject") ||
         Contains(lower, ".delete()") ||
         Contains(lower, "remove-ciminstance"))) {
        *out = Finding{70, "shadow copies deleted via powershell wmi"};
        return true;
    }

    /* Backup catalog deletion. */
    if (Contains(lower, "wbadmin") && Contains(lower, "delete catalog")) {
        *out = Finding{70, "backup catalog deleted via wbadmin"};
        return true;
    }

    /* Disabling boot-time recovery. */
    if (Contains(lower, "bcdedit") &&
        Contains(lower, "recoveryenabled") &&
        (Contains(lower, " no") || Contains(lower, " off") ||
         Contains(lower, " 0"))) {
        *out = Finding{60, "boot recovery disabled via bcdedit"};
        return true;
    }

    return false;
}

void ShadowCopyDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kShadowCopyScore] = std::to_string(finding.score);
    event.fields[field::kShadowCopyVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kShadowCopySignals] = finding.signal;
}

void ShadowCopyDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    const std::string lower = ToLowerAscii(text);

    /* Score the primary family, then escalate when recovery-disable is
     * combined with a shadow wipe. */
    Finding finding;
    if (!AnalyzeCommand(lower, &finding)) return;

    const bool recoveryDisabled =
        Contains(lower, "bcdedit") && Contains(lower, "recoveryenabled") &&
        (Contains(lower, " no") || Contains(lower, " off") ||
         Contains(lower, " 0"));
    if (recoveryDisabled && finding.score >= 75) {
        finding.score = 95;
        finding.signal = "shadow wipe combined with recovery disable";
    }

    if (finding.score < m_minScore) return;

    const uint64_t now = event.ts100ns;
    const std::string key = finding.signal;
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
                "[edr-shadow-copy] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
