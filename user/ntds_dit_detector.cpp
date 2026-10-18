/*
 * ntds_dit_detector.cpp - NTDS.dit extraction (T1003.003).
 */
#include "ntds_dit_detector.h"

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

NtdsDitDetector::NtdsDitDetector(bool enabled, uint32_t minScore,
                                 uint32_t dedupWindowSeconds,
                                 size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool NtdsDitDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START || type == EDR_EVT_FILE_READ;
}

bool NtdsDitDetector::AnalyzeFileAccess(const Event& event,
                                        Finding* out) const {
    auto pathIt = event.fields.find(field::kFilePath);
    if (pathIt == event.fields.end()) return false;
    const std::string lowerPath = ToLowerAscii(pathIt->second);
    if (lowerPath.find("ntds.dit") == std::string::npos) return false;

    /* Only the directory service on a DC legitimately opens ntds.dit.
     * System32 / Windows directory binaries (ntdsutil, vssadmin in a
     * support role) are exempt; anything else reading the store is an
     * extraction attempt. */
    const std::string image = ToLowerAscii(
        [&event]() {
            auto found = event.fields.find(field::kImage);
            return found == event.fields.end() ? std::string()
                                               : found->second;
        }());
    if (image.empty()) return false;
    if (image.find("system32\\") != std::string::npos) return false;
    if (image.find("\\windows\\") != std::string::npos) return false;

    *out = Finding{80u, "ntds.dit read by non-system process"};
    return true;
}

bool NtdsDitDetector::AnalyzeCommand(const std::string& lower,
                                     Finding* out) const {
    const bool ntdsRef = Contains(lower, "ntds.dit");
    const bool shadowPivot =
        Contains(lower, "harddiskvolumeshadowcopy");

    /* Volume Shadow Copy pivot: \\?\GLOBALROOT\Device\
     * HarddiskVolumeShadowCopyN\Windows\NTDS\ntds.dit */
    if (shadowPivot && ntdsRef) {
        *out = Finding{90u, "ntds.dit extracted via shadow copy"};
        return true;
    }

    /* ntdsutil IFM media creation. */
    if (Contains(lower, "ntdsutil") &&
        (Contains(lower, "activate instance ntds") ||
         Contains(lower, " create full") ||
         Contains(lower, " ifm"))) {
        *out = Finding{85u, "ntdsutil ifm media creation"};
        return true;
    }

    /* esentutl /y raw copy of the Jet database. */
    if (Contains(lower, "esentutl") && Contains(lower, " /y") && ntdsRef) {
        *out = Finding{80u, "esentutl raw copy of ntds.dit"};
        return true;
    }

    /* PowerShell database extraction. */
    if (Contains(lower, "ntds.dit") &&
        (Contains(lower, "copy-item") ||
         Contains(lower, "extracttofile") ||
         Contains(lower, ".copyto(") ||
         Contains(lower, "copyto("))) {
        *out = Finding{80u, "powershell copy of ntds.dit"};
        return true;
    }

    /* Generic copy/archive tooling referencing the database. */
    if (ntdsRef &&
        (Contains(lower, "copy ") || Contains(lower, "xcopy") ||
         Contains(lower, "robocopy") || Contains(lower, "copyto(") ||
         Contains(lower, "\\copy") || Contains(lower, "7z ") ||
         Contains(lower, "tar ") || Contains(lower, " rar ") ||
         Contains(lower, "wbadmin"))) {
        *out = Finding{70u, "ntds.dit copied by copy tool"};
        return true;
    }

    /* Any other reference to the database file itself. */
    if (ntdsRef) {
        *out = Finding{60u, "ntds.dit referenced on command line"};
        return true;
    }

    return false;
}

void NtdsDitDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kNtdsDitScore] = std::to_string(finding.score);
    event.fields[field::kNtdsDitVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kNtdsDitSignals] = finding.signal;
}

void NtdsDitDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    if (event.type == EDR_EVT_FILE_READ) {
        if (!AnalyzeFileAccess(event, &finding)) return;
    } else {
        std::string text;
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty()) return;
        const std::string lower = ToLowerAscii(text);
        if (!AnalyzeCommand(lower, &finding)) return;
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
                "[edr-ntds-dit] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
