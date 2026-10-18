/*
 * disk_wipe_detector.cpp - See disk_wipe_detector.h.
 */
#include "disk_wipe_detector.h"

#include <algorithm>
#include <cctype>

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

/* True when the text contains a drive-letter colon target (e.g. "c:" or
 * "d:\"), used to confirm a real format target. */
bool HasDriveColon(const std::string& text) {
    for (size_t i = 1; i < text.size(); ++i) {
        if (text[i] == ':' &&
            ((text[i - 1] >= 'a' && text[i - 1] <= 'z') ||
             (text[i - 1] >= '0' && text[i - 1] <= '9')))
            return true;
    }
    return false;
}

} // namespace

DiskWipeDetector::DiskWipeDetector(bool enabled, uint32_t minScore,
                                   uint32_t dedupWindowSeconds,
                                   size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool DiskWipeDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool DiskWipeDetector::AnalyzeCommandLine(const std::string& lower,
                                          Finding* out) const {
    if (Contains(lower, "diskpart")) {
        if (Contains(lower, "clean all")) {
            *out = Finding{90, "diskpart_clean_all", "diskpart"};
            return true;
        }
        if (Contains(lower, " clean")) {
            *out = Finding{85, "diskpart_clean", "diskpart"};
            return true;
        }
        return false;
    }

    if (Contains(lower, "cipher") && Contains(lower, "/w:")) {
        *out = Finding{60, "cipher_free_space_wipe", "cipher"};
        return true;
    }

    if (Contains(lower, "format-volume") ||
        Contains(lower, "clear-volume")) {
        *out = Finding{70, "powershell_volume_wipe",
                       Contains(lower, "format-volume") ? "format-volume"
                                                        : "clear-volume"};
        return true;
    }

    if (Contains(lower, " format ") || Contains(lower, "format ")) {
        if (!HasDriveColon(lower)) return false;
        if (Contains(lower, "/q") || Contains(lower, "-q")) {
            *out = Finding{75, "quick_format", "format"};
            return true;
        }
        *out = Finding{85, "full_format", "format"};
        return true;
    }

    return false;
}

void DiskWipeDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kDiskWipeScore] = std::to_string(finding.score);
    const std::string verdict =
        finding.score >= 75 ? "MALICIOUS" : "SUSPICIOUS";
    event.fields[field::kDiskWipeVerdict] = verdict;
    event.fields[field::kDiskWipeSignals] = finding.signal;
    if (!finding.target.empty()) {
        event.fields[field::kDiskWipeTargets] = finding.target;
    }
}

void DiskWipeDetector::Enrich(Event& event) {
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

    Finding finding;
    if (!AnalyzeCommandLine(lower, &finding)) return;
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
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
