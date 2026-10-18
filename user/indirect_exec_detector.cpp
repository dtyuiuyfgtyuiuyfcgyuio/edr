/*
 * indirect_exec_detector.cpp - Indirect command execution detector
 * (T1202).
 */
#include "indirect_exec_detector.h"

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

std::string Basename(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

} // namespace

IndirectExecDetector::IndirectExecDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool IndirectExecDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool IndirectExecDetector::Analyze(const std::string& lower,
                                   const std::string& imageLower,
                                   Finding* out) const {
    const std::string base = Basename(imageLower);

    if ((base == "forfiles.exe" || Contains(lower, "forfiles")) &&
        (Contains(lower, " /c ") || Contains(lower, " /c\"") ||
         Contains(lower, "/c:") || Contains(lower, " -c ") ||
         Contains(lower, " -c\""))) {
        *out = Finding{90, "forfiles /c proxy execution"};
        return true;
    }

    if ((base == "pcalua.exe" || Contains(lower, "pcalua")) &&
        (Contains(lower, " -a ") || Contains(lower, " /a ") ||
         Contains(lower, "-a:") || Contains(lower, "/a:"))) {
        *out = Finding{85, "pcalua -a proxy execution"};
        return true;
    }

    if ((base == "ieexec.exe" || Contains(lower, "ieexec")) &&
        (Contains(lower, "http://") || Contains(lower, "https://") ||
         Contains(lower, "file://"))) {
        *out = Finding{80, "ieexec remote assembly execution"};
        return true;
    }

    if ((base == "conhost.exe" || Contains(lower, "conhost")) &&
        Contains(lower, "--headless")) {
        *out = Finding{75, "conhost --headless command proxy"};
        return true;
    }

    if ((base == "ftp.exe" || Contains(lower, "ftp.exe")) &&
        (Contains(lower, " -s:") || Contains(lower, " /s:") ||
         Contains(lower, "-s:\"") || Contains(lower, " -s "))) {
        *out = Finding{70, "ftp -s scripted command execution"};
        return true;
    }

    if ((base == "presentationhost.exe" ||
         Contains(lower, "presentationhost")) &&
        (Contains(lower, ".xbap") || Contains(lower, ".xaml"))) {
        *out = Finding{65, "presentationhost XBAP/XAML proxy"};
        return true;
    }

    return false;
}

void IndirectExecDetector::Stamp(Event& event, const Finding& finding,
                                 const std::string& key) {
    event.fields[field::kIndirectExecScore] =
        std::to_string(finding.score);
    event.fields[field::kIndirectExecVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kIndirectExecSignals] = finding.signal;
    event.fields[field::kIndirectExecText] = key;
}

void IndirectExecDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    std::string image;
    auto imgIt = event.fields.find(field::kImage);
    if (imgIt != event.fields.end()) image = imgIt->second;
    if (text.empty() && image.empty()) return;

    const std::string combined = ToLowerAscii(image + " " + text);
    const std::string imageLower = ToLowerAscii(image);

    Finding finding;
    if (!Analyze(combined, imageLower, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = combined.substr(0, 160);
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
                "[edr-indirect-exec] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
