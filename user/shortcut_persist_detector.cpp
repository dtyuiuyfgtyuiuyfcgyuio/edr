/*
 * shortcut_persist_detector.cpp - Startup-folder shortcut persistence
 * detector (T1547.009).
 */
#include "shortcut_persist_detector.h"

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

bool EndsWith(const std::string& value, const char* suffix) {
    const size_t n = std::char_traits<char>::length(suffix);
    return value.size() >= n &&
           value.compare(value.size() - n, n, suffix) == 0;
}

bool IsStartupPath(const std::string& lower) {
    return Contains(lower, "\\startup\\") ||
           Contains(lower, "\\startup/") ||
           Contains(lower, "/startup/") ||
           Contains(lower, "programs\\startup") ||
           Contains(lower, "programs/startup") ||
           Contains(lower, "start menu\\programs\\startup") ||
           EndsWith(lower, "\\startup") ||
           EndsWith(lower, "/startup");
}

bool IsShortcutName(const std::string& lower) {
    return EndsWith(lower, ".lnk") || EndsWith(lower, ".url") ||
           Contains(lower, ".lnk") || Contains(lower, ".url");
}

bool IsReadOnlyBrowse(const std::string& lower) {
    return (Contains(lower, "explorer.exe") || Contains(lower, "dir ") ||
            Contains(lower, "get-childitem") || Contains(lower, "start ")) &&
           !Contains(lower, "copy") && !Contains(lower, "move") &&
           !Contains(lower, "createshortcut") && !Contains(lower, ">");
}

} // namespace

ShortcutPersistDetector::ShortcutPersistDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool ShortcutPersistDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_RENAME;
}

bool ShortcutPersistDetector::Analyze(const std::string& lower,
                                      Finding* out) const {
    if (!IsStartupPath(lower)) return false;
    if (IsReadOnlyBrowse(lower)) return false;

    if (Contains(lower, "createshortcut") ||
        (Contains(lower, "wscript.shell") && Contains(lower, ".lnk"))) {
        *out = Finding{90, "WScript.Shell CreateShortcut into Startup"};
        return true;
    }

    if (IsShortcutName(lower) &&
        (Contains(lower, "copy") || Contains(lower, "xcopy") ||
         Contains(lower, "move") || Contains(lower, "copy-item") ||
         Contains(lower, "move-item") || Contains(lower, "robocopy") ||
         Contains(lower, ">"))) {
        *out = Finding{80, "shortcut copied into Startup folder"};
        return true;
    }

    if (Contains(lower, "wscript.shell") && IsStartupPath(lower)) {
        *out = Finding{65, "WScript.Shell object targeting Startup"};
        return true;
    }

    return false;
}

void ShortcutPersistDetector::Stamp(Event& event, const Finding& finding,
                                    const std::string& key) {
    event.fields[field::kShortcutPersistScore] =
        std::to_string(finding.score);
    event.fields[field::kShortcutPersistVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kShortcutPersistSignals] = finding.signal;
    event.fields[field::kShortcutPersistText] = key;
}

void ShortcutPersistDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    if (event.type == EDR_EVT_FILE_CREATE ||
        event.type == EDR_EVT_FILE_RENAME) {
        auto pathIt = event.fields.find(field::kFilePath);
        if (pathIt == event.fields.end())
            pathIt = event.fields.find(field::kTargetPath);
        if (pathIt == event.fields.end()) return;
        const std::string lowerPath = ToLowerAscii(pathIt->second);
        if (!IsStartupPath(lowerPath) || !IsShortcutName(lowerPath))
            return;
        Finding finding{90, "shortcut written into Startup folder"};
        if (finding.score >= m_minScore)
            Stamp(event, finding, lowerPath.substr(0, 160));
        return;
    }

    std::string text;
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
                "[edr-shortcut-persist] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
