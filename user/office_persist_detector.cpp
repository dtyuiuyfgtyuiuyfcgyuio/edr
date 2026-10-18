/*
 * office_persist_detector.cpp - Office application-startup persistence
 * detector (T1137).
 */
#include "office_persist_detector.h"

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

/* .xlam / .xll, or a bare .xla that is not the prefix of .xlsx / .xls. */
bool HasExcelAddinExt(const std::string& lower) {
    if (Contains(lower, ".xlam") || Contains(lower, ".xll"))
        return true;
    size_t pos = 0;
    while ((pos = lower.find(".xla", pos)) != std::string::npos) {
        const size_t after = pos + 4;
        if (after >= lower.size() ||
            !std::isalpha(static_cast<unsigned char>(lower[after])))
            return true;
        pos = after;
    }
    return false;
}

bool IsReadOnlyListing(const std::string& lower) {
    return (Contains(lower, "dir ") || Contains(lower, "get-childitem") ||
            Contains(lower, "get-item") || Contains(lower, "type ") ||
            Contains(lower, "get-content")) &&
           !Contains(lower, "copy") && !Contains(lower, "move") &&
           !Contains(lower, "set-content") && !Contains(lower, "add-content") &&
           !Contains(lower, "out-file") && !Contains(lower, "reg add") &&
           !Contains(lower, ">") && !Contains(lower, "new-item");
}

} // namespace

OfficePersistDetector::OfficePersistDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool OfficePersistDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE ||
           type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_RENAME;
}

bool OfficePersistDetector::Analyze(const std::string& lower,
                                    Finding* out) const {
    if (IsReadOnlyListing(lower)) return false;

    if (Contains(lower, "vbaproject.otm")) {
        *out = Finding{90, "Outlook VBAProject.OTM persistence"};
        return true;
    }

    const bool officeKey = Contains(lower, "\\office\\") ||
                           Contains(lower, " microsoft\\office");
    const bool addinsKey = Contains(lower, "\\addins") ||
                           Contains(lower, "\\addins\\");
    if (officeKey && addinsKey &&
        (Contains(lower, "loadbehavior") || Contains(lower, ".dll") ||
         Contains(lower, ".xll") || Contains(lower, "manifest"))) {
        *out = Finding{90, "Office COM add-in LoadBehavior persistence"};
        return true;
    }

    if ((Contains(lower, "excel\\options") ||
         Contains(lower, "excel\\\\options")) &&
        (Contains(lower, " open") || Contains(lower, "\\open") ||
         Contains(lower, " open1") || Contains(lower, "/r "))) {
        *out = Finding{85, "Excel OPEN/OPEN1 add-in persistence"};
        return true;
    }

    if (Contains(lower, ".wll") &&
        (Contains(lower, "\\startup") || Contains(lower, "word\\startup") ||
         Contains(lower, "word/startup"))) {
        *out = Finding{85, "Word STARTUP WLL drop"};
        return true;
    }

    if (HasExcelAddinExt(lower) &&
        (Contains(lower, "xlstart") || Contains(lower, "excel\\xlstart"))) {
        *out = Finding{85, "Excel XLSTART add-in drop"};
        return true;
    }

    if (Contains(lower, "webaddins") ||
        (Contains(lower, "outlook") &&
         (Contains(lower, "\\homepage") || Contains(lower, " homepage")))) {
        *out = Finding{80, "Outlook WebAddin / homepage hijack"};
        return true;
    }

    if (Contains(lower, "addins.add") ||
        Contains(lower, "register-exceladdin") ||
        Contains(lower, "application.addins")) {
        *out = Finding{80, "Office object-model add-in registration"};
        return true;
    }

    if (officeKey && addinsKey) {
        *out = Finding{75, "Office add-in registry write"};
        return true;
    }

    return false;
}

void OfficePersistDetector::Stamp(Event& event, const Finding& finding,
                                  const std::string& key) {
    event.fields[field::kOfficePersistScore] =
        std::to_string(finding.score);
    event.fields[field::kOfficePersistVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kOfficePersistSignals] = finding.signal;
    event.fields[field::kOfficePersistText] = key;
}

void OfficePersistDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    if (event.type == EDR_EVT_FILE_CREATE ||
        event.type == EDR_EVT_FILE_RENAME) {
        auto pathIt = event.fields.find(field::kFilePath);
        if (pathIt == event.fields.end())
            pathIt = event.fields.find(field::kTargetPath);
        if (pathIt == event.fields.end()) return;
        const std::string lowerPath = ToLowerAscii(pathIt->second);
        Finding finding;
        if (Contains(lowerPath, "vbaproject.otm")) {
            finding = Finding{90, "Outlook VBAProject.OTM persistence"};
        } else if (EndsWith(lowerPath, ".wll") &&
                   (Contains(lowerPath, "\\startup") ||
                    Contains(lowerPath, "/startup") ||
                    Contains(lowerPath, "word\\startup"))) {
            finding = Finding{85, "Word STARTUP WLL drop"};
        } else if ((EndsWith(lowerPath, ".xlam") ||
                    EndsWith(lowerPath, ".xla") ||
                    EndsWith(lowerPath, ".xll")) &&
                   Contains(lowerPath, "xlstart")) {
            finding = Finding{85, "Excel XLSTART add-in drop"};
        } else {
            return;
        }
        if (finding.score >= m_minScore)
            Stamp(event, finding, lowerPath.substr(0, 160));
        return;
    }

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
                "[edr-office-persist] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
