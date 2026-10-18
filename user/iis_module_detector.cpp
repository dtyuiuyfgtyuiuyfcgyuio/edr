/*
 * iis_module_detector.cpp - IIS module / ISAPI persistence detector
 * (T1505.004).
 */
#include "iis_module_detector.h"

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

bool EndsWith(const std::string& value, const char* suffix) {
    const size_t n = std::char_traits<char>::length(suffix);
    return value.size() >= n &&
           value.compare(value.size() - n, n, suffix) == 0;
}

bool IsReadOnlyQuery(const std::string& lower) {
    if (Contains(lower, "list module") ||
        Contains(lower, "list filter") ||
        Contains(lower, "get-webglobalmodule") ||
        Contains(lower, "get-webconfiguration") ||
        Contains(lower, "appcmd list") ||
        Contains(lower, "get-item ")) {
        return !Contains(lower, "add module") &&
               !Contains(lower, "install module") &&
               !Contains(lower, "add filter") &&
               !Contains(lower, "new-webglobalmodule") &&
               !Contains(lower, "add-webconfiguration") &&
               !Contains(lower, "set-content") &&
               !Contains(lower, "set config");
    }
    return false;
}

bool IsInstallerImage(const std::string& lowerImage) {
    const std::string base = Basename(lowerImage);
    return base == "w3wp.exe" || base == "inetinfo.exe" ||
           base == "svchost.exe" || base == "msiexec.exe" ||
           base == "trustedinstaller.exe" || base == "tiworker.exe" ||
           base == "setup.exe" || base == "wuauclt.exe" ||
           base == "iissetup.exe";
}

} // namespace

IisModuleDetector::IisModuleDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool IisModuleDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_RENAME;
}

bool IisModuleDetector::Analyze(const std::string& lower,
                                Finding* out) const {
    if (IsReadOnlyQuery(lower)) return false;

    if (Contains(lower, "appcmd") &&
        (Contains(lower, "add module") ||
         Contains(lower, "install module") ||
         Contains(lower, "add filter"))) {
        *out = Finding{90, "appcmd IIS module install"};
        return true;
    }
    if (Contains(lower, "new-webglobalmodule") ||
        (Contains(lower, "add-webconfiguration") &&
         (Contains(lower, "globalmodules") ||
          Contains(lower, "isapifilters")))) {
        *out = Finding{85, "PowerShell IIS module install"};
        return true;
    }
    if (Contains(lower, "applicationhost.config") &&
        (Contains(lower, "set-content") || Contains(lower, "out-file") ||
         Contains(lower, "copy") || Contains(lower, "move ") ||
         Contains(lower, "xcopy") || Contains(lower, "robocopy"))) {
        *out = Finding{80, "applicationHost.config overwrite"};
        return true;
    }
    if (Contains(lower, "appcmd") && Contains(lower, "set config") &&
        (Contains(lower, "globalmodules") ||
         Contains(lower, "isapifilters"))) {
        *out = Finding{85, "appcmd set config module"};
        return true;
    }
    return false;
}

bool IisModuleDetector::AnalyzeFile(const std::string& lowerPath,
                                    const std::string& lowerImage,
                                    Finding* out) const {
    if (!EndsWith(lowerPath, ".dll")) return false;
    const bool inetsrv = Contains(lowerPath, "\\inetsrv\\") ||
                         Contains(lowerPath, "/inetsrv/");
    const bool inetpub = Contains(lowerPath, "\\inetpub\\") ||
                         Contains(lowerPath, "/inetpub/");
    if (!inetsrv && !inetpub) return false;
    if (IsInstallerImage(lowerImage)) return false;
    *out = Finding{75, "IIS native module DLL drop"};
    return true;
}

void IisModuleDetector::Stamp(Event& event, const Finding& finding,
                              const std::string& key) {
    event.fields[field::kIisModuleScore] = std::to_string(finding.score);
    event.fields[field::kIisModuleVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kIisModuleSignals] = finding.signal;
    event.fields[field::kIisModuleText] = key;
}

void IisModuleDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    std::string key;

    if (event.type == EDR_EVT_FILE_CREATE ||
        event.type == EDR_EVT_FILE_RENAME) {
        auto pathIt = event.fields.find(field::kFilePath);
        if (pathIt == event.fields.end())
            pathIt = event.fields.find(field::kTargetPath);
        if (pathIt == event.fields.end()) return;
        std::string image;
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt != event.fields.end()) image = imgIt->second;
        const std::string lowerPath = ToLowerAscii(pathIt->second);
        if (!AnalyzeFile(lowerPath, ToLowerAscii(image), &finding))
            return;
        if (finding.score < m_minScore) return;
        key = lowerPath.substr(0, 160);
    } else {
        std::string text;
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
        if (!Analyze(lower, &finding)) return;
        if (finding.score < m_minScore) return;
        key = lower.substr(0, 160);
    }

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
                "[edr-iis-module] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
