/*
 * shim_db_detector.cpp - See shim_db_detector.h.
 */
#include "shim_db_detector.h"

#include <algorithm>
#include <cctype>
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

std::string BaseNameOf(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    return slash == std::string::npos ? value : value.substr(slash + 1);
}

bool EndsWith(const std::string& value, const char* suffix) {
    const size_t len = std::strlen(suffix);
    return value.size() >= len &&
           value.compare(value.size() - len, len, suffix) == 0;
}

bool IsUserWritablePath(const std::string& path) {
    const std::string lower = ToLowerAscii(path);
    return Contains(lower, "\\appdata\\") ||
           Contains(lower, "\\temp\\") ||
           Contains(lower, "\\tmp\\") ||
           Contains(lower, "\\programdata\\") ||
           Contains(lower, "\\users\\public\\") ||
           Contains(lower, "\\downloads\\") ||
           Contains(lower, "\\windows\\temp\\");
}

} // namespace

ShimDbDetector::ShimDbDetector(bool enabled, uint32_t minScore,
                               uint32_t dedupWindowSeconds,
                               size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool ShimDbDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START || type == EDR_EVT_REG_WRITE ||
           type == EDR_EVT_FILE_CREATE;
}

bool ShimDbDetector::AnalyzeProcessStart(const std::string& image,
                                         const std::string& commandLine,
                                         Finding* out) const {
    const std::string base = ToLowerAscii(BaseNameOf(image));
    if (base != "sdbinst.exe") return false;
    const std::string lower = ToLowerAscii(commandLine);

    /* Uninstalling a shim database is cleanup, not persistence. */
    if (Contains(lower, "-u") || Contains(lower, " /u")) return false;

    if (Contains(lower, ".sdb")) {
        *out = Finding{85, "sdbinst_shim_db_install", commandLine};
        return true;
    }
    *out = Finding{60, "sdbinst_shim_tool", commandLine};
    return true;
}

bool ShimDbDetector::AnalyzeRegWrite(const std::string& regKey,
                                     Finding* out) const {
    const std::string lower = ToLowerAscii(regKey);
    if (!Contains(lower, "appcompatflags")) return false;
    /* The \Custom\ subkey only holds shims installed via sdbinst -
     * the attacker-controlled surface. */
    if (Contains(lower, "\\custom\\")) {
        *out = Finding{90, "appcompat_custom_shim_write", regKey};
        return true;
    }
    if (Contains(lower, "installedsdb") || Contains(lower, "installsdb")) {
        *out = Finding{80, "installed_sdb_write", regKey};
        return true;
    }
    return false;
}

bool ShimDbDetector::AnalyzeFileCreate(const std::string& filePath,
                                       Finding* out) const {
    const std::string lower = ToLowerAscii(filePath);
    if (!EndsWith(lower, ".sdb")) return false;
    if (!IsUserWritablePath(lower)) return false;
    *out = Finding{55, "shim_db_staged", filePath};
    return true;
}

void ShimDbDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kShimDbScore] = std::to_string(finding.score);
    const std::string verdict =
        finding.score >= 75 ? "MALICIOUS" : "SUSPICIOUS";
    event.fields[field::kShimDbVerdict] = verdict;
    event.fields[field::kShimDbSignals] = finding.signal;
    if (!finding.path.empty()) {
        event.fields[field::kShimDbPaths] = finding.path;
    }
}

void ShimDbDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    if (event.type == EDR_EVT_PROCESS_START) {
        std::string image;
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt != event.fields.end()) image = imgIt->second;
        std::string commandLine;
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) commandLine = cmdIt->second;
        if (!AnalyzeProcessStart(image, commandLine, &finding)) return;
    } else if (event.type == EDR_EVT_REG_WRITE) {
        std::string regKey;
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt != event.fields.end()) regKey = keyIt->second;
        if (!AnalyzeRegWrite(regKey, &finding)) return;
    } else if (event.type == EDR_EVT_FILE_CREATE) {
        std::string filePath;
        auto pathIt = event.fields.find(field::kFilePath);
        if (pathIt != event.fields.end()) filePath = pathIt->second;
        if (!AnalyzeFileCreate(filePath, &finding)) return;
    } else {
        return;
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
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
