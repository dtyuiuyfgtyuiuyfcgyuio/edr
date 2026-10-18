/*
 * webshell_detector.cpp - See webshell_detector.h.
 */
#include "webshell_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

} // namespace

WebshellDetector::WebshellDetector(bool enabled, size_t stateCapacity,
                                   uint32_t dedupSeconds)
    : m_enabled(enabled),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_dedup100ns(static_cast<uint64_t>(dedupSeconds) *
                   kFiletimeTicksPerSecond),
      m_dedupSeconds(dedupSeconds) {}

bool WebshellDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_FILE_CREATE || type == EDR_EVT_FILE_RENAME;
}

bool WebshellDetector::IsScriptExtension(const std::string& extension) const {
    static const char* const kExtensions[] = {
        "php",   "phtml", "asp",   "aspx", "ashx", "asa",
        "asax",  "ascx",  "jsp",   "jspx", "cgi",  "pl",
        "shtml",
    };
    for (const char* ext : kExtensions) {
        if (extension == ext) return true;
    }
    return false;
}

bool WebshellDetector::IsWebRoot(const std::string& raw) const {
    const std::string path = LowerAscii(raw);
    static const char* const kRoots[] = {
        "\\inetpub\\wwwroot", "\\wwwroot", "\\htdocs", "\\www\\",
        "\\html\\",           "\\webapps", "\\phpstudy", "\\xampp",
        "\\jboss",
    };
    for (const char* root : kRoots) {
        if (path.find(root) != std::string::npos) return true;
    }
    return false;
}

bool WebshellDetector::IsSuspiciousName(const std::string& raw) const {
    const std::string base = BaseName(raw);
    size_t dot = base.find_last_of('.');
    const std::string stem =
        dot == std::string::npos ? base : base.substr(0, dot);
    static const char* const kTokens[] = {
        "cmd",       "shell",    "webshell", "backdoor", "bypass",
        "eval",      "hack",     "upload",   "c99",      "r57",
        "b374k",     "wso",      "phpspy",   "alibaba",  "kaixin",
        "cknife",    "antsword", "yijuhua",
    };
    for (const char* token : kTokens) {
        if (stem.find(token) != std::string::npos) return true;
    }
    return false;
}

bool WebshellDetector::IsWebServerWriter(const std::string& raw) const {
    const std::string base = BaseName(raw);
    static const char* const kServers[] = {
        "w3wp.exe",       "iisexpress.exe", "php-cgi.exe", "php.exe",
        "httpd.exe",      "apache.exe",     "nginx.exe",   "caddy.exe",
        "lighttpd.exe",   "java.exe",       "javaw.exe",   "dotnet.exe",
        "node.exe",       "python.exe",
    };
    for (const char* server : kServers) {
        if (base == server) return true;
    }
    return base.find("tomcat") != std::string::npos;
}

void WebshellDetector::WriteState(Event& event, uint32_t score,
                                  const std::string& reasons,
                                  const std::string& path,
                                  const std::string& extension) {
    event.fields[field::kWebshellScore] = std::to_string(score);
    event.fields[field::kWebshellReasons] = reasons;
    event.fields[field::kWebshellPath] = path;
    event.fields[field::kWebshellExtension] = extension;
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) event.fields[field::kWebshellVerdict] = verdict;
}

void WebshellDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (event.type != EDR_EVT_FILE_CREATE &&
        event.type != EDR_EVT_FILE_RENAME) {
        return;
    }

    const std::string path = FieldValue(event, field::kFilePath);
    if (path.empty()) return;
    const std::string base = BaseName(path);
    size_t dot = base.find_last_of('.');
    if (dot == std::string::npos) return;
    const std::string extension = base.substr(dot + 1);
    if (!IsScriptExtension(extension)) return;
    if (!IsWebRoot(path)) return;

    std::string reasons = "webroot_script";
    uint32_t score = 35;
    if (IsSuspiciousName(base)) {
        reasons += ",suspicious_name";
        score += 50;
    }
    const std::string image = FieldValue(event, field::kImage);
    if (!image.empty() && !IsWebServerWriter(image)) {
        reasons += ",non_webserver_writer";
        score += 30;
    }
    score = std::min(100u, score);
    if (score < 55) return;

    const uint64_t now = EventTime(event);
    const std::string key = LowerAscii(path);
    auto found = m_recentPaths.find(key);
    if (found != m_recentPaths.end() && now >= found->second.lastStamp100ns &&
        now - found->second.lastStamp100ns <= m_dedup100ns) {
        return;
    }
    m_recentPaths[key].lastStamp100ns = now;
    while (m_recentPaths.size() > m_stateCapacity) {
        m_recentPaths.erase(m_recentPaths.begin());
    }

    WriteState(event, score, reasons, path, extension);
}

} // namespace edr
