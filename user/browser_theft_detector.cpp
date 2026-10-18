/*
 * browser_theft_detector.cpp - See browser_theft_detector.h.
 */
#include "browser_theft_detector.h"

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

bool ContainsI(const std::string& haystack, const char* needle) {
    const std::string h = LowerAscii(haystack);
    const std::string n = LowerAscii(needle);
    return h.find(n) != std::string::npos;
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

BrowserTheftDetector::BrowserTheftDetector(bool enabled,
                                           uint32_t windowSeconds,
                                           size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool BrowserTheftDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_READ;
}

bool BrowserTheftDetector::IsBrowserProcess(const std::string& image) {
    const std::string base = BaseName(image);
    return base == "chrome.exe" || base == "msedge.exe" ||
           base == "firefox.exe" || base == "brave.exe" ||
           base == "opera.exe" || base == "iexplore.exe" ||
           base == "browser_exe.exe";
}

bool BrowserTheftDetector::IdentifyBrowserData(const std::string& path,
                                               std::string& browser,
                                               std::string& dataType) {
    const std::string lower = LowerAscii(path);
    /* Chromium-based: Chrome, Edge, Brave, Opera */
    if (lower.find("\\google\\chrome\\") != std::string::npos ||
        lower.find("\\microsoft\\edge\\") != std::string::npos ||
        lower.find("\\bravesoftware\\") != std::string::npos) {
        browser = "chromium";
        if (lower.find("login data") != std::string::npos) {
            dataType = "login_data"; return true;
        }
        if (lower.find("cookies") != std::string::npos) {
            dataType = "cookies"; return true;
        }
        if (lower.find("web data") != std::string::npos) {
            dataType = "web_data"; return true;
        }
        if (lower.find("local state") != std::string::npos) {
            dataType = "local_state"; return true;
        }
        if (lower.find("history") != std::string::npos) {
            dataType = "history"; return true;
        }
    }
    /* Firefox */
    if (lower.find("\\mozilla\\firefox\\") != std::string::npos ||
        lower.find("\\profiles\\") != std::string::npos) {
        browser = "firefox";
        if (lower.find("logins.json") != std::string::npos) {
            dataType = "logins"; return true;
        }
        if (lower.find("key4.db") != std::string::npos) {
            dataType = "key4_db"; return true;
        }
        if (lower.find("cookies.sqlite") != std::string::npos) {
            dataType = "cookies"; return true;
        }
        if (lower.find("formhistory.sqlite") != std::string::npos) {
            dataType = "form_history"; return true;
        }
        if (lower.find("places.sqlite") != std::string::npos) {
            dataType = "history"; return true;
        }
    }
    return false;
}

void BrowserTheftDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t BrowserTheftDetector::ComputeScore(const ProcState& state) const {
    uint32_t score = 0;
    /* Accessing login data or key4.db is most suspicious */
    for (const auto& dt : state.dataTypes) {
        if (dt == "login_data" || dt == "logins" || dt == "key4_db") {
            score += 40;
        } else if (dt == "cookies") {
            score += 25;
        } else if (dt == "local_state") {
            score += 20; /* needed to decrypt Chrome cookies */
        } else if (dt == "web_data" || dt == "form_history") {
            score += 15;
        } else if (dt == "history") {
            score += 10;
        }
    }
    /* Accessing local state + cookies = full credential theft chain */
    if (state.sawLocalState && state.dataTypes.count("cookies") > 0)
        score += 20;
    /* Multiple browsers = credential harvesting tool */
    if (state.browsers.size() >= 2) score += 15;
    return std::min(100u, score);
}

std::string BrowserTheftDetector::BrowserList(const ProcState& state) const {
    std::string list;
    for (const auto& b : state.browsers) {
        if (!list.empty()) list += ",";
        list += b;
    }
    return list;
}

std::string BrowserTheftDetector::DataTypeList(const ProcState& state) const {
    std::string list;
    for (const auto& dt : state.dataTypes) {
        if (!list.empty()) list += ",";
        list += dt;
    }
    return list;
}

void BrowserTheftDetector::WriteState(Event& event,
                                      const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kBrowserTheftScore] = std::to_string(score);
    event.fields[field::kBrowserTheftBrowsers] = BrowserList(state);
    event.fields[field::kBrowserTheftDataTypes] = DataTypeList(state);
    event.fields[field::kBrowserTheftWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty())
        event.fields[field::kBrowserTheftVerdict] = verdict;
}

void BrowserTheftDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string path = FieldValue(event, field::kFilePath);
    if (path.empty()) return;

    std::string browser, dataType;
    if (!IdentifyBrowserData(path, browser, dataType)) return;

    /* Check if the accessing process is a browser itself — legitimate */
    const std::string image = FieldValue(event, field::kImage);
    if (IsBrowserProcess(image)) return;

    ProcState& state = m_procs[event.pid];
    state.browsers.insert(browser);
    state.dataTypes.insert(dataType);
    if (dataType == "local_state") state.sawLocalState = true;
    state.lastSeen100ns = now;
    WriteState(event, state);
}

} // namespace edr
