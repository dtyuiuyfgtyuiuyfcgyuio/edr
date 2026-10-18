/*
 * powershell_download_execute_detector.cpp - See powershell_download_execute_detector.h.
 *
 * Repeated PowerShell process starts by the same parent image basename are
 * correlated over a rolling window. When a PowerShell process launches
 * another suspicious child within the window and the command line contains
 * download/execution markers, the current event is stamped with
 * powershell_download_execute_* fields.
 */
#include "powershell_download_execute_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

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

bool ContainsDownloadOrExecuteMarker(const std::string& cmd) {
    const std::string lower = LowerAscii(cmd);
    return lower.find("downloadstring") != std::string::npos ||
           lower.find("invoke-webrequest") != std::string::npos ||
           lower.find("iwr") != std::string::npos ||
           lower.find("frombase64") != std::string::npos ||
           lower.find("bypass") != std::string::npos ||
           lower.find("hidden") != std::string::npos ||
           lower.find("encodedcommand") != std::string::npos ||
           lower.find("downloadfile") != std::string::npos ||
           lower.find("iex ") != std::string::npos ||
           lower.find("iex(") != std::string::npos;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    if (map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& left, const auto& right) {
            return left.second.lastSeen100ns < right.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

} // namespace

PowerShellDownloadExecuteDetector::PowerShellDownloadExecuteDetector(
    bool enabled, uint32_t windowSeconds, size_t stateCapacity,
    uint32_t minDistinctScripts)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minDistinctScripts(std::max<uint32_t>(1, minDistinctScripts)) {}

bool PowerShellDownloadExecuteDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

void PowerShellDownloadExecuteDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_parents.begin(); it != m_parents.end();) {
        ParentState& state = it->second;
        for (auto script = state.scripts.begin(); script != state.scripts.end();) {
            if (now100ns >= script->second.lastSeen100ns &&
                now100ns - script->second.lastSeen100ns > m_window100ns) {
                script = state.scripts.erase(script);
            } else {
                ++script;
            }
        }
        if (state.scripts.empty()) {
            it = m_parents.erase(it);
        } else {
            ++it;
        }
    }
}

void PowerShellDownloadExecuteDetector::WriteState(Event& event,
                                                   const ParentState& state) {
    std::vector<std::string> scripts;
    for (const auto& entry : state.scripts) {
        if (scripts.size() >= 6) break;
        scripts.push_back(entry.first);
    }
    std::sort(scripts.begin(), scripts.end());

    std::string joined;
    for (const std::string& script : scripts) {
        if (!joined.empty()) joined += ",";
        joined += script;
    }

    const uint32_t count = static_cast<uint32_t>(state.scripts.size());
    const uint32_t score = std::min(100u, count * 20u + 15u);
    event.fields[field::kPowerShellDownloadExecuteScore] = std::to_string(score);
    event.fields[field::kPowerShellDownloadExecuteCount] = std::to_string(count);
    event.fields[field::kPowerShellDownloadExecuteSignals] = joined;
    event.fields[field::kPowerShellDownloadExecuteWindowSeconds] = std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kPowerShellDownloadExecuteVerdict] = verdict;
    }
}

void PowerShellDownloadExecuteDetector::Enrich(Event& event) {
    if (!m_enabled || event.pid == 0) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string parentBase = BaseName(FieldValue(event, field::kParentImage));
    const std::string childBase = BaseName(FieldValue(event, field::kImage));
    if (parentBase.empty() || childBase.empty() || childBase != "powershell.exe")
        return;

    const std::string cmd = FieldValue(event, field::kCommandLine);
    if (!ContainsDownloadOrExecuteMarker(cmd)) return;

    /* Real telemetry gives every process start a fresh PID; correlate by the
     * parent process so repeated child launches accumulate in one bucket. */
    const std::string key = std::to_string(event.ppid) + "@" + parentBase;
    ParentState& state = m_parents[key];
    /* Count distinct scripts (per command line), not the child basename,
     * which the filter above pins to "powershell.exe" for every event. */
    auto existing = state.scripts.find(cmd);
    if (existing == state.scripts.end()) {
        ScriptInfo info;
        info.lastSeen100ns = now;
        state.scripts.emplace(cmd, info);
    } else {
        existing->second.lastSeen100ns = now;
    }
    state.lastSeen100ns = now;

    const uint32_t count = static_cast<uint32_t>(state.scripts.size());
    if (count >= m_minDistinctScripts && count > state.lastFlaggedCount) {
        state.lastFlaggedCount = count;
        WriteState(event, state);
    }

    EvictOldest(m_parents, m_stateCapacity);
}

} // namespace edr
