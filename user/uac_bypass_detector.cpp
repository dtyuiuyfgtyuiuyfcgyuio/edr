/*
 * uac_bypass_detector.cpp - See uac_bypass_detector.h.
 */
#include "uac_bypass_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
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

UacBypassDetector::UacBypassDetector(bool enabled, uint32_t windowSeconds,
                                     size_t stateCapacity,
                                     uint32_t minDistinctKeys)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minDistinctKeys(std::max<uint32_t>(1, minDistinctKeys)) {}

bool UacBypassDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_REG_WRITE || type == EDR_EVT_PROCESS_START;
}

bool UacBypassDetector::IsBypassKey(const std::string& raw) const {
    const std::string key = LowerAscii(raw);
    return key.find("\\software\\classes\\ms-settings\\shell\\open\\command") !=
               std::string::npos ||
           key.find("\\software\\classes\\mscfile\\shell\\open\\command") !=
               std::string::npos ||
           key.find("\\policies\\microsoft\\windows\\installer\\alwaysinstallelevated") !=
               std::string::npos ||
           key.find("\\currentversion\\silentprocessexit\\") !=
               std::string::npos ||
           key.find("\\currentversion\\appcertdlls\\") != std::string::npos;
}

bool UacBypassDetector::IsElevatedBinary(const std::string& raw) const {
    const std::string name = BaseName(raw);
    return name == "fodhelper.exe" || name == "computerdefaults.exe" ||
           name == "eventvwr.exe" || name == "sdclt.exe";
}

void UacBypassDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_recentKeys.begin(); it != m_recentKeys.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_recentKeys.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t UacBypassDetector::DistinctRecentKeys(uint64_t now100ns) {
    PurgeExpired(now100ns);
    return static_cast<uint32_t>(m_recentKeys.size());
}

void UacBypassDetector::WriteState(Event& event, uint32_t count,
                                   uint32_t score,
                                   const std::vector<std::string>& keys) {
    std::string joined;
    for (const std::string& key : keys) {
        if (!joined.empty()) joined += ",";
        joined += key;
    }
    event.fields[field::kUacBypassScore] = std::to_string(score);
    event.fields[field::kUacBypassCount] = std::to_string(count);
    event.fields[field::kUacBypassKeys] = joined;
    event.fields[field::kUacBypassWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) event.fields[field::kUacBypassVerdict] = verdict;
}

void UacBypassDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    if (event.type == EDR_EVT_REG_WRITE) {
        const std::string key = FieldValue(event, field::kRegKey);
        if (key.empty() || !IsBypassKey(key)) return;
        m_recentKeys[key].lastSeen100ns = now;
        EvictOldest(m_recentKeys, m_stateCapacity);
        return;
    }

    if (event.type != EDR_EVT_PROCESS_START) return;
    if (!IsElevatedBinary(FieldValue(event, field::kImage))) return;

    const uint32_t count = DistinctRecentKeys(now);
    if (count < m_minDistinctKeys) return;

    std::vector<std::string> keys;
    for (const auto& entry : m_recentKeys) {
        if (keys.size() >= 8) break;
        keys.push_back(entry.first);
    }
    std::sort(keys.begin(), keys.end());
    const uint32_t score = std::min(100u, count * 35u + 20u);
    WriteState(event, count, score, keys);
}

} // namespace edr
