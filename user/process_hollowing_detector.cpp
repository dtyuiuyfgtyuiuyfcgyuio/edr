/*
 * process_hollowing_detector.cpp - See process_hollowing_detector.h.
 *
 * Qualification gate: the image must be a full path (contain a backslash;
 * basename-only images from process polling are skipped so they cannot
 * false-positive), the basename must end with ".exe", and the basename must
 * be one of the protected system binary names. Scoring: +55 when the image
 * is outside the trusted system directory prefixes (outside_system_dir),
 * +25 when it sits in a user-writable location (user_writable_path), and
 * +20 when at least one of the first two fired and the parent image
 * basename is a known unusual launcher (unusual_parent; booster only, never
 * triggers alone). Capped at 100. The event is stamped only when the score
 * reaches minScore, and the same pid@lowercase-full-path key is not
 * re-stamped within the dedup window (the default suppresses duplicate
 * reports of one process from the ETW and driver sources).
 */
#include "process_hollowing_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
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

std::string Join(const std::vector<std::string>& values,
                 const char* separator) {
    std::string result;
    for (const std::string& value : values) {
        if (!result.empty()) result += separator;
        result += value;
    }
    return result;
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

bool HasPathSeparator(const std::string& value) {
    return value.find('\\') != std::string::npos;
}

bool IsProtectedName(const std::string& base) {
    static const std::set<std::string> names = {
        "svchost.exe", "conhost.exe", "dllhost.exe", "taskhostw.exe",
        "runtimebroker.exe", "securityhealthservice.exe", "lsass.exe",
        "winlogon.exe", "services.exe", "csrss.exe", "smss.exe",
        "wininit.exe", "spoolsv.exe"
    };
    return names.count(base) != 0;
}

bool IsUnderSystemDirectory(const std::string& lowerImage) {
    static const char* const kPrefixes[] = {
        "c:\\windows\\system32\\", "c:/windows/system32/",
        "c:\\windows\\syswow64\\", "c:/windows/syswow64/",
        "c:\\windows\\winsxs\\",   "c:/windows/winsxs/"
    };
    for (const char* prefix : kPrefixes) {
        const size_t length = std::strlen(prefix);
        if (lowerImage.size() >= length &&
            lowerImage.compare(0, length, prefix) == 0)
            return true;
    }
    return false;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (value.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool IsUserWritableLocation(const std::string& lowerImage) {
    if (lowerImage.find("\\users\\") != std::string::npos &&
        ContainsAny(lowerImage, {"\\appdata\\", "\\downloads\\",
                                 "\\desktop\\"}))
        return true;
    return ContainsAny(lowerImage, {"\\windows\\temp\\", "c:\\temp\\",
                                    "\\programdata\\"});
}

bool IsSuspiciousParent(const std::string& parentBase) {
    static const std::set<std::string> names = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
        "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "powershell.exe", "pwsh.exe", "cmd.exe"
    };
    return names.count(parentBase) != 0;
}

} // namespace

ProcessHollowingDetector::ProcessHollowingDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool ProcessHollowingDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

void ProcessHollowingDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_dedupWindow100ns)
            it = m_keys.erase(it);
        else
            ++it;
    }
}

void ProcessHollowingDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (event.pid == 0) return;

    const std::string image = FieldValue(event, field::kImage);
    if (!HasPathSeparator(image)) return;
    const std::string base = BaseName(image);
    if (base.size() < 4 ||
        base.compare(base.size() - 4, 4, ".exe") != 0)
        return;
    if (!IsProtectedName(base)) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string lowerImage = LowerAscii(image);
    const std::string key = std::to_string(event.pid) + "@" + lowerImage;
    if (m_keys.find(key) != m_keys.end()) return;

    const std::string parentBase =
        BaseName(FieldValue(event, field::kParentImage));

    uint32_t score = 0;
    std::vector<std::string> reasons;
    const bool outsideSystemDir = !IsUnderSystemDirectory(lowerImage);
    if (outsideSystemDir) {
        score += 55;
        reasons.push_back("outside_system_dir");
    }
    const bool userWritable = IsUserWritableLocation(lowerImage);
    if (userWritable) {
        score += 25;
        reasons.push_back("user_writable_path");
    }
    if ((outsideSystemDir || userWritable) && !parentBase.empty() &&
        IsSuspiciousParent(parentBase)) {
        score += 20;
        reasons.push_back("unusual_parent");
    }
    if (score > 100) score = 100;
    if (score < m_minScore) return;

    event.fields[field::kHollowScore] = std::to_string(score);
    event.fields[field::kHollowReasons] = Join(reasons, ",");
    event.fields[field::kHollowBase] = base;
    event.fields[field::kHollowPath] = image;
    event.fields[field::kHollowParent] = parentBase;

    KeyState state;
    state.lastSeen100ns = now;
    m_keys[key] = state;
    EvictOldest(m_keys, m_stateCapacity);
}

} // namespace edr
