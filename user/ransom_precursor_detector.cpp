/*
 * ransom_precursor_detector.cpp - See ransom_precursor_detector.h.
 *
 * Host-wide correlation of recognized anti-recovery PROCESS_START commands.
 * Techniques expire with the window. Time rollback is rejected. The stamp
 * re-emits when the distinct-technique count grows, or after the dedup
 * interval if the count is still at or above the threshold.
 */
#include "ransom_precursor_detector.h"

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

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
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

std::string ClassifyRansomPrecursor(const std::string& image,
                                    const std::string& commandLine) {
    const std::string name = BaseName(image);
    const std::string cmd = LowerAscii(commandLine);

    if (name == "vssadmin.exe") {
        if (Contains(cmd, "delete") && Contains(cmd, "shadow"))
            return "shadow_delete";
        if (Contains(cmd, "resize") && Contains(cmd, "shadowstorage"))
            return "shadow_resize";
        return "";
    }
    if (name == "wmic.exe" || name == "wmic") {
        if (Contains(cmd, "shadowcopy") && Contains(cmd, "delete"))
            return "shadow_delete";
        return "";
    }
    if (name == "powershell.exe" || name == "pwsh.exe") {
        if (Contains(cmd, "win32_shadowcopy") && Contains(cmd, "delete"))
            return "shadow_delete";
        return "";
    }
    if (name == "wbadmin.exe") {
        if (Contains(cmd, "delete") &&
            (Contains(cmd, "catalog") || Contains(cmd, "systemstatebackup") ||
             Contains(cmd, "backup")))
            return "backup_delete";
        return "";
    }
    if (name == "bcdedit.exe") {
        if (Contains(cmd, "recoveryenabled") && Contains(cmd, "no"))
            return "recovery_disable";
        if (Contains(cmd, "bootstatuspolicy") &&
            Contains(cmd, "ignoreallfailures"))
            return "recovery_disable";
        return "";
    }
    if (name == "wevtutil.exe") {
        if (Contains(cmd, "clear-log") || Contains(cmd, "clearlog"))
            return "log_clear";
        if (Contains(cmd, " cl ") || Contains(cmd, "\tcl ") ||
            Contains(cmd, " cl\t") || Contains(cmd, "\tcl\t"))
            return "log_clear";
        if (cmd.size() >= 3 && cmd.compare(cmd.size() - 3, 3, " cl") == 0)
            return "log_clear";
        return "";
    }
    if (name == "fsutil.exe") {
        if (Contains(cmd, "usn") && Contains(cmd, "deletejournal"))
            return "usn_delete";
        return "";
    }
    if (name == "cipher.exe") {
        if (Contains(cmd, "/w") || Contains(cmd, "-w"))
            return "free_space_wipe";
        return "";
    }
    return "";
}

RansomPrecursorDetector::RansomPrecursorDetector(
    bool enabled, uint32_t windowSeconds, size_t stateCapacity,
    uint32_t minTechniques, uint32_t dedupSeconds)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minTechniques(std::max<uint32_t>(2, minTechniques)),
      m_dedup100ns(static_cast<uint64_t>(dedupSeconds) *
                   kFiletimeTicksPerSecond) {}

bool RansomPrecursorDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

void RansomPrecursorDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        KeyState& state = it->second;
        for (auto tech = state.techniques.begin();
             tech != state.techniques.end();) {
            if (now100ns >= tech->second.lastSeen100ns &&
                now100ns - tech->second.lastSeen100ns > m_window100ns)
                tech = state.techniques.erase(tech);
            else
                ++tech;
        }
        if (state.techniques.empty())
            it = m_keys.erase(it);
        else
            ++it;
    }
}

void RansomPrecursorDetector::WriteState(Event& event,
                                         const KeyState& state) {
    std::vector<std::string> techniques;
    for (const auto& entry : state.techniques)
        techniques.push_back(entry.first);
    std::sort(techniques.begin(), techniques.end());

    std::string joined;
    for (const std::string& technique : techniques) {
        if (!joined.empty()) joined += ",";
        joined += technique;
    }

    const uint32_t count = static_cast<uint32_t>(techniques.size());
    event.fields[field::kRansomPrecursorScore] =
        std::to_string(std::min(100u, count * 35u));
    event.fields[field::kRansomPrecursorTechniques] = joined;
    event.fields[field::kRansomPrecursorCount] = std::to_string(count);
    event.fields[field::kRansomPrecursorWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void RansomPrecursorDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_PROCESS_START) return;

    const std::string technique = ClassifyRansomPrecursor(
        FieldValue(event, field::kImage),
        FieldValue(event, field::kCommandLine));
    if (technique.empty()) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    /* Host-wide: ransomware launches several signed binaries. */
    KeyState& state = m_keys["host"];
    if (state.lastSeen100ns != 0 && now < state.lastSeen100ns)
        return; /* reject time rollback; do not borrow future evidence */
    state.lastSeen100ns = now;
    state.techniques[technique].lastSeen100ns = now;
    EvictOldest(m_keys, m_stateCapacity);

    const uint32_t count = static_cast<uint32_t>(state.techniques.size());
    if (count < m_minTechniques) return;

    const bool grew = count > state.lastFlaggedCount;
    const bool cooled =
        state.lastStamp100ns == 0 ||
        (now >= state.lastStamp100ns &&
         now - state.lastStamp100ns >= m_dedup100ns);
    if (!grew && !cooled) return;

    WriteState(event, state);
    state.lastFlaggedCount = count;
    state.lastStamp100ns = now;
}

} // namespace edr
