/*
 * lateral_movement_detector.cpp - See lateral_movement_detector.h.
 *
 * Per attribution key, NET_CONNECT events to lateral-movement ports are
 * counted per distinct destination IP in a rolling window. When at least
 * minDestCount distinct destination IPs are reached, the current event is
 * stamped with:
 *   lateral_move_score       = min(100, destCount * scorePerDest)
 *   lateral_move_dest_count  = number of distinct destination IPs
 *   lateral_move_ports       = comma-separated distinct matched port numbers
 *   lateral_move_window_seconds
 *
 * Loopback destinations (127.*) are excluded; all other IPs (including
 * private RFC-1918 ranges) are counted.
 */
#include "lateral_movement_detector.h"

#include <windows.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

/* Lateral movement port set (T1021 technique coverage). */
constexpr uint16_t kLateralPorts[] = {
    22,    /* SSH */
    23,    /* Telnet */
    135,   /* RPC/DCE endpoint mapper */
    139,   /* NetBIOS session */
    445,   /* SMB */
    3389,  /* RDP */
    5900,  /* VNC */
    5985,  /* WinRM HTTP */
    5986,  /* WinRM HTTPS */
};

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    std::string base = slash == std::string::npos ? value : value.substr(slash + 1);
    for (char& c : base) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return base;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Join(const std::set<std::string>& values, const char* sep) {
    std::string result;
    for (const std::string& v : values) {
        if (!result.empty()) result += sep;
        result += v;
    }
    return result;
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    if (map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& a, const auto& b) {
            return a.second.lastSeen100ns < b.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

} // namespace

LateralMovementDetector::LateralMovementDetector(bool enabled,
                                                 uint32_t windowSeconds,
                                                 size_t stateCapacity,
                                                 uint32_t minDestCount,
                                                 uint32_t scorePerDest)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minDestCount(minDestCount),
      m_scorePerDest(scorePerDest) {}

bool LateralMovementDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_NET_CONNECT;
}

/* Returns true and sets portOut if portStr is a watched lateral port. */
bool LateralMovementDetector::IsLateralPort(const std::string& portStr,
                                            std::string& portOut) {
    if (portStr.empty()) return false;
    int port = 0;
    try { port = std::stoi(portStr); } catch (...) { return false; }
    for (uint16_t p : kLateralPorts) {
        if (port == static_cast<int>(p)) {
            portOut = std::to_string(p);
            return true;
        }
    }
    return false;
}

bool LateralMovementDetector::IsLoopback(const std::string& ip) {
    return ip.size() >= 4 && ip.substr(0, 4) == "127.";
}

void LateralMovementDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_keys.erase(it);
        else
            ++it;
    }
}

void LateralMovementDetector::WriteState(Event& event,
                                         const KeyState& state) {
    const uint32_t count = static_cast<uint32_t>(state.destIps.size());
    const uint32_t score = std::min(100u, count * m_scorePerDest);
    event.fields[field::kLateralMoveScore] = std::to_string(score);
    event.fields[field::kLateralMoveDestCount] = std::to_string(count);
    event.fields[field::kLateralMovePorts] = Join(state.ports, ",");
    event.fields[field::kLateralMoveWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void LateralMovementDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    /* Only process connections to lateral-movement ports. */
    const std::string portStr = FieldValue(event, field::kDstPort);
    std::string matchedPort;
    if (!IsLateralPort(portStr, matchedPort)) return;

    const std::string destIp = FieldValue(event, field::kDstIp);
    if (destIp.empty() || IsLoopback(destIp)) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string image = FieldValue(event, field::kImage);

    std::string key;
    if (event.pid > 0 && !image.empty()) {
        key = "pid:" + std::to_string(event.pid) + "@" + BaseName(image);
    } else if (!image.empty()) {
        key = "img:" + BaseName(image);
    } else {
        return; /* No attribution possible. */
    }

    KeyState& state = m_keys[key];
    state.destIps.insert(destIp);
    state.ports.insert(matchedPort);
    state.lastSeen100ns = now;

    if (!state.flagged &&
        state.destIps.size() >= m_minDestCount) {
        state.flagged = true;
        WriteState(event, state);
    }

    EvictOldest(m_keys, m_stateCapacity);
}

} // namespace edr
