/*
 * port_scan_detector.cpp - See port_scan_detector.h.
 *
 * Per (pid, image basename) key, distinct destination ports are counted
 * per destination IP in a rolling window. When any IP reaches
 * minDistinctPorts, the current event is stamped with:
 *   port_scan_score         = min(100, portCount * 4)
 *   port_scan_port_count    = distinct ports on that IP
 *   port_scan_target        = the scanned destination IP
 *   port_scan_sample_ports  = first 8 port numbers, comma-separated
 *   port_scan_window_seconds
 *
 * Loopback destinations and port 0 are excluded. Each key is flagged once
 * per window; when all of its destinations expire the key is dropped so
 * the flag resets.
 */
#include "port_scan_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
constexpr size_t kMaxPortsPerDest = 256;
constexpr size_t kSamplePortLimit = 8;

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

bool ParsePort(const std::string& value, uint16_t& port) {
    if (value.empty() || value.size() > 5) return false;
    unsigned long parsed = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        parsed = parsed * 10u + static_cast<unsigned long>(c - '0');
        if (parsed > 65535ul) return false;
    }
    if (parsed == 0ul) return false;
    port = static_cast<uint16_t>(parsed);
    return true;
}

bool IsLoopback(const std::string& ip) {
    if (ip.empty() || ip == "0.0.0.0" || ip == "::" || ip == "::1")
        return true;
    if (ip.size() >= 4 && ip.compare(0, 4, "127.") == 0) return true;
    return false;
}

std::string JoinPorts(const std::set<uint16_t>& ports, size_t limit) {
    std::string result;
    size_t n = 0;
    for (uint16_t port : ports) {
        if (n >= limit) break;
        if (!result.empty()) result += ',';
        result += std::to_string(port);
        ++n;
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

} // namespace

PortScanDetector::PortScanDetector(bool enabled, uint32_t windowSeconds,
                                   size_t stateCapacity,
                                   uint32_t minDistinctPorts)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minDistinctPorts(minDistinctPorts) {}

bool PortScanDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_NET_CONNECT;
}

void PortScanDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        KeyState& state = it->second;
        for (auto dest = state.dests.begin(); dest != state.dests.end();) {
            if (now100ns >= dest->second.lastSeen100ns &&
                now100ns - dest->second.lastSeen100ns > m_window100ns)
                dest = state.dests.erase(dest);
            else
                ++dest;
        }
        if (state.dests.empty())
            it = m_keys.erase(it);
        else
            ++it;
    }
}

void PortScanDetector::WriteState(Event& event, const std::string& targetIp,
                                  const DestState& dest) {
    const uint32_t count = static_cast<uint32_t>(dest.ports.size());
    event.fields[field::kPortScanScore] =
        std::to_string(std::min(100u, count * 4u));
    event.fields[field::kPortScanPortCount] = std::to_string(count);
    event.fields[field::kPortScanTarget] = targetIp;
    event.fields[field::kPortScanSamplePorts] =
        JoinPorts(dest.ports, kSamplePortLimit);
    event.fields[field::kPortScanWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void PortScanDetector::Enrich(Event& event) {
    if (!m_enabled || event.pid == 0) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string ip = FieldValue(event, field::kDstIp);
    uint16_t port = 0;
    if (IsLoopback(ip) ||
        !ParsePort(FieldValue(event, field::kDstPort), port))
        return;

    const std::string image = BaseName(FieldValue(event, field::kImage));
    const std::string key = std::to_string(event.pid) + "@" + image;

    KeyState& state = m_keys[key];
    DestState& dest = state.dests[ip];
    if (dest.ports.size() < kMaxPortsPerDest)
        dest.ports.insert(port);
    dest.lastSeen100ns = now;
    state.lastSeen100ns = now;

    if (!state.flagged && dest.ports.size() >= m_minDistinctPorts) {
        state.flagged = true;
        WriteState(event, ip, dest);
    }

    EvictOldest(m_keys, m_stateCapacity);
}

} // namespace edr
