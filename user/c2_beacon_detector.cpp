/*
 * c2_beacon_detector.cpp - See c2_beacon_detector.h.
 *
 * Per (pid, image basename) key, NET_CONNECT destinations are counted within
 * a rolling window. When at least minRepeatEndpoints distinct endpoints each
 * show at least minConnectionsPerEndpoint connections, the current event is
 * stamped with c2_beacon_score (min(100, repeatCount*20)),
 * c2_beacon_repeat_connections, c2_beacon_destinations (first 6 repeated
 * endpoints), and c2_beacon_window_seconds. Each key is flagged once per
 * window; when all of its endpoints expire the key is dropped so the flag
 * resets and the threshold must be re-met before fields are emitted again.
 */
#include "c2_beacon_detector.h"

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

} // namespace

C2BeaconDetector::C2BeaconDetector(bool enabled, uint32_t windowSeconds,
                                   size_t stateCapacity,
                                   uint32_t minRepeatEndpoints,
                                   uint32_t minConnectionsPerEndpoint)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minRepeatEndpoints(minRepeatEndpoints),
      m_minConnectionsPerEndpoint(minConnectionsPerEndpoint) {}

bool C2BeaconDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_NET_CONNECT;
}

void C2BeaconDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        KeyState& state = it->second;
        for (auto ep = state.endpoints.begin(); ep != state.endpoints.end();) {
            if (now100ns >= ep->second.lastSeen100ns &&
                now100ns - ep->second.lastSeen100ns > m_window100ns)
                ep = state.endpoints.erase(ep);
            else
                ++ep;
        }
        if (state.endpoints.empty())
            it = m_keys.erase(it);
        else
            ++it;
    }
}

void C2BeaconDetector::WriteState(Event& event, const KeyState& state) {
    uint32_t repeatCount = 0;
    std::vector<std::string> destinations;
    for (const auto& entry : state.endpoints) {
        if (entry.second.count >= m_minConnectionsPerEndpoint) {
            ++repeatCount;
            if (destinations.size() < 6)
                destinations.push_back(entry.first);
        }
    }
    event.fields[field::kC2BeaconScore] =
        std::to_string(std::min(100u, repeatCount * 20u));
    event.fields[field::kC2BeaconRepeatConnections] =
        std::to_string(repeatCount);
    event.fields[field::kC2BeaconDestinations] = Join(destinations, ",");
    event.fields[field::kC2BeaconWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void C2BeaconDetector::Enrich(Event& event) {
    if (!m_enabled || event.pid == 0) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string image = BaseName(FieldValue(event, field::kImage));
    const std::string key = std::to_string(event.pid) + "@" + image;

    const std::string ip = FieldValue(event, field::kDstIp);
    const std::string port = FieldValue(event, field::kDstPort);
    if (ip.empty() || ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" ||
        port.empty() || port == "0")
        return;

    const std::string endpoint = ip + ":" + port;

    KeyState& state = m_keys[key];
    auto existing = state.endpoints.find(endpoint);
    if (existing == state.endpoints.end()) {
        EndpointInfo info;
        info.count = 1;
        info.lastSeen100ns = now;
        state.endpoints.emplace(endpoint, info);
    } else {
        ++existing->second.count;
        existing->second.lastSeen100ns = now;
    }
    state.lastSeen100ns = now;

    uint32_t repeatCount = 0;
    for (const auto& entry : state.endpoints) {
        if (entry.second.count >= m_minConnectionsPerEndpoint)
            ++repeatCount;
    }

    if (!state.flagged && repeatCount >= m_minRepeatEndpoints) {
        state.flagged = true;
        WriteState(event, state);
    }

    EvictOldest(m_keys, m_stateCapacity);
}

} // namespace edr