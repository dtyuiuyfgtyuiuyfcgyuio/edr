/*
 * nonstandard_port_egress_detector.cpp - See
 * nonstandard_port_egress_detector.h for the scoring model and rationale.
 *
 * Per (pid, image basename) key, distinct destination IPs and ports plus a
 * connection count are accumulated inside a rolling window and turned into
 * shape signals. The current event is stamped with:
 *   nonstandard_port_score           = capped signal sum, never below 55
 *   nonstandard_port_verdict         = malicious at 75+, else suspicious
 *   nonstandard_port_signals         = comma-joined signal names
 *   nonstandard_port_host_count      = distinct destinations in window
 *   nonstandard_port_port_count      = distinct destination ports in window
 *   nonstandard_port_connection_count= connections in window
 *
 * Loopback and wildcard destinations are ignored, as is port 0. A key is
 * stamped at most once per dedup window, so a sustained shape does not
 * restamp every connection.
 */
#include "nonstandard_port_egress_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {
namespace {

constexpr uint32_t kSuspiciousFloor = 55;
constexpr size_t kMaxDistinctHosts = 256;
constexpr size_t kMaxDistinctPorts = 128;

/* Ports that never raise the unusual_port signal on their own. A process
 * can still score through the breadth and volume signals while using one
 * of these. */
bool IsWellKnownPort(int port) {
    static const int kWellKnown[] = {
        21,  22,  25,  53,   80,  110,  123,  143,  389,  443,  445,
        465, 587, 993, 995,  3306, 3389, 5432, 5985, 5986, 6379, 8080,
        8443, 27017};
    for (int known : kWellKnown) {
        if (known == port) return true;
    }
    return false;
}

/* Classic raw-transport and beacon ports (T1095). 8443 is absent here:
 * it is on the well-known list, so it only counts as raw when the
 * transport itself is already a raw protocol. */
bool IsRawPort(int port) {
    switch (port) {
        case 1337:
        case 4444:
        case 5555:
        case 6666:
        case 31337:
            return true;
        default:
            return false;
    }
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool Contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

/* Accepts "443" and "443/tcp" alike: parse the leading integer and ignore
 * any transport suffix. Returns 0 when no leading digits are present. */
int ParsePort(const std::string& value) {
    size_t index = 0;
    while (index < value.size() && (value[index] == ' ' || value[index] == '\t'))
        ++index;
    if (index >= value.size() || value[index] < '0' || value[index] > '9')
        return 0;
    unsigned long parsed = 0;
    while (index < value.size() && value[index] >= '0' &&
           value[index] <= '9') {
        parsed = parsed * 10ul + static_cast<unsigned long>(value[index] - '0');
        if (parsed > 65535ul) return 0;
        ++index;
    }
    if (parsed == 0ul) return 0;
    return static_cast<int>(parsed);
}

/* The ETW collector emits "tcp"/"udp" for every connection, so the token
 * alone says nothing. Only transports that are plainly not HTTP, TLS or
 * DNS count here; "raw" and similar explicit markers do. */
bool IsRawProtocol(const std::string& protocol) {
    const std::string lower = LowerAscii(protocol);
    if (lower.empty()) return false;
    if (Contains(lower, "http") || Contains(lower, "https") ||
        Contains(lower, "tls") || Contains(lower, "ssl") ||
        Contains(lower, "dns") || Contains(lower, "quic") ||
        Contains(lower, "ws") || Contains(lower, "smb"))
        return false;
    if (Contains(lower, "tcp") || Contains(lower, "udp")) return false;
    return true;
}

bool IsLocalDestination(const std::string& ip) {
    if (ip.empty() || ip == "0.0.0.0" || ip == "::" || ip == "::1")
        return true;
    if (ip.size() >= 4 && ip.compare(0, 4, "127.") == 0) return true;
    return false;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

} // namespace

NonstandardPortEgressDetector::NonstandardPortEgressDetector(
    bool enabled, uint32_t minScore, uint32_t windowSeconds,
    uint32_t dedupWindowSeconds, size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

/* static */
bool NonstandardPortEgressDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_NET_CONNECT;
}

void NonstandardPortEgressDetector::ResetWindow(ActorState& state,
                                                uint64_t now100ns) const {
    state.hosts.clear();
    state.ports.clear();
    state.connections = 0;
    state.unusualPortSeen = false;
    state.rawProtocolSeen = false;
    state.windowStart100ns = now100ns;
    state.lastSeen100ns = now100ns;
}

void NonstandardPortEgressDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_actors.begin(); it != m_actors.end();) {
        ActorState& state = it->second;
        if (now100ns >= state.lastSeen100ns &&
            now100ns - state.lastSeen100ns > m_window100ns) {
            it = m_actors.erase(it);
            continue;
        }
        if (now100ns >= state.windowStart100ns &&
            now100ns - state.windowStart100ns > m_window100ns)
            ResetWindow(state, now100ns);
        ++it;
    }
}

void NonstandardPortEgressDetector::Stamp(Event& event, uint32_t score,
                                           const std::string& signals,
                                           const ActorState& state) const {
    event.fields[field::kNonstandardPortScore] = std::to_string(score);
    event.fields[field::kNonstandardPortVerdict] =
        score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kNonstandardPortSignals] = signals;
    event.fields[field::kNonstandardPortHostCount] =
        std::to_string(static_cast<uint32_t>(state.hosts.size()));
    event.fields[field::kNonstandardPortPortCount] =
        std::to_string(static_cast<uint32_t>(state.ports.size()));
    event.fields[field::kNonstandardPortConnectionCount] =
        std::to_string(state.connections);
}

void NonstandardPortEgressDetector::Enrich(Event& event) {
    if (!m_enabled || event.pid == 0) return;
    if (event.type != EDR_EVT_NET_CONNECT) return;

    const uint64_t now = EventTime(event);
    /* Sweep before touching this event's key so no reference is held
     * across an erase below. */
    PurgeExpired(now);

    const std::string ip = FieldValue(event, field::kDstIp);
    if (IsLocalDestination(ip)) return;
    const int port = ParsePort(FieldValue(event, field::kDstPort));
    if (port == 0) return;

    const std::string image = BaseName(FieldValue(event, field::kImage));
    const std::string key = std::to_string(event.pid) + "@" + image;

    /* Reject out-of-order timestamps before they can poison the window. */
    auto existing = m_actors.find(key);
    if (existing != m_actors.end() && now < existing->second.lastSeen100ns)
        return;

    /* Capacity: reset the whole map rather than growing without bound.
     * Egress shape is cheap to rebuild from the next few connections. */
    if (m_actors.size() > m_stateCapacity) {
        std::fprintf(stderr,
            "[edr-nonstandard-port] actor capacity %zu reached; "
            "egress shape state reset\n",
            m_stateCapacity);
        m_actors.clear();
        existing = m_actors.end();
    }

    ActorState& state = m_actors[key];
    if (state.windowStart100ns == 0) ResetWindow(state, now);

    if (state.hosts.size() < kMaxDistinctHosts) state.hosts.insert(ip);
    if (state.ports.size() < kMaxDistinctPorts) state.ports.insert(port);
    if (state.connections < 1000000u) ++state.connections;
    state.lastSeen100ns = now;

    if (!IsWellKnownPort(port)) state.unusualPortSeen = true;
    if (IsRawProtocol(FieldValue(event, field::kProtocol)) || IsRawPort(port))
        state.rawProtocolSeen = true;

    uint32_t score = 0;
    std::string signals;
    auto AddSignal = [&](const char* name, uint32_t weight) {
        if (!signals.empty()) signals += ",";
        signals += name;
        score = std::min(100u, score + weight);
    };

    if (state.unusualPortSeen) AddSignal("unusual_port", 25);
    if (state.hosts.size() >= 5) AddSignal("many_hosts", 25);
    if (state.ports.size() >= 4) AddSignal("many_ports", 20);
    if (state.rawProtocolSeen) AddSignal("raw_protocol", 25);
    if (state.connections >= 12) AddSignal("high_volume", 15);

    /* Breadth without a non-standard port or raw transport is a fan-out
     * floor of 55, so many_hosts + many_ports alone stays SUSPICIOUS while
     * high_volume alone (+15) never reaches the band. */
    if (state.hosts.size() >= 5 && state.ports.size() >= 4 && score < 55)
        score = kSuspiciousFloor;

    if (score < kSuspiciousFloor) return;
    if (score > 100u) score = 100u;
    if (score < m_minScore) return;

    /* Restamp only when the shape widened or the dedup window cooled. */
    const bool widened = score > state.lastStampScore;
    const bool cooled = state.lastStamp100ns == 0 ||
                        (now >= state.lastStamp100ns &&
                         now - state.lastStamp100ns >= m_dedupWindow100ns);
    if (!widened && !cooled) return;

    Stamp(event, score, signals, state);
    state.lastStampScore = score;
    state.lastStamp100ns = now;
}

} // namespace edr
