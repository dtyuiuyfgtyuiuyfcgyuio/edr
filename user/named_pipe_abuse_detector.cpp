/* named_pipe_abuse_detector.cpp - See named_pipe_abuse_detector.h. */
#include "named_pipe_abuse_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <limits>
#include <string>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string FieldValue(const Event& event, const char* name) {
    const auto it = event.fields.find(name);
    return it == event.fields.end() ? std::string() : it->second;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           static_cast<uint64_t>(now.dwLowDateTime);
}

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool IsGuidLike(const std::string& value) {
    const bool braced = value.size() == 38 && value.front() == '{' &&
                        value.back() == '}';
    const size_t offset = braced ? 1 : 0;
    if ((!braced && value.size() != 36) ||
        (braced && value.size() != 38) ||
        value[offset + 8] != '-' || value[offset + 13] != '-' ||
        value[offset + 18] != '-' || value[offset + 23] != '-')
        return false;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) continue;
        const unsigned char c = static_cast<unsigned char>(value[offset + i]);
        if (!std::isxdigit(c)) return false;
    }
    return true;
}

double Entropy(const std::string& value) {
    if (value.empty()) return 0.0;
    unsigned counts[256] = {};
    for (unsigned char c : value) ++counts[c];
    double entropy = 0.0;
    for (unsigned count : counts) {
        if (count == 0) continue;
        const double probability = static_cast<double>(count) /
                                   static_cast<double>(value.size());
        entropy -= probability * std::log2(probability);
    }
    return entropy;
}

void AddSignal(std::string* signals, const char* signal) {
    if (!signals->empty()) signals->append(",");
    signals->append(signal);
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    while (map.size() > capacity) {
        auto oldest = std::min_element(map.begin(), map.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastSeen100ns < right.second.lastSeen100ns;
            });
        if (oldest == map.end()) break;
        map.erase(oldest);
    }
}

uint32_t NameScore(const std::string& name, std::string* signals) {
    uint32_t score = 0;
    static constexpr const char* kToolMarkers[] = {
        "meterpreter", "cobalt", "beacon", "remcom", "psexec",
        "paexec", "impacket", "smbexec", "postex", "winrmexec",
        "bindshell", "reverse", "payload"
    };
    for (const char* marker : kToolMarkers) {
        if (Contains(name, marker)) {
            score += 75;
            AddSignal(signals, "known_tool_pipe_name");
            break;
        }
    }
    if (IsGuidLike(name)) {
        score += 50;
        AddSignal(signals, "guid_pipe_name");
    }
    if (name.size() >= 16 && Entropy(name) >= 3.8) {
        score += 35;
        AddSignal(signals, "high_entropy_pipe_name");
    }
    return std::min<uint32_t>(score, 100);
}

} // namespace

NamedPipeAbuseDetector::NamedPipeAbuseDetector(
        bool enabled, uint32_t minScore, uint32_t windowSeconds,
        size_t stateCapacity, uint32_t minDistinctPids,
        uint32_t dedupWindowSeconds)
    : m_enabled(enabled),
      m_minScore(std::max<uint32_t>(1, std::min<uint32_t>(100, minScore))),
      m_windowSeconds(std::max<uint32_t>(1, windowSeconds)),
      m_window100ns(static_cast<uint64_t>(std::max<uint32_t>(1, windowSeconds)) *
                    kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minDistinctPids(std::max<uint32_t>(2, minDistinctPids)),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond) {}

bool NamedPipeAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_NAMED_PIPE;
}

void NamedPipeAbuseDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_states.begin(); it != m_states.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_states.erase(it);
        else
            ++it;
    }
}

void NamedPipeAbuseDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_NAMED_PIPE) return;

    const std::string pipe = LowerAscii(FieldValue(event, field::kPipeName));
    if (pipe.empty()) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    /* Make room before inserting a new key. Evicting after taking a
     * reference could erase this state and leave a dangling reference. */
    auto stateIt = m_states.find(pipe);
    if (stateIt == m_states.end()) {
        if (m_states.size() >= m_stateCapacity)
            EvictOldest(m_states, m_stateCapacity - 1);
        stateIt = m_states.emplace(pipe, State{}).first;
    }
    State& state = stateIt->second;
    state.lastSeen100ns = now;
    if (++state.operationCount == 0) state.operationCount =
        std::numeric_limits<uint32_t>::max();
    const std::string operation = LowerAscii(FieldValue(event, field::kPipeOperation));
    if (operation == "connected" || operation == "connect") {
        if (state.connectedCount != std::numeric_limits<uint32_t>::max())
            ++state.connectedCount;
    }
    const std::string pid = FieldValue(event, field::kPid);
    if (!pid.empty() && state.pids.size() < 256) state.pids.insert(pid);

    std::string signals;
    uint32_t score = NameScore(pipe, &signals);
    if (state.connectedCount >= 2) {
        score += 15;
        AddSignal(&signals, "repeated_pipe_connections");
    }
    if (state.pids.size() >= m_minDistinctPids) {
        score += 25;
        AddSignal(&signals, "cross_process_pipe_activity");
    }
    if (state.operationCount >= 8) {
        score += 10;
        AddSignal(&signals, "pipe_activity_burst");
    }
    score = std::min<uint32_t>(100, score);
    if (score < m_minScore || signals.empty()) return;
    if (state.lastAlert100ns != 0 && m_dedupWindow100ns != 0 &&
        now >= state.lastAlert100ns &&
        now - state.lastAlert100ns < m_dedupWindow100ns)
        return;

    event.fields[field::kNamedPipeAbuseScore] = std::to_string(score);
    event.fields[field::kNamedPipeAbuseVerdict] =
        score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kNamedPipeAbuseSignals] = signals;
    event.fields[field::kNamedPipeAbuseOperationCount] =
        std::to_string(state.operationCount);
    event.fields[field::kNamedPipeAbuseDistinctPids] =
        std::to_string(state.pids.size());
    event.fields[field::kNamedPipeAbuseWindowSeconds] =
        std::to_string(m_windowSeconds);
    state.lastAlert100ns = now;
}

} // namespace edr
