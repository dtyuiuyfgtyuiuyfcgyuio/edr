/*
 * rdp_chain_detector.cpp - See rdp_chain_detector.h.
 */
#include "rdp_chain_detector.h"

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

RdpChainDetector::RdpChainDetector(bool enabled, uint32_t windowSeconds,
                                   size_t stateCapacity,
                                   uint32_t minDistinctSources)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minDistinctSources(std::max<uint32_t>(1, minDistinctSources)) {}

bool RdpChainDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_RDP_SESSION;
}

void RdpChainDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_sessions.begin(); it != m_sessions.end();) {
        SessionState& state = it->second;
        for (auto src = state.sources.begin(); src != state.sources.end();) {
            if (now100ns >= src->second.lastSeen100ns &&
                now100ns - src->second.lastSeen100ns > m_window100ns) {
                src = state.sources.erase(src);
            } else {
                ++src;
            }
        }
        if (state.sources.empty()) {
            it = m_sessions.erase(it);
        } else {
            ++it;
        }
    }
}

void RdpChainDetector::WriteState(Event& event, const SessionState& state) {
    std::vector<std::string> sources;
    for (const auto& entry : state.sources) {
        if (sources.size() >= 6) break;
        sources.push_back(entry.first);
    }
    std::sort(sources.begin(), sources.end());

    std::string joined;
    for (const std::string& source : sources) {
        if (!joined.empty()) joined += ",";
        joined += source;
    }

    const uint32_t count = static_cast<uint32_t>(state.sources.size());
    const uint32_t score = std::min(100u, count * 20u + 15u);
    event.fields[field::kRdpChainScore] = std::to_string(score);
    event.fields[field::kRdpChainCount] = std::to_string(count);
    event.fields[field::kRdpChainSources] = joined;
    event.fields[field::kRdpChainWindowSeconds] = std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) event.fields[field::kRdpChainVerdict] = verdict;
}

void RdpChainDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_RDP_SESSION) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    std::string source = FieldValue(event, field::kRdpSourceIp);
    std::string user = FieldValue(event, field::kRdpUser);
    std::string action = LowerAscii(FieldValue(event, field::kRdpAction));
    if (source.empty() && user.empty()) return;
    if (action != "logon" && action != "reconnect" && action != "auth_success")
        return;

    /* Correlate per user (domain+user when available) so distinct source
     * addresses accumulate for the same account. Anonymous sessions stay
     * separate by source address. */
    const std::string domain = FieldValue(event, field::kRdpDomain);
    const std::string key =
        user.empty() ? ("src:" + source)
                     : (domain.empty() ? user : domain + "\\" + user);
    SessionState& state = m_sessions[key];
    auto existing = state.sources.find(source);
    if (existing == state.sources.end()) {
        SourceInfo info;
        info.lastSeen100ns = now;
        state.sources.emplace(source, info);
    } else {
        existing->second.lastSeen100ns = now;
    }
    state.lastSeen100ns = now;

    const uint32_t count = static_cast<uint32_t>(state.sources.size());
    if (count >= m_minDistinctSources && count > state.lastFlaggedCount) {
        state.lastFlaggedCount = count;
        WriteState(event, state);
    }

    EvictOldest(m_sessions, m_stateCapacity);
}

} // namespace edr
