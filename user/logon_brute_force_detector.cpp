/*
 * logon_brute_force_detector.cpp - See logon_brute_force_detector.h.
 *
 * Per (src_ip, target_user) key, LOGON_FAILURE events are counted within a
 * rolling window. When at least minFailures failed logons occur, the current
 * event is stamped with logon_brute_score (min(100, failures)),
 * logon_brute_failures, logon_brute_target_user, logon_brute_src_ip, and
 * logon_brute_window_seconds, and the key's counter resets so the threshold
 * must be re-met before fields are emitted again. A per-key cooldown
 * (dedupSeconds, 0 disables) suppresses re-stamping while failures continue so
 * a sustained attack does not flood alerts; even without a cooldown,
 * re-emission is rate-limited to once per minFailures failures.
 */
#include "logon_brute_force_detector.h"

#include <windows.h>

#include <algorithm>
#include <string>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
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

LogonBruteForceDetector::LogonBruteForceDetector(bool enabled,
                                                 uint32_t windowSeconds,
                                                 size_t stateCapacity,
                                                 uint32_t minFailures,
                                                 uint32_t dedupSeconds)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minFailures(std::max<uint32_t>(1, minFailures)),
      m_dedup100ns(static_cast<uint64_t>(dedupSeconds) *
                   kFiletimeTicksPerSecond) {}

bool LogonBruteForceDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_LOGON;
}

void LogonBruteForceDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_keys.erase(it);
        else
            ++it;
    }
}

void LogonBruteForceDetector::WriteState(Event& event, const KeyState& state) {
    event.fields[field::kLogonBruteScore] =
        std::to_string(std::min(100u, state.failures));
    event.fields[field::kLogonBruteFailures] = std::to_string(state.failures);
    const std::string srcIp = FieldValue(event, field::kSrcIp);
    if (!srcIp.empty())
        event.fields[field::kLogonBruteSrcIp] = srcIp;
    const std::string targetUser = FieldValue(event, field::kTargetUser);
    if (!targetUser.empty())
        event.fields[field::kLogonBruteTargetUser] = targetUser;
    event.fields[field::kLogonBruteWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void LogonBruteForceDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    if (FieldValue(event, field::kOperationType) != "LOGON_FAILURE")
        return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string srcIp = FieldValue(event, field::kSrcIp);
    const std::string targetUser = FieldValue(event, field::kTargetUser);

    /* Local interactive failures (4625 reports IpAddress "-") and events
     * without a target user cannot be attributed to a remote brute force;
     * skip them so local typos do not accumulate into a false positive. */
    if (srcIp.empty() || srcIp == "-" || targetUser.empty()) return;

    const std::string key = srcIp + "|" + targetUser;
    KeyState& state = m_keys[key];
    ++state.failures;
    state.lastSeen100ns = now;

    if (state.failures >= m_minFailures &&
        (m_dedup100ns == 0 || now >= state.suppressUntil100ns)) {
        state.suppressUntil100ns =
            m_dedup100ns == 0 ? 0 : now + m_dedup100ns;
        WriteState(event, state);
        state.failures = 0; /* next stamp needs a fresh batch of failures */
    }

    EvictOldest(m_keys, m_stateCapacity);
}

} // namespace edr
