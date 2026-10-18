/*
 * password_spray_detector.cpp - See password_spray_detector.h.
 */
#include "password_spray_detector.h"
#include "credential_detector_util.h"

#include <windows.h>

#include <algorithm>
#include <limits>
#include <set>
#include <string>

namespace edr {
namespace {

using credential_detail::LowerAscii;
using credential_detail::NormalizeSourceIp;
using credential_detail::SaturatingAdd;
using credential_detail::TrimBounded;

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
constexpr size_t kMaxUsersField = 16;
constexpr size_t kMaxSummaryBytes = 4096;

const std::string& FieldValue(const Event& event, const char* name) {
    static const std::string empty;
    const auto found = event.fields.find(name);
    return found == event.fields.end() ? empty : found->second;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool IsRemoteLogonType(const std::string& value) {
    return value == "3" || value == "8" || value == "10";
}

std::string NormalizeUser(const Event& event) {
    std::string user;
    if (!TrimBounded(FieldValue(event, field::kTargetUser),
                     credential_detail::kMaxUserChars, user))
        return {};
    user = LowerAscii(std::move(user));
    if (user == "-" || user == "anonymous logon") return {};

    std::string domain;
    const std::string& rawDomain = FieldValue(event, field::kTargetDomain);
    if (!rawDomain.empty()) {
        if (!TrimBounded(rawDomain, credential_detail::kMaxDomainChars,
                         domain))
            return {};
        domain = LowerAscii(std::move(domain));
        if (domain == "-") domain.clear();
    }

    const size_t slash = user.find('\\');
    if (slash != std::string::npos) {
        if (slash == 0 || slash + 1 >= user.size()) return {};
        domain = user.substr(0, slash);
        user.erase(0, slash + 1);
    }
    const size_t at = user.rfind('@');
    if (at != std::string::npos) {
        if (at == 0 || at + 1 >= user.size()) return {};
        domain = user.substr(at + 1); /* UPN realm is authoritative. */
        user.resize(at);
    }
    if (user.empty() || user.back() == '$' ||
        user.size() > credential_detail::kMaxUserChars ||
        domain.size() > credential_detail::kMaxDomainChars)
        return {};
    return domain.empty() ? user : domain + "\\" + user;
}

std::string JoinUsers(
    const std::unordered_map<std::string, uint32_t>& counts) {
    std::set<std::string> ordered;
    for (const auto& entry : counts) {
        if (entry.second != 0) ordered.insert(entry.first);
    }
    std::string result;
    size_t emitted = 0;
    for (const std::string& user : ordered) {
        if (emitted >= kMaxUsersField) break;
        const size_t separator = result.empty() ? 0 : 1;
        if (user.size() + separator > kMaxSummaryBytes - result.size()) break;
        if (separator != 0) result += ",";
        result += user;
        ++emitted;
    }
    return result;
}

std::string JoinUsers(const std::unordered_set<std::string>& users) {
    std::set<std::string> ordered(users.begin(), users.end());
    std::string result;
    size_t emitted = 0;
    for (const std::string& user : ordered) {
        if (emitted >= kMaxUsersField) break;
        const size_t separator = result.empty() ? 0 : 1;
        if (user.size() + separator > kMaxSummaryBytes - result.size()) break;
        if (separator != 0) result += ",";
        result += user;
        ++emitted;
    }
    return result;
}

template <typename Map>
void EvictLeastRecentlyTouched(Map& map, size_t capacity) {
    while (map.size() > capacity) {
        const auto oldest = std::min_element(map.begin(), map.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastTouchedSequence <
                       right.second.lastTouchedSequence;
            });
        if (oldest == map.end()) return;
        map.erase(oldest);
    }
}

} // namespace

PasswordSprayDetector::PasswordSprayDetector(
    bool enabled, uint32_t windowSeconds, size_t stateCapacity,
    uint32_t minFailures, uint32_t minDistinctUsers,
    uint32_t successFollowupSeconds, uint32_t dedupSeconds,
    size_t maxFailuresPerSource)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minFailures(std::max<uint32_t>(1, minFailures)),
      m_minDistinctUsers(std::max<uint32_t>(1, minDistinctUsers)),
      m_successFollowup100ns(
          static_cast<uint64_t>(successFollowupSeconds) *
          kFiletimeTicksPerSecond),
      m_dedup100ns(static_cast<uint64_t>(dedupSeconds) *
                   kFiletimeTicksPerSecond),
      m_maxFailuresPerSource(std::max<size_t>(1, maxFailuresPerSource)) {}

bool PasswordSprayDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_LOGON;
}

size_t PasswordSprayDetector::ObservationCount(
    const std::string& sourceIp) const {
    std::string normalized;
    if (!NormalizeSourceIp(sourceIp, normalized)) return 0;
    const auto found = m_sources.find(normalized);
    return found == m_sources.end() ? 0 : found->second.failures.size();
}

void PasswordSprayDetector::PruneFailures(SourceState& state,
                                          uint64_t now100ns) const {
    while (!state.failures.empty()) {
        const FailureObservation& oldest = state.failures.front();
        if (now100ns < oldest.ts100ns ||
            now100ns - oldest.ts100ns <= m_window100ns)
            break;
        const auto count = state.userCounts.find(oldest.user);
        if (count != state.userCounts.end()) {
            if (count->second <= 1) state.userCounts.erase(count);
            else --count->second;
        }
        state.failures.pop_front();
    }
}

void PasswordSprayDetector::AppendFailure(SourceState& state,
                                          const std::string& user,
                                          uint64_t now100ns) const {
    state.failures.push_back({now100ns, user});
    ++state.userCounts[user];
    while (state.failures.size() > m_maxFailuresPerSource) {
        const std::string evictedUser = state.failures.front().user;
        state.failures.pop_front();
        const auto count = state.userCounts.find(evictedUser);
        if (count != state.userCounts.end()) {
            if (count->second <= 1) state.userCounts.erase(count);
            else --count->second;
        }
    }
}

void PasswordSprayDetector::ClearEpisode(SourceState& state) const {
    state.sprayUsers.clear();
    state.reportedSuccessUsers.clear();
    state.sprayFailureCount = 0;
    state.episodeStartedAt100ns = 0;
}

void PasswordSprayDetector::WriteFailureState(
    Event& event, const std::string& sourceIp,
    const SourceState& state) const {
    const uint32_t failures = static_cast<uint32_t>(state.failures.size());
    const uint32_t users = static_cast<uint32_t>(state.userCounts.size());
    const uint32_t score = std::min(90u, users * 10u + failures * 2u);
    event.fields[field::kPasswordSprayScore] = std::to_string(score);
    event.fields[field::kPasswordSprayFailures] = std::to_string(failures);
    event.fields[field::kPasswordSprayUserCount] = std::to_string(users);
    event.fields[field::kPasswordSprayUsers] = JoinUsers(state.userCounts);
    event.fields[field::kPasswordSpraySrcIp] = sourceIp;
    event.fields[field::kPasswordSprayWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void PasswordSprayDetector::WriteSuccessState(
    Event& event, const std::string& sourceIp, const std::string& user,
    const SourceState& state, uint64_t now100ns) const {
    event.fields[field::kPasswordSprayScore] = "100";
    event.fields[field::kPasswordSprayFailures] =
        std::to_string(state.sprayFailureCount);
    event.fields[field::kPasswordSprayUserCount] =
        std::to_string(state.sprayUsers.size());
    event.fields[field::kPasswordSprayUsers] = JoinUsers(state.sprayUsers);
    event.fields[field::kPasswordSpraySrcIp] = sourceIp;
    event.fields[field::kPasswordSprayWindowSeconds] =
        std::to_string(m_windowSeconds);
    event.fields[field::kPasswordSpraySuccess] = "true";
    event.fields[field::kPasswordSpraySuccessUser] = user;
    const uint64_t delay =
        (now100ns - state.episodeStartedAt100ns) / kFiletimeTicksPerSecond;
    event.fields[field::kPasswordSpraySuccessDelaySeconds] =
        std::to_string(delay);
}

void PasswordSprayDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const std::string& operation = FieldValue(event, field::kOperationType);
    if (operation != "LOGON_FAILURE" && operation != "LOGON") return;
    if (!IsRemoteLogonType(FieldValue(event, field::kLogonType))) return;

    std::string sourceIp;
    if (!NormalizeSourceIp(FieldValue(event, field::kSrcIp), sourceIp)) return;
    const std::string user = NormalizeUser(event);
    if (user.empty()) return;

    const uint64_t now = EventTime(event);
    auto found = m_sources.find(sourceIp);
    if (found != m_sources.end() && now < found->second.lastSeen100ns) {
        return; /* Reject rollback before state mutation or enrichment. */
    }

    if (operation == "LOGON") {
        if (found == m_sources.end()) return;
        SourceState& state = found->second;
        PruneFailures(state, now);
        if (state.failures.size() < m_minFailures ||
            state.userCounts.size() < m_minDistinctUsers) {
            state.thresholdLatched = false;
        }
        if (state.episodeStartedAt100ns != 0 &&
            now - state.episodeStartedAt100ns > m_successFollowup100ns) {
            ClearEpisode(state);
        }
        state.lastSeen100ns = now;
        state.lastTouchedSequence = SaturatingAdd(m_touchSequence, 1);
        m_touchSequence = state.lastTouchedSequence;

        if (state.episodeStartedAt100ns == 0 ||
            state.sprayUsers.find(user) == state.sprayUsers.end() ||
            state.reportedSuccessUsers.find(user) !=
                state.reportedSuccessUsers.end())
            return;

        WriteSuccessState(event, sourceIp, user, state, now);
        state.reportedSuccessUsers.insert(user);
        return;
    }

    SourceState& state = m_sources[sourceIp];
    PruneFailures(state, now);
    const bool thresholdBeforeFailure =
        state.failures.size() >= m_minFailures &&
        state.userCounts.size() >= m_minDistinctUsers;
    if (!thresholdBeforeFailure) state.thresholdLatched = false;
    if (state.episodeStartedAt100ns != 0 &&
        now - state.episodeStartedAt100ns > m_successFollowup100ns) {
        ClearEpisode(state);
    }
    AppendFailure(state, user, now);
    state.lastSeen100ns = now;
    state.lastTouchedSequence = SaturatingAdd(m_touchSequence, 1);
    m_touchSequence = state.lastTouchedSequence;

    const bool threshold =
        state.failures.size() >= m_minFailures &&
        state.userCounts.size() >= m_minDistinctUsers;
    const bool thresholdCrossed = threshold && !state.thresholdLatched;
    state.thresholdLatched = threshold;
    if (thresholdCrossed && state.episodeStartedAt100ns == 0) {
        state.episodeStartedAt100ns = now;
        state.sprayFailureCount =
            static_cast<uint32_t>(state.failures.size());
        state.sprayUsers.clear();
        for (const auto& entry : state.userCounts) {
            if (entry.second != 0 &&
                state.sprayUsers.size() < m_maxFailuresPerSource) {
                state.sprayUsers.insert(entry.first);
            }
        }
        state.reportedSuccessUsers.clear();
    } else if (state.episodeStartedAt100ns != 0) {
        if (state.sprayUsers.size() < m_maxFailuresPerSource)
            state.sprayUsers.insert(user);
        if (state.sprayFailureCount < std::numeric_limits<uint32_t>::max())
            ++state.sprayFailureCount;
    }

    const bool cooldownElapsed =
        m_dedup100ns == 0 || state.suppressUntil100ns == 0 ||
        now >= state.suppressUntil100ns;
    if (threshold && cooldownElapsed) {
        state.suppressUntil100ns =
            m_dedup100ns == 0 ? 0 : SaturatingAdd(now, m_dedup100ns);
        WriteFailureState(event, sourceIp, state);
    }
    EvictLeastRecentlyTouched(m_sources, m_stateCapacity);
}

} // namespace edr
