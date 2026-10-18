/*
 * privileged_group_detector.cpp - See privileged_group_detector.h.
 */
#include "privileged_group_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>

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

PrivilegedGroupDetector::PrivilegedGroupDetector(bool enabled,
                                                 uint32_t windowSeconds,
                                                 size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool PrivilegedGroupDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_ACCOUNT_CHANGE;
}

std::string PrivilegedGroupDetector::LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool PrivilegedGroupDetector::IsSensitiveGroup(const std::string& groupName) {
    /* Substring matching on the lowercased name absorbs BUILTIN\ prefixes
     * and the localized-name tail risk is accepted: these English names are
     * stable on EN builds and partial matches stay conservative. */
    static const char* kSensitive[] = {
        "administrators",       /* covers Administrators + Hyper-V Admins */
        "domain admins",
        "enterprise admins",
        "schema admins",
        "backup operators",
        "account operators",
        "server operators",
        "remote desktop users"
    };
    const std::string lower = LowerAscii(groupName);
    for (const char* candidate : kSensitive) {
        if (lower.find(candidate) != std::string::npos) return true;
    }
    return false;
}

std::string PrivilegedGroupDetector::ActorKey(const Event& event) const {
    const std::string user =
        LowerAscii(FieldValue(event, field::kSubjectUserName));
    if (user.empty()) return "unknown";
    const std::string domain =
        LowerAscii(FieldValue(event, field::kSubjectDomainName));
    if (domain.empty()) return user;
    return domain + "\\" + user;
}

void PrivilegedGroupDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_actors.begin(); it != m_actors.end();) {
        if (it->second.lastSeen100ns != 0 &&
            now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_actors.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t PrivilegedGroupDetector::ComputeScore(
        const ActorState& state) const {
    uint32_t score = 0;
    if (state.sensitiveAdds > 0) score += 60;
    if (state.sensitiveAdds >= 2) score += 20;
    if (state.totalAdds >= 4) score += 10;
    if (score == 0 && state.totalAdds >= 3) score += 30;
    return std::min(100u, score);
}

std::string PrivilegedGroupDetector::GroupList(
        const ActorState& state) const {
    std::string list;
    for (const auto& group : state.groups) {
        if (!list.empty()) list += ",";
        list += group;
    }
    return list;
}

void PrivilegedGroupDetector::WriteState(Event& event,
                                         const ActorState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kPrivilegedGroupScore] = std::to_string(score);
    event.fields[field::kPrivilegedGroupCount] =
        std::to_string(state.totalAdds);
    event.fields[field::kPrivilegedGroupSensitiveAdds] =
        std::to_string(state.sensitiveAdds);
    event.fields[field::kPrivilegedGroupGroups] = GroupList(state);
    event.fields[field::kPrivilegedGroupWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kPrivilegedGroupVerdict] = verdict;
    }
}

void PrivilegedGroupDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_ACCOUNT_CHANGE) return;
    if (FieldValue(event, field::kOperationType) != "GROUP_MEMBER_ADD") {
        return;
    }

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string group = FieldValue(event, field::kTargetGroupName);
    if (group.empty()) return; /* unattributable target: skip */

    ActorState& state = m_actors[ActorKey(event)];
    state.groups.insert(LowerAscii(group));
    ++state.totalAdds;
    if (IsSensitiveGroup(group)) ++state.sensitiveAdds;
    state.lastSeen100ns = now;

    /* Benign one-off additions to ordinary groups stay silent until churn
     * accumulates, keeping help-desk activity out of the alert stream. */
    if (state.sensitiveAdds == 0 && state.totalAdds < 3) {
        EvictOldest(m_actors, m_stateCapacity);
        return;
    }

    WriteState(event, state);
    EvictOldest(m_actors, m_stateCapacity);
}

} // namespace edr
