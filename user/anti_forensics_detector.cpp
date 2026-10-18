/*
 * anti_forensics_detector.cpp - See anti_forensics_detector.h.
 */
#include "anti_forensics_detector.h"

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

AntiForensicsDetector::AntiForensicsDetector(bool enabled,
                                             uint32_t windowSeconds,
                                             size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool AntiForensicsDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_AUDIT_LOG;
}

std::string AntiForensicsDetector::LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string AntiForensicsDetector::ActorKey(const Event& event) const {
    const std::string user =
        LowerAscii(FieldValue(event, field::kSubjectUserName));
    if (user.empty()) return "unknown";
    const std::string domain =
        LowerAscii(FieldValue(event, field::kSubjectDomainName));
    if (domain.empty()) return user;
    return domain + "\\" + user;
}

void AntiForensicsDetector::PurgeExpired(uint64_t now100ns) {
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

uint32_t AntiForensicsDetector::ComputeScore(const ActorState& state) const {
    uint32_t score = 0;
    /* Clearing the Security log is the classic cover-your-tracks move
     * (T1070.002); a service stop alone is weaker evidence but escalates
     * the picture when combined with, or repeated by, a clear. Audit
     * policy changes (4719) and log-full (1104) are quieter tampering
     * signals that combine into the same correlation window. */
    if (state.mechanisms.count("security_log_cleared")) score += 55;
    if (state.mechanisms.count("security_audit_stopped")) score += 20;
    if (state.mechanisms.count("audit_policy_changed")) score += 30;
    if (state.mechanisms.count("security_log_full")) score += 15;
    if (state.clearCount >= 2) score += 25;
    return std::min(100u, score);
}

std::string AntiForensicsDetector::MechanismList(
        const ActorState& state) const {
    std::string list;
    for (const auto& mechanism : state.mechanisms) {
        if (!list.empty()) list += ",";
        list += mechanism;
    }
    return list;
}

void AntiForensicsDetector::WriteState(Event& event,
                                       const ActorState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kAntiForensicsScore] = std::to_string(score);
    event.fields[field::kAntiForensicsCount] =
        std::to_string(state.clearCount);
    event.fields[field::kAntiForensicsMechanisms] = MechanismList(state);
    event.fields[field::kAntiForensicsWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kAntiForensicsVerdict] = verdict;
    }
}

void AntiForensicsDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_AUDIT_LOG) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string eventId = FieldValue(event, field::kAuditLogEventId);
    std::string mechanism;
    if (eventId == "1102") {
        mechanism = "security_log_cleared";
    } else if (eventId == "1100") {
        mechanism = "security_audit_stopped";
    } else if (eventId == "4719") {
        mechanism = "audit_policy_changed";
    } else if (eventId == "1104") {
        mechanism = "security_log_full";
    } else {
        return;
    }

    ActorState& state = m_actors[ActorKey(event)];
    state.mechanisms.insert(mechanism);
    if (mechanism == "security_log_cleared") ++state.clearCount;
    state.lastSeen100ns = now;

    WriteState(event, state);
    EvictOldest(m_actors, m_stateCapacity);
}

} // namespace edr
