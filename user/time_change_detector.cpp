/*
 * time_change_detector.cpp - See time_change_detector.h.
 */
#include "time_change_detector.h"

#include <windows.h>

#include <algorithm>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

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

int64_t AbsoluteValue(int64_t value) {
    return value < 0 ? -value : value;
}

} // namespace

TimeChangeDetector::TimeChangeDetector(bool enabled, uint32_t windowSeconds,
                                       size_t stateCapacity,
                                       uint32_t toleranceSeconds,
                                       uint32_t bigJumpSeconds)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_tolerance100ns(static_cast<uint64_t>(toleranceSeconds) *
                       kFiletimeTicksPerSecond),
      m_bigJump100ns(static_cast<uint64_t>(bigJumpSeconds) *
                     kFiletimeTicksPerSecond) {}

bool TimeChangeDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_SYSTEM_TIME_CHANGE;
}

bool TimeChangeDetector::ParseTickString(const std::string& text,
                                         uint64_t& out) {
    if (text.empty()) return false;
    uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (~0ULL - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

void TimeChangeDetector::PurgeExpired(uint64_t now100ns) {
    if (m_host.lastSeen100ns == 0) return;
    if (now100ns >= m_host.lastSeen100ns &&
        now100ns - m_host.lastSeen100ns > m_window100ns) {
        m_host = HostState{};
    }
}

uint32_t TimeChangeDetector::ComputeScore(const HostState& state) const {
    uint32_t score = 0;
    /* Rollback is the strong signal: it can resurrect expired certificates
     * and silently re-arm time-based locks. Forward jumps distort
     * retention/scheduling; moderate shifts are stamped for hunting but
     * stay below alerting. */
    if (state.mechanisms.count("time_rollback")) score += 65;
    if (state.mechanisms.count("large_forward_jump")) score += 45;
    if (state.mechanisms.count("time_shift")) score += 30;
    if (state.rollbackCount >= 2) score += 15;
    return std::min(100u, score);
}

std::string TimeChangeDetector::MechanismList(const HostState& state) const {
    std::string list;
    for (const auto& mechanism : state.mechanisms) {
        if (!list.empty()) list += ",";
        list += mechanism;
    }
    return list;
}

void TimeChangeDetector::WriteState(Event& event, const HostState& state,
                                    int64_t deltaSeconds) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kTimeChangeDeltaSeconds] =
        std::to_string(deltaSeconds);
    event.fields[field::kTimeChangeScore] = std::to_string(score);
    event.fields[field::kTimeChangeCount] =
        std::to_string(state.changeCount);
    event.fields[field::kTimeChangeMechanisms] = MechanismList(state);
    event.fields[field::kTimeChangeWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kTimeChangeVerdict] = verdict;
    }
}

void TimeChangeDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_SYSTEM_TIME_CHANGE) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    uint64_t previousTicks = 0;
    uint64_t newTicks = 0;
    auto previousField = event.fields.find(field::kTimeChangePrev100ns);
    auto newField = event.fields.find(field::kTimeChangeNew100ns);
    if (previousField == event.fields.end() ||
        newField == event.fields.end() ||
        !ParseTickString(previousField->second, previousTicks) ||
        !ParseTickString(newField->second, newTicks)) {
        return; /* malformed telemetry: leave the event unstamped */
    }

    const int64_t deltaTicks =
        static_cast<int64_t>(newTicks - previousTicks);
    if (AbsoluteValue(deltaTicks) <= static_cast<int64_t>(m_tolerance100ns)) {
        /* NTP-scale correction: not attacker-relevant. */
        return;
    }

    std::string mechanism;
    if (deltaTicks < -static_cast<int64_t>(m_tolerance100ns)) {
        mechanism = "time_rollback";
    } else if (deltaTicks >= static_cast<int64_t>(m_bigJump100ns)) {
        mechanism = "large_forward_jump";
    } else {
        mechanism = "time_shift";
    }

    m_host.mechanisms.insert(mechanism);
    ++m_host.changeCount;
    if (mechanism == "time_rollback") ++m_host.rollbackCount;
    m_host.lastSeen100ns = now;

    WriteState(event, m_host, deltaTicks /
                                   static_cast<int64_t>(kFiletimeTicksPerSecond));
}

} // namespace edr
