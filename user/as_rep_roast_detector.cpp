/*
 * as_rep_roast_detector.cpp - AS-REP roasting (T1558.004).
 */
#include "as_rep_roast_detector.h"
#include "credential_detector_util.h"

#include <windows.h>

#include <algorithm>
#include <string>

namespace edr {
namespace {

using credential_detail::LowerAscii;
using credential_detail::NormalizeSourceIp;
using credential_detail::SaturatingAdd;
using credential_detail::TrimBounded;

constexpr size_t kMaxUserChars = 256;

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

bool IsNoPreAuth(const Event& event) {
    std::string preAuth;
    if (!TrimBounded(FieldValue(event, field::kPreAuthType), 16, preAuth))
        return false;
    preAuth = LowerAscii(std::move(preAuth));
    return preAuth == "0" || preAuth == "0x0" || preAuth == "0x00" ||
           preAuth == "0x00000000";
}

std::string NormalizeTarget(const std::string& userValue,
                            const std::string& domainValue) {
    std::string user;
    if (!TrimBounded(userValue, kMaxUserChars, user)) return {};
    user = LowerAscii(std::move(user));
    if (user == "-" || user == "$" || user.empty()) return {};
    std::string domain;
    if (!TrimBounded(domainValue, 256, domain) || domain == "-") return user;
    return user + "@" + LowerAscii(domain);
}

} // namespace

AsRepRoastDetector::AsRepRoastDetector(bool enabled, uint32_t windowSeconds,
                                       size_t stateCapacity,
                                       uint32_t dedupSeconds)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(stateCapacity),
      m_dedup100ns(static_cast<uint64_t>(dedupSeconds) *
                   kFiletimeTicksPerSecond) {}

/* static */
bool AsRepRoastDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_LOGON;
}

void AsRepRoastDetector::WriteState(Event& event,
                                    const std::string& sourceIp,
                                    const RequesterState& state) const {
    uint32_t score = 0;
    if (state.count >= 3) score = 90;
    else if (state.count == 2) score = 80;
    else score = 65;

    event.fields[field::kAsRepRoastScore] = std::to_string(score);
    event.fields[field::kAsRepRoastVerdict] =
        score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kAsRepRoastCount] = std::to_string(state.count);
    event.fields[field::kAsRepRoastTarget] = state.displayTarget;
    event.fields[field::kAsRepRoastSrcIp] = sourceIp;
    event.fields[field::kAsRepRoastWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void AsRepRoastDetector::EvictLeastRecentlyTouched(size_t capacity) {
    if (m_requesters.size() <= capacity) return;
    const auto oldest = std::min_element(
        m_requesters.begin(), m_requesters.end(),
        [](const auto& left, const auto& right) {
            return left.second.lastSeen100ns < right.second.lastSeen100ns;
        });
    if (oldest != m_requesters.end()) m_requesters.erase(oldest);
}

void AsRepRoastDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_LOGON) return;
    if (FieldValue(event, field::kOperationType) != "TGT_REQUEST") return;
    if (!IsNoPreAuth(event)) return;

    std::string sourceIp;
    NormalizeSourceIp(FieldValue(event, field::kSrcIp), sourceIp);
    const std::string target =
        NormalizeTarget(FieldValue(event, field::kTargetUser),
                        FieldValue(event, field::kTargetDomain));
    if (target.empty()) return;

    const uint64_t now = EventTime(event);
    const std::string key = sourceIp + "|" + target;
    auto found = m_requesters.find(key);
    if (found != m_requesters.end() &&
        now < found->second.lastSeen100ns) {
        return; /* Reject rollback before state mutation or enrichment. */
    }

    RequesterState& state = m_requesters[key];
    /* Capture the previous timestamp before overwriting it; the window
     * expiry check below must compare against the prior sighting, not
     * against the update just applied. */
    const uint64_t previousSeen100ns = state.lastSeen100ns;
    state.lastSeen100ns = now;
    state.displayTarget = target;

    if (found != m_requesters.end() &&
        now - previousSeen100ns >= m_window100ns) {
        state.count = 1;
        state.lastAlertedCount = 0;
        state.lastStamp100ns = 0;
    } else if (found != m_requesters.end()) {
        const uint64_t incremented = SaturatingAdd(state.count, 1);
        state.count = static_cast<uint32_t>(
            std::min<uint64_t>(incremented, 0x7FFFFFFFu));
    } else {
        state.count = 1;
    }
    state.lastTouchedSequence = SaturatingAdd(m_touchSequence, 1);
    m_touchSequence = state.lastTouchedSequence;

    const bool threshold = state.count >= 1;
    const bool firstAlert = state.lastAlertedCount == 0;
    const bool cooldownElapsed =
        m_dedup100ns == 0 || state.lastStamp100ns == 0 ||
        now >= state.lastStamp100ns + m_dedup100ns;
    const bool evidenceEscalated =
        state.count > state.lastAlertedCount;
    if (threshold && (firstAlert || cooldownElapsed || evidenceEscalated)) {
        state.lastAlertedCount = state.count;
        state.lastStamp100ns = now;
        WriteState(event, sourceIp, state);
    }
    EvictLeastRecentlyTouched(m_stateCapacity);
}

} // namespace edr
