/*
 * golden_ticket_detector.cpp - See golden_ticket_detector.h.
 */
#include "golden_ticket_detector.h"

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

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

/* Trim surrounding whitespace and quote pairs the XML rendering keeps. */
std::string Trim(const std::string& value) {
    size_t begin = 0;
    size_t end = value.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(value[begin])))
        ++begin;
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(value[end - 1])))
        --end;
    if (end - begin >= 2 && value[begin] == '"' && value[end - 1] == '"') {
        ++begin;
        --end;
    }
    return value.substr(begin, end - begin);
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

GoldenTicketDetector::GoldenTicketDetector(bool enabled,
                                           uint32_t windowSeconds,
                                           size_t stateCapacity,
                                           uint32_t minRepeatCount)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minRepeatCount(std::max<uint32_t>(2, minRepeatCount)) {}

bool GoldenTicketDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_LOGON;
}

bool GoldenTicketDetector::IsRc4Encryption(const std::string& encryptionType) {
    /* 0x17 / 23 = RC4-HMAC; the value arrives in hex (0x17) or decimal
     * (23) depending on the log rendering. */
    const std::string value = LowerAscii(Trim(encryptionType));
    return value == "0x17" || value == "23";
}

bool GoldenTicketDetector::IsKrbtgtAccount(const std::string& targetUser) {
    return LowerAscii(Trim(targetUser)) == "krbtgt";
}

void GoldenTicketDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_sources.begin(); it != m_sources.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_sources.erase(it);
        else
            ++it;
    }
}

uint32_t GoldenTicketDetector::ComputeScore(
    const SourceState& state) const {
    uint32_t score = 0;
    if (state.sawKrbtgtTgt) score += 90;
    if (state.sawKrbtgtTgs) score += 85;
    if (state.rc4TgtCount > 0) score += 80;
    if (state.rc4TgtCount >= m_minRepeatCount) score += 10;
    /* RC4 service tickets for krbtgt combine both independent signals. */
    if (state.sawKrbtgtTgs && state.rc4TgtCount > 0) score = 100;
    return std::min(100u, score);
}

std::string GoldenTicketDetector::SignalList(
    const SourceState& state) const {
    std::string signals;
    const std::pair<bool, const char*> kFlags[] = {
        {state.sawKrbtgtTgt, "krbtgt_tgt_request"},
        {state.sawKrbtgtTgs, "krbtgt_service_ticket"},
        {state.rc4TgtCount > 0, "rc4_encrypted_tgt"},
        {state.rc4TgtCount >= m_minRepeatCount, "rc4_tgt_repeat"},
    };
    for (const auto& entry : kFlags) {
        if (!entry.first) continue;
        if (!signals.empty()) signals += ",";
        signals += entry.second;
    }
    return signals;
}

void GoldenTicketDetector::WriteState(Event& event,
                                      const SourceState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kGoldenTicketScore] = std::to_string(score);
    event.fields[field::kGoldenTicketSignals] = SignalList(state);
    std::string targets;
    for (const std::string& target : state.targets) {
        if (!targets.empty()) targets += ",";
        targets += target;
    }
    event.fields[field::kGoldenTicketTargets] = targets;
    event.fields[field::kGoldenTicketRc4Count] =
        std::to_string(state.rc4TgtCount);
    event.fields[field::kGoldenTicketWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kGoldenTicketVerdict] = verdict;
    }
}

void GoldenTicketDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    const std::string operation = FieldValue(event, field::kOperationType);
    const bool isTgt = operation == "TGT_REQUEST";
    const bool isTgs = operation == "TGS_REQUEST";
    if (!isTgt && !isTgs) return;

    const std::string targetUser = FieldValue(event, field::kTargetUser);
    const std::string encryption =
        FieldValue(event, field::kTgsTicketEncryptionType);
    const bool rc4 = isTgt && IsRc4Encryption(encryption);
    const bool krbtgt = IsKrbtgtAccount(targetUser);
    if (!rc4 && !krbtgt) return; /* Normal ticket traffic. */

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    std::string key = Trim(FieldValue(event, field::kSrcIp));
    if (key.empty()) key = Trim(FieldValue(event, field::kSubjectUserName));
    if (key.empty()) key = "unknown-source";

    SourceState& state = m_sources[key];
    if (isTgt && rc4) ++state.rc4TgtCount;
    if (isTgt && krbtgt) state.sawKrbtgtTgt = true;
    if (isTgs && krbtgt) state.sawKrbtgtTgs = true;
    if (!targetUser.empty()) state.targets.insert(Trim(targetUser));
    state.lastSeen100ns = now;

    WriteState(event, state);
    EvictOldest(m_sources, m_stateCapacity);
}

} // namespace edr
