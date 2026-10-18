/*
 * ntlm_relay_detector.cpp - See ntlm_relay_detector.h.
 */
#include "ntlm_relay_detector.h"

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

} // namespace

NtlmRelayDetector::NtlmRelayDetector(bool enabled, uint32_t windowSeconds,
                                     size_t stateCapacity, uint32_t minEvents)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minEvents(std::max(2u, minEvents)) {}

bool NtlmRelayDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_LOGON;
}

bool NtlmRelayDetector::IsNtlmLogon(const Event& event) {
    /* Logon type 3 = network (NTLM). Auth package NTLM or Negossp. */
    const std::string logonType = FieldValue(event, field::kLogonType);
    const std::string authPkg = FieldValue(event, field::kAuthPackage);
    if (logonType != "3") return false;
    const std::string authLower = LowerAscii(authPkg);
    return authLower.find("ntlm") != std::string::npos ||
           authLower.find("negotiate") != std::string::npos ||
           authPkg.empty(); /* if no auth pkg info, assume NTLM for type 3 */
}

void NtlmRelayDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_accounts.begin(); it != m_accounts.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_accounts.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t NtlmRelayDetector::ComputeScore(const AccountState& state) const {
    uint32_t score = 0;
    const size_t srcCount = state.sourceIps.size();
    if (srcCount >= 5) score += 40;
    else if (srcCount >= 3) score += 30;
    else if (srcCount >= 2) score += 20;
    const size_t wsCount = state.sourceWorkstations.size();
    if (wsCount >= 3) score += 20;
    else if (wsCount >= 2) score += 10;
    const size_t eventCount = state.timeline.size();
    if (static_cast<uint32_t>(eventCount) >= m_minEvents * 2) score += 25;
    else if (static_cast<uint32_t>(eventCount) >= m_minEvents) score += 15;
    /* Multiple sources + multiple events = strong relay indicator */
    if (srcCount >= 2 && eventCount >= m_minEvents) score += 15;
    return std::min(100u, score);
}

std::string NtlmRelayDetector::SignalList(const AccountState& state) const {
    std::string signals;
    if (state.sourceIps.size() >= 2) {
        signals += "multiple_sources:" + std::to_string(state.sourceIps.size());
    }
    if (state.sourceWorkstations.size() >= 2) {
        if (!signals.empty()) signals += ",";
        signals += "multiple_workstations:" +
                   std::to_string(state.sourceWorkstations.size());
    }
    if (state.timeline.size() >= m_minEvents) {
        if (!signals.empty()) signals += ",";
        signals += "burst_logons:" + std::to_string(state.timeline.size());
    }
    return signals;
}

std::string NtlmRelayDetector::SourceList(const AccountState& state) const {
    std::string srcs;
    for (const auto& ip : state.sourceIps) {
        if (!srcs.empty()) srcs += ",";
        srcs += ip;
        if (srcs.size() > 200) break;
    }
    return srcs;
}

std::string NtlmRelayDetector::AccountList(const AccountState& state) const {
    std::string wss;
    for (const auto& ws : state.sourceWorkstations) {
        if (!wss.empty()) wss += ",";
        wss += ws;
        if (wss.size() > 200) break;
    }
    return wss;
}

void NtlmRelayDetector::WriteState(Event& event, const AccountState& state,
                                   const std::string& account) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kNtlmRelayScore] = std::to_string(score);
    event.fields[field::kNtlmRelaySignals] = SignalList(state);
    event.fields[field::kNtlmRelaySources] = SourceList(state);
    event.fields[field::kNtlmRelayTargetAccounts] = account;
    event.fields[field::kNtlmRelayWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty())
        event.fields[field::kNtlmRelayVerdict] = verdict;
}

void NtlmRelayDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!IsNtlmLogon(event)) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string targetUser = FieldValue(event, field::kTargetUser);
    const std::string srcIp = FieldValue(event, field::kSrcIp);
    const std::string srcWs = FieldValue(event, field::kSourceWorkstation);
    if (targetUser.empty()) return;

    AccountState& state = m_accounts[targetUser];
    if (!srcIp.empty()) state.sourceIps.insert(srcIp);
    if (!srcWs.empty()) {
        /* Strip leading \\ from workstation name */
        std::string ws = srcWs;
        if (ws.size() >= 2 && ws[0] == '\\' && ws[1] == '\\')
            ws = ws.substr(2);
        state.sourceWorkstations.insert(LowerAscii(ws));
    }
    state.timeline[now] = srcIp;
    state.lastSeen100ns = now;

    /* Only stamp when we have enough indicators */
    if (state.sourceIps.size() >= 2 ||
        state.timeline.size() >= m_minEvents) {
        WriteState(event, state, targetUser);
    }
}

} // namespace edr
