/*
 * logon_success_detector.cpp - See logon_success_detector.h.
 */
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "logon_success_detector.h"

#include "credential_detector_util.h"

#include <windows.h>

#include <algorithm>
#include <limits>
#include <string>

namespace edr {
namespace {

using credential_detail::LowerAscii;
using credential_detail::NormalizeSourceIp;
using credential_detail::SaturatingAdd;
using credential_detail::TrimBounded;

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
constexpr uint64_t kFutureToleranceSeconds = 300;
constexpr uint32_t kMaximumMinFailures = 256;
constexpr size_t kMaximumStates = 8192;
constexpr size_t kMaximumScopeChars = 128;

const std::string& FieldValue(const Event& event, const char* name) {
    static const std::string empty;
    const auto found = event.fields.find(name);
    return found == event.fields.end() ? empty : found->second;
}

uint64_t SystemTime100ns() {
    FILETIME now{};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool NormalizeAccount(const Event& event, std::string& domain,
                     std::string& user) {
    if (!TrimBounded(FieldValue(event, field::kTargetUser),
                     credential_detail::kMaxUserChars, user))
        return false;
    user = LowerAscii(std::move(user));
    if (user == "-" || user == "anonymous logon") return false;

    const std::string& rawDomain = FieldValue(event, field::kTargetDomain);
    if (!rawDomain.empty() &&
        !TrimBounded(rawDomain, credential_detail::kMaxDomainChars, domain))
        return false;
    if (!domain.empty()) domain = LowerAscii(std::move(domain));
    if (domain == "-") domain.clear();

    const size_t slash = user.find('\\');
    if (slash != std::string::npos) {
        if (slash == 0 || slash + 1 >= user.size()) return false;
        const std::string embeddedDomain = user.substr(0, slash);
        if (!domain.empty() && domain != embeddedDomain) return false;
        domain = embeddedDomain;
        user.erase(0, slash + 1);
    }
    const size_t at = user.rfind('@');
    if (at != std::string::npos) {
        if (at == 0 || at + 1 >= user.size()) return false;
        const std::string upnDomain = user.substr(at + 1);
        if (!domain.empty() && domain != upnDomain) return false;
        domain = upnDomain;
        user.resize(at);
    }
    if (domain.empty() || user.empty() || user.back() == '$' ||
        user.size() > credential_detail::kMaxUserChars ||
        domain.size() > credential_detail::kMaxDomainChars ||
        domain.find_first_of("\\/") != std::string::npos ||
        user.find_first_of("\\/") != std::string::npos)
        return false;
    return true;
}

bool NormalizeScopePart(const std::string& input, std::string& output,
                        bool required) {
    if (input.empty()) {
        output.clear();
        return !required;
    }
    if (!TrimBounded(input, kMaximumScopeChars, output)) return false;
    output = LowerAscii(std::move(output));
    return true;
}

bool CorrelationKey(const Event& event, std::string& key) {
    std::string source;
    const std::string& eventSource = event.source.empty()
        ? FieldValue(event, field::kSource) : event.source;
    if (!NormalizeScopePart(eventSource, source, true)) return false;

    std::string endpoint;
    const auto endpointIt = event.fields.find(field::kEndpointId);
    if (endpointIt != event.fields.end() &&
        !NormalizeScopePart(endpointIt->second, endpoint, false))
        return false;

    std::string sourceIp;
    if (!NormalizeSourceIp(FieldValue(event, field::kSrcIp), sourceIp))
        return false;
    std::string domain;
    std::string user;
    if (!NormalizeAccount(event, domain, user)) return false;

    /* Length-prefix every untrusted field so separator characters cannot
     * merge two different source, endpoint, address, or account tuples. */
    const auto append = [&key](const std::string& part) {
        key += std::to_string(part.size());
        key += ':';
        key += part;
    };
    key.reserve(source.size() + endpoint.size() + sourceIp.size() +
                domain.size() + user.size() + 48);
    append(source);
    append(endpoint);
    append(sourceIp);
    append(domain);
    append(user);
    return true;
}

bool IsRemoteLogon(const Event& event) {
    const std::string& logonType = FieldValue(event, field::kLogonType);
    return logonType == "3" || logonType == "10";
}

} // namespace

LogonSuccessDetector::LogonSuccessDetector(bool enabled,
                                           uint32_t windowSeconds,
                                           size_t stateCapacity,
                                           uint32_t minFailures)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, std::min(stateCapacity,
                                                   kMaximumStates))),
      m_minFailures(std::max<uint32_t>(2, std::min(minFailures,
                                                   kMaximumMinFailures))) {}

bool LogonSuccessDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_LOGON;
}

void LogonSuccessDetector::EvictOldest(const std::string& preserveKey) {
    while (m_states.size() > m_stateCapacity) {
        auto oldest = m_states.end();
        for (auto it = m_states.begin(); it != m_states.end(); ++it) {
            if (it->first == preserveKey) continue;
            if (oldest == m_states.end() ||
                it->second.lastSeen100ns < oldest->second.lastSeen100ns ||
                (it->second.lastSeen100ns == oldest->second.lastSeen100ns &&
                 it->first < oldest->first))
                oldest = it;
        }
        if (oldest == m_states.end()) return;
        m_states.erase(oldest);
    }
}

void LogonSuccessDetector::Enrich(Event& event) {
    if (!m_enabled || !Inspects(event.type) || !IsRemoteLogon(event)) return;
    const std::string& operation = FieldValue(event, field::kOperationType);
    if (operation != "LOGON_FAILURE" && operation != "LOGON") return;

    std::string key;
    if (!CorrelationKey(event, key)) return;

    const uint64_t now = event.ts100ns == 0 ? SystemTime100ns() : event.ts100ns;
    const uint64_t current = SystemTime100ns();
    const uint64_t maxAccepted = SaturatingAdd(
        current, kFutureToleranceSeconds * kFiletimeTicksPerSecond);
    if (now > maxAccepted) return;

    auto found = m_states.find(key);
    if (found != m_states.end()) {
        KeyState& state = found->second;
        if (now < state.lastEvent100ns)
            return; /* A delayed record must not roll the key's state backward. */
        if (now >= state.lastSeen100ns &&
            now - state.lastSeen100ns > m_window100ns) {
            m_states.erase(found);
            found = m_states.end();
        } else {
            while (!state.failures100ns.empty() &&
                   now >= state.failures100ns.front() &&
                   now - state.failures100ns.front() > m_window100ns)
                state.failures100ns.pop_front();
        }
    }

    if (operation == "LOGON") {
        if (found == m_states.end()) {
            /* Remember even unmatched successes briefly, so delayed failures
             * from before that success cannot form a stale episode. */
            KeyState& tombstone = m_states[key];
            tombstone.lastEvent100ns = now;
            tombstone.lastSeen100ns = now;
            EvictOldest(key);
            return;
        }
        KeyState& state = found->second;
        if (state.failures100ns.size() >= m_minFailures) {
            event.fields[field::kLogonSuccessScore] = "75";
            event.fields[field::kLogonSuccessFailures] =
                std::to_string(state.failures100ns.size());
            event.fields[field::kLogonSuccessWindowSeconds] =
                std::to_string(m_windowSeconds);
        }
        /* Keep a bounded-window tombstone so delayed failures cannot rebuild
         * an already consumed episode or make a later success alert twice. */
        state.failures100ns.clear();
        state.lastEvent100ns = now;
        state.lastSeen100ns = now;
        return;
    }

    KeyState& state = m_states[key];
    state.lastEvent100ns = now;
    state.lastSeen100ns = now;
    state.failures100ns.push_back(now);
    while (state.failures100ns.size() > m_minFailures)
        state.failures100ns.pop_front();
    EvictOldest(key);
}

} // namespace edr
