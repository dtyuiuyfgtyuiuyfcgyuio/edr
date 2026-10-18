/*
 * kerberoast_detector.cpp - See kerberoast_detector.h.
 */
#include "kerberoast_detector.h"
#include "credential_detector_util.h"

#include <windows.h>

#include <algorithm>
#include <set>
#include <string>

namespace edr {
namespace {

using credential_detail::LowerAscii;
using credential_detail::NormalizeSourceIp;
using credential_detail::SaturatingAdd;
using credential_detail::TrimBounded;

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
constexpr size_t kMaxServicesField = 16;
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

bool IsSuccessfulRc4(const Event& event) {
    std::string encryption;
    std::string status;
    if (!TrimBounded(FieldValue(event, field::kTgsTicketEncryptionType),
                     16, encryption) ||
        !TrimBounded(FieldValue(event, field::kTgsFailureCode), 16, status))
        return false;
    encryption = LowerAscii(std::move(encryption));
    status = LowerAscii(std::move(status));
    const bool rc4 = encryption == "0x17" || encryption == "23";
    const bool success = status == "0" || status == "0x0" ||
                         status == "0x00000000";
    return rc4 && success;
}

std::string NormalizeRequester(const std::string& domainValue,
                               const std::string& userValue) {
    std::string user;
    if (!TrimBounded(userValue, credential_detail::kMaxUserChars, user))
        return {};
    user = LowerAscii(std::move(user));
    if (user == "-" || user == "anonymous logon") return {};

    std::string domain;
    if (!domainValue.empty()) {
        if (!TrimBounded(domainValue, credential_detail::kMaxDomainChars,
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

std::string NormalizeService(const std::string& serviceValue) {
    std::string service;
    if (!TrimBounded(serviceValue, credential_detail::kMaxServiceChars,
                     service))
        return {};
    service = LowerAscii(std::move(service));
    if (service == "-") return {};

    /* A forwarded SPN may include an @REALM suffix; it is not part of the
     * service identity for distinct-count purposes. */
    const size_t at = service.rfind('@');
    if (at != std::string::npos) {
        if (at == 0 || at + 1 >= service.size()) return {};
        service.resize(at);
    }
    if (service.empty()) return {};

    /* Standalone account-form values and krbtgt can be filtered reliably.
     * Class/instance SPNs (HOST/server, cifs/server, ...) do not reveal the
     * backing account type and therefore remain eligible. */
    const size_t slash = service.find('/');
    const std::string principal = service.substr(0, slash);
    if (principal.empty() || principal == "krbtgt") return {};
    if (slash == std::string::npos && principal.back() == '$') return {};
    if (slash != std::string::npos && slash + 1 >= service.size()) return {};
    return service;
}

std::string RequesterKey(const std::string& sourceIp,
                         const std::string& domain,
                         const std::string& requester) {
    std::string normalizedIp;
    if (!NormalizeSourceIp(sourceIp, normalizedIp)) return {};
    const std::string account = NormalizeRequester(domain, requester);
    return account.empty() ? std::string()
                           : normalizedIp + "|" + account;
}

std::string JoinServices(
    const std::unordered_map<std::string, uint64_t>& services) {
    std::set<std::string> ordered;
    for (const auto& entry : services) ordered.insert(entry.first);
    std::string result;
    size_t emitted = 0;
    for (const std::string& service : ordered) {
        if (emitted >= kMaxServicesField) break;
        const size_t separator = result.empty() ? 0 : 1;
        if (service.size() + separator > kMaxSummaryBytes - result.size()) break;
        if (separator != 0) result += ",";
        result += service;
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

KerberoastDetector::KerberoastDetector(
    bool enabled, uint32_t windowSeconds, size_t stateCapacity,
    uint32_t minServiceCount, uint32_t dedupSeconds,
    size_t maxServicesPerRequester)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minServiceCount(std::max<uint32_t>(1, minServiceCount)),
      m_dedup100ns(static_cast<uint64_t>(dedupSeconds) *
                   kFiletimeTicksPerSecond),
      m_maxServicesPerRequester(
          std::max<size_t>(1, maxServicesPerRequester)) {}

bool KerberoastDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_LOGON;
}

size_t KerberoastDetector::ServiceCount(
    const std::string& sourceIp, const std::string& domain,
    const std::string& requester) const {
    const std::string key = RequesterKey(sourceIp, domain, requester);
    if (key.empty()) return 0;
    const auto found = m_requesters.find(key);
    return found == m_requesters.end() ? 0 : found->second.services.size();
}

void KerberoastDetector::PruneServices(RequesterState& state,
                                       uint64_t now100ns) const {
    for (auto it = state.services.begin(); it != state.services.end();) {
        if (now100ns >= it->second &&
            now100ns - it->second > m_window100ns)
            it = state.services.erase(it);
        else
            ++it;
    }
    if (state.services.empty()) {
        state.lastAlertedServiceCount = 0;
        state.suppressUntil100ns = 0;
    } else if (state.lastAlertedServiceCount > state.services.size()) {
        state.lastAlertedServiceCount = state.services.size();
    }
}

void KerberoastDetector::WriteState(
    Event& event, const std::string& sourceIp,
    const RequesterState& state) const {
    const uint32_t count = static_cast<uint32_t>(state.services.size());
    event.fields[field::kKerberoastScore] =
        std::to_string(std::min(100u, count * 15u));
    event.fields[field::kKerberoastServiceCount] = std::to_string(count);
    event.fields[field::kKerberoastServices] = JoinServices(state.services);
    event.fields[field::kKerberoastRequester] = state.displayRequester;
    event.fields[field::kKerberoastSrcIp] = sourceIp;
    event.fields[field::kKerberoastWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void KerberoastDetector::Enrich(Event& event) {
    if (!m_enabled ||
        FieldValue(event, field::kOperationType) != "TGS_REQUEST" ||
        !IsSuccessfulRc4(event))
        return;

    std::string sourceIp;
    if (!NormalizeSourceIp(FieldValue(event, field::kSrcIp), sourceIp)) return;
    const std::string requester = NormalizeRequester(
        FieldValue(event, field::kTargetDomain),
        FieldValue(event, field::kTargetUser));
    const std::string service =
        NormalizeService(FieldValue(event, field::kTgsServiceName));
    if (requester.empty() || service.empty()) return;

    const std::string key = sourceIp + "|" + requester;
    const uint64_t now = EventTime(event);
    auto found = m_requesters.find(key);
    if (found != m_requesters.end() && now < found->second.lastSeen100ns) {
        return; /* Reject rollback before state mutation or enrichment. */
    }

    RequesterState& state = m_requesters[key];
    PruneServices(state, now);
    const auto existing = state.services.find(service);
    const bool distinctService = existing == state.services.end();
    if (distinctService) {
        while (state.services.size() >= m_maxServicesPerRequester) {
            const auto oldest = std::min_element(
                state.services.begin(), state.services.end(),
                [](const auto& left, const auto& right) {
                    return left.second < right.second;
                });
            if (oldest == state.services.end()) break;
            state.services.erase(oldest);
        }
        state.services.emplace(service, now);
    } else {
        existing->second = now;
    }
    state.lastSeen100ns = now;
    state.lastTouchedSequence = SaturatingAdd(m_touchSequence, 1);
    m_touchSequence = state.lastTouchedSequence;
    state.displayRequester = requester;

    const bool threshold = state.services.size() >= m_minServiceCount;
    const bool firstAlert = state.lastAlertedServiceCount == 0;
    const bool cooldownElapsed =
        m_dedup100ns == 0 || state.suppressUntil100ns == 0 ||
        now >= state.suppressUntil100ns;
    const bool evidenceEscalated = distinctService &&
        state.services.size() >=
            state.lastAlertedServiceCount + m_minServiceCount;
    if (threshold && (firstAlert || cooldownElapsed || evidenceEscalated)) {
        state.lastAlertedServiceCount = state.services.size();
        state.suppressUntil100ns =
            m_dedup100ns == 0 ? 0 : SaturatingAdd(now, m_dedup100ns);
        WriteState(event, sourceIp, state);
    }
    EvictLeastRecentlyTouched(m_requesters, m_stateCapacity);
}

} // namespace edr
