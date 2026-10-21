/*
 * doh_abuse_detector.cpp - See doh_abuse_detector.h.
 */
#include "doh_abuse_detector.h"

#include <windows.h>

#include <algorithm>
#include <cassert>
#include <cctype>
#include <string>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
constexpr uint64_t kMaxFutureTicks = 300ULL * kFiletimeTicksPerSecond;
// Bound retained timestamped evidence across all processes and per process.
// At either cap, oldest samples are discarded, which can lower sensitivity
// but cannot extend evidence beyond the configured sliding window.
constexpr size_t kMaxObservations = 100000;
constexpr size_t kMaxObservationsPerProcess = 1024;
constexpr size_t kMaxImageLength = 4096;
constexpr size_t kMaxSourceLength = 64;
constexpr size_t kMaxEndpointIdLength = 128;

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

/* Strip trailing dot of fully-qualified names. */
std::string NormalizeQueryName(const std::string& name) {
    std::string lower = LowerAscii(name);
    while (!lower.empty() && lower.back() == '.') lower.pop_back();
    return lower;
}

uint64_t WallTime100ns() {
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool IsAsciiToken(const std::string& value, size_t maxLength) {
    if (value.empty() || value.size() > maxLength) return false;
    for (unsigned char c : value) {
        if (c < 0x21 || c > 0x7e) return false;
    }
    return true;
}

void AppendKeyPart(std::string& key, const std::string& part) {
    key += std::to_string(part.size());
    key.push_back(':');
    key += part;
    key.push_back('|');
}

bool IsGuidIdentity(const std::string& raw) {
    size_t begin = 0;
    size_t end = raw.size();
    if (end == 38 && raw.front() == '{' && raw.back() == '}') {
        begin = 1;
        --end;
    }
    if (end - begin != 36) return false;
    bool nonzero = false;
    for (size_t i = begin; i < end; ++i) {
        const size_t offset = i - begin;
        if (offset == 8 || offset == 13 || offset == 18 || offset == 23) {
            if (raw[i] != '-') return false;
        } else {
            const unsigned char c = static_cast<unsigned char>(raw[i]);
            if (!std::isxdigit(c)) return false;
            nonzero = nonzero || c != '0';
        }
    }
    return nonzero;
}

bool ResolveAggregationKey(const Event& event, const std::string& image,
                           std::string& key) {
    if (image.empty() || image.size() > kMaxImageLength) return false;
    std::string source = event.source;
    const auto sourceField = event.fields.find(field::kSource);
    if (!source.empty()) {
        if (sourceField != event.fields.end() && sourceField->second != source)
            return false;
    } else if (sourceField != event.fields.end()) {
        source = sourceField->second;
    }
    if (!IsAsciiToken(source, kMaxSourceLength)) return false;

    std::string endpointId;
    const auto endpointField = event.fields.find(field::kEndpointId);
    if (endpointField != event.fields.end()) {
        endpointId = endpointField->second;
        if (!IsAsciiToken(endpointId, kMaxEndpointIdLength)) return false;
    }

    std::string processIdentity;
    if (event.processStartTime100ns != 0) {
        if (event.pid == 0 || event.processStartTime100ns > event.ts100ns)
            return false;
        processIdentity = "pidstart:" + std::to_string(event.pid) + ":" +
                          std::to_string(event.processStartTime100ns);
    } else if (IsGuidIdentity(event.processIdentity)) {
        processIdentity = "guid:" + LowerAscii(event.processIdentity);
    } else {
        return false;
    }

    key.clear();
    AppendKeyPart(key, endpointId);
    AppendKeyPart(key, source);
    AppendKeyPart(key, image);
    AppendKeyPart(key, processIdentity);
    return true;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

} // namespace

DohAbuseDetector::DohAbuseDetector(bool enabled, uint32_t windowSeconds,
                                   size_t stateCapacity,
                                   uint32_t minRepeatCount)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minRepeatCount(std::max<uint32_t>(1, minRepeatCount)) {}

bool DohAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_DNS_QUERY;
}

const std::unordered_set<std::string>&
DohAbuseDetector::KnownEndpoints() {
    static const std::unordered_set<std::string> kEndpoints = {
        "cloudflare-dns.com",
        "one.one.one.one",
        "chrome.cloudflare-dns.com",
        "firefox.dns.nextdns.io",
        "dns.google",
        "dns.quad9.net",
        "dns9.quad9.net",
        "securedns.es",
        "doh.opendns.com",
        "doh.cleanbrowsing.org",
        "doh.mullvad.net",
        "dns.adguard.com",
        "doh.libredns.gr",
        "doh.sb",
        "dns.surfsharkdns.com",
    };
    return kEndpoints;
}

std::string DohAbuseDetector::EndpointFor(const std::string& queryName) {
    const std::unordered_set<std::string>& endpoints = KnownEndpoints();
    auto found = endpoints.find(queryName);
    if (found != endpoints.end()) return *found;

    /* Subdomains of known providers still count as the provider. */
    for (const std::string& endpoint : endpoints) {
        if (queryName.size() > endpoint.size() &&
            queryName.compare(queryName.size() - endpoint.size(),
                              endpoint.size(), endpoint) == 0 &&
            queryName[queryName.size() - endpoint.size() - 1] == '.') {
            return endpoint;
        }
    }
    return std::string();
}

bool DohAbuseDetector::IsBrowserOrSystem(const std::string& image) {
    static const char* kBenign[] = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
        "vivaldi.exe", "safari.exe", "svchost.exe", "dnsclient.exe",
        "systemsettings.exe", "onedrive.exe"
    };
    const std::string lower = LowerAscii(image);
    const size_t slash = lower.find_last_of("\\/");
    const std::string base = slash == std::string::npos
                                 ? lower
                                 : lower.substr(slash + 1);
    for (const char* benign : kBenign) {
        if (base == benign) return true;
    }
    return false;
}

void DohAbuseDetector::PurgeExpired(uint64_t now100ns) {
    const uint64_t boundary = now100ns > m_window100ns
        ? now100ns - m_window100ns : 0;
    while (!m_observationTimeIndex.empty() &&
           m_observationTimeIndex.begin()->first <= boundary) {
        DropOldestObservation();
    }
}

void DohAbuseDetector::EraseState(
    std::unordered_map<std::string, KeyState>::iterator stateIt) {
    if (stateIt == m_keys.end()) return;
    KeyState& state = stateIt->second;
    for (const Observation& observation : state.observations)
        m_observationTimeIndex.erase(observation.timeIndex);
    m_totalObservations -= state.observations.size();
    if (state.hasLastSeenIndex) m_lastSeenIndex.erase(state.lastSeenIndex);
    m_keys.erase(stateIt);
}

void DohAbuseDetector::DropOldestObservation() {
    if (m_observationTimeIndex.empty()) return;
    const auto oldestObservation = m_observationTimeIndex.begin();
    KeyState* statePointer = oldestObservation->second;
    assert(statePointer != nullptr);
    const std::string* keyPointer = statePointer->mapKey;
    assert(keyPointer != nullptr);

    auto stateIt = m_keys.find(*keyPointer);
    assert(stateIt != m_keys.end());
    assert(&stateIt->second == statePointer);
    assert(!stateIt->second.observations.empty());
    assert(stateIt->second.observations.front().timeIndex == oldestObservation);

    KeyState& state = stateIt->second;
    m_observationTimeIndex.erase(state.observations.front().timeIndex);
    state.observations.pop_front();
    --m_totalObservations;
    if (state.observations.empty()) EraseState(stateIt);
}

void DohAbuseDetector::EvictOldestState() {
    while (m_keys.size() >= m_stateCapacity && !m_lastSeenIndex.empty()) {
        const std::string* keyPointer = m_lastSeenIndex.begin()->second;
        assert(keyPointer != nullptr);
        auto stateIt = m_keys.find(*keyPointer);
        assert(stateIt != m_keys.end());
        assert(stateIt->second.hasLastSeenIndex);
        EraseState(stateIt);
    }
}

void DohAbuseDetector::TouchState(KeyState& state, uint64_t timestamp100ns) {
    if (state.hasLastSeenIndex) m_lastSeenIndex.erase(state.lastSeenIndex);
    state.lastSeen100ns = timestamp100ns;
    state.lastSeenIndex = m_lastSeenIndex.emplace(timestamp100ns, state.mapKey);
    state.hasLastSeenIndex = true;
}

uint32_t DohAbuseDetector::ComputeScore(size_t queryCount, size_t endpointCount,
                                       bool sawNonBrowser, bool aggregate) const {
    uint32_t score = 0;
    if (endpointCount != 0) score += 40;
    if (aggregate && queryCount >= m_minRepeatCount) score += 20;
    if (aggregate && endpointCount >= 2) score += 15;
    if (sawNonBrowser) score += 20;
    return std::min(100u, score);
}

std::string DohAbuseDetector::SignalList(size_t queryCount, size_t endpointCount,
                                        bool sawNonBrowser, bool aggregate) const {
    std::string signals;
    const std::pair<bool, const char*> kFlags[] = {
        {endpointCount != 0, "doh_endpoint"},
        {aggregate && queryCount >= m_minRepeatCount, "repeat_queries"},
        {aggregate && endpointCount >= 2, "multi_provider"},
        {sawNonBrowser, "non_browser"},
    };
    for (const auto& entry : kFlags) {
        if (!entry.first) continue;
        if (!signals.empty()) signals += ",";
        signals += entry.second;
    }
    return signals;
}

void DohAbuseDetector::WriteState(Event& event, const KeyState& state,
                                  bool aggregate) const {
    std::unordered_set<std::string> endpointSet;
    bool sawNonBrowser = false;
    for (const Observation& observation : state.observations) {
        endpointSet.insert(observation.endpoint);
        sawNonBrowser = sawNonBrowser || observation.nonBrowser;
    }
    const size_t queryCount = state.observations.size();
    const uint32_t score = ComputeScore(queryCount, endpointSet.size(),
                                        sawNonBrowser, aggregate);
    event.fields[field::kDohAbuseScore] = std::to_string(score);
    event.fields[field::kDohAbuseSignals] =
        SignalList(queryCount, endpointSet.size(), sawNonBrowser, aggregate);
    std::string endpoints;
    std::vector<std::string> sortedEndpoints;
    sortedEndpoints.reserve(endpointSet.size());
    for (const std::string& endpoint : endpointSet)
        sortedEndpoints.push_back(endpoint);
    std::sort(sortedEndpoints.begin(), sortedEndpoints.end());
    for (const std::string& endpoint : sortedEndpoints) {
        if (!endpoints.empty()) endpoints += ",";
        endpoints += endpoint;
    }
    event.fields[field::kDohAbuseEndpoints] = endpoints;
    event.fields[field::kDohAbuseQueryCount] =
        std::to_string(queryCount);
    event.fields[field::kDohAbuseWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kDohAbuseVerdict] = verdict;
    }
}

void DohAbuseDetector::Enrich(Event& event) {
    if (!m_enabled || !Inspects(event.type) ||
        event.disposition != EventDisposition::ReportAndEvaluate ||
        event.ts100ns == 0) return;
    const auto phase = event.fields.find("dns_phase");
    if (phase != event.fields.end() && phase->second != "completed") return;

    const uint64_t wallNow = WallTime100ns();
    if (event.ts100ns > wallNow && event.ts100ns - wallNow > kMaxFutureTicks)
        return;
    if (event.processStartTime100ns != 0 &&
        event.processStartTime100ns > event.ts100ns) return;

    const std::string image = FieldValue(event, field::kImage);

    const std::string queryName =
        NormalizeQueryName(FieldValue(event, field::kDnsQueryName));
    const std::string endpoint = EndpointFor(queryName);
    if (endpoint.empty()) return; /* Not a DoH provider lookup. */

    std::string key;
    const bool canAggregate = ResolveAggregationKey(event, image, key);
    auto previous = canAggregate ? m_keys.find(key) : m_keys.end();
    if (canAggregate) {
        if (previous != m_keys.end() &&
            event.ts100ns < previous->second.latestTimestamp100ns) return;
    }

    // Only a valid, recognized DoH observation advances the event-time
    // cleanup. Ordinary DNS and rejected out-of-order observations do not
    // alter any process window.
    PurgeExpired(event.ts100ns);

    if (!canAggregate) {
        KeyState single;
        single.observations.push_back(
            {event.ts100ns, endpoint,
             !image.empty() && !IsBrowserOrSystem(image)});
        WriteState(event, single, false);
        return;
    }

    auto found = m_keys.find(key);
    if (found != m_keys.end() &&
        found->second.observations.size() >= kMaxObservationsPerProcess) {
        m_observationTimeIndex.erase(found->second.observations.front().timeIndex);
        found->second.observations.pop_front();
        --m_totalObservations;
    }

    // Make room from ordered indexes before reacquiring/creating the current
    // state. The global budget may erase its last old observation and state.
    while (m_totalObservations >= kMaxObservations)
        DropOldestObservation();

    found = m_keys.find(key);
    if (found == m_keys.end()) {
        EvictOldestState();
        found = m_keys.emplace(key, KeyState{}).first;
        found->second.mapKey = &found->first;
    }
    KeyState& currentState = found->second;
    const auto observationIndex =
        m_observationTimeIndex.emplace(event.ts100ns, &currentState);
    currentState.observations.push_back({event.ts100ns, endpoint,
                                         !IsBrowserOrSystem(image),
                                         observationIndex});
    currentState.latestTimestamp100ns = event.ts100ns;
    ++m_totalObservations;
    TouchState(currentState, event.ts100ns);

    WriteState(event, currentState, true);
}

} // namespace edr
