/*
 * doh_abuse_detector.cpp - See doh_abuse_detector.h.
 */
#include "doh_abuse_detector.h"

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

/* Strip trailing dot of fully-qualified names. */
std::string NormalizeQueryName(const std::string& name) {
    std::string lower = LowerAscii(name);
    while (!lower.empty() && lower.back() == '.') lower.pop_back();
    return lower;
}

std::string BaseNameOf(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    return slash == std::string::npos ? value : value.substr(slash + 1);
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
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_keys.erase(it);
        else
            ++it;
    }
}

uint32_t DohAbuseDetector::ComputeScore(const KeyState& state) const {
    uint32_t score = 0;
    if (!state.endpoints.empty()) score += 40;
    if (state.queryCount >= m_minRepeatCount) score += 20;
    if (state.endpoints.size() >= 2) score += 15;
    if (state.sawNonBrowser) score += 20;
    return std::min(100u, score);
}

std::string DohAbuseDetector::SignalList(const KeyState& state) const {
    std::string signals;
    const std::pair<bool, const char*> kFlags[] = {
        {!state.endpoints.empty(), "doh_endpoint"},
        {state.queryCount >= m_minRepeatCount, "repeat_queries"},
        {state.endpoints.size() >= 2, "multi_provider"},
        {state.sawNonBrowser, "non_browser"},
    };
    for (const auto& entry : kFlags) {
        if (!entry.first) continue;
        if (!signals.empty()) signals += ",";
        signals += entry.second;
    }
    return signals;
}

void DohAbuseDetector::WriteState(Event& event, const KeyState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kDohAbuseScore] = std::to_string(score);
    event.fields[field::kDohAbuseSignals] = SignalList(state);
    std::string endpoints;
    for (const std::string& endpoint : state.endpoints) {
        if (!endpoints.empty()) endpoints += ",";
        endpoints += endpoint;
    }
    event.fields[field::kDohAbuseEndpoints] = endpoints;
    event.fields[field::kDohAbuseQueryCount] =
        std::to_string(state.queryCount);
    event.fields[field::kDohAbuseWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kDohAbuseVerdict] = verdict;
    }
}

void DohAbuseDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string image = FieldValue(event, field::kImage);

    std::string key;
    if (event.pid > 0 && !image.empty()) {
        key = "pid:" + std::to_string(event.pid) + "@" + BaseNameOf(image);
    } else if (!image.empty()) {
        key = "img:" + BaseNameOf(image);
    } else {
        return; /* No attribution possible. */
    }

    const std::string queryName =
        NormalizeQueryName(FieldValue(event, field::kDnsQueryName));
    const std::string endpoint = EndpointFor(queryName);
    if (endpoint.empty()) return; /* Not a DoH provider lookup. */

    KeyState& state = m_keys[key];
    ++state.queryCount;
    state.endpoints.insert(endpoint);
    state.sawNonBrowser = !IsBrowserOrSystem(image);
    state.lastSeen100ns = now;

    WriteState(event, state);
    EvictOldest(m_keys, m_stateCapacity);
}

} // namespace edr
