#include "dns_failure_detector.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <unordered_set>

#include <windows.h>

#include "event_bus.h"

namespace edr {
namespace {
constexpr uint64_t kTicksPerSecond = 10000000ULL;
constexpr uint64_t kMaxFutureTicks = 300ULL * kTicksPerSecond;
constexpr size_t kMaxObservations = 256;
constexpr size_t kMaxIdentity = 256;
constexpr size_t kMaxEndpoint = 128;
constexpr size_t kMaxSource = 64;
constexpr size_t kMaxImage = 4096;

uint64_t WallFileTime() {
    FILETIME time{};
    GetSystemTimePreciseAsFileTime(&time);
    return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

bool IsAsciiToken(const std::string& value, size_t maxLength) {
    if (value.empty() || value.size() > maxLength) return false;
    for (unsigned char c : value) {
        if (c < 0x21 || c > 0x7e) return false;
    }
    return true;
}

bool IsBoundedImage(const std::string& value) {
    if (value.empty() || value.size() > kMaxImage) return false;
    for (size_t i = 0; i < value.size();) {
        const unsigned char lead = static_cast<unsigned char>(value[i]);
        if (lead < 0x80) {
            if (lead == 0 || lead < 0x20 || lead == 0x7f) return false;
            ++i;
            continue;
        }
        size_t continuation = 0;
        uint32_t codepoint = 0;
        if (lead >= 0xc2 && lead <= 0xdf) { continuation = 1; codepoint = lead & 0x1f; }
        else if (lead >= 0xe0 && lead <= 0xef) { continuation = 2; codepoint = lead & 0x0f; }
        else if (lead >= 0xf0 && lead <= 0xf4) { continuation = 3; codepoint = lead & 0x07; }
        else return false;
        if (i + continuation >= value.size()) return false;
        for (size_t n = 1; n <= continuation; ++n) {
            const unsigned char byte = static_cast<unsigned char>(value[i + n]);
            if (byte < 0x80 || byte > 0xbf) return false;
            codepoint = (codepoint << 6) | (byte & 0x3f);
        }
        if ((continuation == 2 && codepoint < 0x800) ||
            (continuation == 3 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff) return false;
        i += continuation + 1;
    }
    return true;
}

bool IsGuidIdentity(const std::string& value) {
    size_t begin = 0, end = value.size();
    if (end == 38 && value.front() == '{' && value.back() == '}') {
        begin = 1;
        --end;
    }
    if (end - begin != 36) return false;
    for (size_t i = begin; i < end; ++i) {
        if (i - begin == 8 || i - begin == 13 || i - begin == 18 || i - begin == 23) {
            if (value[i] != '-') return false;
        } else if (!std::isxdigit(static_cast<unsigned char>(value[i]))) {
            return false;
        }
    }
    return true;
}

bool IsTrustedFallbackIdentity(const std::string& value) {
    if (!IsAsciiToken(value, kMaxIdentity)) return false;
    return IsGuidIdentity(value);
}

bool IsIpLiteral(const std::string& name) {
    bool digitsDots = true;
    for (unsigned char c : name) digitsDots = digitsDots && ((c >= '0' && c <= '9') || c == '.');
    if (digitsDots) return true;
    return name.find(':') != std::string::npos;
}

bool NormalizeName(const std::string& raw, std::string& normalized) {
    if (raw.empty() || raw.size() > 254) return false;
    normalized.clear();
    normalized.reserve(raw.size());
    for (unsigned char c : raw) {
        if (c > 0x7e || c < 0x21) return false;
        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + ('a' - 'A'));
        normalized.push_back(static_cast<char>(c));
    }
    if (!normalized.empty() && normalized.back() == '.') normalized.pop_back();
    if (normalized.empty() || normalized.size() > 253 || IsIpLiteral(normalized)) return false;
    size_t labels = 0;
    size_t start = 0;
    while (start < normalized.size()) {
        size_t dot = normalized.find('.', start);
        size_t end = dot == std::string::npos ? normalized.size() : dot;
        const size_t length = end - start;
        if (length == 0 || length > 63 || normalized[start] == '-' || normalized[end - 1] == '-') return false;
        if (length >= 4 && normalized.compare(start, 4, "xn--") == 0) return false;
        for (size_t i = start; i < end; ++i) {
            const unsigned char c = static_cast<unsigned char>(normalized[i]);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
        }
        ++labels;
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    if (labels < 2 || normalized == "localhost" || normalized == "unknown.invalid") return false;
    const auto endsWith = [&normalized](const char* suffix) {
        const size_t n = std::char_traits<char>::length(suffix);
        return normalized.size() >= n && normalized.compare(normalized.size() - n, n, suffix) == 0 &&
               (normalized.size() == n || normalized[normalized.size() - n - 1] == '.');
    };
    const char* localSuffixes[] = {"local", "localhost", "localdomain", "lan", "internal",
                                   "test", "invalid", "example", "arpa"};
    for (const char* suffix : localSuffixes) if (endsWith(suffix)) return false;
    return true;
}

bool ParseHighEntropy(const Event& event) {
    const auto it = event.fields.find(std::string(field::kDnsEntropy));
    if (it == event.fields.end() || it->second.empty() || it->second.size() > 32) return false;
    bool dot = false, digit = false;
    for (unsigned char c : it->second) {
        if (c == '.' && !dot) { dot = true; continue; }
        if (c < '0' || c > '9') return false;
        digit = true;
    }
    if (!digit) return false;
    char* end = nullptr;
    const double value = std::strtod(it->second.c_str(), &end);
    return end == it->second.c_str() + it->second.size() && std::isfinite(value) && value > 3.5 && value <= 8.0;
}

bool GetField(const Event& event, const char* key, std::string& value) {
    const auto it = event.fields.find(std::string(key));
    if (it == event.fields.end()) return false;
    value = it->second;
    return true;
}

void AppendKeyPart(std::string& key, const std::string& part) {
    key += std::to_string(part.size());
    key.push_back(':');
    key += part;
    key.push_back('|');
}

std::string Number(size_t value) { return std::to_string(value); }
} // namespace

DnsFailureDetector::DnsFailureDetector(bool enabled, uint32_t windowSeconds,
                                       size_t stateCapacity, uint32_t minQueries,
                                       uint32_t minDistinctNames,
                                       uint32_t minFailurePercent,
                                       uint32_t minHighEntropyFailures)
    : enabled_(enabled),
      windowTicks_(static_cast<uint64_t>(std::max<uint32_t>(1, windowSeconds)) * kTicksPerSecond),
      stateCapacity_(std::max<size_t>(1, std::min<size_t>(8192, stateCapacity))),
      minQueries_(std::max<uint32_t>(1, std::min<uint32_t>(kMaxObservations, minQueries))),
      minDistinctNames_(std::max<uint32_t>(1, std::min<uint32_t>(kMaxObservations, minDistinctNames))),
      minFailurePercent_(std::max<uint32_t>(1, std::min<uint32_t>(100, minFailurePercent))),
      minHighEntropyFailures_(std::max<uint32_t>(1, std::min<uint32_t>(kMaxObservations, minHighEntropyFailures))) {}

bool DnsFailureDetector::Inspects(uint32_t eventType) {
    return eventType == EDR_EVT_DNS_QUERY;
}

void DnsFailureDetector::Enrich(Event& event) {
    if (!enabled_ || !Inspects(event.type) || event.disposition != EventDisposition::ReportAndEvaluate ||
        event.ts100ns == 0) return;
    std::string phase;
    if (GetField(event, "dns_phase", phase) && phase != "completed") return;
    const uint64_t wallNow = WallFileTime();
    if (event.ts100ns > wallNow && event.ts100ns - wallNow > kMaxFutureTicks) return;

    std::string endpoint, source, fieldSource, image, rawName, normalizedName, status;
    if (GetField(event, field::kEndpointId, endpoint) && !IsAsciiToken(endpoint, kMaxEndpoint)) return;
    if (!GetField(event, field::kImage, image) || !IsBoundedImage(image) ||
        !GetField(event, field::kDnsQueryName, rawName) || !NormalizeName(rawName, normalizedName) ||
        !GetField(event, field::kDnsQueryStatus, status)) return;
    if (!event.source.empty()) {
        source = event.source;
        if (GetField(event, field::kSource, fieldSource) && fieldSource != source) return;
    } else if (!GetField(event, field::kSource, source)) return;
    if (!IsAsciiToken(source, kMaxSource)) return;
    const bool knownSuccess = status == "0";
    const bool failed = status == "9003";
    if (!knownSuccess && !failed) return;

    // A contradictory creation timestamp is stronger evidence of invalid
    // attribution than any fallback identity on the same event.
    if (event.processStartTime100ns != 0 &&
        event.processStartTime100ns > event.ts100ns) return;

    std::string processKey;
    if (event.pid != 0 && event.processStartTime100ns != 0 &&
        event.processStartTime100ns <= event.ts100ns) {
        processKey = "pidstart:" + std::to_string(event.pid) + ":" + std::to_string(event.processStartTime100ns);
    } else if (IsTrustedFallbackIdentity(event.processIdentity)) {
        processKey = "identity:" + event.processIdentity;
    } else return;

    std::string key;
    AppendKeyPart(key, endpoint);
    AppendKeyPart(key, source);
    AppendKeyPart(key, processKey);
    AppendKeyPart(key, image);

    auto found = states_.find(key);
    if (found != states_.end() && event.ts100ns < found->second.latestTimestamp) return;
    if (found == states_.end()) {
        if (states_.size() >= stateCapacity_) {
            auto oldest = std::min_element(states_.begin(), states_.end(), [](const auto& a, const auto& b) {
                return a.second.lastSeen < b.second.lastSeen;
            });
            if (oldest != states_.end()) states_.erase(oldest);
        }
        found = states_.emplace(key, State{}).first;
    }

    State& state = found->second;
    state.latestTimestamp = event.ts100ns;
    state.lastSeen = wallNow;
    while (!state.observations.empty() && event.ts100ns >= state.observations.front().timestamp &&
           event.ts100ns - state.observations.front().timestamp >= windowTicks_) {
        state.observations.pop_front();
    }
    state.observations.push_back({event.ts100ns, normalizedName, failed, failed && ParseHighEntropy(event)});
    while (state.observations.size() > kMaxObservations) state.observations.pop_front();

    size_t failures = 0, highEntropyFailures = 0;
    std::unordered_set<std::string> failedNames;
    for (const auto& observation : state.observations) {
        if (!observation.failed) continue;
        ++failures;
        if (observation.highEntropy) ++highEntropyFailures;
        failedNames.insert(observation.name);
    }
    const size_t queries = state.observations.size();
    const size_t distinct = failedNames.size();
    const size_t percent = queries == 0 ? 0 : failures * 100 / queries;
    const bool qualifies = queries >= minQueries_ && distinct >= minDistinctNames_ &&
                           failures * 100 >= queries * minFailurePercent_;
    event.fields[std::string(field::kDnsFailureQueryCount)] = Number(queries);
    event.fields[std::string(field::kDnsFailureNxdomainCount)] = Number(failures);
    event.fields[std::string(field::kDnsFailureDistinctNames)] = Number(distinct);
    event.fields[std::string(field::kDnsFailurePercent)] = Number(percent);
    event.fields[std::string(field::kDnsFailureHighEntropyCount)] = Number(highEntropyFailures);
    event.fields[std::string(field::kDnsFailureWindowSeconds)] = std::to_string(windowTicks_ / kTicksPerSecond);
    if (!qualifies) state.emittedScore = 0;
    if (!qualifies) return;
    const uint32_t score = highEntropyFailures >= minHighEntropyFailures_ ? 75 : 55;
    if (score <= state.emittedScore) return;
    event.fields[std::string(field::kDnsFailureScore)] = std::to_string(score);
    state.emittedScore = score;
}

} // namespace edr
