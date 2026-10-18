/*
 * dns_beacon_detector.cpp - See dns_beacon_detector.h.
 */
#include "dns_beacon_detector.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <string>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kTicksPerSecond = 10000000ULL;
constexpr uint64_t kMaxFutureTicks = 300ULL * kTicksPerSecond;
constexpr double kHighEntropyThreshold = 3.5;
constexpr size_t kMaxTotalObservations = 100000;
constexpr size_t kMaxStateCapacity = 65536;
constexpr size_t kMaxEndpoint = 128;
constexpr size_t kMaxSource = 64;
constexpr size_t kMaxImage = 4096;

uint64_t WallFileTime() {
    FILETIME now{};
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

bool IsBoundedUtf8(const std::string& value, size_t maxLength) {
    if (value.empty() || value.size() > maxLength) return false;
    for (size_t i = 0; i < value.size();) {
        const unsigned char lead = static_cast<unsigned char>(value[i]);
        if (lead < 0x80) {
            if (lead == 0 || lead < 0x20 || lead == 0x7f) return false;
            ++i;
            continue;
        }
        size_t continuation = 0;
        uint32_t codepoint = 0;
        if (lead >= 0xc2 && lead <= 0xdf) {
            continuation = 1;
            codepoint = lead & 0x1f;
        } else if (lead >= 0xe0 && lead <= 0xef) {
            continuation = 2;
            codepoint = lead & 0x0f;
        } else if (lead >= 0xf0 && lead <= 0xf4) {
            continuation = 3;
            codepoint = lead & 0x07;
        } else {
            return false;
        }
        if (i + continuation >= value.size()) return false;
        for (size_t n = 1; n <= continuation; ++n) {
            const unsigned char byte = static_cast<unsigned char>(value[i + n]);
            if (byte < 0x80 || byte > 0xbf) return false;
            codepoint = (codepoint << 6) | (byte & 0x3f);
        }
        if ((continuation == 2 && codepoint < 0x800) ||
            (continuation == 3 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) ||
            codepoint > 0x10ffff) return false;
        i += continuation + 1;
    }
    return true;
}

bool IsHex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

char LowerAscii(char c) {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
}

bool NormalizeProcessGuid(const std::string& raw, std::string& normalized) {
    size_t begin = 0;
    size_t end = raw.size();
    if (end == 38 && raw.front() == '{' && raw.back() == '}') {
        begin = 1;
        --end;
    }
    if (end - begin != 36) return false;
    static constexpr size_t kHyphens[] = {8, 13, 18, 23};
    bool nonzero = false;
    normalized.clear();
    normalized.reserve(36);
    for (size_t i = begin; i < end; ++i) {
        const size_t offset = i - begin;
        const bool hyphen = offset == kHyphens[0] || offset == kHyphens[1] ||
                            offset == kHyphens[2] || offset == kHyphens[3];
        if (hyphen) {
            if (raw[i] != '-') return false;
            normalized.push_back('-');
        } else {
            if (!IsHex(raw[i])) return false;
            const char c = LowerAscii(raw[i]);
            nonzero = nonzero || c != '0';
            normalized.push_back(c);
        }
    }
    return nonzero;
}

bool ParseHighEntropy(const Event& event) {
    const auto found = event.fields.find(field::kDnsEntropy);
    if (found == event.fields.end() || found->second.empty() ||
        found->second.size() > 32) return false;
    bool dot = false;
    bool digit = false;
    for (unsigned char c : found->second) {
        if (c == '.' && !dot) {
            dot = true;
            continue;
        }
        if (c < '0' || c > '9') return false;
        digit = true;
    }
    if (!digit) return false;
    char* end = nullptr;
    const double value = std::strtod(found->second.c_str(), &end);
    return end == found->second.c_str() + found->second.size() &&
           std::isfinite(value) && value >= 0.0 && value <= 8.0 &&
           value > kHighEntropyThreshold;
}

std::string FieldValue(const Event& event, const char* name) {
    const auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

void AppendKeyPart(std::string& key, const std::string& part) {
    key += std::to_string(part.size());
    key.push_back(':');
    key += part;
    key.push_back('|');
}

bool ResolveKey(const Event& event, std::string& key) {
    // Native local producers do not carry endpoint_id. An explicitly supplied
    // endpoint must still be valid; absence denotes the local scope.
    std::string endpoint;
    const auto endpointField = event.fields.find(field::kEndpointId);
    if (endpointField != event.fields.end()) {
        endpoint = endpointField->second;
        if (!IsAsciiToken(endpoint, kMaxEndpoint)) return false;
    }

    std::string source = event.source;
    const auto sourceField = event.fields.find(field::kSource);
    if (!source.empty()) {
        if (sourceField != event.fields.end() && sourceField->second != source)
            return false;
    } else if (sourceField != event.fields.end()) {
        source = sourceField->second;
    }
    if (!IsAsciiToken(source, kMaxSource)) return false;

    // Image is optional display metadata. A rename or DOS/device-path alias
    // must not split a reliable process instance into separate counters.
    const std::string image = FieldValue(event, field::kImage);
    if (!image.empty() && !IsBoundedUtf8(image, kMaxImage)) return false;
    if (event.processStartTime100ns != 0 &&
        event.processStartTime100ns > event.ts100ns) return false;

    std::string processKey;
    if (event.pid != 0 && event.processStartTime100ns != 0) {
        processKey = "pidstart:" + std::to_string(event.pid) + ":" +
                     std::to_string(event.processStartTime100ns);
    } else {
        std::string guid;
        if (!NormalizeProcessGuid(event.processIdentity, guid)) return false;
        processKey = "guid:" + guid;
    }

    key.clear();
    AppendKeyPart(key, endpoint);
    AppendKeyPart(key, source);
    AppendKeyPart(key, processKey);
    return true;
}

bool IsCompletedOrUnphased(const Event& event) {
    const auto phase = event.fields.find("dns_phase");
    return phase == event.fields.end() || phase->second == "completed";
}

std::string DomainLabel(std::string host) {
    if (host.empty() || host.size() > 254) return {};
    if (host.back() == '.') host.pop_back();
    if (host.empty() || host.size() > 253) return {};
    for (char& c : host) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    std::vector<std::string> labels;
    size_t start = 0;
    while (start < host.size()) {
        const size_t dot = host.find('.', start);
        const size_t end = dot == std::string::npos ? host.size() : dot;
        const std::string label = host.substr(start, end - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' ||
            label.back() == '-') return {};
        for (char c : label) {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                return {};
        }
        labels.push_back(label);
        start = end + 1;
    }
    if (labels.size() < 2 || host.back() == '.' || labels.back() == "arpa") return {};
    size_t selected = labels.size() - 2;
    if (labels.size() >= 3 && labels.back().size() == 2) {
        const std::string& second = labels[selected];
        if (second == "co" || second == "com" || second == "net" ||
            second == "org" || second == "gov" || second == "edu" ||
            second == "ac") --selected;
    }
    const std::string& label = labels[selected];
    if (label.compare(0, 4, "xn--") == 0) return {};
    return label;
}

void AnalyzeDomain(Event& event) {
    const std::string host = FieldValue(event, field::kDnsQueryName);
    const std::string label = DomainLabel(host);
    if (label.size() < 8) return;
    std::string core;
    for (char c : label) if (c != '-') core += c;
    if (core.size() < 8) return;

    std::array<size_t, 128> counts{};
    size_t letters = 0;
    size_t vowels = 0;
    size_t digits = 0;
    size_t run = 0;
    size_t maxRun = 0;
    size_t alternations = 0;
    for (size_t i = 0; i < core.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(core[i]);
        ++counts[c];
        const bool letter = c >= 'a' && c <= 'z';
        const bool vowel = c == 'a' || c == 'e' || c == 'i' || c == 'o' ||
                           c == 'u' || c == 'y';
        if (letter) {
            ++letters;
            if (vowel) ++vowels;
        } else {
            ++digits;
        }
        run = letter && !vowel ? run + 1 : 0;
        maxRun = std::max(maxRun, run);
        if (i > 0 && ((c >= '0' && c <= '9') !=
                      (core[i - 1] >= '0' && core[i - 1] <= '9')))
            ++alternations;
    }
    if (letters == 0) return;
    double entropy = 0;
    for (size_t count : counts) {
        if (count == 0) continue;
        const double p = static_cast<double>(count) / core.size();
        entropy -= p * std::log2(p);
    }
    const double vowelRatio = static_cast<double>(vowels) / letters;
    uint32_t score = 0;
    std::string signals;
    const auto add = [&](uint32_t points, const char* signal) {
        score += points;
        if (!signals.empty()) signals += ",";
        signals += signal;
    };
    if (entropy >= 4.0) add(30, "very_high_entropy");
    else if (entropy >= 3.6) add(18, "high_entropy");
    if (vowelRatio <= 0.18) add(24, "very_low_vowel_ratio");
    else if (vowelRatio <= 0.26) add(12, "low_vowel_ratio");
    if (maxRun >= 6) add(16, "consonant_run");
    if (static_cast<double>(digits) / core.size() > 0.2 && alternations >= 3)
        add(12, "digit_letter_alternation");
    if (core.size() >= 14 && entropy >= 3.6) add(8, "long_high_entropy_label");
    if (score < 55) return;
    event.fields[field::kDnsDgaScore] = std::to_string(std::min(100u, score));
    event.fields[field::kDnsDgaSignals] = signals;
    event.fields[field::kDnsDgaLabel] = label;
}

} // namespace

DnsBeaconDetector::DnsBeaconDetector(bool enabled, uint32_t windowSeconds,
                                     size_t stateCapacity,
                                     uint32_t minQueryCount,
                                     uint32_t minHighEntropyCount)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(std::max<uint32_t>(1, windowSeconds)) *
                    kTicksPerSecond),
      m_windowSeconds(std::max<uint32_t>(1, windowSeconds)),
      m_stateCapacity(std::max<size_t>(1, std::min(stateCapacity,
                                                   kMaxStateCapacity))),
      m_minQueryCount(minQueryCount),
      m_minHighEntropyCount(minHighEntropyCount) {}

bool DnsBeaconDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_DNS_QUERY;
}

void DnsBeaconDetector::EraseState(std::unordered_map<std::string, KeyState>::iterator it) {
    if (it == m_keys.end()) return;
    m_totalObservations -= it->second.observations.size();
    m_keys.erase(it);
}

void DnsBeaconDetector::EvictOldestKey(
    std::unordered_map<std::string, KeyState>::iterator except) {
    auto oldest = m_keys.end();
    for (auto it = m_keys.begin(); it != m_keys.end(); ++it) {
        if (it == except) continue;
        if (oldest == m_keys.end() ||
            it->second.lastSeenWall100ns < oldest->second.lastSeenWall100ns)
            oldest = it;
    }
    if (oldest != m_keys.end()) EraseState(oldest);
}

void DnsBeaconDetector::MakeObservationRoom(
    std::unordered_map<std::string, KeyState>::iterator current) {
    while (m_totalObservations >= kMaxTotalObservations) {
        const size_t before = m_totalObservations;
        EvictOldestKey(current);
        if (m_totalObservations < before) continue;

        KeyState& state = current->second;
        if (state.observations.empty()) return;
        const Observation removed = state.observations.front();
        state.observations.pop_front();
        --m_totalObservations;
        --state.totalCount;
        if (removed.highEntropy) --state.highEntropyCount;
        state.discardedThrough100ns = std::max(
            state.discardedThrough100ns, removed.timestamp100ns);
    }
}

void DnsBeaconDetector::Enrich(Event& event) {
    if (!m_enabled || !Inspects(event.type) ||
        event.disposition != EventDisposition::ReportAndEvaluate ||
        event.ts100ns == 0 || !IsCompletedOrUnphased(event)) return;

    const uint64_t wallNow = WallFileTime();
    if (event.ts100ns > wallNow && event.ts100ns - wallNow > kMaxFutureTicks)
        return;

    std::string key;
    const bool hasIdentity = ResolveKey(event, key);
    auto stateIt = hasIdentity ? m_keys.find(key) : m_keys.end();
    if (stateIt != m_keys.end() &&
        event.ts100ns < stateIt->second.latestTimestamp100ns) return;

    // Lexical DGA evidence is independent of process attribution, but never
    // runs for report-only, incomplete, zero-time, or implausibly future data.
    AnalyzeDomain(event);
    if (!hasIdentity) return;

    if (stateIt == m_keys.end()) {
        while (m_keys.size() >= m_stateCapacity) EvictOldestKey(m_keys.end());
        stateIt = m_keys.emplace(key, KeyState{}).first;
    }

    KeyState& state = stateIt->second;
    const uint64_t boundary = event.ts100ns > m_window100ns
        ? event.ts100ns - m_window100ns : 0;
    while (!state.observations.empty() &&
           state.observations.front().timestamp100ns <= boundary) {
        const Observation removed = state.observations.front();
        state.observations.pop_front();
        --m_totalObservations;
        --state.totalCount;
        if (removed.highEntropy) --state.highEntropyCount;
    }
    if (state.discardedThrough100ns != 0 &&
        state.discardedThrough100ns <= boundary)
        state.discardedThrough100ns = 0;

    // A completely expired window ends the old episode even when one query
    // is sufficient to qualify again. Partial expiry alone must not rearm a
    // steady qualifying stream on each new query.
    if (state.observations.empty() && state.discardedThrough100ns == 0)
        state.emittedBand = -1;

    MakeObservationRoom(stateIt);
    const bool highEntropy = ParseHighEntropy(event);
    state.observations.push_back({event.ts100ns, highEntropy});
    ++state.totalCount;
    if (highEntropy) ++state.highEntropyCount;
    ++m_totalObservations;
    state.latestTimestamp100ns = event.ts100ns;
    state.lastSeenWall100ns = wallNow;

    event.fields[field::kDnsBeaconQueryCount] = std::to_string(state.totalCount);
    event.fields[field::kDnsBeaconHighEntropyCount] =
        std::to_string(state.highEntropyCount);
    event.fields[field::kDnsBeaconWindowSeconds] =
        std::to_string(m_windowSeconds);

    const bool qualifies = state.totalCount >= m_minQueryCount &&
                           state.highEntropyCount >= m_minHighEntropyCount;
    const bool hasUnexpiredDiscarded = state.discardedThrough100ns > boundary;
    if (!qualifies) {
        if (!hasUnexpiredDiscarded) state.emittedBand = -1;
        return;
    }

    const uint32_t score = std::min(100u, state.totalCount);
    const int band = score >= 20 ? 2 : (score >= 10 ? 1 : 0);
    if (band <= state.emittedBand) return;
    event.fields[field::kDnsBeaconScore] = std::to_string(score);
    state.emittedBand = band;
}

} // namespace edr
