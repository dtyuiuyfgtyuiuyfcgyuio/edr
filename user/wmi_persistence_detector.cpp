/*
 * wmi_persistence_detector.cpp - See wmi_persistence_detector.h.
 */
#include "wmi_persistence_detector.h"

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

WmiPersistenceDetector::WmiPersistenceDetector(bool enabled,
                                               uint32_t windowSeconds,
                                               size_t stateCapacity,
                                               uint32_t minMatches)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minMatches(std::max<uint32_t>(1, minMatches)) {}

bool WmiPersistenceDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_WMI_EVENT || type == EDR_EVT_PROCESS_START;
}

bool WmiPersistenceDetector::IsSubscriptionOperation(
    const std::string& operation) const {
    const std::string op = LowerAscii(operation);
    return op == "temporary_event_subscription" ||
           op == "permanent_event_subscription" ||
           op == "filter_to_consumer_binding" ||
           op == "provider_load";
}

void WmiPersistenceDetector::RecordSubscription(const Event& event,
                                                uint64_t now100ns) {
    const std::string op = FieldValue(event, field::kOperationType);
    if (!IsSubscriptionOperation(op)) return;

    std::string payload;
    for (const char* name : {
             field::kWmiQuery, field::kWmiOperation, field::kWmiProviderName,
             field::kWmiProviderPath, field::kWmiHostProcess,
             field::kWmiPossibleCause}) {
        const std::string value = FieldValue(event, name);
        if (!value.empty()) {
            if (!payload.empty()) payload += " ";
            payload += value;
        }
    }
    if (payload.empty()) return;

    const std::string query = FieldValue(event, field::kWmiQuery);
    std::string key = query.empty()
        ? "consumer:" + FieldValue(event, field::kWmiProviderName) + ":" +
              FieldValue(event, field::kWmiOperation)
        : query;
    key = LowerAscii(key);
    if (key.empty() || key == "consumer::") return;

    SubscriptionInfo info;
    info.payload = LowerAscii(payload);
    info.lastSeen100ns = now100ns;
    auto existing = m_subscriptions.find(key);
    if (existing == m_subscriptions.end()) {
        m_subscriptions.emplace(key, info);
    } else {
        existing->second = info;
    }
    EvictOldest(m_subscriptions, m_stateCapacity);
}

void WmiPersistenceDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_subscriptions.begin(); it != m_subscriptions.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_subscriptions.erase(it);
        } else {
            ++it;
        }
    }
}

bool WmiPersistenceDetector::PayloadMatches(const std::string& payload,
                                            const Event& event) const {
    const std::string image = LowerAscii(FieldValue(event, field::kImage));
    if (!image.empty() && payload.find(image) != std::string::npos) return true;

    const std::string cmd = LowerAscii(FieldValue(event, field::kCommandLine));
    size_t pos = 0;
    while (pos < cmd.size()) {
        while (pos < cmd.size() &&
               (cmd[pos] == ' ' || cmd[pos] == '\t' || cmd[pos] == '\r' ||
                cmd[pos] == '\n' || cmd[pos] == '"' || cmd[pos] == '\'')) {
            ++pos;
        }
        const size_t start = pos;
        while (pos < cmd.size() &&
               (cmd[pos] != ' ' && cmd[pos] != '\t' && cmd[pos] != '\r' &&
                cmd[pos] != '\n' && cmd[pos] != '"' && cmd[pos] != '\'')) {
            ++pos;
        }
        if (pos - start >= 6 &&
            payload.find(cmd.substr(start, pos - start)) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void WmiPersistenceDetector::WriteState(
    Event& event, uint32_t matches, uint32_t score,
    const std::vector<std::string>& matched) {
    std::string joined;
    for (const std::string& snippet : matched) {
        if (!joined.empty()) joined += " | ";
        joined += snippet.substr(0, 160);
    }
    event.fields[field::kWmiPersistenceScore] = std::to_string(score);
    event.fields[field::kWmiPersistenceMatches] = std::to_string(matches);
    event.fields[field::kWmiPersistenceMatchText] = joined;
    event.fields[field::kWmiPersistenceWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) event.fields[field::kWmiPersistenceVerdict] = verdict;
}

void WmiPersistenceDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    if (event.type == EDR_EVT_WMI_EVENT) {
        RecordSubscription(event, now);
        return;
    }

    if (event.type != EDR_EVT_PROCESS_START) return;

    std::vector<std::string> matched;
    for (const auto& entry : m_subscriptions) {
        if (PayloadMatches(entry.second.payload, event)) {
            matched.push_back(entry.second.payload);
            if (matched.size() >= 8) break;
        }
    }
    if (matched.size() < m_minMatches) return;

    const uint32_t matches =
        std::min<uint32_t>(8, static_cast<uint32_t>(matched.size()));
    const uint32_t score = std::min(100u, matches * 35u + 20u);
    WriteState(event, matches, score, matched);
}

} // namespace edr
