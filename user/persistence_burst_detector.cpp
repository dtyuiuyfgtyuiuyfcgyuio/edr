/*
 * persistence_burst_detector.cpp - See persistence_burst_detector.h.
 */
#include "persistence_burst_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <vector>

namespace edr {
namespace {

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

uint64_t EventTime(const Event& event) {
    return event.ts100ns;
}

} // namespace

PersistenceBurstDetector::PersistenceBurstDetector(
    bool enabled, uint32_t windowSeconds, size_t stateCapacity,
    uint32_t minScore, uint32_t dedupSeconds)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    10000000ULL),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minScore(std::max<uint32_t>(10, minScore)),
      m_dedup100ns(static_cast<uint64_t>(dedupSeconds) * 10000000ULL) {}

bool PersistenceBurstDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_REG_WRITE ||
           type == EDR_EVT_SERVICE_CHANGE ||
           type == EDR_EVT_TASK_SCHEDULER ||
           type == EDR_EVT_WMI_EVENT;
}

bool PersistenceBurstDetector::Classify(const Event& event,
                                        std::string* concreteKey,
                                        uint32_t* weight,
                                        std::string* mechanism) const {
    if (event.type == EDR_EVT_SERVICE_CHANGE) {
        const std::string action = LowerAscii(
            FieldValue(event, field::kServiceAction));
        if (action != "added" && action != "modified") return false;
        *concreteKey = "svc:" + FieldValue(event, field::kServiceName);
        *weight = 35;
        *mechanism = "service";
        return true;
    }

    if (event.type == EDR_EVT_REG_WRITE) {
        const std::string key = LowerAscii(
            FieldValue(event, field::kRegKey));
        const bool runKey =
            key.find("\\run") != std::string::npos ||
            key.find("\\runonce") != std::string::npos ||
            key.find("\\startupapproved\\run") != std::string::npos;
        const bool imageFileExecution =
            key.find("image file execution options") != std::string::npos;
        if (!runKey && !imageFileExecution) return false;
        *concreteKey = "reg:" + key + "\\" +
                       FieldValue(event, field::kRegValue);
        *weight = 30;
        *mechanism = "startup";
        return true;
    }

    if (event.type == EDR_EVT_TASK_SCHEDULER) {
        const std::string op = LowerAscii(
            FieldValue(event, field::kOperationType));
        if (op != "task_registered" && op != "task_deleted" &&
            op != "task_updated")
            return false;
        *concreteKey = "task:" + FieldValue(event, field::kTaskName);
        *weight = 20;
        *mechanism = "task";
        return true;
    }

    if (event.type == EDR_EVT_WMI_EVENT) {
        const std::string query = LowerAscii(
            FieldValue(event, field::kWmiQuery));
        /* Event-consumer persistence: __EventFilter +
         * CommandLineEventConsumer / ActiveScriptEventConsumer /
         * __EventConsumer. */
        const bool persistence =
            Contains(query, "__eventfilter") ||
            Contains(query, "commandlineeventconsumer") ||
            Contains(query, "activescripteventconsumer") ||
            Contains(query, "logfileeventconsumer") ||
            Contains(query, "__eventconsumer");
        if (!persistence) return false;
        *concreteKey = "wmi:" + query;
        *weight = 25;
        *mechanism = "wmi";
        return true;
    }

    return false;
}

void PersistenceBurstDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_state.begin(); it != m_state.end();) {
        KeyState& state = it->second;
        for (auto key = state.keys.begin(); key != state.keys.end();) {
            if (now100ns >= key->second &&
                now100ns - key->second > m_window100ns)
                key = state.keys.erase(key);
            else
                ++key;
        }
        if (state.keys.empty())
            it = m_state.erase(it);
        else
            ++it;
    }
}

void PersistenceBurstDetector::WriteState(Event& event,
                                          const KeyState& state) {
    std::unordered_set<std::string> mechanisms;
    uint32_t weight = 0;
    for (const auto& key : state.keys) {
        const char* colon = std::strchr(key.first.c_str(), ':');
        if (!colon) {
            mechanisms.insert(key.first);
            continue;
        }
        const std::string prefix(key.first.c_str(), colon);
        if (prefix == "svc") mechanisms.insert("service");
        else if (prefix == "reg") mechanisms.insert("startup");
        else mechanisms.insert(prefix);
    }
    /* Weight is recomputed from the live keys so expired entries do not
     * inflate the score. */
    for (const auto& key : state.keys) {
        if (key.first.compare(0, 4, "svc:") == 0) weight += 35;
        else if (key.first.compare(0, 4, "reg:") == 0) weight += 30;
        else if (key.first.compare(0, 4, "wmi:") == 0) weight += 25;
        else if (key.first.compare(0, 5, "task:") == 0) weight += 20;
    }
    if (mechanisms.size() >= 4) weight += 20;

    weight = std::min(100u, weight);
    event.fields[field::kPersistBurstScore] = std::to_string(weight);
    event.fields[field::kPersistBurstVerdict] =
        weight >= 75 ? "malicious" : "suspicious";

    std::vector<std::string> sorted(mechanisms.begin(), mechanisms.end());
    std::sort(sorted.begin(), sorted.end());
    std::string joined;
    for (const std::string& m : sorted) {
        if (!joined.empty()) joined += ",";
        joined += m;
    }
    event.fields[field::kPersistBurstMechanisms] = joined;
    event.fields[field::kPersistBurstCount] =
        std::to_string(state.keys.size());
    event.fields[field::kPersistBurstWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void PersistenceBurstDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string concreteKey, mechanism;
    uint32_t weight = 0;
    if (!Classify(event, &concreteKey, &weight, &mechanism)) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    KeyState& state = m_state["host"];
    if (state.lastSeen100ns != 0 && now < state.lastSeen100ns)
        return; /* reject time rollback */
    state.lastSeen100ns = now;
    state.keys[concreteKey] = now;

    if (m_state.size() > m_stateCapacity) {
        auto oldest = std::min_element(m_state.begin(), m_state.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastSeen100ns <
                       right.second.lastSeen100ns;
            });
        if (oldest != m_state.end()) m_state.erase(oldest);
    }

    uint32_t total = 0;
    std::unordered_set<std::string> mechanisms;
    for (const auto& key : state.keys) {
        if (key.first.compare(0, 4, "svc:") == 0) total += 35;
        else if (key.first.compare(0, 4, "reg:") == 0) total += 30;
        else if (key.first.compare(0, 4, "wmi:") == 0) total += 25;
        else if (key.first.compare(0, 5, "task:") == 0) total += 20;
        const char* colon = std::strchr(key.first.c_str(), ':');
        if (colon) mechanisms.insert(std::string(key.first.c_str(), colon));
        else mechanisms.insert(key.first);
    }
    if (mechanisms.size() >= 4) total += 20;
    total = std::min(100u, total);

    if (total < m_minScore) return;

    const bool grew = total > state.lastWeight;
    const bool cooled =
        state.lastStamp100ns == 0 ||
        (now >= state.lastStamp100ns &&
         now - state.lastStamp100ns >= m_dedup100ns);
    if (!grew && !cooled) return;

    WriteState(event, state);
    state.lastWeight = total;
    state.lastStamp100ns = now;
}

} // namespace edr
