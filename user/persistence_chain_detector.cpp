/*
 * persistence_chain_detector.cpp - See persistence_chain_detector.h.
 *
 * Per (pid, image basename) key, persistence mechanisms are tracked within a
 * rolling window. When at least minMechanisms distinct mechanisms are
 * observed, the current event is stamped with persist_chain_score
 * (min(100, count*25)), persist_chain_mechanisms (sorted comma list),
 * persist_chain_count, and persist_chain_window_seconds. Each key is flagged
 * once per window; when all of its mechanisms expire the key is dropped so
 * the flag resets and the threshold must be re-met before fields are emitted
 * again. Mechanism extraction is field-only: REG_WRITE keys, TASK_SCHEDULER
 * events, SERVICE_CHANGE additions, Startup-folder FILE_CREATE events, and
 * WMI permanent-subscription events (5859/5861).
 */
#include "persistence_chain_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <set>
#include <string>
#include <vector>

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

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

/* Maps one event to its persistence mechanism; empty when the event is not
 * a persistence write. Pure, field-only extraction. */
std::string MechanismForEvent(const Event& event) {
    const std::string type = FieldValue(event, field::kType);
    if (type == "REG_WRITE") {
        const std::string key = LowerAscii(FieldValue(event, field::kRegKey));
        if (Contains(key, "currentversion\\run")) return "run_key";
        if (Contains(key, "image file execution options"))
            return "ifeo_debugger";
        if (Contains(key, "winlogon")) return "winlogon";
        if (Contains(key, "appinit_dlls") ||
            Contains(LowerAscii(FieldValue(event, field::kRegValue)),
                     "appinit_dlls"))
            return "appinit_dlls";
        if (Contains(key, "control\\lsa") ||
            Contains(key, "\\lsa")) return "lsa_packages";
        if (Contains(key, "clsid") && Contains(key, "inprocserver32"))
            return "com_inproc";
        if (Contains(key, "securityproviders\\wdigest"))
            return "wdigest";
        if (Contains(key, "services\\portproxy"))
            return "portproxy";
        if (Contains(key, "appcertdlls"))
            return "appcert_dlls";
        if (Contains(key, "silentprocessexit"))
            return "silent_process_exit";
        return "";
    }
    if (type == "TASK_SCHEDULER") return "scheduled_task";
    if (type == "SERVICE_CHANGE") {
        const std::string action = FieldValue(event, field::kServiceAction);
        return action == "added" ? "service" : "";
    }
    if (type == "FILE_CREATE") {
        const std::string path = LowerAscii(FieldValue(event, field::kFilePath));
        if (Contains(path, "\\startup\\") ||
            Contains(path, "programs\\startup"))
            return "startup_folder";
        return "";
    }
    if (type == "WMI_EVENT") {
        const std::string wmiId = FieldValue(event, field::kWmiEventId);
        if (wmiId == "5859" || wmiId == "5861") return "wmi_subscription";
        return "";
    }
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

PersistenceChainDetector::PersistenceChainDetector(
    bool enabled, uint32_t windowSeconds, size_t stateCapacity,
    uint32_t minMechanisms)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minMechanisms(std::max<uint32_t>(2, minMechanisms)) {}

bool PersistenceChainDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_REG_WRITE || type == EDR_EVT_TASK_SCHEDULER ||
           type == EDR_EVT_SERVICE_CHANGE || type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_WMI_EVENT;
}

void PersistenceChainDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        KeyState& state = it->second;
        for (auto mech = state.mechanisms.begin();
             mech != state.mechanisms.end();) {
            if (now100ns >= mech->second.lastSeen100ns &&
                now100ns - mech->second.lastSeen100ns > m_window100ns)
                mech = state.mechanisms.erase(mech);
            else
                ++mech;
        }
        if (state.mechanisms.empty())
            it = m_keys.erase(it);
        else
            ++it;
    }
}

void PersistenceChainDetector::WriteState(Event& event,
                                          const KeyState& state) {
    std::vector<std::string> mechanisms;
    for (const auto& entry : state.mechanisms) {
        mechanisms.push_back(entry.first);
    }
    std::sort(mechanisms.begin(), mechanisms.end());

    std::string joined;
    for (const std::string& mechanism : mechanisms) {
        if (!joined.empty()) joined += ",";
        joined += mechanism;
    }

    const uint32_t count = static_cast<uint32_t>(mechanisms.size());
    event.fields[field::kPersistChainScore] =
        std::to_string(std::min(100u, count * 25u));
    event.fields[field::kPersistChainMechanisms] = joined;
    event.fields[field::kPersistChainCount] = std::to_string(count);
    event.fields[field::kPersistChainWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void PersistenceChainDetector::Enrich(Event& event) {
    if (!m_enabled || event.pid == 0) return;

    const std::string mechanism = MechanismForEvent(event);
    if (mechanism.empty()) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string image = BaseName(FieldValue(event, field::kImage));
    const std::string key = std::to_string(event.pid) + "@" + image;

    KeyState& state = m_keys[key];
    auto existing = state.mechanisms.find(mechanism);
    if (existing == state.mechanisms.end()) {
        MechanismInfo info;
        info.lastSeen100ns = now;
        state.mechanisms.emplace(mechanism, info);
    } else {
        existing->second.lastSeen100ns = now;
    }
    state.lastSeen100ns = now;

    const uint32_t count =
        static_cast<uint32_t>(state.mechanisms.size());
    if (count >= m_minMechanisms && count > state.lastFlaggedCount) {
        state.lastFlaggedCount = count;
        WriteState(event, state);
    }

    EvictOldest(m_keys, m_stateCapacity);
}

} // namespace edr
