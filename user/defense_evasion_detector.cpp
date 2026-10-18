/*
 * defense_evasion_detector.cpp - See defense_evasion_detector.h.
 */
#include "defense_evasion_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <string>
#include <unordered_set>
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

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (Contains(value, needle)) return true;
    }
    return false;
}

bool IsProtectedServiceName(const std::string& lowerName) {
    static const std::unordered_set<std::string> kNames = {
        "windefend",
        "wdnisvc",
        "securityhealthservice",
        "sense",
        "mpssvc",
        "sharedaccess",
        "sysmon",
        "sysmon64",
        "eventlog",
        "wscsvc",
        "msseces",
        "savservice",
    };
    return kNames.find(lowerName) != kNames.end();
}

bool CommandTargetsProtected(const std::string& lowerCommand) {
    return ContainsAny(lowerCommand, {
        "windefend",
        "wdnisvc",
        "securityhealthservice",
        "sense",
        "mpssvc",
        "sharedaccess",
        "sysmon",
        "eventlog",
        "wscsvc",
        "msseces",
        "savservice",
        "msmpeng",
        "mssecs",
    });
}

std::string ClassifyDefenseEvasionCommand(const std::string& image,
                                          const std::string& commandLine) {
    const std::string name = BaseName(image);
    const std::string cmd = LowerAscii(commandLine);

    if (Contains(cmd, "set-mppreference") &&
        ContainsAny(cmd, {
            "disablerealtimemonitoring",
            "disablebehaviormonitoring",
            "disableioavprotection",
            "disableintrusionpreventionsystem",
            "disablescriptscanning"})) {
        return "defender_disable";
    }

    if (Contains(cmd, "reg add") &&
        ContainsAny(cmd, {
            "disableantispyware",
            "disablerealtimemonitoring",
            "disablebehaviormonitoring",
            "disableioavprotection"})) {
        return "defender_disable";
    }

    if (ContainsAny(cmd, {
            "sc stop ",
            "sc config ",
            "sc delete ",
            "net stop ",
            "stop-service",
            "taskkill /f /im "}) &&
        CommandTargetsProtected(cmd)) {
        return "security_service_tamper";
    }

    if (Contains(cmd, "wevtutil") &&
        (Contains(cmd, "clear-log") || Contains(cmd, "clearlog") ||
         Contains(cmd, " cl "))) {
        return "audit_log_tamper";
    }
    if (ContainsAny(cmd, {"clear-eventlog", "remove-eventlog"}) ||
        (Contains(cmd, "auditpol") && Contains(cmd, "/clear"))) {
        return "audit_log_tamper";
    }

    if (ContainsAny(cmd, {
            "netsh advfirewall set allprofiles state off",
            "netsh advfirewall firewall set opmode disable",
            "netsh firewall set opmode disable",
            "set-netfirewallprofile -enabled false"})) {
        return "firewall_disable";
    }

    if (name == "bcdedit.exe" &&
        (ContainsAny(cmd, {"testsigning on", "debug on"}))) {
        return "boot_config_tamper";
    }

    if (name == "sc.exe" && CommandTargetsProtected(cmd)) {
        return "security_service_tamper";
    }

    return "";
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
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

std::string ClassifyDefenseEvasionEvent(const Event& event) {
    if (event.type == EDR_EVT_PROCESS_START) {
        return ClassifyDefenseEvasionCommand(
            FieldValue(event, field::kImage),
            FieldValue(event, field::kCommandLine));
    }

    if (event.type == EDR_EVT_ETW_TAMPER) {
        const std::string type = LowerAscii(FieldValue(event, field::kEtwTamperType));
        if (type.find("patched") != std::string::npos)
            return "etw_patch";
        if (type.find("provider") != std::string::npos)
            return "etw_provider_disable";
        if (type.find("session") != std::string::npos)
            return "etw_session_stop";
        return "etw_telemetry_tamper";
    }

    if (event.type == EDR_EVT_DEFENDER) {
        const std::string operation =
            LowerAscii(FieldValue(event, field::kOperationType));
        if (operation.find("realtime_protection_disabled") != std::string::npos)
            return "defender_disable";
        if (operation.find("config_changed") != std::string::npos)
            return "defender_policy_change";
        return "";
    }

    if (event.type == EDR_EVT_SERVICE_CHANGE) {
        const std::string service =
            LowerAscii(FieldValue(event, field::kServiceName));
        if (!IsProtectedServiceName(service)) return "";
        const std::string action =
            LowerAscii(FieldValue(event, field::kServiceAction));
        if (action == "removed") return "security_service_removed";
        if (action == "added" || action == "modified")
            return "security_service_tamper";
    }

    return "";
}

DefenseEvasionDetector::DefenseEvasionDetector(
    bool enabled, uint32_t windowSeconds, size_t stateCapacity,
    uint32_t minTechniques, uint32_t dedupSeconds)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minTechniques(std::max<uint32_t>(2, minTechniques)),
      m_dedup100ns(static_cast<uint64_t>(dedupSeconds) *
                   kFiletimeTicksPerSecond) {}

bool DefenseEvasionDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_SERVICE_CHANGE ||
           type == EDR_EVT_DEFENDER ||
           type == EDR_EVT_ETW_TAMPER;
}

void DefenseEvasionDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        KeyState& state = it->second;
        for (auto tech = state.techniques.begin();
             tech != state.techniques.end();) {
            if (now100ns >= tech->second.lastSeen100ns &&
                now100ns - tech->second.lastSeen100ns > m_window100ns)
                tech = state.techniques.erase(tech);
            else
                ++tech;
        }
        if (state.techniques.empty())
            it = m_keys.erase(it);
        else
            ++it;
    }
}

void DefenseEvasionDetector::WriteState(Event& event,
                                        const KeyState& state) {
    std::vector<std::string> techniques;
    for (const auto& entry : state.techniques)
        techniques.push_back(entry.first);
    std::sort(techniques.begin(), techniques.end());

    std::string joined;
    for (const std::string& technique : techniques) {
        if (!joined.empty()) joined += ",";
        joined += technique;
    }

    const uint32_t count = static_cast<uint32_t>(techniques.size());
    event.fields[field::kDefenseEvasionScore] =
        std::to_string(std::min(100u, count * 30u));
    event.fields[field::kDefenseEvasionTechniques] = joined;
    event.fields[field::kDefenseEvasionCount] = std::to_string(count);
    event.fields[field::kDefenseEvasionWindowSeconds] =
        std::to_string(m_windowSeconds);
    event.fields[field::kDefenseEvasionVerdict] =
        "multi_stage_defense_evasion";
}

void DefenseEvasionDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    const std::string technique = ClassifyDefenseEvasionEvent(event);
    if (technique.empty()) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    KeyState& state = m_keys["host"];
    if (state.lastSeen100ns != 0 && now < state.lastSeen100ns)
        return;
    state.lastSeen100ns = now;
    state.techniques[technique].lastSeen100ns = now;
    EvictOldest(m_keys, m_stateCapacity);

    const uint32_t count = static_cast<uint32_t>(state.techniques.size());
    if (count < m_minTechniques) return;

    const bool grew = count > state.lastFlaggedCount;
    const bool cooled =
        state.lastStamp100ns == 0 ||
        (now >= state.lastStamp100ns &&
         now - state.lastStamp100ns >= m_dedup100ns);
    if (!grew && !cooled) return;

    WriteState(event, state);
    state.lastFlaggedCount = count;
    state.lastStamp100ns = now;
}

} // namespace edr
