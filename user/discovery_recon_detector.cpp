/*
 * discovery_recon_detector.cpp - See discovery_recon_detector.h.
 */
#include "discovery_recon_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <initializer_list>
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

std::string ClassifyDiscoveryTechnique(const std::string& image,
                                       const std::string& commandLine) {
    const std::string name = BaseName(image);
    const std::string cmd = LowerAscii(commandLine);

    if (name == "whoami.exe" || name == "quser.exe" ||
        (name == "query.exe" &&
         ContainsAny(cmd, {"user", "session", "process"})) ||
        (name == "net.exe" &&
         ContainsAny(cmd, {"user", "group", "localgroup", "accounts"})) ||
        (name == "wmic.exe" && Contains(cmd, "useraccount"))) {
        return "account_discovery";
    }

    if (name == "nltest.exe" || name == "dsquery.exe" ||
        name == "adfind.exe" || name == "ldifde.exe" ||
        name == "csvde.exe" ||
        (name == "net.exe" &&
         ContainsAny(cmd, {"view /domain", "computer", "accounts /domain"})) ||
        (name == "powershell.exe" &&
         ContainsAny(cmd, {"get-adcomputer", "get-aduser", "get-adgroup"}))) {
        return "domain_discovery";
    }

    if (name == "systeminfo.exe" || name == "msinfo32.exe" ||
        name == "winver.exe" ||
        (name == "wmic.exe" &&
         ContainsAny(cmd, {"os get", "computersystem get", "bios get"}))) {
        return "system_discovery";
    }

    if (name == "ipconfig.exe" || name == "route.exe" ||
        name == "arp.exe" || name == "netstat.exe" ||
        name == "nbtstat.exe" || name == "tracert.exe") {
        return "network_discovery";
    }

    if (name == "tasklist.exe" || name == "ps.exe" ||
        (name == "wmic.exe" && Contains(cmd, "process")) ||
        (name == "powershell.exe" && Contains(cmd, "get-process"))) {
        return "process_discovery";
    }

    if (name == "fltmc.exe" || name == "driverquery.exe" ||
        (name == "wmic.exe" && Contains(cmd, "antivirusproduct")) ||
        (name == "powershell.exe" &&
         ContainsAny(cmd, {
             "get-mpcomputerstatus",
             "get-mppreference",
             "get-service win"})) ||
        (name == "sc.exe" && ContainsAny(cmd, {"query", "qdescription"}))) {
        return "security_software_discovery";
    }

    if (name == "schtasks.exe" && Contains(cmd, "/query") ||
        (name == "powershell.exe" && Contains(cmd, "get-scheduledtask"))) {
        return "scheduled_task_discovery";
    }

    if (name == "reg.exe" && Contains(cmd, "query") ||
        (name == "powershell.exe" &&
         ContainsAny(cmd, {"get-itemproperty", "get-childitem -path hklm"}))) {
        return "registry_discovery";
    }

    if (name == "net.exe" &&
        ContainsAny(cmd, {"share", "view", "use", "session"})) {
        return "share_discovery";
    }

    if (name == "gpresult.exe" || name == "auditpol.exe" ||
        name == "secedit.exe") {
        return "policy_discovery";
    }

    return "";
}

DiscoveryReconDetector::DiscoveryReconDetector(
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

bool DiscoveryReconDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

void DiscoveryReconDetector::PurgeExpired(uint64_t now100ns) {
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

void DiscoveryReconDetector::WriteState(Event& event,
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
    event.fields[field::kDiscoveryScore] =
        std::to_string(std::min(100u, count * 25u));
    event.fields[field::kDiscoveryTechniques] = joined;
    event.fields[field::kDiscoveryCount] = std::to_string(count);
    event.fields[field::kDiscoveryWindowSeconds] =
        std::to_string(m_windowSeconds);
    event.fields[field::kDiscoveryVerdict] =
        "multi_stage_reconnaissance";
}

void DiscoveryReconDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_PROCESS_START) return;

    const std::string technique = ClassifyDiscoveryTechnique(
        FieldValue(event, field::kImage),
        FieldValue(event, field::kCommandLine));
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
