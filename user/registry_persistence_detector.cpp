/*
 * registry_persistence_detector.cpp - See registry_persistence_detector.h.
 */
#include "registry_persistence_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <string>

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

RegistryPersistenceDetector::RegistryPersistenceDetector(bool enabled,
                                                         uint32_t windowSeconds,
                                                         size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool RegistryPersistenceDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_REG_WRITE;
}

bool RegistryPersistenceDetector::IsPersistenceRegistryKey(
    const std::string& regKey, std::string& mechanism) {
    const std::string key = LowerAscii(regKey);
    if (key.empty()) return false;

    /* Run / RunOnce keys (T1547.001) */
    if (key.find("\\software\\microsoft\\windows\\currentversion\\run") !=
            std::string::npos ||
        key.find("\\software\\microsoft\\windows\\currentversion\\runonce") !=
            std::string::npos) {
        mechanism = "run_key";
        return true;
    }
    /* IFEO Debugger (T1546.012) */
    if (key.find("\\image file execution options\\") != std::string::npos &&
        (key.find("debugger") != std::string::npos ||
         key.find("globalflag") != std::string::npos ||
         key.find("silentprocessexit") != std::string::npos)) {
        mechanism = "ifeo_debugger";
        return true;
    }
    /* Winlogon Shell / Userinit (T1547.004) */
    if (key.find("\\software\\microsoft\\windows nt\\currentversion\\winlogon") !=
            std::string::npos &&
        (key.find("\\shell") != std::string::npos ||
         key.find("\\userinit") != std::string::npos ||
         key.find("\\notify") != std::string::npos)) {
        mechanism = "winlogon";
        return true;
    }
    /* AppInit_DLLs (T1574.002) */
    if (key.find("\\software\\microsoft\\windows nt\\currentversion\\windows") !=
            std::string::npos &&
        key.find("appinit_dlls") != std::string::npos) {
        mechanism = "appinit_dlls";
        return true;
    }
    /* LSA Security Packages (T1546.008) */
    if (key.find("\\currentcontrolset\\control\\lsa") != std::string::npos &&
        (key.find("security packages") != std::string::npos ||
         key.find("authentication packages") != std::string::npos ||
         key.find("notification packages") != std::string::npos ||
         key.find("\\lsa\\") != std::string::npos)) {
        mechanism = "lsa_security_packages";
        return true;
    }
    /* COM hijacking: InprocServer32 under CLSID (T1546.008 / T1574.001) */
    if (key.find("\\clsid\\") != std::string::npos &&
        key.find("inprocserver32") != std::string::npos) {
        mechanism = "com_hijack";
        return true;
    }
    /* Service registration (T1543.003) */
    if (key.find("\\currentcontrolset\\services\\") != std::string::npos) {
        mechanism = "service_registration";
        return true;
    }
    /* StartupApproved / Explorer shell service objects (T1547.001) */
    if (key.find("\\currentversion\\explorer\\shellexecutehooks") !=
            std::string::npos ||
        key.find("\\currentversion\\explorer\\shellserviceobjects") !=
            std::string::npos) {
        mechanism = "explorer_persistence";
        return true;
    }
    /* WMI event subscription (T1546.003) */
    if (key.find("\\software\\microsoft\\wbem\\subscriptions") !=
            std::string::npos ||
        key.find("\\software\\microsoft\\wbem\\consumer") !=
            std::string::npos) {
        mechanism = "wmi_subscription";
        return true;
    }
    /* Scheduled tasks via registry-backed TaskCache (T1053.005) */
    if (key.find("\\currentversion\\explorer\\taskcache") !=
        std::string::npos) {
        mechanism = "task_cache";
        return true;
    }
    return false;
}

bool RegistryPersistenceDetector::IsSuspiciousServicePath(
    const std::string& imagePath) {
    if (imagePath.empty()) return false;
    const std::string lower = LowerAscii(imagePath);
    /* Service ImagePath can be a quoted path or a bare command line; take the
     * first token (path or executable) before arguments. */
    std::string exePath = lower;
    if (!exePath.empty() && exePath[0] == '"') {
        const size_t quote = exePath.find('"', 1);
        if (quote != std::string::npos) {
            exePath = exePath.substr(1, quote - 1);
        }
    } else {
        const size_t space = exePath.find_first_of(" \t");
        if (space != std::string::npos) {
            exePath = exePath.substr(0, space);
        }
    }
    /* Image path in user-writable or unusual locations */
    if (exePath.find("\\temp\\") != std::string::npos ||
        exePath.find("\\appdata\\") != std::string::npos ||
        exePath.find("\\downloads\\") != std::string::npos ||
        exePath.find("\\desktop\\") != std::string::npos ||
        exePath.find("\\public\\") != std::string::npos ||
        exePath.find("\\programdata\\") != std::string::npos) {
        return true;
    }
    /* cmd.exe / powershell.exe used as service image */
    const size_t slash = exePath.find_last_of("\\/");
    const std::string base = slash == std::string::npos
        ? exePath : exePath.substr(slash + 1);
    return base == "cmd.exe" || base == "powershell.exe" ||
           base == "pwsh.exe" || base == "wscript.exe" ||
           base == "cscript.exe" || base == "rundll32.exe";
}

void RegistryPersistenceDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t RegistryPersistenceDetector::ComputeScore(
        const ProcState& state) const {
    uint32_t score = 0;
    const size_t count = state.mechanisms.size();
    /* A single mechanism is common for legitimate software installers; two
     * or more distinct persistence mechanisms in one process is the strong
     * signal. The suspicious_service_path mechanism only appears when a
     * service ImagePath lands in a user-writable location or script host. */
    if (count == 1) {
        score += 40;
    } else if (count >= 2) {
        score += 55 + static_cast<uint32_t>(count - 2) * 15;
    }
    if (state.persistenceCount >= 3) score += 10;
    if (state.persistenceCount >= 5) score += 10;
    return std::min(100u, score);
}

std::string RegistryPersistenceDetector::MechanismList(
        const ProcState& state) const {
    std::string list;
    for (const auto& mechanism : state.mechanisms) {
        if (!list.empty()) list += ",";
        list += mechanism;
    }
    return list;
}

std::string RegistryPersistenceDetector::KeyList(
        const ProcState& state) const {
    std::string list;
    for (const auto& key : state.regKeys) {
        if (!list.empty()) list += ",";
        list += key;
    }
    return list;
}

void RegistryPersistenceDetector::WriteState(Event& event,
                                             const ProcState& state,
                                             const std::string& mechanism) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kRegistryPersistenceScore] = std::to_string(score);
    event.fields[field::kRegistryPersistenceCount] =
        std::to_string(state.persistenceCount);
    event.fields[field::kRegistryPersistenceMechanisms] = MechanismList(state);
    event.fields[field::kRegistryPersistenceKeys] = KeyList(state);
    event.fields[field::kRegistryPersistenceWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kRegistryPersistenceVerdict] = verdict;
    }
}

void RegistryPersistenceDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_REG_WRITE) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const uint32_t pid = event.pid;
    if (pid == 0) return;

    const std::string regKey = FieldValue(event, field::kRegKey);
    std::string mechanism;
    if (!IsPersistenceRegistryKey(regKey, mechanism)) return;

    ProcState& state = m_procs[pid];
    state.mechanisms.insert(mechanism);
    state.regKeys.insert(regKey);
    ++state.persistenceCount;

    /* Service registrations: check the ImagePath value for suspicious
     * user-writable or script-host locations (T1543.003). */
    if (mechanism == "service_registration") {
        const std::string imagePath = FieldValue(event, field::kRegValue);
        if (!imagePath.empty() && IsSuspiciousServicePath(imagePath)) {
            state.mechanisms.insert("suspicious_service_path");
        }
    }

    state.lastSeen100ns = now;
    WriteState(event, state, mechanism);
    EvictOldest(m_procs, m_stateCapacity);
}

} // namespace edr
