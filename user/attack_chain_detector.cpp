/*
 * attack_chain_detector.cpp - See attack_chain_detector.h.
 *
 * Tactic mapping (self-derived from event fields):
 *   EXECUTION: PROCESS_START whose image is under a user-writable directory,
 *     or a script-host child (powershell/pwsh/rundll32/cmd spawned by
 *     powershell/pwsh/wscript/mshta/cscript)
 *   PERSISTENCE: REG_WRITE under \Run/RunOnce/IFEO/Services, TASK_SCHEDULER,
 *                 service install/start events, or FILE_CREATE under a
 *                 Startup directory
 *   DEFENSE_EVASION: Defender realtime-protection-disabled (5001) or a
 *                    PRIVILEGE TOKEN_ADJUSTED (4703) event
 *   PRIVILEGE_ESCALATION: PRIVILEGE SENSITIVE_USED/SENSITIVE_OBJECT, or a
 *                 service install hook starting at SYSTEM boot
 *   CREDENTIAL_ACCESS: PROCESS_READ of lsass/winlogon/csrss, PROCESS_ACCESS
 *                 of them with vm_read, or FILE_READ of the SAM/SECURITY/
 *                 SYSTEM hive files
 *   NETWORK: NET_CONNECT to an external (non-private) destination
 *
 * Score: 15 per distinct tactic plus +10 when EXECUTION and PERSISTENCE are
 * both present without DEFENSE_EVASION, capped at 100. DNS queries are not
 * counted as NETWORK to avoid a near-universal false positive.
 */
#include "attack_chain_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <string>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

const char* const kStageNames[] = {
    "EXECUTION", "PERSISTENCE", "DEFENSE_EVASION",
    "PRIVILEGE_ESCALATION", "CREDENTIAL_ACCESS", "NETWORK"};
const char* const kTacticNames[] = {
    "Execution", "Persistence", "Defense Evasion",
    "Privilege Escalation", "Credential Access", "Command and Control"};
constexpr size_t kTacticCount = sizeof(kStageNames) / sizeof(kStageNames[0]);

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

std::string InstanceKey(const Event& event) {
    const std::string endpoint = LowerAscii(FieldValue(event, field::kEndpointId));
    const std::string scope = std::to_string(endpoint.size()) + ":" + endpoint;
    if (event.pid != 0 && event.processStartTime100ns != 0)
        return scope + "|pid:" + std::to_string(event.pid) + "@" +
               std::to_string(event.processStartTime100ns);
    const std::string identity = LowerAscii(event.processIdentity);
    if (identity.empty() || identity.size() > 256 ||
        identity.rfind("pid:", 0) == 0 || identity.rfind("wmi/", 0) == 0 ||
        identity.find_first_not_of("0123456789") == std::string::npos) return {};
    const size_t at = identity.find('@');
    if (at != std::string::npos && at != 0 &&
        identity.substr(0, at).find_first_not_of("0123456789") == std::string::npos) {
        uint32_t pid = 0;
        uint64_t creation = 0;
        const char* begin = identity.data();
        const auto parsedPid = std::from_chars(begin, begin + at, pid);
        const auto parsedTime = std::from_chars(begin + at + 1,
                                                begin + identity.size(), creation);
        if (parsedPid.ec != std::errc{} || parsedPid.ptr != begin + at ||
            parsedTime.ec != std::errc{} || parsedTime.ptr != begin + identity.size() ||
            pid == 0 || creation == 0 || pid != event.pid) return {};
        return scope + "|pid:" + std::to_string(pid) + "@" + std::to_string(creation);
    }
    std::string source = event.source;
    if (source.empty()) source = FieldValue(event, field::kSource);
    if (source.empty()) return {};
    source = LowerAscii(source);
    if (source != "sysmon" && source != "etw") return {};
    return scope + "|source:" + std::to_string(source.size()) + ":" + source +
           "|pid:" + std::to_string(event.pid) + "|opaque:" + identity;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

/* User-writable launch locations (same list as BehaviorEnricher): Temp,
 * AppData, ProgramData, Downloads, Public; system paths never qualify. */
bool IsUserWritablePath(const std::string& image) {
    const std::string lower = LowerAscii(image);
    if (lower.find("\\windows\\") != std::string::npos) return false;
    return lower.find("\\temp\\") != std::string::npos ||
           lower.find("\\appdata\\") != std::string::npos ||
           lower.find("\\programdata\\") != std::string::npos ||
           lower.find("\\downloads\\") != std::string::npos ||
           lower.find("\\public\\") != std::string::npos;
}

bool IsPrivateIp(const std::string& ip) {
    if (ip.empty()) return true;
    if (ip.find(':') != std::string::npos) {
        return ip == "::" || ip == "::1" ||
               ip.compare(0, 4, "fe80") == 0 ||
               ip.compare(0, 4, "fc00") == 0 ||
               ip.compare(0, 2, "fd") == 0 ||
               ip.compare(0, 4, "ff0") == 0;
    }
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return true;
    if (a == 0 || a == 10 || a == 127) return true;
    if (a == 169 && b == 254) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a >= 224 && a <= 255) return true;
    return false;
}

bool IsCredentialTarget(const std::string& image) {
    const std::string base = BaseName(image);
    return base == "lsass.exe" || base == "winlogon.exe" ||
           base == "csrss.exe";
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

AttackChainDetector::AttackChainDetector(size_t stateCapacity,
                                         uint32_t windowSeconds)
    : m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond) {}

bool AttackChainDetector::Inspects(uint16_t type) {
    switch (type) {
    case EDR_EVT_PROCESS_START:
    case EDR_EVT_PROCESS_STOP:
    case EDR_EVT_REG_WRITE:
    case EDR_EVT_FILE_CREATE:
    case EDR_EVT_NET_CONNECT:
    case EDR_EVT_TASK_SCHEDULER:
    case EDR_EVT_PRIVILEGE:
    case EDR_EVT_PROCESS_ACCESS:
    case EDR_EVT_MEMORY_WRITE:
    case EDR_EVT_SECTION_MAP:
    case EDR_EVT_THREAD_CREATE:
    case EDR_EVT_APC_INJECT:
    case EDR_EVT_CONTEXT_CHANGE:
    case EDR_EVT_HANDLE_DUPLICATE:
    case EDR_EVT_PROCESS_READ:
    case EDR_EVT_FILE_READ:
    case EDR_EVT_SERVICE_INSTALL:
    case EDR_EVT_SERVICE_INSTALL_HOOK:
    case EDR_EVT_SERVICE_START_HOOK:
    case EDR_EVT_DEFENDER:
        return true;
    default:
        return false;
    }
}

uint8_t AttackChainDetector::TacticFor(const Event& event) {
    switch (event.type) {
    case EDR_EVT_PROCESS_START: {
        const std::string image =
            LowerAscii(FieldValue(event, field::kImage));
        if (image.empty()) return 0;
        if (IsUserWritablePath(image)) return TacticExecution;
        const std::string parentImage =
            LowerAscii(FieldValue(event, field::kParentImage));
        const std::string childBase = BaseName(image);
        const std::string parentBase = BaseName(parentImage);
        if (parentBase == "powershell.exe" || parentBase == "pwsh.exe" ||
            parentBase == "mshta.exe" || parentBase == "wscript.exe" ||
            parentBase == "cscript.exe") {
            if (childBase == "powershell.exe" || childBase == "pwsh.exe" ||
                childBase == "rundll32.exe" || childBase == "cmd.exe")
                return TacticExecution;
        }
        return 0;
    }
    case EDR_EVT_REG_WRITE: {
        const std::string key =
            LowerAscii(FieldValue(event, field::kRegKey));
        if (key.find("\\run") != std::string::npos ||
            key.find("runonce") != std::string::npos ||
            key.find("image file execution options") != std::string::npos ||
            key.find("\\services\\") != std::string::npos)
            return TacticPersistence;
        return 0;
    }
    case EDR_EVT_FILE_CREATE: {
        const std::string path =
            LowerAscii(FieldValue(event, field::kFilePath));
        if (path.find("\\startup\\") != std::string::npos ||
            path.find("start menu\\programs\\startup") != std::string::npos)
            return TacticPersistence;
        return 0;
    }
    case EDR_EVT_TASK_SCHEDULER:
        return TacticPersistence;
    case EDR_EVT_SERVICE_INSTALL:
        return TacticPersistence;
    case EDR_EVT_SERVICE_INSTALL_HOOK: {
        uint8_t bits = TacticPersistence;
        if (FieldValue(event, field::kServiceStartType) == "1")
            bits |= TacticPrivilegeEscalation;
        return bits;
    }
    case EDR_EVT_SERVICE_START_HOOK:
        return TacticPersistence;
    case EDR_EVT_DEFENDER:
        if (FieldValue(event, field::kOperationType) ==
            "REALTIME_PROTECTION_DISABLED")
            return TacticDefenseEvasion;
        return 0;
    case EDR_EVT_PRIVILEGE: {
        const std::string op =
            FieldValue(event, field::kPrivilegeOperation);
        if (op == "TOKEN_ADJUSTED") return TacticDefenseEvasion;
        if (op == "SENSITIVE_USED" || op == "SENSITIVE_OBJECT")
            return TacticPrivilegeEscalation;
        return 0;
    }
    case EDR_EVT_PROCESS_ACCESS:
        if (IsCredentialTarget(FieldValue(event, field::kTargetImage)) &&
            FieldValue(event, field::kAccessVmRead) == "true")
            return TacticCredentialAccess;
        return 0;
    case EDR_EVT_PROCESS_READ:
        if (IsCredentialTarget(FieldValue(event, field::kTargetImage)))
            return TacticCredentialAccess;
        return 0;
    case EDR_EVT_FILE_READ: {
        const std::string name =
            BaseName(FieldValue(event, field::kTargetPath));
        if (name == "sam" || name == "security" || name == "system")
            return TacticCredentialAccess;
        return 0;
    }
    case EDR_EVT_NET_CONNECT: {
        const std::string ip = FieldValue(event, field::kDstIp);
        if (ip.empty() || IsPrivateIp(ip)) return 0;
        return TacticNetwork;
    }
    default:
        return 0;
    }
}

void AttackChainDetector::PurgeExpired(uint64_t now100ns) {
    if (m_lastPurge100ns != 0 &&
        (now100ns <= m_lastPurge100ns ||
         now100ns - m_lastPurge100ns <= m_window100ns))
        return;
    m_lastPurge100ns = now100ns;
    for (auto it = m_states.begin(); it != m_states.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_states.erase(it);
        else
            ++it;
    }
}

void AttackChainDetector::WriteState(Event& event, const PidState& state) {
    /* Score is purely a function of how many distinct tactics this pid has
     * accumulated: 15 per stage, plus 10 for the execution+persistence combo
     * without defense evasion. One or two stages land at 15/30/40 - below the
     * 55 SUSPICIOUS bar - so they must not be published: EDR-134 requires 60+
     * (four stages) and a sub-55 score field is a dead letter no rule reads.
     * The stages/tactics fields are stamped at the same time as the score, so
     * gating here keeps the event shape consistent. */
    const int raw = static_cast<int>(state.order.size()) * 15 +
                    (((state.mask & TacticExecution) &&
                      (state.mask & TacticPersistence) &&
                      !(state.mask & TacticDefenseEvasion)) ? 10 : 0);
    if (raw < 55) return;

    std::string stages;
    std::string tactics;
    for (size_t i = 0; i < state.order.size(); ++i) {
        if (!stages.empty()) {
            stages += ",";
            tactics += ",";
        }
        stages += kStageNames[state.order[i]];
        tactics += kTacticNames[state.order[i]];
    }
    event.fields[field::kAttackChainStages] = stages;
    event.fields[field::kAttackChainStageCount] =
        std::to_string(state.order.size());
    event.fields[field::kAttackChainTactics] = tactics;
    event.fields[field::kAttackChainScore] =
        std::to_string(std::min(100, raw));
}

void AttackChainDetector::Enrich(Event& event) {
    if (!Inspects(event.type)) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);
    if (event.pid == 0) return;

    const std::string key = InstanceKey(event);
    auto existing = m_states.find(key);
    if (existing != m_states.end()) {
        const uint64_t last = existing->second.lastSeen100ns;
        if (now < last && last - now > m_window100ns) return;
        // Lazy global sweeps must not extend the accessed instance's window.
        if (now >= last && now - last > m_window100ns) {
            m_states.erase(existing);
            existing = m_states.end();
        }
    }
    if (event.type == EDR_EVT_PROCESS_STOP) {
        if (!key.empty()) m_states.erase(key);
        return;
    }
    if (key.empty()) {
        if (event.type == EDR_EVT_PROCESS_START) {
            const std::string endpoint = LowerAscii(FieldValue(event, field::kEndpointId));
            for (auto it = m_states.begin(); it != m_states.end();) {
                if (it->second.pid == event.pid && it->second.endpoint == endpoint &&
                    now >= it->second.lastSeen100ns)
                    it = m_states.erase(it);
                else ++it;
            }
        }
        // Weak events may describe a stage, but never join a prior instance.
        return;
    }

    const uint8_t add = TacticFor(event);
    if (existing == m_states.end()) {
        if (add == 0) return;
        PidState state;
        state.pid = event.pid;
        state.endpoint = LowerAscii(FieldValue(event, field::kEndpointId));
        state.lastSeen100ns = now;
        state.mask = add;
        for (size_t i = 0; i < kTacticCount; ++i) {
            if (add & (static_cast<uint8_t>(1u << i)))
                state.order.push_back(static_cast<uint8_t>(i));
        }
        WriteState(event, state);
        m_states.emplace(key, state);
        EvictOldest(m_states, m_stateCapacity);
        return;
    }

    PidState& state = existing->second;
    state.lastSeen100ns = std::max(state.lastSeen100ns, now);
    for (size_t i = 0; i < kTacticCount; ++i) {
        const uint8_t bit = static_cast<uint8_t>(1u << i);
        if ((add & bit) && !(state.mask & bit)) {
            state.mask |= bit;
            state.order.push_back(static_cast<uint8_t>(i));
        }
    }
    WriteState(event, state);
    EvictOldest(m_states, m_stateCapacity);
}

} // namespace edr
