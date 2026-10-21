/*
 * privilege_escalation_detector.cpp - See privilege_escalation_detector.h.
 */
#include "privilege_escalation_detector.h"

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

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

uint64_t WallTime100ns() {
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool Token(const std::string& value, size_t maximum) {
    if (value.empty() || value.size() > maximum) return false;
    for (unsigned char c : value) if (c < 0x21 || c > 0x7e) return false;
    return true;
}

// Same strong-identity and length-encoded scope convention as DoH/LOLBIN.
bool AggregationKey(const Event& event, std::string& key) {
    if (!event.pid) return false;
    std::string source = event.source;
    const auto fieldSource = event.fields.find(field::kSource);
    if (fieldSource != event.fields.end()) {
        if (!source.empty() && source != fieldSource->second) return false;
        source = fieldSource->second;
    }
    if (!Token(source, 64)) return false;
    std::string endpoint;
    const auto endpointField = event.fields.find(field::kEndpointId);
    if (endpointField != event.fields.end()) {
        endpoint = endpointField->second;
        if (!Token(endpoint, 128)) return false;
    }
    std::string identity;
    if (event.processStartTime100ns) {
        identity = "start:" + std::to_string(event.processStartTime100ns);
    } else {
        std::string guid = event.processIdentity;
        if (guid.size() == 38 && guid.front() == '{' && guid.back() == '}')
            guid = guid.substr(1, 36);
        if (guid.size() != 36) return false;
        bool nonzero = false;
        for (size_t i = 0; i < guid.size(); ++i) {
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (guid[i] != '-') return false;
            } else {
                if (!std::isxdigit(static_cast<unsigned char>(guid[i]))) return false;
                nonzero = nonzero || guid[i] != '0';
            }
        }
        if (!nonzero) return false;
        identity = "guid:" + LowerAscii(guid);
    }
    key.clear();
    for (const auto& part : {endpoint, source, std::to_string(event.pid), identity})
        key += std::to_string(part.size()) + ":" + part + "|";
    return true;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

} // namespace

PrivilegeEscalationDetector::PrivilegeEscalationDetector(
        bool enabled, uint32_t windowSeconds, size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool PrivilegeEscalationDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_SERVICE_INSTALL ||
           type == EDR_EVT_PROCESS_ACCESS ||
           type == EDR_EVT_HANDLE_DUPLICATE ||
           type == EDR_EVT_IMAGE_LOAD ||
           type == EDR_EVT_PRIVILEGE;
}

bool PrivilegeEscalationDetector::IsSuspiciousServicePath(
        const std::string& path) {
    if (path.empty()) return false;
    const std::string lower = LowerAscii(path);
    /* Suspicious if not in standard Windows directories */
    if (lower.find("\\windows\\system32\\") != std::string::npos) return false;
    if (lower.find("\\program files\\") != std::string::npos) return false;
    if (lower.find("\\program files (x86)\\") != std::string::npos) return false;
    /* Flag temp, user-profile, public, or non-standard paths */
    if (lower.find("\\temp\\") != std::string::npos) return true;
    if (lower.find("\\users\\public\\") != std::string::npos) return true;
    if (lower.find("\\appdata\\") != std::string::npos) return true;
    if (lower.find("\\programdata\\") != std::string::npos) return true;
    if (lower.find("\\downloads\\") != std::string::npos) return true;
    /* PowerShell/cmd as service binary is suspicious */
    const std::string base = BaseName(path);
    if (base == "powershell.exe" || base == "cmd.exe" ||
        base == "wscript.exe" || base == "cscript.exe" ||
        base == "mshta.exe" || base == "rundll32.exe" ||
        base == "regsvr32.exe") return true;
    return true; /* Non-standard path by default */
}

bool PrivilegeEscalationDetector::IsSuspiciousPrivilege(
        const std::string& privileges) {
    const std::string lower = LowerAscii(privileges);
    size_t start = 0;
    while (start < lower.size()) {
        const size_t end = lower.find_first_of(" \t\r\n,;", start);
        const auto token = lower.substr(start, end == std::string::npos
            ? std::string::npos : end - start);
        if (token == "sedebugprivilege" || token == "setcbprivilege" ||
            token == "seassignprimarytokenprivilege" || token == "seimpersonateprivilege")
            return true;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return false;
}

bool PrivilegeEscalationDetector::HasDuplicateHandleAccess(
        const std::string& accessMask) {
    if (accessMask.empty()) return false;
    const size_t start = accessMask.rfind("0x", 0) == 0 ||
                         accessMask.rfind("0X", 0) == 0 ? 2 : 0;
    if (accessMask.size() <= start || accessMask.size() - start > 8) return false;
    uint32_t mask = 0;
    for (size_t i = start; i < accessMask.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(accessMask[i]);
        unsigned digit = 0;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return false;
        mask = (mask << 4) | digit;
    }
    /* PROCESS_DUP_HANDLE (0x0040) */
    return (mask & 0x0040) != 0;
}

bool PrivilegeEscalationDetector::IsElevatedImage(const std::string& image) {
    const std::string base = BaseName(image);
    static const char* kElevated[] = {
        "winlogon.exe", "lsass.exe", "svchost.exe",
        "services.exe", "smss.exe", "csrss.exe",
        "wininit.exe", "spoolsv.exe", "dllhost.exe"
    };
    for (const char* name : kElevated) {
        if (base == name) return true;
    }
    return false;
}

void PrivilegeEscalationDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns >= m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

void PrivilegeEscalationDetector::ExpireSignals(ProcState& state,
                                                uint64_t now100ns) const {
    const std::array<bool*, 5> flags{{&state.sawServiceInstall,
        &state.sawTokenManipulation, &state.sawPrivilegedChild,
        &state.sawDllSideload, &state.sawSuspiciousPrivilege}};
    for (size_t i = 0; i < flags.size(); ++i) {
        if (*flags[i] && now100ns >= state.signalTimes[i] &&
            now100ns - state.signalTimes[i] >= m_window100ns) *flags[i] = false;
    }
}

uint32_t PrivilegeEscalationDetector::ComputeScore(
        const ProcState& state) const {
    uint32_t score = 0;
    if (state.sawServiceInstall) score += 35;
    if (state.sawTokenManipulation) score += 40;
    if (state.sawPrivilegedChild) score += 25;
    if (state.sawDllSideload) score += 20;
    if (state.sawSuspiciousPrivilege) score += 30;
    int signalCount = 0;
    if (state.sawServiceInstall) ++signalCount;
    if (state.sawTokenManipulation) ++signalCount;
    if (state.sawPrivilegedChild) ++signalCount;
    if (state.sawDllSideload) ++signalCount;
    if (state.sawSuspiciousPrivilege) ++signalCount;
    if (signalCount >= 2) score += 15;
    return std::min(100u, score);
}

std::string PrivilegeEscalationDetector::SignalList(
        const ProcState& state) const {
    std::string signals;
    const char* names[] = {"service_install", "token_manipulation",
                           "privileged_child", "dll_sideload",
                           "suspicious_privilege"};
    const bool flags[] = {state.sawServiceInstall,
                          state.sawTokenManipulation,
                          state.sawPrivilegedChild,
                          state.sawDllSideload,
                          state.sawSuspiciousPrivilege};
    for (size_t i = 0; i < 5; ++i) {
        if (!flags[i]) continue;
        if (!signals.empty()) signals += ",";
        signals += names[i];
    }
    return signals;
}

std::string PrivilegeEscalationDetector::TechniqueList(
        const ProcState& state) const {
    std::string techs;
    if (state.sawServiceInstall) {
        if (!techs.empty()) techs += ",";
        techs += "T1543.003";
    }
    if (state.sawTokenManipulation) {
        if (!techs.empty()) techs += ",";
        techs += "T1134.002";
    }
    if (state.sawSuspiciousPrivilege) {
        if (!techs.empty()) techs += ",";
        techs += "T1134.001";
    }
    if (state.sawDllSideload) {
        if (!techs.empty()) techs += ",";
        techs += "T1574.001";
    }
    return techs;
}

void PrivilegeEscalationDetector::WriteState(Event& event,
                                              const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kPrivEscScore] = std::to_string(score);
    event.fields[field::kPrivEscSignals] = SignalList(state);
    event.fields[field::kPrivEscTechniques] = TechniqueList(state);
    event.fields[field::kPrivEscWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty())
        event.fields[field::kPrivEscVerdict] = verdict;
}

void PrivilegeEscalationDetector::Enrich(Event& event) {
    if (!m_enabled || !Inspects(event.type) ||
        event.disposition != EventDisposition::ReportAndEvaluate) return;
    const uint64_t now = event.ts100ns;
    const uint64_t wall = WallTime100ns();
    if (!now || (now > wall && now - wall > 300 * kFiletimeTicksPerSecond) ||
        event.processStartTime100ns > now) return;
    size_t signal = 0;
    if (event.type == EDR_EVT_SERVICE_INSTALL) {
        const std::string imagePath =
            FieldValue(event, field::kServiceImagePath);
        if (!IsSuspiciousServicePath(imagePath)) return;
        signal = 0;
    } else if (event.type == EDR_EVT_PROCESS_ACCESS) {
        // Sysmon 10's native GrantedAccess is normalized by its parser.
        const bool sysmonAccess = event.source == "sysmon" &&
            FieldValue(event, field::kSysmonEventId) == "10";
        const std::string mask = FieldValue(event,
            sysmonAccess ? field::kGrantedAccess : field::kAccessMask);
        const std::string targetImage =
            FieldValue(event, field::kTargetImage);
        if (!HasDuplicateHandleAccess(mask) || !IsElevatedImage(targetImage))
            return;
        signal = 1;
    } else if (event.type == EDR_EVT_HANDLE_DUPLICATE) {
        const std::string targetImage =
            FieldValue(event, field::kTargetImage);
        if (!IsElevatedImage(targetImage)) return;
        signal = 1;
    } else if (event.type == EDR_EVT_PRIVILEGE) {
        const std::string privileges = FieldValue(event,
            event.source == "security_log" ? field::kPrivilegeList : field::kPrivileges);
        if (!IsSuspiciousPrivilege(privileges)) return;
        signal = 4;
    } else if (event.type == EDR_EVT_IMAGE_LOAD) {
        const bool sysmonImage = event.source == "sysmon" &&
            FieldValue(event, field::kSysmonEventId) == "7";
        const std::string dllPath = FieldValue(event,
            sysmonImage ? field::kTargetImage : field::kImageLoaded);
        const std::string host = FieldValue(event, field::kImage);
        if (dllPath.empty() || !IsElevatedImage(host)) return;
        std::string lower = LowerAscii(dllPath);
        std::replace(lower.begin(), lower.end(), '/', '\\');
        if (lower.find("\\system32\\") != std::string::npos) return;
        if (lower.find("\\syswow64\\") != std::string::npos) return;
        signal = 3;
    } else {
        return;
    }

    std::string key;
    ProcState singleEvent;
    ProcState* state = &singleEvent;
    if (m_window100ns != 0 && AggregationKey(event, key)) {
        const auto prior = m_procs.find(key);
        if (prior != m_procs.end() && now < prior->second.lastSeen100ns) return;
        PurgeExpired(now);
        if (m_procs.find(key) == m_procs.end() && m_procs.size() >= m_stateCapacity) {
            const auto oldest = std::min_element(m_procs.begin(), m_procs.end(),
                [](const auto& a, const auto& b) {
                    return a.second.lastSeen100ns < b.second.lastSeen100ns;
                });
            m_procs.erase(oldest);
        }
        state = &m_procs[key];
        ExpireSignals(*state, now);
    }
    const std::array<bool*, 5> flags{{&state->sawServiceInstall,
        &state->sawTokenManipulation, &state->sawPrivilegedChild,
        &state->sawDllSideload, &state->sawSuspiciousPrivilege}};
    *flags[signal] = true;
    state->signalTimes[signal] = now;
    state->lastSeen100ns = now;
    WriteState(event, *state);
}

} // namespace edr
