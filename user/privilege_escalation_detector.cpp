/*
 * privilege_escalation_detector.cpp - See privilege_escalation_detector.h.
 */
#include "privilege_escalation_detector.h"

#include <windows.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdlib>

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

bool ContainsI(const std::string& haystack, const char* needle) {
    const std::string h = LowerAscii(haystack);
    const std::string n = LowerAscii(needle);
    return h.find(n) != std::string::npos;
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

bool PrivilegeEscalationDetector::IsLocalSystemService(
        const std::string& account) {
    const std::string lower = LowerAscii(account);
    return lower == "localsystem" ||
           lower.find("nt authority\\system") != std::string::npos ||
           lower == ".\\system";
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
    /* SeDebugPrivilege is the most suspicious — enables process access */
    return ContainsI(privileges, "SeDebugPrivilege") ||
           ContainsI(privileges, "SeTcbPrivilege") ||
           ContainsI(privileges, "SeAssignPrimaryTokenPrivilege") ||
           ContainsI(privileges, "SeImpersonatePrivilege");
}

bool PrivilegeEscalationDetector::HasDuplicateHandleAccess(
        const std::string& accessMask) {
    if (accessMask.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long mask = std::strtoul(accessMask.c_str(), &end, 16);
    if (errno != 0 || end == accessMask.c_str()) return false;
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
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
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
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    if (event.type == EDR_EVT_SERVICE_INSTALL) {
        const std::string imagePath =
            FieldValue(event, field::kServiceImagePath);
        const std::string serviceName =
            FieldValue(event, field::kServiceName);
        if (!IsSuspiciousServicePath(imagePath)) return;
        ProcState& state = m_procs[event.pid];
        state.sawServiceInstall = true;
        state.detail = "suspicious service: " + serviceName;
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    if (event.type == EDR_EVT_PROCESS_ACCESS) {
        const std::string mask = FieldValue(event, field::kAccessMask);
        const std::string targetImage =
            FieldValue(event, field::kTargetImage);
        if (!HasDuplicateHandleAccess(mask) || !IsElevatedImage(targetImage))
            return;
        ProcState& state = m_procs[event.pid];
        state.sawTokenManipulation = true;
        state.detail = "duplicate handle to " + BaseName(targetImage);
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    if (event.type == EDR_EVT_HANDLE_DUPLICATE) {
        const std::string targetImage =
            FieldValue(event, field::kTargetImage);
        if (!IsElevatedImage(targetImage)) return;
        ProcState& state = m_procs[event.pid];
        state.sawTokenManipulation = true;
        state.detail = "handle duplicated from " + BaseName(targetImage);
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    if (event.type == EDR_EVT_PRIVILEGE) {
        const std::string privileges = FieldValue(event, field::kPrivileges);
        if (!IsSuspiciousPrivilege(privileges)) return;
        ProcState& state = m_procs[event.pid];
        state.sawSuspiciousPrivilege = true;
        state.detail = "suspicious privilege acquired";
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    if (event.type == EDR_EVT_IMAGE_LOAD) {
        const std::string dllPath = FieldValue(event, field::kImageLoaded);
        const std::string targetImage =
            FieldValue(event, field::kTargetImage);
        if (!IsElevatedImage(targetImage)) return;
        const std::string lower = LowerAscii(dllPath);
        if (lower.find("\\system32\\") != std::string::npos) return;
        if (lower.find("\\syswow64\\") != std::string::npos) return;
        ProcState& state = m_procs[event.pid];
        state.sawDllSideload = true;
        state.detail = "DLL sideload into " + BaseName(targetImage);
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }
}

} // namespace edr
