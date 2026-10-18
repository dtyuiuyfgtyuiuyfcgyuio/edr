/*
 * anti_analysis_detector.cpp - See anti_analysis_detector.h.
 */
#include "anti_analysis_detector.h"

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

AntiAnalysisDetector::AntiAnalysisDetector(bool enabled,
                                           uint32_t windowSeconds,
                                           size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool AntiAnalysisDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool AntiAnalysisDetector::HasVmDetectionArgs(const std::string& cmdLine) {
    if (ContainsI(cmdLine, "vmware")) return true;
    if (ContainsI(cmdLine, "virtualbox")) return true;
    if (ContainsI(cmdLine, "vbox")) return true;
    if (ContainsI(cmdLine, "qemu")) return true;
    if (ContainsI(cmdLine, "xen")) return true;
    if (ContainsI(cmdLine, "hyper-v")) return true;
    if (ContainsI(cmdLine, "parallels")) return true;
    /* VM MAC OUIs: 00:0C:29 (VMware), 08:00:27 (VBox), 00:50:56 (VMware) */
    if (ContainsI(cmdLine, "00:0c:29") || ContainsI(cmdLine, "00-0c-29"))
        return true;
    if (ContainsI(cmdLine, "08:00:27") || ContainsI(cmdLine, "08-00-27"))
        return true;
    if (ContainsI(cmdLine, "00:50:56") || ContainsI(cmdLine, "00-50-56"))
        return true;
    if (ContainsI(cmdLine, "vmtools")) return true;
    if (ContainsI(cmdLine, "vboxguest")) return true;
    if (ContainsI(cmdLine, "vmci")) return true;
    /* WMI queries for VM detection */
    if (ContainsI(cmdLine, "Win32_ComputerSystem") &&
        (ContainsI(cmdLine, "Manufacturer") ||
         ContainsI(cmdLine, "Model"))) return true;
    return false;
}

bool AntiAnalysisDetector::HasDebuggerDetectionArgs(
        const std::string& cmdLine) {
    if (ContainsI(cmdLine, "IsDebuggerPresent")) return true;
    if (ContainsI(cmdLine, "CheckRemoteDebuggerPresent")) return true;
    if (ContainsI(cmdLine, "NtQueryInformationProcess")) return true;
    if (ContainsI(cmdLine, "ProcessDebugFlags")) return true;
    if (ContainsI(cmdLine, "ProcessDebugObjectHandle")) return true;
    if (ContainsI(cmdLine, "ProcessDebugPort")) return true;
    if (ContainsI(cmdLine, "OLLYDBG")) return true;
    if (ContainsI(cmdLine, "WinDbg")) return true;
    if (ContainsI(cmdLine, "x64dbg")) return true;
    if (ContainsI(cmdLine, "debugger")) return true;
    if (ContainsI(cmdLine, "BeingDebugged")) return true;
    if (ContainsI(cmdLine, "NtGlobalFlag")) return true;
    return false;
}

bool AntiAnalysisDetector::HasSleepBombArgs(const std::string& cmdLine) {
    if (ContainsI(cmdLine, "Start-Sleep") ||
        ContainsI(cmdLine, "sleep ")) {
        const std::string lower = LowerAscii(cmdLine);
        size_t pos = lower.find("sleep");
        while (pos != std::string::npos) {
            size_t numStart = pos + 5;
            while (numStart < lower.size() &&
                   !std::isdigit(static_cast<unsigned char>(lower[numStart])))
                ++numStart;
            if (numStart < lower.size()) {
                const long seconds = std::atol(lower.c_str() + numStart);
                if (seconds > 600) return true;
            }
            pos = lower.find("sleep", pos + 5);
        }
    }
    return false;
}

bool AntiAnalysisDetector::IsAnalysisToolParent(const std::string& image) {
    const std::string base = BaseName(image);
    static const char* kTools[] = {
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
        "wireshark.exe", "procmon.exe", "procmon64.exe",
        "processhacker.exe", "pestudio.exe", "die.exe",
        "ida.exe", "ida64.exe", "idag.exe", "idag64.exe",
        "immunitydebugger.exe", "fiddler.exe", "httpdebugger.exe",
        "autoruns.exe", "tcpview.exe", "vmware.exe", "vmware-vmx.exe",
        "vboxsvc.exe", "virtualbox.exe", "qemu-system-x86_64.exe",
        "qemu.exe", "sandboxiedcomlaunch.exe", "sandboxie.exe",
        "cuckoomon.exe", "cuckoo.exe", "anyrun.exe", "joesandbox.exe"
    };
    for (const char* tool : kTools) {
        if (base == tool) return true;
    }
    return false;
}

bool AntiAnalysisDetector::IsSysInfoQuery(const std::string& cmdLine) {
    if (ContainsI(cmdLine, "Get-WmiObject") &&
        (ContainsI(cmdLine, "Win32_BIOS") ||
         ContainsI(cmdLine, "Win32_Processor") ||
         ContainsI(cmdLine, "Win32_BaseBoard"))) return true;
    if (ContainsI(cmdLine, "systeminfo")) return true;
    if (ContainsI(cmdLine, "wmic bios") || ContainsI(cmdLine, "wmic cpu"))
        return true;
    return false;
}

void AntiAnalysisDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t AntiAnalysisDetector::ComputeScore(const ProcState& state) const {
    uint32_t score = 0;
    if (state.sawVmCheck) score += 35;
    if (state.sawDebuggerCheck) score += 30;
    if (state.sawSleepBomb) score += 25;
    if (state.sawAnalysisToolParent) score += 20;
    if (state.sawSysInfoQuery) score += 15;
    int signals = 0;
    if (state.sawVmCheck) ++signals;
    if (state.sawDebuggerCheck) ++signals;
    if (state.sawSleepBomb) ++signals;
    if (state.sawSysInfoQuery) ++signals;
    if (signals >= 2) score += 15;
    return std::min(100u, score);
}

std::string AntiAnalysisDetector::SignalList(const ProcState& state) const {
    std::string signals;
    const char* names[] = {"vm_check", "debugger_check", "sleep_bomb",
                           "analysis_tool_parent", "sysinfo_query"};
    const bool flags[] = {state.sawVmCheck, state.sawDebuggerCheck,
                          state.sawSleepBomb, state.sawAnalysisToolParent,
                          state.sawSysInfoQuery};
    for (size_t i = 0; i < 5; ++i) {
        if (!flags[i]) continue;
        if (!signals.empty()) signals += ",";
        signals += names[i];
    }
    return signals;
}

std::string AntiAnalysisDetector::TechniqueList(
        const ProcState& state) const {
    std::string techs;
    if (state.sawVmCheck || state.sawSysInfoQuery) {
        if (!techs.empty()) techs += ",";
        techs += "T1497.001";
    }
    if (state.sawDebuggerCheck) {
        if (!techs.empty()) techs += ",";
        techs += "T1497.002";
    }
    if (state.sawSleepBomb) {
        if (!techs.empty()) techs += ",";
        techs += "T1497.003";
    }
    return techs;
}

void AntiAnalysisDetector::WriteState(Event& event,
                                      const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kAntiAnalysisScore] = std::to_string(score);
    event.fields[field::kAntiAnalysisSignals] = SignalList(state);
    event.fields[field::kAntiAnalysisTechniques] = TechniqueList(state);
    event.fields[field::kAntiAnalysisWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty())
        event.fields[field::kAntiAnalysisVerdict] = verdict;
}

void AntiAnalysisDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    if (event.type == EDR_EVT_PROCESS_START) {
        const std::string cmdLine = FieldValue(event, field::kCommandLine);
        const std::string parentImage =
            FieldValue(event, field::kParentImage);
        bool changed = false;
        ProcState& state = m_procs[event.pid];
        if (HasVmDetectionArgs(cmdLine)) {
            state.sawVmCheck = true; changed = true;
        }
        if (HasDebuggerDetectionArgs(cmdLine)) {
            state.sawDebuggerCheck = true; changed = true;
        }
        if (HasSleepBombArgs(cmdLine)) {
            state.sawSleepBomb = true; changed = true;
        }
        if (IsSysInfoQuery(cmdLine)) {
            state.sawSysInfoQuery = true; changed = true;
        }
        if (IsAnalysisToolParent(parentImage)) {
            state.sawAnalysisToolParent = true; changed = true;
        }
        if (changed) {
            state.lastSeen100ns = now;
            WriteState(event, state);
        }
        return;
    }

    if (event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        const std::string script = FieldValue(event, field::kCommandLine);
        bool changed = false;
        ProcState& state = m_procs[event.pid];
        if (HasVmDetectionArgs(script)) {
            state.sawVmCheck = true; changed = true;
        }
        if (HasDebuggerDetectionArgs(script)) {
            state.sawDebuggerCheck = true; changed = true;
        }
        if (HasSleepBombArgs(script)) {
            state.sawSleepBomb = true; changed = true;
        }
        if (IsSysInfoQuery(script)) {
            state.sawSysInfoQuery = true; changed = true;
        }
        if (changed) {
            state.lastSeen100ns = now;
            WriteState(event, state);
        }
        return;
    }
}

} // namespace edr
