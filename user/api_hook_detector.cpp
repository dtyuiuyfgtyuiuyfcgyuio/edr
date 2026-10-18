/*
 * api_hook_detector.cpp - See api_hook_detector.h.
 *
 * Detects API hooking / tampering across these event sources:
 * - ETW_TAMPER: provider disable / session stop / EtwEventWrite patch
 *   (defense evasion).
 * - WINDOWS_HOOK: SetWindowsHookEx for input surveillance or process
 *   injection carrier.
 * - IMAGE_LOAD: injection of hooking DLLs into other processes.
 * - PROCESS_ACCESS: opening a target process with VM_WRITE / CREATE_THREAD
 *   to install hooks or patch in-memory.
 *
 * The detector is deliberately conservative: hooking primitives alone
 * score low; combinations (patch + critical API + unusual source) raise
 * the score to the alert threshold.
 */
#include "api_hook_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
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

std::string Join(const std::vector<std::string>& values,
                 const char* separator) {
    std::string result;
    for (const std::string& value : values) {
        if (!result.empty()) result += separator;
        result += value;
    }
    return result;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (value.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool IsUserWritableLocation(const std::string& lowerPath) {
    if (lowerPath.find("\\users\\") != std::string::npos &&
        ContainsAny(lowerPath, {"\\appdata\\", "\\downloads\\",
                                 "\\desktop\\", "\\temp\\"}))
        return true;
    return ContainsAny(lowerPath, {"\\windows\\temp\\", "c:\\temp\\",
                                    "\\programdata\\"});
}

} // namespace

ApiHookDetector::ApiHookDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool ApiHookDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_ETW_TAMPER ||
           type == EDR_EVT_WINDOWS_HOOK ||
           type == EDR_EVT_IMAGE_LOAD ||
           type == EDR_EVT_PROCESS_ACCESS;
}

void ApiHookDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    PurgeExpired(EventTime(event));

    switch (event.type) {
        case EDR_EVT_ETW_TAMPER:
            AnalyzeEtwTamper(event);
            break;
        case EDR_EVT_WINDOWS_HOOK:
            AnalyzeWindowsHook(event);
            break;
        case EDR_EVT_IMAGE_LOAD:
            AnalyzeImageLoad(event);
            break;
        case EDR_EVT_PROCESS_ACCESS:
            AnalyzeProcessAccess(event);
            break;
    }
}

bool ApiHookDetector::IsCriticalApi(const std::string& lowerFunction) const {
    static const std::set<std::string> kCritical = {
        "etweventwrite", "etwnotification", "nttraceevent",
        "amsiscanbuffer", "amsiscanstring",
        "ntqueryinformationprocess", "ntqueryvirtuallmemory",
        "ntreadvirtualmemory", "ntwritevirtualmemory",
        "ntprotectvirtualmemory", "ntallocvirtualmemory",
        "ntresumethread", "ntcreatethreadex", "ntcreateprocessex",
        "ntcreatesection", "ntmaptviewofsection", "ntmaptviewofsectionex",
        "ntduplicateobject", "ntopenthread", "ntopenprocess",
        "ntsetinformationprocess", "ntsetcontextthread",
        "ldrloaddll", "ldrgetprocedureaddress", "ntunmapviewofsection"
    };
    return kCritical.count(lowerFunction) != 0;
}

bool ApiHookDetector::IsEtwProvider(const std::string& lowerGuid) const {
    // Microsoft-Windows-Kernel-Process, -Kernel-Network, -Kernel-File,
    // -Kernel-Audit, Microsoft-Windows-Sysmon, DNS Client, ETW .NET, etc.
    static const std::set<std::string> kEtwGuids = {
        "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
        "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
        "{2d576b3d-2cec-4a63-84a6-523f4f0a5d1b}",
        "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}",
        "{7dd42a49-5329-4832-8dfd-43d979153a88}",
        "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}",
        "{edd08927-9cc4-4e65-b970-c2560fb5c289}",
        "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}"
    };
    return kEtwGuids.count(lowerGuid) != 0;
}

bool ApiHookDetector::IsAmsiBypassPattern(const std::string& lowerText) const {
    static const char* const patterns[] = {
        "amsi", "a m s i", "amsiscanbuffer", "etweventwrite",
        "patch", "virtualprotect", "write",
        "0x0f", "0xb8",  // MOV EAX,imm opcode prefix used in AMSI bypass
        "byte[]", "gettype", "getfield", "setvalue", "invoke"
    };
    for (const char* p : patterns) {
        if (lowerText.find(p) != std::string::npos) return true;
    }
    return false;
}

void ApiHookDetector::AnalyzeEtwTamper(Event& event) {
    std::string tamperType = LowerAscii(FieldValue(event, field::kEtwTamperType));
    std::string providerGuid = LowerAscii(FieldValue(event, field::kEtwProviderGuid));
    std::string detail = LowerAscii(FieldValue(event, field::kEtwTamperDetail));
    std::string module = LowerAscii(FieldValue(event, field::kEtwTamperModule));

    std::string key = "etw:" + std::to_string(event.pid) + ":" +
                      std::to_string(event.ts100ns / 10000000ULL);
    HookState& state = GetOrCreateState(key);
    state.lastSeen100ns = EventTime(event);
    state.targetFunction = "etw";

    // Core ETW tampering primitives
    if (ContainsAny(tamperType, {"disable", "provider_disable", "patch",
                                 "unregister", "session_stop"})) {
        UpdateScore(state, 45, "etw_provider_disabled");
    }

    // Protected provider being targeted
    if (IsEtwProvider(providerGuid)) {
        UpdateScore(state, 30, "protected_etw_provider_targeted");
    }

    // EtwEventWrite patch (classic AMSI/ETW bypass)
    if (ContainsAny(detail, {"etweventwrite", "patch", "hook", "jmp"})) {
        UpdateScore(state, 40, "etweventwrite_patched");
    }

    // Patch performed from non-system module
    if (!module.empty() && IsUserWritableLocation(module)) {
        UpdateScore(state, 25, "etw_patch_from_user_module");
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void ApiHookDetector::AnalyzeWindowsHook(Event& event) {
    std::string hookType = LowerAscii(FieldValue(event, field::kHookType));
    std::string hookModule = LowerAscii(FieldValue(event, field::kHookModulePath));
    uint32_t hookThreadId = 0;
    try {
        hookThreadId = static_cast<uint32_t>(
            std::stoul(FieldValue(event, field::kHookThreadId)));
    } catch (...) {}

    std::string key = "hook:" + std::to_string(event.pid) + ":" +
                      std::to_string(hookThreadId);
    HookState& state = GetOrCreateState(key);
    state.lastSeen100ns = EventTime(event);
    state.targetFunction = hookType;

    // Global hook (thread 0) is high-risk
    if (hookThreadId == 0) {
        UpdateScore(state, 40, "global_windows_hook");
    }

    // Suspicious hook types (keyboard/mouse surveillance)
    if (ContainsAny(hookType, {"wh_keyboard", "wh_keyboard_ll",
                               "wh_mouse_ll", "wh_getmessage",
                               "wh_callwndproc", "wh_cbt"})) {
        UpdateScore(state, 30, "input_surveillance_hook");
    }

    // Hook DLL from user-writable location
    if (!hookModule.empty() && IsUserWritableLocation(hookModule)) {
        UpdateScore(state, 35, "hook_dll_from_user_location");
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void ApiHookDetector::AnalyzeImageLoad(Event& event) {
    std::string imagePath = FieldValue(event, field::kImageLoaded);
    if (imagePath.empty()) imagePath = FieldValue(event, field::kImagePath);
    if (imagePath.empty()) return;

    std::string base = BaseName(imagePath);
    std::string lowerPath = LowerAscii(imagePath);

    // Known hooking / DLL injection payloads
    static const std::set<std::string> kHookingModules = {
        "hook.dll", "inject.dll", "detour.dll", "detours.dll",
        "winhook.dll", "apihook.dll", "minhook.dll", "comhook.dll",
        "easthook.dll", "ilhook.dll", "syshook.dll", "x86hook.dll"
    };

    if (kHookingModules.count(base) != 0) {
        std::string key = "img:" + std::to_string(event.pid) + ":" +
                          std::to_string(event.ts100ns / 10000000ULL);
        HookState& state = GetOrCreateState(key);
        state.lastSeen100ns = EventTime(event);
        state.targetFunction = base;

        UpdateScore(state, 40, "hooking_dll_loaded");

        if (IsUserWritableLocation(lowerPath)) {
            UpdateScore(state, 30, "hooking_dll_from_user_location");
        }

        if (state.score >= m_minScore && !state.alerted) {
            StampEvent(event, state);
        }
    }
}

void ApiHookDetector::AnalyzeProcessAccess(Event& event) {
    std::string callTrace = LowerAscii(FieldValue(event, field::kCallTrace));
    std::string grantedAccess = FieldValue(event, field::kGrantedAccess);

    // Cross-process access with VM_WRITE + CREATE_THREAD is the classic
    // hook-installation / injection pattern. Only fire on high-risk access
    // combos.
    bool hasVmWrite = !FieldValue(event, field::kAccessVmWrite).empty();
    bool hasCreateThread = !FieldValue(event, field::kAccessCreateThread).empty();
    bool hasVmOperation = !FieldValue(event, field::kAccessVmOperation).empty();

    if (!(hasVmWrite && hasCreateThread && hasVmOperation)) return;

    std::string key = "acc:" + std::to_string(event.pid) + ":" +
                      std::to_string(event.ts100ns / 10000000ULL);
    HookState& state = GetOrCreateState(key);
    state.lastSeen100ns = EventTime(event);
    state.targetFunction = grantedAccess;

    UpdateScore(state, 30, "process_access_for_hook_install");

    // Call trace from user module / unknown module
    if (ContainsAny(callTrace, {"unknown", "anon", "0x"})) {
        UpdateScore(state, 25, "hook_install_from_unmapped_memory");
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

ApiHookDetector::HookState& ApiHookDetector::GetOrCreateState(
    const std::string& key) {
    auto it = m_hookStates.find(key);
    if (it != m_hookStates.end()) return it->second;

    HookState state;
    if (m_hookStates.size() >= m_stateCapacity) {
        auto oldest = std::min_element(m_hookStates.begin(),
                                        m_hookStates.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastSeen100ns < right.second.lastSeen100ns;
            });
        if (oldest != m_hookStates.end()) m_hookStates.erase(oldest);
    }
    auto [inserted, _] = m_hookStates.emplace(key, state);
    return inserted->second;
}

void ApiHookDetector::PurgeExpired(uint64_t now100ns) {
    if (m_dedupWindow100ns == 0) return;
    for (auto it = m_hookStates.begin(); it != m_hookStates.end();) {
        if (now100ns > it->second.lastSeen100ns &&
            (now100ns - it->second.lastSeen100ns) > m_dedupWindow100ns * 10) {
            it = m_hookStates.erase(it);
        } else {
            ++it;
        }
    }
}

void ApiHookDetector::UpdateScore(HookState& state, uint32_t weight,
                                   const char* reason) {
    for (const auto& r : state.reasons) {
        if (r == reason) return;
    }
    state.score += weight;
    if (state.score > 100) state.score = 100;
    state.reasons.push_back(reason);
}

void ApiHookDetector::StampEvent(Event& event, const HookState& state) {
    const_cast<HookState&>(state).alerted = true;

    event.fields[field::kApiHookScore] = std::to_string(state.score);
    event.fields[field::kApiHookFunctions] = state.targetFunction;
    event.fields[field::kApiHookModules] = Join(state.reasons, ",");
    event.fields[field::kApiHookVerdict] =
        state.score >= 60 ? "malicious" : "suspicious";

    event.fields[field::kMitreAttack] = "T1562.001,T1055";
    event.fields[field::kMitreTactic] = "Defense Evasion";
}

} // namespace edr
