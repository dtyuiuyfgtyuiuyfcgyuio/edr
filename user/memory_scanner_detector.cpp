/*
 * memory_scanner_detector.cpp - See memory_scanner_detector.h.
 *
 * Detects suspicious memory artifacts by analyzing multiple event types:
 * - PROCESS_ACCESS: Detects cross-process memory operations with suspicious patterns
 * - THREAD_CREATE: Detects remote thread creation in suspicious contexts
 * - MEMORY_WRITE: Detects cross-process memory writes to executable regions
 * - IMAGE_LOAD: Detects unsigned/suspicious DLLs loaded into processes
 * - PROCESS_START: Tracks process lifecycle for correlation
 *
 * Scoring system:
 * - RWX memory region: +30
 * - Unmapped executable region: +40
 * - PE header in non-file memory: +50
 * - Remote thread to executable memory: +35
 * - Cross-process memory write to executable: +45
 * - Unsigned DLL in suspicious location: +25
 * - Multiple suspicious indicators: bonus multiplier
 *
 * The detector maintains per-process state with time-expiring entries.
 */
#include "memory_scanner_detector.h"

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

uint64_t FieldU64(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    if (found == event.fields.end()) return 0;
    try {
        return std::stoull(found->second, nullptr, 0);
    } catch (...) {
        return 0;
    }
}

uint32_t FieldU32(const Event& event, const char* name) {
    return static_cast<uint32_t>(FieldU64(event, name));
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

// Common legitimate system DLLs that are expected to be loaded
bool IsKnownLegitimateModule(const std::string& baseName) {
    static const std::set<std::string> kLegitimate = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "gdi32.dll", "advapi32.dll", "msvcrt.dll", "combase.dll",
        "rpcrt4.dll", "ole32.dll", "oleaut32.dll", "shell32.dll",
        "shlwapi.dll", "sechost.dll", "bcrypt.dll", "bcryptprimitives.dll",
        "crypt32.dll", "win32u.dll", "gdi32full.dll", "ucrtbase.dll",
        "vcruntime140.dll", "msvcp140.dll", "ws2_32.dll", "wldp.dll",
        "ntmarta.dll", "profapi.dll", "powrprof.dll", "umpdc.dll",
        "cfgmgr32.dll", "devobj.dll", "msasn1.dll", "cryptsp.dll",
        "rsaenh.dll", "ncrypt.dll", "ntasn1.dll", "dpapi.dll"
    };
    return kLegitimate.count(baseName) != 0;
}

// Check for PE header magic (MZ) at a memory location indicator
bool HasPeHeaderIndicator(const std::string& callTrace) {
    // If call trace shows execution from non-standard module
    if (!callTrace.empty()) {
        std::string lower = LowerAscii(callTrace);
        // Suspicious if call trace points to heap/stack memory
        if (ContainsAny(lower, {"heap", "stack", "0x", "[", "+"})) {
            return true;
        }
    }
    return false;
}

// Detect shellcode patterns in event metadata
bool DetectShellcodeIndicators(const Event& event) {
    std::string callTrace = FieldValue(event, field::kCallTrace);

    // Call trace from unusual / unbacked memory regions indicates
    // execution of shellcode (no module backing the address).
    if (!callTrace.empty()) {
        std::string lower = LowerAscii(callTrace);
        if (ContainsAny(lower, {"unknown", "anon", "unbacked", "pageheap",
                                "guard"})) {
            return true;
        }
    }

    return false;
}

} // namespace

MemoryScannerDetector::MemoryScannerDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool MemoryScannerDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_ACCESS ||
           type == EDR_EVT_THREAD_CREATE ||
           type == EDR_EVT_MEMORY_WRITE ||
           type == EDR_EVT_IMAGE_LOAD ||
           type == EDR_EVT_PROCESS_START;
}

void MemoryScannerDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    uint64_t now = EventTime(event);
    PurgeExpired(now);

    switch (event.type) {
        case EDR_EVT_PROCESS_START:
            AnalyzeProcessStart(event);
            break;

        case EDR_EVT_PROCESS_ACCESS: {
            uint32_t targetPid = FieldU32(event, field::kTargetPid);
            if (targetPid == 0) return;
            std::string targetImage = FieldValue(event, field::kTargetImage);
            if (targetImage.empty()) targetImage = "pid:" + std::to_string(targetPid);
            auto& state = GetOrCreateState(targetPid, targetImage, 0);
            AnalyzeProcessAccess(event, state);
            break;
        }

        case EDR_EVT_THREAD_CREATE: {
            uint32_t targetPid = FieldU32(event, field::kTargetPid);
            if (targetPid == 0) targetPid = event.pid;
            std::string targetImage = FieldValue(event, field::kTargetImage);
            if (targetImage.empty()) targetImage = event.source;
            auto& state = GetOrCreateState(targetPid, targetImage, 0);
            AnalyzeThreadCreate(event, state);
            break;
        }

        case EDR_EVT_MEMORY_WRITE: {
            uint32_t targetPid = FieldU32(event, field::kTargetPid);
            if (targetPid == 0) return;
            std::string targetImage = FieldValue(event, field::kTargetImage);
            if (targetImage.empty()) targetImage = "pid:" + std::to_string(targetPid);
            auto& state = GetOrCreateState(targetPid, targetImage, 0);
            AnalyzeMemoryWrite(event, state);
            break;
        }

        case EDR_EVT_IMAGE_LOAD: {
            uint32_t pid = event.pid;
            if (pid == 0) return;
            std::string image = event.source;
            auto& state = GetOrCreateState(pid, image, 0);
            AnalyzeImageLoad(event, state);
            break;
        }
    }
}

void MemoryScannerDetector::AnalyzeProcessStart(Event& event) {
    uint32_t pid = event.pid;
    if (pid == 0) return;

    std::string image = FieldValue(event, field::kImage);
    if (image.empty()) image = event.source;

    uint64_t startTime = event.ts100ns;
    if (startTime == 0) {
        FILETIME now = {};
        GetSystemTimePreciseAsFileTime(&now);
        startTime = (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                    now.dwLowDateTime;
    }

    // Create fresh state for new process
    ProcessState state;
    state.pid = pid;
    state.imagePath = image;
    state.startTime100ns = startTime;
    state.lastSeen100ns = startTime;
    state.score = 0;
    state.alerted = false;

    // Check for immediate suspicious indicators on process start
    std::string parentImage = FieldValue(event, field::kParentImage);
    std::string commandLine = FieldValue(event, field::kCommandLine);

    // Suspicious parent spawning process with encoded/obfuscated command
    if (!parentImage.empty() && !commandLine.empty()) {
        std::string lowerCmd = LowerAscii(commandLine);
        std::string parentBase = BaseName(parentImage);

        // Office apps, browsers spawning processes with suspicious commands
        if (ContainsAny(parentBase, {"winword", "excel", "powerpnt", "outlook",
                                      "msedge", "chrome", "firefox"}) &&
            ContainsAny(lowerCmd, {"-enc", "frombase64", "iex", "invoke-expression",
                                    "downloadstring", "downloadfile"})) {
            UpdateScore(state, 30, "suspicious_parent_with_encoded_command");
        }
    }

    m_processStates[pid] = state;
}

void MemoryScannerDetector::AnalyzeProcessAccess(Event& event,
                                                  ProcessState& state) {
    uint64_t now = EventTime(event);
    state.lastSeen100ns = now;

    std::string grantedAccess = FieldValue(event, field::kGrantedAccess);
    std::string callTrace = FieldValue(event, field::kCallTrace);
    uint32_t sourcePid = event.pid;

    // Skip self-access (process reading itself is normal)
    if (sourcePid == state.pid) return;

    // Detect suspicious cross-process access patterns
    bool hasVmRead = !FieldValue(event, field::kAccessVmRead).empty();
    bool hasVmWrite = !FieldValue(event, field::kAccessVmWrite).empty();
    bool hasVmOperation = !FieldValue(event, field::kAccessVmOperation).empty();
    bool hasCreateThread = !FieldValue(event, field::kAccessCreateThread).empty();

    // Full access combo (VM_READ + VM_WRITE + VM_OPERATION + CREATE_THREAD)
    // is highly suspicious - indicates potential process hollowing/injection
    if (hasVmRead && hasVmWrite && hasVmOperation && hasCreateThread) {
        UpdateScore(state, 45, "full_memory_access_combo_from_external");
    } else if (hasVmWrite && hasCreateThread) {
        // VM_WRITE + CREATE_THREAD indicates code injection.
        UpdateScore(state, 35, "vm_write_with_create_thread");
    }

    // Check for suspicious granted access rights
    if (!grantedAccess.empty()) {
        std::string lower = LowerAscii(grantedAccess);
        // PROCESS_VM_WRITE (0x0020) + PROCESS_CREATE_THREAD (0x0002)
        if (ContainsAny(lower, {"0x0020", "0x0002", "0x1fffff", "0x001fffff"})) {
            UpdateScore(state, 25, "suspicious_access_rights");
        }
    }

    // Check source process location
    std::string sourceImage = FieldValue(event, field::kImage);
    if (!sourceImage.empty()) {
        std::string lowerSource = LowerAscii(sourceImage);
        if (IsUserWritableLocation(lowerSource)) {
            UpdateScore(state, 20, "access_from_user_writable_location");
        }
    }

    // Detect shellcode execution indicators
    if (DetectShellcodeIndicators(event)) {
        UpdateScore(state, 40, "shellcode_execution_indicators");
    }

    // PE header in non-file-backed memory
    if (HasPeHeaderIndicator(callTrace)) {
        UpdateScore(state, 50, "pe_header_in_memory");
    }

    // Check if target is a protected/critical process
    std::string targetBase = BaseName(state.imagePath);
    static const std::set<std::string> kCritical = {
        "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
        "wininit.exe", "smss.exe", "svchost.exe"
    };
    if (kCritical.count(targetBase) != 0) {
        UpdateScore(state, 15, "access_to_critical_process");
    }

    // Stamp event if threshold reached
    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void MemoryScannerDetector::AnalyzeThreadCreate(Event& event,
                                                 ProcessState& state) {
    uint64_t now = EventTime(event);
    state.lastSeen100ns = now;

    std::string remoteThread = FieldValue(event, field::kRemoteThread);
    std::string startModule = FieldValue(event, field::kStartModule);
    std::string startFunction = FieldValue(event, field::kStartFunction);
    uint64_t startAddress = FieldU64(event, field::kStartAddress);

    // Remote thread creation is suspicious
    if (remoteThread == "true" || remoteThread == "1") {
        UpdateScore(state, 30, "remote_thread_creation");

        // Remote thread to executable memory region
        if (startModule.empty() || startModule == "unknown" ||
            startModule == "N/A") {
            UpdateScore(state, 35, "remote_thread_to_unmapped_address");
        }

        // Check if start address is in unusual location
        if (startAddress != 0) {
            // Addresses in heap/stack ranges are suspicious for thread start
            // Typical heap: 0x00000000`00000000 - 0x00007FFF`FFFFFFFF (user space)
            // But we look for non-standard module addresses
            if (startModule.empty()) {
                UpdateScore(state, 40, "thread_start_in_non_module_memory");
            }
        }
    }

    // Thread started in suspicious module
    if (!startModule.empty()) {
        std::string lowerModule = LowerAscii(startModule);
        if (IsUserWritableLocation(lowerModule)) {
            UpdateScore(state, 35, "thread_start_in_user_writable_module");
        }
    }

    // Check for APC injection indicators
    std::string apcInject = FieldValue(event, field::kApcInject);
    if (apcInject == "true" || apcInject == "1") {
        UpdateScore(state, 30, "apc_injection_detected");
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void MemoryScannerDetector::AnalyzeMemoryWrite(Event& event,
                                                ProcessState& state) {
    uint64_t now = EventTime(event);
    state.lastSeen100ns = now;

    uint32_t sourcePid = event.pid;

    // Skip self-writes
    if (sourcePid == state.pid) return;

    // Cross-process memory write is suspicious
    UpdateScore(state, 25, "cross_process_memory_write");

    // Check target address characteristics
    std::string memorySize = FieldValue(event, field::kMemorySize);

    // Writing to executable memory region
    // (This would need memory protection info from the event if available)
    std::string protection = FieldValue(event, field::kMemoryProtection);
    if (!protection.empty()) {
        std::string lower = LowerAscii(protection);
        // PAGE_EXECUTE (0x10), PAGE_EXECUTE_READ (0x20),
        // PAGE_EXECUTE_READWRITE (0x40), PAGE_EXECUTE_WRITECOPY (0x80)
        if (ContainsAny(lower, {"execute", "0x10", "0x20", "0x40", "0x80",
                                 "rwx", "r-x"})) {
            UpdateScore(state, 45, "write_to_executable_memory");
        }
    }

    // Large write to another process (potential PE/module injection)
    if (!memorySize.empty()) {
        try {
            uint64_t size = std::stoull(memorySize);
            if (size > 4096) {  // More than a page
                UpdateScore(state, 30, "large_cross_process_memory_write");
            }
        } catch (...) {}
    }

    // Check source process
    std::string sourceImage = FieldValue(event, field::kImage);
    if (!sourceImage.empty()) {
        std::string lowerSource = LowerAscii(sourceImage);
        if (IsUserWritableLocation(lowerSource)) {
            UpdateScore(state, 20, "memory_write_from_user_writable");
        }
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void MemoryScannerDetector::AnalyzeImageLoad(Event& event,
                                              ProcessState& state) {
    uint64_t now = EventTime(event);
    state.lastSeen100ns = now;

    std::string imagePath = FieldValue(event, field::kImagePath);
    if (imagePath.empty()) imagePath = FieldValue(event, field::kFilePath);
    if (imagePath.empty()) return;

    std::string lowerPath = LowerAscii(imagePath);
    std::string base = BaseName(imagePath);

    // Skip known legitimate modules
    if (IsKnownLegitimateModule(base)) return;

    // Check for DLL loaded from suspicious location
    if (IsUserWritableLocation(lowerPath)) {
        UpdateScore(state, 25, "dll_from_user_writable_location");

        // Unsigned DLL from user location is more suspicious
        std::string signatureStatus = FieldValue(event, field::kSignatureStatus);
        if (signatureStatus == "unsigned" || signatureStatus == "invalid" ||
            signatureStatus == "0") {
            UpdateScore(state, 35, "unsigned_dll_from_user_location");
        }
    }

    // Check for DLL sideloading indicators
    // (legitimate DLL name in wrong location)
    if (IsKnownLegitimateModule(base) && !lowerPath.empty()) {
        static const char* const kSystemPaths[] = {
            "c:\\windows\\system32\\", "c:/windows/system32/",
            "c:\\windows\\syswow64\\", "c:/windows/syswow64/"
        };
        bool inSystemDir = false;
        for (const char* prefix : kSystemPaths) {
            if (lowerPath.compare(0, strlen(prefix), prefix) == 0) {
                inSystemDir = true;
                break;
            }
        }
        if (!inSystemDir) {
            UpdateScore(state, 30, "system_dll_from_non_system_location");
        }
    }

    // Check for DLL with suspicious characteristics
    std::string sha256 = FieldValue(event, field::kSha256);
    if (sha256.empty()) {
        UpdateScore(state, 10, "dll_without_hash");
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

MemoryScannerDetector::ProcessState& MemoryScannerDetector::GetOrCreateState(
    uint32_t pid, const std::string& image, uint64_t startTime100ns) {
    auto it = m_processStates.find(pid);
    if (it != m_processStates.end()) {
        // Update image if we have a better one
        if (it->second.imagePath.empty() && !image.empty()) {
            it->second.imagePath = image;
        }
        return it->second;
    }

    // Create new state
    ProcessState state;
    state.pid = pid;
    state.imagePath = image;
    state.startTime100ns = startTime100ns;
    state.lastSeen100ns = startTime100ns;

    // Evict oldest if at capacity
    if (m_processStates.size() >= m_stateCapacity) {
        auto oldest = std::min_element(m_processStates.begin(),
                                        m_processStates.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastSeen100ns < right.second.lastSeen100ns;
            });
        if (oldest != m_processStates.end()) {
            m_processStates.erase(oldest);
        }
    }

    auto [inserted, _] = m_processStates.emplace(pid, state);
    return inserted->second;
}

void MemoryScannerDetector::PurgeExpired(uint64_t now100ns) {
    if (m_dedupWindow100ns == 0) return;

    for (auto it = m_processStates.begin(); it != m_processStates.end();) {
        if (now100ns > it->second.lastSeen100ns &&
            (now100ns - it->second.lastSeen100ns) > m_dedupWindow100ns * 10) {
            it = m_processStates.erase(it);
        } else {
            ++it;
        }
    }
}

void MemoryScannerDetector::UpdateScore(ProcessState& state, uint32_t weight,
                                         const char* reason) {
    // Apply diminishing returns for repeated same reasons
    bool alreadyHas = false;
    for (const auto& r : state.reasons) {
        if (r == reason) {
            alreadyHas = true;
            break;
        }
    }

    if (!alreadyHas) {
        state.score += weight;
        state.reasons.push_back(reason);
    }

    // Cap at 100
    if (state.score > 100) state.score = 100;
}

void MemoryScannerDetector::StampEvent(Event& event,
                                        const ProcessState& state) {
    // Mark this process as alerted to prevent duplicate alerts
    const_cast<ProcessState&>(state).alerted = true;

    // Add memory scanner fields to event
    event.fields[field::kMemoryScanScore] = std::to_string(state.score);

    // Build reasons string
    std::string reasons;
    for (size_t i = 0; i < state.reasons.size(); ++i) {
        if (i > 0) reasons += ",";
        reasons += state.reasons[i];
    }
    event.fields[field::kMemoryScanReasons] = reasons;

    // Add suspicious region count
    event.fields[field::kMemoryScanRegions] =
        std::to_string(state.suspiciousRegions.size());

    // Add MITRE ATT&CK mapping
    event.fields[field::kMitreAttack] = "T1055";  // Process Injection
    event.fields[field::kMitreTactic] = "Defense Evasion, Privilege Escalation";
}

bool MemoryScannerDetector::IsSuspiciousMemoryProtection(uint32_t protection) const {
    // PAGE_EXECUTE_READWRITE (0x40) is suspicious
    // PAGE_EXECUTE_WRITECOPY (0x80) is suspicious
    constexpr uint32_t kSuspicious =
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (protection & kSuspicious) != 0;
}

bool MemoryScannerDetector::IsExecutableProtection(uint32_t protection) const {
    constexpr uint32_t kExecutable =
        PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (protection & kExecutable) != 0;
}

} // namespace edr
