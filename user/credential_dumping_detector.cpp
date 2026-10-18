/*
 * credential_dumping_detector.cpp - See credential_dumping_detector.h.
 */
#include "credential_dumping_detector.h"

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

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

uint32_t ParsePid(const std::string& text, uint32_t fallback) {
    if (text.empty()) return fallback;
    errno = 0;
    char* end = nullptr;
    const unsigned long value = std::strtoul(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str()) return fallback;
    return static_cast<uint32_t>(value);
}

bool ContainsI(const std::string& haystack, const char* needle) {
    const std::string h = LowerAscii(haystack);
    const std::string n = LowerAscii(needle);
    return h.find(n) != std::string::npos;
}

std::string Verdict(uint32_t score) {
    /* House scoring contract: >=55 SUSPICIOUS, >=75 MALICIOUS. A SUSPICIOUS
     * floor of 50 would let the 50-54 band publish a score that the house-strict
     * rule bands (`^(?:5[5-9]|[6-9][0-9]|100)$`) deliberately exclude. */
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

} // namespace

CredentialDumpingDetector::CredentialDumpingDetector(bool enabled,
                                                     uint32_t windowSeconds,
                                                     size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool CredentialDumpingDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_ACCESS ||
           type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_READ ||
           type == EDR_EVT_REG_WRITE ||
           type == EDR_EVT_NAMED_PIPE ||
           type == EDR_EVT_IMAGE_LOAD;
}

bool CredentialDumpingDetector::IsLsass(const std::string& image) {
    return BaseName(image) == "lsass.exe";
}

bool CredentialDumpingDetector::IsSamFile(const std::string& path) {
    const std::string lower = LowerAscii(path);
    return lower.find("\\config\\sam") != std::string::npos ||
           lower.find("\\config\\security") != std::string::npos ||
           lower.find("\\config\\system") != std::string::npos;
}

bool CredentialDumpingDetector::IsNtdsDit(const std::string& path) {
    return ContainsI(path, "ntds.dit");
}

bool CredentialDumpingDetector::IsRegSaveKey(const std::string& regKey) {
    const std::string lower = LowerAscii(regKey);
    /* HKLM\SAM, HKLM\SECURITY — reg save / reg export targets */
    return lower.find("\\sam") != std::string::npos ||
           lower.find("\\security") != std::string::npos;
}

bool CredentialDumpingDetector::IsSuspiciousPipe(const std::string& pipeName) {
    const std::string lower = LowerAscii(pipeName);
    /* Mimikatz uses pipes like \\.\pipe\lsass, nanodump uses similar */
    return lower.find("lsass") != std::string::npos ||
           lower.find("mimikatz") != std::string::npos ||
           lower.find("nanodump") != std::string::npos ||
           lower.find("lsadrv") != std::string::npos ||
           lower.find("cachedump") != std::string::npos;
}

bool CredentialDumpingDetector::IsSuspiciousDll(const std::string& dllPath) {
    const std::string base = BaseName(dllPath);
    /* Suspicious DLLs loaded into LSASS: yaotl, custom SSP, kerkberos exts */
    static const char* kSuspiciousDlls[] = {
        "yaotl.dll", "mimilib.dll", "kappfree.dll",
        "kerberos.dll", "ssp.dll", "wdigest.dll"
    };
    /* Only flag if it's NOT in System32 (i.e. loaded from an unusual path) */
    const std::string lower = LowerAscii(dllPath);
    if (lower.find("\\system32\\") != std::string::npos) return false;
    for (const char* dll : kSuspiciousDlls) {
        if (base == dll) return true;
    }
    return false;
}

bool CredentialDumpingDetector::HasReadMemoryAccess(
        const std::string& accessMask) {
    if (accessMask.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long mask = std::strtoul(accessMask.c_str(), &end,
                                             16); /* hex */
    if (errno != 0 || end == accessMask.c_str()) return false;
    /* PROCESS_VM_READ (0x0010) | PROCESS_QUERY_INFORMATION (0x0400)
     * | PROCESS_DUP_HANDLE (0x0040) — common Mimikatz access pattern */
    return (mask & 0x0010) != 0;
}

void CredentialDumpingDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t CredentialDumpingDetector::PidOf(const Event& event) const {
    if (event.type == EDR_EVT_PROCESS_ACCESS) return event.pid;
    if (event.type == EDR_EVT_NAMED_PIPE)
        return ParsePid(FieldValue(event, field::kPid), event.pid);
    if (event.type == EDR_EVT_IMAGE_LOAD)
        return ParsePid(FieldValue(event, field::kPid), event.pid);
    return event.pid;
}

uint32_t CredentialDumpingDetector::ComputeScore(
        const ProcState& state) const {
    uint32_t score = 0;
    if (state.sawLsassAccess) score += 50;
    if (state.sawSamFile) score += 35;
    if (state.sawNtdsDit) score += 40;
    if (state.sawRegSave) score += 30;
    if (state.sawPipe) score += 25;
    if (state.sawImageLoad) score += 20;
    /* Bonus for multiple signals — strong correlation indicator */
    int signalCount = 0;
    if (state.sawLsassAccess) ++signalCount;
    if (state.sawSamFile) ++signalCount;
    if (state.sawNtdsDit) ++signalCount;
    if (state.sawRegSave) ++signalCount;
    if (state.sawPipe) ++signalCount;
    if (state.sawImageLoad) ++signalCount;
    if (signalCount >= 2) score += 15;
    if (signalCount >= 3) score += 10;
    return std::min(100u, score);
}

std::string CredentialDumpingDetector::SignalList(
        const ProcState& state) const {
    std::string signals;
    const char* names[] = {"lsass_access", "sam_file", "ntds_dit",
                           "reg_save", "pipe", "image_load"};
    const bool flags[] = {state.sawLsassAccess, state.sawSamFile,
                          state.sawNtdsDit, state.sawRegSave,
                          state.sawPipe, state.sawImageLoad};
    for (size_t i = 0; i < 6; ++i) {
        if (!flags[i]) continue;
        if (!signals.empty()) signals += ",";
        signals += names[i];
    }
    return signals;
}

std::string CredentialDumpingDetector::TechniqueList(
        const ProcState& state) const {
    std::string techs;
    if (state.sawLsassAccess) {
        if (!techs.empty()) techs += ",";
        techs += "T1003.001";
    }
    if (state.sawSamFile || state.sawRegSave) {
        if (!techs.empty()) techs += ",";
        techs += "T1003.002";
    }
    if (state.sawNtdsDit) {
        if (!techs.empty()) techs += ",";
        techs += "T1003.003";
    }
    return techs;
}

void CredentialDumpingDetector::WriteState(Event& event,
                                           const ProcState& state,
                                           const std::string& detail) {
    const uint32_t score = ComputeScore(state);
    /* House scoring contract: below 55 there is no verdict, so a lone weak
     * signal (e.g. a named pipe alone at 25, or pipe+image_load at 45) must
     * not publish a score field that no rule can consume. */
    if (Verdict(score).empty()) return;
    event.fields[field::kCredentialDumpScore] = std::to_string(score);
    event.fields[field::kCredentialDumpSignals] = SignalList(state);
    event.fields[field::kCredentialDumpTechniques] = TechniqueList(state);
    event.fields[field::kCredentialDumpWindowSeconds] =
        std::to_string(m_windowSeconds);
    if (!detail.empty())
        event.fields[field::kCredentialDumpDetail] = detail;
    const std::string verdict = Verdict(score);
    if (!verdict.empty())
        event.fields[field::kCredentialDumpVerdict] = verdict;
}

void CredentialDumpingDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    /* Process access to LSASS with read-memory rights */
    if (event.type == EDR_EVT_PROCESS_ACCESS) {
        const std::string targetImage =
            FieldValue(event, field::kTargetImage);
        if (!IsLsass(targetImage)) return;
        const std::string mask = FieldValue(event, field::kAccessMask);
        const bool hasReadAccess = HasReadMemoryAccess(mask);
        if (!hasReadAccess && mask.empty()) {
            /* If no access mask info, still flag lsass access */
        } else if (!hasReadAccess) {
            return;
        }
        const uint32_t pid = event.pid;
        ProcState& state = m_procs[pid];
        state.sawLsassAccess = true;
        state.lastSeen100ns = now;
        WriteState(event, state, "lsass.exe memory access");
        return;
    }

    /* File operations on SAM/SECURITY/SYSTEM or ntds.dit */
    if (event.type == EDR_EVT_FILE_CREATE ||
        event.type == EDR_EVT_FILE_READ) {
        const std::string path = FieldValue(event, field::kFilePath);
        if (IsSamFile(path)) {
            const uint32_t pid = event.pid;
            ProcState& state = m_procs[pid];
            state.sawSamFile = true;
            state.lastSeen100ns = now;
            WriteState(event, state, "SAM/SYSTEM/SECURITY hive access");
            return;
        }
        if (IsNtdsDit(path)) {
            const uint32_t pid = event.pid;
            ProcState& state = m_procs[pid];
            state.sawNtdsDit = true;
            state.lastSeen100ns = now;
            WriteState(event, state, "ntds.dit access");
            return;
        }
        return;
    }

    /* Registry write to SAM/SECURITY hive (reg save target) */
    if (event.type == EDR_EVT_REG_WRITE) {
        const std::string regKey = FieldValue(event, field::kRegKey);
        if (!IsRegSaveKey(regKey)) return;
        const uint32_t pid = event.pid;
        ProcState& state = m_procs[pid];
        state.sawRegSave = true;
        state.lastSeen100ns = now;
        WriteState(event, state, "registry SAM/SECURITY hive write");
        return;
    }

    /* Suspicious named pipe (Mimikatz/nanodump) */
    if (event.type == EDR_EVT_NAMED_PIPE) {
        const std::string pipeName = FieldValue(event, field::kPipeName);
        if (!IsSuspiciousPipe(pipeName)) return;
        const uint32_t pid = PidOf(event);
        if (pid == 0) return;
        ProcState& state = m_procs[pid];
        state.sawPipe = true;
        state.lastSeen100ns = now;
        WriteState(event, state, "credential-dumping named pipe");
        return;
    }

    /* Suspicious DLL loaded (from unusual path) */
    if (event.type == EDR_EVT_IMAGE_LOAD) {
        const std::string dllPath = FieldValue(event, field::kImageLoaded);
        const std::string targetImage =
            FieldValue(event, field::kTargetImage);
        /* Only flag if loaded into lsass or if the DLL itself is suspicious */
        if (!IsLsass(targetImage) && !IsSuspiciousDll(dllPath)) return;
        if (!IsSuspiciousDll(dllPath) && IsLsass(targetImage)) {
            /* DLL loaded into lsass from non-system path */
            const std::string lower = LowerAscii(dllPath);
            if (lower.find("\\system32\\") != std::string::npos) return;
        }
        const uint32_t pid = PidOf(event);
        if (pid == 0) return;
        ProcState& state = m_procs[pid];
        state.sawImageLoad = true;
        state.lastSeen100ns = now;
        WriteState(event, state, "suspicious DLL load");
        return;
    }
}

} // namespace edr
