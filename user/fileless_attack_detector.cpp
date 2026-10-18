/*
 * fileless_attack_detector.cpp - See fileless_attack_detector.h.
 *
 * Detects fileless / in-memory attack techniques across multiple event
 * sources:
 * - POWERSHELL_SCRIPT: script block text analyzed for obfuscation,
 *   download-execute and reflection techniques.
 * - WMI_EVENT: permanent event subscription (__EventFilter +
 *   __EventConsumer) used for fileless persistence.
 * - PROCESS_START: script hosts (wscript/cscript/mshta/rundll32)
 *   spawned with encoded / suspicious arguments.
 * - THREAD_CREATE / PROCESS_ACCESS: in-memory injection primitives that
 *   commonly accompany fileless payload delivery.
 *
 * Techniques are scored with a bounded per-script state keyed by script
 * block id / process pid so that one alert covers a full campaign.
 */
#include "fileless_attack_detector.h"

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

bool IsScriptHostBase(const std::string& lowerBase) {
    static const std::set<std::string> hosts = {
        "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe",
        "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe"
    };
    return hosts.count(lowerBase) != 0;
}

} // namespace

FilelessAttackDetector::FilelessAttackDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool FilelessAttackDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_WMI_EVENT ||
           type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_THREAD_CREATE ||
           type == EDR_EVT_PROCESS_ACCESS;
}

void FilelessAttackDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    PurgeExpired(EventTime(event));

    switch (event.type) {
        case EDR_EVT_POWERSHELL_SCRIPT:
            AnalyzePowerShell(event);
            break;
        case EDR_EVT_WMI_EVENT:
            AnalyzeWmi(event);
            break;
        case EDR_EVT_PROCESS_START:
            AnalyzeProcessStart(event);
            break;
        case EDR_EVT_THREAD_CREATE:
            AnalyzeThreadCreate(event);
            break;
        case EDR_EVT_PROCESS_ACCESS:
            AnalyzeProcessAccess(event);
            break;
    }
}

bool FilelessAttackDetector::ContainsObfuscation(const std::string& text) const {
    std::string lower = LowerAscii(text);
    // Common PowerShell obfuscation primitives
    static const char* const patterns[] = {
        "-enc", "frombase64string", "-e ", "-encodedcommand", "iex(",
        "invoke-expression", "-w hidden", "-windowstyle", "-nop",
        "-noprofile", "-ex bypass", "-executionpolicy", " -ep ",
        "char(" , "convertto-securestring", "encrypted", "$env:appdata",
        "backtick", "```", "join('", "replace(", "-replace"
    };
    for (const char* p : patterns) {
        if (lower.find(p) != std::string::npos) return true;
    }
    // Base64-like run of alnum (encoded blob)
    size_t alnumRun = 0;
    for (char c : lower) {
        if (std::isalnum(static_cast<unsigned char>(c))) {
            if (++alnumRun > 64) return true;
        } else {
            alnumRun = 0;
        }
    }
    return false;
}

bool FilelessAttackDetector::ContainsDownloadExecute(const std::string& text) const {
    std::string lower = LowerAscii(text);
    static const char* const patterns[] = {
        "downloadstring", "downloadfile", "invoke-webrequest",
        "iwr ", "wget ", "curl ", "system.net.webclient",
        "net.webclient", "winhttp", "start-process -filepath",
        "add-type", "iex", "new-object system.net",
        ".download", "webrequest", "request ="
    };
    for (const char* p : patterns) {
        if (lower.find(p) != std::string::npos) return true;
    }
    return false;
}

bool FilelessAttackDetector::ContainsReflection(const std::string& text) const {
    std::string lower = LowerAscii(text);
    static const char* const patterns[] = {
        "reflection.assembly", "load(byte", "loadfile", "load(",
        "assembly.load", "dllimport", "add-type -typedefinition",
        "getmethod", "invoke(", "createinstance", "marshal",
        "virtualprotect", "writeprocessmemory", "createremotethread",
        "alloc", "generaterandomencrypted"
    };
    for (const char* p : patterns) {
        if (lower.find(p) != std::string::npos) return true;
    }
    return false;
}

bool FilelessAttackDetector::IsScriptHost(const std::string& lowerBase) const {
    return IsScriptHostBase(lowerBase);
}

void FilelessAttackDetector::AnalyzePowerShell(Event& event) {
    std::string scriptText = FieldValue(event, field::kScriptBlockText);
    std::string scriptId = FieldValue(event, field::kScriptBlockId);
    if (scriptId.empty()) {
        scriptId = "ps:" + std::to_string(event.pid) + ":" +
                   std::to_string(event.ts100ns);
    }

    if (scriptText.empty()) return;

    ScriptState& state = GetOrCreateState(scriptId);
    state.lastSeen100ns = EventTime(event);

    // Obfuscation
    if (ContainsObfuscation(scriptText)) {
        UpdateScore(state, 35, "obfuscation");
    }

    // Download-execute
    if (ContainsDownloadExecute(scriptText)) {
        UpdateScore(state, 45, "download_execute");
    }

    // Reflection / in-memory loading
    if (ContainsReflection(scriptText)) {
        UpdateScore(state, 55, "reflective_loading");
    }

    // Script stored in unusual location (fileless staging)
    std::string scriptPath = LowerAscii(FieldValue(event, field::kScriptPath));
    if (!scriptPath.empty() &&
        ContainsAny(scriptPath, {"\\temp\\", "\\appdata\\", "\\downloads\\"})) {
        UpdateScore(state, 20, "script_from_user_location");
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void FilelessAttackDetector::AnalyzeWmi(Event& event) {
    std::string query = FieldValue(event, field::kWmiQuery);
    std::string operation = LowerAscii(FieldValue(event, field::kWmiOperation));
    std::string providerName = LowerAscii(FieldValue(event, field::kWmiProviderName));

    // Permanent event subscription creation is a classic fileless
    // persistence primitive.
    bool filterOp = ContainsAny(operation, {"__eventfilter", "filter"}); 
    bool consumerOp = ContainsAny(operation, {"__eventconsumer", "consumer"});
    bool bindingOp = ContainsAny(operation, {"__filtertoconsumerbinding", "binding"});

    if (filterOp || consumerOp || bindingOp) {
        std::string key = "wmi:" + std::to_string(event.pid) + ":" +
                          std::to_string(event.ts100ns / 10000000ULL);
        ScriptState& state = GetOrCreateState(key);
        state.lastSeen100ns = EventTime(event);

        // Query with malicious command execution
        if (!query.empty()) {
            std::string lowerQuery = LowerAscii(query);
            if (ContainsAny(lowerQuery, {"powershell", "cmd.exe", "rundll32",
                                         "wscript", "cscript", "mshta",
                                         "execute", "wscript.shell",
                                         "winmgmts"})) {
                UpdateScore(state, 45, "wmi_subscription_command_execution");
            }
            if (ContainsDownloadExecute(lowerQuery)) {
                UpdateScore(state, 40, "wmi_subscription_download_execute");
            }
        }

        // Filter+Consumer+Binding (full subscription chain)
        if (filterOp && consumerOp) {
            UpdateScore(state, 30, "wmi_full_subscription");
        }

        // Non-standard provider
        if (!providerName.empty() &&
            ContainsAny(providerName, {"unmanaged", "reflective", "unknown"})) {
            UpdateScore(state, 20, "wmi_suspicious_provider");
        }

        if (state.score >= m_minScore && !state.alerted) {
            StampEvent(event, state);
        }
    }
}

void FilelessAttackDetector::AnalyzeProcessStart(Event& event) {
    std::string image = FieldValue(event, field::kImage);
    std::string commandLine = FieldValue(event, field::kCommandLine);
    if (image.empty() || commandLine.empty()) return;

    std::string base = BaseName(image);
    if (!IsScriptHost(base)) return;

    std::string lowerCmd = LowerAscii(commandLine);
    std::string key = "proc:" + std::to_string(event.pid);
    ScriptState& state = GetOrCreateState(key);
    state.lastSeen100ns = EventTime(event);

    // Script host with encoded payload
    if (ContainsAny(lowerCmd, {"-enc", "-encodedcommand", "-e ", "frombase64"})) {
        UpdateScore(state, 40, "script_host_encoded_payload");
    }

    // Script host with obfuscation flags
    if (ContainsAny(lowerCmd, {"-w hidden", "-windowstyle", "-nop", "-ep bypass",
                               "-executionpolicy bypass", "-noprofile"})) {
        UpdateScore(state, 25, "script_host_hidden_flags");
    }

    // Script host downloading and executing
    if (ContainsDownloadExecute(lowerCmd)) {
        UpdateScore(state, 45, "script_host_download_execute");
    }

    // Script host with URL in command line
    if (lowerCmd.find("http://") != std::string::npos ||
        lowerCmd.find("https://") != std::string::npos) {
        UpdateScore(state, 30, "script_host_url_argument");
    }

    // regsvr32 / rundll32 loading remote or unusual content
    if (ContainsAny(base, {"regsvr32", "rundll32"})) {
        if (ContainsAny(lowerCmd, {"scrobj.dll", "http://", "https://",
                                   ".sct", ".xll", ".dll", ".ocx"})) {
            UpdateScore(state, 35, "squiblydoo_pattern");
        }
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void FilelessAttackDetector::AnalyzeThreadCreate(Event& event) {
    std::string remoteThread = FieldValue(event, field::kRemoteThread);
    if (remoteThread != "true" && remoteThread != "1") return;

    std::string startModule = LowerAscii(FieldValue(event, field::kStartModule));
    std::string key = "thread:" + std::to_string(event.pid) + ":" +
                      std::to_string(event.ts100ns / 10000000ULL);
    ScriptState& state = GetOrCreateState(key);
    state.lastSeen100ns = EventTime(event);

    // Remote thread into non-module memory = fileless payload execution
    if (startModule.empty() || startModule == "unknown" ||
        startModule == "n/a") {
        UpdateScore(state, 40, "remote_thread_to_unmapped_memory");
    }

    // Remote thread into user-writable module
    if (ContainsAny(startModule, {"\\temp\\", "\\appdata\\", "\\downloads\\"})) {
        UpdateScore(state, 35, "remote_thread_to_user_module");
    }

    if (state.score >= m_minScore && !state.alerted) {
        StampEvent(event, state);
    }
}

void FilelessAttackDetector::AnalyzeProcessAccess(Event& event) {
    std::string callTrace = LowerAscii(FieldValue(event, field::kCallTrace));
    if (callTrace.empty()) return;

    // Unbacked (anon) memory in call trace is a fileless execution signal
    if (ContainsAny(callTrace, {"anon", "unbacked", "reserved", "0x"})) {
        std::string key = "access:" + std::to_string(event.pid) + ":" +
                          std::to_string(event.ts100ns / 10000000ULL);
        ScriptState& state = GetOrCreateState(key);
        state.lastSeen100ns = EventTime(event);

        UpdateScore(state, 30, "execution_from_unbacked_memory");

        if (state.score >= m_minScore && !state.alerted) {
            StampEvent(event, state);
        }
    }
}

FilelessAttackDetector::ScriptState& FilelessAttackDetector::GetOrCreateState(
    const std::string& key) {
    auto it = m_scriptStates.find(key);
    if (it != m_scriptStates.end()) return it->second;

    ScriptState state;
    if (m_scriptStates.size() >= m_stateCapacity) {
        auto oldest = std::min_element(m_scriptStates.begin(),
                                        m_scriptStates.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastSeen100ns < right.second.lastSeen100ns;
            });
        if (oldest != m_scriptStates.end()) m_scriptStates.erase(oldest);
    }
    auto [inserted, _] = m_scriptStates.emplace(key, state);
    return inserted->second;
}

void FilelessAttackDetector::PurgeExpired(uint64_t now100ns) {
    if (m_dedupWindow100ns == 0) return;
    for (auto it = m_scriptStates.begin(); it != m_scriptStates.end();) {
        if (now100ns > it->second.lastSeen100ns &&
            (now100ns - it->second.lastSeen100ns) > m_dedupWindow100ns * 10) {
            it = m_scriptStates.erase(it);
        } else {
            ++it;
        }
    }
}

void FilelessAttackDetector::UpdateScore(ScriptState& state, uint32_t weight,
                                          const char* technique) {
    for (const auto& t : state.techniques) {
        if (t == technique) return;
    }
    state.score += weight;
    if (state.score > 100) state.score = 100;
    state.techniques.push_back(technique);
}

void FilelessAttackDetector::StampEvent(Event& event,
                                         const ScriptState& state) {
    const_cast<ScriptState&>(state).alerted = true;

    event.fields[field::kFilelessScore] = std::to_string(state.score);
    event.fields[field::kFilelessCount] =
        std::to_string(state.techniques.size());
    event.fields[field::kFilelessTechniques] = Join(state.techniques, ",");
    event.fields[field::kFilelessVerdict] =
        state.score >= 60 ? "malicious" : "suspicious";

    event.fields[field::kMitreAttack] =
        "T1059.001,T1059.003,T1218.010,T1546.003";
    event.fields[field::kMitreTactic] =
        "Execution,Persistence,Defense Evasion";
}

} // namespace edr
