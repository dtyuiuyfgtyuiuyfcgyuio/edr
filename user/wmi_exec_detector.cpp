/*
 * wmi_exec_detector.cpp - Windows Management Instrumentation / CIM execution
 * detection (T1047). See wmi_exec_detector.h for coverage boundaries.
 */
#include "wmi_exec_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace edr {
namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

std::string ToLowerAscii(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string Basename(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

// Typosquatted wmic image names (形近). Deliberately an allowlist so the
// legitimate system host wmiprvse.exe is never flagged.
bool IsWmicTyposquat(const std::string& base) {  // base already lowercased, includes .exe
    static const char* kSquats[] = {
        "wm1c.exe", "wmlc.exe", "wmicc.exe", "wmiic.exe",
        "wmi1c.exe", "wm1cc.exe", "wml1c.exe", nullptr};
    for (int i = 0; kSquats[i] != nullptr; ++i) {
        if (base == kSquats[i]) return true;
    }
    return false;
}

constexpr const char* kSigProcessCallCreate = "wmic_process_call_create";
constexpr const char* kSigNodeRemote        = "wmic_node_remote";
constexpr const char* kSigRemoteCreds       = "wmic_remote_creds";
constexpr const char* kSigNonSystem32       = "wmic_nonsystem32";
constexpr const char* kSigRelativeName      = "wmic_relative_name";
constexpr const char* kSigInvokeCreate      = "ps_invoke_create";
constexpr const char* kSigGetWin32Create    = "ps_getwin32_create";
constexpr const char* kSigHiddenWindow      = "win32_processstartup_hidden";

// Stable signal-emission order (signals field is comma-joined in this order).
constexpr const char* kSignalOrder[] = {
    kSigProcessCallCreate, kSigNodeRemote, kSigRemoteCreds, kSigNonSystem32,
    kSigRelativeName, kSigInvokeCreate, kSigGetWin32Create, kSigHiddenWindow};

} // namespace

WmiExecDetector::WmiExecDetector(bool enabled, uint32_t minScore,
                                 uint32_t dedupWindowSeconds,
                                 size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool WmiExecDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START || type == EDR_EVT_WMI_EVENT;
}

bool WmiExecDetector::Analyze(const std::string& text, const std::string& lower,
                              const std::string& image,
                              const std::string& imageLower,
                              Finding* out) const {
    std::vector<std::pair<uint32_t, const char*>> matched;  // (base, signalId)

    // 1. wmic process call create / wmic process create
    if (Contains(lower, "process call create") || Contains(lower, "process create"))
        matched.push_back({75, kSigProcessCallCreate});

    // 2/3. wmic /node: remote execution, with/without explicit credentials.
    const bool remote = Contains(lower, "/node:");
    const bool creds =
        remote &&
        (Contains(lower, "/user:") || Contains(lower, "/password:") ||
         Contains(lower, "/u:") || Contains(lower, "/p:") ||
         Contains(lower, " -u ") || Contains(lower, " -p "));
    if (creds) {
        matched.push_back({74, kSigRemoteCreds});
    } else if (remote) {
        matched.push_back({55, kSigNodeRemote});
    }

    // 4. wmic image outside the system32\wbem directory.
    if (Contains(imageLower, "wmic") &&
        !Contains(imageLower, "system32\\wbem") &&
        !Contains(imageLower, "system32/wbem")) {
        matched.push_back({55, kSigNonSystem32});
    }

    // 5. typosquatted wmic image name.
    {
        const std::string base = ToLowerAscii(Basename(image));
        if (IsWmicTyposquat(base)) matched.push_back({54, kSigRelativeName});
    }

    // 6. PowerShell Invoke-CimMethod / Invoke-WmiMethod -MethodName Create.
    if ((Contains(lower, "invoke-cimmethod") || Contains(lower, "invoke-wmimethod")) &&
        Contains(lower, "create")) {
        matched.push_back({75, kSigInvokeCreate});
    }

    // 7. PowerShell Get-WmiObject / Get-CimInstance Win32_Process + .Create(
    if ((Contains(lower, "get-wmiobject") || Contains(lower, "get-ciminstance")) &&
        Contains(lower, "win32_process") && Contains(lower, ".create(")) {
        matched.push_back({75, kSigGetWin32Create});
    }

    // 8. Win32_ProcessStartup hidden-window evasion.
    if (Contains(lower, "win32_processstartup") &&
        (Contains(lower, "showwindow") || Contains(lower, "createflags"))) {
        matched.push_back({75, kSigHiddenWindow});
    }

    if (matched.empty()) return false;

    uint32_t best = 0;
    for (const auto& m : matched) {
        if (m.first > best) best = m.first;
    }
    // Do not inflate two 75-point execution-shape signals that describe the
    // same operation (for example Invoke-CimMethod Create with a hidden
    // ProcessStartup).  Corroboration is reserved for an independent
    // lower-confidence signal such as remote credentials or image location.
    bool hasLowerConfidence = false;
    for (const auto& m : matched) {
        if (m.first < 75) {
            hasLowerConfidence = true;
            break;
        }
    }
    if (matched.size() >= 2 && hasLowerConfidence) {
        best = std::min<uint32_t>(100, best + 5);
    }

    std::string signals;
    for (const char* id : kSignalOrder) {
        bool on = false;
        for (const auto& m : matched) {
            if (m.second == id) { on = true; break; }
        }
        if (on) {
            if (!signals.empty()) signals += ",";
            signals += id;
        }
    }

    out->score = best;
    out->signals = signals;
    out->techniques = "T1047";
    return true;
}

void WmiExecDetector::Stamp(Event& event, const Finding& finding,
                            const std::string& /*key*/) {
    event.fields[field::kWmiExecScore] = std::to_string(finding.score);
    if (finding.score >= 55) {
        event.fields[field::kWmiExecVerdict] =
            finding.score >= 75 ? "malicious" : "suspicious";
        event.fields[field::kWmiExecSignals] = finding.signals;
        event.fields[field::kWmiExecTechniques] = finding.techniques;
    }
}

void WmiExecDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    std::string text;
    if (event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    } else {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
    }
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    if (text.empty()) return;

    const std::string lower = ToLowerAscii(text);

    std::string image;
    auto imgIt = event.fields.find(field::kImage);
    if (imgIt != event.fields.end()) image = imgIt->second;
    const std::string imageLower = ToLowerAscii(image);

    Finding finding;
    if (!Analyze(text, lower, image, imageLower, &finding)) return;
    if (finding.score < m_minScore) return;
    if (finding.score < 55) return;  // house rule: <55 fully silent

    const std::string key = lower.substr(0, std::min<size_t>(lower.size(), 160));

    const uint64_t now = event.ts100ns;  // house rule: use event timestamp
    auto it = m_lastAlert.find(key);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                "[edr-wmi-exec] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
