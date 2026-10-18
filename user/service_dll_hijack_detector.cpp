/*
 * service_dll_hijack_detector.cpp - ServiceDll hijack detector (T1574.011).
 */
#include "service_dll_hijack_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool EndsWith(const std::string& value, const char* suffix) {
    const size_t n = std::char_traits<char>::length(suffix);
    return value.size() >= n &&
           value.compare(value.size() - n, n, suffix) == 0;
}

bool MentionsWritableDir(const std::string& lower) {
    return Contains(lower, "\\temp\\") || Contains(lower, "%temp%") ||
           Contains(lower, "\\appdata\\") || Contains(lower, "%appdata%") ||
           Contains(lower, "\\users\\public") ||
           Contains(lower, "\\programdata\\") ||
           Contains(lower, "\\downloads\\") ||
           Contains(lower, "\\desktop\\");
}

bool IsSystem32Path(const std::string& lower) {
    return Contains(lower, "\\windows\\system32\\") ||
           Contains(lower, "%systemroot%\\system32") ||
           Contains(lower, "%windir%\\system32");
}

bool IsReadOnlyQuery(const std::string& lower) {
    const bool reads = Contains(lower, "reg query") ||
                       Contains(lower, "get-itemproperty") ||
                       Contains(lower, "get-childitem") ||
                       Contains(lower, "sc qc") ||
                       Contains(lower, "sc query");
    if (!reads) return false;
    return !Contains(lower, "reg add") && !Contains(lower, "reg delete") &&
           !Contains(lower, "set-itemproperty") &&
           !Contains(lower, "new-itemproperty") &&
           !Contains(lower, "sc create") &&
           !Contains(lower, "sc config");
}

bool IsTrustedWriter(const std::string& lower) {
    return Contains(lower, "msiexec") || Contains(lower, "trustedinstaller") ||
           Contains(lower, "tiworker") || Contains(lower, "\\servicing\\") ||
           Contains(lower, "setup.exe") || Contains(lower, "wusa");
}

bool IsServiceDllKey(const std::string& lower) {
    return Contains(lower, "\\services\\") &&
           (Contains(lower, "servicedll") || Contains(lower, "\\parameters"));
}

} // namespace

ServiceDllHijackDetector::ServiceDllHijackDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_capacity(stateCapacity) {}

/* static */
bool ServiceDllHijackDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

/* static */
bool ServiceDllHijackDetector::ClassifyPayload(const std::string& data,
                                               Finding* out) {
    if (data.empty()) return false;
    const std::string lower = ToLowerAscii(data);
    if (IsSystem32Path(lower) && !MentionsWritableDir(lower)) {
        // Stock svchost implementations live in system32; silent.
        // But if it's system32 AND writable dir (e.g., Temp\System32) it's not stock.
        return false;
    }
    if (MentionsWritableDir(lower)) {
        *out = Finding{90, "ServiceDll in user-writable path"};
        return true;
    }
    if (Contains(lower, "%") || Contains(lower, "\\users\\")) {
        // Environment-variable or user-profile indirection.
        *out = Finding{90, "ServiceDll with env-var/user-profile path"};
        return true;
    }
    // Any DLL outside system32 is at least suspicious (svchost plane).
    if (Contains(lower, ".dll")) {
        *out = Finding{85, "ServiceDll outside system32"};
        return true;
    }
    return false;
}

void ServiceDllHijackDetector::Stamp(Event& event, const Finding& finding,
                                     const std::string& key) {
    event.fields[field::kServiceDllHijackScore] = std::to_string(finding.score);
    event.fields[field::kServiceDllHijackVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kServiceDllHijackSignals] = finding.signal;
    event.fields[field::kServiceDllHijackText] = key;
}

void ServiceDllHijackDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        auto valIt = event.fields.find(field::kRegValue);
        std::string keyText;
        if (keyIt != event.fields.end()) keyText = keyIt->second;
        std::string valText;
        if (valIt != event.fields.end()) valText = valIt->second;

        const std::string lowerJoined = ToLowerAscii(keyText + " " + valText);
        if (!IsServiceDllKey(lowerJoined)) return;

        const std::string lowerKey = ToLowerAscii(keyText);
        const std::string lowerVal = ToLowerAscii(valText);

        // Dual shape handling.
        bool keyNamesSlot = EndsWith(lowerKey, "\\servicedll") ||
                            lowerKey == "servicedll";
        bool valNamesSlot = lowerVal == "servicedll";

        Finding finding;
        if (keyNamesSlot && !valText.empty()) {
            // sysmon/reg_watch: key ends with ServiceDll, valText is DATA
            if (!ClassifyPayload(valText, &finding)) return;
        } else if (valNamesSlot) {
            // driver/imonitor: val is the NAME "ServiceDll"
            if (keyText.empty() || lowerKey.find("\\services\\") == std::string::npos)
                return;
            finding = Finding{75, "ServiceDll registered with no payload token"};
        } else {
            // Command-shaped reg write on REG_WRITE plane - treat valText as data
            // Only if valText looks like a DLL path
            if (valText.empty() || !ClassifyPayload(valText, &finding))
                return;
        }

        if (finding.score < m_minScore) return;
        Stamp(event, finding, lowerJoined.substr(0, 160));
        return;
    }

    // Command-plane: PROCESS_START / POWERSHELL_SCRIPT
    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) return;

    const std::string lower = ToLowerAscii(text);
    if (!Contains(lower, "servicedll")) return;
    if (IsReadOnlyQuery(lower)) return;
    if (IsTrustedWriter(lower)) return;

    // Extract assigned data similarly to screensaver - look for /d or -Value
    std::string data;
    // Try to find DLL path after ServiceDll mention
    size_t pos = lower.find("servicedll");
    if (pos != std::string::npos) {
        // Look for .dll after that
        size_t dllPos = lower.find(".dll", pos);
        if (dllPos != std::string::npos) {
            // Grab a window around it for classification
            size_t start = (dllPos > 60) ? dllPos - 60 : pos;
            size_t end = std::min(lower.size(), dllPos + 60);
            data = text.substr(start, end - start);
        } else {
            // No dll token yet - treat as slot registration
            Finding finding{75, "ServiceDll written with no payload token"};
            if (finding.score < m_minScore) return;
            const std::string key = lower.substr(0, 160);
            const uint64_t now = event.ts100ns;
            auto it = m_state.find(key);
            if (it != m_state.end()) {
                if (m_dedupWindow100ns != 0 && now >= it->second &&
                    now - it->second < m_dedupWindow100ns)
                    return;
                it->second = now;
            } else {
                if (m_capacity > 0 && m_state.size() >= m_capacity) {
                    m_state.clear();
                    std::fprintf(stderr,
                        "[edr-service-dll] state capacity %zu reached; dedup reset\n",
                        m_capacity);
                }
                m_state.emplace(key, now);
            }
            Stamp(event, finding, key);
            return;
        }
    }

    Finding finding;
    if (!ClassifyPayload(data, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = lower.substr(0, 160);
    const uint64_t now = event.ts100ns;
    auto it = m_state.find(key);
    if (it != m_state.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_capacity > 0 && m_state.size() >= m_capacity) {
            m_state.clear();
            std::fprintf(stderr,
                "[edr-service-dll] state capacity %zu reached; dedup reset\n",
                m_capacity);
        }
        m_state.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
