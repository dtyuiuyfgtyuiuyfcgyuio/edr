/*
 * dll_search_order_detector.cpp - DLL search order hijack detector (T1574.002).
 */
#include "dll_search_order_detector.h"

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

bool MentionsAppDir(const std::string& lower) {
    return Contains(lower, "\\program files\\") ||
           Contains(lower, "\\program files (x86)\\");
}

bool IsReadOnlyQuery(const std::string& lower) {
    const bool reads = Contains(lower, "reg query") ||
                       Contains(lower, "get-itemproperty") ||
                       Contains(lower, "get-childitem") ||
                       Contains(lower, "dir ") ||
                       Contains(lower, "gpresult");
    if (!reads) return false;
    return !Contains(lower, "reg add") && !Contains(lower, "reg delete") &&
           !Contains(lower, "set-itemproperty") &&
           !Contains(lower, "new-itemproperty") &&
           !Contains(lower, "copy") && !Contains(lower, "xcopy") &&
           !Contains(lower, ">") && !Contains(lower, "knownlls");
}

bool IsTrustedWriter(const std::string& lower) {
    return Contains(lower, "msiexec") || Contains(lower, "trustedinstaller") ||
           Contains(lower, "tiworker") || Contains(lower, "\\servicing\\") ||
           Contains(lower, "setup.exe") || Contains(lower, "wusa");
}

} // namespace

DllSearchOrderDetector::DllSearchOrderDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_capacity(stateCapacity) {}

/* static */
bool DllSearchOrderDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE ||
           type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_RENAME;
}

/* static */
bool DllSearchOrderDetector::ClassifyFileWrite(const std::string& path,
                                               Finding* out) {
    if (path.empty()) return false;
    const std::string lower = ToLowerAscii(path);
    if (!EndsWith(lower, ".dll")) return false;
    if (IsSystem32Path(lower) && !MentionsWritableDir(lower)) return false;
    // Known hijackable DLL names get higher confidence, but any .dll in
    // an app dir is search-order relevant.
    if (MentionsAppDir(lower)) {
        // Writing a DLL next to a program's exe means it wins over System32.
        *out = Finding{85, "DLL written to application image directory"};
        return true;
    }
    if (MentionsWritableDir(lower)) {
        *out = Finding{80, "DLL written to user-writable directory"};
        return true;
    }
    // Generic .dll write outside system32 but not in obvious hijack dirs:
    // still suspicious at 75 if payload present (covered by writable/app check above).
    return false;
}

/* static */
bool DllSearchOrderDetector::ClassifyKnownDllPayload(const std::string& data,
                                                     Finding* out) {
    if (data.empty()) return false;
    const std::string lower = ToLowerAscii(data);
    if (IsSystem32Path(lower) && !MentionsWritableDir(lower)) return false;
    if (MentionsWritableDir(lower)) {
        *out = Finding{90, "KnownDLLs pointing to writable directory"};
        return true;
    }
    if (Contains(lower, "%") || Contains(lower, "\\users\\")) {
        *out = Finding{90, "KnownDLLs with env-var/user-profile path"};
        return true;
    }
    if (Contains(lower, ".dll")) {
        *out = Finding{90, "KnownDLLs hijack outside system32"};
        return true;
    }
    return false;
}

void DllSearchOrderDetector::Stamp(Event& event, const Finding& finding,
                                   const std::string& key) {
    event.fields[field::kDllSearchOrderScore] = std::to_string(finding.score);
    event.fields[field::kDllSearchOrderVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kDllSearchOrderSignals] = finding.signal;
    event.fields[field::kDllSearchOrderText] = key;
}

void DllSearchOrderDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    if (event.type == EDR_EVT_FILE_CREATE ||
        event.type == EDR_EVT_FILE_RENAME) {
        auto pathIt = event.fields.find(field::kFilePath);
        if (pathIt == event.fields.end())
            pathIt = event.fields.find(field::kTargetPath);
        if (pathIt == event.fields.end()) return;
        const std::string lowerPath = ToLowerAscii(pathIt->second);
        // Check trusted writer via parent image if available
        auto imageIt = event.fields.find(field::kImage);
        if (imageIt != event.fields.end() && IsTrustedWriter(ToLowerAscii(imageIt->second)))
            return;
        Finding finding;
        if (!ClassifyFileWrite(pathIt->second, &finding)) return;
        if (finding.score < m_minScore) return;
        Stamp(event, finding, lowerPath.substr(0, 160));
        return;
    }

    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        auto valIt = event.fields.find(field::kRegValue);
        std::string keyText;
        if (keyIt != event.fields.end()) keyText = keyIt->second;
        std::string valText;
        if (valIt != event.fields.end()) valText = valIt->second;
        const std::string lowerJoined = ToLowerAscii(keyText + " " + valText);
        if (!Contains(lowerJoined, "knowndlls")) return;
        // KnownDLLs: key is ...\Session Manager\KnownDLLs, value is dll name, data is path
        // In sysmon shape, kRegKey is full path + value, kRegValue is data
        // In driver shape, kRegValue is value name
        std::string data;
        // Heuristic: valText is data if it contains .dll or :\ or %
        if (Contains(ToLowerAscii(valText), ".dll") ||
            Contains(valText, ":\\") || Contains(valText, "%")) {
            data = valText;
        } else if (Contains(ToLowerAscii(keyText), ".dll")) {
            // Fallback: data might be in keyText tail? rare
            data = valText;
        } else {
            // No data observed - name-only KnownDLLs write
            Finding finding{75, "KnownDLLs registered with no payload token"};
            if (finding.score < m_minScore) return;
            Stamp(event, finding, lowerJoined.substr(0, 160));
            return;
        }
        Finding finding;
        if (!ClassifyKnownDllPayload(data, &finding)) return;
        if (finding.score < m_minScore) return;
        Stamp(event, finding, lowerJoined.substr(0, 160));
        return;
    }

    // Command plane
    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) return;

    const std::string lower = ToLowerAscii(text);
    if (IsReadOnlyQuery(lower)) return;
    if (IsTrustedWriter(lower)) return;

    bool mentionsKnownDlls = Contains(lower, "knowndlls");
    bool mentionsSetDllDir = Contains(lower, "setdlldirectory");

    if (mentionsKnownDlls || mentionsSetDllDir) {
        // Check if payload path is present and suspicious
        if (MentionsWritableDir(lower)) {
            Finding finding{90, "KnownDLLs/SetDllDirectory with writable path"};
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
                        "[edr-dll-search] state capacity %zu reached; dedup reset\n",
                        m_capacity);
                }
                m_state.emplace(key, now);
            }
            Stamp(event, finding, key);
            return;
        }
        if (Contains(lower, ".dll") && !IsSystem32Path(lower)) {
            Finding finding{75, "KnownDLLs/SetDllDirectory outside system32"};
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
                        "[edr-dll-search] state capacity %zu reached; dedup reset\n",
                        m_capacity);
                }
                m_state.emplace(key, now);
            }
            Stamp(event, finding, key);
            return;
        }
        // KnowDLLs mentioned without extractable payload -> still 75 (slot)
        if (mentionsKnownDlls) {
            Finding finding{75, "KnownDLLs written with no payload token"};
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
                        "[edr-dll-search] state capacity %zu reached; dedup reset\n",
                        m_capacity);
                }
                m_state.emplace(key, now);
            }
            Stamp(event, finding, key);
            return;
        }
    }

    // FILE copy plane via command line: copy version.dll "C:\Program Files\App\"
    if ((Contains(lower, "copy") || Contains(lower, "xcopy") || Contains(lower, "move") ||
         Contains(lower, "copy-item") || Contains(lower, "move-item")) &&
        Contains(lower, ".dll")) {
        if (MentionsAppDir(lower)) {
            Finding finding{85, "DLL copied to application directory"};
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
                        "[edr-dll-search] state capacity %zu reached; dedup reset\n",
                        m_capacity);
                }
                m_state.emplace(key, now);
            }
            Stamp(event, finding, key);
            return;
        }
        if (MentionsWritableDir(lower)) {
            Finding finding{80, "DLL copied to writable directory"};
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
                        "[edr-dll-search] state capacity %zu reached; dedup reset\n",
                        m_capacity);
                }
                m_state.emplace(key, now);
            }
            Stamp(event, finding, key);
            return;
        }
    }
}

} // namespace edr
