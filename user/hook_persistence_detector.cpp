/*
 * hook_persistence_detector.cpp - Hook-based persistence scoring (T1546).
 */
#include "hook_persistence_detector.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace edr {

namespace {

std::string LowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool Contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

bool EndsWith(const std::string& text, const char* suffix) {
    const size_t len = strlen(suffix);
    return text.size() >= len && text.compare(text.size() - len, len,
                                               suffix) == 0;
}

/* Extracts the path component between `prefix` and `suffix`, e.g. the
 * image name from "...Image File Execution Options\sethc.exe\Debugger". */
std::string MidComponent(const std::string& text, const char* prefix,
                         const char* suffix) {
    const size_t begin = text.find(prefix);
    if (begin == std::string::npos) return std::string();
    const size_t start = begin + strlen(prefix);
    const size_t end = text.rfind(suffix);
    if (end == std::string::npos || end < start) return std::string();
    return text.substr(start, end - start);
}

bool IsUserWritablePath(const std::string& lowerValue) {
    if (lowerValue.find(':') == std::string::npos) return true; /* relative */
    static const char* const kMarkers[] = {
        "\\temp\\", "\\appdata\\", "\\programdata\\", "\\downloads\\",
        "\\users\\public\\", "\\windows\\temp\\", "\\perflogs\\",
        "\\desktop\\", "\\documents\\"
    };
    for (const char* marker : kMarkers)
        if (Contains(lowerValue, marker)) return true;
    return false;
}

bool IsSuspiciousDebuggerValue(const std::string& lowerValue) {
    static const char* const kMarkers[] = {
        "cmd.exe", "powershell", "wscript", "cscript", "mshta",
        "rundll32", "regsvr32", "msbuild", "installutil"
    };
    for (const char* marker : kMarkers)
        if (Contains(lowerValue, marker)) return true;
    return IsUserWritablePath(lowerValue);
}

} // namespace

HookPersistenceDetector::HookPersistenceDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {
    for (const char* image : {"sethc.exe", "utilman.exe", "osk.exe",
                              "magnify.exe", "narrator.exe",
                              "displayswitch.exe", "atbroker.exe"})
        m_accessibilityImages.insert(image);
}

/* static */
bool HookPersistenceDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_REG_WRITE;
}

bool HookPersistenceDetector::Analyze(const std::string& rawKey,
                                      const std::string& rawValue,
                                      Finding* out) const {
    if (!out) return false;
    const std::string key = LowerAscii(rawKey);
    const std::string value = LowerAscii(rawValue);
    if (value.empty() || value.rfind("<binary:", 0) == 0 ||
        value.rfind("<truncated:", 0) == 0)
        return false;

    /* T1546.008 / T1546.012: IFEO Debugger values. The registry watch
     * collector emits "<prefix>\<image>\Debugger" for its watchSubtree
     * IFEO target; the periodic hook scan uses the same shape. */
    if (Contains(key, "\\image file execution options\\") &&
        EndsWith(key, "\\debugger")) {
        const std::string image =
            MidComponent(key, "image file execution options\\", "\\debugger");
        if (m_accessibilityImages.count(image) != 0) {
            *out = Finding{85, "T1546.008",
                           "debugger backdoor on accessibility binary"};
            return true;
        }
        if (IsSuspiciousDebuggerValue(value)) {
            *out = Finding{75, "T1546.012",
                           "ifeo debugger launches interpreter or "
                           "user-writable payload"};
        } else {
            *out = Finding{60, "T1546.012", "ifeo debugger value set"};
        }
        return true;
    }

    /* T1546.015: COM hijack via InprocServer32/LocalServer32. */
    if (Contains(key, "\\classes\\clsid\\") &&
        (EndsWith(key, "\\inprocserver32") ||
         EndsWith(key, "\\localserver32"))) {
        const bool hkcu = key.rfind("hkcu\\", 0) == 0;
        const bool userWritable = IsUserWritablePath(value);
        if (hkcu && userWritable) {
            *out = Finding{75, "T1546.015",
                           "user hive com server points to user-writable "
                           "or relative target"};
        } else if (hkcu) {
            *out = Finding{65, "T1546.015",
                           "user hive com server registration"};
        } else if (userWritable) {
            *out = Finding{70, "T1546.015",
                           "machine com server points to user-writable "
                           "or relative target"};
        } else {
            return false; /* machine hive, system location: benign */
        }
        return true;
    }

    return false;
}

void HookPersistenceDetector::Stamp(Event& event, const Finding& finding,
                                    const std::string& key) {
    event.fields[field::kHookPersistScore] = std::to_string(finding.score);
    event.fields[field::kHookPersistVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kHookPersistTechnique] = finding.technique;
    event.fields[field::kHookPersistReasons] = finding.reason;
    event.fields[field::kHookPersistKey] = key;
}

void HookPersistenceDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    auto keyIt = event.fields.find(field::kRegKey);
    if (keyIt == event.fields.end()) return;
    auto valueIt = event.fields.find(field::kRegValue);

    Finding finding;
    if (!Analyze(keyIt->second,
                 valueIt != event.fields.end() ? valueIt->second
                                               : std::string(),
                 &finding))
        return;
    if (finding.score < m_minScore) return;

    const uint64_t now = event.ts100ns;
    auto it = m_lastAlert.find(keyIt->second);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                "[edr-hookpersist] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(keyIt->second, now);
    }

    Stamp(event, finding, keyIt->second);
}

} // namespace edr
