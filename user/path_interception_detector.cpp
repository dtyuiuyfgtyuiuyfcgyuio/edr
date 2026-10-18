/*
 * path_interception_detector.cpp - PATH environment variable hijack
 * detector (T1574.007 / T1574.008).
 */
#include "path_interception_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 const char* const needles[], size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (Contains(value, needles[i])) return true;
    }
    return false;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* User-writable directories that make a planted binary shadow a
 * legitimate one on the search order. */
constexpr const char* kWritableDirs[] = {
    "%temp%", "%appdata%", "%localappdata%", "\\users\\public",
    "\\programdata\\", "\\windows\\temp\\", "\\tmp\\", "c:\\temp\\",
    "\\downloads", "$env:temp", "$env:appdata",
};

constexpr const char* kPathWriteVerbs[] = {
    "setx path", "setx \"path\"", "reg add", "set-itemproperty",
    "new-itemproperty", "setenvironmentvariable", "[environment]::",
};

bool HasWritableDir(const std::string& lower) {
    for (const char* dir : kWritableDirs) {
        if (Contains(lower, dir)) return true;
    }
    return false;
}

/* Last backslash-delimited component of a registry key path. */
std::string LastKeyComponent(const std::string& lowerKey) {
    const size_t slash = lowerKey.find_last_of('\\');
    return slash == std::string::npos ? lowerKey
                                      : lowerKey.substr(slash + 1);
}

/* True when the REG_WRITE names the search-order PATH value itself.
 *
 * REG_WRITE arrives in two shapes (see CLAUDE.md): the driver/imonitor
 * shape puts the bare key path in kRegKey and the value name in
 * kRegValue, while the sysmon/reg_watch/reg_baseline snapshot shape puts
 * the value name at the end of kRegKey and the data in kRegValue. So the
 * value name is matched exactly against kRegValue and against the last
 * component of kRegKey - never as a loose substring, which would fire on
 * neighbouring values such as PATHEXT or PSModulePath. */
bool NamesPathValue(const std::string& lowerKey,
                    const std::string& lowerValue) {
    if (!Contains(lowerKey, "environment")) return false;
    return lowerValue == "path" || LastKeyComponent(lowerKey) == "path";
}

} // namespace

PathInterceptionDetector::PathInterceptionDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool PathInterceptionDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool PathInterceptionDetector::Analyze(const std::string& lower,
                                       Finding* out) const {
    /* A bare PowerShell assignment is the classic prepend and carries no
     * verb from kPathWriteVerbs:  $env:Path = "C:\temp;$env:Path".
     * Only whitespace may sit between the variable and the '='; an
     * equality comparison (-eq) or a later unrelated '=' on the same line
     * must not count (same shape as the timestomp heuristic). */
    const bool envAssign = [&lower]() {
        static const char* const kVars[] = {"$env:path", "%path%"};
        for (const char* var : kVars) {
            size_t pos = 0;
            const size_t varLen = std::strlen(var);
            while ((pos = lower.find(var, pos)) != std::string::npos) {
                size_t j = pos + varLen;
                while (j < lower.size() &&
                       (lower[j] == ' ' || lower[j] == '\t'))
                    ++j;
                if (j < lower.size() && lower[j] == '=' &&
                    (j + 1 >= lower.size() || lower[j + 1] != '='))
                    return true;
                pos += varLen;
            }
        }
        return false;
    }();

    /* Read-only PATH display stays silent. */
    if (!envAssign &&
        (Contains(lower, "echo %path%") ||
         Contains(lower, "get-childitem") ||
         Contains(lower, "$env:path")) &&
        !ContainsAny(lower, kPathWriteVerbs,
                     sizeof(kPathWriteVerbs) /
                     sizeof(kPathWriteVerbs[0])))
        return false;

    const bool pathTarget =
        Contains(lower, "path") &&
        Contains(lower, "environment");
    const bool regAddPath = Contains(lower, "reg add") &&
                            Contains(lower, "/v path");

    if (regAddPath && HasWritableDir(lower)) {
        *out = Finding{90, "machine PATH persisted to user-writable "
                           "directory"};
        return true;
    }
    if (regAddPath) {
        *out = Finding{70, "PATH registry value modified"};
        return true;
    }

    const bool psSetPath =
        Contains(lower, "setenvironmentvariable(\"path\"") ||
        Contains(lower, "setenvironmentvariable('path'") ||
        (Contains(lower, "set-itemproperty") &&
         Contains(lower, "\"path\""));
    if (psSetPath && HasWritableDir(lower)) {
        *out = Finding{85, "PATH redirected via PowerShell to "
                           "user-writable directory"};
        return true;
    }

    if (Contains(lower, "setx path") || Contains(lower, "setx \"path\"")) {
        if (HasWritableDir(lower)) {
            *out = Finding{85, "setx PATH pointing at user-writable "
                               "directory"};
            return true;
        }
        *out = Finding{65, "setx PATH rewritten"};
        return true;
    }

    /* In-process PATH prepend: only actionable when the injected entry is
     * a user-writable directory, otherwise it is ordinary shell setup. */
    if (envAssign && HasWritableDir(lower)) {
        *out = Finding{80, "PATH prepended with user-writable directory"};
        return true;
    }

    if (pathTarget && HasWritableDir(lower)) {
        *out = Finding{70, "script-plane PATH prepend of writable "
                           "directory"};
        return true;
    }

    return false;
}

void PathInterceptionDetector::Stamp(Event& event, const Finding& finding,
                                     const std::string& key) {
    event.fields[field::kPathInterceptScore] =
        std::to_string(finding.score);
    event.fields[field::kPathInterceptVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kPathInterceptSignals] = finding.signal;
    event.fields[field::kPathInterceptText] = key;
}

void PathInterceptionDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;

    /* Registry plane: direct writes to the Environment Path value. */
    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        const std::string lowerKey = ToLowerAscii(keyIt->second);
        std::string lowerValue;
        auto valIt = event.fields.find(field::kRegValue);
        if (valIt != event.fields.end())
            lowerValue = ToLowerAscii(valIt->second);
        if (!NamesPathValue(lowerKey, lowerValue)) return;

        /* Only the snapshot shape carries the new data in kRegValue; in
         * the bare shape kRegValue is the value name, so scanning both
         * for a writable directory is safe either way. */
        const std::string haystack = lowerKey + " " + lowerValue;
        Finding finding;
        const bool writable = HasWritableDir(haystack);
        finding.score = writable ? 90u : 75u;
        finding.signal = writable
            ? "Environment PATH persisted to user-writable directory"
            : "Environment PATH registry value modified";
        if (finding.score < m_minScore) return;
        StampDeduped(event, finding, haystack.substr(0, 160));
        return;
    }

    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    StampDeduped(event, finding, lower.substr(0, 160));
}

/* Shared dedup + stamp tail for every plane: a repeated key inside the
 * dedup window is dropped, so a polling registry collector that
 * re-reports the same value cannot re-alert. */
void PathInterceptionDetector::StampDeduped(Event& event,
                                            const Finding& finding,
                                            const std::string& key) {
    const uint64_t now = event.ts100ns;
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
                "[edr-path-intercept] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
