/*
 * timestomp_detector.cpp - File timestamp tampering (T1070.006).
 */
#include "timestomp_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

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

} // namespace

TimestompDetector::TimestompDetector(bool enabled, uint32_t minScore,
                                     uint32_t dedupWindowSeconds,
                                     size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool TimestompDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_FILE_INTEGRITY;
}

bool TimestompDetector::AnalyzeSysmonFileTime(const Event& event,
                                              Finding* out,
                                              std::string* key) const {
    if (event.type != EDR_EVT_FILE_INTEGRITY) return false;
    auto id = event.fields.find(field::kSysmonEventId);
    auto path = event.fields.find(field::kFilePath);
    auto current = event.fields.find(field::kFileCreationTime);
    auto previous = event.fields.find(field::kFilePreviousCreationTime);
    if (id == event.fields.end() || id->second != "2" ||
        path == event.fields.end() || path->second.empty() ||
        current == event.fields.end() || current->second.empty() ||
        previous == event.fields.end() || previous->second.empty() ||
        current->second == previous->second) return false;

    *out = Finding{95, "Sysmon file creation time changed"};
    *key = ToLowerAscii(path->second).substr(0, 260);
    return true;
}

bool TimestompDetector::Analyze(const std::string& lower,
                                Finding* out) const {
    /* Dedicated timestomping tools. The canonical tool is timestomp.exe
     * (Meterpreter): match the basename so any path prefix hits. Also
     * accept the extension-less Meterpreter spelling ("timestomp C:\f
     * M 12 ...") via a boundary-checked token - a preceding path
     * separator / quote / operator or command position 0, always
     * followed by whitespace, so prose like "timestomping" never hits. */
    if (Contains(lower, "timestomp.exe") ||
        Contains(lower, "\\timestomp ") ||
        Contains(lower, "/timestomp ") ||
        Contains(lower, "\"timestomp ") ||
        lower.compare(0, 10, "timestomp ") == 0) {
        *out = Finding{85, "dedicated timestomp tool invoked"};
        return true;
    }

    /* PowerShell property assignment: (Get-Item f).LastWriteTime = ...,
     * $f.CreationTime = ... . Assignment shape only: between the end of
     * the property name and '=' whitespace is allowed and nothing else
     * (optionally a closing ']' for member-access-on-index-expression),
     * so pipelines like "gci | % { $_.lastwritetime }" or an unrelated
     * later assignment on the same line never hit. */
    static const char* const kTimeProps[] = {
        ".lastwritetime", ".creationtime", ".lastaccesstime",
        ".creationtimeutc", ".lastwritetimeutc"
    };
    const auto IsAssignEq = [&lower](size_t pos) {
        while (pos < lower.size() &&
               (lower[pos] == ' ' || lower[pos] == '\t' ||
                lower[pos] == ']'))
            ++pos;
        return pos < lower.size() && lower[pos] == '=';
    };
    for (const char* prop : kTimeProps) {
        size_t pos = lower.find(prop);
        while (pos != std::string::npos) {
            if (IsAssignEq(pos + std::strlen(prop))) {
                *out = Finding{70, "file timestamp property assignment"};
                return true;
            }
            pos = lower.find(prop, pos + 1);
        }
    }

    /* .NET static setters: [IO.File]::SetLastWriteTime(path, time),
     * [System.IO.File]::SetCreationTime, SetLastAccessTime,
    *  SetCreationTimeUtc etc. */
    if (Contains(lower, "io.file]::set") ||
        Contains(lower, "system.io.file]::set")) {
        if (Contains(lower, "setlastwritetime") ||
            Contains(lower, "setcreationtime") ||
            Contains(lower, "setlastaccesstime")) {
            *out = Finding{70, ".NET file time setter invoked"};
            return true;
        }
    }
    return false;
}

void TimestompDetector::Stamp(Event& event, const Finding& finding,
                              const std::string& key) {
    event.fields[field::kTimestompScore] = std::to_string(finding.score);
    event.fields[field::kTimestompVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kTimestompSignals] = finding.signal;
    event.fields[field::kTimestompCommand] = key;
}

void TimestompDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    std::string key;
    if (AnalyzeSysmonFileTime(event, &finding, &key)) {
        if (finding.score < m_minScore) return;
    } else {
        if (event.type == EDR_EVT_FILE_INTEGRITY) return;
        std::string text;
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            /* Script blocks carry the body in kScriptBlockText, never
             * kCommandLine/kImage. */
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
        if (text.empty()) {
            auto imgIt = event.fields.find(field::kImage);
            if (imgIt == event.fields.end()) return;
            text = imgIt->second;
        }
        const std::string lower = ToLowerAscii(text);
        if (!Analyze(lower, &finding)) return;
        if (finding.score < m_minScore) return;
        key = lower.substr(0, 160);
    }

    /* Dedup per normalized command prefix or target path. */
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
                "[edr-timestomp] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
