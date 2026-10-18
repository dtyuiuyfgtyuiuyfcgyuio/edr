/*
 * lsass_dump_detector.cpp - One-liner LSASS memory dump (T1003.001).
 */
#include "lsass_dump_detector.h"

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

/* True when the command text references the LSASS process as a target:
 * "lsass" token (lsass.exe, lsass, pid-of-lsass helpers). */
bool ReferencesLsass(const std::string& lower) {
    return Contains(lower, "lsass");
}

} // namespace

LsassDumpDetector::LsassDumpDetector(bool enabled, uint32_t minScore,
                                     uint32_t dedupWindowSeconds,
                                     size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool LsassDumpDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool LsassDumpDetector::Analyze(const std::string& lower,
                                Finding* out) const {
    /* Unambiguous credential-dump tool tokens: these binaries/scripts
     * have no benign use on workstations. Score alone. */
    static const char* const kToolTokens[] = {
        "mimikatz", "nanodump", "secretsdump", "pypykatz", "lsassy",
        "hashdump", "gsecdump", "lazagne", "sharpdump", "safetydump",
        "handlekatz",
    };
    for (const char* token : kToolTokens) {
        if (!Contains(lower, token)) continue;
        *out = Finding{90, "credential dump tool token"};
        return true;
    }

    /* rundll32 comsvcs.dll,#MiniDump / MiniDump export call: the
     * canonical one-liner. The ordinal/name form is
     *   rundll32.exe C:\...\comsvcs.dll, MiniDump <pid> out.dmp full
     * Require both comsvcs and minidump tokens - each alone is not a
     * dump (comsvcs loads for COM+, MiniDumpW is exported elsewhere). */
    if (Contains(lower, "comsvcs") && Contains(lower, "minidump")) {
        *out = Finding{90, "comsvcs MiniDump one-liner"};
        return true;
    }

    /* Sysinternals/other procdump against LSASS. procdump alone dumps
     * arbitrary processes (benchmarks etc.), so require an lsass
     * reference in the same command. */
    if ((Contains(lower, "procdump") || Contains(lower, "procump")) &&
        ReferencesLsass(lower)) {
        *out = Finding{85, "procdump targeting lsass"};
        return true;
    }

    /* PowerShell .Dump() on Get-Process lsass:
     *   Get-Process lsass | % { $_.Dump() }  /  [System.Diagnostics.Process]... */
    if (ReferencesLsass(lower) &&
        (Contains(lower, ".dump(") || Contains(lower, ".dump ()") ||
         Contains(lower, "minifydump") || Contains(lower, "mini_dump") ||
         Contains(lower, "-mm ") && Contains(lower, "rundll32"))) {
        *out = Finding{80, "process dump api against lsass"};
        return true;
    }

    /* Dump path naming convention. An lsass-named *.dmp appearing in a
     * non-file-operation command is the dump being produced (custom
     * dumper writing its output). Pure file operations against an
     * existing dump (copy/move/dir/...) are downstream handling of a
     * dump that already happened - still reportable, but not the dump
     * act itself, so they stay under the malicious band. */
    if (ReferencesLsass(lower) && Contains(lower, ".dmp")) {
        static const char* const kRefVerbs[] = {
            "copy", "move", "rename", "del ", "erase ", "type ",
            "more ", "dir ", "gci ", "get-childitem", "get-item",
            "remove-item", "cat ",
        };
        bool pureReference = false;
        for (const char* verb : kRefVerbs) {
            if (!Contains(lower, verb)) continue;
            pureReference = true;
            break;
        }
        *out = Finding{pureReference ? 60u : 80u,
                       pureReference ? "lsass-named dump file referenced"
                                     : "lsass-named dump file written"};
        return true;
    }
    return false;
}

void LsassDumpDetector::Stamp(Event& event, const Finding& finding,
                              const std::string& key) {
    event.fields[field::kLsassDumpScore] = std::to_string(finding.score);
    event.fields[field::kLsassDumpVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kLsassDumpSignals] = finding.signal;
    event.fields[field::kLsassDumpCommand] = key;
}

void LsassDumpDetector::Enrich(Event& event) {
    if (!m_enabled) return;

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

    Finding finding;
    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    /* Dedup per normalized command prefix. */
    const std::string key = lower.substr(0, 160);
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
                "[edr-lsass-dump] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
