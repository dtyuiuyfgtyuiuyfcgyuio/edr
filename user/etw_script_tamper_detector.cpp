/*
 * etw_script_tamper_detector.cpp - Script-plane ETW impairment
 * (T1562.001).
 */
#include "etw_script_tamper_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (Contains(value, needle)) return true;
    }
    return false;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* Telemetry-ish trace session names an attacker would target with
 * logman stop/delete. Generic "logman stop mysession" never fires. */
bool NamesTelemetrySession(const std::string& lower) {
    static const char* const kSessions[] = {
        "sysmon", "powershell", "defender", "windefend", "amsi",
        "seclogon", "smbclient", "wmi-etw", "dns-etw", "autologger",
        "kernel-etw", "nt-kernel",
    };
    for (const char* session : kSessions) {
        if (Contains(lower, session)) return true;
    }
    return false;
}

} // namespace

EtwScriptTamperDetector::EtwScriptTamperDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool EtwScriptTamperDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool EtwScriptTamperDetector::Analyze(const std::string& lower,
                                      Finding* out) const {
    /* The classic PowerShell telemetry strip: reflect the PowerShell
     * ETW provider type and unregister its event providers. Referencing
     * PSEtwLogProvider has no benign operator use. */
    if (Contains(lower, "psetwlogprovider")) {
        if (ContainsAny(lower, {"get_eventproviders", "eventproviders",
                                "unregister", "remove-", "stop-"})) {
            *out = Finding{85, "PowerShell ETW provider strip"};
        } else {
            *out = Finding{70, "PSEtwLogProvider referenced"};
        }
        return true;
    }

    /* In-script EtwEventWrite patch: the bypass act needs both the
     * target and a memory-write primitive. A bare mention stays under
     * the malicious band (write-up/tooling reference, like lsass_dump's
     * referenced-vs-written split). */
    if (Contains(lower, "etweventwrite")) {
        if (ContainsAny(lower, {"virtualprotect", "writeprocessmemory",
                                "memcpy", "copy", "patch", "jmp",
                                "hook"})) {
            *out = Finding{90, "EtwEventWrite patch in script"};
        } else {
            *out = Finding{60, "EtwEventWrite referenced"};
        }
        return true;
    }

    /* Trace-session lifecycle cmdlets. Stopping/removing a trace
     * session is administrative but session-targeted; score alone. */
    if (ContainsAny(lower, {"stop-etwtracesession",
                            "remove-etwtracesession",
                            "set-etwtrafficpolicy"})) {
        *out = Finding{80, "ETW trace session stopped via cmdlet"};
        return true;
    }

    /* logman stop/delete naming a telemetry session. logman against an
     * arbitrary user session (perf capture etc.) never fires. */
    if ((Contains(lower, "logman stop") ||
         Contains(lower, "logman delete")) &&
        NamesTelemetrySession(lower)) {
        *out = Finding{75, "telemetry trace session via logman"};
        return true;
    }

    /* Autologger start-key disable: keeps telemetry sessions from
     * coming back after reboot. Requires the autologger key path plus
     * a registry write primitive on the Start value. */
    if (Contains(lower, "autologger") && Contains(lower, "start") &&
        ContainsAny(lower, {"reg add", "reg.exe add", "set-itemproperty",
                            "new-itemproperty", "SetValue"})) {
        *out = Finding{70, "ETW autologger start disabled"};
        return true;
    }

    /* wevtutil channel disable: /e:false flips an event channel off -
     * complements audit_log_tamper which covers clear-log only. */
    if (Contains(lower, "wevtutil") && Contains(lower, "/e:false")) {
        *out = Finding{70, "event channel disabled via wevtutil"};
        return true;
    }

    return false;
}

void EtwScriptTamperDetector::Stamp(Event& event, const Finding& finding,
                                    const std::string& key) {
    event.fields[field::kEtwScriptScore] = std::to_string(finding.score);
    event.fields[field::kEtwScriptVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kEtwScriptSignals] = finding.signal;
    event.fields[field::kEtwScriptText] = key;
}

void EtwScriptTamperDetector::Enrich(Event& event) {
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

    /* Dedup per normalized text prefix. */
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
                "[edr-etw-script] state capacity %zu reached;"
                " dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
