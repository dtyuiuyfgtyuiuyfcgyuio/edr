/*
 * amsi_bypass_detector.cpp - AMSI bypass (T1562.001), graded.
 */
#include "amsi_bypass_detector.h"

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

} // namespace

AmsiBypassDetector::AmsiBypassDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool AmsiBypassDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool AmsiBypassDetector::Analyze(const std::string& lower,
                                 Finding* out) const {
    /* The canonical flag patch: flip amsiInitFailed through reflection
     * so every later scan short-circuits (the bypass sets it truthy).
     * The reflective field-write separates the act from documentation
     * that merely mentions the field name. */
    if (Contains(lower, "amsiinitfailed")) {
        if (ContainsAny(lower, {"setvalue", "setfield",
                                ".getfield(", "invoke("})) {
            *out = Finding{90, "AmsiInitFailed flag patched"};
        } else {
            *out = Finding{60, "AmsiInitFailed referenced"};
        }
        return true;
    }

    /* In-memory stub patch of amsi.dll / AmsiScanBuffer: needs the API
     * surface plus a memory-write primitive. Bare API references stay
     * in the reference band. */
    if (Contains(lower, "amsiscanbuffer") ||
        Contains(lower, "amsi.dll")) {
        if (ContainsAny(lower, {"virtualprotect", "writeprocessmemory",
                                "virtualprotectex", "memcpy",
                                "marshal.copy", "patch"})) {
            *out = Finding{85, "AMSI buffer stub patched"};
        } else {
            *out = Finding{60, "AMSI scan API referenced"};
        }
        return true;
    }

    /* Well-known bypass helpers invoked by name. */
    if (ContainsAny(lower, {"disable-amsi ", "disable-amsi;",
                            "bypass-amsi", "break-amsi",
                            "patch-amsi", "amsi-patch", "-amsibypass"})) {
        *out = Finding{80, "AMSI bypass helper invoked"};
        return true;
    }

    /* Reflection prep against the internal AmsiUtils type - the setup
     * step of the flag patch above. */
    if (Contains(lower, "amsiutils") &&
        Contains(lower, ".gettype(")) {
        *out = Finding{75, "AmsiUtils type reflection"};
        return true;
    }

    return false;
}

void AmsiBypassDetector::Stamp(Event& event, const Finding& finding,
                               const std::string& key) {
    event.fields[field::kAmsiBypassScore] = std::to_string(finding.score);
    event.fields[field::kAmsiBypassVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kAmsiBypassSignals] = finding.signal;
    event.fields[field::kAmsiBypassText] = key;
}

void AmsiBypassDetector::Enrich(Event& event) {
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
                "[edr-amsi-bypass] state capacity %zu reached;"
                " dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
