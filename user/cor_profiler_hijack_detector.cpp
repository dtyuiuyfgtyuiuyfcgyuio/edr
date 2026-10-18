/*
 * cor_profiler_hijack_detector.cpp - .NET profiler hijack detector
 * (T1574.012 COR_PROFILER).
 */
#include "cor_profiler_hijack_detector.h"

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

CorProfilerHijackDetector::CorProfilerHijackDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool CorProfilerHijackDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool CorProfilerHijackDetector::Analyze(const std::string& lower,
                                        bool registryPlane,
                                        Finding* out) const {
    /* Pure removal of the variables never scores (cleanup / hardening).
     * Note [Environment]::SetEnvironmentVariable("COR_...","1") is a
     * write and MUST be scored, so only explicit delete verbs are
     * excluded here. */
    const bool deleteVerb = Contains(lower, "reg delete") ||
                            Contains(lower, "remove-itemproperty") ||
                            Contains(lower, "remove-item ");
    const bool profilerName =
        Contains(lower, "cor_profiler") ||
        Contains(lower, "coreclr_profiler");
    if (deleteVerb && profilerName) return false;

    const bool namesProfiler = profilerName;
    const bool armsProfiler =
        Contains(lower, "cor_enable_profiling") ||
        Contains(lower, "coreclr_enable_profiling");
    const bool profilerPath = Contains(lower, "cor_profiler_path") ||
                              Contains(lower, "coreclr_profiler_path");
    if (!namesProfiler && !armsProfiler && !profilerPath) return false;

    /* On the registry plane the value write itself is the hijack. */
    if (registryPlane) {
        *out = Finding{90, "profiler environment variable written"};
        return true;
    }

    /* The command plane: value matters (arming = 1). */
    const bool armedToOne =
        Contains(lower, "=1") || Contains(lower, "= 1") ||
        Contains(lower, "/d 1") || Contains(lower, "-value 1") ||
        Contains(lower, "'1'") || Contains(lower, "\"1\"") ||
        /* setx COR_ENABLE_PROFILING 1 (value as trailing token). */
        Contains(lower, "profiling 1");
    /* A CLSID argument looks like {...} with a hex tail. */
    const bool clsidShape = Contains(lower, "{") && Contains(lower, "}");

    if (namesProfiler && clsidShape && armedToOne) {
        *out = Finding{95, "profiler armed and named"};
        return true;
    }
    if (namesProfiler && clsidShape) {
        *out = Finding{90, "profiler clsid injected"};
        return true;
    }
    if (namesProfiler && armedToOne) {
        *out = Finding{90, "profiler armed and named"};
        return true;
    }
    if (namesProfiler) {
        *out = Finding{85, "profiler environment variable set"};
        return true;
    }
    if (profilerPath) {
        *out = Finding{85, "profiler path pointed at dll"};
        return true;
    }
    /* `reg add` persisting the enable flag machine-wide is the full
     * hijack (same weight as the registry plane); plain setx arming
     * stays at 80. */
    if (armsProfiler && armedToOne && Contains(lower, "reg add")) {
        *out = Finding{90, "profiler loading armed via reg add"};
        return true;
    }
    if (armsProfiler && armedToOne) {
        *out = Finding{80, "profiler loading armed"};
        return true;
    }
    /* Mention without arming values - low signal, below min anyway. */
    return false;
}

void CorProfilerHijackDetector::Stamp(Event& event, const Finding& finding,
                                      const std::string& key) {
    event.fields[field::kCorProfilerHijackScore] =
        std::to_string(finding.score);
    event.fields[field::kCorProfilerHijackVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kCorProfilerHijackSignals] = finding.signal;
    event.fields[field::kCorProfilerHijackCommand] = key;
}

void CorProfilerHijackDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    bool registryPlane = false;
    if (event.type == EDR_EVT_REG_WRITE) {
        /* Compose the registry text from key + value (driver shape) or
         * the full key path (snapshot shape appends the value name). */
        auto keyIt = event.fields.find(field::kRegKey);
        auto valIt = event.fields.find(field::kRegValue);
        if (keyIt != event.fields.end()) text = keyIt->second;
        if (valIt != event.fields.end()) {
            if (!text.empty()) text += " ";
            text += valIt->second;
        }
        registryPlane = true;
    } else {
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
    }
    if (text.empty()) return;
    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!Analyze(lower, registryPlane, &finding)) return;
    if (finding.score < m_minScore) return;

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
                "[edr-cor-profiler] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
