/*
 * surveillance_detector.cpp - See surveillance_detector.h.
 */
#include "surveillance_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    if (map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& left, const auto& right) {
            return left.second.lastSeen100ns < right.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

} // namespace

SurveillanceDetector::SurveillanceDetector(bool enabled,
                                           uint32_t windowSeconds,
                                           size_t stateCapacity,
                                           uint32_t minSignals)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minSignals(std::max<uint32_t>(1, minSignals)) {}

bool SurveillanceDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_CLIPBOARD_ACCESS || type == EDR_EVT_KEYLOGGER ||
           type == EDR_EVT_WALLPAPER_CHANGE || type == EDR_EVT_CAMERA_ACCESS;
}

std::string SurveillanceDetector::SignalName(uint16_t type) const {
    switch (type) {
    case EDR_EVT_CLIPBOARD_ACCESS:
        return "clipboard_access";
    case EDR_EVT_KEYLOGGER:
        return "keylogger";
    case EDR_EVT_WALLPAPER_CHANGE:
        return "wallpaper_change";
    case EDR_EVT_CAMERA_ACCESS:
        return "camera_access";
    default:
        return "";
    }
}

std::string SurveillanceDetector::KnownTool(const std::string& raw) const {
    const std::string base = BaseName(raw);
    static const char* const kToolTokens[] = {
        "keylogger", "spyrix",   "refog",  "arctitan", "revealer",
        "screenspy", "spytech",  "spytector", "mspy",   "flexispy",
    };
    for (const char* token : kToolTokens) {
        if (base.find(token) != std::string::npos) return token;
    }
    return "";
}

void SurveillanceDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_processes.begin(); it != m_processes.end();) {
        ProcState& state = it->second;
        for (auto sig = state.signals.begin(); sig != state.signals.end();) {
            if (now100ns >= sig->second &&
                now100ns - sig->second > m_window100ns) {
                sig = state.signals.erase(sig);
            } else {
                ++sig;
            }
        }
        if (state.signals.empty() && state.toolName.empty()) {
            it = m_processes.erase(it);
        } else {
            ++it;
        }
    }
}

void SurveillanceDetector::WriteState(Event& event,
                                      const ProcState& state) const {
    std::vector<std::string> signals;
    for (const auto& entry : state.signals) signals.push_back(entry.first);
    std::sort(signals.begin(), signals.end());

    std::string joined;
    for (const std::string& signal : signals) {
        if (!joined.empty()) joined += ",";
        joined += signal;
    }
    if (!state.toolName.empty()) {
        if (!joined.empty()) joined += ",";
        joined += "known_tool:" + state.toolName;
    }

    const uint32_t count = static_cast<uint32_t>(signals.size());
    uint32_t score = 0;
    if (!state.toolName.empty()) {
        score = 80;
    } else {
        score = std::min(100u, 40u + 30u * (count - 1u));
    }
    const std::string verdict = Verdict(score);

    event.fields[field::kSurveillanceScore] = std::to_string(score);
    event.fields[field::kSurveillanceCount] = std::to_string(count);
    event.fields[field::kSurveillanceSignals] = joined;
    event.fields[field::kSurveillanceWindowSeconds] =
        std::to_string(m_windowSeconds);
    if (!verdict.empty()) event.fields[field::kSurveillanceVerdict] = verdict;
}

void SurveillanceDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const std::string signal = SignalName(event.type);
    if (signal.empty()) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string tool = KnownTool(FieldValue(event, field::kImage));
    if (event.pid == 0) {
        /* No process attribution: only a known tool name can be flagged. */
        if (tool.empty()) return;
        ProcState transient;
        transient.lastSeen100ns = now;
        transient.toolName = tool;
        WriteState(event, transient);
        return;
    }

    ProcState& state = m_processes[event.pid];
    state.lastSeen100ns = now;

    const bool isNewSignal = state.signals.count(signal) == 0;
    state.signals[signal] = now;
    const bool isNewTool = tool.empty() ? false : state.toolName.empty();
    if (!tool.empty()) state.toolName = tool;

    /* Only stamp when the signal set actually grows (or the tool is first
     * seen), so a long surveillance session does not re-alert on every
     * clipboard event. */
    if (!isNewSignal && !isNewTool) return;

    const uint32_t count = static_cast<uint32_t>(state.signals.size());
    if (state.toolName.empty() && count < m_minSignals) return;

    WriteState(event, state);
    EvictOldest(m_processes, m_stateCapacity);
}

} // namespace edr
