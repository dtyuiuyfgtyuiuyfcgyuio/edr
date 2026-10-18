/*
 * input_simulation_detector.cpp - See input_simulation_detector.h.
 */
#include "input_simulation_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>

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

InputSimulationDetector::InputSimulationDetector(bool enabled,
                                                 uint32_t windowSeconds,
                                                 size_t stateCapacity,
                                                 uint32_t burstThreshold)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_burstThreshold(std::max<uint32_t>(1, burstThreshold)) {}

bool InputSimulationDetector::IsSystemProcess(const std::string& image) {
    static const char* kBenign[] = {
        "svchost.exe", "csrss.exe", "dwm.exe", "winlogon.exe",
        "explorer.exe", "ctfmon.exe", "searchapp.exe", "shellexperiencehost.exe",
        "textinputhost.exe", "runtimebroker.exe", "applicationframehost.exe",
        "msrdc.exe", "mstsc.exe", "rdpinput.exe"
    };
    const std::string lower = LowerAscii(image);
    for (const char* benign : kBenign) {
        const size_t n = std::strlen(benign);
        const size_t pos = lower.rfind(benign);
        if (pos == std::string::npos) continue;
        if (pos + n == lower.size() &&
            (pos == 0 || lower[pos - 1] == '\\' || lower[pos - 1] == '/')) {
            return true;
        }
    }
    return false;
}

void InputSimulationDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_procs.erase(it);
        else
            ++it;
    }
}

uint32_t InputSimulationDetector::ComputeScore(const ProcState& state,
                                               bool systemProcess) const {
    uint32_t score = 0;
    if (!systemProcess) score += 40;
    if (state.eventCount >= m_burstThreshold) score += 30;
    return std::min(100u, score);
}

std::string InputSimulationDetector::SignalList(const ProcState& state,
                                                bool systemProcess) const {
    std::string signals;
    if (!systemProcess) signals = "non_system_injector";
    if (state.eventCount >= m_burstThreshold) {
        if (!signals.empty()) signals += ",";
        signals += "injection_burst";
    }
    return signals;
}

void InputSimulationDetector::WriteState(Event& event,
                                         const ProcState& state,
                                         bool systemProcess) {
    const uint32_t score = ComputeScore(state, systemProcess);
    event.fields[field::kInputSimScore] = std::to_string(score);
    event.fields[field::kInputSimSignals] =
        SignalList(state, systemProcess);
    event.fields[field::kInputSimEventCount] =
        std::to_string(state.eventCount);
    event.fields[field::kInputSimWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kInputSimVerdict] = verdict;
    }
}

void InputSimulationDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const uint32_t pid = event.pid;
    if (pid == 0) return;

    ProcState& state = m_procs[pid];
    ++state.eventCount;
    state.lastSeen100ns = now;

    const bool systemProcess =
        IsSystemProcess(FieldValue(event, field::kImage));

    WriteState(event, state, systemProcess);
    EvictOldest(m_procs, m_stateCapacity);
}

} // namespace edr
