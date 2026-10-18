/*
 * canary_detector.cpp - Canary (honeypot) file interaction scoring.
 */
#include "canary_detector.h"

#include <cstdio>

namespace edr {

namespace {

bool GetField(const Event& event, const char* name, std::string* out) {
    auto it = event.fields.find(name);
    if (it == event.fields.end()) return false;
    *out = it->second;
    return true;
}

} // namespace

CanaryDetector::CanaryDetector(bool enabled, uint32_t dedupWindowSeconds,
                               size_t stateCapacity)
    : m_enabled(enabled),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool CanaryDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_FILE_INTEGRITY;
}

void CanaryDetector::Stamp(Event& event, uint32_t score,
                           const std::string& path) {
    event.fields[field::kCanaryScore] = std::to_string(score);
    /* >=75 MALICIOUS / >=55 SUSPICIOUS; below 55 no verdict is written
     * (house convention shared with the security-log detector family). */
    event.fields[field::kCanaryVerdict] =
        score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kCanaryPath] = path;
}

void CanaryDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string flag;
    if (!GetField(event, field::kCanaryFlag, &flag) || flag != "true")
        return;

    std::string action;
    if (!GetField(event, field::kFimAction, &action)) return;

    uint32_t score = 0;
    const char* reason = nullptr;
    if (action == "accessed") {
        score = 60;
        reason = "canary file accessed";
    } else if (action == "modified") {
        score = 80;
        reason = "canary file modified or replaced";
    } else if (action == "removed") {
        score = 90;
        reason = "canary file deleted";
    } else {
        /* "added" and unknown actions carry no attacker signal. */
        return;
    }

    std::string path;
    GetField(event, field::kFimPath, &path);

    const uint64_t now = event.ts100ns;
    auto it = m_lastAlert.find(path);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns) {
            return; /* same canary already alerted inside the window */
        }
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear(); /* coarse bound: reset tracking state */
            std::fprintf(stderr,
                "[edr-canary] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(path, now);
    }

    Stamp(event, score, path);
    event.fields[field::kCanaryReasons] = reason;
}

} // namespace edr
