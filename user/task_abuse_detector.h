/*
 * task_abuse_detector.h - Scheduled task abuse detector (T1053.005).
 *
 * Scores TASK_SCHEDULER events (106 register / 140 update / 141 delete)
 * from the TaskScheduler Operational log. Event 106 does not carry the
 * task definition XML, so v1 heuristics key on what the log reliably
 * provides - the task name and user context:
 *   - RTLO (U+202E) character inside the task name          -> 75
 *   - double-extension task name ("invoice.pdf.exe")        -> 75
 *   - interpreter keyword or user-writable path fragment
 *     embedded in the task name                              -> 70
 *   - opaque GUID-only task name registration               -> 55
 *   - mass TASK_DELETED burst for one user context
 *     (cleanup anti-forensics)                               -> 60
 *
 * Alerts are deduplicated per task name inside the dedup window; delete
 * bursts are counted per user context over a sliding window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_TASK_ABUSE_DETECTOR_H
#define EDR_TASK_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class TaskAbuseDetector {
public:
    struct Settings {
        bool enabled = false;
        uint32_t minScore = 55;
        uint32_t dedupWindowSeconds = 300;
        size_t stateCapacity = 1024;
        uint32_t deleteBurstThreshold = 5;      /* deletes per window */
        uint32_t deleteBurstWindowSeconds = 60;
    };

    explicit TaskAbuseDetector(const Settings& settings);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool AnalyzeName(const std::string& lowerName, Finding* out) const;
    bool AnalyzeDeleteBurst(const std::string& userContext,
                            uint64_t now100ns, Finding* out);
    void Stamp(Event& event, const Finding& finding,
               const std::string& taskKey);

    Settings m_settings;
    uint64_t m_dedupWindow100ns;
    uint64_t m_burstWindow100ns;

    /* task key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;
    /* user context -> timestamps of recent TASK_DELETED events. */
    std::unordered_map<std::string, std::deque<uint64_t>> m_deleteTimes;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_TASK_ABUSE_DETECTOR_H */
