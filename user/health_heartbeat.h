/*
 * health_heartbeat.h - Agent self-monitoring heartbeat.
 *
 * Periodically samples agent internals and reports one line per tick:
 *   - uptime in seconds
 *   - event bus pending depth and cumulative dropped count
 *   - optional alert/event HTTP reporter queue depths and cumulative dropped counts
 * A drop counter that keeps growing between ticks means the consumer
 * side cannot keep up with telemetry volume; this makes the condition
 * observable from stderr / syslog without touching the detection path.
 *
 * Reporting sinks: one stderr line (always) plus an optional
 * SyslogForwarder enqueue (info severity, rule id "HEALTH"). The
 * heartbeat is pure observability - it never pushes events into the
 * bus and never participates in scoring.
 *
 * Thread-safety: own worker thread; Start/Stop are not thread-safe
 * against each other (same contract as the collectors).
 */
#ifndef EDR_HEALTH_HEARTBEAT_H
#define EDR_HEALTH_HEARTBEAT_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace edr {

class EventBus;
class Reporter;
class SyslogForwarder;
class ICollector;

struct HealthComponent {
    std::string name;
    std::string state;
    bool countersAvailable = false;
    std::string lastSuccess100ns;
    std::string replayState;
    std::map<std::string, uint64_t> counters;
};

HealthComponent SampleCollectorHealth(const std::string& name,
                                      const ICollector* collector);

class HealthHeartbeat {
public:
    using DiagnosticsFn = std::function<std::vector<HealthComponent>()>;
    HealthHeartbeat(uint32_t pollSeconds, const EventBus* bus,
                    SyslogForwarder* syslog,
                    std::string collectorsSummary,
                    const Reporter* reporter = nullptr,
                    const Reporter* eventReporter = nullptr,
                    DiagnosticsFn diagnostics = {});

    ~HealthHeartbeat();

    bool Start();
    void Stop();
    /* Read-only sample; callback exceptions produce unavailable diagnostics. */
    std::string Snapshot(uint64_t uptimeSeconds = 0) const;

private:
    void Run();

    uint32_t m_pollMs;
    const EventBus* m_bus;
    SyslogForwarder* m_syslog;
    std::string m_collectorsSummary;
    const Reporter* m_reporter;
    const Reporter* m_eventReporter;
    DiagnosticsFn m_diagnostics;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
};

} // namespace edr

#endif /* EDR_HEALTH_HEARTBEAT_H */
