/*
 * health_heartbeat.cpp - Agent self-monitoring heartbeat.
 */
#include "health_heartbeat.h"

#include <windows.h>

#include <cstdio>
#include <ctime>
#include <algorithm>

#include "event_bus.h"
#include "reporter.h"
#include "syslog_forwarder.h"
#include "json_lite.h"
#include "collector.h"

namespace edr {

namespace {

std::string IsoTimestamp() {
    FILETIME ft = {};
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER ticks;
    ticks.LowPart = ft.dwLowDateTime;
    ticks.HighPart = ft.dwHighDateTime;
    const time_t unixSeconds =
        static_cast<time_t>((ticks.QuadPart - 116444736000000000ULL) /
                            10000000ULL);
    struct tm tmUtc = {};
    gmtime_s(&tmUtc, &unixSeconds);
    char buffer[32] = {};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tmUtc);
    return buffer;
}

std::string BoundedValidUtf8(const std::string& value) {
    size_t sourceEnd = std::min<size_t>(value.size(), 4096);
    if (sourceEnd < value.size()) {
        while (sourceEnd &&
               (static_cast<unsigned char>(value[sourceEnd]) & 0xc0) == 0x80) {
            --sourceEnd;
        }
    }
    if (!sourceEnd) return {};

    const int sourceBytes = static_cast<int>(sourceEnd);
    const int wideLength = MultiByteToWideChar(CP_UTF8, 0, value.data(),
        sourceBytes, nullptr, 0);
    if (wideLength <= 0) return {};
    std::wstring wide(static_cast<size_t>(wideLength), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, value.data(), sourceBytes,
            &wide[0], wideLength) != wideLength) {
        return {};
    }

    const int utf8Length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        wide.data(), wideLength, nullptr, 0, nullptr, nullptr);
    if (utf8Length <= 0) return {};
    std::string utf8(static_cast<size_t>(utf8Length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
            wideLength, &utf8[0], utf8Length, nullptr, nullptr) != utf8Length) {
        return {};
    }

    if (utf8.size() > 4096) {
        size_t end = 4096;
        while (end &&
               (static_cast<unsigned char>(utf8[end]) & 0xc0) == 0x80) {
            --end;
        }
        utf8.resize(end);
    }
    return utf8;
}

} // namespace

HealthHeartbeat::HealthHeartbeat(uint32_t pollSeconds, const EventBus* bus,
                                 SyslogForwarder* syslog,
                                 std::string collectorsSummary,
                                 const Reporter* reporter,
                                 const Reporter* eventReporter,
                                 DiagnosticsFn diagnostics)
    : m_pollMs((pollSeconds ? pollSeconds : 300) * 1000u),
      m_bus(bus), m_syslog(syslog),
      m_collectorsSummary(std::move(collectorsSummary)),
      m_reporter(reporter), m_eventReporter(eventReporter),
      m_diagnostics(std::move(diagnostics)) {}

HealthHeartbeat::~HealthHeartbeat() { Stop(); }

HealthComponent SampleCollectorHealth(const std::string& name,
                                      const ICollector* collector) {
    HealthComponent component;
    component.name = name;
    component.state = "unavailable";
    if (!collector) return component;
    try {
        const auto sample = collector->GetHealthSnapshot();
        if (!sample.supported) {
            component.state = "unsupported";
            return component;
        }
        component.state = sample.state.empty() ? (sample.running ? "running" : "stopped") : sample.state;
        component.countersAvailable = true;
        component.replayState = sample.replayState;
        component.counters = {
            {"queue_pending", sample.queuePending},
            {"queue_dropped", sample.queueDropped},
            {"render_errors", sample.renderErrors},
            {"parse_errors", sample.parseErrors},
            {"bus_overflow_observed", sample.busDropped},
            {"source_errors", sample.sourceErrors},
            {"events_pushed", sample.eventsPushed},
            {"worker_running", sample.running ? 1u : 0u},
        };
        if (sample.countersAvailable) component.counters = sample.counters;
        if (sample.lastSuccess100ns)
            component.lastSuccess100ns = std::to_string(sample.lastSuccess100ns);
    } catch (...) {
        /* One failed collector query must not suppress other components. */
    }
    return component;
}

bool HealthHeartbeat::Start() {
    if (m_thread.joinable()) return true;
    if (m_bus == nullptr) return false;
    m_stop.store(false);
    try {
        m_thread = std::thread(&HealthHeartbeat::Run, this);
    } catch (...) {
        m_stop.store(true);
        return false;
    }
    return true;
}

void HealthHeartbeat::Stop() {
    m_stop.store(true);
    if (m_thread.joinable()) m_thread.join();
}

std::string HealthHeartbeat::Snapshot(uint64_t uptimeSeconds) const {
    const std::string timestamp = IsoTimestamp();
    const EventBusStats bus = m_bus ? m_bus->SnapshotStats() : EventBusStats{};
    auto quote = [](const std::string& value) {
        return "\"" + jsonlite::escape(BoundedValidUtf8(value)) + "\"";
    };
    std::string line = "{\"type\":\"health\",\"ts\":" + quote(timestamp) +
        ",\"sampling\":\"periodic\",\"last_sample_ts\":" + quote(timestamp) +
        ",\"uptime_s\":" + std::to_string(uptimeSeconds) +
        ",\"bus_pending\":" + (m_bus ? std::to_string(bus.pending) : "null") +
        ",\"bus_dropped\":" + (m_bus ? std::to_string(bus.dropped) : "null") +
        ",\"collector_inventory\":\"attempted_only\"";
    const std::pair<const char*, uint64_t> busMetrics[] = {
        {"capacity", bus.capacity}, {"high_watermark", bus.highWatermark},
        {"in_flight", bus.inFlight}, {"overflow_dropped", bus.overflowDropped},
        {"consumer_failed", bus.consumerFailed}, {"abandoned", bus.abandoned},
        {"consumed", bus.consumed}, {"deduplicated", bus.deduplicated},
        {"oldest_pending_ms", bus.oldestPendingMs},
    };
    for (const auto& metric : busMetrics)
        line += ",\"bus_" + std::string(metric.first) + "\":" +
            (m_bus ? std::to_string(metric.second) : "null");
    auto reporterFields = [&](const char* prefix, const Reporter* reporter) {
        const std::string key(prefix);
        line += ",\"" + key + "_enabled\":" + (reporter ? "true" : "false");
        line += ",\"" + key + "_runtime_state\":" +
            quote(reporter ? reporter->GetRuntimeState() : "disabled");
        line += ",\"" + key + "_queued\":" +
            (reporter ? std::to_string(reporter->QueuedCount()) : "null");
        line += ",\"" + key + "_dropped\":" +
            (reporter ? std::to_string(reporter->DroppedCount()) : "null");
        line += ",\"" + key + "_spool_state\":" +
            quote(reporter ? reporter->GetSpoolStatus() : "disabled");
        line += ",\"" + key + "_spool_errors\":" +
            (reporter ? std::to_string(reporter->SpoolErrorCount()) : "null");
        const auto delivery = reporter ? reporter->GetDeliveryStats()
                                       : Reporter::DeliveryStats{};
        const std::pair<const char*, uint64_t> deliveryMetrics[] = {
            {"attempts", delivery.attempts}, {"succeeded", delivery.succeeded},
            {"failed", delivery.failed},
            {"consecutive_failures", delivery.consecutiveFailures},
        };
        for (const auto& metric : deliveryMetrics)
            line += ",\"" + key + "_" + metric.first + "\":" +
                (reporter ? std::to_string(metric.second) : "null");
        line += ",\"" + key + "_in_progress\":" +
            (reporter ? (delivery.inProgress ? "true" : "false") : "null");
        line += ",\"" + key + "_last_attempt_100ns\":" +
            (reporter && delivery.lastAttempt100ns != 0
                ? quote(std::to_string(delivery.lastAttempt100ns)) : "null");
        line += ",\"" + key + "_last_success_100ns\":" +
            (reporter && delivery.lastSuccess100ns != 0
                ? quote(std::to_string(delivery.lastSuccess100ns)) : "null");
    };
    reporterFields("reporter", m_reporter);
    reporterFields("event_reporter", m_eventReporter);
    const auto syslog = m_syslog ? m_syslog->GetStatsSnapshot() : SyslogForwarder::Stats{};
    line += ",\"syslog_enabled\":" + std::string(m_syslog ? "true" : "false") +
        ",\"syslog_state\":" + quote(m_syslog ? syslog.state : "disabled") +
        ",\"syslog_running\":" + (m_syslog ? (syslog.running ? "true" : "false") : "null");
    const std::pair<const char*, uint64_t> syslogMetrics[] = {
        {"pending", syslog.pending}, {"in_flight", syslog.inflight},
        {"capacity", syslog.capacity}, {"enqueued", syslog.enqueued},
        {"sent", syslog.sent}, {"failed", syslog.failed},
        {"dropped", syslog.dropped}, {"rejected", syslog.rejected},
        {"start_failures", syslog.startFailures},
    };
    for (const auto& metric : syslogMetrics)
        line += ",\"syslog_" + std::string(metric.first) + "\":" +
            (m_syslog ? std::to_string(metric.second) : "null");
    line += ",\"syslog_last_error\":" +
        (m_syslog ? std::to_string(syslog.lastError) : "null");
    line += ",\"collectors\":" + quote(m_collectorsSummary);
    std::vector<HealthComponent> components;
    const char* diagnosticsState = "unsupported";
    if (m_diagnostics) {
        try {
            components = m_diagnostics();
            diagnosticsState = "sampled";
        } catch (...) {
            diagnosticsState = "unavailable";
        }
    }
    line += ",\"diagnostics\":" + quote(diagnosticsState) +
        ",\"components_truncated\":" + (components.size() > 256 ? "true" : "false") +
        ",\"components\":[";
    const size_t count = std::min<size_t>(components.size(), 256);
    for (size_t i = 0; i < count; ++i) {
        if (i) line += ",";
        const auto& component = components[i];
        line += "{\"name\":" + quote(component.name) + ",\"state\":" + quote(component.state) +
            ",\"last_success_100ns\":" + (component.lastSuccess100ns.empty() ? "null" : quote(component.lastSuccess100ns)) +
            ",\"replay_state\":" + (component.replayState.empty() ? "null" : quote(component.replayState)) +
            ",\"counters_available\":" + (component.countersAvailable ? "true" : "false") +
            ",\"counters\":";
        if (!component.countersAvailable) {
            line += "null}";
            continue;
        }
        line += "{";
        size_t fields = 0;
        for (const auto& counter : component.counters) {
            if (fields >= 64) break;
            if (fields++) line += ",";
            line += quote(counter.first) + ":" + std::to_string(counter.second);
        }
        line += "},\"counters_truncated\":" +
            std::string(component.counters.size() > 64 ? "true" : "false") + "}";
    }
    return line + "]}";
}

void HealthHeartbeat::Run() {
    const uint64_t startTicks = GetTickCount64();
    for (;;) {
        for (uint32_t waited = 0;
             waited < m_pollMs && !m_stop.load(); waited += 100)
            Sleep(100);
        if (m_stop.load()) break;

        const uint64_t uptimeSeconds =
            (GetTickCount64() - startTicks) / 1000ULL;
        const std::string line = Snapshot(uptimeSeconds);
        std::fprintf(stderr, "[edr-health] %s\n", line.c_str());
        if (m_syslog != nullptr)
            m_syslog->Enqueue("info", "HEALTH", line);
    }
}

} // namespace edr
