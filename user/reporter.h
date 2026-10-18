/*
 * reporter.h - Optional HTTP reporter (OFF by default). When enabled, a
 * dedicated thread POSTs alert JSON lines via WinHTTP with a 5s timeout,
 * exponential backoff 1s -> 60s, and a bounded cache (<=1000 entries,
 * including the in-flight item). Volatile mode drops the oldest pending item
 * on overflow. Optional durable mode persists before enqueue, rejects new
 * items at capacity, and provides at-least-once delivery across restarts.
 * Durable backlogs are bound to the exact configured URL (excluding the
 * separate API key); a changed URL fails recovery and preserves spool files.
 * Queue depth and drop count are exposed as read-only health metrics.
 * Start/Stop must be serialized by the owning Agent; Enqueue and metric
 * snapshots may run concurrently with its worker and owner.
 */
#ifndef EDR_REPORTER_H
#define EDR_REPORTER_H

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <cstdint>

#include "reporter_spool.h"

namespace edr {

/* Derive the event endpoint by appending /events to an exact /ingest path,
 * before any query string. Other paths are returned unchanged. */
std::string EventReporterUrl(const std::string& alertUrl);

class Reporter {
public:
    using PostFn = std::function<bool(const std::string&)>;

    Reporter(std::string url, std::string apiKey = "", size_t cacheLimit = 1000,
             PostFn postFn = {}, ReporterSpoolOptions spoolOptions = {});
    ~Reporter();

    bool Start();
    void Stop();
    bool Enqueue(std::string jsonLine);

    /* Read-only queue health metrics for the agent heartbeat and diagnostics. */
    uint64_t DroppedCount() const noexcept { return m_dropped.load(); }
    size_t QueuedCount() const;
    std::string GetRuntimeState() const;
    std::string GetSpoolStatus() const;
    uint64_t SpoolErrorCount() const noexcept;

private:
    enum class RuntimeState {
        NotStarted,
        Started,
        StartFailed,
        WorkerFailed,
        Stopping,
        Stopped,
    };

    struct QueueItem {
        std::string id;
        std::string body;
    };

    void WorkerLoop();
    bool Post(const std::string& body);
    static uint32_t NextBackoff(uint32_t current);

    std::string m_url;
    std::string m_apiKey;
    size_t m_cacheLimit;
    PostFn m_postFn;
    std::unique_ptr<ReporterSpool> m_spool;
    bool m_spoolReady = false;
    bool m_startSucceeded = false;
    RuntimeState m_runtimeState = RuntimeState::NotStarted;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::optional<QueueItem> m_inFlight;
    std::deque<QueueItem> m_pending;
    uint64_t m_nextId = 1;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<uint64_t> m_dropped{0};
};

} // namespace edr

#endif /* EDR_REPORTER_H */
