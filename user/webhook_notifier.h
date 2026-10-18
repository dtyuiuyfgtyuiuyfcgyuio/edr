/*
 * webhook_notifier.h - Optional alert webhook fan-out (OFF by default).
 *
 * POSTs every agent alert to a configurable URL as a JSON envelope so a
 * SOAR/SIEM downstream can consume alerts without polling the JSONL ledger.
 *
 * Config section contract (parsed by config.cpp, see wiring notes):
 *
 *     "webhook": {
 *         "enable": false,            // default false (Boolean)
 *         "url": "",                  // e.g. http://127.0.0.1:9000/alerts (String)
 *         "timeout_seconds": 5,       // BoundedUInt [1, 60], default 5
 *         "queue_capacity": 256       // BoundedUInt [16, 65536], default 256
 *     }
 *
 * Guarantees (design contract):
 *
 *  - NEVER blocks or breaks the alert main path. Alerter's alert-callback
 *    thread only builds a small envelope string and enqueues it; all network
 *    I/O happens on an internal worker thread. Notify() never performs I/O.
 *
 *  - Bounded queue. When the queue is full the OLDEST queued envelope is
 *    evicted to admit the newest one and the dropped counter increments.
 *    This matches the house drop semantics of EventBus::Push and
 *    Reporter::Enqueue (newest always wins; stalest item is sacrificed).
 *
 *  - NO RETRY, by explicit decision. A failed POST is counted in FailedCount
 *    and logged (rate limited) once; the notification is not re-queued.
 *    Local retry would duplicate alerts after ambiguous timeouts and hide
 *    outages from the operator; downstream consumers should reconcile
 *    against the console-side alert ledger (alerts.jsonl / /api/alerts)
 *    instead of relying on this channel for at-least-once delivery.
 *
 *  - Destructor flush semantics: the destructor stops accepting new work,
 *    drains the remaining queued envelopes (best effort, bounded by a fixed
 *    5 second deadline so shutdown cannot hang on a dead endpoint), then
 *    joins the worker. Envelopes still queued when the deadline expires are
 *    abandoned and counted as dropped. The single in-flight transport call,
 *    if any, is always awaited to completion: injected transports MUST
 *    respect their timeoutMs parameter (the production WinHTTP transport
 *    sets resolve/connect/send/receive timeouts from it).
 *
 *  - Thread safety: Notify() may be called concurrently from any thread.
 *    Counters are std::atomic. The mutex is never held during transport I/O.
 *    The object must not be destroyed while another thread is inside
 *    Notify() (same lifecycle rule as EventBus/Reporter).
 */
#ifndef EDR_WEBHOOK_NOTIFIER_H
#define EDR_WEBHOOK_NOTIFIER_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace edr {

class WebhookNotifier {
public:
    /* Injectable transport so unit tests never touch the network.
     * Must return within ~timeoutMs; false + *err describes the failure. */
    using TransportFn = std::function<bool(const std::string& url,
                                           const std::string& contentType,
                                           const std::string& body,
                                           uint32_t timeoutMs, std::string* err)>;

    /* Production constructor: uses the WinHTTP transport. */
    WebhookNotifier(bool enabled, std::string url, uint32_t timeoutSeconds,
                    size_t queueCapacity);

    /* Test constructor: empty transport selects the production WinHTTP one,
     * anything else is used verbatim (must honour timeoutMs). */
    WebhookNotifier(bool enabled, std::string url, uint32_t timeoutSeconds,
                    size_t queueCapacity, TransportFn transport);

    /* Stops accepting work, drains the queue (bounded, see header comment),
     * joins the worker. Never throws. */
    ~WebhookNotifier();

    WebhookNotifier(const WebhookNotifier&) = delete;
    WebhookNotifier& operator=(const WebhookNotifier&) = delete;

    /* Enqueue one alert for delivery. alertJson is a single alert JSON line
     * as produced by AlertToJsonLine. Silently does nothing when disabled or
     * the url is empty. Overflow evicts the oldest queued envelope (dropped++),
     * matching EventBus::Push. Never blocks on I/O. */
    void Notify(const std::string& alertJson);

    /* Read-only counters (atomic; safe from any thread). */
    size_t DroppedCount() const { return m_dropped.load(); }
    size_t DeliveredCount() const { return m_delivered.load(); }
    size_t FailedCount() const { return m_failed.load(); }
    size_t QueuedCount() const;

    /* Builds the outbound envelope (pure, independently testable):
     *   {"kind":"alert","source":"edr-agent","host":"<computer name>",
     *    "ts":"<ISO-8601 UTC>","alert":<alertJson verbatim>}
     * When alertJson (after leading whitespace) does not start with '{' it is
     * not a JSON object, so it is embedded as an escaped string instead:
     *   ...,"alert_raw":"<jsonlite::escape(alertJson)>"}
     * The '{' check is a cheap guard, not a full parse: full validation on the
     * alert thread would violate the never-block rule, and alertJson is
     * produced by AlertToJsonLine (well-formed in practice). */
    static std::string BuildEnvelope(const std::string& alertJson);

private:
    void WorkerLoop();
    void LogFailure(const std::string& err);

    bool m_enabled;
    std::string m_url;
    uint32_t m_timeoutMs;
    size_t m_capacity;
    TransportFn m_transport;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<std::string> m_queue;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};

    std::atomic<size_t> m_dropped{0};
    std::atomic<size_t> m_delivered{0};
    std::atomic<size_t> m_failed{0};
    /* steady-clock ms of the last rate-limited failure log (0 = none yet). */
    std::atomic<uint64_t> m_lastFailLogMs{0};
};

} // namespace edr

#endif /* EDR_WEBHOOK_NOTIFIER_H */
