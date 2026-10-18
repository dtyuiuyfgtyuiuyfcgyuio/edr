/*
 * auto_responder.h - Auto-terminate on detection. When armed (see the
 * main.cpp gates), terminate-action alerts at or above the configured
 * severity are executed asynchronously on a dedicated worker thread through
 * the same ResponseActionExecutor (policy checks + audit ledger) as manual
 * termination. Every decision is reported as a follow-up alert whose event
 * copy gains auto_response_status / auto_response_request_id /
 * auto_response_mode; the original alert was already emitted by the normal
 * pipeline and is never modified. Follow-ups go to Alerter::OnAlert ONLY
 * (never back through the rule engine). Alerter serializes its file writes
 * internally, so the worker and the bus consumer may emit concurrently.
 */
#ifndef EDR_AUTO_RESPONDER_H
#define EDR_AUTO_RESPONDER_H

#include <atomic>
#include <condition_variable>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "alerter.h"
#include "response_actions.h"
#include "rule_engine.h"

namespace edr {

/* Severity rank: low < medium < high < critical; unknown ranks lowest. */
int SeverityRank(const std::string& severity);

class AutoResponder {
public:
    using ExecuteFn =
        std::function<ResponseActionResult(const ResponseActionRequest&)>;
    using DeleteFileExecuteFn =
        std::function<DeleteFileResult(const DeleteFileRequest&)>;

    using IsolationFn = std::function<bool(std::string& error)>;
    using SnapshotFn = std::function<bool(const Alert&, std::string& evidencePath)>;
    using SnapshotWriterFn = std::function<bool(const Alert&, const std::string& requestId,
                                                std::string& evidencePath)>;

    AutoResponder(ExecuteFn executeFn, DeleteFileExecuteFn deleteFileFn,
                  Alerter* alerter, int minSeverityRank,
                  uint32_t maxPerMinute, uint32_t maxTreeSize = 0,
                  bool suspendBeforeTerminate = false,
                  uint32_t maxTreeDepth = 0,
                  bool isolateBeforeTerminate = false,
                  IsolationFn isolateFn = {},
                  SnapshotWriterFn snapshotWriterFn = {},
                  std::vector<std::string> parentImageWhitelist = {});
    ~AutoResponder(); /* Stop() */

    /* Deep-copies *alert.event (the pointer dangles after dispatch). When
     * the bounded queue (capacity 64) is full, the NEW alert is dropped,
     * counted, and noted on stderr. */
    void Enqueue(const Alert& alert);
    void Stop(); /* drains the queue and joins the worker; idempotent */
    uint64_t DroppedCount() const { return m_dropped.load(); }

private:
    struct QueuedAlert {
        Alert alert;
        Event event;
    };

    void WorkerLoop();
    void ProcessAlert(const Alert& alert);
    void EmitFollowUp(const Alert& alert, const std::string& status,
                      const std::string& requestId,
                      const std::string& evidencePath = {},
                      const std::string& actionStatus = {},
                      const std::string& auditWritten = {});

    ExecuteFn m_executeFn;
    DeleteFileExecuteFn m_deleteFileFn;
    Alerter* m_alerter;
    int m_minSeverityRank;
    uint32_t m_maxPerMinute;
    uint32_t m_maxTreeSize;
    bool m_suspendBeforeTerminate;
    uint32_t m_maxTreeDepth;
    bool m_isolateBeforeTerminate;
    IsolationFn m_isolateFn;
    SnapshotWriterFn m_snapshotWriterFn;
    std::vector<std::string> m_parentImageWhitelist;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<QueuedAlert> m_queue;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<uint64_t> m_dropped{0};
    std::atomic<uint64_t> m_skipped{0};
    std::deque<std::chrono::steady_clock::time_point> m_recentCalls;
};

} // namespace edr

#endif /* EDR_AUTO_RESPONDER_H */
