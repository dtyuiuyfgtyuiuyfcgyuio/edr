#include "auto_responder.h"

#include <windows.h>

#include <bcrypt.h>

#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "json_lite.h"
#include "system_snapshot.h"
#include "process_tree_builder.h"

namespace edr {
namespace {

constexpr size_t kQueueCapacity = 64;
uint64_t CurrentFileTime() {
    FILETIME fileTime;
    GetSystemTimePreciseAsFileTime(&fileTime);
    return (static_cast<uint64_t>(fileTime.dwHighDateTime) << 32) |
        fileTime.dwLowDateTime;
}

/* GUID-shaped id (8-4-4-4-12 hex, 36 chars with dashes). The audit ledger
 * replay reconstruction hard-fails on requestIds rejected by ValidRequestId
 * at the next agent start, so this shape is mandatory (M2). */
std::string NewRequestId() {
    unsigned char bytes[16];
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        /* Practically unreachable; keep a valid shape anyway. */
        static std::atomic<uint32_t> fallbackCounter{0};
        char fallback[48];
        std::snprintf(fallback, sizeof(fallback), "auto-%08lx-%08lx-%08lx",
                      static_cast<unsigned long>(GetCurrentProcessId()),
                      static_cast<unsigned long>(CurrentFileTime() & 0xffffffff),
                      static_cast<unsigned long>(fallbackCounter.fetch_add(1)));
        return fallback;
    }
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0f) | 0x40);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3f) | 0x80);
    char id[37];
    int at = 0;
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            id[at++] = '-';
        }
        at += std::snprintf(id + at, sizeof(id) - at, "%02x", bytes[i]);
    }
    id[at] = '\0';
    return std::string(id, static_cast<size_t>(at));
}

} // namespace

int SeverityRank(const std::string& severity) {
    if (severity == "low") return 0;
    if (severity == "medium") return 1;
    if (severity == "high") return 2;
    if (severity == "critical") return 3;
    return -1;
}

AutoResponder::AutoResponder(ExecuteFn executeFn,
                             DeleteFileExecuteFn deleteFileFn, Alerter* alerter,
                             int minSeverityRank, uint32_t maxPerMinute,
                             uint32_t maxTreeSize, bool suspendBeforeTerminate,
                             uint32_t maxTreeDepth, bool isolateBeforeTerminate,
                             IsolationFn isolateFn,
                             SnapshotWriterFn snapshotWriterFn,
                             std::vector<std::string> parentImageWhitelist)
    : m_executeFn(std::move(executeFn)), m_deleteFileFn(std::move(deleteFileFn)),
      m_alerter(alerter), m_minSeverityRank(minSeverityRank),
      m_maxPerMinute(maxPerMinute), m_maxTreeSize(maxTreeSize),
      m_suspendBeforeTerminate(suspendBeforeTerminate),
      m_maxTreeDepth(maxTreeDepth),
      m_isolateBeforeTerminate(isolateBeforeTerminate),
      m_isolateFn(std::move(isolateFn)),
      m_snapshotWriterFn(std::move(snapshotWriterFn)),
      m_parentImageWhitelist(std::move(parentImageWhitelist)) {
    m_thread = std::thread(&AutoResponder::WorkerLoop, this);
}


AutoResponder::~AutoResponder() {
    Stop();
}

void AutoResponder::Enqueue(const Alert& alert) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.size() >= kQueueCapacity) {
            m_dropped.fetch_add(1);
            std::fprintf(stderr,
                "[edr] auto-response queue full; dropping alert for rule %s\n",
                alert.ruleId.c_str());
            return;
        }
        QueuedAlert item;
        item.alert = alert;
        if (alert.event != nullptr) {
            item.event = *alert.event;
        }
        m_queue.push_back(std::move(item));
        /* The copied Alert must point at the queued Event, not the moved-from
         * temporary. */
        m_queue.back().alert.event = &m_queue.back().event;
    }
    m_cv.notify_one();
}

void AutoResponder::Stop() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_thread.joinable()) {
            return;
        }
        m_stop.store(true);
    }
    m_cv.notify_all();
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

void AutoResponder::WorkerLoop() {
    for (;;) {
        QueuedAlert item;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [&] { return m_stop.load() || !m_queue.empty(); });
            if (m_queue.empty()) {
                return; /* stop requested and the queue is fully drained */
            }
            item = std::move(m_queue.front());
            m_queue.pop_front();
        }
        item.alert.event = &item.event;
        ProcessAlert(item.alert);
    }
}

void AutoResponder::ProcessAlert(const Alert& alert) {
    if (alert.action != "terminate" && alert.action != "kill" &&
        alert.action != "delete_file") {
        return; /* only response-action alerts are auto-responded */
    }
    const Event& event = *alert.event;
    if (SeverityRank(alert.severity) < m_minSeverityRank) {
        m_skipped.fetch_add(1); /* below threshold: skip silently */
        return;
    }
    auto monotonicNow = std::chrono::steady_clock::now();
    while (!m_recentCalls.empty() &&
           monotonicNow - m_recentCalls.front() > std::chrono::minutes(1)) {
        m_recentCalls.pop_front();
    }
    if (m_recentCalls.size() >= m_maxPerMinute) {
        EmitFollowUp(alert, "rate_limited", "");
        return;
    }
    m_recentCalls.push_back(monotonicNow);

    if (alert.action == "delete_file") {
        if (!m_deleteFileFn) {
            EmitFollowUp(alert, "unavailable", "");
            return;
        }
        std::string path;
        auto it = event.fields.find(field::kFilePath);
        if (it == event.fields.end())
            it = event.fields.find(field::kTargetPath);
        if (it != event.fields.end()) path = it->second;
        if (path.empty()) {
            EmitFollowUp(alert, "target_unavailable", "");
            return;
        }
        DeleteFileRequest request;
        request.requestId = NewRequestId();
        request.timestamp = std::to_string(CurrentFileTime());
        request.reason = "auto_response:" + alert.ruleId;
        request.path = std::move(path);
        auto hashIt = event.fields.find(field::kSha256);
        if (hashIt != event.fields.end()) request.sha256Hex = hashIt->second;
        if (request.sha256Hex.empty()) {
            EmitFollowUp(alert, "hash_unavailable", "");
            return;
        }
        try {
            DeleteFileResult result = m_deleteFileFn(request);
            EmitFollowUp(alert, result.status, request.requestId, {}, result.status,
                         result.auditWritten ? "true" : "false");
        } catch (const std::exception&) {
            EmitFollowUp(alert, "executor_exception", request.requestId);
        } catch (...) {
            EmitFollowUp(alert, "executor_exception", request.requestId);
        }
        return;
    }

    /* terminate or kill */
    if (event.pid == 0 || event.processStartTime100ns == 0) {
        EmitFollowUp(alert, "identity_unavailable", "");
        return;
    }
    ResponseActionRequest request;
    request.requestId = NewRequestId();
    request.timestamp = std::to_string(CurrentFileTime());
    request.reason = "auto_response:" + alert.ruleId;
    request.pid = event.pid;
    request.createTime100ns = event.processStartTime100ns;
    request.maxTreeSize = m_maxTreeSize;
    request.suspendBeforeTerminate = m_suspendBeforeTerminate;
    request.maxTreeDepth = m_maxTreeDepth;
    request.isolateBeforeTerminate = m_isolateBeforeTerminate;
    request.parentImageWhitelist = m_parentImageWhitelist;
    if (m_snapshotWriterFn) {
        request.snapshotRequested = true;
        request.captureSnapshot = [this, &alert, id = request.requestId](
                std::string& evidencePath) {
            return m_snapshotWriterFn(alert, id, evidencePath);
        };
    }
    if (m_isolateBeforeTerminate && m_isolateFn) {
        request.preIsolationCallback = m_isolateFn;
    }
    try {
        ResponseActionResult result = m_executeFn(request);
        EmitFollowUp(alert, result.status, request.requestId, result.evidencePath,
                     result.status, result.auditWritten ? "true" : "false");
    } catch (const std::exception&) {
        EmitFollowUp(alert, "executor_exception", request.requestId);
    } catch (...) {
        EmitFollowUp(alert, "executor_exception", request.requestId);
    }
}

void AutoResponder::EmitFollowUp(const Alert& alert, const std::string& status,
                                 const std::string& requestId,
                                 const std::string& evidencePath,
                                 const std::string& actionStatus,
                                 const std::string& auditWritten) {
    if (m_alerter == nullptr) {
        return;
    }
    Alert followUp = alert; /* same ruleId/severity/action/mitre arrays */
    Event eventCopy = *alert.event;
    eventCopy.fields[field::kAutoResponseStatus] = auditWritten == "false"
        ? "audit_failed" : status;
    if (!actionStatus.empty()) {
        eventCopy.fields[field::kAutoResponseActionStatus] = actionStatus;
    }
    if (!auditWritten.empty()) {
        eventCopy.fields[field::kAutoResponseAuditWritten] = auditWritten;
    }
    if (!requestId.empty()) {
        eventCopy.fields[field::kAutoResponseRequestId] = requestId;
    }
    eventCopy.fields[field::kAutoResponseMode] = "real";
    if (!evidencePath.empty()) {
        eventCopy.fields[field::kAutoResponseEvidencePath] = evidencePath;
    }
    followUp.event = &eventCopy;
    m_alerter->OnAlert(followUp);
}

} // namespace edr
