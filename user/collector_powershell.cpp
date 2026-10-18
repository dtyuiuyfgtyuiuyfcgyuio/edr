#include <windows.h>
#include <winevt.h>

#include <atomic>
#include <condition_variable>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector.h"
#include "edr_event.h"
#include "event_log_bookmark.h"
#include "powershell_parser.h"
#include "powershell_reassembler.h"

namespace edr {

class PowerShellCollector final : public ICollector {
    struct WorkItem {
        std::wstring xml;
        EventLogBookmarkStore::Token token = 0;
    };

    struct FragmentTokens {
        explicit FragmentTokens(std::shared_ptr<EventLogBookmarkStore> replay)
            : receipts(std::move(replay)) {}
        EventLogBookmarkTokenGroup receipts;
        std::chrono::steady_clock::time_point firstSeen;
    };

public:
    PowerShellCollector(uint32_t queueCapacity, uint32_t workers,
                         uint32_t maxXmlBytes, uint32_t maxScriptChars,
                         PowerShellReassemblyConfig reassembly,
                         EventLogReplayOptions replay)
        : m_queueCapacity(queueCapacity), m_workerCount(workers),
          m_maxXmlBytes(maxXmlBytes), m_maxScriptChars(maxScriptChars),
          m_reassemblyEnabled(reassembly.enabled),
          m_reassemblyTimeoutSeconds(reassembly.timeoutSeconds),
          m_reassembler(std::move(reassembly), [] { return GetTickCount64() / 1000; }),
          m_replay(CreateEventLogBookmarkStore(replay, L"powershell",
              L"Microsoft-Windows-PowerShell/Operational",
              static_cast<size_t>(queueCapacity) + workers)) {}

    ~PowerShellCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_subscription != nullptr) return true;
        if (bus == nullptr) return false;
        DWORD subscriptionFlags = EvtSubscribeToFutureEvents;
        EVT_HANDLE bookmark = nullptr;
        m_bus.store(bus);
        m_stop.store(false);
        for (uint32_t i = 0; i < m_workerCount; ++i)
            m_workers.emplace_back(&PowerShellCollector::WorkerLoop, this);

        m_signalEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_signalEvent == nullptr) {
            std::fprintf(stderr,
                         "[edr-powershell] CreateEventW failed: %lu\n",
                         GetLastError());
            StopWorkers();
            m_bus.store(nullptr);
            return false;
        }

        if (m_replay && !PrepareReplay(subscriptionFlags, bookmark)) {
            StopWorkers();
            CloseHandle(m_signalEvent);
            m_signalEvent = nullptr;
            m_bus.store(nullptr);
            return false;
        }

        m_subscription = EvtSubscribe(nullptr, m_signalEvent,
            L"Microsoft-Windows-PowerShell/Operational",
            L"*[System[(EventID=4104)]]", bookmark, nullptr, nullptr,
            subscriptionFlags);
        const DWORD subscribeError = m_subscription == nullptr
            ? GetLastError() : ERROR_SUCCESS;
        if (bookmark != nullptr) EvtClose(bookmark);
        if (m_subscription == nullptr) {
            if (m_replay) m_replay->MarkSubscriptionError(subscribeError);
            std::fprintf(stderr,
                         "[edr-powershell] subscription unavailable: %lu\n",
                         subscribeError);
            StopWorkers();
            CloseHandle(m_signalEvent);
            m_signalEvent = nullptr;
            m_bus.store(nullptr);
            return false;
        }
        try {
            m_pullThread = std::thread(&PowerShellCollector::PullLoop, this);
        } catch (...) {
            EvtClose(m_subscription);
            m_subscription = nullptr;
            CloseHandle(m_signalEvent);
            m_signalEvent = nullptr;
            StopWorkers();
            m_bus.store(nullptr);
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        EVT_HANDLE subscription = m_subscription;
        if (m_signalEvent != nullptr) SetEvent(m_signalEvent);
        if (m_pullThread.joinable()) m_pullThread.join();
        m_subscription = nullptr;
        if (subscription != nullptr) EvtClose(subscription);
        if (m_signalEvent != nullptr) {
            CloseHandle(m_signalEvent);
            m_signalEvent = nullptr;
        }
        StopWorkers();
        FlushReassembly();
        m_bus.store(nullptr);
        if (subscription != nullptr) {
            std::fprintf(stderr,
                "[edr-powershell] rendered=%llu queued=%llu "
                "queue_dropped=%llu render_errors=%llu parse_errors=%llu "
                "pushed=%llu bus_overflow_observed=%llu subscription_errors=%llu\n",
                static_cast<unsigned long long>(m_rendered.load()),
                static_cast<unsigned long long>(m_queued.load()),
                static_cast<unsigned long long>(m_queueDropped.load()),
                static_cast<unsigned long long>(m_renderErrors.load()),
                static_cast<unsigned long long>(m_parseErrors.load()),
                static_cast<unsigned long long>(m_pushed.load()),
                static_cast<unsigned long long>(m_busOverflowObserved.load()),
                static_cast<unsigned long long>(m_subscriptionErrors.load()));
        }
    }

    CollectorHealthSnapshot GetHealthSnapshot() const override {
        CollectorHealthSnapshot sample;
        sample.supported = true;
        sample.running = m_pullActive.load() && !m_stop.load();
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            sample.queuePending = m_queue.size();
        }
        sample.queueDropped = m_queueDropped.load();
        sample.renderErrors = m_renderErrors.load();
        sample.parseErrors = m_parseErrors.load();
        sample.busDropped = m_busOverflowObserved.load();
        sample.sourceErrors = m_subscriptionErrors.load();
        sample.eventsPushed = m_pushed.load();
        sample.lastSuccess100ns = m_lastSuccess100ns.load();
        const auto replay = m_replay ? m_replay->GetStatus()
                                     : EventLogBookmarkStore::Status{};
        sample.replayState = m_replay
            ? EventLogBookmarkStore::StateName(replay.state) : "disabled";
        return sample;
    }

private:
    void PullLoop() {
        m_pullActive.store(true);
        struct ActivityGuard {
            std::atomic<bool>& active;
            ~ActivityGuard() { active.store(false); }
        } activity{m_pullActive};
        constexpr DWORD kBatchSize = 16;
        EVT_HANDLE events[kBatchSize] = {};
        while (!m_stop.load()) {
            DWORD wait = WaitForSingleObject(m_signalEvent, 1000);
            if (m_stop.load()) break;
            if (wait != WAIT_OBJECT_0) {
                if (wait == WAIT_FAILED) {
                    const DWORD error = GetLastError();
                    m_subscriptionErrors.fetch_add(1);
                    if (m_replay) m_replay->MarkSubscriptionError(error);
                }
                continue;
            }
            ResetEvent(m_signalEvent);
            for (;;) {
                DWORD returned = 0;
                EVT_HANDLE subscription = m_subscription;
                if (subscription == nullptr ||
                    !EvtNext(subscription, kBatchSize, events, 0, 0,
                             &returned)) {
                    DWORD error = GetLastError();
                    if (error != ERROR_NO_MORE_ITEMS &&
                        error != ERROR_TIMEOUT && !m_stop.load()) {
                        m_subscriptionErrors.fetch_add(1);
                        if (m_replay) m_replay->MarkSubscriptionError(error);
                        std::fprintf(stderr,
                            "[edr-powershell] EvtNext failed: %lu\n", error);
                    }
                    break;
                }
                for (DWORD i = 0; i < returned; ++i) {
                    RenderAndEnqueue(events[i]);
                    EvtClose(events[i]);
                    events[i] = nullptr;
                }
            }
        }
    }

    void RenderAndEnqueue(EVT_HANDLE handle) {
        EventLogBookmarkStore::Token replayToken = 0;
        if (m_replay) {
            std::string error;
            if (!m_replay->Capture(handle, replayToken, &error)) {
                m_subscriptionErrors.fetch_add(1);
                std::fprintf(stderr,
                    "[edr-powershell] bookmark capture failed: %s\n",
                    error.c_str());
                return;
            }
        }
        DWORD needed = 0, properties = 0;
        if (!EvtRender(nullptr, handle, EvtRenderEventXml, 0, nullptr,
                       &needed, &properties) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            m_renderErrors.fetch_add(1);
            if (m_replay) (void)m_replay->Complete(replayToken, false);
            return;
        }
        if (needed < sizeof(wchar_t) || needed > m_maxXmlBytes) {
            m_renderErrors.fetch_add(1);
            if (m_replay) (void)m_replay->Complete(replayToken, false);
            return;
        }
        std::vector<wchar_t> buffer(
            (needed + sizeof(wchar_t) - 1) / sizeof(wchar_t));
        if (!EvtRender(nullptr, handle, EvtRenderEventXml, needed,
                       buffer.data(), &needed, &properties)) {
            m_renderErrors.fetch_add(1);
            if (m_replay) (void)m_replay->Complete(replayToken, false);
            return;
        }
        m_rendered.fetch_add(1);
        std::wstring xml(buffer.data());

        std::unique_lock<std::mutex> lock(m_queueMutex, std::try_to_lock);
        if (!lock.owns_lock() || m_queue.size() >= m_queueCapacity ||
            m_stop.load()) {
            m_queueDropped.fetch_add(1);
            if (m_replay) (void)m_replay->Complete(replayToken, false);
            return;
        }
        m_queue.push_back(WorkItem{std::move(xml), replayToken});
        m_queued.fetch_add(1);
        lock.unlock();
        m_queueCv.notify_one();
    }

    void WorkerLoop() {
        for (;;) {
            WorkItem item;
            {
                std::unique_lock<std::mutex> lock(m_queueMutex);
                m_queueCv.wait_for(lock, std::chrono::seconds(1),
                    [&] { return m_stop.load() || !m_queue.empty(); });
                if (m_queue.empty()) {
                    lock.unlock();
                    FlushExpiredReassembly();
                    if (m_stop.load()) return;
                    continue;
                }
                item = std::move(m_queue.front());
                m_queue.pop_front();
            }
            Event event;
            if (!ParsePowerShellXml(item.xml, m_maxScriptChars, event)) {
                m_parseErrors.fetch_add(1);
                if (m_replay) (void)m_replay->Complete(item.token, false);
                continue;
            }
            std::vector<Event> accepted;
            std::vector<Event> expired;
            {
                std::lock_guard<std::mutex> lock(m_replayFragmentMutex);
                std::string key;
                const bool isFragment =
                    m_reassembler.TryGetFragmentKey(event, key);
                const bool isMultifragment = IsMultifragmentCandidate(event);
                /* The raw callback must not be copied into reassembly state.
                 * A fragment group gets exactly one owner: its terminal block. */
                event.onConsumed = {};
                bool exactTombstoneDuplicate = false;
                accepted = m_reassembler.Accept(std::move(event),
                    &exactTombstoneDuplicate);
                if (m_replay && isMultifragment && !isFragment) {
                    m_subscriptionErrors.fetch_add(1);
                    (void)m_replay->Complete(item.token, false);
                } else if (m_replay && isFragment &&
                           !exactTombstoneDuplicate) {
                    auto inserted = m_fragmentTokens.try_emplace(key, m_replay);
                    auto& group = inserted.first->second;
                    if (inserted.second)
                        group.firstSeen = std::chrono::steady_clock::now();
                    if (!group.receipts.Add(item.token)) {
                        m_subscriptionErrors.fetch_add(1);
                        (void)m_replay->Complete(item.token, false);
                        m_fragmentTokens.erase(inserted.first);
                    }
                }
                AttachReplayAcknowledgments(accepted,
                    m_replay && (!isMultifragment ||
                                 exactTombstoneDuplicate) ? item.token : 0);
                expired = m_reassembler.FlushExpired();
                AttachReplayAcknowledgments(expired, 0);
                FailOrphanedFragmentGroups();
            }
            Push(std::move(accepted));
            Push(std::move(expired));
        }
    }

    bool IsMultifragmentCandidate(const Event& event) const {
        if (!m_reassemblyEnabled || event.type != EDR_EVT_POWERSHELL_SCRIPT)
            return false;
        const auto totalValue = event.fields.find(field::kScriptMessageTotal);
        if (totalValue == event.fields.end()) return false;
        char* end = nullptr;
        errno = 0;
        const unsigned long total = std::strtoul(totalValue->second.c_str(),
                                                 &end, 10);
        return errno == 0 && end != totalValue->second.c_str() && *end == '\0' &&
            total > 1;
    }

    void AttachReplayAcknowledgments(
        std::vector<Event>& events,
        EventLogBookmarkStore::Token standaloneToken) {
        if (!m_replay) return;
        for (size_t i = 0; i < events.size(); ++i) {
            Event& event = events[i];
            if (event.disposition == EventDisposition::ReportAndEvaluate &&
                event.fields.find(field::kScriptReassemblyStatus) !=
                    event.fields.end()) {
                std::string key;
                if (!m_reassembler.TryGetFragmentKey(event, key)) {
                    (void)m_replay->Complete(0, false);
                    continue;
                }
                auto found = m_fragmentTokens.find(key);
                if (found == m_fragmentTokens.end() ||
                    !found->second.receipts.Attach(event)) {
                    if (found != m_fragmentTokens.end()) {
                        (void)found->second.receipts.Fail();
                        m_fragmentTokens.erase(found);
                    }
                    (void)m_replay->Complete(0, false);
                    continue;
                }
                m_fragmentTokens.erase(found);
            } else if (i == 0 && standaloneToken != 0) {
                AttachReplayToken(event, standaloneToken);
            }
        }
    }

    void AttachReplayToken(Event& event,
                          EventLogBookmarkStore::Token token) {
        const auto replay = m_replay;
        event.onConsumed = [replay, token](bool accepted) {
            (void)replay->Complete(token, accepted);
        };
    }

    void FlushExpiredReassembly() {
        std::vector<Event> expired;
        {
            std::lock_guard<std::mutex> lock(m_replayFragmentMutex);
            expired = m_reassembler.FlushExpired();
            AttachReplayAcknowledgments(expired, 0);
            FailOrphanedFragmentGroups();
        }
        Push(std::move(expired));
    }

    void FailOrphanedFragmentGroups() {
        if (!m_replay || m_fragmentTokens.empty()) return;
        const auto staleAfter = std::chrono::seconds(
            static_cast<int64_t>(m_reassemblyTimeoutSeconds) + 2);
        const auto now = std::chrono::steady_clock::now();
        for (auto it = m_fragmentTokens.begin(); it != m_fragmentTokens.end();) {
            if (now - it->second.firstSeen <= staleAfter) {
                ++it;
                continue;
            }
            (void)it->second.receipts.Fail();
            it = m_fragmentTokens.erase(it);
        }
    }

    void StopWorkers() {
        m_stop.store(true);
        m_queueCv.notify_all();
        for (auto& worker : m_workers) {
            if (worker.joinable()) worker.join();
        }
        m_workers.clear();
    }

    void Push(std::vector<Event> events) {
        EventBus* bus = m_bus.load();
        if (!bus) {
            for (Event& event : events) {
                if (event.onConsumed) {
                    try { event.onConsumed(false); } catch (...) {}
                }
            }
            return;
        }
        for (const Event& event : events) {
            /* false reports an evicted older event; the current record is
             * accepted, while the previous receipt will latch its own gap. */
            if (!bus->Push(event)) m_busOverflowObserved.fetch_add(1);
            m_pushed.fetch_add(1);
            FILETIME now = {};
            GetSystemTimePreciseAsFileTime(&now);
            m_lastSuccess100ns.store(
                (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                now.dwLowDateTime);
        }
    }

    void FlushReassembly() {
        std::vector<Event> finalEvents;
        {
            std::lock_guard<std::mutex> lock(m_replayFragmentMutex);
            finalEvents = m_reassembler.FlushAll();
            AttachReplayAcknowledgments(finalEvents, 0);
            FailOrphanedFragmentGroups();
        }
        Push(std::move(finalEvents));
    }

    bool PrepareReplay(DWORD& flags, EVT_HANDLE& bookmark) {
        std::string error;
        if (!m_replay->Open(&error) ||
            !m_replay->PrepareSubscription(flags, bookmark)) {
            m_subscriptionErrors.fetch_add(1);
            if (error.empty()) error = m_replay->GetStatus().lastError;
            std::fprintf(stderr, "[edr-powershell] bookmark unavailable: %s\n",
                         error.c_str());
            return false;
        }
        return true;
    }

    size_t m_queueCapacity;
    uint32_t m_workerCount;
    DWORD m_maxXmlBytes;
    size_t m_maxScriptChars;
    bool m_reassemblyEnabled;
    uint32_t m_reassemblyTimeoutSeconds;
    PowerShellReassembler m_reassembler;
    std::shared_ptr<EventLogBookmarkStore> m_replay;
    std::atomic<EventBus*> m_bus{nullptr};
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_pullActive{false};
    std::atomic<uint64_t> m_lastSuccess100ns{0};
    EVT_HANDLE m_subscription = nullptr;
    HANDLE m_signalEvent = nullptr;
    std::thread m_pullThread;
    mutable std::mutex m_queueMutex;
    std::condition_variable m_queueCv;
    std::deque<WorkItem> m_queue;
    std::vector<std::thread> m_workers;
    std::mutex m_replayFragmentMutex;
    std::map<std::string, FragmentTokens> m_fragmentTokens;
    std::atomic<uint64_t> m_rendered{0};
    std::atomic<uint64_t> m_queued{0};
    std::atomic<uint64_t> m_queueDropped{0};
    std::atomic<uint64_t> m_renderErrors{0};
    std::atomic<uint64_t> m_parseErrors{0};
    std::atomic<uint64_t> m_pushed{0};
    std::atomic<uint64_t> m_busOverflowObserved{0};
    std::atomic<uint64_t> m_subscriptionErrors{0};
};

ICollector* CreatePowerShellCollector(uint32_t queueCapacity,
                                       uint32_t workers,
                                       uint32_t maxXmlBytes,
                                       uint32_t maxScriptChars,
                                       PowerShellReassemblyConfig reassembly,
                                       EventLogReplayOptions replay) {
    return new PowerShellCollector(queueCapacity, workers, maxXmlBytes,
                                   maxScriptChars, std::move(reassembly),
                                   std::move(replay));
}

} // namespace edr
