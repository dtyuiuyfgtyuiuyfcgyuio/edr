/*
 * collector_rdp.cpp - Terminal Services / RDP session collector.
 *
 * Two EvtSubscribe handles share one signal event. LocalSessionManager
 * 21/23/24/25 and RemoteConnectionManager 1149 are pulled, bounded-queued,
 * and parsed on worker threads. Either subscription may fail independently;
 * Start succeeds when at least one channel is available.
 */
#include <windows.h>
#include <winevt.h>

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector.h"
#include "collector_rdp.h"
#include "event_log_bookmark.h"
#include "rdp_parser.h"

namespace edr {

class RdpCollector : public ICollector {
    struct WorkItem {
        std::wstring xml;
        std::shared_ptr<EventLogBookmarkStore> replay;
        EventLogBookmarkStore::Token token = 0;
    };

public:
    RdpCollector(uint32_t queueCapacity, uint32_t workers,
                 uint32_t maxXmlBytes, EventLogReplayOptions replay)
        : m_queueCapacity(queueCapacity),
          m_workerCount(workers),
          m_maxXmlBytes(maxXmlBytes),
          m_sessionReplay(CreateEventLogBookmarkStore(replay, L"rdp_session",
              L"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
              static_cast<size_t>(queueCapacity) + workers)),
          m_authReplay(CreateEventLogBookmarkStore(replay, L"rdp_auth",
              L"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
              static_cast<size_t>(queueCapacity) + workers)) {}

    ~RdpCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_sessionSub != nullptr || m_authSub != nullptr) return true;
        if (bus == nullptr) return false;
        m_bus.store(bus);
        m_stop.store(false);
        try {
            for (uint32_t i = 0; i < m_workerCount; ++i)
                m_workers.emplace_back(&RdpCollector::WorkerLoop, this);
        } catch (...) {
            StopWorkers();
            m_bus.store(nullptr);
            return false;
        }

        m_signalEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_signalEvent == nullptr) {
            std::fprintf(stderr, "[edr-rdp] CreateEventW failed: %lu\n",
                         GetLastError());
            StopWorkers();
            m_bus.store(nullptr);
            return false;
        }

        DWORD sessionFlags = EvtSubscribeToFutureEvents;
        EVT_HANDLE sessionBookmark = nullptr;
        const bool sessionReady = !m_sessionReplay ||
            PrepareReplay(m_sessionReplay, sessionFlags, sessionBookmark,
                          "LocalSessionManager");
        if (sessionReady) {
            m_sessionSub = EvtSubscribe(nullptr, m_signalEvent,
                L"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                L"*[System[(EventID=21 or EventID=23 or EventID=24 or EventID=25)]]",
                sessionBookmark, nullptr, nullptr, sessionFlags);
        }
        const DWORD sessionError = m_sessionSub == nullptr
            ? (sessionReady ? GetLastError() : ERROR_SUCCESS) : ERROR_SUCCESS;
        if (sessionBookmark != nullptr) EvtClose(sessionBookmark);
        if (m_sessionSub == nullptr) {
            if (sessionReady && m_sessionReplay)
                m_sessionReplay->MarkSubscriptionError(sessionError);
            std::fprintf(stderr, "[edr-rdp] LocalSessionManager unavailable: %lu\n",
                         sessionError);
        }

        DWORD authFlags = EvtSubscribeToFutureEvents;
        EVT_HANDLE authBookmark = nullptr;
        const bool authReady = !m_authReplay ||
            PrepareReplay(m_authReplay, authFlags, authBookmark,
                          "RemoteConnectionManager");
        if (authReady) {
            m_authSub = EvtSubscribe(nullptr, m_signalEvent,
                L"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                L"*[System[(EventID=1149)]]",
                authBookmark, nullptr, nullptr, authFlags);
        }
        const DWORD authError = m_authSub == nullptr
            ? (authReady ? GetLastError() : ERROR_SUCCESS) : ERROR_SUCCESS;
        if (authBookmark != nullptr) EvtClose(authBookmark);
        if (m_authSub == nullptr) {
            if (authReady && m_authReplay)
                m_authReplay->MarkSubscriptionError(authError);
            std::fprintf(stderr, "[edr-rdp] RemoteConnectionManager unavailable: %lu\n",
                         authError);
        }

        if (m_sessionSub == nullptr && m_authSub == nullptr) {
            StopWorkers();
            CloseHandle(m_signalEvent);
            m_signalEvent = nullptr;
            m_bus.store(nullptr);
            return false;
        }

        try {
            m_pullThread = std::thread(&RdpCollector::PullLoop, this);
        } catch (...) {
            CloseSubscriptions();
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
        if (m_signalEvent != nullptr) SetEvent(m_signalEvent);
        if (m_pullThread.joinable()) m_pullThread.join();
        CloseSubscriptions();
        if (m_signalEvent != nullptr) {
            CloseHandle(m_signalEvent);
            m_signalEvent = nullptr;
        }
        StopWorkers();
        m_bus.store(nullptr);
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
        sample.replayState = ReplayState();
        return sample;
    }

private:
    void CloseSubscriptions() {
        if (m_sessionSub != nullptr) {
            EvtClose(m_sessionSub);
            m_sessionSub = nullptr;
        }
        if (m_authSub != nullptr) {
            EvtClose(m_authSub);
            m_authSub = nullptr;
        }
    }

    void DrainSubscription(EVT_HANDLE subscription,
                           const std::shared_ptr<EventLogBookmarkStore>& replay) {
        if (subscription == nullptr) return;
        constexpr DWORD kBatchSize = 16;
        EVT_HANDLE events[kBatchSize] = {};
        for (;;) {
            DWORD returned = 0;
            if (!EvtNext(subscription, kBatchSize, events, 0, 0, &returned)) {
                DWORD error = GetLastError();
                if (error != ERROR_NO_MORE_ITEMS &&
                    error != ERROR_TIMEOUT && !m_stop.load()) {
                    m_subscriptionErrors.fetch_add(1);
                    if (replay) replay->MarkSubscriptionError(error);
                }
                break;
            }
            for (DWORD i = 0; i < returned; ++i) {
                RenderAndEnqueue(events[i], replay);
                EvtClose(events[i]);
                events[i] = nullptr;
            }
        }
    }

    void PullLoop() {
        m_pullActive.store(true);
        struct ActivityGuard {
            std::atomic<bool>& active;
            ~ActivityGuard() { active.store(false); }
        } activity{m_pullActive};
        while (!m_stop.load()) {
            DWORD wait = WaitForSingleObject(m_signalEvent, 1000);
            if (m_stop.load()) break;
            if (wait != WAIT_OBJECT_0) {
                if (wait == WAIT_FAILED) {
                    const DWORD error = GetLastError();
                    m_subscriptionErrors.fetch_add(1);
                    if (m_sessionReplay)
                        m_sessionReplay->MarkSubscriptionError(error);
                    if (m_authReplay)
                        m_authReplay->MarkSubscriptionError(error);
                }
                continue;
            }
            ResetEvent(m_signalEvent);
            DrainSubscription(m_sessionSub, m_sessionReplay);
            DrainSubscription(m_authSub, m_authReplay);
        }
    }

    void RenderAndEnqueue(
        EVT_HANDLE handle,
        const std::shared_ptr<EventLogBookmarkStore>& replay) {
        EventLogBookmarkStore::Token replayToken = 0;
        if (replay) {
            std::string error;
            if (!replay->Capture(handle, replayToken, &error)) {
                m_subscriptionErrors.fetch_add(1);
                std::fprintf(stderr, "[edr-rdp] bookmark capture failed: %s\n",
                             error.c_str());
                return;
            }
        }
        DWORD needed = 0;
        DWORD properties = 0;
        if (!EvtRender(nullptr, handle, EvtRenderEventXml, 0, nullptr,
                       &needed, &properties) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            m_renderErrors.fetch_add(1);
            if (replay) (void)replay->Complete(replayToken, false);
            return;
        }
        if (needed < sizeof(wchar_t) || needed > m_maxXmlBytes) {
            m_renderErrors.fetch_add(1);
            if (replay) (void)replay->Complete(replayToken, false);
            return;
        }
        std::vector<wchar_t> buffer(
            (needed + sizeof(wchar_t) - 1) / sizeof(wchar_t));
        if (!EvtRender(nullptr, handle, EvtRenderEventXml, needed,
                       buffer.data(), &needed, &properties)) {
            m_renderErrors.fetch_add(1);
            if (replay) (void)replay->Complete(replayToken, false);
            return;
        }
        m_rendered.fetch_add(1);

        std::unique_lock<std::mutex> lock(m_queueMutex, std::try_to_lock);
        if (!lock.owns_lock() || m_queue.size() >= m_queueCapacity ||
            m_stop.load()) {
            m_queueDropped.fetch_add(1);
            if (replay) (void)replay->Complete(replayToken, false);
            return;
        }
        m_queue.push_back(WorkItem{buffer.data(), replay, replayToken});
        m_queued.fetch_add(1);
        lock.unlock();
        m_queueCv.notify_one();
    }

    void WorkerLoop() {
        for (;;) {
            WorkItem item;
            {
                std::unique_lock<std::mutex> lock(m_queueMutex);
                m_queueCv.wait(lock, [&] {
                    return m_stop.load() || !m_queue.empty();
                });
                if (m_queue.empty()) {
                    if (m_stop.load()) return;
                    continue;
                }
                item = std::move(m_queue.front());
                m_queue.pop_front();
            }
            Event event;
            if (!ParseRdpXml(item.xml, event)) {
                m_parseErrors.fetch_add(1);
                if (item.replay)
                    (void)item.replay->Complete(item.token, false);
                continue;
            }
            EventBus* bus = m_bus.load();
            if (bus == nullptr) {
                if (item.replay)
                    (void)item.replay->Complete(item.token, false);
                continue;
            }
            if (item.replay) {
                const auto replay = item.replay;
                const auto token = item.token;
                event.onConsumed = [replay, token](bool accepted) {
                    (void)replay->Complete(token, accepted);
                };
            }
            /* false reports an evicted older event; this event was accepted. */
            if (!bus->Push(event)) m_busOverflowObserved.fetch_add(1);
            m_pushed.fetch_add(1);
            FILETIME now = {};
            GetSystemTimePreciseAsFileTime(&now);
            m_lastSuccess100ns.store(
                (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                now.dwLowDateTime);
        }
    }

    void StopWorkers() {
        m_stop.store(true);
        m_queueCv.notify_all();
        for (std::thread& worker : m_workers) {
            if (worker.joinable()) worker.join();
        }
        m_workers.clear();
    }

    bool PrepareReplay(const std::shared_ptr<EventLogBookmarkStore>& replay,
                       DWORD& flags, EVT_HANDLE& bookmark,
                       const char* source) {
        std::string error;
        if (!replay->Open(&error) ||
            !replay->PrepareSubscription(flags, bookmark)) {
            m_subscriptionErrors.fetch_add(1);
            if (error.empty()) error = replay->GetStatus().lastError;
            std::fprintf(stderr, "[edr-rdp] %s bookmark unavailable: %s\n",
                         source, error.c_str());
            return false;
        }
        return true;
    }

    std::string ReplayState() const {
        if (!m_sessionReplay && !m_authReplay) return "disabled";
        const auto session = m_sessionReplay ? m_sessionReplay->GetStatus()
            : EventLogBookmarkStore::Status{};
        const auto auth = m_authReplay ? m_authReplay->GetStatus()
            : EventLogBookmarkStore::Status{};
        if (m_sessionReplay && !session.available)
            return EventLogBookmarkStore::StateName(session.state);
        if (m_authReplay && !auth.available)
            return EventLogBookmarkStore::StateName(auth.state);
        if ((m_sessionReplay && session.state == EventLogBookmarkStore::State::Empty) ||
            (m_authReplay && auth.state == EventLogBookmarkStore::State::Empty))
            return EventLogBookmarkStore::StateName(
                EventLogBookmarkStore::State::Empty);
        return EventLogBookmarkStore::StateName(
            EventLogBookmarkStore::State::Ready);
    }

    size_t m_queueCapacity;
    uint32_t m_workerCount;
    DWORD m_maxXmlBytes;
    std::shared_ptr<EventLogBookmarkStore> m_sessionReplay;
    std::shared_ptr<EventLogBookmarkStore> m_authReplay;
    std::atomic<EventBus*> m_bus{nullptr};
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_pullActive{false};
    std::atomic<uint64_t> m_lastSuccess100ns{0};
    EVT_HANDLE m_sessionSub = nullptr;
    EVT_HANDLE m_authSub = nullptr;
    HANDLE m_signalEvent = nullptr;
    std::thread m_pullThread;
    mutable std::mutex m_queueMutex;
    std::condition_variable m_queueCv;
    std::deque<WorkItem> m_queue;
    std::vector<std::thread> m_workers;
    std::atomic<uint64_t> m_rendered{0};
    std::atomic<uint64_t> m_queued{0};
    std::atomic<uint64_t> m_queueDropped{0};
    std::atomic<uint64_t> m_renderErrors{0};
    std::atomic<uint64_t> m_parseErrors{0};
    std::atomic<uint64_t> m_pushed{0};
    std::atomic<uint64_t> m_busOverflowObserved{0};
    std::atomic<uint64_t> m_subscriptionErrors{0};
};

ICollector* CreateRdpCollector(uint32_t queueCapacity, uint32_t workers,
                               uint32_t maxXmlBytes,
                               EventLogReplayOptions replay) {
    return new RdpCollector(queueCapacity, workers, maxXmlBytes,
                             std::move(replay));
}

} // namespace edr
