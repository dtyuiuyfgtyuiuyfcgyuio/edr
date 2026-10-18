#include "reporter.h"

#include <windows.h>
#include <winhttp.h>

#include <chrono>
#include <exception>
#include <utility>

#include "config.h"

namespace edr {

std::string EventReporterUrl(const std::string& alertUrl) {
    constexpr char kAlertPath[] = "/ingest";
    constexpr char kEventSuffix[] = "/events";
    const size_t fragment = alertUrl.find('#');
    /* Config rejects fragments: never reinterpret one as part of a route. */
    if (fragment != std::string::npos) return alertUrl;
    const size_t query = alertUrl.find('?');
    const size_t pathEnd = query == std::string::npos ? alertUrl.size() : query;
    const size_t alertPathLength = sizeof(kAlertPath) - 1;
    if (pathEnd < alertPathLength ||
        alertUrl.compare(pathEnd - alertPathLength, alertPathLength,
                         kAlertPath) != 0) {
        return alertUrl;
    }
    return alertUrl.substr(0, pathEnd) + kEventSuffix + alertUrl.substr(pathEnd);
}

Reporter::Reporter(std::string url, std::string apiKey, size_t cacheLimit,
                   PostFn postFn, ReporterSpoolOptions spoolOptions)
    : m_url(std::move(url)), m_apiKey(std::move(apiKey)),
      m_cacheLimit(cacheLimit), m_postFn(std::move(postFn)) {
    if (!spoolOptions.directory.empty())
        m_spool.reset(new ReporterSpool(std::move(spoolOptions), m_url));
}

Reporter::~Reporter() {
    Stop();
}

bool Reporter::Start() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_url.empty() && !m_postFn) {
        if (m_spool) m_spool->SetFailed("Reporter endpoint is not configured");
        m_runtimeState = RuntimeState::StartFailed;
        return false;
    }
    if (m_thread.joinable()) return false;
    if (m_spool && !m_spoolReady) {
        std::vector<ReporterSpoolItem> recovered;
        if (!m_spool->Open(recovered)) {
            m_runtimeState = RuntimeState::StartFailed;
            return false;
        }
        if (recovered.size() > m_cacheLimit) {
            m_spool->SetFailed("recovered backlog exceeds Reporter cache limit");
            m_runtimeState = RuntimeState::StartFailed;
            return false;
        }
        for (auto& saved : recovered) {
            m_pending.push_back(QueueItem{std::move(saved.id), std::move(saved.body)});
        }
        m_spoolReady = true;
    }
    if (m_spool && m_spool->GetStatus() != "ready") {
        m_runtimeState = RuntimeState::StartFailed;
        return false;
    }
    m_stop.store(false);
    try {
        m_thread = std::thread(&Reporter::WorkerLoop, this);
    } catch (const std::exception& error) {
        if (m_spool) m_spool->SetFailed(
            std::string("could not start Reporter worker: ") + error.what());
        m_runtimeState = RuntimeState::StartFailed;
        return false;
    } catch (...) {
        if (m_spool) m_spool->SetFailed("could not start Reporter worker");
        m_runtimeState = RuntimeState::StartFailed;
        return false;
    }
    m_startSucceeded = true;
    m_runtimeState = RuntimeState::Started;
    return true;
}

void Reporter::Stop() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_thread.joinable()) {
            m_startSucceeded = false;
            if (m_runtimeState != RuntimeState::StartFailed)
                m_runtimeState = RuntimeState::Stopped;
            return;
        }
        m_stop.store(true);
        m_runtimeState = RuntimeState::Stopping;
    }
    m_cv.notify_all();
    if (m_thread.joinable()) {
        m_thread.join();
    }
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_startSucceeded = false;
        m_runtimeState = RuntimeState::Stopped;
    }
}

bool Reporter::Enqueue(std::string jsonLine) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_runtimeState == RuntimeState::StartFailed ||
            m_runtimeState == RuntimeState::WorkerFailed ||
            m_runtimeState == RuntimeState::Stopping ||
            m_runtimeState == RuntimeState::Stopped) {
            m_dropped.fetch_add(1);
            return false;
        }
        const size_t count = m_pending.size() + (m_inFlight ? 1U : 0U);
        if (m_spool) {
            if (!m_startSucceeded || !m_spoolReady ||
                m_spool->GetStatus() != "ready") {
                m_dropped.fetch_add(1);
                return false;
            }
            if (m_cacheLimit == 0 || count >= m_cacheLimit) {
                m_dropped.fetch_add(1);
                return false;
            }
            ReporterSpoolItem saved;
            if (!m_spool->Store(jsonLine, saved)) {
                m_dropped.fetch_add(1);
                return false;
            }
            m_pending.push_back(QueueItem{std::move(saved.id),
                                          std::move(saved.body)});
            m_cv.notify_one();
            return true;
        }
        if (m_cacheLimit == 0) {
            m_dropped.fetch_add(1);
            return false;
        }
        if (count >= m_cacheLimit) {
            if (!m_pending.empty()) {
                m_pending.pop_front();
                m_dropped.fetch_add(1);
            } else {
                /* An in-flight request is the only retained item. Keep its
                 * identity stable and discard the new arrival. */
                m_dropped.fetch_add(1);
                return false;
            }
        }
        m_pending.push_back(QueueItem{std::to_string(m_nextId++),
                                      std::move(jsonLine)});
    }
    m_cv.notify_one();
    return true;
}

std::string Reporter::GetSpoolStatus() const {
    return m_spool ? m_spool->GetStatus() : "disabled";
}

uint64_t Reporter::SpoolErrorCount() const noexcept {
    return m_spool ? m_spool->ErrorCount() : 0;
}

size_t Reporter::QueuedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pending.size() + (m_inFlight ? 1U : 0U);
}

std::string Reporter::GetRuntimeState() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    switch (m_runtimeState) {
    case RuntimeState::NotStarted: return "not_started";
    case RuntimeState::Started: return "started";
    case RuntimeState::StartFailed: return "start_failed";
    case RuntimeState::WorkerFailed: return "worker_failed";
    case RuntimeState::Stopping: return "stopping";
    case RuntimeState::Stopped: return "stopped";
    }
    return "unavailable";
}

uint32_t Reporter::NextBackoff(uint32_t current) {
    uint32_t next = current == 0 ? 1000 : current * 2;
    return next > 60000 ? 60000 : next;
}

bool Reporter::Post(const std::string& body) {
    std::wstring url = Utf8ToWide(m_url);

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = (DWORD)std::size(host);
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = (DWORD)std::size(path);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) {
        return false;
    }

    HINTERNET session = WinHttpOpen(L"edr-agent/0.1",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) {
        return false;
    }
    bool ok = false;
    WinHttpSetTimeouts(session, 5000, 5000, 5000, 5000);

    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (connect != nullptr) {
        DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS)
            ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET request = WinHttpOpenRequest(connect, L"POST", path,
                                               nullptr, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               flags);
        if (request != nullptr) {
            std::wstring headers = L"Content-Type: application/json\r\n";
            if (!m_apiKey.empty()) {
                headers += L"X-API-Key: " + Utf8ToWide(m_apiKey) + L"\r\n";
            }
            if (WinHttpSendRequest(request, headers.c_str(), (DWORD)-1,
                                   (LPVOID)body.data(), (DWORD)body.size(),
                                   (DWORD)body.size(), 0) &&
                WinHttpReceiveResponse(request, nullptr)) {
                DWORD status = 0;
                DWORD statusSize = sizeof(status);
                WinHttpQueryHeaders(request,
                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                    WINHTTP_NO_HEADER_INDEX);
                ok = status >= 200 && status < 300;
            }
            WinHttpCloseHandle(request);
        }
        WinHttpCloseHandle(connect);
    }
    WinHttpCloseHandle(session);
    return ok;
}

void Reporter::WorkerLoop() {
    uint32_t backoff = 0;
    for (;;) {
        QueueItem item{};
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            if (m_inFlight) {
                if (backoff != 0) {
                    m_cv.wait_for(lock, std::chrono::milliseconds(backoff),
                                  [&] { return m_stop.load(); });
                }
                if (m_stop.load()) return;
            } else {
                m_cv.wait(lock, [&] {
                    return m_stop.load() || !m_pending.empty();
                });
                if (m_stop.load()) return;
                m_inFlight = std::move(m_pending.front());
                m_pending.pop_front();
                backoff = 0;
            }
            item = *m_inFlight;
        }

        bool posted = false;
        try {
            posted = m_postFn ? m_postFn(item.body) : Post(item.body);
        } catch (...) {
            /* A transport exception is a failed POST; preserve the same
             * in-flight item for the next attempt. */
            posted = false;
        }
        if (posted) {
            if (m_spool && !m_spool->Acknowledge(item.id)) {
                /* The receiver accepted the request, but durable deletion did
                 * not complete. Keep this exact item in flight and stop the
                 * worker; replay after restart is at-least-once. */
                std::lock_guard<std::mutex> lock(m_mutex);
                m_startSucceeded = false;
                m_runtimeState = RuntimeState::WorkerFailed;
                return;
            }
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_inFlight && m_inFlight->id == item.id) {
                m_inFlight.reset();
            }
            backoff = 0;
        } else {
            backoff = NextBackoff(backoff);
        }
    }
}

} // namespace edr
