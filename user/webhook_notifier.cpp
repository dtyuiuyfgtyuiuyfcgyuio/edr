#include "webhook_notifier.h"

#include <windows.h>
#include <winhttp.h>

#include <chrono>
#include <cstdio>

#include "json_lite.h"

namespace edr {

namespace {

constexpr uint32_t kDefaultTimeoutSeconds = 5;
/* Hard cap so a bad config value cannot overflow timeoutMs arithmetic. */
constexpr uint32_t kMaxTimeoutSeconds = 3600;
/* One stderr line per failure window, at most (anti log-flood). */
constexpr uint64_t kFailureLogIntervalMs = 30000;
/* Destructor drain deadline: shutdown latency beats delivery completeness. */
constexpr uint64_t kDrainDeadlineMs = 5000;
const char kContentType[] = "application/json";

/* Local UTF-8 -> UTF-16 helper (deliberately not the config.h one: this
 * module stays linkable without config.cpp). Empty result on invalid input;
 * callers already treat an empty url as an error. */
std::wstring Utf8ToWideChars(const std::string& utf8) {
    if (utf8.empty() || utf8.size() > 32768) return std::wstring();
    const int bytes = static_cast<int>(utf8.size());
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     utf8.c_str(), bytes, nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring wide(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.c_str(), bytes,
                        &wide[0], needed);
    return wide;
}

uint64_t SteadyNowMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

std::string NowIso8601Utc() {
    FILETIME ft = {};
    GetSystemTimeAsFileTime(&ft);
    SYSTEMTIME st = {};
    if (!FileTimeToSystemTime(&ft, &st)) {
        return "1970-01-01T00:00:00.000Z";
    }
    char buf[32] = {};
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                  st.wSecond, st.wMilliseconds);
    return buf;
}

std::string LocalHostName() {
    char nameBuf[256] = {};
    DWORD nameLen = (DWORD)sizeof(nameBuf);
    if (!GetComputerNameA(nameBuf, &nameLen) || nameLen == 0) {
        return "unknown-host";
    }
    return std::string(nameBuf, nameLen);
}

/* Production transport: single WinHTTP POST, timeouts taken from timeoutMs.
 * Any failure returns false with a reason in *err. No response body is read
 * and no status semantics beyond 2xx-OK are validated. */
bool WinHttpPostJson(const std::string& url, const std::string& contentType,
                     const std::string& body, uint32_t timeoutMs,
                     std::string* err) {
    auto fail = [err](const char* what) {
        if (err != nullptr) {
            *err = std::string(what) + " failed (error " +
                   std::to_string(GetLastError()) + ")";
        }
        return false;
    };

    std::wstring wide = Utf8ToWideChars(url);
    if (wide.empty()) {
        if (err != nullptr) *err = "url is not valid UTF-8";
        return false;
    }

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {};
    wchar_t path[2048] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = (DWORD)(sizeof(host) / sizeof(host[0]));
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = (DWORD)(sizeof(path) / sizeof(path[0]));
    if (!WinHttpCrackUrl(wide.c_str(), 0, 0, &uc)) {
        return fail("WinHttpCrackUrl");
    }

    HINTERNET session = WinHttpOpen(L"edr-agent/0.1",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) {
        return fail("WinHttpOpen");
    }
    WinHttpSetTimeouts(session, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (connect == nullptr) {
        WinHttpCloseHandle(session);
        return fail("WinHttpConnect");
    }
    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path, nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           flags);
    if (request == nullptr) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return fail("WinHttpOpenRequest");
    }

    bool ok = false;
    std::wstring headers =
        L"Content-Type: " + Utf8ToWideChars(contentType) + L"\r\n";
    if (!WinHttpSendRequest(request, headers.c_str(), (DWORD)-1,
                            (LPVOID)body.data(), (DWORD)body.size(),
                            (DWORD)body.size(), 0)) {
        fail("WinHttpSendRequest"); /* sets *err, returns false */
    } else if (!WinHttpReceiveResponse(request, nullptr)) {
        fail("WinHttpReceiveResponse");
    } else {
        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        if (!WinHttpQueryHeaders(request,
                                 WINHTTP_QUERY_STATUS_CODE |
                                     WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &status,
                                 &statusSize, WINHTTP_NO_HEADER_INDEX)) {
            fail("WinHttpQueryHeaders");
        } else {
            ok = status >= 200 && status < 300;
            if (!ok && err != nullptr) {
                *err = "HTTP status " + std::to_string(status);
            }
        }
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return ok;
}

} // namespace

WebhookNotifier::WebhookNotifier(bool enabled, std::string url,
                                 uint32_t timeoutSeconds, size_t queueCapacity)
    : WebhookNotifier(enabled, std::move(url), timeoutSeconds, queueCapacity,
                      TransportFn{}) {}

WebhookNotifier::WebhookNotifier(bool enabled, std::string url,
                                 uint32_t timeoutSeconds, size_t queueCapacity,
                                 TransportFn transport)
    : m_enabled(enabled),
      m_url(std::move(url)),
      m_timeoutMs(timeoutSeconds == 0
                      ? kDefaultTimeoutSeconds * 1000
                      : (timeoutSeconds > kMaxTimeoutSeconds
                             ? kMaxTimeoutSeconds * 1000
                             : timeoutSeconds * 1000)),
      m_capacity(queueCapacity == 0 ? 1 : queueCapacity),
      m_transport(std::move(transport)) {
    if (!m_transport) {
        m_transport = WinHttpPostJson;
    }
    /* Disabled or unconfigured instances never start a worker: Notify is a
     * no-op, so the thread would idle forever for nothing. */
    if (m_enabled && !m_url.empty()) {
        m_thread = std::thread(&WebhookNotifier::WorkerLoop, this);
    }
}

WebhookNotifier::~WebhookNotifier() {
    {
        /* Lock ordering with Notify(): whoever takes the mutex second sees
         * a consistent (stopped, fully enqueued) state. */
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stop.store(true);
    }
    m_cv.notify_all();
    if (m_thread.joinable()) {
        m_thread.join(); /* worker drains (bounded) before exiting */
    }
}

size_t WebhookNotifier::QueuedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.size();
}

void WebhookNotifier::Notify(const std::string& alertJson) {
    if (!m_enabled || m_url.empty()) return; /* silent no-op per contract */
    /* Envelope is built on the caller thread (cheap string work only) so the
     * queued item is final and its timestamp reflects alert emission time. */
    std::string envelope = BuildEnvelope(alertJson);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stop.load(std::memory_order_relaxed)) {
            /* Shutdown already began: nothing will drain this item. */
            m_dropped.fetch_add(1);
            return;
        }
        if (m_queue.size() >= m_capacity) {
            /* House drop semantics (EventBus::Push / Reporter::Enqueue):
             * evict the stalest item, always admit the newest. */
            m_queue.pop_front();
            m_dropped.fetch_add(1);
        }
        m_queue.push_back(std::move(envelope));
    }
    m_cv.notify_one();
}

std::string WebhookNotifier::BuildEnvelope(const std::string& alertJson) {
    std::string envelope = "{\"kind\":\"alert\",\"source\":\"edr-agent\",\"host\":\"";
    envelope += jsonlite::escape(LocalHostName());
    envelope += "\",\"ts\":\"";
    envelope += NowIso8601Utc();
    envelope += "\",";
    const size_t first = alertJson.find_first_not_of(" \t\r\n");
    if (first != std::string::npos && alertJson[first] == '{') {
        envelope += "\"alert\":";
        envelope += alertJson; /* embedded verbatim */
    } else {
        /* Not an object: escape it into a string field instead. */
        envelope += "\"alert_raw\":\"";
        envelope += jsonlite::escape(alertJson);
        envelope += "\"";
    }
    envelope += "}";
    return envelope;
}

void WebhookNotifier::LogFailure(const std::string& err) {
    const uint64_t nowMs = SteadyNowMs();
    uint64_t last = m_lastFailLogMs.load(std::memory_order_relaxed);
    /* 0 sentinel = never logged yet (steady clock may read < interval right
     * after boot, so the sentinel is checked explicitly). */
    if (last != 0 && nowMs - last < kFailureLogIntervalMs) return;
    if (!m_lastFailLogMs.compare_exchange_strong(last, nowMs)) return;
    std::fprintf(stderr, "[webhook] delivery failed (url=%s): %s\n",
                 m_url.c_str(), err.c_str());
}

void WebhookNotifier::WorkerLoop() {
    bool draining = false;
    std::chrono::steady_clock::time_point drainDeadline{};
    for (;;) {
        std::string envelope;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [&] { return m_stop.load() || !m_queue.empty(); });
            if (m_stop.load()) {
                if (!draining) {
                    draining = true;
                    drainDeadline = std::chrono::steady_clock::now() +
                                    std::chrono::milliseconds(kDrainDeadlineMs);
                }
                if (m_queue.empty()) return; /* fully drained */
                if (std::chrono::steady_clock::now() >= drainDeadline) {
                    /* Deadline exceeded: abandon the rest, keep the books
                     * honest (these were never delivered). */
                    m_dropped.fetch_add(m_queue.size());
                    m_queue.clear();
                    return;
                }
            } else if (m_queue.empty()) {
                continue;
            }
            envelope = std::move(m_queue.front());
            m_queue.pop_front();
        }
        /* Transport I/O strictly outside the mutex. */
        bool ok = false;
        std::string err;
        try {
            ok = m_transport(m_url, kContentType, envelope, m_timeoutMs, &err);
        } catch (const std::exception& e) {
            ok = false;
            err = std::string("transport exception: ") + e.what();
        } catch (...) {
            ok = false;
            err = "transport exception";
        }
        if (ok) {
            m_delivered.fetch_add(1);
        } else {
            /* No retry by design: count, log (rate limited), move on. */
            m_failed.fetch_add(1);
            LogFailure(err);
        }
    }
}

} // namespace edr
