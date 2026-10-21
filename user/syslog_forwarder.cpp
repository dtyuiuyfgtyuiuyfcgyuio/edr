/*
 * syslog_forwarder.cpp - RFC 5424 syslog forwarding over UDP.
 *
 * Message format (RFC 5424):
 *   <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
 * Example:
 *   <165>1 2026-08-17T12:34:56.789Z workstation edr-agent 1234 EDR-001
 *   [edr@47400 severity="high"] {json payload}
 *
 * Resolve and initialize the UDP transport before reporting startup success.
 * The worker sends each accepted datagram once. Failure is observable and
 * never retries a datagram or blocks the detection thread on network I/O.
 */
#include "syslog_forwarder.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <cstdio>
#include <ctime>

#include "config.h"

#pragma comment(lib, "ws2_32.lib")

namespace edr {

namespace {

/* Bounded per-message size: RFC 5424 has no hard limit, but a typical
 * collector default is 8 KiB; stay under one UDP datagram limit. */
constexpr size_t kMaxDatagram = 8192;
constexpr uint8_t kDefaultFacility = 16; /* local0 */

class WinsockTransport final : public SyslogForwarder::Transport {
public:
    ~WinsockTransport() override { Shutdown(); }

    bool Initialize(const std::string& host, uint16_t port,
                    int& error) noexcept override {
        Shutdown();
        WSADATA data{};
        error = WSAStartup(MAKEWORD(2, 2), &data);
        if (error != 0) return false;
        m_started = true;
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        addrinfo* addresses = nullptr;
        char service[8]{};
        std::snprintf(service, sizeof(service), "%u", static_cast<unsigned>(port));
        error = getaddrinfo(host.c_str(), service, &hints, &addresses);
        if (error != 0) { Shutdown(); return false; }
        if (!addresses || addresses->ai_addrlen != sizeof(m_destination)) {
            if (addresses) freeaddrinfo(addresses);
            error = WSAEADDRNOTAVAIL;
            Shutdown();
            return false;
        }
        m_destination = *reinterpret_cast<const sockaddr_in*>(addresses->ai_addr);
        freeaddrinfo(addresses);
        m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (m_socket == INVALID_SOCKET) {
            error = WSAGetLastError(); Shutdown(); return false;
        }
        const DWORD timeout = 2000;
        if (setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO,
                reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0) {
            error = WSAGetLastError(); Shutdown(); return false;
        }
        error = 0;
        return true;
    }

    bool Send(const std::string& datagram, int& error) noexcept override {
        const int sent = sendto(m_socket, datagram.data(),
            static_cast<int>(datagram.size()), 0,
            reinterpret_cast<const sockaddr*>(&m_destination), sizeof(m_destination));
        error = sent == SOCKET_ERROR ? WSAGetLastError() : 0;
        if (sent != static_cast<int>(datagram.size())) {
            if (!error) error = WSAEMSGSIZE;
            return false;
        }
        return true;
    }

    void Shutdown() noexcept override {
        if (m_socket != INVALID_SOCKET) { closesocket(m_socket); m_socket = INVALID_SOCKET; }
        if (m_started) { WSACleanup(); m_started = false; }
    }

private:
    SOCKET m_socket = INVALID_SOCKET;
    bool m_started = false;
    sockaddr_in m_destination{};
};

std::string NowIso8601Utc() {
    using clock = std::chrono::system_clock;
    std::time_t now = clock::to_time_t(clock::now());
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  clock::now().time_since_epoch()).count() % 1000;
    std::tm tmv = {};
    gmtime_s(&tmv, &now);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                  static_cast<int>(ms));
    return buf;
}

/* Escape a PARAM-VALUE per RFC 5424 SD-ELEMENT rules: backslash, quote
 * and ] must be escaped; control characters are not permitted. */
std::string EscapeSdValue(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (unsigned char c : value) {
        if (c == '"' || c == '\\' || c == ']') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20 || c == 0x7f) {
            out += ' ';
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

/* Truncate for display, keeping the JSON payload useful. */
std::string Truncate(const std::string& text, size_t maxBytes) {
    if (text.size() <= maxBytes) return text;
    return text.substr(0, maxBytes) + "...";
}

} // namespace

SyslogForwarder::SyslogForwarder(std::string host, uint16_t port,
                                 uint8_t facility, std::string hostname,
                                 size_t cacheLimit, std::unique_ptr<Transport> transport)
    : m_host(std::move(host)), m_port(port),
      m_facility(facility > 23 ? kDefaultFacility : facility),
      m_hostname(std::move(hostname)), m_cacheLimit(cacheLimit),
      m_transport(transport ? std::move(transport) : std::make_unique<WinsockTransport>()) {
    m_stats.capacity = cacheLimit;
}

SyslogForwarder::~SyslogForwarder() {
    Stop();
}

int SyslogForwarder::SeverityToSyslog(const std::string& severity) {
    if (severity == "critical") return 2; /* crit */
    if (severity == "high") return 3;     /* err */
    if (severity == "medium") return 4;   /* warning */
    if (severity == "low") return 5;      /* notice */
    return 6;                             /* info */
}

std::string SyslogForwarder::BuildMessage(uint8_t facility, int severity,
                                          const std::string& timestampIso8601,
                                          const std::string& hostname,
                                          const std::string& ruleId,
                                          const std::string& message) {
    if (severity < 0 || severity > 7) severity = 6;
    int pri = static_cast<int>(facility) * 8 + severity;
    std::string host = hostname.empty() ? "-" : hostname;
    std::string app = "edr-agent";
    std::string procid = "-";
    std::string msgid = ruleId.empty() ? "-" : ruleId;
    /* Trim the message and drop embedded newlines (syslog is line based). */
    std::string msg = message;
    for (char& c : msg) {
        if (c == '\n' || c == '\r') c = ' ';
    }
    msg = Truncate(msg, kMaxDatagram - 256);

    return "<" + std::to_string(pri) + ">1 " + timestampIso8601 + " " +
           host + " " + app + " " + procid + " " + msgid +
           " [edr@47400 severity=\"" +
           EscapeSdValue(severity == 2 ? "critical"
                         : severity == 3 ? "high"
                         : severity == 4 ? "medium"
                         : severity == 5 ? "low" : "info") +
           "\"] " + msg;
}

bool SyslogForwarder::Start() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_thread.joinable()) return m_stats.state == "running";
        m_stats.state = "starting";
        m_stats.lastError = 0;
    }
    int error = 0;
    const bool configured = !m_host.empty() && m_host.find('\0') == std::string::npos && m_port != 0;
    if (!configured || !m_transport->Initialize(m_host, m_port, error)) {
        m_transport->Shutdown();
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.state = "start_failed";
        ++m_stats.startFailures;
        m_stats.lastError = error ? error : WSAEINVAL;
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_stop = false;
    try {
        m_thread = std::thread(&SyslogForwarder::WorkerLoop, this);
    } catch (...) {
        m_stop = true;
        m_transport->Shutdown();
        m_stats.state = "start_failed";
        ++m_stats.startFailures;
        m_stats.lastError = WSA_NOT_ENOUGH_MEMORY;
        return false;
    }
    m_stats.state = "running";
    m_stats.running = true;
    return true;
}

void SyslogForwarder::Stop() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_thread.joinable()) {
            return;
        }
        m_stop = true;
        m_stats.state = "stopping";
    }
    m_cv.notify_all();
    if (m_thread.joinable()) {
        m_thread.join();
    }
    m_transport->Shutdown();
    std::lock_guard<std::mutex> lock(m_mutex);
    m_stats.state = "stopped";
}

bool SyslogForwarder::Enqueue(const std::string& severity,
                              const std::string& ruleId,
                              const std::string& message) {
    std::string line = BuildMessage(m_facility, SeverityToSyslog(severity),
                                    NowIso8601Utc(), m_hostname, ruleId,
                                    message);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stop || m_stats.state != "running" || m_cacheLimit == 0) {
            ++m_stats.rejected;
            return false;
        }
        if (m_queue.size() + m_stats.inflight >= m_cacheLimit) {
            if (m_queue.empty()) {
                ++m_stats.rejected;
                return false;
            }
            m_queue.pop_front();
            ++m_stats.dropped;
        }
        m_queue.push_back(std::move(line));
        ++m_stats.enqueued;
    }
    m_cv.notify_one();
    return true;
}

SyslogForwarder::Stats SyslogForwarder::GetStatsSnapshot() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    Stats stats = m_stats;
    stats.pending = m_queue.size();
    return stats;
}

void SyslogForwarder::WorkerLoop() {
    for (;;) {
        std::string item;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] {
                return m_stop || !m_queue.empty();
            });
            if (m_stop && m_queue.empty()) {
                m_stats.running = false;
                break;
            }
            item = std::move(m_queue.front());
            m_queue.pop_front();
            m_stats.inflight = 1;
        }
        int error = 0;
        const bool sent = m_transport->Send(item, error);
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stats.inflight = 0;
            if (sent) ++m_stats.sent;
            else ++m_stats.failed;
            m_stats.lastError = sent ? 0 : error;
        }
    }

}

} // namespace edr
