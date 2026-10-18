/*
 * syslog_forwarder.cpp - RFC 5424 syslog forwarding over UDP.
 *
 * Message format (RFC 5424):
 *   <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
 * Example:
 *   <165>1 2026-08-17T12:34:56.789Z workstation edr-agent 1234 EDR-001
 *   [edr@47400 severity="high"] {json payload}
 *
 * The UDP socket is created lazily per flush batch and is non-persistent:
 * a failed send never blocks or retries the datagram (UDP is
 * fire-and-forget), matching the "telemetry must never stall detection"
 * invariant.
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
                                 size_t cacheLimit)
    : m_host(std::move(host)), m_port(port),
      m_facility(facility > 23 ? kDefaultFacility : facility),
      m_hostname(std::move(hostname)), m_cacheLimit(cacheLimit) {}

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
    if (m_host.empty() || m_port == 0) {
        return false;
    }
    m_stop.store(false);
    m_thread = std::thread(&SyslogForwarder::WorkerLoop, this);
    return true;
}

void SyslogForwarder::Stop() {
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

void SyslogForwarder::Enqueue(const std::string& severity,
                              const std::string& ruleId,
                              const std::string& message) {
    std::string line = BuildMessage(m_facility, SeverityToSyslog(severity),
                                    NowIso8601Utc(), m_hostname, ruleId,
                                    message);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.size() >= m_cacheLimit) {
            m_queue.pop_front();
            m_dropped.fetch_add(1);
        }
        m_queue.push_back(std::move(line));
    }
    m_cv.notify_one();
}

bool SyslogForwarder::Send(const std::string& datagram) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return false;
    }
    /* Bound the send so a stuck collector cannot stall the worker. */
    DWORD sendTimeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
               (const char*)&sendTimeout, sizeof(sendTimeout));

    sockaddr_in dest = {};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(m_port);
    if (inet_pton(AF_INET, m_host.c_str(), &dest.sin_addr) != 1) {
        /* Not a literal IPv4 address: resolve the host name. */
        struct addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        struct addrinfo* result = nullptr;
        if (getaddrinfo(m_host.c_str(), nullptr, &hints, &result) == 0 &&
            result != nullptr) {
            for (struct addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
                if (ai->ai_family == AF_INET) {
                    dest.sin_addr =
                        reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr;
                    break;
                }
            }
            freeaddrinfo(result);
        }
        if (dest.sin_addr.s_addr == INADDR_NONE ||
            dest.sin_addr.s_addr == 0) {
            closesocket(sock);
            return false;
        }
    }

    int sent = sendto(sock, datagram.data(),
                      static_cast<int>(datagram.size()), 0,
                      (const sockaddr*)&dest, sizeof(dest));
    closesocket(sock);
    return sent == static_cast<int>(datagram.size());
}

void SyslogForwarder::WorkerLoop() {
    WSADATA wsaData = {};
    bool wsaStarted = WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
    if (!wsaStarted) {
        std::fprintf(stderr, "[edr] syslog: WSAStartup failed; forwarder idle\n");
    }

    for (;;) {
        std::string item;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] {
                return m_stop.load() || !m_queue.empty();
            });
            if (m_stop.load() && m_queue.empty()) {
                break;
            }
            item = std::move(m_queue.front());
            m_queue.pop_front();
        }
        if (!wsaStarted) continue;
        if (Send(item)) {
            m_sent.fetch_add(1);
        } else {
            m_failed.fetch_add(1);
        }
    }

    if (wsaStarted) {
        WSACleanup();
    }
}

} // namespace edr
