/*
 * syslog_forwarder.h - Optional RFC 5424 syslog forwarder (OFF by default).
 * When enabled, a dedicated thread sends alert JSON messages to a remote
 * syslog collector over UDP. Fire-and-forget semantics: send failures are
 * counted (UDP has no delivery guarantees), with a bounded pending + in-flight
 * queue (default 1000). Start/Stop are serialized by the owner; Enqueue and
 * snapshots may run concurrently. Successful sends mean local UDP acceptance.
 */
#ifndef EDR_SYSLOG_FORWARDER_H
#define EDR_SYSLOG_FORWARDER_H

#include <cstdint>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <memory>
#include <string>
#include <thread>

namespace edr {

class SyslogForwarder {
public:
    struct Stats {
        std::string state = "not_started";
        bool running = false;
        size_t pending = 0;
        size_t inflight = 0;
        size_t capacity = 0;
        uint64_t enqueued = 0;
        uint64_t sent = 0;
        uint64_t failed = 0;
        uint64_t dropped = 0;
        uint64_t rejected = 0;
        uint64_t startFailures = 0;
        int lastError = 0;
    };

    // Initialize/Shutdown run on the owner; Send runs on the worker.
    class Transport {
    public:
        virtual ~Transport() = default;
        virtual bool Initialize(const std::string& host, uint16_t port,
                                int& error) noexcept = 0;
        virtual bool Send(const std::string& datagram, int& error) noexcept = 0;
        virtual void Shutdown() noexcept = 0;
    };

    SyslogForwarder(std::string host, uint16_t port, uint8_t facility,
                    std::string hostname, size_t cacheLimit = 1000,
                    std::unique_ptr<Transport> transport = {});
    ~SyslogForwarder();

    bool Start();
    void Stop();
    bool Enqueue(const std::string& severity, const std::string& ruleId,
                 const std::string& message);
    Stats GetStatsSnapshot() const;

    /* Map an EDR severity name to an RFC 5424 severity (0..7). */
    static int SeverityToSyslog(const std::string& severity);

    /* Build one RFC 5424 message (exposed for tests). */
    static std::string BuildMessage(uint8_t facility, int severity,
                                    const std::string& timestampIso8601,
                                    const std::string& hostname,
                                    const std::string& ruleId,
                                    const std::string& message);

private:
    void WorkerLoop();

    std::string m_host;
    uint16_t m_port;
    uint8_t m_facility;
    std::string m_hostname;
    size_t m_cacheLimit;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<std::string> m_queue;
    std::thread m_thread;
    bool m_stop = true;
    Stats m_stats;
    std::unique_ptr<Transport> m_transport;
};

} // namespace edr

#endif /* EDR_SYSLOG_FORWARDER_H */
