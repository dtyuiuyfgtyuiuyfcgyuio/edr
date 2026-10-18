/*
 * syslog_forwarder.h - Optional RFC 5424 syslog forwarder (OFF by default).
 * When enabled, a dedicated thread sends alert JSON messages to a remote
 * syslog collector over UDP. Fire-and-forget semantics: send failures are
 * dropped (UDP has no delivery guarantees), with a bounded queue (<=1000
 * entries, overflow dropped) so the detection path never blocks.
 */
#ifndef EDR_SYSLOG_FORWARDER_H
#define EDR_SYSLOG_FORWARDER_H

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

namespace edr {

class SyslogForwarder {
public:
    SyslogForwarder(std::string host, uint16_t port, uint8_t facility,
                    std::string hostname, size_t cacheLimit = 1000);
    ~SyslogForwarder();

    bool Start();
    void Stop();
    void Enqueue(const std::string& severity, const std::string& ruleId,
                 const std::string& message);

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
    bool Send(const std::string& datagram);

    std::string m_host;
    uint16_t m_port;
    uint8_t m_facility;
    std::string m_hostname;
    size_t m_cacheLimit;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<std::string> m_queue;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<uint64_t> m_dropped{0};
    std::atomic<uint64_t> m_sent{0};
    std::atomic<uint64_t> m_failed{0};
};

} // namespace edr

#endif /* EDR_SYSLOG_FORWARDER_H */
