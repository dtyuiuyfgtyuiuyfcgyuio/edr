/*
 * alerter.h - Alert sink. Single-threaded owner of alerts.jsonl (one JSON
 * object per line). Optionally mirrors alerts to the Windows Event Log;
 * Event Log failure is never fatal and never blocks file writes (M4).
 */
#ifndef EDR_ALERTER_H
#define EDR_ALERTER_H

#include <atomic>
#include <functional>
#include <mutex>
#include <string>

#include "rule_engine.h"

namespace edr {

class Alerter {
public:
    /* Testable append boundary: return true only after the complete line and
     * its newline have been flushed. On failure, set a useful error string;
     * a false result latches this instance. Recover the ledger, then construct
     * a new Alerter to retry opening it. */
    using AppendFunction =
        std::function<bool(const std::string& line, std::string& error)>;

    struct WriteStatus {
        bool writable = false;
        uint64_t writeFailures = 0;
        uint64_t chainSequence = 0;
        std::string lastError;
    };

    Alerter(std::string alertsPath, bool redact, bool useEventLog,
            AppendFunction appendFunction = {});
    ~Alerter();

    bool Open(); /* false: file could not be opened (eventlog may still work) */
    void OnAlert(const Alert& alert);
    void Close();
    WriteStatus GetWriteStatus() const;

    /* Registers an out-of-process notification sink (e.g. webhook). The sink
     * is invoked at the end of OnAlert, outside the file mutex, with exactly
     * the JSON line that was persisted to alerts.jsonl (chain fields
     * included; identical to the Event Log payload). Sink failures are
     * contained here: a throwing sink never escapes OnAlert (the sink runs
     * on the event consumer thread), is counted, and logs once; the write
     * path is never blocked or failed by the sink. Register before
     * Open()/first OnAlert so no alert can race the setup. */
    void SetSink(std::function<void(const std::string& alertJson)> sink);

    static std::string Redact(const std::string& text);

private:
    void WriteEventLog(const std::string& line, const std::string& severity);

    std::string m_path;
    bool m_redact;
    bool m_useEventLog;
    AppendFunction m_appendFunction;
    void* m_fileHandle = nullptr; /* HANDLE; kept opaque in this header. */
    mutable std::mutex m_mutex;
    void* m_eventSource = nullptr; /* HANDLE */
    uint64_t m_chainSeq = 0;
    std::string m_chainPrev = std::string(64, '0');
    bool m_opened = false;
    bool m_writeFailed = false;
    uint64_t m_writeFailures = 0;
    std::string m_lastWriteError;
    bool ResumeChain();
    /* Optional alert sink (webhook notifier); called with the persisted
     * JSONL line at the end of OnAlert, outside the mutex. */
    std::function<void(const std::string& alertJson)> m_sink;
    /* Sink exceptions contained at the call site; first failure logs. */
    std::atomic<uint64_t> m_sinkFailures{0};
};

/* Serialize an alert + event to one JSON line (UTF-8). */
std::string AlertToJsonLine(const Alert& alert, bool redact);
std::string EventToJsonLine(const Event& event, bool redact);

} // namespace edr

#endif /* EDR_ALERTER_H */
