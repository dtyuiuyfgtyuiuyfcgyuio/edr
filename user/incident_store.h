/*
 * incident_store.h - Durable sink for correlated incidents (incidents.jsonl).
 *
 * The CorrelationEngine folds alerts into incidents and hands finished ones to
 * a callback. Without this store that callback could only log to stderr, so an
 * incident vanished the moment the process exited and nothing downstream (the
 * Web console) could ever show the kill chain.
 *
 * The store owns exactly one file: one JSON object per line, one line per
 * *state change* of an incident. Two record kinds are written:
 *   {"kind":"incident", ...IncidentToJson shape...}  a closed incident
 *   {"kind":"open", ...}                             first sighting
 * The open record lets a console show a chain that is still unfolding, and the
 * closed record supersedes it; replaying the file in order rebuilds the latest
 * state of every incident without any in-memory index on disk.
 *
 * Conventions mirror the Alerter: append-only, line-buffered JSON, flushed on
 * every write so a crash loses at most the record in flight, write failures are
 * never fatal to detection. On Windows the store requires a verified protected
 * owner-only DACL before replay or append; it fails closed if that policy cannot
 * be applied. A retained handle also prevents the path from being replaced
 * while the append stream is open.
 *
 * Thread-safety: guarded by a mutex. The EventBus consumer thread writes; a
 * future periodic flusher may too.
 */
#ifndef EDR_INCIDENT_STORE_H
#define EDR_INCIDENT_STORE_H

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <windows.h>

#include "correlation_engine.h"

namespace edr {

class IncidentStore {
public:
    using ProtectFileFn = std::function<bool(HANDLE)>;
    /* Called with the retained ACL-verified handle and one complete JSONL
     * record including its final newline. Returning true means the full line
     * was appended and flushed. */
    using AppendFn = std::function<bool(HANDLE, const std::string&)>;

    struct WriteStatus {
        bool enabled = false;
        bool open = false;
        bool writable = false;
        bool truncated = false;
        uint64_t writeFailures = 0;
        uint64_t dropped = 0;
        uint64_t chainSequence = 0;
        std::string lastError;
    };

    /* `path` empty disables persistence (Enabled() == false). `redact`
     * follows the Agent-wide redaction switch so incident records never leak
     * more than alert records do. */
    IncidentStore(std::string path, bool redact, size_t maxRecords,
                  ProtectFileFn protectFile = {}, AppendFn append = {});

    /* Opens and retains the append handle after validating recovery state
     * and, on Windows, applying and verifying the protected owner-only DACL.
     * Returns false when recovery, protection, or opening fails; the caller
     * decides whether that is fatal. A disabled store's Open() returns true
     * (nothing to do is not an error). */
    bool Open();
    ~IncidentStore();
    void Close();

    bool Enabled() const { return !m_path.empty(); }
    const std::string& Path() const { return m_path; }

    /* Record an incident that is still accumulating alerts. */
    void OnIncidentOpened(const Incident& incident);

    /* Record a closed (or rolled-up) incident. This is the record a console
     * should prefer when both are present for one incident id. */
    void OnIncidentClosed(const Incident& incident);

    /* Records written by this object instance. maxRecords is a per-instance
     * append cap; reopening with a new instance verifies the full existing
     * chain and starts a fresh per-instance allowance. */
    size_t RecordCount() const;
    /* True once a per-instance cap has actually dropped at least one record. */
    bool Truncated() const;
    /* Returns one mutex-protected snapshot for health reporting. */
    WriteStatus GetWriteStatus() const;

private:
    void Write(const std::string& kind, const Incident& incident);
    bool OpenWithRestrictedAcl();
    void CloseAclHandle();

    std::string m_path;
    bool m_redact;
    size_t m_maxRecords;
    size_t m_recordCount = 0;
    bool m_truncated = false;
    bool m_reportedTruncation = false;
#if !defined(_WIN32)
    std::ofstream m_file;
#endif
    mutable std::mutex m_mutex;
    ProtectFileFn m_protectFile;
    AppendFn m_append;
    HANDLE m_aclHandle = INVALID_HANDLE_VALUE;
    bool m_writeFailed = false;
    bool m_reportedWriteFailure = false;
    uint64_t m_writeFailures = 0;
    uint64_t m_dropped = 0;
    std::string m_lastError;
    uint64_t m_chainSeq = 0;
    std::string m_chainPrev = std::string(64, '0');
    bool ResumeChain();
};

/* One JSON line for an incident record. `kind` is emitted as the leading
 * "kind" member; the remaining members come from IncidentToJson. Exposed for
 * unit tests so the wire shape can be asserted without touching the disk. */
std::string IncidentRecordToJsonLine(const std::string& kind,
                                     const Incident& incident, bool redact);

} // namespace edr

#endif /* EDR_INCIDENT_STORE_H */
