/*
 * reporter_spool.h - Bounded, owner-protected at-least-once delivery journal.
 */
#ifndef EDR_REPORTER_SPOOL_H
#define EDR_REPORTER_SPOOL_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <windows.h>

namespace edr {

struct ReporterSpoolOptions {
    std::string directory; // Empty disables durable mode.
    size_t maxBytes = 16u * 1024u * 1024u;
    size_t maxRecords = 1000;
    size_t maxItemBytes = 1024u * 1024u;
    /* Deterministic failure-only seam for ACK regressions. A false result
     * latches failure before deletion; true still performs the real ACK. */
    std::function<bool()> beforeAcknowledge;
};

struct ReporterSpoolItem {
    std::string id;
    std::string body;
};

class ReporterSpool {
public:
    explicit ReporterSpool(ReporterSpoolOptions options,
                           std::string destinationKey = {});
    ~ReporterSpool();
    ReporterSpool(const ReporterSpool&) = delete;
    ReporterSpool& operator=(const ReporterSpool&) = delete;

    bool Open(std::vector<ReporterSpoolItem>& recovered);
    bool Store(const std::string& body, ReporterSpoolItem& item);
    bool Acknowledge(const std::string& id);
    void SetFailed(const std::string& reason);
    std::string GetStatus() const;
    uint64_t ErrorCount() const noexcept;
    size_t RecordCount() const;
    size_t StorageBytes() const;

private:
    struct Entry {
        HANDLE handle = INVALID_HANDLE_VALUE;
        size_t bytes = 0;
        std::string body;
    };

    bool FailLocked(const std::string& reason);
    bool PrepareDirectoryLocked();
    bool VerifyProtectedObject(HANDLE handle, bool setAcl,
                               std::string& error) const;
    bool VerifyChildPath(HANDLE handle, std::string& error) const;
    bool ReadAndValidate(HANDLE handle, const std::string& filename,
                         ReporterSpoolItem& item, size_t& storageBytes,
                         std::string& error) const;
    std::wstring ItemPath(const std::string& id) const;
    static std::string MakeId(uint64_t sequence);
    static std::string Hash(const std::string& value);

    ReporterSpoolOptions m_options;
    std::string m_destinationFingerprint;
    std::wstring m_directory;
    mutable std::mutex m_mutex;
    HANDLE m_directoryHandle = INVALID_HANDLE_VALUE;
    HANDLE m_lockHandle = INVALID_HANDLE_VALUE;
    std::map<std::string, Entry> m_entries;
    uint64_t m_nextSequence = 1;
    size_t m_storageBytes = 0;
    uint64_t m_errorCount = 0;
    bool m_opened = false;
    bool m_failed = false;
    std::string m_status = "not_started";
};

} // namespace edr

#endif /* EDR_REPORTER_SPOOL_H */
