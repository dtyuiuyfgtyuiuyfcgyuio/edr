#ifndef EDR_RESPONSE_SERVER_H
#define EDR_RESPONSE_SERVER_H

#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "response_actions.h"
#include "quarantine_actions.h"
#include "host_isolation.h"

namespace edr {

constexpr uint32_t kResponseMaxPayload = 16 * 1024;

struct ResponseRequest {
    enum class Kind { Readiness, Terminate, Quarantine, RestoreQuarantine, Isolation, IsolationStatus, DeleteFile, Suspend, Resume } kind = Kind::Readiness;
    std::string requestId;
    std::string timestamp;
    std::string reason;
    uint32_t pid = 0;
    std::string createTime100ns;
    std::string path;
    std::string sha256Hex;
    std::string sourceRequestId;
    uint32_t maxTreeSize = 0;
    bool suspendBeforeTerminate = false;
    uint32_t maxTreeDepth = 0;
    bool isolateBeforeTerminate = false;
    std::vector<std::string> parentImageWhitelist;
    bool snapshotRequested = false;
    std::string evidencePath;
    /* Isolation-specific fields */
    bool isolateEnable = false;       /* true = enable isolation, false = disable */
    std::string managementIp;          /* management server IP to keep reachable */
    std::string allowedPorts;          /* comma-separated ports to keep open */
};

struct ResponseIsolationResult {
    bool success = false;
    std::string status;
    std::string requestId;
    std::string error;
};

/* Callback type for host isolation commands.
 * The implementation should enable/disable isolation and return the result. */
using IsolationHandler = std::function<ResponseIsolationResult(
    bool enable,
    const std::string& managementIp,
    const std::string& allowedPorts)>;
using IsolationStatusHandler = std::function<HostIsolationStatus()>;

struct ResponseAuditState {
    bool available = false;
    bool pending = false;
    bool writable = false;
};

bool LoadResponseCommandKey(const std::string& path,
                            std::vector<unsigned char>& key,
                            std::string& error);
bool BuildResponseFrame(const std::string& payload,
                        const std::vector<unsigned char>& key,
                        std::vector<unsigned char>& frame,
                        std::string& error);
bool ParseResponseFrame(const std::vector<unsigned char>& frame,
                        const std::vector<unsigned char>& key,
                        std::string& payload, std::string& error);
bool ParseResponseRequest(const std::string& payload, uint64_t nowFileTime,
                          uint32_t currentPid, ResponseRequest& request,
                          std::string& error);

class ResponseAuditLedger : public IResponseActionAudit, public IQuarantineAudit {
public:
    using WriteFn = std::function<bool(HANDLE, const std::string&)>;

    explicit ResponseAuditLedger(WriteFn writeFn = {});
    ~ResponseAuditLedger();
    bool Open(const std::string& path, std::string& error);
    bool AcceptDryRun(const ResponseRequest& request, const std::string& action,
                      std::string& error);
    bool AcceptDryRun(const ResponseRequest& request, std::string& error) {
        return AcceptDryRun(request, "terminate", error);
    }
    bool Attempt(const ResponseActionRequest& request,
                 std::string& error) override;
    bool Outcome(const ResponseActionResult& result,
                 std::string& error) override;
    bool AttemptAction(const ResponseActionRequest& request,
                       const char* action,
                       std::string& error) override;
    bool OutcomeAction(const ResponseActionResult& result,
                       const char* action,
                       std::string& error) override;
    bool AttemptQuarantine(const QuarantineRequest& request,
                           const std::string& sha256,
                           std::string& error) override;
    bool OutcomeQuarantine(const QuarantineRequest& request,
                           const QuarantineResult& result,
                           std::string& error) override;
    bool AttemptRestore(const QuarantineRestoreRequest& request,
                        const std::string& originalPath,
                        const std::string& quarantinePath,
                        const std::string& sha256,
                        const std::string& sidecarSha256,
                        std::string& error) override;
    bool OutcomeRestore(const QuarantineRestoreRequest& request,
                        const QuarantineRestoreResult& result,
                        std::string& error) override;
    bool AttemptIsolation(const ResponseRequest& request, std::string& error);
    bool OutcomeIsolation(const ResponseRequest& request,
                          const ResponseIsolationResult& result,
                          std::string& error);
    bool AttemptDeleteFile(const DeleteFileRequest& request,
                           std::string& error) override;
    bool OutcomeDeleteFile(const DeleteFileResult& result,
                           std::string& error) override;
    bool Contains(const std::string& requestId) const;
    ResponseAuditState State() const;
    void Close();

private:
    bool AppendLine(const std::string& line);
    void CloseLocked();
    HANDLE file_;
    WriteFn writeFn_;
    mutable std::mutex mutex_;
    std::unordered_set<std::string> ids_;
    std::deque<std::string> recentIds_;
    bool pendingAttempt_ = false;
    bool writeFailed_ = false;
    std::string pendingRequestId_;
    std::string pendingAction_;
    uint64_t auditChainSeq_ = 0;
    std::string auditChainPrev_ = std::string(64,'0');
};

class ResponseServer {
public:
    ResponseServer();
    ~ResponseServer();
    bool Start(const std::string& pipeName, const std::string& keyFile,
               const std::string& auditPath, bool enableProcessTermination,
               std::string& error, bool enableQuarantine = false,
               const std::string& quarantineDir = "",
               uint64_t quarantineMaxFileBytes = 268435456ULL,
               uint32_t maxTreeSize = 32,
               bool enableDeleteFile = false,
               bool enableProcessSuspend = false,
               bool enableProcessResume = false);
    void Stop();

    /* Synchronous in-process terminate (auto-response). False (result
     * untouched) when real termination is unavailable; otherwise forwards
     * to the executor under the same execution mutex as pipe-served
     * requests so audit attempt->outcome alternation is preserved (M1). */
    bool ExecuteTerminate(const ResponseActionRequest& request,
                          ResponseActionResult& result);

    /* Synchronous in-process delete file (auto-response). False (result
     * untouched) when real file deletion is unavailable. */
    bool ExecuteDeleteFile(const DeleteFileRequest& request,
                           DeleteFileResult& result);

    bool ExecuteSuspend(const ResponseActionRequest& request,
                        ResponseActionResult& result);
    bool ExecuteResume(const ResponseActionRequest& request,
                       ResponseActionResult& result);

    /* Register a handler for host isolation commands received via the
     * response channel.  The handler is called with (enable, managementIp,
     * allowedPorts) and returns a ResponseIsolationResult. */
    void SetIsolationHandler(IsolationHandler handler);
    void SetIsolationStatusHandler(IsolationStatusHandler handler);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace edr

#endif
