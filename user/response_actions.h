#ifndef EDR_RESPONSE_ACTIONS_H
#define EDR_RESPONSE_ACTIONS_H

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace edr {

struct ResponseActionRequest {
    std::string requestId;
    std::string timestamp;
    std::string reason;
    uint32_t pid = 0;
    uint64_t createTime100ns = 0;
    /* >0: terminate the process tree (children first) instead of the single
     * process; the value is a requested cap on total terminated processes.
     * 0: plain single-process termination. */
    uint32_t maxTreeSize = 0;
    bool suspendBeforeTerminate = false;
    /* Depth-based policy: 0 = no limit, otherwise only terminate descendants
     * at or below this depth from the root. */
    uint32_t maxTreeDepth = 0;
    /* If true, isolate the host before tree termination (requires isolation
     * handler to be configured). */
    bool isolateBeforeTerminate = false;
    /* Optional whitelist: if non-empty, skip termination for processes whose
     * parent image path contains any of these strings (case-insensitive). */
    std::vector<std::string> parentImageWhitelist;
    /* Snapshot artifact path produced before termination, if any. */
    std::string evidencePath;
    /* Optional snapshot hook state (set by the auto-response pipeline).
     * When snapshotRequested is true and evidencePath is non-empty, the
     * responder should treat the pre-action evidence capture as successful. */
    bool snapshotRequested = false;
    /* Optional isolation callback for combined isolate-then-tree flows.
     * Returns true on success and fills error on failure. */
    std::function<bool(std::string& error)> preIsolationCallback;
    /* Optional pre-snapshot callback for tree termination. The executor
     * invokes it after identity validation but before process operations. */
    std::function<void(const std::string&, uint32_t)> preSnapshotCallback;
    /* Evidence writer invoked only after policy and durable attempt. False
     * (or an exception) prevents termination; output is copied to outcome. */
    std::function<bool(std::string& evidencePath)> captureSnapshot;
};

struct ResponseActionResult {
    std::string effectiveMode = "real";
    std::string status = "rejected";
    bool terminationRequested = false;
    bool exitObserved = false;
    bool suspendRequested = false;   /* standalone suspend action ran */
    bool resumeRequested = false;    /* standalone resume action ran */
    DWORD win32Error = ERROR_SUCCESS;
    std::string requestId;
    bool auditWritten = true;
    bool treeRequested = false;
    uint32_t childrenTerminated = 0;
    uint32_t childrenSkipped = 0;
    uint32_t childrenFailed = 0;
    /* Tree termination metrics */
    uint32_t treePlanned = 0;         /* total processes planned for termination */
    uint32_t treeDescendants = 0;     /* total descendant processes found */
    uint32_t treeDepth = 0;           /* maximum depth of the process tree */
    uint32_t treeDepthLimit = 0;      /* configured maximum depth, 0 = none */
    uint32_t treeSuspended = 0;       /* processes successfully suspended */
    bool treeTruncated = false;       /* true if tree was capped by maxTreeSize */
    bool isolationRequested = false;  /* combined response requested isolation */
    bool isolationSucceeded = false;  /* isolation callback succeeded */
    bool snapshotCaptured = false;    /* snapshot callback ran */
    std::string evidencePath;         /* optional snapshot/evidence artifact */
    bool snapshotAttempted = false;    /* snapshot callback was requested */
};

struct DeleteFileRequest {
    std::string requestId;
    std::string timestamp;
    std::string reason;
    std::string path;       /* UTF-8 file path to delete */
    std::string sha256Hex;  /* optional expected SHA-256 */
};

struct DeleteFileResult {
    std::string effectiveMode = "real";
    std::string status = "rejected";
    DWORD win32Error = ERROR_SUCCESS;
    std::string requestId;
    bool auditWritten = true;
    bool deleted = false;
    std::string path;
};

/* Pure path policy seam; invalid paths or roots are treated as protected. */
bool IsProtectedResponsePathForRoots(
    const std::wstring& path, const std::vector<std::wstring>& roots);

struct ResponseFileIdentity {
    uint64_t volumeSerial = 0;
    unsigned char fileId[16] = {};
    bool operator==(const ResponseFileIdentity& other) const;
};

/* Stable user-mode snapshot of a process and the instance that parented it.
 * PIDs are reusable, so creation time is mandatory on every planned target. */
struct ResponseProcessIdentity {
    uint32_t pid = 0;
    uint64_t createTime100ns = 0;
    uint32_t parentPid = 0;
    uint64_t parentCreateTime100ns = 0;
};

class IResponseActionPlatform {
public:
    virtual ~IResponseActionPlatform() = default;
    virtual bool Open(uint32_t pid, HANDLE& process, DWORD& error) = 0;
    virtual void Close(HANDLE process) = 0;
    virtual bool Image(HANDLE process, std::wstring& path, std::wstring& base,
                       DWORD& error) = 0;
    virtual bool FileIdentity(const std::wstring& path,
                              ResponseFileIdentity& identity, DWORD& error) = 0;
    /* Open the path for disposition, then return the identity read from that
     * handle. The returned handle must name that object until Close(). */
    virtual bool OpenFileForDelete(const std::wstring& path, HANDLE& file,
                                   ResponseFileIdentity& identity,
                                   DWORD& error) = 0;
    virtual bool DeleteFileHandle(HANDLE file, DWORD& error) = 0;
    virtual bool Critical(HANDLE process, bool& critical, DWORD& error) = 0;
    virtual bool Protected(HANDLE process, bool& protectedProcess,
                           DWORD& error) = 0;
    virtual bool Session(uint32_t pid, DWORD& session, DWORD& error) = 0;
    virtual bool UserSid(HANDLE process, std::wstring& sid, DWORD& error) = 0;
    virtual bool CreateTime(HANDLE process, uint64_t& value, DWORD& error) = 0;
    virtual bool Terminate(HANDLE process, DWORD& error) = 0;
    virtual DWORD Wait(HANDLE process, DWORD timeoutMs, DWORD& error) = 0;
    /* Process tree support (toolhelp snapshot based). */
    virtual bool EnumerateChildren(uint32_t parentPid,
                                   std::vector<uint32_t>& children,
                                   DWORD& error) = 0;
    virtual bool EnumerateChildren(
        const ResponseProcessIdentity& parent,
        std::vector<ResponseProcessIdentity>& children, DWORD& error) = 0;
    virtual bool Suspend(HANDLE process, uint64_t expectedCreateTime100ns,
                         DWORD& error) = 0;
    virtual bool Resume(HANDLE process, uint64_t expectedCreateTime100ns,
                        DWORD& error) = 0;
    virtual bool IsAlive(uint32_t pid, DWORD& error) = 0;
};

class IResponseActionAudit {
public:
    virtual ~IResponseActionAudit() = default;
    virtual bool Attempt(const ResponseActionRequest& request,
                         std::string& error) = 0;
    virtual bool Outcome(const ResponseActionResult& result,
                         std::string& error) = 0;
    /* Action-named variants; the default implementation ignores the action
     * name so test fakes only implementing Attempt/Outcome keep working.
     * The native ledger overrides these to write the action into the
     * durable record. */
    virtual bool AttemptAction(const ResponseActionRequest& request,
                               const char* action, std::string& error) {
        (void)action;
        return Attempt(request, error);
    }
    virtual bool OutcomeAction(const ResponseActionResult& result,
                               const char* action, std::string& error) {
        (void)action;
        return Outcome(result, error);
    }
    virtual bool AttemptDeleteFile(const DeleteFileRequest& request,
                                   std::string& error) = 0;
    virtual bool OutcomeDeleteFile(const DeleteFileResult& result,
                                   std::string& error) = 0;
};

class IResponseEmergencySink {
public:
    virtual ~IResponseEmergencySink() = default;
    virtual void AuditFailure(const ResponseActionResult& result,
                              const std::string& detail) = 0;
    virtual void AuditFailure(const DeleteFileResult& result,
                              const std::string& detail) {
        (void)result;
        (void)detail;
    }
};

class NativeResponseActionPlatform final : public IResponseActionPlatform {
public:
    bool Open(uint32_t pid, HANDLE& process, DWORD& error) override;
    void Close(HANDLE process) override;
    bool Image(HANDLE process, std::wstring& path, std::wstring& base,
               DWORD& error) override;
    bool FileIdentity(const std::wstring& path, ResponseFileIdentity& identity,
                      DWORD& error) override;
    bool OpenFileForDelete(const std::wstring& path, HANDLE& file,
                           ResponseFileIdentity& identity,
                           DWORD& error) override;
    bool DeleteFileHandle(HANDLE file, DWORD& error) override;
    bool Critical(HANDLE process, bool& critical, DWORD& error) override;
    bool Protected(HANDLE process, bool& protectedProcess,
                   DWORD& error) override;
    bool Session(uint32_t pid, DWORD& session, DWORD& error) override;
    bool UserSid(HANDLE process, std::wstring& sid, DWORD& error) override;
    bool CreateTime(HANDLE process, uint64_t& value, DWORD& error) override;
    bool Terminate(HANDLE process, DWORD& error) override;
    DWORD Wait(HANDLE process, DWORD timeoutMs, DWORD& error) override;
    bool EnumerateChildren(uint32_t parentPid, std::vector<uint32_t>& children,
                           DWORD& error) override;
    bool EnumerateChildren(const ResponseProcessIdentity& parent,
                           std::vector<ResponseProcessIdentity>& children,
                           DWORD& error) override;
    bool Suspend(HANDLE process, uint64_t expectedCreateTime100ns,
                 DWORD& error) override;
    bool Resume(HANDLE process, uint64_t expectedCreateTime100ns,
                DWORD& error) override;
    bool IsAlive(uint32_t pid, DWORD& error) override;
};

class EventLogResponseEmergencySink final : public IResponseEmergencySink {
public:
    void AuditFailure(const ResponseActionResult& result,
                      const std::string& detail) override;
};

class ResponseActionExecutor {
public:
    ResponseActionExecutor(IResponseActionPlatform& platform,
                           IResponseActionAudit& audit,
                           IResponseEmergencySink& emergency,
                           DWORD waitMs = 5000,
                           const ResponseFileIdentity* selfIdentity = nullptr,
                           const std::wstring& selfBase = {},
                           uint32_t maxTreeSize = 32);
    ResponseActionResult Execute(const ResponseActionRequest& request);
    /* Standalone containment actions: same validation pipeline as Execute
     * (identity double-check, protected/critical/service policy) but the
     * process is suspended/resumed instead of terminated. */
    ResponseActionResult ExecuteSuspend(const ResponseActionRequest& request);
    ResponseActionResult ExecuteResume(const ResponseActionRequest& request);
    DeleteFileResult ExecuteDeleteFile(const DeleteFileRequest& request);

private:
    enum class SimpleAction { Terminate, Suspend, Resume };
    ResponseActionResult ExecuteTree(const ResponseActionRequest& request);
    ResponseActionResult ExecuteSimple(const ResponseActionRequest& request,
                                       SimpleAction action);

    bool VerifyNotSelf(const std::wstring& path, DWORD& error) const;

    IResponseActionPlatform& platform_;
    IResponseActionAudit& audit_;
    IResponseEmergencySink& emergency_;
    DWORD waitMs_;
    uint32_t maxTreeSize_;
    bool hasSelfIdentity_ = false;
    ResponseFileIdentity selfIdentity_;
    std::wstring selfBase_;
};

} // namespace edr

#endif
