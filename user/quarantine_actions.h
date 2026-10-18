#ifndef EDR_QUARANTINE_ACTIONS_H
#define EDR_QUARANTINE_ACTIONS_H

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "response_actions.h"

namespace edr {

struct QuarantineRequest {
    std::string requestId;
    std::string timestamp;
    std::string reason;
    std::string path;
    std::string sha256Hex;
};

struct QuarantineResult {
    std::string effectiveMode = "real";
    std::string status = "rejected";
    std::string requestId;
    DWORD win32Error = ERROR_SUCCESS;
    bool auditWritten = false;
    bool rolledBack = false;
    std::string quarantinePath;
    std::string sha256Hex;
    std::string sidecarSha256Hex;
};

struct QuarantineRestoreRequest {
    std::string requestId;
    std::string timestamp;
    std::string reason;
    std::string sourceRequestId;
};

struct QuarantineRestoreResult {
    std::string effectiveMode = "real";
    std::string status = "rejected";
    std::string requestId;
    std::string sourceRequestId;
    DWORD win32Error = ERROR_SUCCESS;
    bool auditWritten = false;
    bool partialRestore = false;
    std::string originalPath;
    std::string quarantinePath;
    std::string sha256Hex;
    std::string sidecarSha256Hex;
};

struct QuarantineFileInfo {
    DWORD attributes = 0;
    uint64_t size = 0;
    uint64_t volumeSerial = 0;
    unsigned char fileId[16] = {};
    DWORD numberOfLinks = 0;
};

class IQuarantinePlatform {
public:
    virtual ~IQuarantinePlatform() = default;
    virtual bool OpenFile(const std::string& path, HANDLE& file,
                          DWORD& error) = 0;
    virtual void CloseHandleSafe(HANDLE file) = 0;
    virtual bool FileInfo(HANDLE file, QuarantineFileInfo& info,
                          DWORD& error) = 0;
    virtual bool FinalPath(HANDLE file, std::string& path, DWORD& error) = 0;
    virtual bool DirectoryInfo(const std::string& path,
                               QuarantineFileInfo& info, DWORD& error) = 0;
    virtual bool Hash(HANDLE file, std::string& sha256Hex, DWORD& error) = 0;
    virtual bool EnsureQuarantineDir(const std::string& path,
                                     DWORD& error) = 0;
    virtual bool ProtectAcl(HANDLE file, std::vector<unsigned char>& original,
                            bool& originalProtected, DWORD& error) = 0;
    virtual bool RestoreAcl(HANDLE file,
                            const std::vector<unsigned char>& original,
                            bool originalProtected, DWORD& error) = 0;
    virtual bool Rename(HANDLE file, const std::string& destination,
                        DWORD& error) = 0;
    virtual bool WriteFileAtomic(const std::string& path,
                                 const std::string& bytes, DWORD& error) = 0;
    /* New restore-sidecar APIs default to fail closed so older platform
     * adapters cannot accidentally enable a partial restore implementation. */
    virtual bool ReadFileBounded(const std::string&, size_t, std::string&,
                                 DWORD& error) {
        error = ERROR_NOT_SUPPORTED; return false;
    }
    virtual bool ProtectMetadata(const std::string&, std::string&,
                                 DWORD& error) {
        error = ERROR_NOT_SUPPORTED; return false;
    }
    virtual bool UnprotectMetadata(const std::string&, std::string&,
                                   DWORD& error) {
        error = ERROR_NOT_SUPPORTED; return false;
    }
    virtual bool ValidateOriginalDacl(const std::vector<unsigned char>&, bool,
                                      DWORD& error) {
        error = ERROR_NOT_SUPPORTED; return false;
    }
    virtual bool OpenDirectoryNoFollow(const std::string&, HANDLE& directory,
                                       QuarantineFileInfo&, std::string&,
                                       DWORD& error) {
        directory = INVALID_HANDLE_VALUE;
        error = ERROR_NOT_SUPPORTED; return false;
    }
    virtual bool RenameNoReplaceInDirectory(HANDLE, HANDLE, const std::string&,
                                            DWORD& error) {
        error = ERROR_NOT_SUPPORTED; return false;
    }
};

class IQuarantineAudit {
public:
    virtual ~IQuarantineAudit() = default;
    virtual bool AttemptQuarantine(const QuarantineRequest& request,
                                   const std::string& sha256,
                                   std::string& error) = 0;
    virtual bool OutcomeQuarantine(const QuarantineRequest& request,
                                   const QuarantineResult& result,
                                   std::string& error) = 0;
    virtual bool AttemptRestore(const QuarantineRestoreRequest&,
                                const std::string&, const std::string&,
                                const std::string&, const std::string&,
                                std::string& error) {
        error = "quarantine restore audit is unavailable"; return false;
    }
    virtual bool OutcomeRestore(const QuarantineRestoreRequest&,
                                const QuarantineRestoreResult&,
                                std::string& error) {
        error = "quarantine restore audit is unavailable"; return false;
    }
};

class NativeQuarantinePlatform final : public IQuarantinePlatform {
public:
    bool OpenFile(const std::string& path, HANDLE& file, DWORD& error) override;
    void CloseHandleSafe(HANDLE file) override;
    bool FileInfo(HANDLE file, QuarantineFileInfo& info, DWORD& error) override;
    bool FinalPath(HANDLE file, std::string& path, DWORD& error) override;
    bool DirectoryInfo(const std::string& path, QuarantineFileInfo& info,
                       DWORD& error) override;
    bool Hash(HANDLE file, std::string& sha256Hex, DWORD& error) override;
    bool EnsureQuarantineDir(const std::string& path, DWORD& error) override;
    bool ProtectAcl(HANDLE file, std::vector<unsigned char>& original,
                    bool& originalProtected, DWORD& error) override;
    bool RestoreAcl(HANDLE file, const std::vector<unsigned char>& original,
                    bool originalProtected, DWORD& error) override;
    bool Rename(HANDLE file, const std::string& destination,
                DWORD& error) override;
    bool WriteFileAtomic(const std::string& path, const std::string& bytes,
                         DWORD& error) override;
    bool ReadFileBounded(const std::string& path, size_t maximumBytes,
                         std::string& bytes, DWORD& error) override;
    bool ProtectMetadata(const std::string& clearText,
                         std::string& protectedText, DWORD& error) override;
    bool UnprotectMetadata(const std::string& protectedText,
                           std::string& clearText, DWORD& error) override;
    bool ValidateOriginalDacl(const std::vector<unsigned char>& descriptor,
                              bool originalProtected, DWORD& error) override;
    bool OpenDirectoryNoFollow(const std::string& path, HANDLE& directory,
                               QuarantineFileInfo& info,
                               std::string& finalPath, DWORD& error) override;
    bool RenameNoReplaceInDirectory(HANDLE file, HANDLE directory,
                                    const std::string& leaf,
                                    DWORD& error) override;
};

class QuarantineExecutor {
public:
    QuarantineExecutor(IQuarantinePlatform& platform, IQuarantineAudit& audit,
                       IResponseEmergencySink& emergency,
                       const std::string& quarantineDir,
                       uint64_t maxFileBytes);
    QuarantineResult Execute(const QuarantineRequest& request);
    QuarantineRestoreResult Restore(const QuarantineRestoreRequest& request);

private:
    IQuarantinePlatform& platform_;
    IQuarantineAudit& audit_;
    IResponseEmergencySink& emergency_;
    std::string quarantineDir_;
    uint64_t maxFileBytes_;
};

} // namespace edr

#endif
