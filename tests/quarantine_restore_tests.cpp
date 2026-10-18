/*
 * quarantine_restore_tests.cpp - persistence and fail-closed tests for
 * explicitly audited quarantine restoration.
 */
#include "quarantine_restore_tests.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "json_lite.h"
#include "config.h"
#include "quarantine_actions.h"

namespace {

#define QR_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error(
            "quarantine restore test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

constexpr char kQuarantineDir[] = "C:\\edr-test-quarantine";
constexpr char kSourceDir[] = "C:\\safe-test";
constexpr char kSourcePath[] = "C:\\safe-test\\sample.bin";
constexpr char kSourceRequestId[] = "f1900000-1234-1234-1234-123456789abc";
constexpr char kRestoreRequestId[] = "f1900001-1234-1234-1234-123456789abc";
constexpr char kFileHash[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct FakeFile {
    std::string path;
    std::string contents = "controlled restore fixture bytes";
    std::string hash = kFileHash;
    edr::QuarantineFileInfo info = {};
    std::vector<unsigned char> dacl = {0x11, 0x22, 0x33, 0x44};
    bool daclProtected = true;
};

struct FakeDirectory {
    std::string path;
    edr::QuarantineFileInfo info = {};
};

struct FakeHandle {
    std::shared_ptr<FakeFile> file;
    std::shared_ptr<FakeDirectory> directory;
};

FakeHandle* AsFakeHandle(HANDLE handle) {
    return reinterpret_cast<FakeHandle*>(handle);
}

std::string QuarantinePath() {
    return std::string(kQuarantineDir) + "\\" + kFileHash + ".quarantined";
}

std::string SidecarPath(const std::string& sourceRequestId) {
    return std::string(kQuarantineDir) + "\\" + sourceRequestId + ".json";
}

class RestoreTestPlatform final : public edr::IQuarantinePlatform {
public:
    std::map<std::string, std::shared_ptr<FakeFile>> files;
    std::map<std::string, std::shared_ptr<FakeDirectory>> directories;
    std::map<std::string, std::string> sidecars;
    std::map<std::string, bool> sidecarOwnerProtected;
    std::vector<std::unique_ptr<FakeHandle>> handles;
    std::vector<std::string> relativeRenameDestinations;
    std::vector<unsigned char> originalDacl = {0x11, 0x22, 0x33, 0x44};
    std::string metadataPathOverride;
    bool forceReparseParent = false;
    bool rejectMetadataUnprotect = false;
    bool rejectOriginalDacl = false;
    bool rejectRestoreAcl = false;
    bool rejectRename = false;
    int restoreAclCalls = 0;
    int relativeRenameCalls = 0;

    RestoreTestPlatform() {
        AddDirectory(kSourceDir);
        AddFile(kSourcePath);
    }

    std::shared_ptr<FakeDirectory> AddDirectory(const std::string& path) {
        auto directory = std::make_shared<FakeDirectory>();
        directory->path = path;
        directory->info.attributes = FILE_ATTRIBUTE_DIRECTORY;
        directory->info.volumeSerial = 7;
        directories[path] = directory;
        return directory;
    }

    std::shared_ptr<FakeFile> AddFile(const std::string& path,
                                      std::string contents = "controlled restore fixture bytes") {
        auto file = std::make_shared<FakeFile>();
        file->path = path;
        file->contents = std::move(contents);
        file->info.attributes = FILE_ATTRIBUTE_NORMAL;
        file->info.size = file->contents.size();
        file->info.volumeSerial = 7;
        file->info.numberOfLinks = 1;
        for (size_t i = 0; i < sizeof(file->info.fileId); ++i)
            file->info.fileId[i] = static_cast<unsigned char>(i + 1);
        files[path] = file;
        return file;
    }

    HANDLE NewHandle(std::shared_ptr<FakeFile> file) {
        auto handle = std::make_unique<FakeHandle>();
        handle->file = std::move(file);
        HANDLE value = reinterpret_cast<HANDLE>(handle.get());
        handles.push_back(std::move(handle));
        return value;
    }

    HANDLE NewHandle(std::shared_ptr<FakeDirectory> directory) {
        auto handle = std::make_unique<FakeHandle>();
        handle->directory = std::move(directory);
        HANDLE value = reinterpret_cast<HANDLE>(handle.get());
        handles.push_back(std::move(handle));
        return value;
    }

    bool OpenFile(const std::string& path, HANDLE& file, DWORD& error) override {
        const auto found = files.find(path);
        if (found == files.end()) {
            file = INVALID_HANDLE_VALUE;
            error = ERROR_FILE_NOT_FOUND;
            return false;
        }
        file = NewHandle(found->second);
        return true;
    }
    void CloseHandleSafe(HANDLE) override {}
    bool FileInfo(HANDLE handle, edr::QuarantineFileInfo& info,
                  DWORD& error) override {
        FakeHandle* value = AsFakeHandle(handle);
        if (!value || !value->file) {
            error = ERROR_INVALID_HANDLE;
            return false;
        }
        info = value->file->info;
        return true;
    }
    bool FinalPath(HANDLE handle, std::string& path, DWORD& error) override {
        FakeHandle* value = AsFakeHandle(handle);
        if (!value || !value->file) {
            error = ERROR_INVALID_HANDLE;
            return false;
        }
        path = value->file->path;
        return true;
    }
    bool DirectoryInfo(const std::string& path,
                       edr::QuarantineFileInfo& info, DWORD& error) override {
        const auto found = directories.find(path);
        if (found == directories.end()) {
            error = ERROR_PATH_NOT_FOUND;
            return false;
        }
        info = found->second->info;
        return true;
    }
    bool Hash(HANDLE handle, std::string& hash, DWORD& error) override {
        FakeHandle* value = AsFakeHandle(handle);
        if (!value || !value->file) {
            error = ERROR_INVALID_HANDLE;
            return false;
        }
        hash = value->file->hash;
        return true;
    }
    bool EnsureQuarantineDir(const std::string& path, DWORD&) override {
        auto directory = AddDirectory(path);
        directory->info.attributes = FILE_ATTRIBUTE_DIRECTORY;
        return true;
    }
    bool ProtectAcl(HANDLE handle, std::vector<unsigned char>& original,
                    bool& originalProtected, DWORD& error) override {
        FakeHandle* value = AsFakeHandle(handle);
        if (!value || !value->file) {
            error = ERROR_INVALID_HANDLE;
            return false;
        }
        original = value->file->dacl;
        originalProtected = value->file->daclProtected;
        value->file->dacl = {0x53, 0x59, 0x53, 0x41};
        value->file->daclProtected = true;
        return true;
    }
    bool RestoreAcl(HANDLE handle, const std::vector<unsigned char>& original,
                    bool originalProtected, DWORD& error) override {
        FakeHandle* value = AsFakeHandle(handle);
        if (!value || !value->file || rejectRestoreAcl) {
            error = ERROR_INVALID_ACL;
            return false;
        }
        ++restoreAclCalls;
        value->file->dacl = original;
        value->file->daclProtected = originalProtected;
        return true;
    }
    bool Rename(HANDLE handle, const std::string& destination,
                DWORD& error) override {
        FakeHandle* value = AsFakeHandle(handle);
        if (!value || !value->file || rejectRename) {
            error = ERROR_WRITE_FAULT;
            return false;
        }
        if (files.find(destination) != files.end()) {
            error = ERROR_FILE_EXISTS;
            return false;
        }
        files.erase(value->file->path);
        value->file->path = destination;
        files[destination] = value->file;
        return true;
    }
    bool WriteFileAtomic(const std::string& path, const std::string& bytes,
                         DWORD& error) override {
        if (sidecars.find(path) != sidecars.end()) {
            error = ERROR_FILE_EXISTS;
            return false;
        }
        sidecars[path] = bytes;
        sidecarOwnerProtected[path] = true;
        return true;
    }

    bool ReadFileBounded(const std::string& path, size_t maximumBytes,
                         std::string& bytes, DWORD& error) override {
        const auto found = sidecars.find(path);
        if (found == sidecars.end()) {
            error = ERROR_FILE_NOT_FOUND;
            return false;
        }
        if (!sidecarOwnerProtected[path]) {
            error = ERROR_ACCESS_DENIED;
            return false;
        }
        if (found->second.size() > maximumBytes) {
            error = ERROR_FILE_TOO_LARGE;
            return false;
        }
        bytes = found->second;
        return true;
    }
    bool ProtectMetadata(const std::string& clearText, std::string& protectedText,
                         DWORD&) override {
        protectedText = "TEST-SEALED:" + clearText;
        return true;
    }
    bool UnprotectMetadata(const std::string& protectedText,
                           std::string& clearText, DWORD& error) override {
        static const std::string prefix = "TEST-SEALED:";
        if (rejectMetadataUnprotect || protectedText.rfind(prefix, 0) != 0) {
            error = ERROR_INVALID_DATA;
            return false;
        }
        clearText = protectedText.substr(prefix.size());
        if (!metadataPathOverride.empty()) {
            const std::string before = "\"original_path\":\"" +
                jsonlite::escape(kSourcePath) + "\"";
            const std::string after = "\"original_path\":\"" +
                jsonlite::escape(metadataPathOverride) + "\"";
            const size_t position = clearText.find(before);
            if (position == std::string::npos) {
                error = ERROR_INVALID_DATA;
                return false;
            }
            clearText.replace(position, before.size(), after);
        }
        return true;
    }
    bool ValidateOriginalDacl(const std::vector<unsigned char>& descriptor,
                              bool, DWORD& error) override {
        if (rejectOriginalDacl || descriptor != originalDacl) {
            error = ERROR_INVALID_ACL;
            return false;
        }
        return true;
    }
    bool OpenDirectoryNoFollow(const std::string& path, HANDLE& directory,
                               edr::QuarantineFileInfo& info,
                               std::string& finalPath, DWORD& error) override {
        const auto found = directories.find(path);
        if (found == directories.end() || forceReparseParent) {
            directory = INVALID_HANDLE_VALUE;
            error = forceReparseParent ? ERROR_REPARSE_TAG_INVALID
                                       : ERROR_PATH_NOT_FOUND;
            return false;
        }
        directory = NewHandle(found->second);
        info = found->second->info;
        finalPath = found->second->path;
        return true;
    }
    bool RenameNoReplaceInDirectory(HANDLE fileHandle, HANDLE directoryHandle,
                                    const std::string& leaf,
                                    DWORD& error) override {
        FakeHandle* file = AsFakeHandle(fileHandle);
        FakeHandle* directory = AsFakeHandle(directoryHandle);
        if (!file || !file->file || !directory || !directory->directory ||
            rejectRename) {
            error = ERROR_WRITE_FAULT;
            return false;
        }
        const std::string destination = directory->directory->path + "\\" + leaf;
        ++relativeRenameCalls;
        relativeRenameDestinations.push_back(destination);
        if (files.find(destination) != files.end()) {
            error = ERROR_FILE_EXISTS;
            return false;
        }
        files.erase(file->file->path);
        file->file->path = destination;
        files[destination] = file->file;
        return true;
    }
};

class RestoreTestAudit final : public edr::IQuarantineAudit {
public:
    bool rejectQuarantineAttempt = false;
    bool rejectRestoreAttempt = false;
    bool rejectRestoreOutcome = false;
    int quarantineAttempts = 0;
    int quarantineOutcomes = 0;
    int restoreAttempts = 0;
    int restoreOutcomes = 0;
    std::string restoredSourceId;
    std::string restoredPath;
    std::string restoredHash;
    std::string restoredSidecarDigest;

    bool AttemptQuarantine(const edr::QuarantineRequest&, const std::string&,
                           std::string& error) override {
        ++quarantineAttempts;
        if (rejectQuarantineAttempt) {
            error = "quarantine attempt write failed";
            return false;
        }
        return true;
    }
    bool OutcomeQuarantine(const edr::QuarantineRequest&,
                           const edr::QuarantineResult&,
                           std::string&) override {
        ++quarantineOutcomes;
        return true;
    }
    bool AttemptRestore(const edr::QuarantineRestoreRequest& request,
                        const std::string& originalPath,
                        const std::string& quarantinePath,
                        const std::string& sha256,
                        const std::string& sidecarSha256,
                        std::string& error) override {
        ++restoreAttempts;
        restoredSourceId = request.sourceRequestId;
        restoredPath = originalPath;
        restoredHash = sha256;
        restoredSidecarDigest = sidecarSha256;
        (void)quarantinePath;
        if (rejectRestoreAttempt) {
            error = "restore attempt write failed";
            return false;
        }
        return true;
    }
    bool OutcomeRestore(const edr::QuarantineRestoreRequest&,
                        const edr::QuarantineRestoreResult&,
                        std::string& error) override {
        ++restoreOutcomes;
        if (rejectRestoreOutcome) {
            error = "restore outcome write failed";
            return false;
        }
        return true;
    }
};

class RestoreTestEmergency final : public edr::IResponseEmergencySink {
public:
    int calls = 0;
    std::string lastStatus;

    void AuditFailure(const edr::ResponseActionResult& result,
                      const std::string&) override {
        ++calls;
        lastStatus = result.status;
    }
};

std::vector<unsigned char> CurrentProcessUserSid(DWORD& error) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error = GetLastError();
        return {};
    }
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (!needed) {
        error = GetLastError();
        CloseHandle(token);
        return {};
    }
    std::vector<unsigned char> storage(needed);
    if (!GetTokenInformation(token, TokenUser, storage.data(), needed, &needed)) {
        error = GetLastError();
        CloseHandle(token);
        return {};
    }
    CloseHandle(token);
    const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
    const DWORD sidLength = GetLengthSid(user->User.Sid);
    std::vector<unsigned char> sid(sidLength);
    if (!CopySid(sidLength, sid.data(), user->User.Sid)) {
        error = GetLastError();
        return {};
    }
    return sid;
}

bool BuildCurrentUserTestDescriptor(PSECURITY_DESCRIPTOR& descriptor,
                                    DWORD& error) {
    descriptor = nullptr;
    error = ERROR_SUCCESS;
    const std::vector<unsigned char> userSid = CurrentProcessUserSid(error);
    if (userSid.empty()) return false;
    LPWSTR sidText = nullptr;
    if (!ConvertSidToStringSidW(const_cast<unsigned char*>(userSid.data()),
                                &sidText)) {
        error = GetLastError();
        return false;
    }
    BYTE systemSid[SECURITY_MAX_SID_SIZE], adminSid[SECURITY_MAX_SID_SIZE];
    DWORD systemSize = sizeof(systemSid), adminSize = sizeof(adminSid);
    const bool knownSidsReady =
        CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSize) &&
        CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid,
                           &adminSize);
    if (!knownSidsReady) {
        error = GetLastError();
        LocalFree(sidText);
        return false;
    }
    std::wstring sddl = L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";
    if (!EqualSid(const_cast<unsigned char*>(userSid.data()), systemSid) &&
        !EqualSid(const_cast<unsigned char*>(userSid.data()), adminSid)) {
        sddl += L"(A;OICI;GA;;;";
        sddl += sidText;
        sddl += L")";
    }
    LocalFree(sidText);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        error = GetLastError();
        return false;
    }
    return true;
}

bool IsExpectedCurrentUserTestAcl(HANDLE file, DWORD& error,
                                  std::string* diagnostic = nullptr) {
    if (diagnostic) diagnostic->clear();
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    PSID owner = nullptr;
    const DWORD status = GetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor);
    if (status != ERROR_SUCCESS || !descriptor || !dacl) {
        if (descriptor) LocalFree(descriptor);
        error = status == ERROR_SUCCESS ? ERROR_INVALID_ACL : status;
        if (diagnostic) *diagnostic = "GetSecurityInfo status=" +
            std::to_string(status) + " descriptor=" +
            std::to_string(descriptor != nullptr) + " dacl=" +
            std::to_string(dacl != nullptr);
        return false;
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    std::vector<unsigned char> currentSid;
    DWORD sidError = ERROR_SUCCESS;
    currentSid = CurrentProcessUserSid(sidError);
    if (currentSid.empty() || !owner) {
        LocalFree(descriptor);
        error = sidError == ERROR_SUCCESS ? ERROR_INVALID_OWNER : sidError;
        if (diagnostic) *diagnostic = "token SID or owner unavailable sid_error=" +
            std::to_string(sidError) + " owner=" + std::to_string(owner != nullptr);
        return false;
    }
    const BOOL gotControl = GetSecurityDescriptorControl(
        descriptor, &control, &revision);
    const bool ownerMatches = EqualSid(owner, currentSid.data()) != FALSE;
    bool valid = gotControl && (control & SE_DACL_PROTECTED) &&
        !(dacl->AclRevision < ACL_REVISION) && ownerMatches;
    BYTE systemSid[SECURITY_MAX_SID_SIZE], adminSid[SECURITY_MAX_SID_SIZE];
    DWORD systemSize = sizeof(systemSid), adminSize = sizeof(adminSid);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSize) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid,
                            &adminSize)) valid = false;
    struct PrincipalAclCounts {
        PSID sid;
        DWORD direct = 0;
        DWORD combined = 0;
        DWORD inheritOnly = 0;
    };
    std::vector<PrincipalAclCounts> principals;
    principals.push_back({systemSid});
    if (!EqualSid(adminSid, systemSid)) principals.push_back({adminSid});
    if (std::none_of(principals.begin(), principals.end(),
            [&](const PrincipalAclCounts& item) {
                return EqualSid(item.sid, currentSid.data()) != FALSE;
            })) {
        principals.push_back({currentSid.data()});
    }
    std::string aceFailure;
    std::string aceSummary;
    GENERIC_MAPPING fileMapping = {
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
        FILE_ALL_ACCESS
    };
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) {
            valid = false;
            if (aceFailure.empty()) aceFailure = "GetAce failed";
            break;
        }
        auto* header = static_cast<ACE_HEADER*>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            valid = false;
            if (aceFailure.empty()) aceFailure = "unsupported ACE type=" +
                std::to_string(header->AceType) + " flags=" +
                std::to_string(header->AceFlags);
            continue;
        }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        const DWORD rawMask = ace->Mask;
        DWORD mask = ace->Mask;
        MapGenericMask(&mask, &fileMapping);
        const PSID sid = &ace->SidStart;
        LPWSTR sidText = nullptr;
        const std::string sidValue = ConvertSidToStringSidW(
            const_cast<PSID>(sid), &sidText)
            ? edr::WideToUtf8(sidText) : "<invalid-sid>";
        if (sidText) LocalFree(sidText);
        aceSummary += (aceSummary.empty() ? "" : ",") + sidValue + "/" +
            std::to_string(ace->Header.AceFlags) + "/" +
            std::to_string(rawMask) + "->" + std::to_string(mask);
        auto principal = std::find_if(principals.begin(), principals.end(),
            [&](const PrincipalAclCounts& item) {
                return EqualSid(sid, item.sid) != FALSE;
            });
        if (principal == principals.end() || mask != FILE_ALL_ACCESS) {
            valid = false;
            if (aceFailure.empty()) aceFailure =
                "unknown trustee or non-full-access mask=" +
                std::to_string(mask);
            continue;
        }
        const BYTE flags = ace->Header.AceFlags;
        if (flags == 0) {
            ++principal->direct;
        } else if (flags ==
                (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) {
            ++principal->combined;
        } else if (flags == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
                             INHERIT_ONLY_ACE)) {
            ++principal->inheritOnly;
        } else {
            valid = false;
            if (aceFailure.empty()) aceFailure = "unsupported ACE flags=" +
                std::to_string(flags);
        }
    }
    bool inheritanceShapeKnown = false;
    bool expectedInheritance = false;
    DWORD expectedAceCount = 0;
    bool systemFound = false, adminFound = false, userFound = false;
    for (const PrincipalAclCounts& principal : principals) {
        const DWORD effectiveCount = principal.direct + principal.combined;
        const DWORD inheritanceCount = principal.combined +
            principal.inheritOnly;
        const bool acceptedShape = effectiveCount == 1 &&
            inheritanceCount <= 1 &&
            !(principal.combined &&
              (principal.direct || principal.inheritOnly));
        if (!acceptedShape) {
            valid = false;
            if (aceFailure.empty()) aceFailure =
                "principal has invalid effective/inherit-only ACE counts";
        }
        if (!inheritanceShapeKnown) {
            expectedInheritance = inheritanceCount == 1;
            inheritanceShapeKnown = true;
        } else if ((inheritanceCount == 1) != expectedInheritance) {
            valid = false;
            if (aceFailure.empty()) aceFailure =
                "principals disagree on inherited-ACE presence";
        }
        expectedAceCount += principal.direct + principal.combined +
            principal.inheritOnly;
        if (EqualSid(principal.sid, systemSid)) systemFound = true;
        if (EqualSid(principal.sid, adminSid)) adminFound = true;
        if (EqualSid(principal.sid, currentSid.data())) userFound = true;
    }
    const DWORD aceCount = dacl->AceCount;
    const bool ok = valid && aceCount == expectedAceCount &&
        systemFound && adminFound && userFound;
    LocalFree(descriptor);
    if (!ok) {
        error = sidError == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : sidError;
        if (diagnostic) {
            *diagnostic = "owner_matches=" + std::to_string(ownerMatches) +
                " protected=" +
                std::to_string((control & SE_DACL_PROTECTED) != 0) +
                " got_control=" + std::to_string(gotControl != FALSE) +
                " ace_count=" + std::to_string(aceCount) +
                " expected_count=" + std::to_string(expectedAceCount) +
                " system=" + std::to_string(systemFound) +
                " admin=" + std::to_string(adminFound) +
                " user=" + std::to_string(userFound) +
                (aceFailure.empty() ? std::string() : " "+ aceFailure) +
                " ACEs=" + aceSummary;
        }
    }
    return ok;
}

bool ApplyCurrentUserTestAcl(HANDLE file, DWORD& error,
                            std::string* failureStage = nullptr) {
    if (failureStage) failureStage->clear();
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!BuildCurrentUserTestDescriptor(descriptor, error)) {
        if (failureStage) *failureStage = "build descriptor";
        return false;
    }
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) ||
        !present || !dacl) {
        LocalFree(descriptor);
        error = ERROR_INVALID_ACL;
        if (failureStage) *failureStage = "read generated DACL";
        return false;
    }
    /* Pin the owner to the current token user as well: on elevated hosts the
     * platform default owner is the Administrators group, which the
     * owner-only verification below rejects. */
    DWORD sidError2 = ERROR_SUCCESS;
    std::vector<unsigned char> currentOwner = CurrentProcessUserSid(sidError2);
    if (currentOwner.empty()) {
        LocalFree(descriptor);
        error = ERROR_INVALID_OWNER;
        if (failureStage) *failureStage = "read token user SID";
        return false;
    }
    const DWORD status = SetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
        PROTECTED_DACL_SECURITY_INFORMATION,
        reinterpret_cast<PSID>(currentOwner.data()), nullptr, dacl, nullptr);
    LocalFree(descriptor);
    if (status != ERROR_SUCCESS) {
        error = status;
        if (failureStage) *failureStage = "SetSecurityInfo";
        return false;
    }
    std::string diagnostic;
    if (!IsExpectedCurrentUserTestAcl(file, error, &diagnostic)) {
        if (failureStage) *failureStage =
            "verify owner/protected DACL: " + diagnostic;
        return false;
    }
    return true;
}

bool SameTestPath(const std::string& left, const std::string& right) {
    std::wstring a = edr::Utf8ToWide(left);
    std::wstring b = edr::Utf8ToWide(right);
    wchar_t aFull[32768] = {}, bFull[32768] = {};
    const DWORD aLength = GetFullPathNameW(a.c_str(), 32768, aFull, nullptr);
    const DWORD bLength = GetFullPathNameW(b.c_str(), 32768, bFull, nullptr);
    if (!aLength || aLength >= 32768 || !bLength || bLength >= 32768)
        return false;
    std::wstring aa(aFull, aLength), bb(bFull, bLength);
    return CompareStringOrdinal(aa.data(), static_cast<int>(aa.size()),
        bb.data(), static_cast<int>(bb.size()), TRUE) == CSTR_EQUAL;
}

/* Real Windows file/DPAPI/rename exercise for an un-elevated developer token.
 * The adapter grants that token access only on its generated temp tree; it
 * leaves the production SYSTEM/Administrators ACL policy untouched. */
class CurrentUserNativeTestPlatform final : public edr::IQuarantinePlatform {
public:
    explicit CurrentUserNativeTestPlatform(std::string quarantineDir)
        : quarantineDir_(std::move(quarantineDir)) {}

    bool OpenFile(const std::string& path, HANDLE& file, DWORD& error) override {
        return native_.OpenFile(path, file, error);
    }
    void CloseHandleSafe(HANDLE file) override { native_.CloseHandleSafe(file); }
    bool FileInfo(HANDLE file, edr::QuarantineFileInfo& info,
                  DWORD& error) override {
        return native_.FileInfo(file, info, error);
    }
    bool FinalPath(HANDLE file, std::string& path, DWORD& error) override {
        return native_.FinalPath(file, path, error);
    }
    bool DirectoryInfo(const std::string& path, edr::QuarantineFileInfo& info,
                       DWORD& error) override {
        return native_.DirectoryInfo(path, info, error);
    }
    bool Hash(HANDLE file, std::string& hash, DWORD& error) override {
        return native_.Hash(file, hash, error);
    }
    bool EnsureQuarantineDir(const std::string& path, DWORD& error) override {
        if (!SameTestPath(path, quarantineDir_)) {
            error = ERROR_ACCESS_DENIED;
            lastFailure_ = "quarantine path did not match fixture path";
            return false;
        }
        const DWORD attributes = GetFileAttributesW(edr::Utf8ToWide(path).c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            error = GetLastError();
            lastFailure_ = "GetFileAttributesW";
            return false;
        }
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            error = (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
                ? ERROR_REPARSE_TAG_INVALID : ERROR_DIRECTORY;
            lastFailure_ = "fixture is not an ordinary directory";
            return false;
        }
        HANDLE directory = CreateFileW(edr::Utf8ToWide(path).c_str(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (directory == INVALID_HANDLE_VALUE) {
            error = GetLastError();
            lastFailure_ = "open fixture directory for test ACL";
            return false;
        }
        std::string aclFailure;
        const bool secured = ApplyCurrentUserTestAcl(directory, error,
                                                      &aclFailure);
        if (!secured) lastFailure_ = aclFailure;
        CloseHandle(directory);
        return secured;
    }
    bool ProtectAcl(HANDLE file, std::vector<unsigned char>& original,
                    bool& originalProtected, DWORD& error) override {
        /* Obtain owner rights on the same fixture object before the native
         * adapter removes the developer token's access from its DACL. */
        HANDLE ownerAccess = ReOpenFile(file, READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT);
        if (ownerAccess == INVALID_HANDLE_VALUE) {
            error = GetLastError();
            return false;
        }
        if (!native_.ProtectAcl(file, original, originalProtected, error)) {
            CloseHandle(ownerAccess);
            return false;
        }
        const bool secured = ApplyCurrentUserTestAcl(ownerAccess, error);
        CloseHandle(ownerAccess);
        if (secured) return true;
        DWORD restoreError = ERROR_SUCCESS;
        native_.RestoreAcl(file, original, originalProtected, restoreError);
        return false;
    }
    bool RestoreAcl(HANDLE file, const std::vector<unsigned char>& original,
                    bool originalProtected, DWORD& error) override {
        return native_.RestoreAcl(file, original, originalProtected, error);
    }
    bool Rename(HANDLE file, const std::string& destination,
                DWORD& error) override {
        return native_.Rename(file, destination, error);
    }
    bool WriteFileAtomic(const std::string& path, const std::string& bytes,
                         DWORD& error) override {
        if (!IsQuarantineChild(path) || bytes.empty() ||
            bytes.size() > MAXDWORD) {
            error = ERROR_ACCESS_DENIED;
            return false;
        }
        const std::string temporary = path + ".testtmp-" +
            std::to_string(GetCurrentProcessId()) + "-" +
            std::to_string(GetTickCount64());
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!BuildCurrentUserTestDescriptor(descriptor, error)) return false;
        SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
        HANDLE file = CreateFileW(edr::Utf8ToWide(temporary).c_str(),
            GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER, 0,
            &security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        LocalFree(descriptor);
        if (file == INVALID_HANDLE_VALUE) {
            error = GetLastError();
            return false;
        }
        DWORD written = 0;
        bool ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()),
            &written, nullptr) && written == bytes.size() &&
            FlushFileBuffers(file);
        if (!ok) error = GetLastError() == ERROR_SUCCESS
            ? ERROR_WRITE_FAULT : GetLastError();
        /* Pin the owner to the current token user through the same helper the
         * fixture directory uses: the elevated default owner (Administrators)
         * would fail the owner check when the sidecar is read back. */
        if (ok) {
            DWORD aclError = ERROR_SUCCESS;
            if (!ApplyCurrentUserTestAcl(file, aclError, nullptr)) {
                ok = false;
                error = aclError != ERROR_SUCCESS ? aclError
                                                  : ERROR_ACCESS_DENIED;
            }
        }
        CloseHandle(file);
        if (ok && !MoveFileExW(edr::Utf8ToWide(temporary).c_str(),
                edr::Utf8ToWide(path).c_str(), MOVEFILE_WRITE_THROUGH)) {
            error = GetLastError();
            ok = false;
        }
        if (!ok) DeleteFileW(edr::Utf8ToWide(temporary).c_str());
        return ok;
    }
    bool ReadFileBounded(const std::string& path, size_t maximumBytes,
                         std::string& bytes, DWORD& error) override {
        bytes.clear();
        if (!IsQuarantineChild(path)) {
            error = ERROR_ACCESS_DENIED;
            return false;
        }
        HANDLE file = INVALID_HANDLE_VALUE;
        if (!native_.OpenFile(path, file, error)) return false;
        edr::QuarantineFileInfo info;
        std::string finalPath;
        bool ok = native_.FileInfo(file, info, error) &&
            native_.FinalPath(file, finalPath, error) &&
            SameTestPath(path, finalPath) &&
            !(info.attributes & (FILE_ATTRIBUTE_DIRECTORY |
                                 FILE_ATTRIBUTE_REPARSE_POINT)) &&
            info.numberOfLinks == 1 && info.size > 0 &&
            info.size <= maximumBytes &&
            IsExpectedCurrentUserTestAcl(file, error);
        if (!ok && error == ERROR_SUCCESS) error = ERROR_INVALID_DATA;
        if (ok) {
            LARGE_INTEGER zero = {};
            ok = SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) != FALSE;
            if (!ok) error = GetLastError();
        }
        if (ok) {
            bytes.resize(static_cast<size_t>(info.size));
            size_t offset = 0;
            while (offset < bytes.size()) {
                const DWORD request = static_cast<DWORD>(
                    std::min<size_t>(bytes.size() - offset, MAXDWORD));
                DWORD read = 0;
                if (!ReadFile(file, bytes.data() + offset, request, &read,
                              nullptr) || read == 0 || read > request) {
                    error = GetLastError() == ERROR_SUCCESS
                        ? ERROR_READ_FAULT : GetLastError();
                    bytes.clear();
                    ok = false;
                    break;
                }
                offset += read;
            }
        }
        native_.CloseHandleSafe(file);
        return ok;
    }
    bool ProtectMetadata(const std::string& clearText, std::string& protectedText,
                         DWORD& error) override {
        return native_.ProtectMetadata(clearText, protectedText, error);
    }
    bool UnprotectMetadata(const std::string& protectedText,
                           std::string& clearText, DWORD& error) override {
        return native_.UnprotectMetadata(protectedText, clearText, error);
    }
    bool ValidateOriginalDacl(const std::vector<unsigned char>& descriptor,
                              bool originalProtected, DWORD& error) override {
        return native_.ValidateOriginalDacl(descriptor, originalProtected, error);
    }
    bool OpenDirectoryNoFollow(const std::string& path, HANDLE& directory,
                               edr::QuarantineFileInfo& info,
                               std::string& finalPath, DWORD& error) override {
        return native_.OpenDirectoryNoFollow(path, directory, info, finalPath,
                                             error);
    }
    bool RenameNoReplaceInDirectory(HANDLE file, HANDLE directory,
                                    const std::string& leaf,
                                    DWORD& error) override {
        return native_.RenameNoReplaceInDirectory(file, directory, leaf, error);
    }
    const std::string& LastFailure() const { return lastFailure_; }
private:
    bool IsQuarantineChild(const std::string& path) const {
        const size_t separator = path.find_last_of("\\/");
        if (separator == std::string::npos || separator + 1 >= path.size())
            return false;
        const std::string parent = path.substr(0, separator);
        const std::string leaf = path.substr(separator + 1);
        return SameTestPath(parent, quarantineDir_) &&
            leaf.find_first_of("\\/:") == std::string::npos &&
            leaf != "." && leaf != "..";
    }

    edr::NativeQuarantinePlatform native_;
    std::string quarantineDir_;
    std::string lastFailure_;
};

edr::QuarantineRequest MakeQuarantineRequest() {
    edr::QuarantineRequest request;
    request.requestId = kSourceRequestId;
    request.timestamp = "134348719355421281";
    request.reason = "restore metadata contract";
    request.path = kSourcePath;
    return request;
}

edr::QuarantineRestoreRequest MakeRestoreRequest() {
    edr::QuarantineRestoreRequest request;
    request.requestId = kRestoreRequestId;
    request.timestamp = "134348719355421282";
    request.reason = "manual restore after review";
    request.sourceRequestId = kSourceRequestId;
    return request;
}

edr::QuarantineResult ExecuteQuarantine(RestoreTestPlatform& platform,
        RestoreTestAudit& audit, RestoreTestEmergency& emergency) {
    edr::QuarantineExecutor executor(platform, audit, emergency,
                                     kQuarantineDir, 1024);
    return executor.Execute(MakeQuarantineRequest());
}

edr::QuarantineRestoreResult ExecuteRestore(RestoreTestPlatform& platform,
        RestoreTestAudit& audit, RestoreTestEmergency& emergency,
        const edr::QuarantineRestoreRequest& request = MakeRestoreRequest()) {
    /* This new executor models service restart: files and sidecars persist in
     * the platform, but no in-memory executor state is shared. */
    edr::QuarantineExecutor reopened(platform, audit, emergency,
                                     kQuarantineDir, 1024);
    return reopened.Restore(request);
}

void TestNewQuarantinePersistsVersionedRestoreEnvelope() {
    RestoreTestPlatform platform;
    RestoreTestAudit audit;
    RestoreTestEmergency emergency;
    const edr::QuarantineResult result =
        ExecuteQuarantine(platform, audit, emergency);

    QR_CHECK(result.status == "quarantined");
    QR_CHECK(result.auditWritten);
    QR_CHECK(audit.quarantineAttempts == 1 && audit.quarantineOutcomes == 1);
    QR_CHECK(platform.files.find(QuarantinePath()) != platform.files.end());

    const auto found = platform.sidecars.find(SidecarPath(kSourceRequestId));
    QR_CHECK(found != platform.sidecars.end());
    QR_CHECK(platform.sidecarOwnerProtected[SidecarPath(kSourceRequestId)]);
    const jsonlite::Value sidecar = jsonlite::parse(found->second);
    const auto* version = sidecar.find("schema_version");
    const auto* sourceRequestId = sidecar.find("source_request_id");
    const auto* protectedMetadata = sidecar.find("protected_metadata");
    QR_CHECK(version != nullptr && version->type == jsonlite::Type::Number &&
             version->number == 2);
    QR_CHECK(sourceRequestId != nullptr &&
             sourceRequestId->type == jsonlite::Type::String &&
             sourceRequestId->str == kSourceRequestId);
    QR_CHECK(protectedMetadata != nullptr &&
             protectedMetadata->type == jsonlite::Type::String &&
             !protectedMetadata->str.empty());
}

void TestRestoreSurvivesExecutorRestartAndRestoresDacl() {
    RestoreTestPlatform platform;
    RestoreTestAudit audit;
    RestoreTestEmergency emergency;
    const std::vector<unsigned char> expectedDacl = platform.originalDacl;
    QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");

    const edr::QuarantineRestoreResult result =
        ExecuteRestore(platform, audit, emergency);

    if (result.status != "restored") {
        throw std::runtime_error("restart round-trip restore status=" +
            result.status + " win32=" + std::to_string(result.win32Error) +
            " relative_renames=" + std::to_string(platform.relativeRenameCalls) +
            " audit_attempts=" + std::to_string(audit.restoreAttempts) +
            " audit_outcomes=" + std::to_string(audit.restoreOutcomes));
    }
    QR_CHECK(result.status == "restored");
    QR_CHECK(result.auditWritten);
    QR_CHECK(!result.partialRestore);
    QR_CHECK(result.requestId == kRestoreRequestId);
    QR_CHECK(result.sourceRequestId == kSourceRequestId);
    QR_CHECK(result.originalPath == kSourcePath);
    QR_CHECK(result.sha256Hex == kFileHash);
    QR_CHECK(platform.files.find(QuarantinePath()) == platform.files.end());
    const auto restored = platform.files.find(kSourcePath);
    QR_CHECK(restored != platform.files.end());
    QR_CHECK(restored->second->hash == kFileHash);
    QR_CHECK(restored->second->dacl == expectedDacl);
    QR_CHECK(restored->second->daclProtected);
    QR_CHECK(platform.relativeRenameCalls == 1);
    QR_CHECK(platform.relativeRenameDestinations.size() == 1 &&
             platform.relativeRenameDestinations[0] == kSourcePath);
    QR_CHECK(audit.restoreAttempts == 1 && audit.restoreOutcomes == 1);
    QR_CHECK(audit.restoredSourceId == kSourceRequestId);
    QR_CHECK(audit.restoredPath == kSourcePath &&
             audit.restoredHash == kFileHash);
    QR_CHECK(!audit.restoredSidecarDigest.empty());
}

void TestRestoreConflictDoesNotReplaceDestination() {
    RestoreTestPlatform platform;
    RestoreTestAudit audit;
    RestoreTestEmergency emergency;
    QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
    const std::string existingBytes = "pre-existing destination must survive";
    auto existing = platform.AddFile(kSourcePath, existingBytes);

    const edr::QuarantineRestoreResult result =
        ExecuteRestore(platform, audit, emergency);

    QR_CHECK(result.status == "destination_exists");
    QR_CHECK(!result.partialRestore);
    QR_CHECK(platform.files.find(QuarantinePath()) != platform.files.end());
    QR_CHECK(platform.files.find(kSourcePath)->second == existing);
    QR_CHECK(existing->contents == existingBytes);
    QR_CHECK(platform.restoreAclCalls == 0);
    QR_CHECK(audit.restoreAttempts == 1 && audit.restoreOutcomes == 1);
}

void TestTamperedSidecarAndLegacySidecarAreNotRestorable() {
    {
        RestoreTestPlatform platform;
        RestoreTestAudit audit;
        RestoreTestEmergency emergency;
        QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
        platform.sidecars[SidecarPath(kSourceRequestId)] =
            "{\"schema_version\":2,\"source_request_id\":\"f1900000-1234\","
            "\"protected_metadata\":\"edited\"}";

        const edr::QuarantineRestoreResult result =
            ExecuteRestore(platform, audit, emergency);

        QR_CHECK(result.status == "metadata_invalid");
        QR_CHECK(platform.files.find(QuarantinePath()) != platform.files.end());
        QR_CHECK(platform.files.find(kSourcePath) == platform.files.end());
        QR_CHECK(platform.relativeRenameCalls == 0);
        QR_CHECK(audit.restoreAttempts == 0);
    }
    {
        RestoreTestPlatform platform;
        RestoreTestAudit audit;
        RestoreTestEmergency emergency;
        QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
        platform.sidecars[SidecarPath(kSourceRequestId)] =
            "{\"original_path\":\"C:\\\\safe-test\\\\sample.bin\","
            "\"sha256\":\"" + std::string(kFileHash) + "\"}";

        const edr::QuarantineRestoreResult result =
            ExecuteRestore(platform, audit, emergency);

        QR_CHECK(result.status == "not_restorable");
        QR_CHECK(platform.relativeRenameCalls == 0);
        QR_CHECK(audit.restoreAttempts == 0);
    }
}

void TestRestoreRejectsChangedContentOrObjectIdentity() {
    for (bool changeIdentity : {false, true}) {
        RestoreTestPlatform platform;
        RestoreTestAudit audit;
        RestoreTestEmergency emergency;
        QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
        auto quarantined = platform.files.at(QuarantinePath());
        if (changeIdentity) {
            quarantined->info.fileId[0] ^= 0xff;
        } else {
            quarantined->hash = std::string(64, 'b');
        }

        const edr::QuarantineRestoreResult result =
            ExecuteRestore(platform, audit, emergency);

        QR_CHECK(result.status == (changeIdentity ? "identity_changed" :
                                                       "content_mismatch"));
        QR_CHECK(platform.files.find(QuarantinePath()) != platform.files.end());
        QR_CHECK(platform.files.find(kSourcePath) == platform.files.end());
        QR_CHECK(platform.relativeRenameCalls == 0);
        QR_CHECK(audit.restoreAttempts == 0);
    }
}

void TestRestoreRejectsInvalidDaclBeforeMutation() {
    RestoreTestPlatform platform;
    RestoreTestAudit audit;
    RestoreTestEmergency emergency;
    QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
    platform.rejectOriginalDacl = true;

    const edr::QuarantineRestoreResult result =
        ExecuteRestore(platform, audit, emergency);

    QR_CHECK(result.status == "metadata_invalid");
    QR_CHECK(platform.files.find(QuarantinePath()) != platform.files.end());
    QR_CHECK(platform.files.find(kSourcePath) == platform.files.end());
    QR_CHECK(platform.relativeRenameCalls == 0);
    QR_CHECK(audit.restoreAttempts == 0);
}

void TestRestoreRejectsProtectedAndReparseDestinations() {
    {
        RestoreTestPlatform platform;
        RestoreTestAudit audit;
        RestoreTestEmergency emergency;
        QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
        platform.metadataPathOverride =
            edr::ExpandEnvStrings("%SystemRoot%\\System32\\restore-owned.bin");

        const edr::QuarantineRestoreResult result =
            ExecuteRestore(platform, audit, emergency);

        QR_CHECK(result.status == "policy_rejected");
        QR_CHECK(platform.relativeRenameCalls == 0);
    }
    {
        RestoreTestPlatform platform;
        RestoreTestAudit audit;
        RestoreTestEmergency emergency;
        QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
        platform.forceReparseParent = true;

        const edr::QuarantineRestoreResult result =
            ExecuteRestore(platform, audit, emergency);

        QR_CHECK(result.status == "path_resolution_failed");
        QR_CHECK(platform.relativeRenameCalls == 0);
    }
}

void TestRestoreAuditFailureBlocksMutationAndOutcomeFailureIsUncertain() {
    {
        RestoreTestPlatform platform;
        RestoreTestAudit audit;
        RestoreTestEmergency emergency;
        QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
        audit.rejectRestoreAttempt = true;

        const edr::QuarantineRestoreResult result =
            ExecuteRestore(platform, audit, emergency);

        QR_CHECK(result.status == "audit_failed");
        QR_CHECK(!result.auditWritten);
        QR_CHECK(platform.files.find(QuarantinePath()) != platform.files.end());
        QR_CHECK(platform.relativeRenameCalls == 0);
        QR_CHECK(audit.restoreAttempts == 1 && audit.restoreOutcomes == 0);
    }
    {
        RestoreTestPlatform platform;
        RestoreTestAudit audit;
        RestoreTestEmergency emergency;
        QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
        audit.rejectRestoreOutcome = true;

        const edr::QuarantineRestoreResult result =
            ExecuteRestore(platform, audit, emergency);

        QR_CHECK(result.status == "restored");
        QR_CHECK(!result.auditWritten);
        QR_CHECK(platform.files.find(kSourcePath) != platform.files.end());
        QR_CHECK(audit.restoreAttempts == 1 && audit.restoreOutcomes == 1);
        QR_CHECK(emergency.calls == 1);
    }
}

void TestDaclRestoreFailureReportsProtectedPartialState() {
    RestoreTestPlatform platform;
    RestoreTestAudit audit;
    RestoreTestEmergency emergency;
    QR_CHECK(ExecuteQuarantine(platform, audit, emergency).status == "quarantined");
    platform.rejectRestoreAcl = true;

    const edr::QuarantineRestoreResult result =
        ExecuteRestore(platform, audit, emergency);

    QR_CHECK(result.status == "restore_acl_failed");
    QR_CHECK(result.partialRestore);
    QR_CHECK(platform.files.find(kSourcePath) != platform.files.end());
    QR_CHECK(platform.files.find(QuarantinePath()) == platform.files.end());
    QR_CHECK(platform.files.at(kSourcePath)->dacl ==
             std::vector<unsigned char>({0x53, 0x59, 0x53, 0x41}));
    QR_CHECK(audit.restoreAttempts == 1 && audit.restoreOutcomes == 1);
    QR_CHECK(emergency.calls == 1);
}

struct NativeTempTree {
    std::wstring root;
    std::wstring sourceDir;
    std::wstring quarantineDir;
    std::wstring sourcePath;

    NativeTempTree(std::wstring rootPath, std::wstring sourceDirectory,
                   std::wstring quarantineDirectory, std::wstring source)
        : root(std::move(rootPath)), sourceDir(std::move(sourceDirectory)),
          quarantineDir(std::move(quarantineDirectory)),
          sourcePath(std::move(source)) {}
    NativeTempTree(const NativeTempTree&) = delete;
    NativeTempTree& operator=(const NativeTempTree&) = delete;
    NativeTempTree(NativeTempTree&& other) noexcept
        : root(std::move(other.root)), sourceDir(std::move(other.sourceDir)),
          quarantineDir(std::move(other.quarantineDir)),
          sourcePath(std::move(other.sourcePath)) {
        other.root.clear();
    }
    ~NativeTempTree() {
        if (root.empty()) return;
        DeleteFileW(sourcePath.c_str());
        WIN32_FIND_DATAW entry = {};
        HANDLE find = FindFirstFileW((quarantineDir + L"\\*").c_str(), &entry);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if (!(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    DeleteFileW((quarantineDir + L"\\" + entry.cFileName).c_str());
            } while (FindNextFileW(find, &entry));
            FindClose(find);
        }
        RemoveDirectoryW(quarantineDir.c_str());
        RemoveDirectoryW(sourceDir.c_str());
        RemoveDirectoryW(root.c_str());
    }
};

NativeTempTree MakeNativeTempTree(const wchar_t* suffix) {
    wchar_t temp[MAX_PATH] = {};
    QR_CHECK(GetTempPathW(MAX_PATH, temp) > 0);
    const std::wstring root = std::wstring(temp) + L"edr-restore-" + suffix +
        L"-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
    NativeTempTree tree(root, root + L"\\source", root + L"\\quarantine",
                        root + L"\\source\\owned.bin");
    QR_CHECK(CreateDirectoryW(tree.root.c_str(), nullptr));
    QR_CHECK(CreateDirectoryW(tree.sourceDir.c_str(), nullptr));
    QR_CHECK(CreateDirectoryW(tree.quarantineDir.c_str(), nullptr));
    return tree;
}

void WriteNativeTempFile(const std::wstring& path, const std::string& contents) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    QR_CHECK(file != INVALID_HANDLE_VALUE);
    DWORD written = 0;
    const bool ok = contents.size() <= MAXDWORD && WriteFile(file,
        contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) &&
        written == contents.size() && FlushFileBuffers(file);
    CloseHandle(file);
    QR_CHECK(ok);
}

struct NativeDaclSnapshot {
    std::vector<unsigned char> bytes;
    bool protectedDacl = false;
};

NativeDaclSnapshot CaptureNativeDacl(const std::wstring& path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    const DWORD status = GetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
        &descriptor);
    QR_CHECK(status == ERROR_SUCCESS && descriptor && dacl);
    ACL_SIZE_INFORMATION aclInfo = {};
    QR_CHECK(GetAclInformation(dacl, &aclInfo, sizeof(aclInfo),
                               AclSizeInformation));
    NativeDaclSnapshot snapshot;
    snapshot.bytes.assign(reinterpret_cast<unsigned char*>(dacl),
        reinterpret_cast<unsigned char*>(dacl) + aclInfo.AclBytesInUse);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    QR_CHECK(GetSecurityDescriptorControl(descriptor, &control, &revision));
    snapshot.protectedDacl = (control & SE_DACL_PROTECTED) != 0;
    LocalFree(descriptor);
    return snapshot;
}

uint64_t CurrentNativeFileTime() {
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
}

void TestNativeRestoreRoundTripAfterExecutorRestart(bool currentUserAcl) {
    NativeTempTree tree = MakeNativeTempTree(L"roundtrip");
    const std::string contents = "controlled native quarantine restore bytes";
    WriteNativeTempFile(tree.sourcePath, contents);
    const NativeDaclSnapshot originalDacl = CaptureNativeDacl(tree.sourcePath);
    const std::string sourcePath = edr::WideToUtf8(tree.sourcePath.c_str());
    const std::string quarantineDir = edr::WideToUtf8(tree.quarantineDir.c_str());
    edr::NativeQuarantinePlatform nativePlatform;
    CurrentUserNativeTestPlatform currentUserPlatform(quarantineDir);
    edr::IQuarantinePlatform& platform = currentUserAcl
        ? static_cast<edr::IQuarantinePlatform&>(currentUserPlatform)
        : static_cast<edr::IQuarantinePlatform&>(nativePlatform);
    const edr::QuarantineRequest quarantineRequest{
        "f1900002-1234-1234-1234-123456789abc",
        std::to_string(CurrentNativeFileTime()), "controlled native restore",
        sourcePath, ""};
    RestoreTestAudit audit;
    RestoreTestEmergency emergency;
    edr::QuarantineResult quarantined;
    {
        edr::QuarantineExecutor executor(platform, audit, emergency,
                                         quarantineDir, 1024 * 1024);
        quarantined = executor.Execute(quarantineRequest);
    }
    if (quarantined.status != "quarantined") {
        throw std::runtime_error("native temp quarantine status=" +
            quarantined.status + " win32=" +
            std::to_string(quarantined.win32Error) + " source=" + sourcePath +
            " quarantine_dir=" + quarantineDir + " quarantine_path=" +
            quarantined.quarantinePath +
            (currentUserAcl ? " adapter_stage=" + currentUserPlatform.LastFailure()
                            : std::string()));
    }
    QR_CHECK(quarantined.status == "quarantined");
    QR_CHECK(quarantined.auditWritten &&
             quarantined.sidecarSha256Hex.size() == 64);
    QR_CHECK(GetFileAttributesW(tree.sourcePath.c_str()) == INVALID_FILE_ATTRIBUTES);

    HANDLE parentDirectory = INVALID_HANDLE_VALUE;
    edr::QuarantineFileInfo parentInfo;
    std::string finalParent;
    DWORD parentError = ERROR_SUCCESS;
    const std::string sourceDirectory = edr::WideToUtf8(tree.sourceDir.c_str());
    QR_CHECK(platform.OpenDirectoryNoFollow(sourceDirectory, parentDirectory,
        parentInfo, finalParent, parentError));
    const std::wstring renamedSourceDir = tree.root + L"\\source-renamed";
    SetLastError(ERROR_SUCCESS);
    const BOOL parentRenameSucceeded = MoveFileExW(tree.sourceDir.c_str(),
        renamedSourceDir.c_str(), MOVEFILE_WRITE_THROUGH);
    const DWORD parentRenameError = parentRenameSucceeded
        ? ERROR_SUCCESS : GetLastError();
    platform.CloseHandleSafe(parentDirectory);
    QR_CHECK(!parentRenameSucceeded);
    QR_CHECK(parentRenameError == ERROR_SHARING_VIOLATION);

    const edr::QuarantineRestoreRequest restoreRequest{
        "f1900003-1234-1234-1234-123456789abc",
        std::to_string(CurrentNativeFileTime()), "controlled native restore",
        quarantineRequest.requestId};
    edr::QuarantineRestoreResult restored;
    {
        edr::QuarantineExecutor reopened(platform, audit, emergency,
                                         quarantineDir, 1024 * 1024);
        restored = reopened.Restore(restoreRequest);
    }
    if (restored.status != "restored") {
        throw std::runtime_error("native temp restore status=" +
            restored.status + " win32=" + std::to_string(restored.win32Error) +
            " partial=" + std::to_string(restored.partialRestore) +
            " audit_written=" + std::to_string(restored.auditWritten) +
            " source_exists=" + std::to_string(
                GetFileAttributesW(tree.sourcePath.c_str()) !=
                    INVALID_FILE_ATTRIBUTES) +
            " quarantine_exists=" + std::to_string(
                GetFileAttributesW(edr::Utf8ToWide(
                    quarantined.quarantinePath).c_str()) !=
                    INVALID_FILE_ATTRIBUTES) +
            " attempts=" + std::to_string(audit.restoreAttempts) +
            " outcomes=" + std::to_string(audit.restoreOutcomes) +
            " emergency=" + std::to_string(emergency.calls));
    }
    QR_CHECK(restored.status == "restored");
    QR_CHECK(restored.auditWritten && !restored.partialRestore);
    QR_CHECK(restored.sha256Hex.size() == 64 &&
             restored.sidecarSha256Hex == quarantined.sidecarSha256Hex);
    QR_CHECK(audit.quarantineAttempts == 1 && audit.quarantineOutcomes == 1 &&
             audit.restoreAttempts == 1 && audit.restoreOutcomes == 1);
    QR_CHECK(GetFileAttributesW(tree.sourcePath.c_str()) != INVALID_FILE_ATTRIBUTES);
    const NativeDaclSnapshot restoredDacl = CaptureNativeDacl(tree.sourcePath);
    QR_CHECK(restoredDacl.bytes == originalDacl.bytes &&
             restoredDacl.protectedDacl == originalDacl.protectedDacl);
    HANDLE restoredFile = INVALID_HANDLE_VALUE;
    DWORD error = ERROR_SUCCESS;
    QR_CHECK(platform.OpenFile(sourcePath, restoredFile, error));
    std::string restoredHash;
    QR_CHECK(platform.Hash(restoredFile, restoredHash, error));
    platform.CloseHandleSafe(restoredFile);
    QR_CHECK(restoredHash == restored.sha256Hex);
}

void TestNativeRestoreConflictPreservesExistingDestination(bool currentUserAcl) {
    NativeTempTree tree = MakeNativeTempTree(L"conflict");
    const std::string sourcePath = edr::WideToUtf8(tree.sourcePath.c_str());
    const std::string quarantineDir = edr::WideToUtf8(tree.quarantineDir.c_str());
    edr::NativeQuarantinePlatform nativePlatform;
    CurrentUserNativeTestPlatform currentUserPlatform(quarantineDir);
    edr::IQuarantinePlatform& platform = currentUserAcl
        ? static_cast<edr::IQuarantinePlatform&>(currentUserPlatform)
        : static_cast<edr::IQuarantinePlatform&>(nativePlatform);
    WriteNativeTempFile(tree.sourcePath, "controlled quarantine conflict bytes");
    const edr::QuarantineRequest quarantineRequest{
        "f1900004-1234-1234-1234-123456789abc",
        std::to_string(CurrentNativeFileTime()), "controlled conflict test",
        sourcePath, ""};
    RestoreTestAudit audit;
    RestoreTestEmergency emergency;
    edr::QuarantineResult quarantined;
    {
        edr::QuarantineExecutor executor(platform, audit, emergency,
                                         quarantineDir, 1024 * 1024);
        quarantined = executor.Execute(quarantineRequest);
    }
    QR_CHECK(quarantined.status == "quarantined");
    const std::string conflictingContents = "keep this pre-existing file";
    WriteNativeTempFile(tree.sourcePath, conflictingContents);

    const edr::QuarantineRestoreRequest restoreRequest{
        "f1900005-1234-1234-1234-123456789abc",
        std::to_string(CurrentNativeFileTime()), "controlled conflict test",
        quarantineRequest.requestId};
    edr::QuarantineRestoreResult result;
    {
        edr::QuarantineExecutor reopened(platform, audit, emergency,
                                         quarantineDir, 1024 * 1024);
        result = reopened.Restore(restoreRequest);
    }
    QR_CHECK(result.status == "destination_exists");
    QR_CHECK(result.auditWritten && !result.partialRestore);
    QR_CHECK(audit.restoreAttempts == 1 && audit.restoreOutcomes == 1);
    QR_CHECK(GetFileAttributesW(tree.sourcePath.c_str()) != INVALID_FILE_ATTRIBUTES);
    QR_CHECK(GetFileAttributesW(edr::Utf8ToWide(
        quarantined.quarantinePath).c_str()) != INVALID_FILE_ATTRIBUTES);
    std::ifstream existing(tree.sourcePath, std::ios::binary);
    const std::string actual((std::istreambuf_iterator<char>(existing)),
                             std::istreambuf_iterator<char>());
    QR_CHECK(actual == conflictingContents);
}

void TestCurrentUserNativeRestoreRoundTripAndConflict() {
    TestNativeRestoreRoundTripAfterExecutorRestart(true);
    TestNativeRestoreConflictPreservesExistingDestination(true);
}

} // namespace

void RunQuarantineRestoreTests() {
    TestNewQuarantinePersistsVersionedRestoreEnvelope();
    TestRestoreSurvivesExecutorRestartAndRestoresDacl();
    TestRestoreConflictDoesNotReplaceDestination();
    TestTamperedSidecarAndLegacySidecarAreNotRestorable();
    TestRestoreRejectsChangedContentOrObjectIdentity();
    TestRestoreRejectsInvalidDaclBeforeMutation();
    TestRestoreRejectsProtectedAndReparseDestinations();
    TestRestoreAuditFailureBlocksMutationAndOutcomeFailureIsUncertain();
    TestDaclRestoreFailureReportsProtectedPartialState();
    TestCurrentUserNativeRestoreRoundTripAndConflict();
}

int RunQuarantineRestoreNativeTests(std::string& skipReason) {
    bool hasPrivilege = false;
    /* Check membership errors separately from a normal non-admin token so
     * only the expected privilege limitation is reported as a CTest skip. */
    BYTE systemSid[SECURITY_MAX_SID_SIZE], adminSid[SECURITY_MAX_SID_SIZE];
    DWORD systemSize = sizeof(systemSid), adminSize = sizeof(adminSid);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSize) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid,
                            &adminSize)) {
        skipReason = "well-known SID lookup failed: " +
            std::to_string(GetLastError());
        return 1;
    }
    BOOL isSystem = FALSE, isAdministrator = FALSE;
    if (!CheckTokenMembership(nullptr, systemSid, &isSystem) ||
        !CheckTokenMembership(nullptr, adminSid, &isAdministrator)) {
        skipReason = "token membership check failed: " +
            std::to_string(GetLastError());
        return 1;
    }
    hasPrivilege = isSystem || isAdministrator;
    if (!hasPrivilege) {
        skipReason = "requires LocalSystem or an enabled Administrators token "
                     "for the production SYSTEM/Administrators-only quarantine ACL";
        return 77;
    }
    skipReason.clear();
    edr::NativeQuarantinePlatform platform;
    TestNativeRestoreRoundTripAfterExecutorRestart(false);
    TestNativeRestoreConflictPreservesExistingDestination(false);
    return 0;
}
