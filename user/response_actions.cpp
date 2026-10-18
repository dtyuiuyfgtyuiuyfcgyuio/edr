#include "response_actions.h"

#include <sddl.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

#include "config.h"
#include "../common/edr_ioctl.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cwctype>
#include <deque>
#include <memory>
#include <unordered_set>
#include <vector>

namespace edr {
namespace {

constexpr DWORD kProcessAccess = PROCESS_QUERY_LIMITED_INFORMATION |
    PROCESS_TERMINATE | SYNCHRONIZE;

DWORD LastErrorOr(DWORD fallback) {
    DWORD value = GetLastError();
    return value == ERROR_SUCCESS ? fallback : value;
}

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), towlower);
    return value;
}

bool DeniedImage(const std::wstring& value) {
    static const std::unordered_set<std::wstring> denied = {
        L"csrss.exe", L"lsass.exe", L"services.exe", L"smss.exe",
        L"wininit.exe", L"winlogon.exe", L"lsaiso.exe", L"system", L"registry"
    };
    return denied.find(Lower(value)) != denied.end();
}

/* Per-child deny-list: the single-process deny-list plus svchost.exe
 * (a tree kill that touches svchost is always refused for that child). */
bool DeniedTreeChild(const std::wstring& value) {
    static const std::unordered_set<std::wstring> denied = {
        L"csrss.exe", L"lsass.exe", L"services.exe", L"smss.exe",
        L"wininit.exe", L"winlogon.exe", L"lsaiso.exe", L"system",
        L"registry", L"svchost.exe"
    };
    return denied.find(Lower(value)) != denied.end();
}

bool ContainsWhitelistToken(const std::wstring& value,
                            const std::vector<std::string>& whitelist) {
    std::wstring lower = Lower(value);
    for (const auto& token : whitelist) {
        std::wstring wide = Lower(Utf8ToWide(token));
        if (!wide.empty() && lower.find(wide) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool ServiceSid(const std::wstring& sid) {
    return sid == L"S-1-5-18" || sid == L"S-1-5-19" || sid == L"S-1-5-20";
}

ResponseActionResult Reject(const ResponseActionRequest& request,
                            const char* status, DWORD error = ERROR_ACCESS_DENIED) {
    ResponseActionResult result;
    result.requestId = request.requestId;
    result.status = status;
    result.win32Error = error;
    return result;
}

DeleteFileResult RejectDeleteFile(const DeleteFileRequest& request,
                                  const char* status, DWORD error = ERROR_ACCESS_DENIED) {
    DeleteFileResult result;
    result.requestId = request.requestId;
    result.path = request.path;
    result.status = status;
    result.win32Error = error;
    return result;
}

bool WellFormedLocalPath(const std::wstring& path) {
    if (path.size() < 3 || !iswalpha(path[0]) || path[1] != L':' ||
        path[2] != L'\\' || path.find(L'\0') != std::wstring::npos ||
        path.find(L'/') != std::wstring::npos) return false;
    size_t start = 3;
    while (start < path.size()) {
        const size_t end = path.find(L'\\', start);
        const std::wstring part = path.substr(start, end - start);
        if (part.empty() || part == L"." || part == L".." ||
            part.back() == L'.' || part.back() == L' ' ||
            part.find(L':') != std::wstring::npos) return false;
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return path.back() != L'\\' || path.size() == 3;
}

bool IsProtectedPath(const std::wstring& path) {
    wchar_t windows[MAX_PATH] = {};
    const UINT length = GetWindowsDirectoryW(windows, MAX_PATH);
    if (!length || length >= MAX_PATH) return true;
    std::vector<std::wstring> roots = {windows};
    for (const KNOWNFOLDERID* folder : {&FOLDERID_ProgramFiles,
                                        &FOLDERID_ProgramData,
                                        &FOLDERID_Public}) {
        PWSTR value = nullptr;
        HRESULT status = SHGetKnownFolderPath(*folder, KF_FLAG_DONT_VERIFY,
                                              nullptr, &value);
        if (FAILED(status) || !value) {
            if (value) CoTaskMemFree(value);
            return true;
        }
        roots.emplace_back(value);
        CoTaskMemFree(value);
    }
    PWSTR x86 = nullptr;
    const HRESULT x86Status = SHGetKnownFolderPath(FOLDERID_ProgramFilesX86,
                                      KF_FLAG_DONT_VERIFY, nullptr, &x86);
    if (FAILED(x86Status) || !x86) {
        if (x86) CoTaskMemFree(x86);
        return true;
    }
    roots.emplace_back(x86);
    CoTaskMemFree(x86);
    roots.push_back(std::wstring(1, windows[0]) + L":\\$Recycle.Bin");
    return IsProtectedResponsePathForRoots(path, roots);
}

} // namespace

bool IsProtectedResponsePathForRoots(
    const std::wstring& path, const std::vector<std::wstring>& roots) {
    if (!WellFormedLocalPath(path) || roots.empty()) return true;
    const std::wstring lower = Lower(path);
    for (const std::wstring& root : roots) {
        if (!WellFormedLocalPath(root) || root.size() <= 3) return true;
        const std::wstring prefix = Lower(root);
        if (lower.size() >= prefix.size() &&
            lower.compare(0, prefix.size(), prefix) == 0 &&
            (lower.size() == prefix.size() || lower[prefix.size()] == L'\\')) {
            return true;
        }
    }
    return false;
}

namespace {

bool ValidDeletePath(const std::wstring& path) {
    /* DeleteFileW interprets drive paths, device paths and reparse points
     * differently. Restrict this destructive action to existing local files
     * whose entire path can be checked before writing the audit attempt. */
    if (path.size() < 4 || path.find(L'\0') != std::wstring::npos ||
        !((path[0] >= L'A' && path[0] <= L'Z') ||
          (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\') return false;
    bool targetExists = true;
    size_t start = 3;
    while (start < path.size()) {
        size_t end = path.find(L'\\', start);
        if (end == std::wstring::npos) end = path.size();
        const std::wstring component = path.substr(start, end - start);
        if (component.empty() || component == L"." || component == L".." ||
            component.back() == L'.' || component.back() == L' ' ||
            component.find(L':') != std::wstring::npos ||
            component.find(L'/') != std::wstring::npos) return false;
        std::wstring prefix = path.substr(0, end);
        DWORD attr = GetFileAttributesW(prefix.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            if (end != path.size() || GetLastError() != ERROR_FILE_NOT_FOUND)
                return false;
            targetExists = false;
        } else if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
            return false;
        }
        if (end < path.size() && !(attr & FILE_ATTRIBUTE_DIRECTORY)) return false;
        if (end == path.size() && targetExists &&
            (attr & FILE_ATTRIBUTE_DIRECTORY)) return false;
        start = end + 1;
    }
    if (path.back() == L'\\') return false;

    /* Expand 8.3 aliases before checking protected directories. A missing
     * leaf is allowed so repeated delete requests remain idempotent. */
    const std::wstring existingPath = targetExists ? path :
        path.substr(0, path.find_last_of(L'\\') + 1);
    std::vector<wchar_t> expanded(32768);
    DWORD length = GetLongPathNameW(existingPath.c_str(), expanded.data(),
                                    static_cast<DWORD>(expanded.size()));
    if (length == 0 || length >= expanded.size()) return false;
    std::wstring expandedPath(expanded.data(), length);
    if (expandedPath.size() > 3 && expandedPath.back() == L'\\')
        expandedPath.pop_back();
    return !IsProtectedPath(expandedPath);
}

std::string HexString(const unsigned char* data, size_t size) {
    static const char kHex[] = "0123456789abcdef";
    std::string out(size * 2, '0');
    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return out;
}

std::string Sha256HexFile(const std::wstring& path) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objSize = 0, resultSize = 0;
    std::vector<unsigned char> obj;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0) status = BCryptGetProperty(
        alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objSize),
        sizeof(objSize), &resultSize, 0);
    if (status >= 0) {
        obj.resize(objSize);
        status = BCryptCreateHash(alg, &hash, obj.data(), objSize, nullptr, 0, 0);
    }
    struct Guard {
        BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h;
        ~Guard() { if (h) BCryptDestroyHash(h); if (a) BCryptCloseAlgorithmProvider(a, 0); }
    } guard{alg, hash};
    if (status < 0) return {};

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    constexpr DWORD kChunk = 65536;
    std::vector<unsigned char> buffer(kChunk);
    DWORD read = 0;
    while (ReadFile(file, buffer.data(), kChunk, &read, nullptr) && read > 0) {
        status = BCryptHashData(hash, buffer.data(), read, 0);
        if (status < 0) { CloseHandle(file); return {}; }
    }
    CloseHandle(file);
    std::array<unsigned char, 32> digest{};
    status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (status < 0) return {};
    return HexString(digest.data(), digest.size());
}

} // namespace

bool ResponseFileIdentity::operator==(const ResponseFileIdentity& other) const {
    return volumeSerial == other.volumeSerial &&
        memcmp(fileId, other.fileId, sizeof(fileId)) == 0;
}

bool NativeResponseActionPlatform::Open(uint32_t pid, HANDLE& process,
                                        DWORD& error) {
    process = OpenProcess(kProcessAccess, FALSE, pid);
    if (!process) { error = LastErrorOr(ERROR_ACCESS_DENIED); return false; }
    return true;
}

void NativeResponseActionPlatform::Close(HANDLE process) { CloseHandle(process); }

bool NativeResponseActionPlatform::Image(HANDLE process, std::wstring& path,
                                         std::wstring& base, DWORD& error) {
    std::vector<wchar_t> buffer(32768);
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size) || !size) {
        error = LastErrorOr(ERROR_FILE_NOT_FOUND); return false;
    }
    path.assign(buffer.data(), size);
    size_t slash = path.find_last_of(L"\\/");
    base = slash == std::wstring::npos ? path : path.substr(slash + 1);
    if (base.empty()) { error = ERROR_FILE_NOT_FOUND; return false; }
    return true;
}

bool NativeResponseActionPlatform::FileIdentity(const std::wstring& path,
                                                ResponseFileIdentity& identity,
                                                DWORD& error) {
    HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_FILE_NOT_FOUND); return false;
    }
    FILE_ID_INFO info = {};
    BOOL ok = GetFileInformationByHandleEx(file, FileIdInfo, &info, sizeof(info));
    if (!ok) error = LastErrorOr(ERROR_NOT_SUPPORTED);
    CloseHandle(file);
    if (!ok) return false;
    identity.volumeSerial = info.VolumeSerialNumber;
    memcpy(identity.fileId, info.FileId.Identifier, sizeof(identity.fileId));
    return true;
}

bool NativeResponseActionPlatform::OpenFileForDelete(
        const std::wstring& path, HANDLE& file, ResponseFileIdentity& identity,
        DWORD& error) {
    file = CreateFileW(path.c_str(), DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        file = nullptr;
        error = LastErrorOr(ERROR_ACCESS_DENIED);
        return false;
    }

    auto fail = [&](DWORD failure) {
        error = failure;
        CloseHandle(file);
        file = nullptr;
        return false;
    };

    FILE_ATTRIBUTE_TAG_INFO attributes = {};
    if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo,
                                      &attributes, sizeof(attributes)))
        return fail(LastErrorOr(ERROR_NOT_SUPPORTED));
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return fail(ERROR_ACCESS_DENIED);

    /* Resolve the opened object and apply the protected-root policy to that
     * identity, not only to the path observed before opening it. */
    std::vector<wchar_t> finalBuffer(32768);
    DWORD finalLength = GetFinalPathNameByHandleW(file, finalBuffer.data(),
        static_cast<DWORD>(finalBuffer.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!finalLength || finalLength >= finalBuffer.size())
        return fail(LastErrorOr(ERROR_INVALID_NAME));
    std::wstring finalPath(finalBuffer.data(), finalLength);
    if (finalPath.rfind(L"\\\\?\\", 0) == 0)
        finalPath.erase(0, 4);
    if (finalPath.size() < 4 || finalPath[1] != L':' ||
        finalPath[2] != L'\\' || !ValidDeletePath(finalPath))
        return fail(ERROR_ACCESS_DENIED);

    FILE_ID_INFO info = {};
    if (!GetFileInformationByHandleEx(file, FileIdInfo, &info, sizeof(info)))
        return fail(LastErrorOr(ERROR_NOT_SUPPORTED));
    identity.volumeSerial = info.VolumeSerialNumber;
    memcpy(identity.fileId, info.FileId.Identifier, sizeof(identity.fileId));
    return true;
}

bool NativeResponseActionPlatform::DeleteFileHandle(HANDLE file,
                                                     DWORD& error) {
    FILE_DISPOSITION_INFO disposition = {};
    disposition.DeleteFile = TRUE;
    if (SetFileInformationByHandle(file, FileDispositionInfo, &disposition,
                                   sizeof(disposition))) return true;
    error = LastErrorOr(ERROR_ACCESS_DENIED);
    return false;
}

bool NativeResponseActionPlatform::Critical(HANDLE process, bool& critical,
                                            DWORD& error) {
    using Function = BOOL(WINAPI*)(HANDLE, PBOOL);
    auto function = reinterpret_cast<Function>(GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsProcessCritical"));
    BOOL value = FALSE;
    if (!function || !function(process, &value)) {
        error = function ? LastErrorOr(ERROR_ACCESS_DENIED) : ERROR_NOT_SUPPORTED;
        return false;
    }
    critical = value != FALSE;
    return true;
}

bool NativeResponseActionPlatform::Protected(HANDLE process,
                                             bool& protectedProcess,
                                             DWORD& error) {
    using Function = BOOL(WINAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);
    auto function = reinterpret_cast<Function>(GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "GetProcessInformation"));
    if (!function) { error = ERROR_NOT_SUPPORTED; return false; }
    PROCESS_PROTECTION_LEVEL_INFORMATION info = {};
    if (!function(process, ProcessProtectionLevelInfo, &info, sizeof(info))) {
        error = LastErrorOr(ERROR_ACCESS_DENIED); return false;
    }
    protectedProcess = info.ProtectionLevel != PROTECTION_LEVEL_NONE;
    return true;
}

bool NativeResponseActionPlatform::Session(uint32_t pid, DWORD& session,
                                           DWORD& error) {
    if (!ProcessIdToSessionId(pid, &session)) {
        error = LastErrorOr(ERROR_ACCESS_DENIED); return false;
    }
    return true;
}

bool NativeResponseActionPlatform::UserSid(HANDLE process, std::wstring& sid,
                                           DWORD& error) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        error = LastErrorOr(ERROR_ACCESS_DENIED); return false;
    }
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> buffer(size);
    if (!size || !GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        error = LastErrorOr(ERROR_ACCESS_DENIED); CloseHandle(token); return false;
    }
    LPWSTR text = nullptr;
    bool ok = ConvertSidToStringSidW(
        reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text) != FALSE;
    if (ok) { sid = text; LocalFree(text); }
    else error = LastErrorOr(ERROR_ACCESS_DENIED);
    CloseHandle(token);
    return ok;
}

bool NativeResponseActionPlatform::CreateTime(HANDLE process, uint64_t& value,
                                              DWORD& error) {
    FILETIME create = {}, exit = {}, kernel = {}, user = {};
    if (!GetProcessTimes(process, &create, &exit, &kernel, &user)) {
        error = LastErrorOr(ERROR_ACCESS_DENIED); return false;
    }
    value = (static_cast<uint64_t>(create.dwHighDateTime) << 32) |
        create.dwLowDateTime;
    return true;
}

namespace {

/*
 * Escalation-ladder state: SeDebug is enabled lazily on the first
 * ACCESS_DENIED terminate and stays on for the process lifetime.
 */
bool& DebugPrivilegeEnabled() {
    static bool enabled = false;
    return enabled;
}

bool EnableDebugPrivilegeOnce() {
    if (DebugPrivilegeEnabled()) return true;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    TOKEN_PRIVILEGES tp = {};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME,
                               &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp),
                                          nullptr, nullptr) != FALSE &&
                    GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    DebugPrivilegeEnabled() = ok;
    return ok;
}

/* Settle window used between an escalated kill and the aliveness
 * re-check. Short on purpose: response latency matters. */
constexpr DWORD kEscalationSettleMs = 3000;

/* Legacy PID-only driver IOCTL helper. It is intentionally not called by
 * identity-bound response execution because the request cannot identify a
 * process instance. Keep the fixed wire layout available for a future ABI
 * that carries and validates creation identity. */
[[maybe_unused]] bool DriverKill(uint32_t pid) {
    if (pid == 0) return false;
    HANDLE device = CreateFileW(L"\\\\.\\edrdrv", GENERIC_WRITE, 0,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) return false;
    DWORD returned = 0;
    EDR_KILL_PROCESS_REQUEST request = {pid};
    const BOOL ok = DeviceIoControl(device, IOCTL_EDR_KILL_PROCESS,
                                    &request, EDR_KILL_PROCESS_REQUEST_SIZE,
                                    nullptr, 0,
                                    &returned, nullptr);
    CloseHandle(device);
    return ok != FALSE;
}

} // namespace

bool NativeResponseActionPlatform::Terminate(HANDLE process, DWORD& error) {
    if (TerminateProcess(process, 1)) return true;
    error = LastErrorOr(ERROR_ACCESS_DENIED);

    uint64_t targetCreateTime = 0;
    if (!CreateTime(process, targetCreateTime, error)) return false;
    DWORD targetWait = WaitForSingleObject(process, 0);
    if (targetWait == WAIT_OBJECT_0) return true;
    if (targetWait == WAIT_FAILED) {
        error = LastErrorOr(ERROR_GEN_FAILURE);
        return false;
    }

    /* ---- Escalation ladder for tamper-protected processes ----
     * SilverFox / Gh0stRAT-lineage loaders self-protect against plain
     * TerminateProcess by stripping handle rights from openers or by
     * running an anti-exit watchdog. Escalate in stages, keeping every
     * operation bound to this process instance. */
    const uint32_t pid = GetProcessId(process);

    /* Stage 1: enable SeDebugPrivilege and retry directly. */
    if (pid != 0 && EnableDebugPrivilegeOnce()) {
        HANDLE elevated = OpenProcess(
            PROCESS_TERMINATE | SYNCHRONIZE |
                PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE, pid);
        if (elevated) {
            uint64_t elevatedCreateTime = 0;
            const bool sameInstance =
                CreateTime(elevated, elevatedCreateTime, error) &&
                elevatedCreateTime == targetCreateTime;
            const bool killed = sameInstance &&
                TerminateProcess(elevated, 1) != FALSE;
            if (killed) {
                WaitForSingleObject(elevated, kEscalationSettleMs);
                CloseHandle(elevated);
                return true;
            }
            CloseHandle(elevated);
        }
    }

    /* Stage 2: suspend every thread first so a self-re-spawn watchdog
     * cannot interfere, then retry termination on the same handle. */
    if (pid != 0) {
        DWORD suspendError = 0;
        (void)Suspend(process, targetCreateTime, suspendError);
        if (TerminateProcess(process, 1)) {
            WaitForSingleObject(process, kEscalationSettleMs);
            return true;
        }
        error = GetLastError();
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return true;
    }

    /* Stage 3: contain inside a kill-on-close job object, then force
     * the job to terminate now rather than waiting for handle cleanup. */
    if (pid != 0) {
        HANDLE job = CreateJobObjectW(nullptr, nullptr);
        if (job) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (SetInformationJobObject(job,
                                        JobObjectExtendedLimitInformation,
                                        &limits, sizeof(limits)) &&
                AssignProcessToJobObject(job, process)) {
                TerminateJobObject(job, 1);
                const DWORD wait = WaitForSingleObject(process,
                                                       kEscalationSettleMs);
                CloseHandle(job);
                if (wait == WAIT_OBJECT_0) return true;
            } else {
                CloseHandle(job);
            }
        }
    }

    /* The driver's current request contains only a PID. Do not send it here:
     * after this handle's process exits, Windows may reuse that PID before a
     * PID-only kernel lookup and the driver could terminate a replacement. */

    return false;
}

DWORD NativeResponseActionPlatform::Wait(HANDLE process, DWORD timeoutMs,
                                         DWORD& error) {
    DWORD result = WaitForSingleObject(process, timeoutMs);
    if (result == WAIT_FAILED) error = LastErrorOr(ERROR_GEN_FAILURE);
    return result;
}

bool NativeResponseActionPlatform::EnumerateChildren(uint32_t parentPid,
        std::vector<uint32_t>& children, DWORD& error) {
    children.clear();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_GEN_FAILURE);
        return false;
    }
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok;
         ok = Process32NextW(snapshot, &entry)) {
        if (entry.th32ParentProcessID == parentPid)
            children.push_back(entry.th32ProcessID);
    }
    CloseHandle(snapshot);
    return true;
}

bool NativeResponseActionPlatform::EnumerateChildren(
        const ResponseProcessIdentity& parent,
        std::vector<ResponseProcessIdentity>& children, DWORD& error) {
    children.clear();
    if (!parent.pid || !parent.createTime100ns) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }

    HANDLE parentHandle = nullptr;
    if (!Open(parent.pid, parentHandle, error)) return false;
    struct ParentGuard {
        IResponseActionPlatform& platform;
        HANDLE handle;
        ~ParentGuard() { platform.Close(handle); }
    } parentGuard{*this, parentHandle};

    uint64_t currentParentCreateTime = 0;
    if (!CreateTime(parentHandle, currentParentCreateTime, error) ||
        currentParentCreateTime != parent.createTime100ns) {
        if (currentParentCreateTime != parent.createTime100ns)
            error = ERROR_INVALID_PARAMETER;
        return false;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_GEN_FAILURE);
        return false;
    }
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok;
         ok = Process32NextW(snapshot, &entry)) {
        if (entry.th32ParentProcessID != parent.pid ||
            entry.th32ProcessID == 0 || entry.th32ProcessID == parent.pid)
            continue;

        HANDLE childHandle = nullptr;
        DWORD childError = ERROR_SUCCESS;
        if (!Open(entry.th32ProcessID, childHandle, childError)) {
            ResponseProcessIdentity child;
            child.pid = entry.th32ProcessID;
            child.parentPid = parent.pid;
            child.parentCreateTime100ns = parent.createTime100ns;
            children.push_back(child); /* executor records an identity skip */
            continue;
        }
        uint64_t childCreateTime = 0;
        const bool haveIdentity = CreateTime(childHandle, childCreateTime,
                                             childError);
        Close(childHandle);

        ResponseProcessIdentity child;
        child.pid = entry.th32ProcessID;
        child.createTime100ns = haveIdentity &&
            childCreateTime >= parent.createTime100ns ? childCreateTime : 0;
        child.parentPid = parent.pid;
        child.parentCreateTime100ns = parent.createTime100ns;
        children.push_back(child);
    }
    CloseHandle(snapshot);

    currentParentCreateTime = 0;
    if (!CreateTime(parentHandle, currentParentCreateTime, error) ||
        currentParentCreateTime != parent.createTime100ns) {
        children.clear();
        if (currentParentCreateTime != parent.createTime100ns)
            error = ERROR_INVALID_PARAMETER;
        return false;
    }
    return true;
}

namespace {

bool ProcessHandleMatches(HANDLE process, uint64_t expectedCreateTime,
                          DWORD& error) {
    if (!process || process == INVALID_HANDLE_VALUE ||
        GetProcessId(process) == 0) {
        error = ERROR_INVALID_HANDLE;
        return false;
    }
    FILETIME create = {}, exit = {}, kernel = {}, user = {};
    if (!GetProcessTimes(process, &create, &exit, &kernel, &user)) {
        error = LastErrorOr(ERROR_ACCESS_DENIED);
        return false;
    }
    const uint64_t actualCreateTime =
        (static_cast<uint64_t>(create.dwHighDateTime) << 32) |
        create.dwLowDateTime;
    if (actualCreateTime != expectedCreateTime) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    const DWORD wait = WaitForSingleObject(process, 0);
    if (wait != WAIT_TIMEOUT) {
        error = wait == WAIT_OBJECT_0 ? ERROR_INVALID_PARAMETER
                                      : LastErrorOr(ERROR_GEN_FAILURE);
        return false;
    }
    return true;
}

} // namespace

bool NativeResponseActionPlatform::Suspend(
        HANDLE process, uint64_t expectedCreateTime100ns, DWORD& error) {
    error = ERROR_SUCCESS;
    if (!ProcessHandleMatches(process, expectedCreateTime100ns, error))
        return false;
    const DWORD pid = GetProcessId(process);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_GEN_FAILURE);
        return false;
    }
    DWORD suspended = 0;
    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Thread32First(snapshot, &entry); ok;
         ok = Thread32Next(snapshot, &entry)) {
        if (entry.th32OwnerProcessID != pid) continue;
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME |
                                   THREAD_QUERY_LIMITED_INFORMATION,
                                   FALSE, entry.th32ThreadID);
        if (thread != nullptr) {
            if (GetProcessIdOfThread(thread) == pid &&
                ProcessHandleMatches(process, expectedCreateTime100ns, error)) {
                if (SuspendThread(thread) != static_cast<DWORD>(-1)) {
                    if (ProcessHandleMatches(process,
                            expectedCreateTime100ns, error)) {
                        ++suspended;
                    } else {
                        (void)ResumeThread(thread);
                    }
                }
            }
            CloseHandle(thread);
            if (error == ERROR_INVALID_PARAMETER) break;
        }
    }
    CloseHandle(snapshot);
    if (suspended == 0) { error = ERROR_ACCESS_DENIED; return false; }
    return true;
}

bool NativeResponseActionPlatform::Resume(
        HANDLE process, uint64_t expectedCreateTime100ns, DWORD& error) {
    error = ERROR_SUCCESS;
    if (!ProcessHandleMatches(process, expectedCreateTime100ns, error))
        return false;
    const DWORD pid = GetProcessId(process);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_GEN_FAILURE);
        return false;
    }
    DWORD resumed = 0;
    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Thread32First(snapshot, &entry); ok;
         ok = Thread32Next(snapshot, &entry)) {
        if (entry.th32OwnerProcessID != pid) continue;
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME |
                                   THREAD_QUERY_LIMITED_INFORMATION,
                                   FALSE, entry.th32ThreadID);
        if (thread != nullptr) {
            if (GetProcessIdOfThread(thread) == pid &&
                ProcessHandleMatches(process, expectedCreateTime100ns, error) &&
                ResumeThread(thread) != static_cast<DWORD>(-1)) ++resumed;
            CloseHandle(thread);
            if (error == ERROR_INVALID_PARAMETER) break;
        }
    }
    CloseHandle(snapshot);
    if (resumed == 0) { error = ERROR_ACCESS_DENIED; return false; }
    return true;
}

bool NativeResponseActionPlatform::IsAlive(uint32_t pid, DWORD& error) {
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!process) {
        error = LastErrorOr(ERROR_ACCESS_DENIED);
        return false;
    }
    DWORD wait = WaitForSingleObject(process, 0);
    CloseHandle(process);
    if (wait == WAIT_TIMEOUT) return true;
    if (wait == WAIT_OBJECT_0) return false;
    error = LastErrorOr(ERROR_GEN_FAILURE);
    return false;
}

void EventLogResponseEmergencySink::AuditFailure(
        const ResponseActionResult& result, const std::string& detail) {
    HANDLE source = RegisterEventSourceW(nullptr, L"EDR-Agent-Service");
    if (!source) return;
    std::wstring message = L"Response outcome audit failed for request " +
        std::wstring(result.requestId.begin(), result.requestId.end()) + L": " +
        std::wstring(detail.begin(), detail.end());
    LPCWSTR strings[] = {message.c_str()};
    ReportEventW(source, EVENTLOG_ERROR_TYPE, 0, 1101, nullptr, 1, 0,
                 strings, nullptr);
    DeregisterEventSource(source);
}

ResponseActionExecutor::ResponseActionExecutor(IResponseActionPlatform& platform,
        IResponseActionAudit& audit, IResponseEmergencySink& emergency,
        DWORD waitMs, const ResponseFileIdentity* selfIdentity,
        const std::wstring& selfBase, uint32_t maxTreeSize)
    : platform_(platform), audit_(audit), emergency_(emergency), waitMs_(waitMs),
      maxTreeSize_(maxTreeSize == 0 ? 1 : maxTreeSize),
      hasSelfIdentity_(selfIdentity != nullptr), selfBase_(Lower(selfBase)) {
    if (selfIdentity) selfIdentity_ = *selfIdentity;
}

ResponseActionResult ResponseActionExecutor::Execute(
        const ResponseActionRequest& request) {
    if (request.maxTreeSize > 0) return ExecuteTree(request);
    if (request.requestId.empty() || request.reason.empty() ||
        request.createTime100ns == 0 || request.pid == 0 || request.pid == 4 ||
        request.pid == GetCurrentProcessId())
        return Reject(request, "policy_rejected", ERROR_INVALID_PARAMETER);

    HANDLE raw = nullptr;
    DWORD error = ERROR_SUCCESS;
    if (!platform_.Open(request.pid, raw, error))
        return Reject(request, "open_failed", error);
    struct Guard { IResponseActionPlatform& p; HANDLE h; ~Guard() { p.Close(h); } } guard{platform_, raw};

    std::wstring path, base, selfPath, selfBase;
    ResponseFileIdentity targetIdentity, selfIdentity;
    bool critical = false, protectedProcess = false;
    DWORD session = 0;
    std::wstring sid;
    if (!platform_.Image(raw, path, base, error) ||
        !platform_.FileIdentity(path, targetIdentity, error))
        return Reject(request, "identity_check_failed", error);
    if (hasSelfIdentity_) {
        selfIdentity = selfIdentity_;
        selfBase = selfBase_;
    } else if (!platform_.Image(GetCurrentProcess(), selfPath, selfBase, error) ||
               !platform_.FileIdentity(selfPath, selfIdentity, error)) {
        return Reject(request, "identity_check_failed", error);
    }
    if (DeniedImage(base) || targetIdentity == selfIdentity ||
        (!selfBase.empty() && Lower(base) == Lower(selfBase)))
        return Reject(request, "policy_rejected");
    if (!platform_.Critical(raw, critical, error) || critical)
        return Reject(request, critical ? "policy_rejected" : "critical_check_failed", error);
    if (!platform_.Protected(raw, protectedProcess, error) || protectedProcess)
        return Reject(request, protectedProcess ? "policy_rejected" : "protection_check_failed", error);
    if (!platform_.Session(request.pid, session, error) || session == 0)
        return Reject(request, session == 0 ? "policy_rejected" : "session_check_failed", error);
    if (!platform_.UserSid(raw, sid, error) || ServiceSid(sid))
        return Reject(request, ServiceSid(sid) ? "policy_rejected" : "token_check_failed", error);

    uint64_t createTime = 0;
    if (!platform_.CreateTime(raw, createTime, error) ||
        createTime != request.createTime100ns)
        return Reject(request, "identity_mismatch",
                      createTime == request.createTime100ns ? error : ERROR_INVALID_PARAMETER);

    std::string auditError;
    if (!audit_.Attempt(request, auditError))
        return Reject(request, auditError == "requestId replay" ? "replay" : "audit_failed",
                      ERROR_WRITE_FAULT);

    ResponseActionResult result;
    result.requestId = request.requestId;
    if (!platform_.CreateTime(raw, createTime, error) ||
        createTime != request.createTime100ns) {
        result.status = "identity_changed";
        result.win32Error = createTime == request.createTime100ns ? error : ERROR_INVALID_PARAMETER;
    } else {
        bool snapshotOk = true;
        if (request.captureSnapshot) {
            result.snapshotAttempted = true;
            try {
                snapshotOk = request.captureSnapshot(result.evidencePath) &&
                    !result.evidencePath.empty();
            } catch (...) { snapshotOk = false; }
            result.snapshotCaptured = snapshotOk;
        }
        if (!snapshotOk) {
            result.status = "snapshot_failed";
            result.evidencePath.clear();
            result.win32Error = ERROR_SERVICE_SPECIFIC_ERROR;
        } else if (request.captureSnapshot &&
                   (!platform_.CreateTime(raw, createTime, error) ||
                    createTime != request.createTime100ns)) {
            result.status = "identity_changed";
            result.win32Error = createTime == request.createTime100ns
                ? error : ERROR_INVALID_PARAMETER;
        } else if (!platform_.Terminate(raw, error)) {
            result.status = "terminate_failed";
            result.win32Error = error;
        } else {
            result.terminationRequested = true;
            DWORD wait = platform_.Wait(raw, waitMs_, error);
            if (wait == WAIT_OBJECT_0) {
                result.exitObserved = true;
                result.status = "terminated";
            } else if (wait == WAIT_TIMEOUT) {
                result.status = "termination_pending";
                result.win32Error = WAIT_TIMEOUT;
            } else {
                result.status = "wait_failed";
                result.win32Error = error;
            }
        }
    }
    if (!audit_.Outcome(result, auditError)) {
        result.auditWritten = false;
        emergency_.AuditFailure(result, auditError);
    }
    return result;
}

ResponseActionResult ResponseActionExecutor::ExecuteTree(
        const ResponseActionRequest& request) {
    if (request.requestId.empty() || request.reason.empty() ||
        request.createTime100ns == 0 || request.pid == 0 || request.pid == 4 ||
        request.pid == GetCurrentProcessId())
        return Reject(request, "policy_rejected", ERROR_INVALID_PARAMETER);

    uint32_t cap = request.maxTreeSize;
    if (cap > maxTreeSize_) cap = maxTreeSize_;
    uint32_t depthCap = request.maxTreeDepth;

    HANDLE raw = nullptr;
    DWORD error = ERROR_SUCCESS;
    if (!platform_.Open(request.pid, raw, error))
        return Reject(request, "open_failed", error);
    struct Guard { IResponseActionPlatform& p; HANDLE h; ~Guard() { p.Close(h); } } guard{platform_, raw};

    std::wstring path, base, selfPath, selfBase;
    ResponseFileIdentity targetIdentity, selfIdentity;
    bool critical = false, protectedProcess = false;
    DWORD session = 0;
    std::wstring sid;
    if (!platform_.Image(raw, path, base, error) ||
        !platform_.FileIdentity(path, targetIdentity, error))
        return Reject(request, "identity_check_failed", error);
    if (hasSelfIdentity_) {
        selfIdentity = selfIdentity_;
        selfBase = selfBase_;
    } else if (!platform_.Image(GetCurrentProcess(), selfPath, selfBase, error) ||
               !platform_.FileIdentity(selfPath, selfIdentity, error)) {
        return Reject(request, "identity_check_failed", error);
    }
    if (DeniedImage(base) || targetIdentity == selfIdentity ||
        (!selfBase.empty() && Lower(base) == Lower(selfBase)))
        return Reject(request, "policy_rejected");
    if (!platform_.Critical(raw, critical, error) || critical)
        return Reject(request, critical ? "policy_rejected" : "critical_check_failed", error);
    if (!platform_.Protected(raw, protectedProcess, error) || protectedProcess)
        return Reject(request, protectedProcess ? "policy_rejected" : "protection_check_failed", error);
    if (!platform_.Session(request.pid, session, error) || session == 0)
        return Reject(request, session == 0 ? "policy_rejected" : "session_check_failed", error);
    if (!platform_.UserSid(raw, sid, error) || ServiceSid(sid))
        return Reject(request, ServiceSid(sid) ? "policy_rejected" : "token_check_failed", error);
    uint64_t rootCreate = 0;
    if (!platform_.CreateTime(raw, rootCreate, error) ||
        rootCreate != request.createTime100ns)
        return Reject(request, "identity_mismatch",
                      rootCreate == request.createTime100ns ? error : ERROR_INVALID_PARAMETER);

    std::string auditError;
    if (!audit_.Attempt(request, auditError))
        return Reject(request, auditError == "requestId replay" ? "replay" : "audit_failed",
                      ERROR_WRITE_FAULT);

    struct TreeNode {
        ResponseProcessIdentity identity;
        uint32_t depth = 0;
        bool root = false;
        std::wstring parentImage; /* parent process image path for whitelist */
    };

    std::vector<TreeNode> plan;
    plan.reserve(cap);
    size_t descendantCount = 0;
    uint32_t maxDepth = 0;
    bool truncated = false;
    bool depthTruncated = false;
    size_t enumSkips = 0;
    std::deque<TreeNode> frontier;
    std::unordered_set<uint32_t> queued;
    ResponseProcessIdentity rootIdentity;
    rootIdentity.pid = request.pid;
    rootIdentity.createTime100ns = request.createTime100ns;
    frontier.push_back(TreeNode{rootIdentity, 0, true, L""});
    queued.insert(request.pid);

    while (!frontier.empty()) {
        TreeNode current = frontier.front();
        frontier.pop_front();

        if (plan.size() >= cap) {
            truncated = true;
            break;
        }
        plan.push_back(current);
        if (current.depth > 0) {
            ++descendantCount;
            if (current.depth > maxDepth) maxDepth = current.depth;
        }

        if (depthCap > 0 && current.depth >= depthCap) {
            depthTruncated = true;
            continue;
        }

        std::vector<ResponseProcessIdentity> children;
        DWORD enumError = ERROR_SUCCESS;
        if (!platform_.EnumerateChildren(current.identity, children, enumError)) {
            enumSkips++;
            continue;
        }
        for (const ResponseProcessIdentity& child : children) {
            if (!child.pid || !child.createTime100ns ||
                child.createTime100ns < current.identity.createTime100ns ||
                child.parentPid != current.identity.pid ||
                child.parentCreateTime100ns != current.identity.createTime100ns) {
                ++enumSkips;
                continue;
            }
            if (queued.find(child.pid) != queued.end()) continue;
            queued.insert(child.pid);
            if (plan.size() + frontier.size() >= cap) {
                truncated = true;
                break;
            }
            std::wstring parentImage;
            if (current.identity.pid != request.pid) {
                HANDLE parentHandle = nullptr;
                DWORD parentError = ERROR_SUCCESS;
                if (platform_.Open(current.identity.pid, parentHandle, parentError)) {
                    std::wstring parentPath, parentBase;
                    uint64_t openedParentCreateTime = 0;
                    if (platform_.CreateTime(parentHandle,
                            openedParentCreateTime, parentError) &&
                        openedParentCreateTime == current.identity.createTime100ns &&
                        platform_.Image(parentHandle, parentPath, parentBase,
                                        parentError)) {
                        parentImage = parentPath;
                    }
                    platform_.Close(parentHandle);
                }
            }
            frontier.push_back(TreeNode{child, current.depth + 1, false,
                                        parentImage});
        }
    }

    if (!frontier.empty()) truncated = true;

    ResponseActionResult result;
    result.requestId = request.requestId;
    result.treeRequested = true;
    result.treePlanned = static_cast<uint32_t>(plan.size());
    result.treeDescendants = static_cast<uint32_t>(descendantCount);
    result.treeDepth = maxDepth;
    result.treeDepthLimit = depthCap;
    result.treeTruncated = truncated || depthTruncated;
    result.childrenSkipped = static_cast<uint32_t>(enumSkips);
    result.isolationRequested = request.isolateBeforeTerminate;
    result.snapshotCaptured = request.snapshotRequested && !request.evidencePath.empty();
    result.snapshotAttempted = request.snapshotRequested;
    result.evidencePath = request.evidencePath;

    auto auditEarlyOutcome = [&] {
        if (!audit_.Outcome(result, auditError)) {
            result.auditWritten = false;
            emergency_.AuditFailure(result, auditError);
        }
    };
    auto rootIdentityCurrent = [&] {
        uint64_t current = 0;
        if (platform_.CreateTime(raw, current, error) &&
            current == request.createTime100ns) return true;
        result.status = "identity_changed";
        result.win32Error = current == request.createTime100ns
            ? error : ERROR_INVALID_PARAMETER;
        auditEarlyOutcome();
        return false;
    };
    if (!rootIdentityCurrent()) return result;

    /* External response hooks may alter the host or write evidence. Run them
     * only after root policy/identity checks and the durable attempt record. */
    if (request.isolateBeforeTerminate) {
        std::string isoError;
        bool isolated = false;
        try {
            isolated = request.preIsolationCallback &&
                request.preIsolationCallback(isoError);
        } catch (...) {
            isolated = false;
        }
        if (!isolated) {
            result.status = "isolation_failed";
            result.win32Error = ERROR_SERVICE_SPECIFIC_ERROR;
            auditEarlyOutcome();
            return result;
        }
        result.isolationSucceeded = true;
    }
    if (request.preSnapshotCallback) {
        try {
            request.preSnapshotCallback(request.requestId, request.pid);
        } catch (...) {
            result.status = "snapshot_failed";
            result.snapshotCaptured = false;
            result.win32Error = ERROR_SERVICE_SPECIFIC_ERROR;
            auditEarlyOutcome();
            return result;
        }
    }
    if (request.captureSnapshot) {
        result.snapshotAttempted = true;
        bool captured = false;
        try {
            captured = request.captureSnapshot(result.evidencePath) &&
                !result.evidencePath.empty();
        } catch (...) { captured = false; }
        result.snapshotCaptured = captured;
        if (!captured) {
            result.status = "snapshot_failed";
            result.evidencePath.clear();
            result.win32Error = ERROR_SERVICE_SPECIFIC_ERROR;
            auditEarlyOutcome();
            return result;
        }
    }
    if (!rootIdentityCurrent()) return result;

    auto settle = [&](HANDLE handle) -> DWORD {
        DWORD localError = ERROR_SUCCESS;
        DWORD outcome = platform_.Wait(handle, waitMs_, localError);
        if (outcome == WAIT_TIMEOUT) {
            DWORD retryMs = waitMs_ / 2;
            if (retryMs < 100) retryMs = 100;
            outcome = platform_.Wait(handle, retryMs, localError);
        }
        if (localError != ERROR_SUCCESS) error = localError;
        return outcome;
    };

    auto suspendIfRequested = [&](HANDLE process, uint64_t createTime,
                                 std::string& status, bool& suspended) -> bool {
        suspended = false;
        if (!request.suspendBeforeTerminate) return true;
        if (platform_.Suspend(process, createTime, error)) {
            suspended = true;
            ++result.treeSuspended;
            return true;
        }
        status = "suspend_failed";
        return false;
    };

    auto resumeIfNeeded = [&](HANDLE process, uint64_t createTime,
                              bool suspended) {
        if (!suspended) return;
        DWORD resumeError = ERROR_SUCCESS;
        platform_.Resume(process, createTime, resumeError);
    };

    std::vector<TreeNode> reversePlan(plan.rbegin(), plan.rend());
    for (const TreeNode& node : reversePlan) {
        if (node.root) {
            uint64_t before = 0;
            if (!platform_.CreateTime(raw, before, error) ||
                before != node.identity.createTime100ns) {
                result.status = "identity_changed";
                result.win32Error = before == node.identity.createTime100ns
                    ? error : ERROR_INVALID_PARAMETER;
                break;
            }
            bool suspended = false;
            if (!suspendIfRequested(raw, node.identity.createTime100ns,
                                   result.status, suspended)) {
                result.win32Error = error;
                break;
            }
            uint64_t beforeTerminate = 0;
            if (!platform_.CreateTime(raw, beforeTerminate, error) ||
                beforeTerminate != node.identity.createTime100ns) {
                resumeIfNeeded(raw, node.identity.createTime100ns, suspended);
                result.status = "identity_changed";
                result.win32Error = beforeTerminate == node.identity.createTime100ns
                    ? error : ERROR_INVALID_PARAMETER;
                break;
            }
            if (!platform_.Terminate(raw, error)) {
                resumeIfNeeded(raw, node.identity.createTime100ns, suspended);
                result.status = "terminate_failed";
                result.win32Error = error;
                break;
            }
            result.terminationRequested = true;
            DWORD wait = settle(raw);
            if (wait == WAIT_OBJECT_0) {
                result.exitObserved = true;
                result.status = "terminated";
            } else if (wait == WAIT_TIMEOUT) {
                result.status = "termination_pending";
                result.win32Error = WAIT_TIMEOUT;
            } else {
                result.status = "wait_failed";
                result.win32Error = error;
            }
            break;
        }
        if (node.depth > 0 && depthCap > 0 && node.depth > depthCap) {
            result.childrenSkipped++;
            continue;
        }
        if (!request.parentImageWhitelist.empty() &&
            ContainsWhitelistToken(node.parentImage, request.parentImageWhitelist)) {
            result.childrenSkipped++;
            continue;
        }

        HANDLE process = nullptr;
        if (!platform_.Open(node.identity.pid, process, error)) {
            result.childrenSkipped++;
            continue;
        }
        struct ChildGuard {
            IResponseActionPlatform& p;
            HANDLE h;
            ~ChildGuard() { p.Close(h); }
        } childGuard{platform_, process};

        uint64_t openedCreateTime = 0;
        if (!platform_.CreateTime(process, openedCreateTime, error) ||
            openedCreateTime != node.identity.createTime100ns) {
            ++result.childrenSkipped;
            continue;
        }

        std::wstring childPath, childBase;
        if (!platform_.Image(process, childPath, childBase, error) ||
            DeniedTreeChild(childBase)) {
            result.childrenSkipped++;
            continue;
        }
        ResponseFileIdentity childIdentity;
        if (!platform_.FileIdentity(childPath, childIdentity, error) ||
            childIdentity == selfIdentity) {
            result.childrenSkipped++;
            continue;
        }
        bool childCritical = false, childProtected = false;
        DWORD childSession = 0;
        std::wstring childSid;
        if (!platform_.Critical(process, childCritical, error) || childCritical ||
            !platform_.Protected(process, childProtected, error) ||
            childProtected || !platform_.Session(node.identity.pid, childSession, error) ||
            childSession == 0 || !platform_.UserSid(process, childSid, error) ||
            ServiceSid(childSid)) {
            result.childrenSkipped++;
            continue;
        }
        uint64_t beforeSuspend = 0;
        if (!platform_.CreateTime(process, beforeSuspend, error) ||
            beforeSuspend != node.identity.createTime100ns) {
            result.childrenSkipped++;
            continue;
        }
        bool suspended = false;
        if (!suspendIfRequested(process, node.identity.createTime100ns,
                                result.status, suspended)) {
            result.childrenSkipped++;
            continue;
        }
        uint64_t childRecheck = 0;
        if (!platform_.CreateTime(process, childRecheck, error) ||
            childRecheck != node.identity.createTime100ns) {
            resumeIfNeeded(process, node.identity.createTime100ns, suspended);
            result.childrenSkipped++;
            continue;
        }
        if (!platform_.Terminate(process, error)) {
            resumeIfNeeded(process, node.identity.createTime100ns, suspended);
            result.childrenFailed++;
            continue;
        }
        DWORD wait = settle(process);
        if (wait == WAIT_OBJECT_0)
            result.childrenTerminated++;
        else
            result.childrenFailed++;
    }

    if (result.status == "terminated") {
        if (result.childrenFailed > 0) result.status = "child_terminate_failed";
        else if (result.childrenSkipped > 0) result.status = "partial_tree";
        else if (result.treeTruncated) result.status = "tree_truncated";
        else result.status = "tree_terminated";
    }
    if (result.status == "rejected") {
        result.status = result.treeTruncated ? "tree_truncated" : "tree_terminated";
    }
    if (!audit_.Outcome(result, auditError)) {
        result.auditWritten = false;
        emergency_.AuditFailure(result, auditError);
    }
    return result;
}

ResponseActionResult ResponseActionExecutor::ExecuteSuspend(
        const ResponseActionRequest& request) {
    return ExecuteSimple(request, SimpleAction::Suspend);
}

ResponseActionResult ResponseActionExecutor::ExecuteResume(
        const ResponseActionRequest& request) {
    return ExecuteSimple(request, SimpleAction::Resume);
}

ResponseActionResult ResponseActionExecutor::ExecuteSimple(
        const ResponseActionRequest& request, SimpleAction action) {
    const char* actionName = action == SimpleAction::Suspend ? "suspend"
        : action == SimpleAction::Resume ? "resume" : "terminate";
    const char* failStatus = action == SimpleAction::Suspend ? "suspend_failed"
        : action == SimpleAction::Resume ? "resume_failed" : "terminate_failed";
    const char* okStatus = action == SimpleAction::Suspend ? "suspended"
        : action == SimpleAction::Resume ? "resumed" : "terminated";
    if (request.requestId.empty() || request.reason.empty() ||
        request.createTime100ns == 0 || request.pid == 0 || request.pid == 4 ||
        request.pid == GetCurrentProcessId())
        return Reject(request, "policy_rejected", ERROR_INVALID_PARAMETER);

    HANDLE raw = nullptr;
    DWORD error = ERROR_SUCCESS;
    if (!platform_.Open(request.pid, raw, error))
        return Reject(request, "open_failed", error);
    struct Guard { IResponseActionPlatform& p; HANDLE h; ~Guard() { p.Close(h); } } guard{platform_, raw};

    std::wstring path, base, selfPath, selfBase;
    ResponseFileIdentity targetIdentity, selfIdentity;
    bool critical = false, protectedProcess = false;
    DWORD session = 0;
    std::wstring sid;
    if (!platform_.Image(raw, path, base, error) ||
        !platform_.FileIdentity(path, targetIdentity, error))
        return Reject(request, "identity_check_failed", error);
    if (hasSelfIdentity_) {
        selfIdentity = selfIdentity_;
        selfBase = selfBase_;
    } else if (!platform_.Image(GetCurrentProcess(), selfPath, selfBase, error) ||
               !platform_.FileIdentity(selfPath, selfIdentity, error)) {
        return Reject(request, "identity_check_failed", error);
    }
    // suspend/resume must respect same blacklist as terminate including svchost
    bool denied = DeniedImage(base);
    if (action != SimpleAction::Terminate) {
        std::wstring lower = Lower(base);
        if (lower == L"svchost.exe") denied = true;
    }
    if (denied || targetIdentity == selfIdentity ||
        (!selfBase.empty() && Lower(base) == Lower(selfBase)))
        return Reject(request, "policy_rejected");
    if (!platform_.Critical(raw, critical, error) || critical)
        return Reject(request, critical ? "policy_rejected" : "critical_check_failed", error);
    if (!platform_.Protected(raw, protectedProcess, error) || protectedProcess)
        return Reject(request, protectedProcess ? "policy_rejected" : "protection_check_failed", error);
    if (!platform_.Session(request.pid, session, error) || session == 0)
        return Reject(request, session == 0 ? "policy_rejected" : "session_check_failed", error);
    if (!platform_.UserSid(raw, sid, error) || ServiceSid(sid))
        return Reject(request, ServiceSid(sid) ? "policy_rejected" : "token_check_failed", error);

    uint64_t createTime = 0;
    if (!platform_.CreateTime(raw, createTime, error) ||
        createTime != request.createTime100ns)
        return Reject(request, "identity_mismatch",
                      createTime == request.createTime100ns ? error : ERROR_INVALID_PARAMETER);

    std::string auditError;
    if (!audit_.AttemptAction(request, actionName, auditError))
        return Reject(request, auditError == "requestId replay" ? "replay" : "audit_failed",
                      ERROR_WRITE_FAULT);

    ResponseActionResult result;
    result.requestId = request.requestId;
    if (action == SimpleAction::Suspend) result.suspendRequested = true;
    else if (action == SimpleAction::Resume) result.resumeRequested = true;
    else result.terminationRequested = true;

    uint64_t recheck = 0;
    if (!platform_.CreateTime(raw, recheck, error) ||
        recheck != request.createTime100ns) {
        result.status = "identity_changed";
        result.win32Error = recheck == request.createTime100ns ? error : ERROR_INVALID_PARAMETER;
    } else {
        bool ok = false;
        if (action == SimpleAction::Suspend)
            ok = platform_.Suspend(raw, request.createTime100ns, error);
        else if (action == SimpleAction::Resume)
            ok = platform_.Resume(raw, request.createTime100ns, error);
        else ok = platform_.Terminate(raw, error);
        if (!ok) {
            result.status = failStatus;
            result.win32Error = error;
        } else {
            result.status = okStatus;
            result.win32Error = ERROR_SUCCESS;
            if (action == SimpleAction::Terminate) {
                result.terminationRequested = true;
                DWORD wait = platform_.Wait(raw, waitMs_, error);
                if (wait == WAIT_OBJECT_0) result.exitObserved = true;
                else if (wait == WAIT_TIMEOUT) {
                    result.status = "termination_pending";
                    result.win32Error = WAIT_TIMEOUT;
                } else {
                    result.status = "wait_failed";
                    result.win32Error = error;
                }
            }
        }
    }
    if (!audit_.OutcomeAction(result, actionName, auditError)) {
        result.auditWritten = false;
        emergency_.AuditFailure(result, auditError);
    }
    return result;
}

bool ResponseActionExecutor::VerifyNotSelf(const std::wstring& path,
                                           DWORD& error) const {
    ResponseFileIdentity identity;
    if (!platform_.FileIdentity(path, identity, error)) {
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            error = ERROR_SUCCESS;
            return true;
        }
        return false;
    }

    /* The server normally supplies the agent identity at startup. Keep the
     * executor safe when embedded callers omit it: resolve the current image
     * through the platform seam before allowing a file delete. */
    ResponseFileIdentity selfIdentity;
    if (hasSelfIdentity_) {
        selfIdentity = selfIdentity_;
    } else {
        std::wstring selfPath, selfBase;
        if (!platform_.Image(GetCurrentProcess(), selfPath, selfBase, error) ||
            !platform_.FileIdentity(selfPath, selfIdentity, error)) {
            return false;
        }
    }
    if (identity == selfIdentity) {
        error = ERROR_ACCESS_DENIED;
        return false;
    }
    return true;
}

DeleteFileResult ResponseActionExecutor::ExecuteDeleteFile(
        const DeleteFileRequest& request) {
    if (request.requestId.empty() || request.reason.empty() ||
        request.path.empty()) {
        return RejectDeleteFile(request, "policy_rejected",
                                ERROR_INVALID_PARAMETER);
    }
    std::wstring path = Utf8ToWide(request.path);
    if (path.empty() || !ValidDeletePath(path)) {
        return RejectDeleteFile(request, "policy_rejected",
                                ERROR_INVALID_PARAMETER);
    }

    DWORD error = ERROR_SUCCESS;
    if (!VerifyNotSelf(path, error)) {
        return RejectDeleteFile(request, "policy_rejected", error);
    }

    if (!request.sha256Hex.empty()) {
        std::string actual = Sha256HexFile(path);
        std::string expected = request.sha256Hex;
        std::transform(expected.begin(), expected.end(), expected.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (actual.empty() || actual != expected) {
            return RejectDeleteFile(request, "hash_mismatch",
                                    actual.empty() ? ERROR_FILE_NOT_FOUND
                                   : ERROR_INVALID_DATA);
        }
    }

    /* Bind the audited request to the file object observed during policy
     * validation. The eventual delete uses a retained handle whose identity
     * is read from the handle itself; no path operation follows the check. */
    ResponseFileIdentity expectedIdentity;
    DWORD identityError = ERROR_SUCCESS;
    bool expectedExists = platform_.FileIdentity(path, expectedIdentity,
                                                 identityError);
    if (!expectedExists && identityError != ERROR_FILE_NOT_FOUND &&
        identityError != ERROR_PATH_NOT_FOUND) {
        return RejectDeleteFile(request, "identity_check_failed", identityError);
    }

    std::string auditError;
    if (!audit_.AttemptDeleteFile(request, auditError)) {
        return RejectDeleteFile(request,
                                auditError == "requestId replay" ? "replay"
                                                                 : "audit_failed",
                                ERROR_WRITE_FAULT);
    }

    DeleteFileResult result;
    result.requestId = request.requestId;
    result.path = request.path;

    HANDLE deleteHandle = nullptr;
    ResponseFileIdentity handleIdentity;
    error = ERROR_SUCCESS;
    if (!platform_.OpenFileForDelete(path, deleteHandle, handleIdentity, error)) {
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            result.deleted = true;
            result.status = "already_gone";
        } else {
            result.status = "identity_check_failed";
            result.win32Error = error;
        }
    } else {
        struct DeleteHandleGuard {
            IResponseActionPlatform& platform;
            HANDLE handle;
            ~DeleteHandleGuard() { platform.Close(handle); }
        } deleteGuard{platform_, deleteHandle};

        if (!expectedExists) {
            /* The request was audited while the path did not name a file.
             * A later-created object cannot inherit that authorization. */
            result.status = "identity_changed";
            result.win32Error = ERROR_INVALID_DATA;
        } else if (!(handleIdentity == expectedIdentity)) {
            result.status = "identity_changed";
            result.win32Error = ERROR_INVALID_DATA;
        } else if (!platform_.DeleteFileHandle(deleteHandle, error)) {
            /* No path-based or delayed reboot fallback: only the verified
             * object handle may be marked for deletion. */
            result.status = "delete_failed";
            result.win32Error = error;
        } else {
            result.deleted = true;
            result.status = "deleted";
        }
    }

    if (!audit_.OutcomeDeleteFile(result, auditError)) {
        result.auditWritten = false;
        emergency_.AuditFailure(result, auditError);
    }
    return result;
}

} // namespace edr
