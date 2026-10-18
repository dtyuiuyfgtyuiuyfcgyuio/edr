#include "response_server.h"

#include <bcrypt.h>
#include <aclapi.h>
#include <sddl.h>
#include <wincrypt.h>

#include <algorithm>
#include <cmath>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <thread>

#include "config.h"
#include "json_lite.h"

namespace edr {
namespace {

constexpr DWORD kIoTimeoutMs = 5000;
constexpr size_t kReplayLimit = 50000;
constexpr size_t kReplayRecordLimit = 8 * 1024 * 1024;
constexpr DWORD kReplayReadChunkSize = 64 * 1024;
constexpr double kMaxSafeChainSequence = 9007199254740991.0;

std::string WinError(const char* operation) {
    return std::string(operation) + " failed: " + std::to_string(GetLastError());
}

bool ProtectLocalFile(const std::wstring& path, bool mustExist,
                      std::string& error) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        if (mustExist) { error = WinError("inspect protected file"); return false; }
    } else if ((attributes & FILE_ATTRIBUTE_DIRECTORY) ||
               (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        error = "response file must be a regular non-reparse file";
        return false;
    }
    HANDLE token = nullptr;
    DWORD tokenSize = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error = WinError("open response service token"); return false;
    }
    GetTokenInformation(token, TokenUser, nullptr, 0, &tokenSize);
    std::vector<unsigned char> tokenBuffer(tokenSize);
    if (!tokenSize || !GetTokenInformation(token, TokenUser,
            tokenBuffer.data(), tokenSize, &tokenSize)) {
        CloseHandle(token); error = WinError("query response service identity");
        return false;
    }
    CloseHandle(token);
    LPWSTR identity = nullptr;
    auto* user = reinterpret_cast<TOKEN_USER*>(tokenBuffer.data());
    if (!ConvertSidToStringSidW(user->User.Sid, &identity)) {
        error = WinError("format response service identity"); return false;
    }
    std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;";
    sddl += identity;
    sddl += L")";
    LocalFree(identity);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1,
            &descriptor, nullptr)) {
        error = WinError("create response file DACL");
        return false;
    }
    BOOL secured = SetFileSecurityW(path.c_str(),
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        descriptor);
    LocalFree(descriptor);
    if (!secured) { error = WinError("protect response file"); return false; }
    return true;
}

bool HmacSha256(const std::vector<unsigned char>& key, const unsigned char* data,
                size_t size, std::array<unsigned char, 32>& digest,
                std::string& error) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0, resultSize = 0;
    std::vector<unsigned char> object;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status >= 0) status = BCryptGetProperty(
        algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
        sizeof(objectSize), &resultSize, 0);
    if (status >= 0) {
        object.resize(objectSize);
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectSize,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
    }
    if (status >= 0 && size > std::numeric_limits<ULONG>::max()) status = -1;
    if (status >= 0) status = BCryptHashData(
        hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0);
    if (status >= 0) status = BCryptFinishHash(
        hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        error = "BCrypt HMAC-SHA256 failed";
        return false;
    }
    return true;
}

bool ConstantTimeEqual(const unsigned char* a, const unsigned char* b,
                       size_t size) {
    unsigned char difference = 0;
    for (size_t i = 0; i < size; ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}

static std::string Sha256HexLedger(const std::string& text) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    DWORD objLen = 0, ret = 0;
    std::vector<unsigned char> obj;
    unsigned char digest[32] = {};
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st >= 0) st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &ret, 0);
    if (st >= 0) { obj.resize(objLen); st = BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0); }
    if (st >= 0) st = BCryptHashData(h, (PUCHAR)text.data(), (ULONG)text.size(), 0);
    if (st >= 0) st = BCryptFinishHash(h, digest, sizeof(digest), 0);
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (st < 0) return std::string(64, '0');
    static const char hex[] = "0123456789abcdef";
    std::string out; out.resize(64);
    for (size_t i = 0; i < 32; ++i) { out[i*2]=hex[digest[i]>>4]; out[i*2+1]=hex[digest[i]&15]; }
    return out;
}
static std::string ChainHashForLedger(uint64_t seq, const std::string& prev, const std::string& payloadHash) {
    return Sha256HexLedger(std::to_string(seq) + "|" + prev + "|" + payloadHash);
}
static std::string StableJsonLedger(const jsonlite::Value& v) {
    switch(v.type){
        case jsonlite::Type::Null: return "null";
        case jsonlite::Type::Bool: return v.boolean?"true":"false";
        case jsonlite::Type::Number: { double n=v.number; if(std::floor(n)==n) return std::to_string((long long)n); char buf[64]; std::snprintf(buf,sizeof(buf),"%.15g",n); return std::string(buf); }
        case jsonlite::Type::String: return "\""+jsonlite::escape(v.str)+"\"";
        case jsonlite::Type::Array: { std::string s="["; for(size_t i=0;i<v.array.size();++i){ if(i) s+=","; s+=StableJsonLedger(v.array[i]); } s+="]"; return s; }
        case jsonlite::Type::Object: { std::string s="{"; bool first=true; for(auto &kv: v.object){ if(!first) s+=","; first=false; s+="\""+jsonlite::escape(kv.first)+"\""+":"+StableJsonLedger(kv.second); } s+="}"; return s; }
    }
    return "null";
}
static bool IsHexDigestLedger(const std::string& value) {
    if (value.size() != 64) return false;
    for (unsigned char ch : value) {
        if (!((ch >= '0' && ch <= '9') ||
              (ch >= 'a' && ch <= 'f') ||
              (ch >= 'A' && ch <= 'F'))) return false;
    }
    return true;
}

bool Decimal(const std::string& value, uint64_t& result, bool nonzero) {
    if (value.empty() || value.size() > 20 ||
        (value.size() > 1 && value[0] == '0')) return false;
    uint64_t parsed = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        unsigned digit = static_cast<unsigned>(c - '0');
        if (parsed > (UINT64_MAX - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    if (nonzero && parsed == 0) return false;
    result = parsed;
    return true;
}

bool ExactKeys(const jsonlite::Value& value,
               std::initializer_list<const char*> allowed, std::string& error) {
    for (const auto& item : value.object) {
        bool found = false;
        for (const char* key : allowed) found |= item.first == key;
        if (!found) {
            error = "unknown field '" + item.first + "'";
            return false;
        }
    }
    return true;
}

const jsonlite::Value* Required(const jsonlite::Value& value, const char* key,
                                jsonlite::Type type, std::string& error) {
    const jsonlite::Value* result = value.find(key);
    if (!result || result->type != type) {
        error = std::string("field '") + key + "' is missing or has wrong type";
        return nullptr;
    }
    return result;
}

bool ValidRequestId(const std::string& value) {
    if (value.size() < 16 || value.size() > 64) return false;
    for (char c : value) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-')) return false;
    }
    return value.find('-') != std::string::npos;
}

bool ValidReason(const std::string& value) {
    if (value.empty() || value.size() > 1024) return false;
    for (unsigned char c : value) {
        if (c < 0x20 && c != '\t') return false;
        if (c == 0x7f) return false;
    }
    return true;
}

bool ValidQuarantinePath(const std::string& value) {
    if (value.size() < 3 || value.size() > 4096 ||
        !std::isalpha(static_cast<unsigned char>(value[0])) || value[1] != ':' ||
        value[2] != '\\') return false;
    for (size_t i = 0; i < value.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(value[i]);
        if (c < 0x20 || c == 0x7f || (i > 1 && c == ':')) return false;
    }
    return !Utf8ToWide(value).empty();
}

bool ValidSha256(const std::string& value) {
    return value.empty() || (value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        }));
}

bool OverlappedIo(HANDLE pipe, bool write, void* buffer, DWORD size,
                  std::atomic<bool>& stopping) {
    unsigned char* cursor = static_cast<unsigned char*>(buffer);
    DWORD done = 0;
    while (done < size && !stopping.load()) {
        HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!event) return false;
        OVERLAPPED ov = {};
        ov.hEvent = event;
        DWORD transferred = 0;
        BOOL started = write
            ? WriteFile(pipe, cursor + done, size - done, &transferred, &ov)
            : ReadFile(pipe, cursor + done, size - done, &transferred, &ov);
        if (!started && GetLastError() == ERROR_IO_PENDING) {
            DWORD wait = WaitForSingleObject(event, kIoTimeoutMs);
            if (wait == WAIT_OBJECT_0)
                started = GetOverlappedResult(pipe, &ov, &transferred, FALSE);
            else {
                CancelIoEx(pipe, &ov);
                WaitForSingleObject(event, INFINITE);
                started = FALSE;
            }
        }
        CloseHandle(event);
        if (!started || transferred == 0) return false;
        done += transferred;
    }
    return done == size;
}

bool AuthorizedPipeClient(HANDLE pipe) {
    if (!ImpersonateNamedPipeClient(pipe)) return false;
    HANDLE token = nullptr;
    bool authorized = false;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        BYTE systemBuffer[SECURITY_MAX_SID_SIZE];
        BYTE adminBuffer[SECURITY_MAX_SID_SIZE];
        DWORD systemSize = sizeof(systemBuffer), adminSize = sizeof(adminBuffer);
        BOOL member = FALSE;
        if (CreateWellKnownSid(WinLocalSystemSid, nullptr, systemBuffer,
                               &systemSize) &&
            CheckTokenMembership(token, systemBuffer, &member) && member) {
            authorized = true;
        } else if (CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
                                      adminBuffer, &adminSize) &&
                   CheckTokenMembership(token, adminBuffer, &member) && member) {
            authorized = true;
        }
        CloseHandle(token);
    }
    RevertToSelf();
    return authorized;
}

std::string JsonResponse(bool ok, const std::string& mode,
                         const std::string& status,
                         const std::string& requestId = {},
                         bool requested = false, bool exited = false,
                         DWORD win32Error = ERROR_SUCCESS,
                         uint32_t childrenTerminated = 0,
                         uint32_t childrenSkipped = 0,
                         uint32_t childrenFailed = 0,
                         bool treeRequested = false,
                         uint32_t treePlanned = 0,
                         uint32_t treeDescendants = 0,
                         uint32_t treeDepth = 0,
                         uint32_t treeSuspended = 0,
                         bool treeTruncated = false,
                         bool snapshotAttempted = false,
                         bool snapshotCaptured = false,
                         const std::string& evidencePath = {}) {
    std::string treeCounters;
    if (treeRequested) {
        treeCounters = ",\"children_terminated\":" +
            std::to_string(childrenTerminated) + ",\"children_skipped\":" +
            std::to_string(childrenSkipped) + ",\"children_failed\":" +
            std::to_string(childrenFailed) + ",\"tree_planned\":" +
            std::to_string(treePlanned) + ",\"tree_descendants\":" +
            std::to_string(treeDescendants) + ",\"tree_depth\":" +
            std::to_string(treeDepth) + ",\"tree_suspended\":" +
            std::to_string(treeSuspended) + ",\"tree_truncated\":" +
            (treeTruncated ? std::string("true") : std::string("false"));
    }
    std::string evidenceFields;
    if (snapshotAttempted || snapshotCaptured || !evidencePath.empty()) {
        evidenceFields = ",\"snapshot_attempted\":" +
            std::string(snapshotAttempted ? "true" : "false") +
            ",\"snapshot_captured\":" +
            std::string(snapshotCaptured ? "true" : "false");
        if (!evidencePath.empty()) {
            evidenceFields += ",\"evidence_path\":\"" +
                jsonlite::escape(evidencePath) + "\"";
        }
    }
    return std::string("{\"version\":1,\"ok\":") + (ok ? "true" : "false") +
        ",\"effective_mode\":\"" + jsonlite::escape(mode) +
        "\",\"status\":\"" +
        jsonlite::escape(status) + "\"" +
        ",\"termination_requested\":" + (requested ? "true" : "false") +
        ",\"exit_observed\":" + (exited ? "true" : "false") +
        ",\"win32_error\":" + std::to_string(win32Error) +
        (requestId.empty() ? "" : ",\"requestId\":\"" +
            jsonlite::escape(requestId) + "\"") + treeCounters + evidenceFields + "}";
}

std::string JsonQuarantineResponse(const QuarantineResult& result) {
    bool ok = result.auditWritten && (result.status == "quarantined" ||
        (result.effectiveMode == "dry_run" && result.status == "accepted"));
    return std::string("{\"version\":1,\"ok\":") + (ok ? "true" : "false") +
        ",\"effective_mode\":\"" + jsonlite::escape(result.effectiveMode) +
        "\",\"status\":\"" + jsonlite::escape(result.status) +
        "\",\"requestId\":\"" + jsonlite::escape(result.requestId) + "\"" +
        (result.quarantinePath.empty() ? "" : ",\"quarantine_path\":\"" +
            jsonlite::escape(result.quarantinePath) + "\"") +
        (result.sha256Hex.empty() ? "" : ",\"sha256\":\"" +
            jsonlite::escape(result.sha256Hex) + "\"") +
        (result.sidecarSha256Hex.empty() ? "" : ",\"sidecar_sha256\":\"" +
            jsonlite::escape(result.sidecarSha256Hex) + "\"") +
        ",\"rolled_back\":" + (result.rolledBack ? "true" : "false") +
        ",\"win32_error\":" + std::to_string(result.win32Error) + "}";
}

std::string JsonRestoreQuarantineResponse(
        const QuarantineRestoreResult& result) {
    const bool restored = result.status == "restored";
    const bool dryRunAccepted = result.effectiveMode == "dry_run" &&
        result.status == "accepted";
    const bool ok = result.auditWritten && (restored || dryRunAccepted);
    return std::string("{\"version\":1,\"ok\":") + (ok ? "true" : "false") +
        ",\"effective_mode\":\"" + jsonlite::escape(result.effectiveMode) +
        "\",\"status\":\"" + jsonlite::escape(result.status) +
        "\",\"requestId\":\"" + jsonlite::escape(result.requestId) +
        "\",\"source_request_id\":\"" +
        jsonlite::escape(result.sourceRequestId) + "\"" +
        (result.originalPath.empty() ? "" : ",\"original_path\":\"" +
            jsonlite::escape(result.originalPath) + "\"") +
        (result.quarantinePath.empty() ? "" : ",\"quarantine_path\":\"" +
            jsonlite::escape(result.quarantinePath) + "\"") +
        (result.sha256Hex.empty() ? "" : ",\"sha256\":\"" +
            jsonlite::escape(result.sha256Hex) + "\"") +
        (result.sidecarSha256Hex.empty() ? "" : ",\"sidecar_sha256\":\"" +
            jsonlite::escape(result.sidecarSha256Hex) + "\"") +
        ",\"restored\":" + (restored ? "true" : "false") +
        ",\"partial_restore\":" + (result.partialRestore ? "true" : "false") +
        ",\"audit_written\":" + (result.auditWritten ? "true" : "false") +
        ",\"win32_error\":" + std::to_string(result.win32Error) + "}";
}

std::string JsonDeleteFileResponse(const DeleteFileResult& result) {
    bool ok = result.auditWritten &&
        (result.deleted || (result.effectiveMode == "dry_run" &&
                            result.status == "accepted"));
    return std::string("{\"version\":1,\"ok\":") + (ok ? "true" : "false") +
        ",\"effective_mode\":\"" + jsonlite::escape(result.effectiveMode) +
        "\",\"status\":\"" + jsonlite::escape(result.status) +
        "\",\"requestId\":\"" + jsonlite::escape(result.requestId) + "\"" +
        ",\"path\":\"" + jsonlite::escape(result.path) + "\"" +
        ",\"deleted\":" + (result.deleted ? "true" : "false") +
        ",\"win32_error\":" + std::to_string(result.win32Error) + "}";
}

} // namespace

std::string JsonIsolationResponse(const ResponseIsolationResult& result) {
    return std::string("{\"version\":1,\"ok\":") + (result.success ? "true" : "false") +
        ",\"status\":\"" + jsonlite::escape(result.status) +
        "\",\"requestId\":\"" + jsonlite::escape(result.requestId) + "\"" +
        (result.error.empty() ? "" : ",\"error\":\"" + jsonlite::escape(result.error) + "\"") +
        "}";
}

std::string JsonIsolationStatusResponse(const HostIsolationStatus& status,
                                        const std::string& requestId) {
    std::string fields;
    if (status.isolated) {
        fields = ",\"managementIp\":\"" + jsonlite::escape(status.managementIp) +
            "\",\"allowedPorts\":\"" + jsonlite::escape(status.allowedPorts) +
            "\",\"isolatedSinceMs\":" + std::to_string(status.isolatedSinceMs) +
            ",\"elapsedMs\":" + std::to_string(status.elapsedMs);
    }
    return std::string("{\"version\":1,\"ok\":true,\"status\":\"ready\",") +
        "\"requestId\":\"" + jsonlite::escape(requestId) + "\"," +
        "\"isolated\":" + (status.isolated ? "true" : "false") + fields + "}";
}

std::string JsonSuspendResponse(const ResponseActionResult& result) {
    bool ok = result.auditWritten && (result.status == "suspended" ||
        result.status == "resumed" ||
        (result.effectiveMode == "dry_run" && result.status == "accepted"));
    return std::string("{\"version\":1,\"ok\":") + (ok ? "true" : "false") +
        ",\"effective_mode\":\"" + jsonlite::escape(result.effectiveMode) +
        "\",\"status\":\"" + jsonlite::escape(result.status) +
        "\",\"requestId\":\"" + jsonlite::escape(result.requestId) + "\"" +
        ",\"win32_error\":" + std::to_string(result.win32Error) + "}";
}

bool LoadResponseCommandKey(const std::string& path,
                            std::vector<unsigned char>& key,
                            std::string& error) {
    key.clear();
    if (path.empty()) { error = "response command key file is empty"; return false; }
    std::wstring wide = Utf8ToWide(path);
    if (wide.empty()) { error = "response command key path is invalid"; return false; }
    HANDLE file = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = WinError("open response command key file"); return false;
    }
    BY_HANDLE_FILE_INFORMATION info = {};
    if (!GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        CloseHandle(file); error = "response command key must be a regular local file";
        return false;
    }
    if (!ProtectLocalFile(wide, true, error)) { CloseHandle(file); return false; }
    LARGE_INTEGER length = {};
    if (!GetFileSizeEx(file, &length) || length.QuadPart <= 0 || length.QuadPart > 8192) {
        CloseHandle(file); error = "response command key file has invalid size";
        return false;
    }
    std::string encoded(static_cast<size_t>(length.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(file, encoded.data(), static_cast<DWORD>(encoded.size()),
                  &read, nullptr) || read != encoded.size()) {
        CloseHandle(file); error = WinError("read response command key file");
        return false;
    }
    CloseHandle(file);
    while (!encoded.empty() && (encoded.back() == '\r' || encoded.back() == '\n' ||
                                encoded.back() == ' ' || encoded.back() == '\t'))
        encoded.pop_back();
    if (encoded.empty() || encoded.size() % 4 != 0 ||
        std::any_of(encoded.begin(), encoded.end(), [](unsigned char c) {
            return !(std::isalnum(c) || c == '+' || c == '/' || c == '=');
        })) {
        error = "response command key is not valid base64";
        return false;
    }
    DWORD size = 0;
    if (!CryptStringToBinaryA(encoded.c_str(),
            static_cast<DWORD>(encoded.size()), CRYPT_STRING_BASE64, nullptr,
            &size, nullptr, nullptr) || size < 32 || size > 4096) {
        error = "response command key must be base64 encoding of 32..4096 bytes";
        return false;
    }
    key.resize(size);
    if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64, key.data(), &size, nullptr, nullptr)) {
        key.clear(); error = "response command key base64 decode failed"; return false;
    }
    key.resize(size);
    return true;
}

bool BuildResponseFrame(const std::string& payload,
                        const std::vector<unsigned char>& key,
                        std::vector<unsigned char>& frame,
                        std::string& error) {
    if (payload.empty() || payload.size() > kResponseMaxPayload || key.size() < 32) {
        error = "invalid response frame payload or key"; return false;
    }
    std::array<unsigned char, 32> mac;
    if (!HmacSha256(key, reinterpret_cast<const unsigned char*>(payload.data()),
                    payload.size(), mac, error)) return false;
    uint32_t size = static_cast<uint32_t>(payload.size());
    frame.resize(4 + payload.size() + mac.size());
    frame[0] = static_cast<unsigned char>(size);
    frame[1] = static_cast<unsigned char>(size >> 8);
    frame[2] = static_cast<unsigned char>(size >> 16);
    frame[3] = static_cast<unsigned char>(size >> 24);
    std::copy(payload.begin(), payload.end(), frame.begin() + 4);
    std::copy(mac.begin(), mac.end(), frame.begin() + 4 + payload.size());
    return true;
}

bool ParseResponseFrame(const std::vector<unsigned char>& frame,
                        const std::vector<unsigned char>& key,
                        std::string& payload, std::string& error) {
    payload.clear();
    if (frame.size() < 36 || key.size() < 32) { error = "response frame is truncated"; return false; }
    uint32_t size = static_cast<uint32_t>(frame[0]) |
        (static_cast<uint32_t>(frame[1]) << 8) |
        (static_cast<uint32_t>(frame[2]) << 16) |
        (static_cast<uint32_t>(frame[3]) << 24);
    if (size == 0 || size > kResponseMaxPayload || frame.size() != 4ULL + size + 32) {
        error = "response frame length is invalid"; return false;
    }
    std::array<unsigned char, 32> expected;
    if (!HmacSha256(key, frame.data() + 4, size, expected, error)) return false;
    if (!ConstantTimeEqual(expected.data(), frame.data() + 4 + size, 32)) {
        error = "response frame authentication failed"; return false;
    }
    payload.assign(reinterpret_cast<const char*>(frame.data() + 4), size);
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, payload.data(), size,
                             nullptr, 0)) {
        payload.clear(); error = "response payload is not valid UTF-8"; return false;
    }
    return true;
}

bool ParseResponseRequest(const std::string& payload, uint64_t nowFileTime,
                          uint32_t currentPid, ResponseRequest& request,
                          std::string& error) {
    try {
        jsonlite::Value root = jsonlite::parse(payload);
        if (root.type != jsonlite::Type::Object) { error = "request must be an object"; return false; }
        const auto* version = Required(root, "version", jsonlite::Type::Number, error);
        const auto* id = Required(root, "requestId", jsonlite::Type::String, error);
        const auto* timestamp = Required(root, "timestamp", jsonlite::Type::String, error);
        const auto* action = Required(root, "action", jsonlite::Type::String, error);
        if (!version || !id || !timestamp || !action) return false;
        if (version->number != 1 || !ValidRequestId(id->str)) {
            error = "invalid version or requestId"; return false;
        }
        uint64_t requestTime = 0;
        if (!Decimal(timestamp->str, requestTime, true)) {
            error = "timestamp must be a nonzero decimal FILETIME string"; return false;
        }
        uint64_t difference = requestTime > nowFileTime ? requestTime - nowFileTime : nowFileTime - requestTime;
        if (difference > 60ULL * 10000000ULL) { error = "timestamp is outside the 60 second window"; return false; }
        ResponseRequest candidate;
        candidate.requestId = id->str;
        candidate.timestamp = timestamp->str;
        if (action->str == "readiness") {
            if (!ExactKeys(root, {"version", "requestId", "timestamp", "action"}, error)) return false;
            candidate.kind = ResponseRequest::Kind::Readiness;
        } else if (action->str == "terminate") {
            if (!ExactKeys(root, {"version", "requestId", "timestamp", "action", "reason", "target",
                                  "maxTreeSize", "suspendBeforeTerminate",
                                  "maxTreeDepth", "isolateBeforeTerminate",
                                  "parentImageWhitelist"}, error)) return false;
            const auto* reason = Required(root, "reason", jsonlite::Type::String, error);
            const auto* target = Required(root, "target", jsonlite::Type::Object, error);
            if (!reason || !target || !ValidReason(reason->str) ||
                !ExactKeys(*target, {"pid", "createTime100ns"}, error)) {
                if (error.empty()) error = "reason is invalid";
                return false;
            }
            const auto* pid = Required(*target, "pid", jsonlite::Type::Number, error);
            const auto* createTime = Required(*target, "createTime100ns", jsonlite::Type::String, error);
            if (!pid || !createTime || pid->number < 0 || pid->number > UINT32_MAX ||
                pid->number != static_cast<uint32_t>(pid->number)) {
                error = "target.pid must be a uint32"; return false;
            }
            uint64_t ignored = 0;
            candidate.pid = static_cast<uint32_t>(pid->number);
            if (!Decimal(createTime->str, ignored, true)) {
                error = "target.createTime100ns must be a nonzero decimal uint64 string"; return false;
            }
            if (candidate.pid == 0 || candidate.pid == 4 || candidate.pid == currentPid) {
                error = "target.pid is protected"; return false;
            }
            if (const auto* tree = root.find("maxTreeSize")) {
                if (tree->type != jsonlite::Type::Number ||
                    !std::isfinite(tree->number) ||
                    std::floor(tree->number) != tree->number ||
                    tree->number < 1 || tree->number > 64) {
                    error = "maxTreeSize must be an integer in [1, 64]";
                    return false;
                }
                candidate.maxTreeSize = static_cast<uint32_t>(tree->number);
            }
            if (const auto* suspend = root.find("suspendBeforeTerminate")) {
                if (suspend->type != jsonlite::Type::Bool) {
                    error = "suspendBeforeTerminate must be boolean";
                    return false;
                }
                candidate.suspendBeforeTerminate = suspend->boolean;
            }
            if (const auto* depth = root.find("maxTreeDepth")) {
                if (depth->type != jsonlite::Type::Number ||
                    !std::isfinite(depth->number) ||
                    std::floor(depth->number) != depth->number ||
                    depth->number < 0 || depth->number > 64) {
                    error = "maxTreeDepth must be an integer in [0, 64]";
                    return false;
                }
                candidate.maxTreeDepth =
                    static_cast<uint32_t>(depth->number);
            }
            if (const auto* isolate = root.find("isolateBeforeTerminate")) {
                if (isolate->type != jsonlite::Type::Bool) {
                    error = "isolateBeforeTerminate must be boolean";
                    return false;
                }
                candidate.isolateBeforeTerminate = isolate->boolean;
            }
            if (const auto* whitelist = root.find("parentImageWhitelist")) {
                if (whitelist->type != jsonlite::Type::Array) {
                    error = "parentImageWhitelist must be an array";
                    return false;
                }
                for (const auto& item : whitelist->array) {
                    if (item.type != jsonlite::Type::String) {
                        error =
                            "parentImageWhitelist entries must be strings";
                        return false;
                    }
                    candidate.parentImageWhitelist.push_back(item.str);
                }
            }
            candidate.kind = ResponseRequest::Kind::Terminate;
            candidate.reason = reason->str;
            candidate.createTime100ns = createTime->str;
        } else if (action->str == "quarantine") {
            if (!ExactKeys(root, {"version", "requestId", "timestamp", "action", "reason", "target"}, error)) return false;
            const auto* reason = Required(root, "reason", jsonlite::Type::String, error);
            const auto* target = Required(root, "target", jsonlite::Type::Object, error);
            if (!reason || !target || !ValidReason(reason->str) ||
                !ExactKeys(*target, {"path", "sha256"}, error)) {
                if (error.empty()) error = "reason is invalid";
                return false;
            }
            const auto* path = Required(*target, "path", jsonlite::Type::String, error);
            const auto* sha256 = Required(*target, "sha256", jsonlite::Type::String, error);
            if (!path || !sha256 || !ValidQuarantinePath(path->str) ||
                !ValidSha256(sha256->str)) {
                error = "quarantine target path or sha256 is invalid"; return false;
            }
            candidate.kind = ResponseRequest::Kind::Quarantine;
            candidate.reason = reason->str;
            candidate.path = path->str;
            candidate.sha256Hex = sha256->str;
        } else if (action->str == "restore_quarantine") {
            if (!ExactKeys(root, {"version", "requestId", "timestamp", "action",
                                  "reason", "sourceRequestId"}, error)) return false;
            const auto* reason = Required(root, "reason", jsonlite::Type::String, error);
            const auto* sourceRequestId = Required(root, "sourceRequestId",
                                                    jsonlite::Type::String, error);
            if (!reason || !sourceRequestId || !ValidReason(reason->str) ||
                !ValidRequestId(sourceRequestId->str) ||
                sourceRequestId->str == candidate.requestId) {
                if (error.empty()) error = "restore source requestId is invalid";
                return false;
            }
            candidate.kind = ResponseRequest::Kind::RestoreQuarantine;
            candidate.reason = reason->str;
            candidate.sourceRequestId = sourceRequestId->str;
        } else if (action->str == "isolate") {
            if (!ExactKeys(root, {"version", "requestId", "timestamp", "action",
                                  "reason", "enable", "managementIp", "allowedPorts"},
                           error)) return false;
            const auto* reason = Required(root, "reason", jsonlite::Type::String, error);
            const auto* enable = Required(root, "enable", jsonlite::Type::Bool, error);
            const auto* mgmtIp = Required(root, "managementIp", jsonlite::Type::String, error);
            const auto* ports = Required(root, "allowedPorts", jsonlite::Type::String, error);
            if (!reason || !enable || !mgmtIp || !ports ||
                !ValidReason(reason->str) ||
                !HostIsolationController::ValidateIsolationParameters(
                    mgmtIp->str, ports->str, error)) {
                if (error.empty()) error = "isolate request fields are invalid";
                return false;
            }
            candidate.kind = ResponseRequest::Kind::Isolation;
            candidate.reason = reason->str;
            candidate.isolateEnable = enable->boolean;
            candidate.managementIp = mgmtIp->str;
            candidate.allowedPorts = ports->str;
        } else if (action->str == "isolation_status") {
            if (!ExactKeys(root, {"version", "requestId", "timestamp", "action"},
                           error)) return false;
            candidate.kind = ResponseRequest::Kind::IsolationStatus;
        } else if (action->str == "delete_file") {
            if (!ExactKeys(root, {"version", "requestId", "timestamp", "action",
                                  "reason", "target"}, error)) return false;
            const auto* reason = Required(root, "reason", jsonlite::Type::String, error);
            const auto* target = Required(root, "target", jsonlite::Type::Object, error);
            if (!reason || !target || !ValidReason(reason->str) ||
                !ExactKeys(*target, {"path", "sha256"}, error)) {
                if (error.empty()) error = "reason is invalid";
                return false;
            }
            const auto* path = Required(*target, "path", jsonlite::Type::String, error);
            const auto* sha256 = Required(*target, "sha256", jsonlite::Type::String, error);
            if (!path || !sha256 || !ValidQuarantinePath(path->str) ||
                !ValidSha256(sha256->str)) {
                error = "delete_file target path or sha256 is invalid"; return false;
            }
            candidate.kind = ResponseRequest::Kind::DeleteFile;
            candidate.reason = reason->str;
            candidate.path = path->str;
            candidate.sha256Hex = sha256->str;
        } else if (action->str == "suspend") {
            if (!ExactKeys(root, {"version", "requestId", "timestamp", "action", "reason", "target"}, error)) return false;
            const auto* reason = Required(root, "reason", jsonlite::Type::String, error);
            const auto* target = Required(root, "target", jsonlite::Type::Object, error);
            if (!reason || !target || !ValidReason(reason->str) ||
                !ExactKeys(*target, {"pid", "createTime100ns"}, error)) {
                if (error.empty()) error = "reason is invalid";
                return false;
            }
            const auto* pid = Required(*target, "pid", jsonlite::Type::Number, error);
            const auto* createTime = Required(*target, "createTime100ns", jsonlite::Type::String, error);
            if (!pid || !createTime || pid->number < 0 || pid->number > UINT32_MAX ||
                pid->number != static_cast<uint32_t>(pid->number)) {
                error = "target.pid must be a uint32"; return false;
            }
            uint64_t ignored = 0;
            candidate.pid = static_cast<uint32_t>(pid->number);
            if (!Decimal(createTime->str, ignored, true)) {
                error = "target.createTime100ns must be a nonzero decimal uint64 string"; return false;
            }
            if (candidate.pid == 0 || candidate.pid == 4 || candidate.pid == currentPid) {
                error = "target.pid is protected"; return false;
            }
            candidate.kind = ResponseRequest::Kind::Suspend;
            candidate.reason = reason->str;
            candidate.createTime100ns = createTime->str;
        } else if (action->str == "resume") {
            if (!ExactKeys(root, {"version", "requestId", "timestamp", "action", "reason", "target"}, error)) return false;
            const auto* reason = Required(root, "reason", jsonlite::Type::String, error);
            const auto* target = Required(root, "target", jsonlite::Type::Object, error);
            if (!reason || !target || !ValidReason(reason->str) ||
                !ExactKeys(*target, {"pid", "createTime100ns"}, error)) {
                if (error.empty()) error = "reason is invalid";
                return false;
            }
            const auto* pid = Required(*target, "pid", jsonlite::Type::Number, error);
            const auto* createTime = Required(*target, "createTime100ns", jsonlite::Type::String, error);
            if (!pid || !createTime || pid->number < 0 || pid->number > UINT32_MAX ||
                pid->number != static_cast<uint32_t>(pid->number)) {
                error = "target.pid must be a uint32"; return false;
            }
            uint64_t ignored = 0;
            candidate.pid = static_cast<uint32_t>(pid->number);
            if (!Decimal(createTime->str, ignored, true)) {
                error = "target.createTime100ns must be a nonzero decimal uint64 string"; return false;
            }
            if (candidate.pid == 0 || candidate.pid == 4 || candidate.pid == currentPid) {
                error = "target.pid is protected"; return false;
            }
            candidate.kind = ResponseRequest::Kind::Resume;
            candidate.reason = reason->str;
            candidate.createTime100ns = createTime->str;
        } else { error = "unsupported action"; return false; }
        request = std::move(candidate);
        return true;
    } catch (const std::exception& exception) {
        error = exception.what(); return false;
    }
}

ResponseAuditLedger::ResponseAuditLedger(WriteFn writeFn)
    : file_(INVALID_HANDLE_VALUE), writeFn_(writeFn) {}
ResponseAuditLedger::~ResponseAuditLedger() { Close(); }

bool ResponseAuditLedger::AppendLine(const std::string& line) {
    if (writeFn_) {
        try {
            if (writeFn_(file_, line)) return true;
        } catch (...) {
        }
        SetLastError(ERROR_WRITE_FAULT);
        return false;
    }
    DWORD written = 0;
    if (!WriteFile(file_, line.data(), static_cast<DWORD>(line.size()),
                   &written, nullptr)) return false;
    if (written != line.size()) {
        SetLastError(ERROR_WRITE_FAULT);
        return false;
    }
    return FlushFileBuffers(file_) != FALSE;
}

bool ResponseAuditLedger::Open(const std::string& path, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    CloseLocked();
    if (path.empty()) { error = "response audit path is empty"; return false; }
    std::wstring wide = Utf8ToWide(path);
    DWORD existing = GetFileAttributesW(wide.c_str());
    if (existing != INVALID_FILE_ATTRIBUTES &&
        (existing & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        error = "response audit must be a regular non-reparse file";
        return false;
    }
    file_ = CreateFileW(wide.c_str(), GENERIC_READ | FILE_APPEND_DATA,
        FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) { error = WinError("open response audit"); return false; }
    BY_HANDLE_FILE_INFORMATION info = {};
    if (!GetFileInformationByHandle(file_, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        error = "response audit must be a regular local file"; CloseLocked(); return false;
    }
    if (!ProtectLocalFile(wide, true, error)) { CloseLocked(); return false; }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file_, &size)) { error = WinError("size response audit"); CloseLocked(); return false; }
    if (size.QuadPart < 0) {
        error = "response audit has an invalid file size";
        CloseLocked();
        return false;
    }
    LARGE_INTEGER offset = {};
    if (!SetFilePointerEx(file_, offset, nullptr, FILE_BEGIN)) { error = WinError("seek response audit"); CloseLocked(); return false; }
    std::string line;
    std::deque<std::string> replayRecentIds;
    std::unordered_set<std::string> replayIdSet;
    bool pendingAttempt = false;
    std::string pendingRequestId;
    std::string pendingAction;
    uint64_t expectedChainSeq = 1;
    std::string expectedChainPrev(64, '0');
    bool chainedHistory = false;
    auto rememberRequestId = [&](const std::string& requestId) {
        if (!replayIdSet.insert(requestId).second) return false;
        replayRecentIds.push_back(requestId);
        if (replayRecentIds.size() > kReplayLimit) {
            replayIdSet.erase(replayRecentIds.front());
            replayRecentIds.pop_front();
        }
        return true;
    };
    auto processLine = [&](std::string& record) {
        if (!record.empty() && record.back() == '\r') record.pop_back();
        if (record.empty()) throw std::runtime_error("empty record");
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                record.data(), static_cast<int>(record.size()), nullptr, 0) == 0)
            throw std::runtime_error("invalid UTF-8");
        auto value = jsonlite::parse(record);
        if (value.type != jsonlite::Type::Object) throw std::runtime_error("object");
        const auto* chainSeq = value.find("chain_seq");
        const auto* chainPrev = value.find("chain_prev");
        const auto* chainHash = value.find("chain_hash");
        const bool hasChain = chainSeq || chainPrev || chainHash;
        if (!hasChain) {
            if (chainedHistory) throw std::runtime_error("mixed chain history");
        } else {
            if (!chainSeq || !chainPrev || !chainHash ||
                chainSeq->type != jsonlite::Type::Number ||
                chainPrev->type != jsonlite::Type::String ||
                chainHash->type != jsonlite::Type::String ||
                !std::isfinite(chainSeq->number) ||
                std::floor(chainSeq->number) != chainSeq->number ||
                chainSeq->number < 1.0 ||
                chainSeq->number > kMaxSafeChainSequence ||
                chainPrev->str != expectedChainPrev ||
                !IsHexDigestLedger(chainPrev->str) ||
                !IsHexDigestLedger(chainHash->str)) {
                throw std::runtime_error("chain");
            }
            const uint64_t sequence = static_cast<uint64_t>(chainSeq->number);
            if (sequence != expectedChainSeq) throw std::runtime_error("chain order");
            const std::string chainHashValue = chainHash->str;
            value.object.erase("chain_seq");
            value.object.erase("chain_prev");
            value.object.erase("chain_hash");
            std::string payloadHash = Sha256HexLedger(StableJsonLedger(value));
            if (ChainHashForLedger(sequence, expectedChainPrev, payloadHash) != chainHashValue) {
                /* Releases before outcome.requestId was persisted can be
                 * replayed safely: the pending attempt supplies the only
                 * unambiguous identity, and restoring it also lets the
                 * historical payload hash verify. */
                const auto* type = value.find("record_type");
                if (!value.find("requestId") && pendingAttempt &&
                    type && type->type == jsonlite::Type::String &&
                    type->str == "outcome" && !pendingRequestId.empty()) {
                    value.object.emplace("requestId",
                                          jsonlite::Value::makeString(pendingRequestId));
                    payloadHash = Sha256HexLedger(StableJsonLedger(value));
                }
                if (ChainHashForLedger(sequence, expectedChainPrev, payloadHash) != chainHashValue)
                    throw std::runtime_error("chain hash");
            }
            chainedHistory = true;
            expectedChainPrev = chainHashValue;
            if (expectedChainSeq == std::numeric_limits<uint64_t>::max())
                throw std::runtime_error("chain overflow");
            ++expectedChainSeq;
        }
        const auto* type = value.find("record_type");
        if (!type) {
            const auto* id = value.find("requestId");
            if (pendingAttempt || !id || id->type != jsonlite::Type::String ||
                !ValidRequestId(id->str)) throw std::runtime_error("legacy");
            if (!rememberRequestId(id->str)) throw std::runtime_error("duplicate");
        } else if (type->type != jsonlite::Type::String) {
            throw std::runtime_error("type");
        } else if (type->str == "attempt") {
            const auto* id = value.find("requestId");
            const auto* action = value.find("action");
            if (pendingAttempt || !id || id->type != jsonlite::Type::String ||
                !ValidRequestId(id->str) || !action ||
                action->type != jsonlite::Type::String || action->str.empty())
                throw std::runtime_error("attempt");
            if (!rememberRequestId(id->str)) throw std::runtime_error("duplicate");
            pendingAttempt = true;
            pendingRequestId = id->str;
            pendingAction = action->str;
        } else if (type->str == "outcome") {
            const auto* id = value.find("requestId");
            const auto* action = value.find("action");
            if (!pendingAttempt || (id && (id->type != jsonlite::Type::String ||
                id->str != pendingRequestId)) || !action ||
                action->type != jsonlite::Type::String ||
                action->str != pendingAction)
                throw std::runtime_error("outcome");
            pendingAttempt = false;
            pendingRequestId.clear();
            pendingAction.clear();
        } else {
            throw std::runtime_error("type");
        }
    };
    /* Preserve read compatibility with pre-chain records as a contiguous
     * prefix; after the first chained line, all later records are verified. */
    std::array<char, kReplayReadChunkSize> readBuffer = {};
    LONGLONG remaining = size.QuadPart;
    while (remaining > 0) {
        const DWORD requestSize = static_cast<DWORD>(
            (std::min<LONGLONG>)(remaining,
                                  static_cast<LONGLONG>(readBuffer.size())));
        DWORD read = 0;
        if (!ReadFile(file_, readBuffer.data(), requestSize, &read, nullptr)) {
            error = WinError("read response audit");
            CloseLocked();
            return false;
        }
        if (read == 0) {
            error = "response audit changed or ended before its replay snapshot";
            CloseLocked();
            return false;
        }
        remaining -= read;
        for (DWORD index = 0; index < read; ++index) {
            const char ch = readBuffer[index];
            if (ch == '\n') {
                try {
                    processLine(line);
                } catch (...) {
                    error = "response audit contains malformed ordering or JSONL";
                    CloseLocked();
                    return false;
                }
                line.clear();
            } else {
                if (line.size() >= kReplayRecordLimit) {
                    error = "response audit record exceeds the safe replay limit";
                    CloseLocked();
                    return false;
                }
                line.push_back(ch);
            }
        }
    }
    if (!line.empty()) {
        error = "response audit ends with an incomplete JSONL record";
        CloseLocked();
        return false;
    }
    LARGE_INTEGER finalSize = {};
    if (!GetFileSizeEx(file_, &finalSize) || finalSize.QuadPart != size.QuadPart) {
        error = "response audit changed while it was being replayed";
        CloseLocked();
        return false;
    }
    ids_.swap(replayIdSet);
    recentIds_.swap(replayRecentIds);
    pendingAttempt_ = pendingAttempt;
    pendingRequestId_ = pendingRequestId;
    pendingAction_ = pendingAction;
    if (chainedHistory) {
        auditChainSeq_ = expectedChainSeq - 1;
        auditChainPrev_ = expectedChainPrev;
    }
    writeFailed_ = false;
    return true;
}

bool ResponseAuditLedger::Attempt(const ResponseActionRequest& request,
                                  std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (pendingAttempt_) { error = "prior attempt has no outcome"; return false; }
    if (ids_.find(request.requestId) != ids_.end()) { error = "requestId replay"; return false; }
    std::string base = "{\"record_type\":\"attempt\",\"timestamp\":\"" +
        jsonlite::escape(request.timestamp) + "\",\"action\":\"terminate\"," +
        "\"effective_mode\":\"real\",\"requestId\":\"" +
        jsonlite::escape(request.requestId) + "\",\"target\":{\"pid\":" +
        std::to_string(request.pid) + ",\"createTime100ns\":\"" +
        std::to_string(request.createTime100ns) + "\"}}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append response attempt"); return false;
    }
    ids_.insert(request.requestId);
    recentIds_.push_back(request.requestId);
    pendingAttempt_ = true;
    pendingRequestId_ = request.requestId;
    pendingAction_ = "terminate";
    auditChainSeq_=seq; auditChainPrev_=ch;
    if (recentIds_.size() > kReplayLimit) {
        ids_.erase(recentIds_.front());
        recentIds_.pop_front();
    }
    return true;
}

bool ResponseAuditLedger::Outcome(const ResponseActionResult& result,
                                  std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (!pendingAttempt_) {
        error = "response audit has no pending attempt"; return false;
    }
    if (pendingAction_ != "terminate" || result.requestId != pendingRequestId_) {
        error = "response audit outcome does not match pending attempt"; return false;
    }
    std::string base = std::string("{\"record_type\":\"outcome\",\"action\":\"terminate\",") +
        "\"requestId\":\"" + jsonlite::escape(pendingRequestId_) + "\"," +
        std::string("\"effective_mode\":\"real\",\"status\":\"") +
        jsonlite::escape(result.status) + "\",\"termination_requested\":" +
        (result.terminationRequested ? "true" : "false") +
        ",\"exit_observed\":" + (result.exitObserved ? "true" : "false") +
        ",\"win32_error\":" + std::to_string(result.win32Error) +
        (result.treeRequested
            ? ",\"children_terminated\":" + std::to_string(result.childrenTerminated) +
                ",\"children_skipped\":" + std::to_string(result.childrenSkipped) +
                ",\"children_failed\":" + std::to_string(result.childrenFailed)
            : "") + "}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append response outcome"); return false;
    }
    pendingAttempt_ = false;
    pendingRequestId_.clear();
    pendingAction_.clear();
    auditChainSeq_=seq; auditChainPrev_=ch;
    return true;
}

bool ResponseAuditLedger::AttemptAction(const ResponseActionRequest& request,
                                        const char* action,
                                        std::string& error) {
    std::string act = action ? action : "terminate";
    if (act == "terminate") return Attempt(request, error);
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (pendingAttempt_) { error = "prior attempt has no outcome"; return false; }
    if (ids_.find(request.requestId) != ids_.end()) { error = "requestId replay"; return false; }
    std::string base = "{\"record_type\":\"attempt\",\"timestamp\":\"" +
        jsonlite::escape(request.timestamp) + "\",\"action\":\"" + jsonlite::escape(act) + "\"," +
        "\"effective_mode\":\"real\",\"requestId\":\"" +
        jsonlite::escape(request.requestId) + "\",\"target\":{\"pid\":" +
        std::to_string(request.pid) + ",\"createTime100ns\":\"" +
        std::to_string(request.createTime100ns) + "\"}}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append response attempt"); return false;
    }
    ids_.insert(request.requestId);
    recentIds_.push_back(request.requestId);
    pendingAttempt_ = true;
    pendingRequestId_ = request.requestId;
    pendingAction_ = act;
    auditChainSeq_=seq; auditChainPrev_=ch;
    if (recentIds_.size() > kReplayLimit) {
        ids_.erase(recentIds_.front());
        recentIds_.pop_front();
    }
    return true;
}

bool ResponseAuditLedger::OutcomeAction(const ResponseActionResult& result,
                                        const char* action,
                                        std::string& error) {
    std::string act = action ? action : "terminate";
    if (act == "terminate") return Outcome(result, error);
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (!pendingAttempt_) {
        error = "response audit has no pending attempt"; return false;
    }
    if (pendingAction_ != act || result.requestId != pendingRequestId_) {
        error = "response audit outcome does not match pending attempt"; return false;
    }
    std::string base = std::string("{\"record_type\":\"outcome\",\"action\":\"") +
        jsonlite::escape(act) + "\"," +
        "\"requestId\":\"" + jsonlite::escape(pendingRequestId_) + "\"," +
        std::string("\"effective_mode\":\"real\",\"status\":\"") +
        jsonlite::escape(result.status) + "\",\"win32_error\":" +
        std::to_string(result.win32Error) + "}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append response outcome"); return false;
    }
    pendingAttempt_ = false;
    pendingRequestId_.clear();
    pendingAction_.clear();
    auditChainSeq_=seq; auditChainPrev_=ch;
    return true;
}

bool ResponseAuditLedger::AttemptQuarantine(const QuarantineRequest& request,
        const std::string& sha256, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (pendingAttempt_) { error = "prior attempt has no outcome"; return false; }
    if (ids_.find(request.requestId) != ids_.end()) { error = "requestId replay"; return false; }
    std::string base = "{\"record_type\":\"attempt\",\"timestamp\":\"" +
        jsonlite::escape(request.timestamp) + "\",\"action\":\"quarantine\"," +
        "\"effective_mode\":\"real\",\"requestId\":\"" +
        jsonlite::escape(request.requestId) + "\",\"target\":{\"path\":\"" +
        jsonlite::escape(request.path) + "\",\"sha256\":\"" +
        jsonlite::escape(sha256) + "\"}}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append quarantine attempt"); return false;
    }
    ids_.insert(request.requestId);
    recentIds_.push_back(request.requestId);
    pendingAttempt_ = true;
    pendingRequestId_ = request.requestId;
    pendingAction_ = "quarantine";
    auditChainSeq_=seq; auditChainPrev_=ch;
    if (recentIds_.size() > kReplayLimit) {
        ids_.erase(recentIds_.front()); recentIds_.pop_front();
    }
    return true;
}

bool ResponseAuditLedger::OutcomeQuarantine(const QuarantineRequest& request,
        const QuarantineResult& result, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (!pendingAttempt_) {
        error = "response audit has no pending attempt"; return false;
    }
    if (pendingAction_ != "quarantine" || request.requestId != pendingRequestId_ ||
        result.requestId != pendingRequestId_) {
        error = "response audit outcome does not match pending attempt"; return false;
    }
    std::string base = std::string("{\"record_type\":\"outcome\",\"action\":\"quarantine\",") +
        "\"requestId\":\"" + jsonlite::escape(pendingRequestId_) + "\"," +
        std::string("\"effective_mode\":\"real\",\"status\":\"") +
        jsonlite::escape(result.status) + "\",\"quarantine_path\":\"" +
        jsonlite::escape(result.quarantinePath) + "\",\"sha256\":\"" +
        jsonlite::escape(result.sha256Hex) + "\",\"sidecar_sha256\":\"" +
        jsonlite::escape(result.sidecarSha256Hex) + "\",\"rolled_back\":" +
        (result.rolledBack ? "true" : "false") + ",\"win32_error\":" +
        std::to_string(result.win32Error) + "}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append quarantine outcome"); return false;
    }
    pendingAttempt_ = false;
    pendingRequestId_.clear();
    pendingAction_.clear();
    auditChainSeq_=seq; auditChainPrev_=ch;
    return true;
}

bool ResponseAuditLedger::AttemptRestore(const QuarantineRestoreRequest& request,
        const std::string& originalPath, const std::string& quarantinePath,
        const std::string& sha256, const std::string& sidecarSha256,
        std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) {
        error = "response audit is not open"; return false;
    }
    if (writeFailed_) {
        error = "response audit write previously failed"; return false;
    }
    if (pendingAttempt_) {
        error = "prior attempt has no outcome"; return false;
    }
    if (ids_.find(request.requestId) != ids_.end()) {
        error = "requestId replay"; return false;
    }
    std::string base = "{\"record_type\":\"attempt\",\"timestamp\":\"" +
        jsonlite::escape(request.timestamp) + "\",\"action\":\"restore_quarantine\"," +
        "\"effective_mode\":\"real\",\"requestId\":\"" +
        jsonlite::escape(request.requestId) + "\",\"target\":{\"source_request_id\":\"" +
        jsonlite::escape(request.sourceRequestId) + "\",\"original_path\":\"" +
        jsonlite::escape(originalPath) + "\",\"quarantine_path\":\"" +
        jsonlite::escape(quarantinePath) + "\",\"sha256\":\"" +
        jsonlite::escape(sha256) + "\",\"sidecar_sha256\":\"" +
        jsonlite::escape(sidecarSha256) + "\"}}";
    std::string payloadHash;
    try {
        auto value = jsonlite::parse(base);
        payloadHash = Sha256HexLedger(StableJsonLedger(value));
    } catch (...) {
        payloadHash = Sha256HexLedger(base);
    }
    const uint64_t sequence = auditChainSeq_ + 1;
    const std::string previous = auditChainPrev_;
    const std::string chainHash =
        ChainHashForLedger(sequence, previous, payloadHash);
    const std::string line = base.substr(0, base.size() - 1) +
        ",\"chain_seq\":" + std::to_string(sequence) +
        ",\"chain_prev\":\"" + previous + "\",\"chain_hash\":\"" +
        chainHash + "\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append quarantine restore attempt");
        return false;
    }
    ids_.insert(request.requestId);
    recentIds_.push_back(request.requestId);
    pendingAttempt_ = true;
    pendingRequestId_ = request.requestId;
    pendingAction_ = "restore_quarantine";
    auditChainSeq_ = sequence;
    auditChainPrev_ = chainHash;
    if (recentIds_.size() > kReplayLimit) {
        ids_.erase(recentIds_.front());
        recentIds_.pop_front();
    }
    return true;
}

bool ResponseAuditLedger::OutcomeRestore(const QuarantineRestoreRequest& request,
        const QuarantineRestoreResult& result, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) {
        error = "response audit is not open"; return false;
    }
    if (writeFailed_) {
        error = "response audit write previously failed"; return false;
    }
    if (!pendingAttempt_ || pendingAction_ != "restore_quarantine" ||
        request.requestId != pendingRequestId_ ||
        result.requestId != pendingRequestId_ ||
        result.sourceRequestId != request.sourceRequestId) {
        error = "response audit outcome does not match pending restore";
        return false;
    }
    std::string base = "{\"record_type\":\"outcome\",\"action\":\"restore_quarantine\"," +
        std::string("\"requestId\":\"") +
        jsonlite::escape(pendingRequestId_) + "\",\"source_request_id\":\"" +
        jsonlite::escape(result.sourceRequestId) + "\",\"effective_mode\":\"real\"," +
        "\"status\":\"" + jsonlite::escape(result.status) +
        "\",\"restored\":" +
        (result.status == "restored" ? "true" : "false") +
        ",\"partial_restore\":" +
        (result.partialRestore ? "true" : "false") +
        ",\"original_path\":\"" + jsonlite::escape(result.originalPath) +
        "\",\"quarantine_path\":\"" +
        jsonlite::escape(result.quarantinePath) + "\",\"sha256\":\"" +
        jsonlite::escape(result.sha256Hex) + "\",\"sidecar_sha256\":\"" +
        jsonlite::escape(result.sidecarSha256Hex) + "\",\"win32_error\":" +
        std::to_string(result.win32Error) + "}";
    std::string payloadHash;
    try {
        auto value = jsonlite::parse(base);
        payloadHash = Sha256HexLedger(StableJsonLedger(value));
    } catch (...) {
        payloadHash = Sha256HexLedger(base);
    }
    const uint64_t sequence = auditChainSeq_ + 1;
    const std::string previous = auditChainPrev_;
    const std::string chainHash =
        ChainHashForLedger(sequence, previous, payloadHash);
    const std::string line = base.substr(0, base.size() - 1) +
        ",\"chain_seq\":" + std::to_string(sequence) +
        ",\"chain_prev\":\"" + previous + "\",\"chain_hash\":\"" +
        chainHash + "\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append quarantine restore outcome");
        return false;
    }
    pendingAttempt_ = false;
    pendingRequestId_.clear();
    pendingAction_.clear();
    auditChainSeq_ = sequence;
    auditChainPrev_ = chainHash;
    return true;
}

bool ResponseAuditLedger::AttemptIsolation(const ResponseRequest& request,
        std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (pendingAttempt_) { error = "prior attempt has no outcome"; return false; }
    if (ids_.find(request.requestId) != ids_.end()) { error = "requestId replay"; return false; }
    std::string base = "{\"record_type\":\"attempt\",\"timestamp\":\"" +
        jsonlite::escape(request.timestamp) + "\",\"action\":\"isolate\"," +
        "\"effective_mode\":\"real\",\"requestId\":\"" +
        jsonlite::escape(request.requestId) + "\",\"enable\":" +
        (request.isolateEnable ? "true" : "false") +
        ",\"managementIp\":\"" + jsonlite::escape(request.managementIp) +
        "\",\"allowedPorts\":\"" + jsonlite::escape(request.allowedPorts) + "\"}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append isolation attempt"); return false;
    }
    ids_.insert(request.requestId);
    recentIds_.push_back(request.requestId);
    pendingAttempt_ = true;
    pendingRequestId_ = request.requestId;
    pendingAction_ = "isolate";
    auditChainSeq_=seq; auditChainPrev_=ch;
    if (recentIds_.size() > kReplayLimit) {
        ids_.erase(recentIds_.front()); recentIds_.pop_front();
    }
    return true;
}

bool ResponseAuditLedger::OutcomeIsolation(const ResponseRequest& request,
        const ResponseIsolationResult& result, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (!pendingAttempt_) {
        error = "response audit has no pending attempt"; return false;
    }
    if (pendingAction_ != "isolate" || request.requestId != pendingRequestId_ ||
        (!result.requestId.empty() && result.requestId != pendingRequestId_)) {
        error = "response audit outcome does not match pending attempt"; return false;
    }
    std::string base = "{\"record_type\":\"outcome\",\"action\":\"isolate\"," +
        std::string("\"effective_mode\":\"real\",\"requestId\":\"") +
        jsonlite::escape(pendingRequestId_) + "\",\"enable\":" +
        (request.isolateEnable ? "true" : "false") + ",\"status\":\"" +
        jsonlite::escape(result.status) + "\",\"success\":" +
        (result.success ? "true" : "false") +
        (result.error.empty() ? "" : ",\"error\":\"" +
            jsonlite::escape(result.error) + "\"") + "}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append isolation outcome"); return false;
    }
    pendingAttempt_ = false;
    pendingRequestId_.clear();
    pendingAction_.clear();
    auditChainSeq_=seq; auditChainPrev_=ch;
    return true;
}

bool ResponseAuditLedger::AttemptDeleteFile(const DeleteFileRequest& request,
        std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (pendingAttempt_) { error = "prior attempt has no outcome"; return false; }
    if (ids_.find(request.requestId) != ids_.end()) { error = "requestId replay"; return false; }
    std::string base = "{\"record_type\":\"attempt\",\"timestamp\":\"" +
        jsonlite::escape(request.timestamp) + "\",\"action\":\"delete_file\"," +
        "\"effective_mode\":\"real\",\"requestId\":\"" +
        jsonlite::escape(request.requestId) + "\",\"target\":{\"path\":\"" +
        jsonlite::escape(request.path) + "\",\"sha256\":\"" +
        jsonlite::escape(request.sha256Hex) + "\"}}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append delete_file attempt"); return false;
    }
    ids_.insert(request.requestId);
    recentIds_.push_back(request.requestId);
    pendingAttempt_ = true;
    pendingRequestId_ = request.requestId;
    pendingAction_ = "delete_file";
    auditChainSeq_=seq; auditChainPrev_=ch;
    if (recentIds_.size() > kReplayLimit) {
        ids_.erase(recentIds_.front()); recentIds_.pop_front();
    }
    return true;
}

bool ResponseAuditLedger::OutcomeDeleteFile(const DeleteFileResult& result,
        std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (!pendingAttempt_) {
        error = "response audit has no pending attempt"; return false;
    }
    if (pendingAction_ != "delete_file" || result.requestId != pendingRequestId_) {
        error = "response audit outcome does not match pending attempt"; return false;
    }
    std::string base = std::string("{\"record_type\":\"outcome\",\"action\":\"delete_file\",") +
        "\"requestId\":\"" + jsonlite::escape(pendingRequestId_) + "\"," +
        std::string("\"effective_mode\":\"real\",\"status\":\"") +
        jsonlite::escape(result.status) + "\",\"path\":\"" +
        jsonlite::escape(result.path) + "\",\"deleted\":" +
        (result.deleted ? "true" : "false") + ",\"win32_error\":" +
        std::to_string(result.win32Error) + "}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append delete_file outcome"); return false;
    }
    pendingAttempt_ = false;
    pendingRequestId_.clear();
    pendingAction_.clear();
    auditChainSeq_=seq; auditChainPrev_=ch;
    return true;
}

bool ResponseAuditLedger::AcceptDryRun(const ResponseRequest& request,
                                       const std::string& action,
                                       std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == INVALID_HANDLE_VALUE) { error = "response audit is not open"; return false; }
    if (writeFailed_) { error = "response audit write previously failed"; return false; }
    if (pendingAttempt_) { error = "prior attempt has no outcome"; return false; }
    if (ids_.find(request.requestId) != ids_.end()) { error = "requestId replay"; return false; }
    std::string target = action == "restore_quarantine"
        ? "{\"source_request_id\":\"" +
            jsonlite::escape(request.sourceRequestId) + "\"}"
        : (action == "quarantine" || action == "delete_file")
        ? "{\"path\":\"" + jsonlite::escape(request.path) +
            "\",\"sha256\":\"" + jsonlite::escape(request.sha256Hex) + "\"}"
        : "{\"pid\":" + std::to_string(request.pid) +
            ",\"createTime100ns\":\"" + jsonlite::escape(request.createTime100ns) + "\"}";
    std::string base = "{\"timestamp\":\"" + jsonlite::escape(request.timestamp) +
        "\",\"action\":\"" + jsonlite::escape(action) +
        "\",\"effective_mode\":\"dry_run\","
        "\"status\":\"accepted\",\"requestId\":\"" +
        jsonlite::escape(request.requestId) + "\",\"target\":" + target + "}";
    std::string payloadHash; try{ auto pv=jsonlite::parse(base); payloadHash=Sha256HexLedger(StableJsonLedger(pv)); }catch(...){ payloadHash=Sha256HexLedger(base); }
    uint64_t seq=auditChainSeq_+1; std::string prev=auditChainPrev_; std::string ch=ChainHashForLedger(seq,prev,payloadHash);
    std::string line = base.substr(0,base.size()-1)+",\"chain_seq\":"+std::to_string(seq)+",\"chain_prev\":\""+prev+"\",\"chain_hash\":\""+ch+"\"}\r\n";
    if (!AppendLine(line)) {
        writeFailed_ = true;
        error = WinError("append response audit"); return false;
    }
    ids_.insert(request.requestId);
    recentIds_.push_back(request.requestId);
    auditChainSeq_=seq; auditChainPrev_=ch;
    if (recentIds_.size() > kReplayLimit) {
        ids_.erase(recentIds_.front());
        recentIds_.pop_front();
    }
    return true;
}

bool ResponseAuditLedger::Contains(const std::string& requestId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ids_.find(requestId) != ids_.end();
}

ResponseAuditState ResponseAuditLedger::State() const {
    std::lock_guard<std::mutex> lock(mutex_);
    ResponseAuditState state;
    state.available = file_ != INVALID_HANDLE_VALUE && !writeFailed_;
    state.pending = pendingAttempt_;
    state.writable = state.available && !state.pending;
    return state;
}

void ResponseAuditLedger::Close() {
    std::lock_guard<std::mutex> lock(mutex_);
    CloseLocked();
}

void ResponseAuditLedger::CloseLocked() {
    if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    file_ = INVALID_HANDLE_VALUE;
    ids_.clear();
    recentIds_.clear();
    pendingAttempt_ = false;
    pendingRequestId_.clear();
    pendingAction_.clear();
    auditChainSeq_=0; auditChainPrev_=std::string(64,'0');
}

struct ResponseServer::Impl {
    HANDLE pipe = INVALID_HANDLE_VALUE;
    HANDLE stopEvent = nullptr;
    std::atomic<bool> stopping{false};
    std::thread worker;
    std::vector<unsigned char> key;
    ResponseAuditLedger ledger;
    NativeResponseActionPlatform platform;
    NativeQuarantinePlatform quarantinePlatform;
    EventLogResponseEmergencySink emergency;
    std::unique_ptr<ResponseActionExecutor> executor;
    std::unique_ptr<QuarantineExecutor> quarantineExecutor;
    std::mutex executeMutex; /* serializes executor calls (shared ledger) */
    bool realTermination = false;
    bool realQuarantine = false;
    bool realDeleteFile = false;
    bool realSuspend = false;
    bool realResume = false;
    ResponseFileIdentity selfIdentity;
    std::wstring selfBase;
    IsolationHandler isolationHandler;
    IsolationStatusHandler isolationStatusHandler;

    void Send(HANDLE connection, const std::string& payload) {
        std::vector<unsigned char> frame;
        std::string ignored;
        if (BuildResponseFrame(payload, key, frame, ignored))
            OverlappedIo(connection, true, frame.data(), static_cast<DWORD>(frame.size()), stopping);
    }

    void ServeConnection() {
        if (!AuthorizedPipeClient(pipe)) return;
        unsigned char header[4];
        if (!OverlappedIo(pipe, false, header, sizeof(header), stopping)) return;
        uint32_t size = static_cast<uint32_t>(header[0]) |
            (static_cast<uint32_t>(header[1]) << 8) |
            (static_cast<uint32_t>(header[2]) << 16) |
            (static_cast<uint32_t>(header[3]) << 24);
        if (size == 0 || size > kResponseMaxPayload) return;
        std::vector<unsigned char> frame(4 + size + 32);
        std::copy(header, header + 4, frame.begin());
        if (!OverlappedIo(pipe, false, frame.data() + 4, size + 32, stopping)) return;
        std::string payload, error;
        if (!ParseResponseFrame(frame, key, payload, error)) return;
        FILETIME now;
        GetSystemTimePreciseAsFileTime(&now);
        uint64_t ticks = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        ResponseRequest request;
        if (!ParseResponseRequest(payload, ticks, GetCurrentProcessId(), request, error)) {
            Send(pipe, JsonResponse(false, realTermination ? "real" : "dry_run", "rejected")); return;
        }
        if (request.kind == ResponseRequest::Kind::Readiness) {
            IsolationHandler readyIsolationHandler;
            IsolationStatusHandler readyStatusHandler;
            {
                std::lock_guard<std::mutex> lock(executeMutex);
                readyIsolationHandler = isolationHandler;
                readyStatusHandler = isolationStatusHandler;
            }
            std::string response = JsonResponse(true, realTermination ? "real" : "dry_run",
                                                "ready", request.requestId);
            response.pop_back();
            response += ",\"capabilities\":{\"terminate\":\"";
            response += realTermination ? "real" : "dry_run";
            response += "\",\"quarantine\":\"";
            response += realQuarantine ? "real" : "dry_run";
            response += "\",\"quarantine_restore\":\"";
            response += realQuarantine ? "real" : "dry_run";
            response += "\",\"delete_file\":\"";
            response += realDeleteFile ? "real" : "dry_run";
            response += "\",\"suspend\":\"";
            response += realSuspend ? "real" : "dry_run";
            response += "\",\"resume\":\"";
            response += realResume ? "real" : "dry_run";
            response += "\",\"host_isolation\":\"";
            response += readyIsolationHandler ? "real" : "unavailable";
            response += "\",\"isolation_status\":\"";
            response += readyStatusHandler ? "real" : "unavailable";
            const ResponseAuditState audit = ledger.State();
            response += "\"},\"audit\":{\"available\":";
            response += audit.available ? "true" : "false";
            response += ",\"pending\":";
            response += audit.pending ? "true" : "false";
            response += ",\"writable\":";
            response += audit.writable ? "true" : "false";
            response += "}}";
            Send(pipe, response); return;
        }
        if (request.kind == ResponseRequest::Kind::Quarantine) {
            if (!realQuarantine) {
                if (!ledger.AcceptDryRun(request, "quarantine", error)) {
                    QuarantineResult result;
                    result.effectiveMode = "dry_run";
                    result.requestId = request.requestId;
                    result.status = error == "requestId replay" ? "replay" : "audit_failed";
                    result.win32Error = ERROR_WRITE_FAULT;
                    Send(pipe, JsonQuarantineResponse(result));
                    return;
                }
                QuarantineResult result;
                result.effectiveMode = "dry_run";
                result.status = "accepted";
                result.requestId = request.requestId;
                result.auditWritten = true;
                Send(pipe, JsonQuarantineResponse(result));
                return;
            }
            QuarantineRequest action{request.requestId, request.timestamp,
                request.reason, request.path, request.sha256Hex};
            QuarantineResult result;
            {
                std::lock_guard<std::mutex> lock(executeMutex);
                result = quarantineExecutor->Execute(action);
            }
            Send(pipe, JsonQuarantineResponse(result));
            return;
        }
        if (request.kind == ResponseRequest::Kind::RestoreQuarantine) {
            if (!realQuarantine) {
                if (!ledger.AcceptDryRun(request, "restore_quarantine", error)) {
                    QuarantineRestoreResult result;
                    result.effectiveMode = "dry_run";
                    result.requestId = request.requestId;
                    result.sourceRequestId = request.sourceRequestId;
                    result.status = error == "requestId replay" ? "replay" :
                        "audit_failed";
                    result.win32Error = ERROR_WRITE_FAULT;
                    Send(pipe, JsonRestoreQuarantineResponse(result));
                    return;
                }
                QuarantineRestoreResult result;
                result.effectiveMode = "dry_run";
                result.requestId = request.requestId;
                result.sourceRequestId = request.sourceRequestId;
                result.status = "accepted";
                result.auditWritten = true;
                Send(pipe, JsonRestoreQuarantineResponse(result));
                return;
            }
            if (!quarantineExecutor) {
                QuarantineRestoreResult result;
                result.requestId = request.requestId;
                result.sourceRequestId = request.sourceRequestId;
                result.status = "unavailable";
                result.win32Error = ERROR_NOT_READY;
                Send(pipe, JsonRestoreQuarantineResponse(result));
                return;
            }
            QuarantineRestoreRequest action{request.requestId,
                request.timestamp, request.reason, request.sourceRequestId};
            QuarantineRestoreResult result;
            {
                std::lock_guard<std::mutex> lock(executeMutex);
                result = quarantineExecutor->Restore(action);
            }
            Send(pipe, JsonRestoreQuarantineResponse(result));
            return;
        }
        if (request.kind == ResponseRequest::Kind::IsolationStatus) {
            IsolationStatusHandler statusHandler;
            {
                std::lock_guard<std::mutex> lock(executeMutex);
                statusHandler = isolationStatusHandler;
            }
            if (!statusHandler) {
                ResponseIsolationResult result;
                result.success = false;
                result.status = "unavailable";
                result.requestId = request.requestId;
                result.error = "isolation status handler is not configured";
                Send(pipe, JsonIsolationResponse(result));
                return;
            }
            Send(pipe, JsonIsolationStatusResponse(statusHandler(), request.requestId));
            return;
        }
        if (request.kind == ResponseRequest::Kind::Isolation) {
            ResponseIsolationResult result;
            result.requestId = request.requestId;
            {
                std::lock_guard<std::mutex> lock(executeMutex);
                if (!ledger.AttemptIsolation(request, error)) {
                    result.success = false;
                    result.status = error == "requestId replay" ? "replay" : "audit_failed";
                    result.error = error;
                    Send(pipe, JsonIsolationResponse(result));
                    return;
                }
                if (!isolationHandler) {
                    result.success = false;
                    result.status = "unavailable";
                    result.error = "isolation handler is not configured";
                } else {
                    result = isolationHandler(
                        request.isolateEnable,
                        request.managementIp,
                        request.allowedPorts);
                    result.requestId = request.requestId;
                }
                std::string auditError;
                if (!ledger.OutcomeIsolation(request, result, auditError)) {
                    result.success = false;
                    result.status = "audit_failed";
                    result.error = auditError;
                }
            }
            Send(pipe, JsonIsolationResponse(result));
            return;
        }
        if (request.kind == ResponseRequest::Kind::Suspend) {
            if (!realSuspend) {
                if (!ledger.AcceptDryRun(request, "suspend", error)) {
                    ResponseActionResult result;
                    result.effectiveMode = "dry_run";
                    result.requestId = request.requestId;
                    result.status = error == "requestId replay" ? "replay" : "audit_failed";
                    result.win32Error = ERROR_WRITE_FAULT;
                    Send(pipe, JsonSuspendResponse(result));
                    return;
                }
                ResponseActionResult result;
                result.effectiveMode = "dry_run";
                result.status = "accepted";
                result.requestId = request.requestId;
                result.auditWritten = true;
                Send(pipe, JsonSuspendResponse(result));
                return;
            }
            uint64_t createTime = 0;
            if (!Decimal(request.createTime100ns, createTime, true)) {
                ResponseActionResult r; r.requestId=request.requestId; r.status="rejected"; r.effectiveMode="real"; r.win32Error=ERROR_INVALID_PARAMETER;
                Send(pipe, JsonSuspendResponse(r)); return;
            }
            ResponseActionRequest action{request.requestId, request.timestamp, request.reason, request.pid, createTime};
            ResponseActionResult result;
            {
                std::lock_guard<std::mutex> lock(executeMutex);
                result = executor->ExecuteSuspend(action);
            }
            Send(pipe, JsonSuspendResponse(result));
            return;
        }
        if (request.kind == ResponseRequest::Kind::Resume) {
            if (!realResume) {
                if (!ledger.AcceptDryRun(request, "resume", error)) {
                    ResponseActionResult result;
                    result.effectiveMode = "dry_run";
                    result.requestId = request.requestId;
                    result.status = error == "requestId replay" ? "replay" : "audit_failed";
                    result.win32Error = ERROR_WRITE_FAULT;
                    Send(pipe, JsonSuspendResponse(result));
                    return;
                }
                ResponseActionResult result;
                result.effectiveMode = "dry_run";
                result.status = "accepted";
                result.requestId = request.requestId;
                result.auditWritten = true;
                Send(pipe, JsonSuspendResponse(result));
                return;
            }
            uint64_t createTime = 0;
            if (!Decimal(request.createTime100ns, createTime, true)) {
                ResponseActionResult r; r.requestId=request.requestId; r.status="rejected"; r.effectiveMode="real"; r.win32Error=ERROR_INVALID_PARAMETER;
                Send(pipe, JsonSuspendResponse(r)); return;
            }
            ResponseActionRequest action{request.requestId, request.timestamp, request.reason, request.pid, createTime};
            ResponseActionResult result;
            {
                std::lock_guard<std::mutex> lock(executeMutex);
                result = executor->ExecuteResume(action);
            }
            Send(pipe, JsonSuspendResponse(result));
            return;
        }
        if (request.kind == ResponseRequest::Kind::DeleteFile) {
            if (!realDeleteFile) {
                if (!ledger.AcceptDryRun(request, "delete_file", error)) {
                    DeleteFileResult result;
                    result.effectiveMode = "dry_run";
                    result.requestId = request.requestId;
                    result.path = request.path;
                    result.status = error == "requestId replay" ? "replay" : "audit_failed";
                    result.win32Error = ERROR_WRITE_FAULT;
                    Send(pipe, JsonDeleteFileResponse(result));
                    return;
                }
                DeleteFileResult result;
                result.effectiveMode = "dry_run";
                result.status = "accepted";
                result.requestId = request.requestId;
                result.path = request.path;
                result.auditWritten = true;
                Send(pipe, JsonDeleteFileResponse(result));
                return;
            }
            DeleteFileRequest action{request.requestId, request.timestamp,
                request.reason, request.path, request.sha256Hex};
            DeleteFileResult result;
            {
                std::lock_guard<std::mutex> lock(executeMutex);
                result = executor->ExecuteDeleteFile(action);
            }
            Send(pipe, JsonDeleteFileResponse(result));
            return;
        }
        if (!realTermination) {
            if (!ledger.AcceptDryRun(request, error)) {
                Send(pipe, JsonResponse(false, "dry_run",
                    error == "requestId replay" ? "replay" : "audit_failed",
                    request.requestId));
                return;
            }
            Send(pipe, JsonResponse(true, "dry_run", "accepted", request.requestId));
            return;
        }
        uint64_t createTime = 0;
        if (!Decimal(request.createTime100ns, createTime, true)) {
            Send(pipe, JsonResponse(false, "real", "rejected", request.requestId));
            return;
        }
        ResponseActionRequest action{request.requestId, request.timestamp,
            request.reason, request.pid, createTime};
        action.maxTreeSize = request.maxTreeSize;
        action.suspendBeforeTerminate = request.suspendBeforeTerminate;
        action.maxTreeDepth = request.maxTreeDepth;
        action.isolateBeforeTerminate = request.isolateBeforeTerminate;
        action.parentImageWhitelist = request.parentImageWhitelist;
        ResponseActionResult result;
        {
            std::lock_guard<std::mutex> lock(executeMutex);
            result = executor->Execute(action);
        }
        bool ok = result.auditWritten &&
            (result.status == "terminated" || result.status == "termination_pending" ||
             result.status == "tree_terminated" || result.status == "partial_tree");
        Send(pipe, JsonResponse(ok, "real",
            result.auditWritten ? result.status : "audit_failed", result.requestId,
            result.terminationRequested, result.exitObserved, result.win32Error,
            result.childrenTerminated, result.childrenSkipped, result.childrenFailed,
            result.treeRequested, result.treePlanned, result.treeDescendants,
            result.treeDepth, result.treeSuspended, result.treeTruncated,
            result.snapshotAttempted, result.snapshotCaptured,
            result.evidencePath));
    }

    void Run() {
        while (!stopping.load()) {
            OVERLAPPED ov = {};
            ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ov.hEvent) break;
            BOOL connected = ConnectNamedPipe(pipe, &ov);
            DWORD error = connected ? ERROR_SUCCESS : GetLastError();
            if (connected || error == ERROR_PIPE_CONNECTED) SetEvent(ov.hEvent);
            else if (!connected && error != ERROR_IO_PENDING) { CloseHandle(ov.hEvent); break; }
            HANDLE waits[] = {ov.hEvent, stopEvent};
            DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0 && !stopping.load()) ServeConnection();
            else CancelIoEx(pipe, &ov);
            WaitForSingleObject(ov.hEvent, INFINITE);
            CloseHandle(ov.hEvent);
            DisconnectNamedPipe(pipe);
        }
    }
};

ResponseServer::ResponseServer() : impl_(new Impl) {}
ResponseServer::~ResponseServer() { Stop(); }

bool ResponseServer::ExecuteTerminate(const ResponseActionRequest& request,
                                      ResponseActionResult& result) {
    std::lock_guard<std::mutex> lock(impl_->executeMutex);
    if (!impl_->executor || !impl_->realTermination) {
        return false;
    }
    result = impl_->executor->Execute(request);
    return true;
}

bool ResponseServer::ExecuteDeleteFile(const DeleteFileRequest& request,
                                       DeleteFileResult& result) {
    std::lock_guard<std::mutex> lock(impl_->executeMutex);
    if (!impl_->executor || !impl_->realDeleteFile) {
        return false;
    }
    result = impl_->executor->ExecuteDeleteFile(request);
    return true;
}

bool ResponseServer::ExecuteSuspend(const ResponseActionRequest& request,
                                    ResponseActionResult& result) {
    std::lock_guard<std::mutex> lock(impl_->executeMutex);
    if (!impl_->executor || !impl_->realSuspend) return false;
    result = impl_->executor->ExecuteSuspend(request);
    return true;
}

bool ResponseServer::ExecuteResume(const ResponseActionRequest& request,
                                   ResponseActionResult& result) {
    std::lock_guard<std::mutex> lock(impl_->executeMutex);
    if (!impl_->executor || !impl_->realResume) return false;
    result = impl_->executor->ExecuteResume(request);
    return true;
}

void ResponseServer::SetIsolationHandler(IsolationHandler handler) {
    std::lock_guard<std::mutex> lock(impl_->executeMutex);
    impl_->isolationHandler = std::move(handler);
}

void ResponseServer::SetIsolationStatusHandler(IsolationStatusHandler handler) {
    std::lock_guard<std::mutex> lock(impl_->executeMutex);
    impl_->isolationStatusHandler = std::move(handler);
}

bool ResponseServer::Start(const std::string& pipeName,
                           const std::string& keyFile,
                           const std::string& auditPath,
                           bool enableProcessTermination, std::string& error,
                           bool enableQuarantine,
                           const std::string& quarantineDir,
                           uint64_t quarantineMaxFileBytes,
                           uint32_t maxTreeSize,
                           bool enableDeleteFile,
                           bool enableProcessSuspend,
                           bool enableProcessResume) {
    Stop();
    if (pipeName.rfind(R"(\\.\pipe\)", 0) != 0 || pipeName.size() > 240) {
        error = "response pipe name must be a bounded local pipe path"; return false;
    }
    if (!LoadResponseCommandKey(keyFile, impl_->key, error) ||
        !impl_->ledger.Open(auditPath, error)) return false;
    if (enableProcessTermination || enableDeleteFile || enableProcessSuspend || enableProcessResume) {
        std::wstring selfPath;
        DWORD identityError = ERROR_SUCCESS;
        if (!impl_->platform.Image(GetCurrentProcess(), selfPath, impl_->selfBase,
                                   identityError) ||
            !impl_->platform.FileIdentity(selfPath, impl_->selfIdentity,
                                          identityError)) {
            error = "capture response agent image identity failed: " +
                std::to_string(identityError);
            impl_->ledger.Close();
            return false;
        }
    }
    auto executor = std::make_unique<ResponseActionExecutor>(
        impl_->platform, impl_->ledger, impl_->emergency, 5000,
        (enableProcessTermination || enableDeleteFile || enableProcessSuspend || enableProcessResume) ? &impl_->selfIdentity
                                                        : nullptr,
        impl_->selfBase, maxTreeSize);
    std::unique_ptr<QuarantineExecutor> quarantineExecutor;
    if (enableQuarantine) {
        std::string directory = quarantineDir.empty()
            ? ExpandEnvStrings(R"(%ProgramData%\edr\quarantine)") : quarantineDir;
        DWORD quarantineError = ERROR_SUCCESS;
        if (!impl_->quarantinePlatform.EnsureQuarantineDir(directory,
                                                           quarantineError)) {
            error = "prepare quarantine directory failed: " +
                std::to_string(quarantineError);
            impl_->ledger.Close();
            return false;
        }
        quarantineExecutor = std::make_unique<QuarantineExecutor>(
            impl_->quarantinePlatform, impl_->ledger, impl_->emergency,
            directory, quarantineMaxFileBytes);
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
            &descriptor, nullptr)) {
        error = WinError("create response pipe DACL"); return false;
    }
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), descriptor, FALSE};
    std::wstring widePipe = Utf8ToWide(pipeName);
    impl_->pipe = CreateNamedPipeW(widePipe.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, kResponseMaxPayload + 36, kResponseMaxPayload + 36,
        kIoTimeoutMs, &attributes);
    LocalFree(descriptor);
    if (impl_->pipe == INVALID_HANDLE_VALUE) {
        error = WinError("create response pipe"); impl_->ledger.Close(); return false;
    }
    impl_->stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!impl_->stopEvent) {
        error = WinError("create response stop event"); Stop(); return false;
    }
    {
        std::lock_guard<std::mutex> lock(impl_->executeMutex);
        impl_->realTermination = enableProcessTermination;
        impl_->realQuarantine = enableQuarantine;
        impl_->realDeleteFile = enableDeleteFile;
        impl_->realSuspend = enableProcessSuspend;
        impl_->realResume = enableProcessResume;
        impl_->executor = std::move(executor);
        impl_->quarantineExecutor = std::move(quarantineExecutor);
    }
    impl_->stopping.store(false);
    try { impl_->worker = std::thread([this] { impl_->Run(); }); }
    catch (...) { error = "create response server thread failed"; Stop(); return false; }
    return true;
}

void ResponseServer::Stop() {
    impl_->stopping.store(true);
    if (impl_->stopEvent) SetEvent(impl_->stopEvent);
    if (impl_->pipe != INVALID_HANDLE_VALUE) CancelIoEx(impl_->pipe, nullptr);
    if (impl_->worker.joinable()) impl_->worker.join();
    if (impl_->pipe != INVALID_HANDLE_VALUE) CloseHandle(impl_->pipe);
    if (impl_->stopEvent) CloseHandle(impl_->stopEvent);
    impl_->pipe = INVALID_HANDLE_VALUE;
    impl_->stopEvent = nullptr;
    {
        std::lock_guard<std::mutex> lock(impl_->executeMutex);
        impl_->realTermination = false;
        impl_->realQuarantine = false;
        impl_->realDeleteFile = false;
        impl_->realSuspend = false;
        impl_->realResume = false;
        impl_->executor.reset();
        impl_->quarantineExecutor.reset();
        impl_->isolationHandler = nullptr;
        impl_->isolationStatusHandler = nullptr;
        impl_->ledger.Close();
    }
    SecureZeroMemory(impl_->key.data(), impl_->key.size());
    impl_->key.clear();
}

} // namespace edr
