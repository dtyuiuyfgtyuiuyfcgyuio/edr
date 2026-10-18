#include "quarantine_actions.h"

#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <wincrypt.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <initializer_list>
#include <vector>

#include "config.h"
#include "json_lite.h"

namespace edr {
namespace {

DWORD LastErrorOr(DWORD fallback) {
    DWORD error = GetLastError();
    return error == ERROR_SUCCESS ? fallback : error;
}

bool ValidRequestId(const std::string& value) {
    if (value.size() < 16 || value.size() > 64) return false;
    for (char c : value) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-')) return false;
    }
    return value.find('-') != std::string::npos;
}

bool Decimal(const std::string& value) {
    if (value.empty() || value.size() > 20 ||
        (value.size() > 1 && value[0] == '0')) return false;
    uint64_t parsed = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        unsigned digit = static_cast<unsigned>(c - '0');
        if (parsed > (UINT64_MAX - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    return parsed != 0;
}

bool ValidText(const std::string& value, size_t maximum) {
    if (value.empty() || value.size() > maximum) return false;
    for (unsigned char c : value)
        if (c < 0x20 || c == 0x7f) return false;
    return true;
}

bool AbsoluteDrivePath(const std::string& path) {
    if (path.size() < 3 || path.size() > 4096 ||
        !std::isalpha(static_cast<unsigned char>(path[0])) || path[1] != ':' ||
        path[2] != '\\') return false;
    size_t componentStart = 3;
    for (size_t i = 0; i < path.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(path[i]);
        if (c < 0x20 || c == 0x7f || (i > 1 && c == ':')) return false;
        if (i >= 3 && (path[i] == '\\' || path[i] == '/')) {
            if (i == componentStart || path[i - 1] == '.' || path[i - 1] == ' ')
                return false;
            componentStart = i + 1;
        }
    }
    if (componentStart == path.size() || path.back() == '.' || path.back() == ' ')
        return false;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(),
                             static_cast<int>(path.size()), nullptr, 0)) return false;
    std::wstring wide = Utf8ToWide(path);
    if (wide.empty()) return false;
    wchar_t full[32768];
    DWORD length = GetFullPathNameW(wide.c_str(), static_cast<DWORD>(std::size(full)),
                                    full, nullptr);
    return length > 0 && length < std::size(full);
}

std::string LowerHex(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool ValidHash(const std::string& value) {
    return value.empty() || (value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        }));
}

std::wstring CanonicalLower(const std::string& path) {
    std::wstring wide = Utf8ToWide(path);
    wchar_t full[32768];
    DWORD length = GetFullPathNameW(wide.c_str(), static_cast<DWORD>(std::size(full)),
                                    full, nullptr);
    if (!length || length >= std::size(full)) return {};
    std::wstring result(full, length);
    std::replace(result.begin(), result.end(), L'/', L'\\');
    while (result.size() > 3 && result.back() == L'\\') result.pop_back();
    std::transform(result.begin(), result.end(), result.begin(), towlower);
    return result;
}

bool ExactOrChild(const std::wstring& path, std::wstring prefix) {
    while (prefix.size() > 3 && prefix.back() == L'\\') prefix.pop_back();
    return path == prefix || (path.size() > prefix.size() &&
        path.compare(0, prefix.size(), prefix) == 0 && path[prefix.size()] == L'\\');
}

bool ProtectedPath(const std::string& path, const std::string& quarantineDir) {
    std::wstring normalized = CanonicalLower(path);
    if (normalized.empty()) return true;
    std::vector<std::string> roots = {quarantineDir};
    for (const char* name : {"SystemRoot", "ProgramFiles", "ProgramFiles(x86)",
                             "ProgramData", "CommonProgramFiles",
                             "CommonProgramFiles(x86)"}) {
        DWORD needed = GetEnvironmentVariableA(name, nullptr, 0);
        if (needed) {
            std::string value(needed, '\0');
            GetEnvironmentVariableA(name, value.data(), needed);
            value.resize(needed - 1);
            roots.push_back(value);
        }
    }
    for (const auto& root : roots) {
        std::wstring prefix = CanonicalLower(root);
        if (!prefix.empty() && ExactOrChild(normalized, prefix)) return true;
    }
    return false;
}

std::string Join(const std::string& directory, const std::string& name) {
    return directory + ((directory.back() == '\\' || directory.back() == '/') ? "" : "\\") + name;
}

constexpr size_t kMaxRestoreSidecarBytes = 512 * 1024;
constexpr size_t kMaxRestoreMetadataBytes = 256 * 1024;
constexpr size_t kMaxOriginalSecurityDescriptorBytes = 128 * 1024;

bool Base64Encode(const unsigned char* bytes, size_t size, std::string& output,
                  DWORD& error) {
    output.clear();
    if (!bytes || size == 0 || size > MAXDWORD) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    DWORD needed = 0;
    const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    if (!CryptBinaryToStringA(bytes, static_cast<DWORD>(size), flags, nullptr,
                              &needed) || needed == 0) {
        error = LastErrorOr(ERROR_INVALID_DATA);
        return false;
    }
    std::string encoded(needed, '\0');
    if (!CryptBinaryToStringA(bytes, static_cast<DWORD>(size), flags,
                              encoded.data(), &needed) || needed == 0) {
        error = LastErrorOr(ERROR_INVALID_DATA);
        return false;
    }
    if (needed > encoded.size()) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    size_t encodedLength = needed;
    if (encodedLength && encoded[encodedLength - 1] == '\0')
        --encodedLength;
    encoded.resize(encodedLength);
    output.swap(encoded);
    return true;
}

bool Base64Decode(const std::string& encoded, size_t maximumBytes,
                  std::vector<unsigned char>& output, DWORD& error) {
    output.clear();
    if (encoded.empty() || encoded.size() > maximumBytes * 2 ||
        encoded.size() % 4 != 0 ||
        std::any_of(encoded.begin(), encoded.end(), [](unsigned char c) {
            return !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=');
        })) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    DWORD needed = 0;
    if (!CryptStringToBinaryA(encoded.data(), static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64, nullptr, &needed, nullptr, nullptr) ||
        needed == 0 || needed > maximumBytes) {
        error = LastErrorOr(ERROR_INVALID_DATA);
        return false;
    }
    output.resize(needed);
    if (!CryptStringToBinaryA(encoded.data(), static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64, output.data(), &needed, nullptr, nullptr) ||
        needed == 0 || needed > maximumBytes) {
        output.clear();
        error = LastErrorOr(ERROR_INVALID_DATA);
        return false;
    }
    output.resize(needed);
    return true;
}

bool HashBytes(const std::string& bytes, std::string& output, DWORD& error) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0, returned = 0;
    std::vector<unsigned char> object;
    unsigned char digest[32] = {};
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm,
        BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &returned, 0);
    if (status >= 0) {
        object.resize(objectSize);
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectSize,
                                  nullptr, 0, 0);
    }
    size_t offset = 0;
    while (status >= 0 && offset < bytes.size()) {
        const DWORD amount = static_cast<DWORD>(std::min<size_t>(
            bytes.size() - offset, MAXDWORD));
        status = BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data() + offset)),
            amount, 0);
        offset += amount;
    }
    if (status >= 0) status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        error = ERROR_GEN_FAILURE;
        output.clear();
        return false;
    }
    static const char hex[] = "0123456789abcdef";
    output.resize(sizeof(digest) * 2);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 15];
    }
    return true;
}

std::string HexBytes(const unsigned char* bytes, size_t size) {
    static const char hex[] = "0123456789abcdef";
    std::string output(size * 2, '0');
    for (size_t i = 0; i < size; ++i) {
        output[i * 2] = hex[bytes[i] >> 4];
        output[i * 2 + 1] = hex[bytes[i] & 15];
    }
    return output;
}

bool ParseHexBytes(const std::string& value, unsigned char* output,
                   size_t size) {
    if (value.size() != size * 2) return false;
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < size; ++i) {
        const int high = digit(value[i * 2]);
        const int low = digit(value[i * 2 + 1]);
        if (high < 0 || low < 0) return false;
        output[i] = static_cast<unsigned char>((high << 4) | low);
    }
    return true;
}

bool ParseUint64(const std::string& value, uint64_t& parsed,
                 bool allowZero = false) {
    parsed = 0;
    if (value.empty() || value.size() > 20 ||
        (value.size() > 1 && value[0] == '0')) return false;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (parsed > (UINT64_MAX - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    return allowZero || parsed != 0;
}

bool ExactKeys(const jsonlite::Value& value,
               std::initializer_list<const char*> expected) {
    if (value.type != jsonlite::Type::Object ||
        value.object.size() != expected.size()) return false;
    for (const char* key : expected)
        if (value.object.find(key) == value.object.end()) return false;
    return true;
}

struct RestoreMetadata {
    std::string sourceRequestId;
    std::string originalPath;
    std::string quarantinePath;
    std::string sha256Hex;
    uint64_t fileSize = 0;
    uint64_t volumeSerial = 0;
    unsigned char fileId[16] = {};
    std::vector<unsigned char> originalSecurityDescriptor;
    bool originalDaclProtected = false;
};

std::string BuildRestoreMetadata(const QuarantineRequest& request,
        const std::string& originalPath, const std::string& quarantinePath,
        const std::string& sha256Hex, const QuarantineFileInfo& identity,
        const std::vector<unsigned char>& originalSecurityDescriptor,
        bool originalDaclProtected, DWORD& error) {
    std::string securityDescriptor;
    if (!Base64Encode(originalSecurityDescriptor.data(),
                      originalSecurityDescriptor.size(), securityDescriptor,
                      error)) return {};
    return std::string("{\"schema_version\":2,\"source_request_id\":\"") +
        jsonlite::escape(request.requestId) + "\",\"original_path\":\"" +
        jsonlite::escape(originalPath) + "\",\"quarantine_path\":\"" +
        jsonlite::escape(quarantinePath) + "\",\"sha256\":\"" +
        jsonlite::escape(sha256Hex) + "\",\"file_size\":\"" +
        std::to_string(identity.size) + "\",\"volume_serial\":\"" +
        std::to_string(identity.volumeSerial) + "\",\"file_id\":\"" +
        HexBytes(identity.fileId, sizeof(identity.fileId)) +
        "\",\"original_security_descriptor\":\"" +
        securityDescriptor + "\",\"original_dacl_protected\":" +
        (originalDaclProtected ? "true" : "false") + "}";
}

bool ParseRestoreMetadata(const std::string& clearText,
        const std::string& expectedSourceRequestId, RestoreMetadata& metadata,
        DWORD& error) {
    try {
        const jsonlite::Value root = jsonlite::parse(clearText);
        if (!ExactKeys(root, {"schema_version", "source_request_id",
                "original_path", "quarantine_path", "sha256", "file_size",
                "volume_serial", "file_id", "original_security_descriptor",
                "original_dacl_protected"})) {
            error = ERROR_INVALID_DATA;
            return false;
        }
        const auto* version = root.find("schema_version");
        const auto* sourceRequestId = root.find("source_request_id");
        const auto* originalPath = root.find("original_path");
        const auto* quarantinePath = root.find("quarantine_path");
        const auto* sha256 = root.find("sha256");
        const auto* fileSize = root.find("file_size");
        const auto* volumeSerial = root.find("volume_serial");
        const auto* fileId = root.find("file_id");
        const auto* descriptor = root.find("original_security_descriptor");
        const auto* daclProtected = root.find("original_dacl_protected");
        if (!version || version->type != jsonlite::Type::Number ||
            version->number != 2 || !sourceRequestId ||
            sourceRequestId->type != jsonlite::Type::String ||
            sourceRequestId->str != expectedSourceRequestId ||
            !originalPath || originalPath->type != jsonlite::Type::String ||
            !quarantinePath || quarantinePath->type != jsonlite::Type::String ||
            !sha256 || sha256->type != jsonlite::Type::String ||
            !fileSize || fileSize->type != jsonlite::Type::String ||
            !volumeSerial || volumeSerial->type != jsonlite::Type::String ||
            !fileId || fileId->type != jsonlite::Type::String ||
            !descriptor || descriptor->type != jsonlite::Type::String ||
            !daclProtected || daclProtected->type != jsonlite::Type::Bool ||
            !ValidHash(sha256->str) || sha256->str.empty() ||
            !ValidRequestId(sourceRequestId->str) ||
            !AbsoluteDrivePath(originalPath->str) ||
            !AbsoluteDrivePath(quarantinePath->str)) {
            error = ERROR_INVALID_DATA;
            return false;
        }
        uint64_t parsedSize = 0, parsedVolume = 0;
        if (!ParseUint64(fileSize->str, parsedSize, true) ||
            !ParseUint64(volumeSerial->str, parsedVolume) ||
            descriptor->str.empty()) {
            error = ERROR_INVALID_DATA;
            return false;
        }
        std::vector<unsigned char> securityDescriptor;
        if (!Base64Decode(descriptor->str,
                          kMaxOriginalSecurityDescriptorBytes,
                          securityDescriptor, error)) return false;
        metadata.sourceRequestId = sourceRequestId->str;
        metadata.originalPath = originalPath->str;
        metadata.quarantinePath = quarantinePath->str;
        metadata.sha256Hex = LowerHex(sha256->str);
        metadata.fileSize = parsedSize;
        metadata.volumeSerial = parsedVolume;
        if (!ParseHexBytes(fileId->str, metadata.fileId,
                           sizeof(metadata.fileId))) {
            error = ERROR_INVALID_DATA;
            return false;
        }
        metadata.originalSecurityDescriptor = std::move(securityDescriptor);
        metadata.originalDaclProtected = daclProtected->boolean;
        return true;
    } catch (...) {
        error = ERROR_INVALID_DATA;
        return false;
    }
}

bool DriveRootPath(const std::string& path) {
    if (path.size() != 3 || !std::isalpha(static_cast<unsigned char>(path[0])) ||
        path[1] != ':' || path[2] != '\\') return false;
    std::wstring wide = Utf8ToWide(path);
    wchar_t full[32768];
    DWORD length = GetFullPathNameW(wide.c_str(), static_cast<DWORD>(std::size(full)),
                                    full, nullptr);
    return length > 0 && length < std::size(full);
}

std::string ParentPath(const std::string& path) {
    size_t separator = path.find_last_of("\\/");
    if (separator == std::string::npos || separator < 2) return {};
    if (separator == 2) return path.substr(0, 3);
    return path.substr(0, separator);
}

std::string LeafName(const std::string& path) {
    size_t separator = path.find_last_of("\\/");
    if (separator == std::string::npos) return {};
    return path.substr(separator + 1);
}

bool ValidLeafName(const std::string& leaf) {
    if (leaf.empty() || leaf == "." || leaf == ".." || leaf.back() == '.' ||
        leaf.back() == ' ' || leaf.size() > 1024) return false;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, leaf.data(),
                             static_cast<int>(leaf.size()), nullptr, 0)) return false;
    for (unsigned char c : leaf)
        if (c < 0x20 || c == 0x7f || c == ':' || c == '/' || c == '\\' ||
            c == '<' || c == '>' || c == '"' || c == '|' || c == '?' || c == '*')
            return false;
    return true;
}

bool SameCanonicalPath(const std::string& left, const std::string& right) {
    const std::wstring a = CanonicalLower(left);
    const std::wstring b = CanonicalLower(right);
    return !a.empty() && !b.empty() && a == b;
}

bool RestrictedAclOnHandle(HANDLE file, DWORD& error) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD status = GetSecurityInfo(file, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
        &descriptor);
    if (status != ERROR_SUCCESS || !descriptor || !dacl) {
        if (descriptor) LocalFree(descriptor);
        error = status == ERROR_SUCCESS ? ERROR_INVALID_ACL : status;
        return false;
    }
    bool valid = dacl->AceCount == 2;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision) ||
        !(control & SE_DACL_PROTECTED)) valid = false;
    BYTE systemSid[SECURITY_MAX_SID_SIZE], adminSid[SECURITY_MAX_SID_SIZE];
    DWORD systemSize = sizeof(systemSid), adminSize = sizeof(adminSid);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSize) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid,
                            &adminSize)) valid = false;
    bool systemFound = false, adminFound = false;
    for (DWORD i = 0; valid && i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) { valid = false; break; }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        DWORD mask = ace->Mask;
        GENERIC_MAPPING fileMapping = {
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
            FILE_ALL_ACCESS
        };
        MapGenericMask(&mask, &fileMapping);
        PSID sid = &ace->SidStart;
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            mask != FILE_ALL_ACCESS) { valid = false; break; }
        if (EqualSid(sid, systemSid)) systemFound = true;
        else if (EqualSid(sid, adminSid)) adminFound = true;
        else valid = false;
    }
    LocalFree(descriptor);
    if (!valid || !systemFound || !adminFound) {
        error = ERROR_ACCESS_DENIED;
        return false;
    }
    return true;
}

QuarantineResult Reject(const QuarantineRequest& request, const char* status,
                        DWORD error = ERROR_ACCESS_DENIED) {
    QuarantineResult result;
    result.requestId = request.requestId;
    result.status = status;
    result.win32Error = error;
    return result;
}

void Emergency(IResponseEmergencySink& sink, const QuarantineResult& result,
               const std::string& detail) {
    ResponseActionResult compatible;
    compatible.requestId = result.requestId;
    compatible.status = result.status;
    compatible.win32Error = result.win32Error;
    compatible.auditWritten = false;
    sink.AuditFailure(compatible, detail);
}

QuarantineRestoreResult RejectRestore(const QuarantineRestoreRequest& request,
        const char* status, DWORD error = ERROR_ACCESS_DENIED) {
    QuarantineRestoreResult result;
    result.requestId = request.requestId;
    result.sourceRequestId = request.sourceRequestId;
    result.status = status;
    result.win32Error = error;
    return result;
}

void Emergency(IResponseEmergencySink& sink,
               const QuarantineRestoreResult& result,
               const std::string& detail) {
    ResponseActionResult compatible;
    compatible.requestId = result.requestId;
    compatible.status = result.status;
    compatible.win32Error = result.win32Error;
    compatible.auditWritten = false;
    sink.AuditFailure(compatible, detail);
}

bool SetRestrictedAcl(const std::wstring& path, DWORD& error) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)", SDDL_REVISION_1,
            &descriptor, nullptr)) {
        error = LastErrorOr(ERROR_INVALID_SECURITY_DESCR); return false;
    }
    BOOL ok = SetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION |
        PROTECTED_DACL_SECURITY_INFORMATION, descriptor);
    if (!ok) error = LastErrorOr(ERROR_ACCESS_DENIED);
    LocalFree(descriptor);
    if (!ok) return false;

    PSECURITY_DESCRIPTOR actual = nullptr;
    PACL dacl = nullptr;
    DWORD status = GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()),
        SE_FILE_OBJECT, DACL_SECURITY_INFORMATION |
        PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
        &actual);
    if (status != ERROR_SUCCESS) { error = status; return false; }
    bool valid = dacl && dacl->AceCount == 2;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(actual, &control, &revision) ||
        !(control & SE_DACL_PROTECTED)) valid = false;
    BYTE systemSid[SECURITY_MAX_SID_SIZE], adminSid[SECURITY_MAX_SID_SIZE];
    DWORD systemSize = sizeof(systemSid), adminSize = sizeof(adminSid);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSize) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &adminSize))
        valid = false;
    bool systemFound = false, adminFound = false;
    for (DWORD i = 0; valid && i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) { valid = false; break; }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        PSID sid = &ace->SidStart;
        DWORD mask = ace->Mask;
        GENERIC_MAPPING fileMapping = {
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
            FILE_ALL_ACCESS
        };
        MapGenericMask(&mask, &fileMapping);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            mask != FILE_ALL_ACCESS) { valid = false; break; }
        if (EqualSid(sid, systemSid)) systemFound = true;
        else if (EqualSid(sid, adminSid)) adminFound = true;
        else valid = false;
    }
    LocalFree(actual);
    if (!valid || !systemFound || !adminFound) {
        error = ERROR_INVALID_ACL; return false;
    }
    return true;
}

bool RestrictedDescriptor(PSECURITY_DESCRIPTOR& descriptor, DWORD& error) {
    descriptor = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)", SDDL_REVISION_1,
            &descriptor, nullptr)) return true;
    error = LastErrorOr(ERROR_INVALID_SECURITY_DESCR);
    return false;
}

bool HasReparseComponent(const std::string& path, DWORD& error) {
    std::wstring full = CanonicalLower(path);
    if (full.empty()) { error = ERROR_BAD_PATHNAME; return true; }
    for (size_t slash = full.find(L'\\', 3);; slash = full.find(L'\\', slash + 1)) {
        std::wstring component = slash == std::wstring::npos ? full : full.substr(0, slash);
        DWORD attributes = GetFileAttributesW(component.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            error = LastErrorOr(ERROR_PATH_NOT_FOUND); return true;
        }
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            error = ERROR_REPARSE_TAG_INVALID; return true;
        }
        if (slash == std::wstring::npos) break;
    }
    return false;
}

} // namespace

bool NativeQuarantinePlatform::OpenFile(const std::string& path, HANDLE& file,
                                        DWORD& error) {
    if (HasReparseComponent(path, error)) {
        file = INVALID_HANDLE_VALUE;
        return false;
    }
    std::wstring wide = Utf8ToWide(path);
    file = CreateFileW(wide.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES | DELETE |
        READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_FILE_NOT_FOUND); return false;
    }
    return true;
}

void NativeQuarantinePlatform::CloseHandleSafe(HANDLE file) {
    if (file && file != INVALID_HANDLE_VALUE) CloseHandle(file);
}

bool NativeQuarantinePlatform::FileInfo(HANDLE file, QuarantineFileInfo& info,
                                        DWORD& error) {
    BY_HANDLE_FILE_INFORMATION basic = {};
    FILE_ID_INFO identity = {};
    LARGE_INTEGER size = {};
    if (!GetFileInformationByHandle(file, &basic) || !GetFileSizeEx(file, &size) ||
        !GetFileInformationByHandleEx(file, FileIdInfo, &identity, sizeof(identity))) {
        error = LastErrorOr(ERROR_NOT_SUPPORTED); return false;
    }
    info.attributes = basic.dwFileAttributes;
    info.size = static_cast<uint64_t>(size.QuadPart);
    info.volumeSerial = identity.VolumeSerialNumber;
    info.numberOfLinks = basic.nNumberOfLinks;
    memcpy(info.fileId, identity.FileId.Identifier, sizeof(info.fileId));
    return true;
}

bool NativeQuarantinePlatform::FinalPath(HANDLE file, std::string& path,
                                         DWORD& error) {
    DWORD needed = GetFinalPathNameByHandleW(file, nullptr, 0,
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!needed) { error = LastErrorOr(ERROR_BAD_PATHNAME); return false; }
    std::wstring resolved(needed, L'\0');
    DWORD length = GetFinalPathNameByHandleW(file, resolved.data(), needed,
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!length || length >= needed) {
        error = LastErrorOr(ERROR_BAD_PATHNAME); return false;
    }
    resolved.resize(length);
    if (resolved.rfind(L"\\\\?\\", 0) != 0 || resolved.size() < 7 ||
        !iswalpha(resolved[4]) || resolved[5] != L':' || resolved[6] != L'\\') {
        error = ERROR_BAD_PATHNAME; return false;
    }
    resolved.erase(0, 4);
    DWORD longNeeded = GetLongPathNameW(resolved.c_str(), nullptr, 0);
    if (!longNeeded) { error = LastErrorOr(ERROR_BAD_PATHNAME); return false; }
    std::wstring longPath(longNeeded, L'\0');
    DWORD longLength = GetLongPathNameW(resolved.c_str(), longPath.data(), longNeeded);
    if (!longLength || longLength >= longNeeded) {
        error = LastErrorOr(ERROR_BAD_PATHNAME); return false;
    }
    longPath.resize(longLength);
    path = WideToUtf8(longPath.c_str());
    if (path.empty()) { error = ERROR_NO_UNICODE_TRANSLATION; return false; }
    return true;
}

bool NativeQuarantinePlatform::DirectoryInfo(const std::string& path,
        QuarantineFileInfo& info, DWORD& error) {
    HANDLE directory = CreateFileW(Utf8ToWide(path).c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (directory == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_PATH_NOT_FOUND); return false;
    }
    BY_HANDLE_FILE_INFORMATION basic = {};
    FILE_ID_INFO identity = {};
    bool ok = GetFileInformationByHandle(directory, &basic) &&
        GetFileInformationByHandleEx(directory, FileIdInfo, &identity,
                                     sizeof(identity));
    if (ok) {
        info.attributes = basic.dwFileAttributes;
        info.volumeSerial = identity.VolumeSerialNumber;
        info.numberOfLinks = basic.nNumberOfLinks;
        memcpy(info.fileId, identity.FileId.Identifier, sizeof(info.fileId));
    } else {
        error = LastErrorOr(ERROR_NOT_SUPPORTED);
    }
    CloseHandle(directory);
    return ok;
}

bool NativeQuarantinePlatform::Hash(HANDLE file, std::string& output,
                                    DWORD& error) {
    LARGE_INTEGER zero = {};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) {
        error = LastErrorOr(ERROR_SEEK); return false;
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0, returned = 0;
    std::vector<unsigned char> object, buffer(64 * 1024);
    unsigned char digest[32];
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm,
        BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &returned, 0);
    if (status >= 0) {
        object.resize(objectSize);
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectSize,
                                  nullptr, 0, 0);
    }
    while (status >= 0) {
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()),
                      &read, nullptr)) {
            error = LastErrorOr(ERROR_READ_FAULT); status = -1; break;
        }
        if (!read) break;
        status = BCryptHashData(hash, buffer.data(), read, 0);
    }
    if (status >= 0) status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        if (error == ERROR_SUCCESS) error = ERROR_GEN_FAILURE;
        return false;
    }
    static const char hex[] = "0123456789abcdef";
    output.resize(64);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 15];
    }
    return true;
}

bool NativeQuarantinePlatform::EnsureQuarantineDir(const std::string& path,
                                                   DWORD& error) {
    if (!AbsoluteDrivePath(path) || GetDriveTypeW(Utf8ToWide(path.substr(0, 3)).c_str()) != DRIVE_FIXED) {
        error = ERROR_BAD_PATHNAME; return false;
    }
    std::wstring full = CanonicalLower(path);
    if (full.empty()) { error = ERROR_BAD_PATHNAME; return false; }
    for (size_t slash = full.find(L'\\', 3);; slash = full.find(L'\\', slash + 1)) {
        std::wstring component = slash == std::wstring::npos ? full : full.substr(0, slash);
        DWORD attributes = GetFileAttributesW(component.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            if (!CreateDirectoryW(component.c_str(), nullptr) &&
                GetLastError() != ERROR_ALREADY_EXISTS) {
                error = LastErrorOr(ERROR_CANNOT_MAKE); return false;
            }
            attributes = GetFileAttributesW(component.c_str());
        }
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            error = ERROR_REPARSE_TAG_INVALID; return false;
        }
        if (slash == std::wstring::npos) break;
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!RestrictedDescriptor(descriptor, error)) return false;
    BOOL secured = SetFileSecurityW(full.c_str(), DACL_SECURITY_INFORMATION |
        PROTECTED_DACL_SECURITY_INFORMATION, descriptor);
    LocalFree(descriptor);
    if (!secured) { error = LastErrorOr(ERROR_ACCESS_DENIED); return false; }
    return SetRestrictedAcl(full, error);
}

bool NativeQuarantinePlatform::ProtectAcl(HANDLE file,
        std::vector<unsigned char>& original, bool& originalProtected,
        DWORD& error) {
    PSECURITY_DESCRIPTOR current = nullptr;
    PACL ignoredDacl = nullptr;
    DWORD status = GetSecurityInfo(file, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &ignoredDacl, nullptr,
        &current);
    if (status != ERROR_SUCCESS || !current) {
        error = status == ERROR_SUCCESS ? ERROR_INVALID_SECURITY_DESCR : status;
        return false;
    }
    DWORD needed = GetSecurityDescriptorLength(current);
    original.assign(reinterpret_cast<unsigned char*>(current),
                    reinterpret_cast<unsigned char*>(current) + needed);
    LocalFree(current);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(
            reinterpret_cast<PSECURITY_DESCRIPTOR>(original.data()), &control,
            &revision)) {
        error = LastErrorOr(ERROR_INVALID_SECURITY_DESCR); return false;
    }
    originalProtected = (control & SE_DACL_PROTECTED) != 0;
    if (!ValidateOriginalDacl(original, originalProtected, error))
        return false;
    PSECURITY_DESCRIPTOR restricted = nullptr;
    if (!RestrictedDescriptor(restricted, error)) return false;
    BOOL daclPresent = FALSE, daclDefaulted = FALSE;
    PACL restrictedDacl = nullptr;
    if (!GetSecurityDescriptorDacl(restricted, &daclPresent, &restrictedDacl,
                                   &daclDefaulted) || !daclPresent ||
        !restrictedDacl) {
        LocalFree(restricted); error = ERROR_INVALID_ACL; return false;
    }
    status = SetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION |
        PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, restrictedDacl,
        nullptr);
    LocalFree(restricted);
    if (status != ERROR_SUCCESS) { error = status; return false; }
    return true;
}

bool NativeQuarantinePlatform::RestoreAcl(HANDLE file,
        const std::vector<unsigned char>& original, bool originalProtected,
        DWORD& error) {
    if (!ValidateOriginalDacl(original, originalProtected, error)) return false;
    BOOL daclPresent = FALSE, daclDefaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(
            reinterpret_cast<PSECURITY_DESCRIPTOR>(
                const_cast<unsigned char*>(original.data())), &daclPresent,
            &dacl, &daclDefaulted) || !daclPresent || !dacl) {
        error = ERROR_INVALID_ACL; return false;
    }
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION |
        (originalProtected ? PROTECTED_DACL_SECURITY_INFORMATION
                           : UNPROTECTED_DACL_SECURITY_INFORMATION);
    DWORD status = SetSecurityInfo(file, SE_FILE_OBJECT, information, nullptr,
                                   nullptr, dacl, nullptr);
    if (status != ERROR_SUCCESS) { error = status; return false; }
    return true;
}

bool NativeQuarantinePlatform::Rename(HANDLE file,
        const std::string& destination, DWORD& error) {
    std::wstring target = Utf8ToWide(destination);
    if (target.empty() || target.size() >
            (MAXDWORD - sizeof(FILE_RENAME_INFO)) / sizeof(wchar_t)) {
        error = ERROR_INVALID_PARAMETER; return false;
    }
    DWORD nameBytes = static_cast<DWORD>(target.size() * sizeof(wchar_t));
    DWORD bytes = static_cast<DWORD>(sizeof(FILE_RENAME_INFO) + nameBytes);
    std::vector<unsigned char> storage(bytes, 0);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
    rename->ReplaceIfExists = FALSE;
    rename->RootDirectory = nullptr;
    rename->FileNameLength = nameBytes;
    memcpy(rename->FileName, target.data(), nameBytes);
    if (!SetFileInformationByHandle(file, FileRenameInfo, rename, bytes)) {
        error = LastErrorOr(ERROR_WRITE_FAULT); return false;
    }
    return true;
}

bool NativeQuarantinePlatform::WriteFileAtomic(const std::string& path,
        const std::string& bytes, DWORD& error) {
    std::string temporary = path + ".tmp-" + std::to_string(GetCurrentProcessId()) +
        "-" + std::to_string(GetCurrentThreadId());
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!RestrictedDescriptor(descriptor, error)) return false;
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    HANDLE file = CreateFileW(Utf8ToWide(temporary).c_str(), GENERIC_WRITE, 0,
        &security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    LocalFree(descriptor);
    if (file == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_FILE_EXISTS); return false;
    }
    DWORD written = 0;
    bool ok = bytes.size() <= MAXDWORD && WriteFile(file, bytes.data(),
        static_cast<DWORD>(bytes.size()), &written, nullptr) &&
        written == bytes.size() && FlushFileBuffers(file);
    if (!ok) error = LastErrorOr(ERROR_WRITE_FAULT);
    CloseHandle(file);
    if (ok && !MoveFileExW(Utf8ToWide(temporary).c_str(), Utf8ToWide(path).c_str(),
            MOVEFILE_WRITE_THROUGH)) {
        error = LastErrorOr(ERROR_WRITE_FAULT); ok = false;
    }
    if (!ok) DeleteFileW(Utf8ToWide(temporary).c_str());
    return ok;
}

bool NativeQuarantinePlatform::ReadFileBounded(const std::string& path,
        size_t maximumBytes, std::string& bytes, DWORD& error) {
    bytes.clear();
    if (!AbsoluteDrivePath(path) || HasReparseComponent(path, error)) {
        if (error == ERROR_SUCCESS) error = ERROR_BAD_PATHNAME;
        return false;
    }
    const std::wstring wide = Utf8ToWide(path);
    HANDLE file = CreateFileW(wide.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES |
        READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_FILE_NOT_FOUND);
        return false;
    }
    struct HandleGuard {
        HANDLE value;
        ~HandleGuard() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    } guard{file};

    QuarantineFileInfo info;
    std::string finalPath;
    if (!FileInfo(file, info, error) || !FinalPath(file, finalPath, error))
        return false;
    if ((info.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        info.numberOfLinks != 1 || info.size == 0 || info.size > maximumBytes ||
        !SameCanonicalPath(path, finalPath)) {
        error = info.size > maximumBytes ? ERROR_FILE_TOO_LARGE : ERROR_INVALID_DATA;
        return false;
    }
    if (!RestrictedAclOnHandle(file, error)) return false;
    LARGE_INTEGER zero = {};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) {
        error = LastErrorOr(ERROR_SEEK);
        return false;
    }
    bytes.resize(static_cast<size_t>(info.size));
    size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD requested = static_cast<DWORD>(std::min<size_t>(
            bytes.size() - offset, MAXDWORD));
        DWORD read = 0;
        if (!ReadFile(file, bytes.data() + offset, requested, &read, nullptr) ||
            read == 0 || read > requested) {
            bytes.clear();
            error = LastErrorOr(ERROR_READ_FAULT);
            return false;
        }
        offset += read;
    }
    return true;
}

bool NativeQuarantinePlatform::ProtectMetadata(const std::string& clearText,
        std::string& protectedText, DWORD& error) {
    protectedText.clear();
    if (clearText.empty() || clearText.size() > kMaxRestoreMetadataBytes ||
        clearText.size() > MAXDWORD) {
        error = ERROR_INVALID_DATA;
        return false;
    }
    DATA_BLOB input = {
        static_cast<DWORD>(clearText.size()),
        reinterpret_cast<BYTE*>(const_cast<char*>(clearText.data()))
    };
    DATA_BLOB output = {};
    if (!CryptProtectData(&input, L"EDR quarantine restore metadata v2",
            nullptr, nullptr, nullptr,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &output)) {
        error = LastErrorOr(ERROR_INVALID_DATA);
        return false;
    }
    bool ok = Base64Encode(output.pbData, output.cbData, protectedText, error);
    if (output.pbData) LocalFree(output.pbData);
    return ok;
}

bool NativeQuarantinePlatform::UnprotectMetadata(const std::string& protectedText,
        std::string& clearText, DWORD& error) {
    clearText.clear();
    std::vector<unsigned char> decoded;
    if (!Base64Decode(protectedText, kMaxRestoreMetadataBytes * 2,
                      decoded, error)) return false;
    DATA_BLOB input = {static_cast<DWORD>(decoded.size()), decoded.data()};
    DATA_BLOB output = {};
    LPWSTR description = nullptr;
    if (!CryptUnprotectData(&input, &description, nullptr, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        error = LastErrorOr(ERROR_INVALID_DATA);
        if (description) LocalFree(description);
        return false;
    }
    if (description) LocalFree(description);
    if (!output.pbData || output.cbData == 0 ||
        output.cbData > kMaxRestoreMetadataBytes ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            reinterpret_cast<const char*>(output.pbData),
            static_cast<int>(output.cbData), nullptr, 0)) {
        if (output.pbData) LocalFree(output.pbData);
        error = ERROR_INVALID_DATA;
        return false;
    }
    clearText.assign(reinterpret_cast<const char*>(output.pbData),
                      output.cbData);
    LocalFree(output.pbData);
    return true;
}

bool NativeQuarantinePlatform::ValidateOriginalDacl(
        const std::vector<unsigned char>& descriptorBytes,
        bool originalProtected, DWORD& error) {
    if (descriptorBytes.empty() ||
        descriptorBytes.size() > kMaxOriginalSecurityDescriptorBytes ||
        descriptorBytes.size() > MAXDWORD) {
        error = ERROR_INVALID_SECURITY_DESCR;
        return false;
    }
    struct RelativeSecurityDescriptorHeader {
        BYTE revision;
        BYTE sbz1;
        SECURITY_DESCRIPTOR_CONTROL control;
        DWORD ownerOffset;
        DWORD groupOffset;
        DWORD saclOffset;
        DWORD daclOffset;
    };
    static_assert(sizeof(RelativeSecurityDescriptorHeader) == 20,
                  "self-relative security descriptor header size changed");
    if (descriptorBytes.size() < sizeof(RelativeSecurityDescriptorHeader)) {
        error = ERROR_INVALID_SECURITY_DESCR;
        return false;
    }
    RelativeSecurityDescriptorHeader header = {};
    memcpy(&header, descriptorBytes.data(), sizeof(header));
    if (header.revision != SECURITY_DESCRIPTOR_REVISION ||
        !(header.control & SE_SELF_RELATIVE) ||
        !(header.control & SE_DACL_PRESENT) || header.daclOffset == 0 ||
        header.daclOffset > descriptorBytes.size() - sizeof(ACL) ||
        static_cast<bool>(header.control & SE_DACL_PROTECTED) !=
            originalProtected) {
        error = ERROR_INVALID_SECURITY_DESCR;
        return false;
    }
    const size_t remaining = descriptorBytes.size() - header.daclOffset;
    auto* dacl = reinterpret_cast<PACL>(
        const_cast<unsigned char*>(descriptorBytes.data() + header.daclOffset));
    if (dacl->AclSize < sizeof(ACL) || dacl->AclSize > remaining ||
        !IsValidAcl(dacl)) {
        error = ERROR_INVALID_ACL;
        return false;
    }
    return true;
}

bool NativeQuarantinePlatform::OpenDirectoryNoFollow(const std::string& path,
        HANDLE& directory, QuarantineFileInfo& info, std::string& finalPath,
        DWORD& error) {
    directory = INVALID_HANDLE_VALUE;
    finalPath.clear();
    if ((!AbsoluteDrivePath(path) && !DriveRootPath(path)) ||
        HasReparseComponent(path, error)) {
        if (error == ERROR_SUCCESS) error = ERROR_BAD_PATHNAME;
        return false;
    }
    directory = CreateFileW(Utf8ToWide(path).c_str(),
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (directory == INVALID_HANDLE_VALUE) {
        error = LastErrorOr(ERROR_PATH_NOT_FOUND);
        return false;
    }
    if (!FileInfo(directory, info, error) ||
        !FinalPath(directory, finalPath, error)) {
        CloseHandle(directory);
        directory = INVALID_HANDLE_VALUE;
        return false;
    }
    if (!(info.attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        !SameCanonicalPath(path, finalPath)) {
        CloseHandle(directory);
        directory = INVALID_HANDLE_VALUE;
        error = ERROR_REPARSE_TAG_INVALID;
        return false;
    }
    return true;
}

bool NativeQuarantinePlatform::RenameNoReplaceInDirectory(HANDLE file,
        HANDLE directory, const std::string& leaf, DWORD& error) {
    if (!ValidLeafName(leaf)) {
        error = ERROR_INVALID_NAME;
        return false;
    }
    const std::wstring target = Utf8ToWide(leaf);
    if (target.empty() || target.size() >
            (MAXDWORD - sizeof(FILE_RENAME_INFO)) / sizeof(wchar_t)) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    const DWORD nameBytes = static_cast<DWORD>(target.size() * sizeof(wchar_t));
    /* Supply the fixed structure plus the exact UTF-16 name bytes. The
     * FileNameLength field itself excludes any terminating NUL. */
    const DWORD bytes = static_cast<DWORD>(sizeof(FILE_RENAME_INFO) + nameBytes);
    std::vector<unsigned char> storage(bytes, 0);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
    rename->ReplaceIfExists = FALSE;
    rename->RootDirectory = directory;
    rename->FileNameLength = nameBytes;
    memcpy(rename->FileName, target.data(), nameBytes);

    /* SetFileInformationByHandle's Win32 wrapper rejects a non-null
     * RootDirectory for FileRenameInfo on supported Windows builds, even
     * though FILE_RENAME_INFO documents the relative-name form. Calling the
     * documented Nt entry point preserves the already-verified directory
     * handle as the rename root instead of resolving an absolute path again. */
    using NtSetInformationFileFn = LONG (NTAPI*)(HANDLE, void*, void*, ULONG,
                                                  ULONG);
    using RtlNtStatusToDosErrorFn = ULONG (NTAPI*)(LONG);
    struct NativeIoStatusBlock {
        union {
            LONG status;
            void* pointer;
        } value;
        ULONG_PTR information;
    } ioStatus = {};
    static_assert(offsetof(NativeIoStatusBlock, information) == sizeof(void*),
                  "IO_STATUS_BLOCK layout mismatch");
    constexpr ULONG kFileRenameInformationClass = 10;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        error = LastErrorOr(ERROR_MOD_NOT_FOUND);
        return false;
    }
    auto setInformation = reinterpret_cast<NtSetInformationFileFn>(
        GetProcAddress(ntdll, "NtSetInformationFile"));
    if (!setInformation) {
        error = LastErrorOr(ERROR_PROC_NOT_FOUND);
        return false;
    }
    const LONG callStatus = setInformation(file, &ioStatus, rename, bytes,
                                           kFileRenameInformationClass);
    constexpr LONG kStatusPending = 0x00000103L;
    /* OpenFile creates synchronous handles. A pending result here would make
     * the rename outcome uncertain, so never turn it into a success based on
     * NT_SUCCESS's nonnegative-status rule. */
    if (callStatus == kStatusPending) {
        error = ERROR_IO_PENDING;
        return false;
    }
    if (callStatus >= 0 && ioStatus.value.status >= 0) return true;

    const LONG failureStatus = callStatus < 0 ? callStatus : ioStatus.value.status;
    auto statusToError = reinterpret_cast<RtlNtStatusToDosErrorFn>(
        GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    if (!statusToError) {
        error = ERROR_PROC_NOT_FOUND;
        return false;
    }
    const DWORD mappedError = static_cast<DWORD>(statusToError(failureStatus));
    error = mappedError == ERROR_SUCCESS ||
            mappedError == ERROR_MR_MID_NOT_FOUND
        ? ERROR_GEN_FAILURE : mappedError;
    return false;
}

QuarantineExecutor::QuarantineExecutor(IQuarantinePlatform& platform,
        IQuarantineAudit& audit, IResponseEmergencySink& emergency,
        const std::string& quarantineDir, uint64_t maxFileBytes)
    : platform_(platform), audit_(audit), emergency_(emergency),
      quarantineDir_(quarantineDir), maxFileBytes_(maxFileBytes) {}

QuarantineResult QuarantineExecutor::Execute(const QuarantineRequest& request) {
    if (!ValidRequestId(request.requestId) || !Decimal(request.timestamp) ||
        !ValidText(request.reason, 1024) || !AbsoluteDrivePath(request.path) ||
        !ValidHash(request.sha256Hex) || !AbsoluteDrivePath(quarantineDir_))
        return Reject(request, "policy_rejected", ERROR_INVALID_PARAMETER);

    DWORD error = ERROR_SUCCESS;
    if (!platform_.EnsureQuarantineDir(quarantineDir_, error))
        return Reject(request, "quarantine_setup_failed", error);
    HANDLE file = INVALID_HANDLE_VALUE;
    if (!platform_.OpenFile(request.path, file, error))
        return Reject(request, "open_failed", error);
    struct Guard {
        IQuarantinePlatform& platform; HANDLE& file;
        ~Guard() { platform.CloseHandleSafe(file); }
    } guard{platform_, file};
    QuarantineFileInfo source, directory;
    if (!platform_.FileInfo(file, source, error))
        return Reject(request, "identity_check_failed", error);
    if (source.attributes & FILE_ATTRIBUTE_DIRECTORY)
        return Reject(request, "policy_rejected", ERROR_DIRECTORY);
    if (source.attributes & FILE_ATTRIBUTE_REPARSE_POINT)
        return Reject(request, "policy_rejected", ERROR_REPARSE_TAG_INVALID);
    if (source.numberOfLinks > 1)
        return Reject(request, "policy_rejected", ERROR_TOO_MANY_LINKS);
    if (source.size > maxFileBytes_)
        return Reject(request, "file_too_large", ERROR_FILE_TOO_LARGE);
    std::string finalPath;
    if (!platform_.FinalPath(file, finalPath, error))
        return Reject(request, "path_resolution_failed", error);
    if (!AbsoluteDrivePath(finalPath) || ProtectedPath(finalPath, quarantineDir_))
        return Reject(request, "policy_rejected", ERROR_ACCESS_DENIED);
    if (!platform_.DirectoryInfo(quarantineDir_, directory, error))
        return Reject(request, "quarantine_setup_failed", error);
    if (!(directory.attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (directory.attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        source.volumeSerial != directory.volumeSerial)
        return Reject(request, "cross_volume", ERROR_NOT_SAME_DEVICE);
    std::string hash;
    if (!platform_.Hash(file, hash, error)) return Reject(request, "hash_failed", error);
    hash = LowerHex(hash);
    if (!request.sha256Hex.empty() && LowerHex(request.sha256Hex) != hash) {
        QuarantineResult result = Reject(request, "hash_mismatch", ERROR_CRC);
        result.sha256Hex = hash;
        return result;
    }

    std::string auditError;
    if (!audit_.AttemptQuarantine(request, hash, auditError))
        return Reject(request, auditError == "requestId replay" ? "replay" : "audit_failed",
                      ERROR_WRITE_FAULT);
    QuarantineResult result;
    result.requestId = request.requestId;
    result.sha256Hex = hash;
    result.quarantinePath = Join(quarantineDir_, hash + ".quarantined");
    std::vector<unsigned char> originalSecurity;
    bool originalProtected = false;
    QuarantineFileInfo retained;
    if (!platform_.FileInfo(file, retained, error)) {
        result.status = "identity_check_failed";
        result.win32Error = error;
        result.quarantinePath.clear();
    } else if (retained.volumeSerial != source.volumeSerial ||
               memcmp(retained.fileId, source.fileId, sizeof(source.fileId)) != 0) {
        result.status = "identity_changed";
        result.win32Error = ERROR_FILE_INVALID;
        result.quarantinePath.clear();
    } else if (retained.numberOfLinks != 1) {
        result.status = "policy_rejected";
        result.win32Error = ERROR_TOO_MANY_LINKS;
        result.quarantinePath.clear();
    } else if (!platform_.ProtectAcl(file, originalSecurity, originalProtected, error)) {
        result.status = "acl_failed";
        result.win32Error = error;
    } else if (!platform_.Rename(file, result.quarantinePath, error)) {
        DWORD restoreError = ERROR_SUCCESS;
        bool restored = platform_.RestoreAcl(file, originalSecurity,
                                             originalProtected, restoreError);
        result.status = (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS)
            ? "destination_exists" : "move_failed";
        result.win32Error = error;
        if (!restored) {
            result.status = "acl_restore_failed";
            result.win32Error = restoreError;
        }
        result.quarantinePath.clear();
    } else {
        const std::string sidecarPath =
            Join(quarantineDir_, request.requestId + ".json");
        const std::string clearMetadata = BuildRestoreMetadata(request, finalPath,
            result.quarantinePath, hash, source, originalSecurity,
            originalProtected, error);
        std::string protectedMetadata;
        bool sidecarReady = !clearMetadata.empty() &&
            platform_.ProtectMetadata(clearMetadata, protectedMetadata, error);
        if (sidecarReady && protectedMetadata.empty()) {
            sidecarReady = false;
            error = ERROR_INVALID_DATA;
        }
        std::string sidecar;
        std::string sidecarDigest;
        if (sidecarReady) {
            sidecar = "{\"schema_version\":2,\"source_request_id\":\"" +
                jsonlite::escape(request.requestId) +
                "\",\"protected_metadata\":\"" +
                jsonlite::escape(protectedMetadata) + "\"}";
            sidecarReady = sidecar.size() <= kMaxRestoreSidecarBytes &&
                HashBytes(sidecar, sidecarDigest, error);
            if (!sidecarReady && error == ERROR_SUCCESS)
                error = ERROR_FILE_TOO_LARGE;
        }
        if (sidecarReady &&
            platform_.WriteFileAtomic(sidecarPath, sidecar, error)) {
            result.status = "quarantined";
            result.sidecarSha256Hex = sidecarDigest;
        } else {
            result.status = sidecar.empty() ? "metadata_seal_failed" :
                (sidecarReady ? "sidecar_failed" : "metadata_seal_failed");
            result.win32Error = error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
            DWORD rollbackError = ERROR_SUCCESS;
            if (!platform_.Rename(file, finalPath, rollbackError)) {
                result.status = (rollbackError == ERROR_ALREADY_EXISTS ||
                                 rollbackError == ERROR_FILE_EXISTS)
                    ? "rollback_conflict" : "rollback_failed";
                result.win32Error = rollbackError;
            } else {
                DWORD restoreError = ERROR_SUCCESS;
                if (platform_.RestoreAcl(file, originalSecurity,
                                         originalProtected, restoreError)) {
                    result.rolledBack = true;
                    result.quarantinePath.clear();
                } else {
                    result.status = "acl_restore_failed";
                    result.win32Error = restoreError;
                    result.quarantinePath.clear();
                }
            }
        }
    }
    if (audit_.OutcomeQuarantine(request, result, auditError)) {
        result.auditWritten = true;
    } else {
        result.auditWritten = false;
        Emergency(emergency_, result, auditError);
    }
    return result;
}

QuarantineRestoreResult QuarantineExecutor::Restore(
        const QuarantineRestoreRequest& request) {
    if (!ValidRequestId(request.requestId) ||
        !ValidRequestId(request.sourceRequestId) ||
        request.requestId == request.sourceRequestId ||
        !Decimal(request.timestamp) || !ValidText(request.reason, 1024) ||
        !AbsoluteDrivePath(quarantineDir_))
        return RejectRestore(request, "policy_rejected", ERROR_INVALID_PARAMETER);

    DWORD error = ERROR_SUCCESS;
    QuarantineFileInfo quarantineDirectory;
    if (!platform_.DirectoryInfo(quarantineDir_, quarantineDirectory, error) ||
        !(quarantineDirectory.attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (quarantineDirectory.attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return RejectRestore(request, "quarantine_setup_failed",
            error == ERROR_SUCCESS ? ERROR_REPARSE_TAG_INVALID : error);

    const std::string sidecarPath =
        Join(quarantineDir_, request.sourceRequestId + ".json");
    std::string sidecarBytes;
    if (!platform_.ReadFileBounded(sidecarPath, kMaxRestoreSidecarBytes,
                                   sidecarBytes, error)) {
        return RejectRestore(request,
            error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
                ? "not_restorable" : "metadata_invalid",
            error);
    }

    jsonlite::Value outer;
    try {
        outer = jsonlite::parse(sidecarBytes);
    } catch (...) {
        return RejectRestore(request, "metadata_invalid", ERROR_INVALID_DATA);
    }
    const auto* version = outer.find("schema_version");
    if (!version) return RejectRestore(request, "not_restorable", ERROR_NOT_SUPPORTED);
    if (version->type != jsonlite::Type::Number || version->number != 2)
        return RejectRestore(request, "not_restorable", ERROR_NOT_SUPPORTED);
    if (!ExactKeys(outer, {"schema_version", "source_request_id",
                           "protected_metadata"}))
        return RejectRestore(request, "metadata_invalid", ERROR_INVALID_DATA);
    const auto* sidecarSourceId = outer.find("source_request_id");
    const auto* protectedMetadata = outer.find("protected_metadata");
    if (!sidecarSourceId || sidecarSourceId->type != jsonlite::Type::String ||
        sidecarSourceId->str != request.sourceRequestId ||
        !protectedMetadata || protectedMetadata->type != jsonlite::Type::String ||
        protectedMetadata->str.empty() ||
        protectedMetadata->str.size() > kMaxRestoreMetadataBytes * 2) {
        return RejectRestore(request, "metadata_invalid", ERROR_INVALID_DATA);
    }

    std::string clearMetadata;
    if (!platform_.UnprotectMetadata(protectedMetadata->str, clearMetadata, error) ||
        clearMetadata.empty() || clearMetadata.size() > kMaxRestoreMetadataBytes)
        return RejectRestore(request, "metadata_invalid",
            error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error);
    RestoreMetadata metadata;
    if (!ParseRestoreMetadata(clearMetadata, request.sourceRequestId,
                              metadata, error) ||
        !platform_.ValidateOriginalDacl(metadata.originalSecurityDescriptor,
                                        metadata.originalDaclProtected, error))
        return RejectRestore(request, "metadata_invalid",
            error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error);

    QuarantineRestoreResult result;
    result.requestId = request.requestId;
    result.sourceRequestId = request.sourceRequestId;
    result.originalPath = metadata.originalPath;
    result.quarantinePath = metadata.quarantinePath;
    result.sha256Hex = metadata.sha256Hex;
    if (metadata.fileSize > maxFileBytes_)
        return RejectRestore(request, "file_too_large", ERROR_FILE_TOO_LARGE);
    if (ProtectedPath(metadata.originalPath, quarantineDir_))
        return RejectRestore(request, "policy_rejected", ERROR_ACCESS_DENIED);
    if (!AbsoluteDrivePath(metadata.originalPath) ||
        !ValidLeafName(LeafName(metadata.originalPath)))
        return RejectRestore(request, "policy_rejected", ERROR_BAD_PATHNAME);

    const std::string expectedQuarantinePath =
        Join(quarantineDir_, metadata.sha256Hex + ".quarantined");
    if (!SameCanonicalPath(metadata.quarantinePath, expectedQuarantinePath) ||
        metadata.volumeSerial != quarantineDirectory.volumeSerial)
        return RejectRestore(request, "metadata_invalid", ERROR_INVALID_DATA);

    std::string sidecarDigest;
    if (!HashBytes(sidecarBytes, sidecarDigest, error))
        return RejectRestore(request, "metadata_invalid", error);
    result.sidecarSha256Hex = sidecarDigest;

    HANDLE quarantinedFile = INVALID_HANDLE_VALUE;
    if (!platform_.OpenFile(metadata.quarantinePath, quarantinedFile, error))
        return RejectRestore(request, "quarantine_file_missing", error);
    struct FileGuard {
        IQuarantinePlatform& platform;
        HANDLE value;
        ~FileGuard() { platform.CloseHandleSafe(value); }
    } fileGuard{platform_, quarantinedFile};

    QuarantineFileInfo quarantinedInfo;
    std::string actualQuarantinePath;
    if (!platform_.FileInfo(quarantinedFile, quarantinedInfo, error) ||
        !platform_.FinalPath(quarantinedFile, actualQuarantinePath, error))
        return RejectRestore(request, "identity_check_failed", error);
    if ((quarantinedInfo.attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (quarantinedInfo.attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        quarantinedInfo.numberOfLinks != 1)
        return RejectRestore(request, "policy_rejected",
            (quarantinedInfo.attributes & FILE_ATTRIBUTE_REPARSE_POINT)
                ? ERROR_REPARSE_TAG_INVALID : ERROR_TOO_MANY_LINKS);
    if (!SameCanonicalPath(actualQuarantinePath, expectedQuarantinePath) ||
        quarantinedInfo.volumeSerial != metadata.volumeSerial ||
        memcmp(quarantinedInfo.fileId, metadata.fileId,
               sizeof(metadata.fileId)) != 0)
        return RejectRestore(request, "identity_changed", ERROR_FILE_INVALID);
    if (quarantinedInfo.size != metadata.fileSize)
        return RejectRestore(request, "content_mismatch", ERROR_CRC);
    if (quarantinedInfo.size > maxFileBytes_)
        return RejectRestore(request, "file_too_large", ERROR_FILE_TOO_LARGE);
    std::string actualHash;
    if (!platform_.Hash(quarantinedFile, actualHash, error))
        return RejectRestore(request, "hash_failed", error);
    if (LowerHex(actualHash) != metadata.sha256Hex)
        return RejectRestore(request, "content_mismatch", ERROR_CRC);

    const std::string destinationParent = ParentPath(metadata.originalPath);
    const std::string destinationLeaf = LeafName(metadata.originalPath);
    HANDLE destinationDirectory = INVALID_HANDLE_VALUE;
    QuarantineFileInfo destinationDirectoryInfo;
    std::string actualDestinationParent;
    if (!platform_.OpenDirectoryNoFollow(destinationParent,
            destinationDirectory, destinationDirectoryInfo,
            actualDestinationParent, error))
        return RejectRestore(request, "path_resolution_failed", error);
    struct DirectoryGuard {
        IQuarantinePlatform& platform;
        HANDLE value;
        ~DirectoryGuard() { platform.CloseHandleSafe(value); }
    } directoryGuard{platform_, destinationDirectory};
    if (!(destinationDirectoryInfo.attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (destinationDirectoryInfo.attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        destinationDirectoryInfo.volumeSerial != metadata.volumeSerial ||
        !SameCanonicalPath(destinationParent, actualDestinationParent))
        return RejectRestore(request, "path_resolution_failed",
            destinationDirectoryInfo.volumeSerial != metadata.volumeSerial
                ? ERROR_NOT_SAME_DEVICE : ERROR_REPARSE_TAG_INVALID);

    std::string auditError;
    if (!audit_.AttemptRestore(request, metadata.originalPath,
            metadata.quarantinePath, metadata.sha256Hex, sidecarDigest,
            auditError)) {
        return RejectRestore(request,
            auditError == "requestId replay" ? "replay" : "audit_failed",
            ERROR_WRITE_FAULT);
    }

    if (!platform_.RenameNoReplaceInDirectory(quarantinedFile,
            destinationDirectory, destinationLeaf, error)) {
        result.status = (error == ERROR_ALREADY_EXISTS ||
                         error == ERROR_FILE_EXISTS)
            ? "destination_exists" : "move_failed";
        result.win32Error = error;
    } else {
        result.partialRestore = true;
        if (platform_.RestoreAcl(quarantinedFile,
                metadata.originalSecurityDescriptor,
                metadata.originalDaclProtected, error)) {
            result.status = "restored";
            result.win32Error = ERROR_SUCCESS;
            result.partialRestore = false;
        } else {
            result.status = "restore_acl_failed";
            result.win32Error = error;
        }
    }

    if (audit_.OutcomeRestore(request, result, auditError)) {
        result.auditWritten = true;
    } else {
        result.auditWritten = false;
        Emergency(emergency_, result, auditError);
    }
    if (result.partialRestore && result.auditWritten)
        Emergency(emergency_, result,
            "quarantine file moved to original path but original DACL restore failed");
    return result;
}

} // namespace edr
