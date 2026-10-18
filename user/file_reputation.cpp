#include "file_reputation.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <algorithm>
#include <cwchar>
#include <cstring>
#include <iterator>
#include <limits>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

namespace edr {
namespace {

constexpr DWORD kReadChunkBytes = 64U * 1024U;

class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}
    ~ScopedHandle() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) {
            CloseHandle(handle_);
        }
    }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    HANDLE get() const { return handle_; }

private:
    HANDLE handle_;
};

class ScopedAlgorithm {
public:
    ~ScopedAlgorithm() {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }
    BCRYPT_ALG_HANDLE* put() { return &handle_; }
    BCRYPT_ALG_HANDLE get() const { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class ScopedHash {
public:
    ~ScopedHash() {
        if (handle_ != nullptr) {
            BCryptDestroyHash(handle_);
        }
    }
    BCRYPT_HASH_HANDLE* put() { return &handle_; }
    BCRYPT_HASH_HANDLE get() const { return handle_; }

private:
    BCRYPT_HASH_HANDLE handle_ = nullptr;
};

bool StartsWithInsensitive(const std::wstring& value, const wchar_t* prefix) {
    const size_t length = std::wcslen(prefix);
    return value.size() >= length &&
           _wcsnicmp(value.c_str(), prefix, length) == 0;
}

bool IsUncPath(const std::wstring& path) {
    if (StartsWithInsensitive(path, L"\\\\?\\UNC\\") ||
        StartsWithInsensitive(path, L"\\??\\UNC\\")) {
        return true;
    }
    return path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\' &&
           !StartsWithInsensitive(path, L"\\\\?\\") &&
           !StartsWithInsensitive(path, L"\\\\.\\");
}

bool IsDevicePath(const std::wstring& path) {
    if (StartsWithInsensitive(path, L"\\\\.\\") ||
        StartsWithInsensitive(path, L"\\??\\")) {
        return true;
    }
    if (!StartsWithInsensitive(path, L"\\\\?\\")) {
        return false;
    }
    const wchar_t* remainder = path.c_str() + 4;
    return !(path.size() >= 7 && remainder[1] == L':' &&
             remainder[2] == L'\\');
}

bool QueryIdentity(HANDLE file, FileIdentity& identity, DWORD& error,
                   bool& directory, bool& reparse) {
    FILE_ID_INFO idInfo{};
    FILE_STANDARD_INFO standardInfo{};
    FILE_BASIC_INFO basicInfo{};
    if (!GetFileInformationByHandleEx(file, FileIdInfo, &idInfo, sizeof(idInfo)) ||
        !GetFileInformationByHandleEx(file, FileStandardInfo, &standardInfo,
                                      sizeof(standardInfo)) ||
        !GetFileInformationByHandleEx(file, FileBasicInfo, &basicInfo,
                                      sizeof(basicInfo))) {
        error = GetLastError();
        return false;
    }
    if (standardInfo.EndOfFile.QuadPart < 0) {
        error = ERROR_FILE_INVALID;
        return false;
    }
    identity.volumeSerial = idInfo.VolumeSerialNumber;
    static_assert(sizeof(identity.fileId) == sizeof(idInfo.FileId.Identifier),
                  "unexpected Windows file ID size");
    std::memcpy(identity.fileId.data(), idInfo.FileId.Identifier,
                identity.fileId.size());
    identity.size = static_cast<std::uint64_t>(standardInfo.EndOfFile.QuadPart);
    identity.lastWriteTime100ns = basicInfo.LastWriteTime.QuadPart;
    identity.changeTime100ns = basicInfo.ChangeTime.QuadPart;
    directory = standardInfo.Directory != FALSE;
    reparse = (basicInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    error = ERROR_SUCCESS;
    return true;
}

bool SameIdentity(const FileIdentity& left, const FileIdentity& right) {
    return left.volumeSerial == right.volumeSerial &&
           left.fileId == right.fileId && left.size == right.size &&
           left.lastWriteTime100ns == right.lastWriteTime100ns &&
           left.changeTime100ns == right.changeTime100ns;
}

std::string Hex(const BYTE* bytes, size_t length) {
    static const char digits[] = "0123456789abcdef";
    std::string result(length * 2, '0');
    for (size_t i = 0; i < length; ++i) {
        result[i * 2] = digits[bytes[i] >> 4];
        result[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    return result;
}

bool HashFile(HANDLE file, std::uint64_t size, std::uint64_t maxFileBytes,
              FileReputationResult& result) {
    ScopedAlgorithm algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        algorithm.put(), BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        result.status = FileReputationStatus::HashError;
        result.statusCode = static_cast<std::uint32_t>(status);
        return false;
    }

    DWORD objectBytes = 0;
    DWORD hashBytes = 0;
    DWORD received = 0;
    status = BCryptGetProperty(algorithm.get(), BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&objectBytes),
                               sizeof(objectBytes), &received, 0);
    if (status >= 0) {
        status = BCryptGetProperty(algorithm.get(), BCRYPT_HASH_LENGTH,
                                   reinterpret_cast<PUCHAR>(&hashBytes),
                                   sizeof(hashBytes), &received, 0);
    }
    if (status < 0 || hashBytes == 0) {
        result.status = FileReputationStatus::HashError;
        result.statusCode = static_cast<std::uint32_t>(status);
        return false;
    }

    std::vector<BYTE> hashObject(objectBytes);
    std::vector<BYTE> digest(hashBytes);
    std::vector<BYTE> chunk(kReadChunkBytes);
    ScopedHash hash;
    status = BCryptCreateHash(algorithm.get(), hash.put(), hashObject.data(),
                              static_cast<ULONG>(hashObject.size()), nullptr, 0, 0);
    if (status < 0) {
        result.status = FileReputationStatus::HashError;
        result.statusCode = static_cast<std::uint32_t>(status);
        return false;
    }

    std::uint64_t remaining = size;
    while (remaining != 0) {
        if (result.bytesHashed >= maxFileBytes) {
            result.status = FileReputationStatus::FileTooLarge;
            result.statusCode = ERROR_FILE_TOO_LARGE;
            return false;
        }
        const DWORD requested = static_cast<DWORD>(
            std::min<std::uint64_t>(
                std::min<std::uint64_t>(remaining, chunk.size()),
                maxFileBytes - result.bytesHashed));
        DWORD read = 0;
        if (!ReadFile(file, chunk.data(), requested, &read, nullptr)) {
            result.status = FileReputationStatus::ReadError;
            result.statusCode = GetLastError();
            return false;
        }
        if (read == 0) {
            result.status = FileReputationStatus::Changed;
            result.statusCode = ERROR_HANDLE_EOF;
            return false;
        }
        status = BCryptHashData(hash.get(), chunk.data(), read, 0);
        if (status < 0) {
            result.status = FileReputationStatus::HashError;
            result.statusCode = static_cast<std::uint32_t>(status);
            return false;
        }
        result.bytesHashed += read;
        remaining -= read;
    }

    status = BCryptFinishHash(hash.get(), digest.data(),
                              static_cast<ULONG>(digest.size()), 0);
    if (status < 0) {
        result.status = FileReputationStatus::HashError;
        result.statusCode = static_cast<std::uint32_t>(status);
        return false;
    }
    result.sha256 = Hex(digest.data(), digest.size());
    return true;
}

std::wstring CertificateName(PCCERT_CONTEXT certificate, DWORD flags) {
    const DWORD length = CertGetNameStringW(certificate,
                                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                            flags, nullptr, nullptr, 0);
    if (length <= 1) {
        return {};
    }
    std::wstring value(length, L'\0');
    if (CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags,
                           nullptr, value.data(), length) != length) {
        return {};
    }
    value.resize(length - 1);
    return value;
}

void ExtractSignerMetadata(HANDLE stateData, SignerMetadata& metadata) {
    CRYPT_PROVIDER_DATA* provider = WTHelperProvDataFromStateData(stateData);
    if (provider == nullptr) {
        return;
    }
    CRYPT_PROVIDER_SGNR* signer =
        WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
    if (signer == nullptr || signer->csCertChain == 0 ||
        signer->pasCertChain == nullptr ||
        signer->pasCertChain[0].pCert == nullptr) {
        return;
    }

    PCCERT_CONTEXT certificate = signer->pasCertChain[0].pCert;
    metadata.available = true;
    metadata.signatureKind = SignatureKind::Embedded;
    metadata.subject = CertificateName(certificate, 0);
    metadata.issuer = CertificateName(certificate, CERT_NAME_ISSUER_FLAG);

    BYTE digest[32]{};
    DWORD digestBytes = sizeof(digest);
    if (CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr,
                              certificate->pbCertEncoded,
                              certificate->cbCertEncoded, digest,
                              &digestBytes) &&
        digestBytes == sizeof(digest)) {
        metadata.certificateSha256 = Hex(digest, digestBytes);
    }
}

AuthenticodeStatus MapTrustStatus(LONG status) {
    switch (status) {
    case ERROR_SUCCESS:
        return AuthenticodeStatus::Trusted;
    case TRUST_E_NOSIGNATURE:
        return AuthenticodeStatus::Unsigned;
    case CERT_E_REVOKED:
        return AuthenticodeStatus::Revoked;
    case CERT_E_EXPIRED:
        return AuthenticodeStatus::Expired;
    case TRUST_E_BAD_DIGEST:
    case TRUST_E_EXPLICIT_DISTRUST:
    case TRUST_E_SUBJECT_NOT_TRUSTED:
    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_CHAINING:
    case CERT_E_WRONG_USAGE:
    case CERT_E_INVALID_NAME:
    case CERT_E_INVALID_POLICY:
    case CRYPT_E_SECURITY_SETTINGS:
        return AuthenticodeStatus::Untrusted;
    default:
        return AuthenticodeStatus::Error;
    }
}

void VerifyEmbeddedSignature(HANDLE file, const std::wstring& path,
                             bool cacheOnly, FileReputationResult& result) {
    LARGE_INTEGER beginning{};
    SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN);

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();
    fileInfo.hFile = file;

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
                            WTD_DISABLE_MD2_MD4;
    if (cacheOnly) {
        trustData.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
    }

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG trustStatus = WinVerifyTrust(nullptr, &policy, &trustData);
    struct TrustStateCloser {
        GUID* policy;
        WINTRUST_DATA* data;
        ~TrustStateCloser() {
            data->dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, policy, data);
        }
    } closer{&policy, &trustData};

    result.authenticodeStatusCode = static_cast<std::int32_t>(trustStatus);
    result.authenticode = MapTrustStatus(trustStatus);
    if (trustData.hWVTStateData != nullptr) {
        ExtractSignerMetadata(trustData.hWVTStateData, result.signer);
    }
}

void DiscardAuthoritativeResults(FileReputationResult& result) {
    result.sha256.clear();
    result.bytesHashed = 0;
    result.authenticode = AuthenticodeStatus::NotChecked;
    result.authenticodeStatusCode = 0;
    result.signer = {};
}

} // namespace

FileReputationResult GetFileReputation(const std::wstring& path,
                                       const FileReputationSettings& settings) {
    FileReputationResult result;
    if (!settings.enabled) {
        result.status = FileReputationStatus::Disabled;
        return result;
    }
    if (path.empty() || path.find(L'\0') != std::wstring::npos) {
        result.status = FileReputationStatus::InvalidPath;
        result.statusCode = ERROR_INVALID_NAME;
        return result;
    }
    if (!settings.allowUnc && IsUncPath(path)) {
        result.status = FileReputationStatus::UncRejected;
        result.statusCode = ERROR_BAD_NETPATH;
        return result;
    }
    if (!settings.allowDevicePaths && IsDevicePath(path)) {
        result.status = FileReputationStatus::DevicePathRejected;
        result.statusCode = ERROR_BAD_PATHNAME;
        return result;
    }

    ScopedHandle file(CreateFileW(
        path.c_str(), FILE_READ_ATTRIBUTES | FILE_READ_DATA,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr));
    if (file.get() == INVALID_HANDLE_VALUE) {
        result.status = FileReputationStatus::OpenError;
        result.statusCode = GetLastError();
        return result;
    }
    SetLastError(ERROR_SUCCESS);
    const DWORD fileType = GetFileType(file.get());
    if (fileType != FILE_TYPE_DISK) {
        result.status = FileReputationStatus::NotDiskFile;
        const DWORD fileTypeError = GetLastError();
        result.statusCode = fileType == FILE_TYPE_UNKNOWN &&
                                    fileTypeError != ERROR_SUCCESS
                                ? fileTypeError
                                : ERROR_INVALID_FUNCTION;
        return result;
    }

    wchar_t finalPath[32768]{};
    const DWORD finalLength = GetFinalPathNameByHandleW(
        file.get(), finalPath, static_cast<DWORD>(std::size(finalPath)),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (finalLength == 0 || finalLength >= std::size(finalPath)) {
        result.status = FileReputationStatus::IdentityError;
        result.statusCode = finalLength == 0 ? GetLastError() : ERROR_BUFFER_OVERFLOW;
        return result;
    }
    const std::wstring normalizedPath(finalPath, finalLength);
    if (!settings.allowUnc && IsUncPath(normalizedPath)) {
        result.status = FileReputationStatus::UncRejected;
        result.statusCode = ERROR_BAD_NETPATH;
        return result;
    }
    if (!settings.allowDevicePaths && IsDevicePath(normalizedPath)) {
        result.status = FileReputationStatus::DevicePathRejected;
        result.statusCode = ERROR_BAD_PATHNAME;
        return result;
    }

    DWORD identityError = ERROR_SUCCESS;
    bool directory = false;
    bool reparse = false;
    if (!QueryIdentity(file.get(), result.identity, identityError, directory,
                       reparse)) {
        result.status = FileReputationStatus::IdentityError;
        result.statusCode = identityError;
        return result;
    }
    if (directory) {
        result.status = FileReputationStatus::NotDiskFile;
        result.statusCode = ERROR_DIRECTORY;
        return result;
    }
    if (reparse && !settings.allowReparsePoints) {
        result.status = FileReputationStatus::ReparsePointRejected;
        result.statusCode = ERROR_REPARSE_TAG_INVALID;
        return result;
    }
    if (result.identity.size > settings.maxFileBytes) {
        result.status = FileReputationStatus::FileTooLarge;
        result.statusCode = ERROR_FILE_TOO_LARGE;
        return result;
    }

    result.status = FileReputationStatus::Complete;
    const bool hashSucceeded = HashFile(file.get(), result.identity.size,
                                        settings.maxFileBytes, result);
    if (hashSucceeded) {
        VerifyEmbeddedSignature(file.get(), normalizedPath,
                                settings.cacheOnlyTrust, result);
    }

    FileIdentity finalIdentity;
    bool finalDirectory = false;
    bool finalReparse = false;
    if (!QueryIdentity(file.get(), finalIdentity, identityError, finalDirectory,
                       finalReparse)) {
        DiscardAuthoritativeResults(result);
        result.status = FileReputationStatus::IdentityError;
        result.statusCode = identityError;
        return result;
    }
    if (!SameIdentity(result.identity, finalIdentity)) {
        DiscardAuthoritativeResults(result);
        result.status = FileReputationStatus::Changed;
        result.statusCode = ERROR_FILE_INVALID;
        return result;
    }
    return result;
}

FileReputationResult GetFileReputation(const std::string& utf8Path,
                                       const FileReputationSettings& settings) {
    if (utf8Path.empty() ||
        utf8Path.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        FileReputationResult result;
        result.status = FileReputationStatus::InvalidPath;
        result.statusCode = ERROR_INVALID_NAME;
        return result;
    }
    const int length = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, utf8Path.data(),
        static_cast<int>(utf8Path.size()), nullptr, 0);
    if (length == 0) {
        FileReputationResult result;
        result.status = FileReputationStatus::InvalidPath;
        result.statusCode = GetLastError();
        return result;
    }
    std::wstring path(static_cast<size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Path.data(),
                            static_cast<int>(utf8Path.size()), path.data(),
                            length) != length) {
        FileReputationResult result;
        result.status = FileReputationStatus::InvalidPath;
        result.statusCode = GetLastError();
        return result;
    }
    return GetFileReputation(path, settings);
}

} // namespace edr
