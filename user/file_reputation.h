#ifndef EDR_FILE_REPUTATION_H
#define EDR_FILE_REPUTATION_H

#include <array>
#include <cstdint>
#include <string>

namespace edr {

struct FileReputationSettings {
    bool enabled = true;
    std::uint64_t maxFileBytes = 64ULL * 1024ULL * 1024ULL;
    bool cacheOnlyTrust = true;
    bool allowUnc = false;
    bool allowDevicePaths = false;
    bool allowReparsePoints = false;
};

enum class FileReputationStatus {
    Complete,
    Disabled,
    InvalidPath,
    OpenError,
    NotDiskFile,
    UncRejected,
    DevicePathRejected,
    ReparsePointRejected,
    FileTooLarge,
    IdentityError,
    ReadError,
    HashError,
    Changed
};

enum class AuthenticodeStatus {
    NotChecked,
    Trusted,
    Unsigned,
    Untrusted,
    Revoked,
    Expired,
    Error
};

enum class SignatureKind {
    None,
    Embedded
};

struct FileIdentity {
    std::uint64_t volumeSerial = 0;
    std::array<std::uint8_t, 16> fileId{};
    std::uint64_t size = 0;
    std::int64_t lastWriteTime100ns = 0;
    std::int64_t changeTime100ns = 0;
};

struct SignerMetadata {
    bool available = false;
    SignatureKind signatureKind = SignatureKind::None;
    std::wstring subject;
    std::wstring issuer;
    std::string certificateSha256;
};

struct FileReputationResult {
    FileReputationStatus status = FileReputationStatus::InvalidPath;
    // Win32 error or NTSTATUS associated with the overall status, if any.
    std::uint32_t statusCode = 0;
    FileIdentity identity;
    std::uint64_t bytesHashed = 0;
    std::string sha256;
    AuthenticodeStatus authenticode = AuthenticodeStatus::NotChecked;
    // Exact LONG returned by WinVerifyTrust, represented without translation.
    std::int32_t authenticodeStatusCode = 0;
    SignerMetadata signer;
    // This module verifies embedded signatures only; it does not query catalogs.
    bool catalogSignaturesSupported = false;
};

FileReputationResult GetFileReputation(
    const std::wstring& path, const FileReputationSettings& settings = {});

FileReputationResult GetFileReputation(
    const std::string& utf8Path, const FileReputationSettings& settings = {});

} // namespace edr

#endif /* EDR_FILE_REPUTATION_H */
