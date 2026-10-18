#include "reporter_spool.h"

#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <limits>
#include <string>
#include <utility>

#include "config.h"
#include "owner_only_sd.h"

namespace edr {
namespace {

constexpr size_t kMaxSpoolRecords = 1000;
constexpr size_t kMaxSpoolBytes = 64u * 1024u * 1024u;
constexpr size_t kMaxSpoolItemBytes = 4u * 1024u * 1024u;
constexpr char kLegacyMagic[] = "EDR-SPOOL-1\n";
constexpr char kMagic[] = "EDR-SPOOL-2\n";
constexpr char kDaclSddl[] = "D:P(A;;FA;;;OW)";

std::string WinError(const char* operation, DWORD code) {
    return std::string(operation) + " (win32=" + std::to_string(code) + ")";
}

std::string NormalizeSddl(const char* value) {
    std::string result = value ? value : "";
    if (result.compare(0, 5, "D:PAI") == 0) result.replace(0, 5, "D:P");
    return result;
}

bool WriteAll(HANDLE handle, const char* data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        const DWORD request = static_cast<DWORD>(std::min<size_t>(
            length - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(handle, data + offset, request, &written, nullptr) ||
            written == 0) return false;
        offset += written;
    }
    return true;
}

bool ReadAll(HANDLE handle, std::string& data, size_t length) {
    data.resize(length);
    size_t offset = 0;
    while (offset < length) {
        const DWORD request = static_cast<DWORD>(std::min<size_t>(
            length - offset, std::numeric_limits<DWORD>::max()));
        DWORD read = 0;
        if (!ReadFile(handle, &data[offset], request, &read, nullptr) || read == 0)
            return false;
        offset += read;
    }
    char extra = 0;
    DWORD read = 0;
    return ReadFile(handle, &extra, 1, &read, nullptr) && read == 0;
}

bool ParseDecimal(const std::string& value, uint64_t& parsed) {
    if (value.empty()) return false;
    uint64_t result = 0;
    for (unsigned char ch : value) {
        if (ch < '0' || ch > '9') return false;
        const unsigned digit = ch - '0';
        if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10) return false;
        result = result * 10 + digit;
    }
    parsed = result;
    return true;
}

bool ReadLine(HANDLE handle, std::string& result, size_t limit) {
    result.clear();
    for (size_t i = 0; i <= limit; ++i) {
        char ch = 0;
        DWORD read = 0;
        if (!ReadFile(handle, &ch, 1, &read, nullptr) || read != 1) return false;
        if (ch == '\n') return true;
        if (result.size() == limit) return false;
        result.push_back(ch);
    }
    return false;
}

std::wstring FinalPath(HANDLE handle) {
    DWORD count = GetFinalPathNameByHandleW(handle, nullptr, 0,
                                             FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (count == 0) return {};
    std::wstring result(count, L'\0');
    DWORD written = GetFinalPathNameByHandleW(handle, &result[0], count,
                                               FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (written == 0 || written >= count) return {};
    result.resize(written);
    return result;
}

bool EqualPath(std::wstring left, std::wstring right) {
    while (!left.empty() && (left.back() == L'\\' || left.back() == L'/')) left.pop_back();
    while (!right.empty() && (right.back() == L'\\' || right.back() == L'/')) right.pop_back();
    return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_EQUAL;
}

} // namespace

ReporterSpool::ReporterSpool(ReporterSpoolOptions options,
                             std::string destinationKey)
    : m_options(std::move(options)),
      m_destinationFingerprint(Hash(destinationKey)) {}

ReporterSpool::~ReporterSpool() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& entry : m_entries) {
        if (entry.second.handle != INVALID_HANDLE_VALUE) CloseHandle(entry.second.handle);
    }
    m_entries.clear();
    if (m_lockHandle != INVALID_HANDLE_VALUE) CloseHandle(m_lockHandle);
    if (m_directoryHandle != INVALID_HANDLE_VALUE) CloseHandle(m_directoryHandle);
}

std::string ReporterSpool::MakeId(uint64_t sequence) {
    char value[32] = {};
    std::snprintf(value, sizeof(value), "%020llu",
                  static_cast<unsigned long long>(sequence));
    std::array<UCHAR, 16> nonce{};
    if (BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string result(value);
    result.push_back('-');
    for (UCHAR byte : nonce) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0f]);
    }
    return result;
}

std::string ReporterSpool::Hash(const std::string& value) {
    if (value.size() > std::numeric_limits<ULONG>::max()) return {};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0, resultLength = 0;
    std::vector<unsigned char> object;
    std::array<unsigned char, 32> digest{};
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm,
                                                   BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, 0);
    if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0);
    if (status >= 0) {
        object.resize(objectLength);
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectLength,
                                  nullptr, 0, 0);
    }
    if (status >= 0) status = BCryptHashData(hash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(value.data())),
        static_cast<ULONG>(value.size()), 0);
    if (status >= 0) status = BCryptFinishHash(hash, digest.data(),
                                               static_cast<ULONG>(digest.size()), 0);
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string result(64, '0');
    for (size_t i = 0; i < digest.size(); ++i) {
        result[i * 2] = hex[digest[i] >> 4];
        result[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    return result;
}

bool ReporterSpool::FailLocked(const std::string& reason) {
    if (!m_failed) {
        m_failed = true;
        ++m_errorCount;
        m_status = "failed: " + reason;
    }
    return false;
}

bool ReporterSpool::VerifyProtectedObject(HANDLE handle, bool setAcl,
                                          std::string& error) const {
    BY_HANDLE_FILE_INFORMATION objectInfo = {};
    if (!GetFileInformationByHandle(handle, &objectInfo)) {
        error = WinError("could not inspect spool object before ACL change", GetLastError());
        return false;
    }
    if ((objectInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        error = "refusing to change ACL on spool reparse point";
        return false;
    }

    /* Never rewrite a foreign owner's ACL, even when this process happens to
     * have administrative WRITE_DAC rights. Verify ownership before mutation. */
    HANDLE ownerToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &ownerToken)) {
        error = WinError("could not open process token for spool owner check", GetLastError());
        return false;
    }
    DWORD ownerBytes = 0;
    GetTokenInformation(ownerToken, TokenUser, nullptr, 0, &ownerBytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || ownerBytes == 0) {
        CloseHandle(ownerToken);
        error = "could not query process owner for spool ACL verification";
        return false;
    }
    std::vector<unsigned char> ownerData(ownerBytes);
    if (!GetTokenInformation(ownerToken, TokenUser, ownerData.data(), ownerBytes,
                             &ownerBytes)) {
        const DWORD code = GetLastError();
        CloseHandle(ownerToken);
        error = WinError("could not read process owner for spool ACL verification", code);
        return false;
    }
    const PSID expectedOwner = reinterpret_cast<TOKEN_USER*>(ownerData.data())->User.Sid;
    PSID beforeOwner = nullptr;
    PSECURITY_DESCRIPTOR beforeDescriptor = nullptr;
    DWORD ownerResult = GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION, &beforeOwner, nullptr, nullptr, nullptr,
        &beforeDescriptor);
    const bool ownerMatchesBefore = ownerResult == ERROR_SUCCESS &&
        beforeOwner != nullptr && EqualSid(beforeOwner, expectedOwner);
    if (beforeDescriptor) LocalFree(beforeDescriptor);
    if (!ownerMatchesBefore) {
        CloseHandle(ownerToken);
        error = ownerResult == ERROR_SUCCESS
            ? "spool object is not owned by the current process account"
            : WinError("could not inspect spool object owner", ownerResult);
        return false;
    }

    if (setAcl) {
        PSECURITY_DESCRIPTOR expected = nullptr;
        std::string aclError;
        expected = CreateOwnerOnlyDescriptor(aclError);
        if (expected == nullptr) {
            CloseHandle(ownerToken);
            error = WinError("could not create owner-only spool ACL", ERROR_INVALID_ACL);
            return false;
        }
        BOOL present = FALSE, defaulted = FALSE;
        PACL dacl = nullptr;
        const BOOL queried = GetSecurityDescriptorDacl(expected, &present, &dacl, &defaulted);
        DWORD result = queried && present
            ? SetSecurityInfo(handle, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, dacl, nullptr)
            : ERROR_INVALID_ACL;
        LocalFree(expected);
        if (result != ERROR_SUCCESS) {
            CloseHandle(ownerToken);
            error = WinError("could not apply protected spool ACL", result);
            return false;
        }
    }

    PSID actualOwner = nullptr;
    PACL actualDacl = nullptr;
    PSECURITY_DESCRIPTOR actual = nullptr;
    DWORD result = GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &actualOwner, nullptr, &actualDacl, nullptr, &actual);
    if (result != ERROR_SUCCESS || actual == nullptr) {
        if (actual) LocalFree(actual);
        CloseHandle(ownerToken);
        error = WinError("could not inspect spool ACL", result);
        return false;
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    LPSTR sddl = nullptr;
    const bool valid = actualOwner != nullptr && EqualSid(actualOwner, expectedOwner) &&
        GetSecurityDescriptorControl(actual, &control, &revision) &&
        (control & SE_DACL_PROTECTED) != 0 && actualDacl != nullptr &&
        ConvertSecurityDescriptorToStringSecurityDescriptorA(actual,
            SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, nullptr) &&
        NormalizeSddl(sddl) == kDaclSddl;
    if (sddl) LocalFree(sddl);
    LocalFree(actual);
    CloseHandle(ownerToken);
    if (!valid) {
        error = "spool object owner or protected DACL does not match current owner-only policy";
        return false;
    }
    return true;
}

bool ReporterSpool::PrepareDirectoryLocked() {
    if (m_options.maxRecords == 0 || m_options.maxRecords > kMaxSpoolRecords ||
        m_options.maxBytes == 0 || m_options.maxBytes > kMaxSpoolBytes ||
        m_options.maxItemBytes == 0 || m_options.maxItemBytes > kMaxSpoolItemBytes ||
        m_options.maxItemBytes > m_options.maxBytes) {
        return FailLocked("configured spool bounds are outside supported limits");
    }
    if (m_options.directory.empty() ||
        m_options.directory.find('\0') != std::string::npos ||
        m_options.directory.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return FailLocked("spool directory is empty, contains NUL, or is too long");
    }
    const int pathChars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        m_options.directory.data(), static_cast<int>(m_options.directory.size()),
        nullptr, 0);
    if (pathChars <= 0) return FailLocked("spool directory is not valid UTF-8");
    m_directory.resize(static_cast<size_t>(pathChars));
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            m_options.directory.data(), static_cast<int>(m_options.directory.size()),
            &m_directory[0], pathChars) != pathChars ||
        m_directory.find(L'\0') != std::wstring::npos) {
        m_directory.clear();
        return FailLocked("spool directory is not a valid Windows path string");
    }
    SECURITY_ATTRIBUTES attributes = {};
    attributes.nLength = sizeof(attributes);
    std::string sdError;
    PSECURITY_DESCRIPTOR sd = CreateOwnerOnlyDescriptor(sdError);
    if (sd == nullptr) {
        return FailLocked(sdError.empty()
            ? "could not create spool security descriptor"
            : "could not create spool security descriptor: " + sdError);
    }
    attributes.lpSecurityDescriptor = sd;
    if (!CreateDirectoryW(m_directory.c_str(), &attributes) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        const DWORD code = GetLastError();
        LocalFree(sd);
        return FailLocked(WinError("could not create spool directory", code));
    }
    m_directoryHandle = CreateFileW(m_directory.c_str(),
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE | READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    LocalFree(sd);
    if (m_directoryHandle == INVALID_HANDLE_VALUE) {
        return FailLocked(WinError("could not open spool directory", GetLastError()));
    }
    BY_HANDLE_FILE_INFORMATION info = {};
    if (!GetFileInformationByHandle(m_directoryHandle, &info))
        return FailLocked(WinError("could not inspect spool directory", GetLastError()));
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return FailLocked("spool path is not a regular non-reparse directory");
    std::string error;
    if (!VerifyProtectedObject(m_directoryHandle, true, error)) return FailLocked(error);

    /* A delete-on-close exclusive file serializes writers without leaving an
     * unowned lock artifact after a process crash. The lock carries the
     * owner-pinned descriptor so the elevated default owner (Administrators)
     * cannot fail the owner-only verification below. */
    const std::wstring lockPath = m_directory + L"\\.reporter.lock";
    std::string lockSdError;
    PSECURITY_DESCRIPTOR lockSd = CreateOwnerOnlyDescriptor(lockSdError);
    if (lockSd == nullptr)
        return FailLocked(lockSdError.empty()
            ? "could not create spool lock ACL"
            : "could not create spool lock ACL: " + lockSdError);
    SECURITY_ATTRIBUTES lockAttributes{};
    lockAttributes.nLength = sizeof(lockAttributes);
    lockAttributes.lpSecurityDescriptor = lockSd;
    m_lockHandle = CreateFileW(lockPath.c_str(), DELETE | READ_CONTROL | WRITE_DAC,
        0, &lockAttributes, CREATE_NEW, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_DELETE_ON_CLOSE |
            FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    LocalFree(lockSd);
    if (m_lockHandle == INVALID_HANDLE_VALUE)
        return FailLocked(WinError("spool is locked or lock file is unavailable", GetLastError()));
    if (!VerifyProtectedObject(m_lockHandle, true, error)) return FailLocked(error);
    if (!VerifyChildPath(m_lockHandle, error)) return FailLocked(error);
    return true;
}

bool ReporterSpool::VerifyChildPath(HANDLE handle, std::string& error) const {
    if (m_directoryHandle == INVALID_HANDLE_VALUE) {
        error = "spool directory handle is unavailable";
        return false;
    }
    const std::wstring parent = FinalPath(m_directoryHandle);
    const std::wstring child = FinalPath(handle);
    if (parent.empty() || child.empty()) {
        error = WinError("could not resolve spool object final path", GetLastError());
        return false;
    }
    std::wstring prefix = parent;
    if (!prefix.empty() && prefix.back() != L'\\') prefix.push_back(L'\\');
    if (child.size() <= prefix.size() ||
        CompareStringOrdinal(child.c_str(), static_cast<int>(prefix.size()),
                             prefix.c_str(), static_cast<int>(prefix.size()), TRUE) != CSTR_EQUAL) {
        error = "spool file handle resolves outside its retained directory";
        return false;
    }
    return true;
}

std::wstring ReporterSpool::ItemPath(const std::string& id) const {
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        id.data(), static_cast<int>(id.size()), nullptr, 0);
    if (count <= 0) return {};
    std::wstring wide(static_cast<size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, id.data(),
            static_cast<int>(id.size()), &wide[0], count) != count) return {};
    return m_directory + L"\\" + wide + L".spool";
}

bool ReporterSpool::ReadAndValidate(HANDLE handle, const std::string& filename,
                                    ReporterSpoolItem& item, size_t& storageBytes,
                                    std::string& error) const {
    BY_HANDLE_FILE_INFORMATION info = {};
    if (!GetFileInformationByHandle(handle, &info)) {
        error = WinError("could not inspect spool record", GetLastError());
        return false;
    }
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        error = "spool record is a directory or reparse point";
        return false;
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(handle, &size) || size.QuadPart < 0 ||
        static_cast<uint64_t>(size.QuadPart) > m_options.maxItemBytes + 512) {
        error = "spool record exceeds configured item bound";
        return false;
    }
    if (!VerifyChildPath(handle, error) || !VerifyProtectedObject(handle, true, error)) return false;
    LARGE_INTEGER beginning = {};
    if (!SetFilePointerEx(handle, beginning, nullptr, FILE_BEGIN)) {
        error = WinError("could not seek spool record", GetLastError());
        return false;
    }
    std::array<char, sizeof(kMagic) - 1> magic{};
    DWORD read = 0;
    if (!ReadFile(handle, magic.data(), static_cast<DWORD>(magic.size()), &read, nullptr) ||
        read != magic.size()) {
        error = "spool record has invalid magic";
        return false;
    }
    const std::string foundMagic(magic.data(), magic.size());
    if (foundMagic == kLegacyMagic) {
        error = "legacy spool record has no destination binding; record preserved";
        return false;
    }
    if (foundMagic != kMagic) {
        error = "spool record has invalid magic";
        return false;
    }
    std::string id, destinationFingerprint, lengthText, digest;
    if (!ReadLine(handle, id, 53) || !ReadLine(handle, destinationFingerprint, 64) ||
        !ReadLine(handle, lengthText, 20) || !ReadLine(handle, digest, 64) ||
        id.size() != 53 || destinationFingerprint.size() != 64 || digest.size() != 64) {
        error = "spool record header is incomplete or malformed";
        return false;
    }
    uint64_t sequence = 0, bodyLength = 0;
    bool validId = id.size() == 53 && id[20] == '-';
    if (validId) {
        for (size_t i = 21; i < id.size(); ++i) {
            const unsigned char ch = static_cast<unsigned char>(id[i]);
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
                validId = false;
                break;
            }
        }
    }
    if (destinationFingerprint != m_destinationFingerprint) {
        error = "spool destination fingerprint mismatch; record preserved";
        return false;
    }
    if (!validId || !ParseDecimal(id.substr(0, 20), sequence) || sequence == 0 ||
        !ParseDecimal(lengthText, bodyLength) || bodyLength > m_options.maxItemBytes ||
        filename != id + ".spool") {
        error = "spool record identity or body length is invalid";
        return false;
    }
    std::string body;
    if (!ReadAll(handle, body, static_cast<size_t>(bodyLength))) {
        error = "spool record body is truncated or has trailing bytes";
        return false;
    }
    if (Hash(id + "|" + destinationFingerprint + "|" + body) != digest) {
        error = "spool record digest verification failed";
        return false;
    }
    item.id = id;
    item.body = std::move(body);
    storageBytes = static_cast<size_t>(size.QuadPart);
    return true;
}

bool ReporterSpool::Open(std::vector<ReporterSpoolItem>& recovered) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_opened) return !m_failed;
    if (m_failed) return false;
    if (m_destinationFingerprint.empty())
        return FailLocked("could not fingerprint Reporter destination");
    if (!PrepareDirectoryLocked()) return false;

    WIN32_FIND_DATAW entry = {};
    HANDLE find = FindFirstFileW((m_directory + L"\\*.spool").c_str(), &entry);
    if (find != INVALID_HANDLE_VALUE) {
        DWORD enumerationError = ERROR_NO_MORE_FILES;
        BOOL hasEntry = TRUE;
        while (hasEntry) {
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                FindClose(find);
                return FailLocked("unexpected directory with spool record extension");
            }
            const std::wstring path = m_directory + L"\\" + entry.cFileName;
            HANDLE file = CreateFileW(path.c_str(), GENERIC_READ | DELETE | READ_CONTROL |
                    WRITE_DAC, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (file == INVALID_HANDLE_VALUE) {
                const DWORD code = GetLastError();
                FindClose(find);
                return FailLocked(WinError("could not open recovered spool record", code));
            }
            const int chars = static_cast<int>(wcslen(entry.cFileName));
            const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                entry.cFileName, chars, nullptr, 0, nullptr, nullptr);
            std::string filename;
            if (bytes > 0) {
                filename.resize(static_cast<size_t>(bytes));
                WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                    entry.cFileName, chars, &filename[0], bytes, nullptr, nullptr);
            }
            ReporterSpoolItem item;
            size_t storageBytes = 0;
            std::string error;
            if (bytes <= 0 || !ReadAndValidate(file, filename, item, storageBytes, error)) {
                CloseHandle(file);
                FindClose(find);
                return FailLocked(error.empty() ? "spool filename is invalid UTF-8" : error);
            }
            if (m_entries.size() >= m_options.maxRecords ||
                storageBytes > m_options.maxBytes - m_storageBytes) {
                CloseHandle(file);
                FindClose(find);
                return FailLocked("recovered spool exceeds configured capacity");
            }
            uint64_t sequence = 0;
            if (!ParseDecimal(item.id.substr(0, 20), sequence) || sequence >= m_nextSequence) {
                if (sequence == std::numeric_limits<uint64_t>::max()) {
                    CloseHandle(file);
                    FindClose(find);
                    return FailLocked("spool sequence space is exhausted");
                }
                m_nextSequence = sequence + 1;
            }
            m_storageBytes += storageBytes;
            m_entries.emplace(item.id, Entry{file, storageBytes, item.body});
            recovered.push_back(std::move(item));
            hasEntry = FindNextFileW(find, &entry);
            if (!hasEntry) enumerationError = GetLastError();
        }
        FindClose(find);
        if (enumerationError != ERROR_NO_MORE_FILES)
            return FailLocked(WinError("spool recovery enumeration failed", enumerationError));
    } else if (GetLastError() != ERROR_FILE_NOT_FOUND) {
        return FailLocked(WinError("could not enumerate spool records", GetLastError()));
    }
    std::sort(recovered.begin(), recovered.end(),
        [](const ReporterSpoolItem& a, const ReporterSpoolItem& b) { return a.id < b.id; });
    m_opened = true;
    m_status = "ready";
    return true;
}

bool ReporterSpool::Store(const std::string& body, ReporterSpoolItem& item) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_failed || !m_opened) return false;
    if (body.size() > m_options.maxItemBytes ||
        m_entries.size() >= m_options.maxRecords ||
        m_nextSequence == std::numeric_limits<uint64_t>::max()) return false;
    const std::string id = MakeId(m_nextSequence);
    if (id.empty()) return FailLocked("could not generate unique spool item identity");
    const std::string digest = Hash(id + "|" + m_destinationFingerprint + "|" + body);
    if (digest.empty()) return FailLocked("could not calculate spool record digest");
    const std::string header = std::string(kMagic) + id + "\n" +
        m_destinationFingerprint + "\n" + std::to_string(body.size()) + "\n" +
        digest + "\n";
    const size_t total = header.size() + body.size();
    if (total > m_options.maxBytes || total > m_options.maxBytes - m_storageBytes)
        return false;
    const std::wstring path = ItemPath(id);
    if (path.empty()) return FailLocked("could not form spool record path");

    std::string aclError;
    PSECURITY_DESCRIPTOR sd = CreateOwnerOnlyDescriptor(aclError);
    if (sd == nullptr)
        return FailLocked(aclError.empty()
            ? "could not create spool record ACL"
            : "could not create spool record ACL: " + aclError);
    SECURITY_ATTRIBUTES attributes = {};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = sd;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE |
            READ_CONTROL | WRITE_DAC, FILE_SHARE_READ, &attributes, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    LocalFree(sd);
    if (file == INVALID_HANDLE_VALUE)
        return FailLocked(WinError("could not create unique spool record", GetLastError()));

    std::string error;
    BY_HANDLE_FILE_INFORMATION info = {};
    bool ok = GetFileInformationByHandle(file, &info) &&
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
        VerifyChildPath(file, error) && VerifyProtectedObject(file, true, error) &&
        WriteAll(file, header.data(), header.size()) &&
        WriteAll(file, body.data(), body.size()) && FlushFileBuffers(file);
    if (!ok) {
        DWORD code = GetLastError();
        if (error.empty()) error = WinError("spool record write or FlushFileBuffers failed", code);
        FILE_DISPOSITION_INFO disposition = {TRUE};
        SetFileInformationByHandle(file, FileDispositionInfo, &disposition,
                                   sizeof(disposition));
        CloseHandle(file);
        return FailLocked(error);
    }
    item.id = id;
    item.body = body;
    m_entries.emplace(id, Entry{file, total, body});
    m_storageBytes += total;
    ++m_nextSequence;
    return true;
}

bool ReporterSpool::Acknowledge(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_failed || !m_opened) return false;
    if (m_options.beforeAcknowledge) {
        bool proceed = false;
        try {
            proceed = m_options.beforeAcknowledge();
        } catch (...) {
            return FailLocked("pre-acknowledgment failure seam threw");
        }
        if (!proceed)
            return FailLocked("pre-acknowledgment failure seam refused deletion");
    }
    auto found = m_entries.find(id);
    if (found == m_entries.end()) return FailLocked("acknowledgment refers to unknown spool item");
    FILE_DISPOSITION_INFO disposition = {TRUE};
    if (!SetFileInformationByHandle(found->second.handle, FileDispositionInfo,
                                    &disposition, sizeof(disposition)))
        return FailLocked(WinError("could not delete acknowledged spool item", GetLastError()));
    CloseHandle(found->second.handle);
    m_storageBytes -= found->second.bytes;
    m_entries.erase(found);
    return true;
}

void ReporterSpool::SetFailed(const std::string& reason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    FailLocked(reason);
}

std::string ReporterSpool::GetStatus() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_status;
}

uint64_t ReporterSpool::ErrorCount() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_errorCount;
}

size_t ReporterSpool::RecordCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries.size();
}

size_t ReporterSpool::StorageBytes() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_storageBytes;
}

} // namespace edr
