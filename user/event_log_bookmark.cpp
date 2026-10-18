/*
 * event_log_bookmark.cpp - protected atomic WinEvt checkpoint storage and
 * contiguous-delivery tracking.
 */
#include "event_log_bookmark.h"
#include "event_bus.h"
#include "owner_only_sd.h"

#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cwctype>
#include <iterator>
#include <limits>
#include <vector>

namespace edr {
namespace {

constexpr char kMagic[] = "EDRBMK01";
constexpr size_t kHeaderBytes = 16;
constexpr size_t kMaxCheckpointBytes = 256 * 1024;
constexpr DWORD kBookmarkStale = 15011;          // ERROR_EVT_QUERY_RESULT_STALE
constexpr DWORD kBookmarkInvalidPosition = 15012; // ERROR_EVT_QUERY_RESULT_INVALID_POSITION

std::string WinError(const char* operation, DWORD error) {
    return std::string(operation) + " (win32=" + std::to_string(error) + ")";
}

std::string NormalizeOwnerOnlyDaclSddl(const char* sddl) {
    std::string normalized = sddl ? sddl : "";
    if (normalized.compare(0, 5, "D:PAI") == 0)
        normalized.replace(0, 5, "D:P");
    return normalized;
}

bool HasProtectedOwnerOnlyDacl(HANDLE file, std::string& error) {
    PACL dacl = nullptr;
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD query = GetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr,
        &descriptor);
    if (query != ERROR_SUCCESS || descriptor == nullptr || dacl == nullptr) {
        error = WinError("GetSecurityInfo checkpoint DACL failed", query);
        if (descriptor != nullptr) LocalFree(descriptor);
        return false;
    }

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    const BOOL readControl =
        GetSecurityDescriptorControl(descriptor, &control, &revision);
    LPSTR sddl = nullptr;
    const BOOL converted = ConvertSecurityDescriptorToStringSecurityDescriptorA(
        descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl,
        nullptr);
    const std::string normalized = converted != FALSE && sddl != nullptr
        ? NormalizeOwnerOnlyDaclSddl(sddl) : std::string();
    HANDLE token = nullptr;
    bool ownerMatches = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        if (needed != 0) {
            std::vector<unsigned char> userBuffer(needed);
            if (GetTokenInformation(token, TokenUser, userBuffer.data(),
                                    needed, &needed)) {
                const auto* user = reinterpret_cast<const TOKEN_USER*>(
                    userBuffer.data());
                ownerMatches = owner != nullptr &&
                    EqualSid(owner, user->User.Sid) != FALSE;
            }
        }
        CloseHandle(token);
    }
    const bool verified = ownerMatches && readControl != FALSE &&
        (control & SE_DACL_PROTECTED) != 0 && converted != FALSE &&
        sddl != nullptr && normalized == "D:P(A;;FA;;;OW)";
    if (!verified) {
        const DWORD failure = !ownerMatches ? ERROR_ACCESS_DENIED :
            (readControl == FALSE || converted == FALSE
                ? GetLastError() : ERROR_INVALID_ACL);
        error = WinError("checkpoint owner/DACL is not current-owner-only",
                         failure);
        if (sddl != nullptr) error += ": " + std::string(sddl);
    }
    if (sddl != nullptr) LocalFree(sddl);
    LocalFree(descriptor);
    return verified;
}

class HandleGuard {
public:
    explicit HandleGuard(HANDLE handle = INVALID_HANDLE_VALUE) : m_handle(handle) {}
    ~HandleGuard() { if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) CloseHandle(m_handle); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HANDLE get() const { return m_handle; }
private:
    HANDLE m_handle;
};

class HandleVectorGuard {
public:
    HandleVectorGuard() = default;
    explicit HandleVectorGuard(std::vector<HANDLE>&& handles)
        : m_handles(std::move(handles)) {}
    ~HandleVectorGuard() {
        for (HANDLE handle : m_handles) {
            if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
                CloseHandle(handle);
        }
    }
    HandleVectorGuard(const HandleVectorGuard&) = delete;
    HandleVectorGuard& operator=(const HandleVectorGuard&) = delete;

    bool Add(HANDLE handle, std::string& error) {
        try {
            m_handles.push_back(handle);
        } catch (...) {
            CloseHandle(handle);
            error = "could not retain checkpoint path component handles";
            return false;
        }
        return true;
    }

    HANDLE Leaf() const {
        return m_handles.empty() ? INVALID_HANDLE_VALUE : m_handles.back();
    }

    void ReleaseTo(std::vector<HANDLE>& output) {
        output = std::move(m_handles);
        m_handles.clear();
    }

private:
    std::vector<HANDLE> m_handles;
};

class EvtHandleGuard {
public:
    EvtHandleGuard(EVT_HANDLE handle,
                   const std::function<void(EVT_HANDLE)>& close)
        : m_handle(handle), m_close(&close) {}
    ~EvtHandleGuard() {
        if (m_handle == nullptr || m_close == nullptr) return;
        try { (*m_close)(m_handle); } catch (...) {}
    }
    EvtHandleGuard(const EvtHandleGuard&) = delete;
    EvtHandleGuard& operator=(const EvtHandleGuard&) = delete;
private:
    EVT_HANDLE m_handle;
    const std::function<void(EVT_HANDLE)>* m_close;
};

bool CreateOwnerOnlySecurityDescriptor(PSECURITY_DESCRIPTOR& descriptor,
                                       std::string& error) {
    /* The owner must be pinned to the token user: the platform default is the
     * Administrators group for elevated tokens, and HasProtectedOwnerOnlyDacl
     * compares the object owner against the token user. */
    descriptor = CreateOwnerOnlyDescriptor(error);
    if (descriptor == nullptr) {
        if (error.empty())
            error = "create checkpoint owner-only descriptor failed";
        return false;
    }
    return true;
}

bool NormalizeCheckpointPath(std::wstring& checkpointPath,
                             std::wstring& directory,
                             std::string& error) {
    if (checkpointPath.empty() || checkpointPath.find(L'\0') !=
        std::wstring::npos) {
        error = "checkpoint path is empty or contains NUL";
        return false;
    }
    const DWORD needed = GetFullPathNameW(checkpointPath.c_str(), 0, nullptr,
                                          nullptr);
    if (needed == 0 || needed > 32767) {
        error = WinError("resolve checkpoint path failed", GetLastError());
        return false;
    }
    std::vector<wchar_t> fullBuffer(static_cast<size_t>(needed) + 1);
    const DWORD copied = GetFullPathNameW(checkpointPath.c_str(),
        static_cast<DWORD>(fullBuffer.size()), fullBuffer.data(), nullptr);
    if (copied == 0 || copied >= fullBuffer.size()) {
        error = WinError("resolve checkpoint path failed", GetLastError());
        return false;
    }
    std::wstring full(fullBuffer.data(), copied);
    std::replace(full.begin(), full.end(), L'/', L'\\');
    if (full.size() < 4 || !std::iswalpha(full[0]) || full[1] != L':' ||
        full[2] != L'\\' || full.rfind(L"\\\\", 0) == 0 ||
        full.rfind(L"\\\\?\\", 0) == 0) {
        error = "checkpoint path must be an absolute local drive path";
        return false;
    }
    const size_t separator = full.find_last_of(L'\\');
    if (separator == std::wstring::npos || separator < 3 ||
        separator + 1 >= full.size()) {
        error = "checkpoint path must name a file below a directory";
        return false;
    }
    const std::wstring filename = full.substr(separator + 1);
    if (filename == L"." || filename == L".." ||
        filename.find(L':') != std::wstring::npos) {
        error = "checkpoint filename is invalid";
        return false;
    }
    directory.assign(full, 0, separator);
    checkpointPath = std::move(full);
    return true;
}

bool OpenSecureCheckpointDirectory(std::wstring& checkpointPath,
                                   std::vector<HANDLE>& directoryHandles,
                                   std::string& error) {
    directoryHandles.clear();
    std::wstring directory;
    if (!NormalizeCheckpointPath(checkpointPath, directory, error))
        return false;

    HANDLE root = CreateFileW(directory.substr(0, 3).c_str(),
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE |
        FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (root == INVALID_HANDLE_VALUE) {
        error = WinError("open checkpoint volume root failed", GetLastError());
        return false;
    }
    BY_HANDLE_FILE_INFORMATION rootInfo{};
    const bool rootOk = GetFileInformationByHandle(root, &rootInfo) != FALSE &&
        (rootInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (rootInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    const DWORD rootError = rootOk ? ERROR_SUCCESS : GetLastError();
    CloseHandle(root);
    if (!rootOk) {
        error = WinError("checkpoint volume root is not a real directory",
                         rootError);
        return false;
    }

    /* Hold every movable component from the drive root to the protected leaf
     * without FILE_SHARE_DELETE until the caller finishes the complete
     * checkpoint read/replace. This prevents the absolute path from being
     * rebound by renaming an ancestor during an operation. The volume root is
     * checked separately above; Windows does not permit renaming that root. */
    HandleVectorGuard retained;
    for (size_t end = 3; end <= directory.size(); ++end) {
        if (end != directory.size() && directory[end] != L'\\') continue;
        if (end == 3) continue;
        const bool isLeaf = end == directory.size();
        const std::wstring component = directory.substr(0, end);
        HANDLE probe = CreateFileW(component.c_str(), FILE_LIST_DIRECTORY |
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
            FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        const DWORD openError = probe == INVALID_HANDLE_VALUE
            ? GetLastError() : ERROR_SUCCESS;
        if (probe == INVALID_HANDLE_VALUE && isLeaf &&
            (openError == ERROR_PATH_NOT_FOUND ||
             openError == ERROR_FILE_NOT_FOUND)) {
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            if (!CreateOwnerOnlySecurityDescriptor(descriptor, error))
                return false;
            SECURITY_ATTRIBUTES attributes{};
            attributes.nLength = sizeof(attributes);
            attributes.lpSecurityDescriptor = descriptor;
            const BOOL created = CreateDirectoryW(component.c_str(),
                                                   &attributes);
            const DWORD createError = created ? ERROR_SUCCESS : GetLastError();
            LocalFree(descriptor);
            if (!created && createError != ERROR_ALREADY_EXISTS) {
                error = WinError("create protected checkpoint directory failed",
                                 createError);
                return false;
            }
            probe = CreateFileW(component.c_str(), FILE_LIST_DIRECTORY |
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        }
        if (probe == INVALID_HANDLE_VALUE) {
            error = WinError("open checkpoint directory component failed",
                             GetLastError());
            return false;
        }
        BY_HANDLE_FILE_INFORMATION info{};
        const bool infoOk = GetFileInformationByHandle(probe, &info) != FALSE;
        if (!infoOk || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            const DWORD failure = infoOk ? ERROR_REPARSE_TAG_INVALID
                                         : GetLastError();
            CloseHandle(probe);
            error = WinError("checkpoint directory component is not a real directory",
                             failure);
            return false;
        }
        if (!retained.Add(probe, error)) return false;
        if (isLeaf) {
            if (!HasProtectedOwnerOnlyDacl(probe, error)) {
                return false;
            }
        }
    }
    if (retained.Leaf() == INVALID_HANDLE_VALUE) {
        error = "checkpoint parent directory could not be opened";
        return false;
    }
    retained.ReleaseTo(directoryHandles);
    return true;
}

bool WideToUtf8(const std::wstring& input, std::string& output) {
    output.clear();
    if (input.empty()) return true;
    if (input.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    const int inputLength = static_cast<int>(input.size());
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        input.data(), inputLength, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return false;
    output.resize(static_cast<size_t>(needed));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(),
        inputLength, output.data(), needed, nullptr, nullptr) == needed;
}

bool Utf8ToWide(const std::string& input, std::wstring& output) {
    output.clear();
    if (input.empty()) return true;
    if (input.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    const int inputLength = static_cast<int>(input.size());
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        input.data(), inputLength, nullptr, 0);
    if (needed <= 0) return false;
    output.resize(static_cast<size_t>(needed));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
        inputLength, output.data(), needed) == needed;
}

uint32_t Crc32(const char* bytes, size_t size) {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= static_cast<unsigned char>(bytes[i]);
        for (unsigned int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u &
                static_cast<uint32_t>(-static_cast<int32_t>(crc & 1u)));
    }
    return ~crc;
}

void AppendU32(std::string& bytes, uint32_t value) {
    for (unsigned int shift = 0; shift < 32; shift += 8)
        bytes.push_back(static_cast<char>((value >> shift) & 0xffu));
}

uint32_t ReadU32(const char* bytes) {
    return static_cast<uint32_t>(static_cast<unsigned char>(bytes[0])) |
        (static_cast<uint32_t>(static_cast<unsigned char>(bytes[1])) << 8) |
        (static_cast<uint32_t>(static_cast<unsigned char>(bytes[2])) << 16) |
        (static_cast<uint32_t>(static_cast<unsigned char>(bytes[3])) << 24);
}

void AppendU64(std::string& bytes, uint64_t value) {
    for (unsigned int shift = 0; shift < 64; shift += 8)
        bytes.push_back(static_cast<char>((value >> shift) & 0xffu));
}

uint64_t ReadU64(const char* bytes) {
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= static_cast<uint64_t>(
            static_cast<unsigned char>(bytes[i])) << (i * 8);
    return value;
}

bool ReadExact(HANDLE file, char* output, size_t bytes, std::string& error) {
    size_t offset = 0;
    while (offset < bytes) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(
            bytes - offset, std::numeric_limits<DWORD>::max()));
        DWORD read = 0;
        if (!ReadFile(file, output + offset, chunk, &read, nullptr)) {
            error = WinError("ReadFile checkpoint failed", GetLastError());
            return false;
        }
        if (read == 0) {
            error = "checkpoint changed or was truncated during read";
            return false;
        }
        offset += read;
    }
    return true;
}

bool WriteExact(HANDLE file, const std::string& bytes, std::string& error) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(
            bytes.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(file, bytes.data() + offset, chunk, &written, nullptr)) {
            error = WinError("WriteFile checkpoint failed", GetLastError());
            return false;
        }
        if (written == 0) {
            error = "WriteFile checkpoint made no progress";
            return false;
        }
        offset += written;
    }
    return true;
}

bool ExtractElement(const std::wstring& xml, const wchar_t* name,
                    std::wstring& value) {
    const std::wstring open = std::wstring(L"<") + name + L">";
    const std::wstring close = std::wstring(L"</") + name + L">";
    const size_t start = xml.find(open);
    if (start == std::wstring::npos) return false;
    const size_t content = start + open.size();
    const size_t end = xml.find(close, content);
    if (end == std::wstring::npos || end == content) return false;
    value.assign(xml, content, end - content);
    return true;
}

bool EventIdentity(EVT_HANDLE event, std::wstring& channel, uint64_t& recordId) {
    DWORD needed = 0;
    DWORD properties = 0;
    if (EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &needed,
                  &properties) == FALSE &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
    if (needed < sizeof(wchar_t) || needed > 1024 * 1024) return false;
    std::vector<wchar_t> buffer((needed + sizeof(wchar_t) - 1) /
                                sizeof(wchar_t));
    if (EvtRender(nullptr, event, EvtRenderEventXml, needed, buffer.data(),
                  &needed, &properties) == FALSE) return false;
    const std::wstring xml(buffer.data());
    std::wstring recordText;
    if (!ExtractElement(xml, L"Channel", channel) ||
        !ExtractElement(xml, L"EventRecordID", recordText)) return false;
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::wcstoull(recordText.c_str(), &end, 10);
    if (errno == ERANGE || end == recordText.c_str() || *end != L'\0' ||
        parsed == 0) return false;
    recordId = static_cast<uint64_t>(parsed);
    return true;
}

EVT_HANDLE CreateBookmark(const wchar_t* xml) {
    return EvtCreateBookmark(xml);
}

bool UpdateBookmark(EVT_HANDLE bookmark, EVT_HANDLE event) {
    return EvtUpdateBookmark(bookmark, event) != FALSE;
}

bool RenderBookmark(EVT_HANDLE bookmark, std::wstring& xml) {
    DWORD needed = 0;
    DWORD properties = 0;
    if (EvtRender(nullptr, bookmark, EvtRenderBookmark, 0, nullptr, &needed,
                  &properties) == FALSE &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
    if (needed < sizeof(wchar_t) || needed > 1024 * 1024) return false;
    std::vector<wchar_t> buffer((needed + sizeof(wchar_t) - 1) /
                                sizeof(wchar_t));
    if (EvtRender(nullptr, bookmark, EvtRenderBookmark, needed, buffer.data(),
                  &needed, &properties) == FALSE) return false;
    xml.assign(buffer.data());
    return true;
}

void CloseBookmark(EVT_HANDLE handle) {
    if (handle != nullptr) EvtClose(handle);
}

bool EncodeCheckpoint(const std::wstring& channel, uint64_t recordId,
                      const std::wstring& bookmarkXml,
                      std::string& bytes, std::string& error) {
    std::string channelUtf8;
    std::string bookmarkUtf8;
    if (!WideToUtf8(channel, channelUtf8) ||
        !WideToUtf8(bookmarkXml, bookmarkUtf8) || channelUtf8.empty() ||
        bookmarkUtf8.empty() || channelUtf8.find('\0') != std::string::npos ||
        bookmarkUtf8.find('\0') != std::string::npos) {
        error = "checkpoint channel or bookmark is not valid UTF-8";
        return false;
    }
    std::string payload;
    payload.reserve(channelUtf8.size() + bookmarkUtf8.size() + 32);
    payload += channelUtf8;
    payload.push_back('\0');
    payload += std::to_string(recordId);
    payload.push_back('\0');
    payload += bookmarkUtf8;
    if (payload.size() > kMaxCheckpointBytes - kHeaderBytes ||
        payload.size() > std::numeric_limits<uint32_t>::max()) {
        error = "checkpoint payload exceeds the safe size limit";
        return false;
    }

    bytes.assign(kMagic, sizeof(kMagic) - 1);
    AppendU32(bytes, static_cast<uint32_t>(payload.size()));
    AppendU32(bytes, Crc32(payload.data(), payload.size()));
    bytes += payload;
    return true;
}

bool DecodeCheckpoint(const std::string& bytes, std::wstring& channel,
                      uint64_t& recordId, std::wstring& bookmarkXml,
                      std::string& error) {
    if (bytes.size() < kHeaderBytes || bytes.size() > kMaxCheckpointBytes ||
        bytes.compare(0, sizeof(kMagic) - 1, kMagic) != 0) {
        error = "checkpoint magic or size is invalid";
        return false;
    }
    const uint32_t payloadSize = ReadU32(bytes.data() + 8);
    const uint32_t expectedCrc = ReadU32(bytes.data() + 12);
    if (payloadSize != bytes.size() - kHeaderBytes ||
        Crc32(bytes.data() + kHeaderBytes, payloadSize) != expectedCrc) {
        error = "checkpoint length or checksum is invalid";
        return false;
    }
    const char* payload = bytes.data() + kHeaderBytes;
    const size_t channelEnd = std::string(payload, payloadSize).find('\0');
    if (channelEnd == std::string::npos || channelEnd == 0) {
        error = "checkpoint channel field is malformed";
        return false;
    }
    const size_t recordStart = channelEnd + 1;
    const size_t recordEndRelative = std::string(payload + recordStart,
        payloadSize - recordStart).find('\0');
    if (recordEndRelative == std::string::npos || recordEndRelative == 0) {
        error = "checkpoint record id field is malformed";
        return false;
    }
    const size_t bookmarkStart = recordStart + recordEndRelative + 1;
    if (bookmarkStart >= payloadSize) {
        error = "checkpoint bookmark field is empty";
        return false;
    }

    const std::string channelUtf8(payload, channelEnd);
    const std::string recordText(payload + recordStart, recordEndRelative);
    const std::string bookmarkUtf8(payload + bookmarkStart,
                                   payloadSize - bookmarkStart);
    if (recordText.find_first_not_of("0123456789") != std::string::npos) {
        error = "checkpoint record id is not an unsigned decimal integer";
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed =
        std::strtoull(recordText.c_str(), &end, 10);
    if (errno == ERANGE || end == recordText.c_str() || *end != '\0' ||
        parsed == 0) {
        error = "checkpoint record id is outside the supported range";
        return false;
    }
    if (!Utf8ToWide(channelUtf8, channel) ||
        !Utf8ToWide(bookmarkUtf8, bookmarkXml)) {
        error = "checkpoint text is not valid UTF-8";
        return false;
    }
    recordId = static_cast<uint64_t>(parsed);
    return true;
}

} // namespace

struct EventLogBookmarkTokenGroup::State {
    explicit State(std::shared_ptr<EventLogBookmarkStore> bookmarkStore)
        : store(std::move(bookmarkStore)) {}

    ~State() { (void)Complete(false); }

    bool Add(EventLogBookmarkStore::Token token) {
        std::lock_guard<std::mutex> lock(mutex);
        if (settled || !store || token == 0) return false;
        try {
            tokens.push_back(token);
        } catch (...) {
            return false;
        }
        return true;
    }

    bool Complete(bool accepted) {
        std::vector<EventLogBookmarkStore::Token> completedTokens;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (settled) return true;
            settled = true;
            completedTokens.swap(tokens);
        }

        if (!store || completedTokens.empty()) return false;
        bool result = true;
        for (const auto token : completedTokens) {
            try {
                result = store->Complete(token, accepted) && result;
            } catch (...) {
                result = false;
            }
        }
        return result;
    }

    size_t Size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return tokens.size();
    }

    std::shared_ptr<EventLogBookmarkStore> store;
    mutable std::mutex mutex;
    std::vector<EventLogBookmarkStore::Token> tokens;
    bool settled = false;
};

EventLogBookmarkTokenGroup::EventLogBookmarkTokenGroup(
    std::shared_ptr<EventLogBookmarkStore> store)
    : m_state(std::make_shared<State>(std::move(store))) {}

EventLogBookmarkTokenGroup::~EventLogBookmarkTokenGroup() {
    (void)Fail();
}

bool EventLogBookmarkTokenGroup::Add(EventLogBookmarkStore::Token token) {
    if (!m_state || !m_state->Add(token)) {
        (void)Fail();
        return false;
    }
    return true;
}

bool EventLogBookmarkTokenGroup::Attach(Event& derivedEvent) {
    if (!m_state || derivedEvent.onConsumed || m_state->Size() == 0)
        return false;
    const auto state = m_state;
    try {
        derivedEvent.onConsumed = [state](bool accepted) {
            (void)state->Complete(accepted);
        };
    } catch (...) {
        return false;
    }
    m_state.reset();
    return true;
}

bool EventLogBookmarkTokenGroup::Fail() {
    if (!m_state) return true;
    const bool result = m_state->Complete(false);
    m_state.reset();
    return result;
}

size_t EventLogBookmarkTokenGroup::size() const {
    return m_state ? m_state->Size() : 0;
}

EventLogBookmarkStore::EventLogBookmarkStore(
    std::wstring checkpointPath, std::wstring channel, bool enabled,
    size_t maxPendingRecords, WinEvtApi winEvt,
    CheckpointDirectoryOpenedFn directoryOpened)
    : m_checkpointPath(std::move(checkpointPath)),
      m_channel(std::move(channel)), m_enabled(enabled),
      m_maxPendingRecords(maxPendingRecords), m_winEvt(std::move(winEvt)),
      m_checkpointDirectoryOpened(std::move(directoryOpened)),
      m_state(enabled ? State::Empty : State::Disabled) {
    if (!m_winEvt.createBookmark) m_winEvt.createBookmark = CreateBookmark;
    if (!m_winEvt.updateBookmark) m_winEvt.updateBookmark = UpdateBookmark;
    if (!m_winEvt.renderBookmark) m_winEvt.renderBookmark = RenderBookmark;
    if (!m_winEvt.eventIdentity) m_winEvt.eventIdentity = EventIdentity;
    if (!m_winEvt.close) m_winEvt.close = CloseBookmark;
}

EventLogBookmarkStore::~EventLogBookmarkStore() = default;

bool EventLogBookmarkStore::IsUsableState() const {
    return m_state == State::Disabled || m_state == State::Empty ||
           m_state == State::Ready;
}

void EventLogBookmarkStore::SetFailure(State state,
                                       const std::string& detail) {
    m_state = state;
    m_lastError = detail;
    m_pending.clear();
}

bool EventLogBookmarkStore::Open(std::string* error) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_opened) {
        if (error != nullptr) *error = m_lastError;
        return IsUsableState();
    }
    m_opened = true;
    if (!m_enabled) {
        m_state = State::Disabled;
        if (error != nullptr) error->clear();
        return true;
    }
    if (m_checkpointPath.empty() || m_channel.empty() ||
        m_maxPendingRecords == 0) {
        SetFailure(State::Unavailable,
                   "enabled bookmark replay requires a path, channel, and pending bound");
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    std::string failure;
    bool loaded = false;
    try {
        loaded = LoadCheckpoint(failure);
    } catch (...) {
        failure = "loading checkpoint raised an exception";
    }
    if (!loaded) {
        const State state = failure.rfind("checkpoint is missing", 0) == 0
            ? State::Empty : State::Corrupt;
        if (state == State::Corrupt) SetFailure(state, failure);
        else {
            m_state = State::Empty;
            m_lastError.clear();
        }
        if (error != nullptr) *error = m_lastError;
        return state != State::Corrupt;
    }
    m_state = State::Ready;
    m_lastError.clear();
    if (error != nullptr) error->clear();
    return true;
}

bool EventLogBookmarkStore::PrepareSubscription(DWORD& flags,
                                                EVT_HANDLE& bookmark) {
    std::lock_guard<std::mutex> lock(m_mutex);
    flags = 0;
    bookmark = nullptr;
    if (!IsUsableState()) return false;
    if (m_state == State::Disabled) {
        flags = EvtSubscribeToFutureEvents;
        return true;
    }
    if (m_state == State::Empty) {
        flags = EvtSubscribeStartAtOldestRecord | EvtSubscribeStrict;
        return true;
    }
    try {
        bookmark = m_winEvt.createBookmark(m_bookmarkXml.c_str());
    } catch (...) {
        SetFailure(State::Unavailable,
                   "EvtCreateBookmark callback threw an exception");
        return false;
    }
    if (bookmark == nullptr) {
        SetFailure(State::Corrupt,
            WinError("EvtCreateBookmark failed for validated checkpoint",
                     GetLastError()));
        return false;
    }
    flags = EvtSubscribeStartAfterBookmark | EvtSubscribeStrict;
    return true;
}

bool EventLogBookmarkStore::Capture(EVT_HANDLE event, Token& token,
                                   std::string* error) {
    std::lock_guard<std::mutex> lock(m_mutex);
    token = 0;
    if (m_state == State::Disabled) {
        if (error != nullptr) *error = "bookmark replay is disabled";
        return false;
    }
    if (m_state != State::Empty && m_state != State::Ready) {
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    if (m_pending.size() >= m_maxPendingRecords) {
        SetFailure(State::Gap, "bookmark in-flight record bound was exceeded");
        if (error != nullptr) *error = m_lastError;
        return false;
    }

    std::wstring eventChannel;
    uint64_t recordId = 0;
    bool hasIdentity = false;
    try {
        hasIdentity = m_winEvt.eventIdentity(event, eventChannel, recordId);
    } catch (...) {
        SetFailure(State::Unavailable,
                   "Event Log identity callback threw an exception");
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    if (!hasIdentity) {
        SetFailure(State::Unavailable,
            WinError("could not read Event Log channel/record identity",
                     GetLastError()));
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    if (eventChannel != m_channel || recordId == 0) {
        SetFailure(State::Reset,
            "event channel or record identity did not match the checkpoint stream");
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    if (recordId <= m_lastObservedRecordId) {
        SetFailure(State::Reset,
            "Event Log record id did not advance beyond the last observed record");
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    if (m_nextToken == 0 || m_nextToken == std::numeric_limits<Token>::max()) {
        SetFailure(State::Gap, "bookmark delivery token space is exhausted");
        if (error != nullptr) *error = m_lastError;
        return false;
    }

    EVT_HANDLE evtBookmark = nullptr;
    try {
        evtBookmark = m_winEvt.createBookmark(nullptr);
    } catch (...) {
        SetFailure(State::Unavailable,
                   "EvtCreateBookmark callback threw an exception");
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    if (evtBookmark == nullptr) {
        SetFailure(State::Unavailable,
            WinError("EvtCreateBookmark failed", GetLastError()));
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    EvtHandleGuard bookmarkGuard(evtBookmark, m_winEvt.close);
    bool updated = false;
    std::wstring xml;
    bool rendered = false;
    try {
        updated = m_winEvt.updateBookmark(evtBookmark, event);
        rendered = updated && m_winEvt.renderBookmark(evtBookmark, xml);
    } catch (...) {
        SetFailure(State::Unavailable,
                   "WinEvt bookmark update/render callback threw an exception");
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    if (!updated || !rendered) {
        SetFailure(State::Unavailable,
            WinError(updated ? "EvtRender bookmark failed"
                             : "EvtUpdateBookmark failed", GetLastError()));
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    std::wstring bookmarkChannel;
    uint64_t bookmarkRecordId = 0;
    if (!ParseBookmarkIdentity(xml, bookmarkChannel, bookmarkRecordId) ||
        bookmarkChannel != m_channel || bookmarkRecordId != recordId) {
        SetFailure(State::Unavailable,
                   "rendered bookmark identity did not match the delivered event");
        if (error != nullptr) *error = m_lastError;
        return false;
    }

    token = m_nextToken++;
    m_pending.emplace(token, PendingRecord{recordId, std::move(xml), false});
    m_lastObservedRecordId = recordId;
    if (m_state == State::Empty) m_state = State::Ready;
    if (error != nullptr) error->clear();
    return true;
}

bool EventLogBookmarkStore::Complete(Token token, bool accepted,
                                     std::string* error) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != State::Empty && m_state != State::Ready) {
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    auto found = m_pending.find(token);
    if (found == m_pending.end()) {
        SetFailure(State::Gap, "unknown or already completed bookmark token");
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    if (!accepted) {
        SetFailure(State::Gap,
                   "source event was dropped or failed before sink consumption");
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    found->second.completed = true;

    auto first = m_pending.find(m_nextCommitToken);
    if (first == m_pending.end() || !first->second.completed) {
        if (error != nullptr) error->clear();
        return true;
    }
    auto last = first;
    while (last != m_pending.end() && last->second.completed) {
        auto next = std::next(last);
        if (next == m_pending.end() || next->first != last->first + 1 ||
            !next->second.completed)
            break;
        last = next;
    }

    std::string failure;
    bool saved = false;
    try {
        saved = SaveCheckpoint(last->second.recordId,
                              last->second.bookmarkXml, failure);
    } catch (...) {
        failure = "saving checkpoint raised an exception";
    }
    if (!saved) {
        SetFailure(State::PersistenceFailure, failure);
        if (error != nullptr) *error = m_lastError;
        return false;
    }
    m_lastCommittedRecordId = last->second.recordId;
    m_bookmarkXml = last->second.bookmarkXml;
    const Token nextCommit = last->first + 1;
    m_pending.erase(m_pending.begin(), std::next(last));
    m_nextCommitToken = nextCommit;
    if (error != nullptr) error->clear();
    return true;
}

void EventLogBookmarkStore::MarkSubscriptionError(DWORD errorCode) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const State state = errorCode == kBookmarkStale ||
                        errorCode == kBookmarkInvalidPosition ||
                        errorCode == ERROR_NOT_FOUND
        ? State::Reset : State::Unavailable;
    SetFailure(state, WinError("EvtSubscribe failed", errorCode));
}

EventLogBookmarkStore::Status EventLogBookmarkStore::GetStatus() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    Status status;
    status.enabled = m_enabled;
    status.available = IsUsableState();
    status.state = m_state;
    status.lastObservedRecordId = m_lastObservedRecordId;
    status.lastCommittedRecordId = m_lastCommittedRecordId;
    status.pending = m_pending.size();
    status.lastError = m_lastError;
    return status;
}

const char* EventLogBookmarkStore::StateName(State state) {
    switch (state) {
    case State::Disabled: return "disabled";
    case State::Empty: return "starting_oldest_retained";
    case State::Ready: return "ready";
    case State::Gap: return "gap";
    case State::Corrupt: return "corrupt";
    case State::Reset: return "reset";
    case State::PersistenceFailure: return "persistence_failure";
    case State::Unavailable: return "unavailable";
    default: return "unavailable";
    }
}

bool EventLogBookmarkStore::LoadCheckpoint(std::string& error) {
    std::vector<HANDLE> directories;
    if (!OpenSecureCheckpointDirectory(m_checkpointPath, directories, error))
        return false;
    HandleVectorGuard directoryGuard(std::move(directories));
    HANDLE file = CreateFileW(m_checkpointPath.c_str(), GENERIC_READ |
        READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD winError = GetLastError();
        if (winError == ERROR_FILE_NOT_FOUND || winError == ERROR_PATH_NOT_FOUND) {
            error = "checkpoint is missing";
            return false;
        }
        error = WinError("open checkpoint failed", winError);
        return false;
    }

    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    bool ok = GetFileInformationByHandle(file, &info) != FALSE &&
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                  FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
        GetFileSizeEx(file, &size) != FALSE && size.QuadPart >=
        static_cast<LONGLONG>(kHeaderBytes) && size.QuadPart <=
        static_cast<LONGLONG>(kMaxCheckpointBytes);
    if (!ok) {
        error = WinError("checkpoint file type or size is invalid",
                         GetLastError());
        CloseHandle(file);
        return false;
    }
    if (!HasProtectedOwnerOnlyDacl(file, error)) {
        CloseHandle(file);
        return false;
    }

    std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
    ok = ReadExact(file, bytes.data(), bytes.size(), error);
    char extra = 0;
    DWORD extraRead = 0;
    if (ok && (!ReadFile(file, &extra, 1, &extraRead, nullptr) || extraRead != 0)) {
        error = "checkpoint changed size while being read";
        ok = false;
    }
    CloseHandle(file);
    if (!ok) return false;

    std::wstring channel;
    std::wstring bookmarkXml;
    uint64_t recordId = 0;
    if (!DecodeCheckpoint(bytes, channel, recordId, bookmarkXml, error) ||
        channel != m_channel) {
        if (error.empty()) error = "checkpoint channel does not match this stream";
        return false;
    }
    std::wstring bookmarkChannel;
    uint64_t bookmarkRecordId = 0;
    if (!ParseBookmarkIdentity(bookmarkXml, bookmarkChannel, bookmarkRecordId) ||
        bookmarkChannel != m_channel || bookmarkRecordId != recordId) {
        error = "checkpoint bookmark identity is malformed or inconsistent";
        return false;
    }
    EVT_HANDLE validation = nullptr;
    try {
        validation = m_winEvt.createBookmark(bookmarkXml.c_str());
    } catch (...) {
        error = "EvtCreateBookmark callback threw while validating checkpoint";
        return false;
    }
    if (validation == nullptr) {
        error = WinError("EvtCreateBookmark rejected checkpoint XML",
                         GetLastError());
        return false;
    }
    EvtHandleGuard validationGuard(validation, m_winEvt.close);
    m_bookmarkXml = std::move(bookmarkXml);
    m_lastCommittedRecordId = recordId;
    m_lastObservedRecordId = recordId;
    return true;
}

bool EventLogBookmarkStore::SaveCheckpoint(uint64_t recordId,
                                           const std::wstring& bookmarkXml,
                                           std::string& error) {
    std::vector<HANDLE> directories;
    if (!OpenSecureCheckpointDirectory(m_checkpointPath, directories, error))
        return false;
    HandleVectorGuard directoryGuard(std::move(directories));
    if (m_checkpointDirectoryOpened) {
        try {
            m_checkpointDirectoryOpened(directoryGuard.Leaf());
        } catch (...) {
            error = "checkpoint directory-open callback threw an exception";
            return false;
        }
    }

    std::string bytes;
    if (!EncodeCheckpoint(m_channel, recordId, bookmarkXml, bytes, error))
        return false;

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!CreateOwnerOnlySecurityDescriptor(descriptor, error)) return false;
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;

    static std::atomic<uint64_t> tempSequence{0};
    std::wstring temporary;
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD lastError = ERROR_FILE_EXISTS;
    for (unsigned int attempt = 0; attempt < 16; ++attempt) {
        temporary = m_checkpointPath + L".tmp-" +
            std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(tempSequence.fetch_add(1));
        file = CreateFileW(temporary.c_str(), GENERIC_WRITE | READ_CONTROL |
            WRITE_DAC, 0, &attributes, CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (file != INVALID_HANDLE_VALUE) break;
        lastError = GetLastError();
        if (lastError != ERROR_FILE_EXISTS && lastError != ERROR_ALREADY_EXISTS)
            break;
    }
    LocalFree(descriptor);
    if (file == INVALID_HANDLE_VALUE) {
        error = WinError("create temporary bookmark checkpoint failed",
                         lastError);
        return false;
    }

    bool ok = HasProtectedOwnerOnlyDacl(file, error);
    if (ok) ok = WriteExact(file, bytes, error);
    if (ok && !FlushFileBuffers(file)) {
        error = WinError("FlushFileBuffers checkpoint failed", GetLastError());
        ok = false;
    }
    if (!CloseHandle(file) && ok) {
        error = WinError("close temporary checkpoint failed", GetLastError());
        ok = false;
    }
    if (ok && !MoveFileExW(temporary.c_str(), m_checkpointPath.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = WinError("atomic bookmark checkpoint replace failed",
                         GetLastError());
        ok = false;
    }
    if (!ok) DeleteFileW(temporary.c_str());
    return ok;
}

bool EventLogBookmarkStore::ParseBookmarkIdentity(
    const std::wstring& xml, std::wstring& channel, uint64_t& recordId) const {
    const size_t bookmark = xml.find(L"<Bookmark ");
    if (bookmark == std::wstring::npos) return false;
    const size_t tagEnd = xml.find(L'>', bookmark);
    if (tagEnd == std::wstring::npos) return false;
    const std::wstring tag = xml.substr(bookmark, tagEnd - bookmark);
    auto attribute = [&](const wchar_t* name, std::wstring& value) {
        const std::wstring key = std::wstring(name) + L"=\"";
        const size_t start = tag.find(key);
        if (start == std::wstring::npos) return false;
        const size_t content = start + key.size();
        const size_t end = tag.find(L'\"', content);
        if (end == std::wstring::npos || end == content) return false;
        value.assign(tag, content, end - content);
        return true;
    };
    std::wstring recordText;
    if (!attribute(L"Channel", channel) ||
        !attribute(L"RecordId", recordText)) return false;
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::wcstoull(recordText.c_str(), &end, 10);
    if (errno == ERANGE || end == recordText.c_str() || *end != L'\0' ||
        parsed == 0) return false;
    recordId = static_cast<uint64_t>(parsed);
    return true;
}

std::shared_ptr<EventLogBookmarkStore> CreateEventLogBookmarkStore(
    const EventLogReplayOptions& options, const wchar_t* streamName,
    const wchar_t* channel, size_t collectorInFlightBound) {
    if (!options.enabled) return nullptr;
    std::wstring path = options.checkpointDirectory;
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/')
        path.push_back(L'\\');
    path += streamName != nullptr ? streamName : L"unknown";
    path += L".bookmark";
    const size_t naturalBound = std::max<size_t>(collectorInFlightBound, 1);
    const size_t configuredBound = options.maxPendingRecords == 0
        ? naturalBound : std::min(options.maxPendingRecords, naturalBound);
    return std::make_shared<EventLogBookmarkStore>(std::move(path),
        channel != nullptr ? channel : L"", true, configuredBound);
}

} // namespace edr
