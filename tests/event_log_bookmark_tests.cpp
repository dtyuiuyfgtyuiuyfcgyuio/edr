/*
 * event_log_bookmark_tests.cpp - durable Event Log bookmark tests. The fake
 * WinEvt boundary keeps tests deterministic; checkpoint file ACLs and atomic
 * replacement still exercise the real Windows filesystem implementation.
 */
#include "event_log_bookmark_tests.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winevt.h>

#include <atomic>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "event_log_bookmark.h"
#include "owner_only_sd.h"
#include "event_bus.h"

namespace {

#define ELB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("event log bookmark test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

void CheckReplayStartFlags(DWORD flags, DWORD expectedOriginFlags) {
    ELB_CHECK((flags & EvtSubscribeStrict) != 0);
    ELB_CHECK((flags & ~static_cast<DWORD>(EvtSubscribeStrict)) ==
              expectedOriginFlags);
}

std::string Utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return "<path conversion failed>";
    std::string result(static_cast<size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.data(),
            static_cast<int>(value.size()), result.data(), bytes,
            nullptr, nullptr) != bytes)
        return "<path conversion failed>";
    return result;
}

std::wstring TempPath(const wchar_t* suffix) {
    wchar_t directory[MAX_PATH] = {};
    ELB_CHECK(GetTempPathW(MAX_PATH, directory) != 0);
    static std::atomic<unsigned long> next{1};
    const std::wstring privateDirectory = std::wstring(directory) +
        L"edr-event-bookmark-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(next.fetch_add(1));
    /* The private parent must be owned by the current token user: the store
     * verifies owner == token user, and the platform default owner is the
     * Administrators group for elevated tokens. */
    std::string sdError;
    PSECURITY_DESCRIPTOR descriptor = edr::CreateOwnerOnlyDescriptor(sdError);
    ELB_CHECK(descriptor != nullptr);
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    const BOOL created = CreateDirectoryW(privateDirectory.c_str(), &attributes);
    const DWORD createError = created ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    ELB_CHECK(created != FALSE || createError == ERROR_ALREADY_EXISTS);
    return privateDirectory + L"\\checkpoint" + suffix;
}

std::wstring ParentDirectory(const std::wstring& path) {
    const size_t separator = path.find_last_of(L"\\/");
    ELB_CHECK(separator != std::wstring::npos);
    return path.substr(0, separator);
}

void RemoveIfPresent(const std::wstring& path) {
    DeleteFileW(path.c_str());
    RemoveDirectoryW(ParentDirectory(path).c_str());
}

void SetWeakDirectoryDacl(const std::wstring& path) {
    HANDLE directory = CreateFileW(path.c_str(),
        READ_CONTROL | WRITE_DAC | WRITE_OWNER,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    ELB_CHECK(directory != INVALID_HANDLE_VALUE);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    ELB_CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;FA;;;OW)(A;;FR;;;WD)", SDDL_REVISION_1, &descriptor,
        nullptr) != FALSE);
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL dacl = nullptr;
    ELB_CHECK(GetSecurityDescriptorDacl(descriptor, &daclPresent, &dacl,
                                        &daclDefaulted) != FALSE &&
              daclPresent != FALSE && dacl != nullptr);
    /* The weak DACL deliberately keeps WD readable; the owner stays pinned to
     * the token user so the store's owner check still passes and the test
     * isolates the DACL weakness. */
    HANDLE token = nullptr;
    ELB_CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != FALSE);
    DWORD userBytes = 0;
    ELB_CHECK(GetTokenInformation(token, TokenUser, nullptr, 0, &userBytes) == FALSE &&
              userBytes > 0);
    std::vector<unsigned char> userBuffer(userBytes);
    ELB_CHECK(GetTokenInformation(token, TokenUser, userBuffer.data(), userBytes,
                                  &userBytes) != FALSE);
    const PSID userSid =
        reinterpret_cast<const TOKEN_USER*>(userBuffer.data())->User.Sid;
    CloseHandle(token);
    const DWORD result = SetSecurityInfo(directory, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
        PROTECTED_DACL_SECURITY_INFORMATION,
        userSid, nullptr, dacl, nullptr);
    LocalFree(descriptor);
    CloseHandle(directory);
    ELB_CHECK(result == ERROR_SUCCESS);
}

std::string ReadAll(const std::wstring& path) {
    std::ifstream input(path, std::ios::binary);
    ELB_CHECK(input.is_open());
    std::string bytes((std::istreambuf_iterator<char>(input)),
                      std::istreambuf_iterator<char>());
    ELB_CHECK(!input.bad());
    return bytes;
}

void ReplaceFirstByte(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ELB_CHECK(file != INVALID_HANDLE_VALUE);
    char original = 0;
    DWORD transferred = 0;
    ELB_CHECK(ReadFile(file, &original, 1, &transferred, nullptr) != FALSE &&
              transferred == 1);
    LARGE_INTEGER start{};
    ELB_CHECK(SetFilePointerEx(file, start, nullptr, FILE_BEGIN) != FALSE);
    const char changed = static_cast<char>(original ^ 0x5a);
    ELB_CHECK(WriteFile(file, &changed, 1, &transferred, nullptr) != FALSE &&
              transferred == 1);
    ELB_CHECK(FlushFileBuffers(file) != FALSE);
    CloseHandle(file);
}

std::string NormalizeDaclSddl(std::string sddl) {
    if (sddl.compare(0, 5, "D:PAI") == 0) sddl.replace(0, 5, "D:P");
    return sddl;
}

bool HasProtectedOwnerOnlyDacl(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD query = GetSecurityInfo(file, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
        &descriptor);
    CloseHandle(file);
    if (query != ERROR_SUCCESS || descriptor == nullptr || dacl == nullptr) {
        if (descriptor != nullptr) LocalFree(descriptor);
        return false;
    }

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    LPSTR sddl = nullptr;
    const bool protectedDacl =
        GetSecurityDescriptorControl(descriptor, &control, &revision) != FALSE &&
        (control & SE_DACL_PROTECTED) != 0;
    const bool converted =
        ConvertSecurityDescriptorToStringSecurityDescriptorA(
            descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl,
            nullptr) != FALSE;
    const std::string normalized = converted && sddl != nullptr
        ? NormalizeDaclSddl(sddl) : std::string();
    if (sddl != nullptr) LocalFree(sddl);
    LocalFree(descriptor);
    return protectedDacl && normalized == "D:P(A;;FA;;;OW)";
}

struct FakeEvent {
    std::wstring channel;
    uint64_t recordId = 0;
};

class FakeWinEvt {
public:
    edr::EventLogBookmarkStore::WinEvtApi Api() {
        edr::EventLogBookmarkStore::WinEvtApi api;
        api.createBookmark = [this](const wchar_t* xml) {
            const EVT_HANDLE handle = NewHandle();
            m_bookmarks[handle] = xml == nullptr ? std::wstring() : xml;
            ++createCalls;
            if (xml != nullptr) lastCreatedXml = xml;
            return handle;
        };
        api.updateBookmark = [this](EVT_HANDLE bookmark, EVT_HANDLE event) {
            ++updateCalls;
            const auto foundEvent = m_events.find(event);
            const auto foundBookmark = m_bookmarks.find(bookmark);
            if (foundEvent == m_events.end() || foundBookmark == m_bookmarks.end())
                return false;
            foundBookmark->second = RenderXml(foundEvent->second);
            return true;
        };
        api.renderBookmark = [this](EVT_HANDLE bookmark, std::wstring& xml) {
            ++renderCalls;
            const auto found = m_bookmarks.find(bookmark);
            if (found == m_bookmarks.end() || found->second.empty()) return false;
            xml = found->second;
            return true;
        };
        api.eventIdentity = [this](EVT_HANDLE event, std::wstring& channel,
                                   uint64_t& recordId) {
            ++identityCalls;
            const auto found = m_events.find(event);
            if (found == m_events.end()) return false;
            channel = found->second.channel;
            recordId = found->second.recordId;
            return true;
        };
        api.close = [this](EVT_HANDLE handle) {
            ++closeCalls;
            m_bookmarks.erase(handle);
        };
        return api;
    }

    EVT_HANDLE AddEvent(const std::wstring& channel, uint64_t recordId) {
        const EVT_HANDLE handle = NewHandle();
        m_events.emplace(handle, FakeEvent{channel, recordId});
        return handle;
    }

    size_t createCalls = 0;
    size_t updateCalls = 0;
    size_t renderCalls = 0;
    size_t identityCalls = 0;
    size_t closeCalls = 0;
    std::wstring lastCreatedXml;

private:
    EVT_HANDLE NewHandle() {
        ++m_nextHandle;
        return reinterpret_cast<EVT_HANDLE>(m_nextHandle * 16u + 1u);
    }

    static std::wstring RenderXml(const FakeEvent& event) {
        return L"<BookmarkList><Bookmark Channel=\"" + event.channel +
            L"\" RecordId=\"" + std::to_wstring(event.recordId) +
            L"\" IsCurrent=\"true\"/></BookmarkList>";
    }

    uintptr_t m_nextHandle = 0x1000;
    std::map<EVT_HANDLE, FakeEvent> m_events;
    std::map<EVT_HANDLE, std::wstring> m_bookmarks;
};

void TestDisabledBookmarkModePreservesFutureOnlySubscription() {
    const std::wstring path = TempPath(L"-disabled.chk");
    RemoveIfPresent(path);
    auto fake = std::make_shared<FakeWinEvt>();
    edr::EventLogBookmarkStore store(path, L"Application", false, 8,
                                     fake->Api());
    ELB_CHECK(store.Open());
    DWORD flags = 0;
    EVT_HANDLE bookmark = reinterpret_cast<EVT_HANDLE>(1);
    ELB_CHECK(store.PrepareSubscription(flags, bookmark));
    ELB_CHECK(flags == EvtSubscribeToFutureEvents && bookmark == nullptr);
    ELB_CHECK(fake->createCalls == 0 && fake->updateCalls == 0 &&
              fake->renderCalls == 0 && fake->identityCalls == 0);
    ELB_CHECK(GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES);
}

void TestAcceptedPrefixCommitsAtomicallyAndResumesFromRealOwnerOnlyFile() {
    const std::wstring path = TempPath(L"-resume.chk");
    RemoveIfPresent(path);
    auto fake = std::make_shared<FakeWinEvt>();
    const auto api = fake->Api();
    {
        edr::EventLogBookmarkStore store(path, L"Application", true, 8, api);
        ELB_CHECK(store.Open());
        DWORD flags = 0;
        EVT_HANDLE resume = nullptr;
        ELB_CHECK(store.PrepareSubscription(flags, resume));
        CheckReplayStartFlags(flags, EvtSubscribeStartAtOldestRecord);
        ELB_CHECK(resume == nullptr);

        const EVT_HANDLE e41 = fake->AddEvent(L"Application", 41);
        const EVT_HANDLE e42 = fake->AddEvent(L"Application", 42);
        edr::EventLogBookmarkStore::Token first = 0, second = 0;
        ELB_CHECK(store.Capture(e41, first));
        ELB_CHECK(store.Capture(e42, second));
        ELB_CHECK(first != 0 && second == first + 1);

        /* A later worker can finish first, but must not persist past e41. */
        ELB_CHECK(store.Complete(second, true));
        ELB_CHECK(store.GetStatus().lastCommittedRecordId == 0);
        ELB_CHECK(GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES);
        ELB_CHECK(store.Complete(first, true));
        const auto status = store.GetStatus();
        ELB_CHECK(status.state == edr::EventLogBookmarkStore::State::Ready);
        ELB_CHECK(status.lastCommittedRecordId == 42 && status.pending == 0);
        ELB_CHECK(HasProtectedOwnerOnlyDacl(path));
    }

    {
        edr::EventLogBookmarkStore resumed(path, L"Application", true, 8, api);
        ELB_CHECK(resumed.Open());
        DWORD flags = 0;
        EVT_HANDLE bookmark = nullptr;
        ELB_CHECK(resumed.PrepareSubscription(flags, bookmark));
        CheckReplayStartFlags(flags, EvtSubscribeStartAfterBookmark);
        ELB_CHECK(bookmark != nullptr);
        ELB_CHECK(fake->lastCreatedXml.find(L"RecordId=\"42\"") !=
                  std::wstring::npos);
        fake->Api().close(bookmark);
    }
    RemoveIfPresent(path);
}

void TestCompleteNeverCommitsPastTheNextIncompleteRecord() {
    const std::wstring path = TempPath(L"-contiguous-prefix.chk");
    RemoveIfPresent(path);
    auto fake = std::make_shared<FakeWinEvt>();
    edr::EventLogBookmarkStore store(path, L"Application", true, 8,
                                     fake->Api());
    ELB_CHECK(store.Open());
    edr::EventLogBookmarkStore::Token first = 0, second = 0;
    ELB_CHECK(store.Capture(fake->AddEvent(L"Application", 91), first));
    ELB_CHECK(store.Capture(fake->AddEvent(L"Application", 92), second));
    ELB_CHECK(store.Complete(first, true));
    const auto prefix = store.GetStatus();
    ELB_CHECK(prefix.state == edr::EventLogBookmarkStore::State::Ready);
    ELB_CHECK(prefix.lastCommittedRecordId == 91);
    ELB_CHECK(prefix.pending == 1);
    ELB_CHECK(ReadAll(path).find("91") != std::string::npos);
    ELB_CHECK(store.Complete(second, true));
    const auto full = store.GetStatus();
    ELB_CHECK(full.state == edr::EventLogBookmarkStore::State::Ready);
    ELB_CHECK(full.lastCommittedRecordId == 92);
    ELB_CHECK(full.pending == 0);
    RemoveIfPresent(path);
}

void TestGroupedFragmentReceiptsWaitForDerivedEventConsumption() {
    const std::wstring acceptedPath = TempPath(L"-fragment-group.chk");
    RemoveIfPresent(acceptedPath);
    auto fake = std::make_shared<FakeWinEvt>();
    size_t checkpointSaves = 0;
    auto acceptedStore = std::make_shared<edr::EventLogBookmarkStore>(
        acceptedPath, L"Application", true, 8, fake->Api(),
        [&](HANDLE) { ++checkpointSaves; });
    ELB_CHECK(acceptedStore->Open());
    edr::EventLogBookmarkStore::Token first = 0, second = 0;
    ELB_CHECK(acceptedStore->Capture(
        fake->AddEvent(L"Application", 51), first));
    ELB_CHECK(acceptedStore->Capture(
        fake->AddEvent(L"Application", 52), second));

    edr::EventLogBookmarkTokenGroup accepted(acceptedStore);
    ELB_CHECK(accepted.Add(first));
    ELB_CHECK(accepted.Add(second));
    edr::Event derived;
    ELB_CHECK(accepted.Attach(derived));
    ELB_CHECK(accepted.size() == 0);
    ELB_CHECK(acceptedStore->GetStatus().pending == 2);
    ELB_CHECK(acceptedStore->GetStatus().lastCommittedRecordId == 0);
    ELB_CHECK(derived.onConsumed != nullptr);

    /* A raw PowerShell fragment group is not durable until the completed or
     * terminal derived block reaches EventBus' consumption receipt. */
    derived.onConsumed(true);
    const auto acceptedStatus = acceptedStore->GetStatus();
    if (acceptedStatus.state != edr::EventLogBookmarkStore::State::Ready) {
        throw std::runtime_error("fragment group receipt state=" +
            std::string(edr::EventLogBookmarkStore::StateName(
                acceptedStatus.state)) + " error=" + acceptedStatus.lastError +
            " pending=" + std::to_string(acceptedStatus.pending) +
            " saves=" + std::to_string(checkpointSaves) +
            " committed=" + std::to_string(
                acceptedStatus.lastCommittedRecordId));
    }
    ELB_CHECK(acceptedStatus.state == edr::EventLogBookmarkStore::State::Ready);
    ELB_CHECK(acceptedStatus.pending == 0);
    ELB_CHECK(acceptedStatus.lastCommittedRecordId == 52);
    RemoveIfPresent(acceptedPath);

    const std::wstring failedPath = TempPath(L"-fragment-group-failed.chk");
    RemoveIfPresent(failedPath);
    auto failedStore = std::make_shared<edr::EventLogBookmarkStore>(
        failedPath, L"Application", true, 8, fake->Api());
    ELB_CHECK(failedStore->Open());
    ELB_CHECK(failedStore->Capture(
        fake->AddEvent(L"Application", 61), first));
    ELB_CHECK(failedStore->Capture(
        fake->AddEvent(L"Application", 62), second));
    edr::EventLogBookmarkTokenGroup failed(failedStore);
    ELB_CHECK(failed.Add(first));
    ELB_CHECK(failed.Add(second));
    edr::Event failedDerived;
    ELB_CHECK(failed.Attach(failedDerived));
    failedDerived.onConsumed(false);
    ELB_CHECK(failedStore->GetStatus().state ==
              edr::EventLogBookmarkStore::State::Gap);
    ELB_CHECK(failedStore->GetStatus().lastCommittedRecordId == 0);
    ELB_CHECK(GetFileAttributesW(failedPath.c_str()) == INVALID_FILE_ATTRIBUTES);
    RemoveIfPresent(failedPath);
}

void TestUnconsumedFragmentReceiptFailsClosedWhenEventIsDestroyed() {
    const std::wstring path = TempPath(L"-fragment-abandoned.chk");
    RemoveIfPresent(path);
    auto fake = std::make_shared<FakeWinEvt>();
    auto store = std::make_shared<edr::EventLogBookmarkStore>(
        path, L"Application", true, 8, fake->Api());
    ELB_CHECK(store->Open());
    edr::EventLogBookmarkStore::Token token = 0;
    ELB_CHECK(store->Capture(fake->AddEvent(L"Application", 71), token));
    {
        edr::EventLogBookmarkTokenGroup group(store);
        ELB_CHECK(group.Add(token));
        edr::Event derived;
        ELB_CHECK(group.Attach(derived));
        ELB_CHECK(store->GetStatus().pending == 1);
    }
    /* No receipt invocation means the callback state destructor must fail the
     * source token instead of letting restart resume beyond it. */
    ELB_CHECK(store->GetStatus().state == edr::EventLogBookmarkStore::State::Gap);
    ELB_CHECK(GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES);
    RemoveIfPresent(path);
}

void TestFailedEarlierProcessingLatchesGapWithoutSkippingCheckpoint() {
    const std::wstring path = TempPath(L"-gap.chk");
    RemoveIfPresent(path);
    auto fake = std::make_shared<FakeWinEvt>();
    const auto api = fake->Api();
    edr::EventLogBookmarkStore store(path, L"Application", true, 8, api);
    ELB_CHECK(store.Open());
    const EVT_HANDLE e10 = fake->AddEvent(L"Application", 10);
    edr::EventLogBookmarkStore::Token initial = 0;
    ELB_CHECK(store.Capture(e10, initial));
    ELB_CHECK(store.Complete(initial, true));
    const std::string beforeGap = ReadAll(path);

    const EVT_HANDLE e11 = fake->AddEvent(L"Application", 11);
    const EVT_HANDLE e12 = fake->AddEvent(L"Application", 12);
    edr::EventLogBookmarkStore::Token first = 0, second = 0;
    ELB_CHECK(store.Capture(e11, first));
    ELB_CHECK(store.Capture(e12, second));
    ELB_CHECK(store.Complete(second, true));
    ELB_CHECK(!store.Complete(first, false));
    const auto status = store.GetStatus();
    ELB_CHECK(status.state == edr::EventLogBookmarkStore::State::Gap);
    ELB_CHECK(status.lastCommittedRecordId == 10);
    ELB_CHECK(ReadAll(path) == beforeGap);
    DWORD flags = 99;
    EVT_HANDLE bookmark = reinterpret_cast<EVT_HANDLE>(1);
    ELB_CHECK(!store.PrepareSubscription(flags, bookmark));
    ELB_CHECK(flags == 0 && bookmark == nullptr);
    ELB_CHECK(!store.Capture(fake->AddEvent(L"Application", 13), first));
    RemoveIfPresent(path);
}

void TestCorruptCheckpointFailsClosedInsteadOfStartingAtFutureEvents() {
    const std::wstring path = TempPath(L"-corrupt.chk");
    RemoveIfPresent(path);
    auto fake = std::make_shared<FakeWinEvt>();
    {
        edr::EventLogBookmarkStore store(path, L"Application", true, 8,
                                         fake->Api());
        ELB_CHECK(store.Open());
        const EVT_HANDLE event = fake->AddEvent(L"Application", 20);
        edr::EventLogBookmarkStore::Token token = 0;
        ELB_CHECK(store.Capture(event, token));
        ELB_CHECK(store.Complete(token, true));
    }
    ReplaceFirstByte(path);

    edr::EventLogBookmarkStore corrupt(path, L"Application", true, 8,
                                       fake->Api());
    ELB_CHECK(!corrupt.Open());
    ELB_CHECK(corrupt.GetStatus().state ==
              edr::EventLogBookmarkStore::State::Corrupt);
    DWORD flags = 7;
    EVT_HANDLE bookmark = reinterpret_cast<EVT_HANDLE>(1);
    ELB_CHECK(!corrupt.PrepareSubscription(flags, bookmark));
    ELB_CHECK(flags == 0 && bookmark == nullptr);
    RemoveIfPresent(path);
}

void TestStaleBookmarkAndNonIncreasingRecordIdReportReset() {
    const std::wstring path = TempPath(L"-reset.chk");
    RemoveIfPresent(path);
    auto fake = std::make_shared<FakeWinEvt>();
    const auto api = fake->Api();
    {
        edr::EventLogBookmarkStore store(path, L"Application", true, 8, api);
        ELB_CHECK(store.Open());
        edr::EventLogBookmarkStore::Token token = 0;
        ELB_CHECK(store.Capture(fake->AddEvent(L"Application", 30), token));
        ELB_CHECK(store.Complete(token, true));
        ELB_CHECK(store.Capture(fake->AddEvent(L"Application", 30), token) ==
                  false);
        ELB_CHECK(store.GetStatus().state ==
                  edr::EventLogBookmarkStore::State::Reset);
        DWORD flags = 7;
        EVT_HANDLE bookmark = reinterpret_cast<EVT_HANDLE>(1);
        ELB_CHECK(!store.PrepareSubscription(flags, bookmark));
        ELB_CHECK(flags == 0 && bookmark == nullptr);
    }

    edr::EventLogBookmarkStore stale(path, L"Application", true, 8, api);
    ELB_CHECK(stale.Open());
    /* 15011 is ERROR_EVT_QUERY_RESULT_STALE: never downgrade to future-only. */
    stale.MarkSubscriptionError(15011);
    ELB_CHECK(stale.GetStatus().state ==
              edr::EventLogBookmarkStore::State::Reset);
    DWORD flags = 7;
    EVT_HANDLE bookmark = reinterpret_cast<EVT_HANDLE>(1);
    ELB_CHECK(!stale.PrepareSubscription(flags, bookmark));
    ELB_CHECK(flags == 0 && bookmark == nullptr);

    edr::EventLogBookmarkStore missing(path, L"Application", true, 8, api);
    ELB_CHECK(missing.Open());
    missing.MarkSubscriptionError(ERROR_NOT_FOUND);
    ELB_CHECK(missing.GetStatus().state ==
              edr::EventLogBookmarkStore::State::Reset);
    flags = 7;
    bookmark = reinterpret_cast<EVT_HANDLE>(1);
    ELB_CHECK(!missing.PrepareSubscription(flags, bookmark));
    ELB_CHECK(flags == 0 && bookmark == nullptr);
    RemoveIfPresent(path);
}

void TestCheckpointWriteFailureIsVisibleAndStopsSubscription() {
    const std::wstring path = TempPath(L"-write-failure.chk");
    RemoveIfPresent(path);

    auto fake = std::make_shared<FakeWinEvt>();
    edr::EventLogBookmarkStore store(path, L"Application", true, 8,
                                     fake->Api());
    ELB_CHECK(store.Open());
    DWORD flags = 0;
    EVT_HANDLE bookmark = nullptr;
    ELB_CHECK(store.PrepareSubscription(flags, bookmark));
    CheckReplayStartFlags(flags, EvtSubscribeStartAtOldestRecord);

    edr::EventLogBookmarkStore::Token token = 0;
    ELB_CHECK(store.Capture(fake->AddEvent(L"Application", 71), token));
    SetWeakDirectoryDacl(ParentDirectory(path));
    ELB_CHECK(!store.Complete(token, true));
    ELB_CHECK(store.GetStatus().state ==
              edr::EventLogBookmarkStore::State::PersistenceFailure);
    ELB_CHECK(store.GetStatus().lastCommittedRecordId == 0);
    flags = 7;
    bookmark = reinterpret_cast<EVT_HANDLE>(1);
    ELB_CHECK(!store.PrepareSubscription(flags, bookmark));
    ELB_CHECK(flags == 0 && bookmark == nullptr);
    ELB_CHECK(GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES);
    RemoveIfPresent(path);
}

void TestCheckpointDirectoryCannotBeRenamedDuringAtomicSave() {
    const std::wstring markerPath = TempPath(L"-rename-root.marker");
    const std::wstring ancestorDirectory = ParentDirectory(markerPath);
    const std::wstring directory = ancestorDirectory + L"\\state";
    const std::wstring path = directory + L"\\checkpoint";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    std::string stateSdError;
    descriptor = edr::CreateOwnerOnlyDescriptor(stateSdError);
    ELB_CHECK(descriptor != nullptr);
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    const BOOL directoryCreated = CreateDirectoryW(directory.c_str(), &attributes);
    const DWORD directoryError = directoryCreated ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    ELB_CHECK(directoryCreated != FALSE || directoryError == ERROR_ALREADY_EXISTS);
    const std::wstring renamedDirectory = directory + L"-renamed";
    const std::wstring renamedAncestor = ancestorDirectory + L"-renamed";
    auto fake = std::make_shared<FakeWinEvt>();
    bool attemptedRename = false;
    bool leafRenameWasBlocked = false;
    bool ancestorRenameWasBlocked = false;
    DWORD leafRenameError = ERROR_SUCCESS;
    DWORD ancestorRenameError = ERROR_SUCCESS;
    edr::EventLogBookmarkStore store(path, L"Application", true, 8,
        fake->Api(), [&](HANDLE retainedDirectory) {
            ELB_CHECK(retainedDirectory != INVALID_HANDLE_VALUE);
            attemptedRename = true;
            const BOOL leafRenamed = MoveFileExW(directory.c_str(),
                renamedDirectory.c_str(), MOVEFILE_WRITE_THROUGH);
            leafRenameWasBlocked = leafRenamed == FALSE;
            leafRenameError = leafRenameWasBlocked ? GetLastError() : ERROR_SUCCESS;
            if (!leafRenameWasBlocked) {
                (void)MoveFileExW(renamedDirectory.c_str(), directory.c_str(),
                                  MOVEFILE_WRITE_THROUGH);
            }
            const BOOL ancestorRenamed = MoveFileExW(ancestorDirectory.c_str(),
                renamedAncestor.c_str(), MOVEFILE_WRITE_THROUGH);
            ancestorRenameWasBlocked = ancestorRenamed == FALSE;
            ancestorRenameError = ancestorRenameWasBlocked
                ? GetLastError() : ERROR_SUCCESS;
            if (!ancestorRenameWasBlocked) {
                (void)MoveFileExW(renamedAncestor.c_str(), ancestorDirectory.c_str(),
                                  MOVEFILE_WRITE_THROUGH);
            }
        });
    ELB_CHECK(store.Open());
    edr::EventLogBookmarkStore::Token token = 0;
    ELB_CHECK(store.Capture(fake->AddEvent(L"Application", 81), token));
    ELB_CHECK(store.Complete(token, true));
    if (!attemptedRename || !leafRenameWasBlocked ||
        !ancestorRenameWasBlocked) {
        throw std::runtime_error("checkpoint rename exclusion failed: attempted=" +
            std::to_string(attemptedRename) + " leafBlocked=" +
            std::to_string(leafRenameWasBlocked) + " leafError=" +
            std::to_string(leafRenameError) + " leafPath=" +
            Utf8(directory) + " leafTarget=" + Utf8(renamedDirectory) +
            " ancestorBlocked=" + std::to_string(ancestorRenameWasBlocked) +
            " ancestorError=" + std::to_string(ancestorRenameError) +
            " ancestorPath=" + Utf8(ancestorDirectory) +
            " ancestorTarget=" + Utf8(renamedAncestor));
    }
    ELB_CHECK(GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES);
    DeleteFileW(path.c_str());
    DeleteFileW((renamedDirectory + L"\\checkpoint").c_str());
    RemoveDirectoryW(renamedDirectory.c_str());
    RemoveDirectoryW(directory.c_str());
    RemoveDirectoryW(ancestorDirectory.c_str());
    DeleteFileW((renamedAncestor + L"\\rename-root.marker").c_str());
    RemoveDirectoryW(renamedAncestor.c_str());
}

void TestExistingCheckpointDirectoryWithBroadDaclFailsClosed() {
    const std::wstring path = TempPath(L"-weak-directory.chk");
    RemoveIfPresent(path);
    const std::wstring directory = ParentDirectory(path);
    ELB_CHECK(CreateDirectoryW(directory.c_str(), nullptr) != FALSE);
    SetWeakDirectoryDacl(directory);

    auto fake = std::make_shared<FakeWinEvt>();
    edr::EventLogBookmarkStore store(path, L"Application", true, 8,
                                     fake->Api());
    ELB_CHECK(!store.Open());
    ELB_CHECK(store.GetStatus().state ==
              edr::EventLogBookmarkStore::State::Corrupt);
    DWORD flags = 99;
    EVT_HANDLE bookmark = reinterpret_cast<EVT_HANDLE>(1);
    ELB_CHECK(!store.PrepareSubscription(flags, bookmark));
    ELB_CHECK(flags == 0 && bookmark == nullptr);
    RemoveIfPresent(path);
}

void TestChannelMismatchAndPendingCapacityBecomeVisibleGap() {
    const std::wstring path = TempPath(L"-bound.chk");
    RemoveIfPresent(path);
    auto fake = std::make_shared<FakeWinEvt>();
    edr::EventLogBookmarkStore store(path, L"Application", true, 1,
                                     fake->Api());
    ELB_CHECK(store.Open());
    edr::EventLogBookmarkStore::Token first = 0, second = 0;
    ELB_CHECK(store.Capture(fake->AddEvent(L"Application", 1), first));
    ELB_CHECK(!store.Capture(fake->AddEvent(L"Application", 2), second));
    ELB_CHECK(store.GetStatus().state ==
              edr::EventLogBookmarkStore::State::Gap);
    ELB_CHECK(store.GetStatus().pending == 0);
    RemoveIfPresent(path);

    const std::wstring channelPath = TempPath(L"-channel.chk");
    RemoveIfPresent(channelPath);
    edr::EventLogBookmarkStore wrongChannel(channelPath, L"Application", true,
                                             4, fake->Api());
    ELB_CHECK(wrongChannel.Open());
    ELB_CHECK(!wrongChannel.Capture(fake->AddEvent(L"System", 9), first));
    ELB_CHECK(wrongChannel.GetStatus().state ==
              edr::EventLogBookmarkStore::State::Reset);
}

} // namespace

void RunEventLogBookmarkTests() {
    TestDisabledBookmarkModePreservesFutureOnlySubscription();
    TestAcceptedPrefixCommitsAtomicallyAndResumesFromRealOwnerOnlyFile();
    TestCompleteNeverCommitsPastTheNextIncompleteRecord();
    TestGroupedFragmentReceiptsWaitForDerivedEventConsumption();
    TestUnconsumedFragmentReceiptFailsClosedWhenEventIsDestroyed();
    TestFailedEarlierProcessingLatchesGapWithoutSkippingCheckpoint();
    TestCorruptCheckpointFailsClosedInsteadOfStartingAtFutureEvents();
    TestStaleBookmarkAndNonIncreasingRecordIdReportReset();
    TestCheckpointWriteFailureIsVisibleAndStopsSubscription();
    TestCheckpointDirectoryCannotBeRenamedDuringAtomicSave();
    TestExistingCheckpointDirectoryWithBroadDaclFailsClosed();
    TestChannelMismatchAndPendingCapacityBecomeVisibleGap();
}
