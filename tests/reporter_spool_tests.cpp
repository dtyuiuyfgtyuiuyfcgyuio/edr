/* Durable Reporter spool regressions. All filesystem cases use private temp dirs. */
#include "reporter_spool_tests.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "reporter.h"
#include "owner_only_sd.h"

namespace {

#define RS_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error(
            "reporter spool test failed at line " +
            std::to_string(line) + ": " + expr);
    }
}

std::string Utf8(const std::wstring& value) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                          value.data(),
                                          static_cast<int>(value.size()),
                                          nullptr, 0, nullptr, nullptr);
    RS_CHECK(size > 0);
    std::string result(static_cast<size_t>(size), '\0');
    RS_CHECK(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                 value.data(),
                                 static_cast<int>(value.size()),
                                 &result[0], size, nullptr, nullptr) == size);
    return result;
}

/* Pre-creates a spool directory the way the product does, with the owner
 * pinned to the token user: the elevated default owner (Administrators) is
 * not the "current process account" the product verifies against. */
bool CreateOwnerPinnedDirectory(const std::wstring& path) {
    std::string error;
    PSECURITY_DESCRIPTOR descriptor = edr::CreateOwnerOnlyDescriptor(error);
    RS_CHECK(descriptor != nullptr);
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    const BOOL created = CreateDirectoryW(path.c_str(), &attributes);
    const DWORD createError = created ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    return created != FALSE || createError == ERROR_ALREADY_EXISTS;
}

class TempDirectory {
public:
    TempDirectory() {
        wchar_t temp[MAX_PATH] = {};
        RS_CHECK(GetTempPathW(MAX_PATH, temp) > 0);
        wchar_t unique[MAX_PATH] = {};
        RS_CHECK(GetTempFileNameW(temp, L"edr", 0, unique) != 0);
        RS_CHECK(DeleteFileW(unique) != FALSE);
        RS_CHECK(CreateDirectoryW(unique, nullptr) != FALSE);
        m_root = unique;
        m_spool = m_root + L"\\spool";
    }

    ~TempDirectory() {
        const std::wstring pattern = m_spool + L"\\*.spool";
        WIN32_FIND_DATAW entry = {};
        HANDLE find = FindFirstFileW(pattern.c_str(), &entry);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    DeleteFileW((m_spool + L"\\" + entry.cFileName).c_str());
            } while (FindNextFileW(find, &entry));
            FindClose(find);
        }
        DeleteFileW((m_spool + L"\\keep.txt").c_str());
        DeleteFileW((m_spool + L"\\corrupt.spool").c_str());
        RemoveDirectoryW(m_spool.c_str());
        RemoveDirectoryW(m_root.c_str());
    }

    const std::wstring& Root() const { return m_root; }
    const std::wstring& Spool() const { return m_spool; }

private:
    std::wstring m_root;
    std::wstring m_spool;
};

edr::ReporterSpoolOptions Options(const TempDirectory& temp) {
    edr::ReporterSpoolOptions options;
    options.directory = Utf8(temp.Spool());
    options.maxBytes = 4 * 1024 * 1024;
    options.maxRecords = 16;
    options.maxItemBytes = 64 * 1024;
    return options;
}

void WaitFor(std::condition_variable& cv, std::unique_lock<std::mutex>& lock,
             const std::function<bool()>& predicate) {
    RS_CHECK(cv.wait_for(lock, std::chrono::seconds(5), predicate));
}

std::vector<std::wstring> SpoolFiles(const std::wstring& directory) {
    std::vector<std::wstring> files;
    WIN32_FIND_DATAW entry = {};
    HANDLE find = FindFirstFileW((directory + L"\\*.spool").c_str(), &entry);
    if (find == INVALID_HANDLE_VALUE) return files;
    do {
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            files.push_back(directory + L"\\" + entry.cFileName);
    } while (FindNextFileW(find, &entry));
    FindClose(find);
    return files;
}

std::string ProtectedDaclSddl(HANDLE handle) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    RS_CHECK(GetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                             nullptr, nullptr, &dacl, nullptr, &descriptor) ==
             ERROR_SUCCESS);
    LPWSTR sddl = nullptr;
    RS_CHECK(ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl,
        nullptr) != FALSE);
    std::wstring value = sddl;
    LocalFree(sddl);
    LocalFree(descriptor);
    if (value.rfind(L"D:PAI", 0) == 0) value.replace(0, 5, L"D:P");
    int bytes = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                    static_cast<int>(value.size()), nullptr, 0,
                                    nullptr, nullptr);
    RS_CHECK(bytes > 0);
    std::string result(static_cast<size_t>(bytes), '\0');
    RS_CHECK(WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                 static_cast<int>(value.size()), &result[0],
                                 bytes, nullptr, nullptr) == bytes);
    return result;
}

void TestDurableEnqueuePersistsBeforePostAndRestartReusesOneItem() {
    TempDirectory temp;
    std::mutex mutex;
    std::condition_variable cv;
    bool releaseFirst = false;
    bool releaseSecond = false;
    std::vector<std::string> sent;
    {
    edr::Reporter reporter("", "", 8,
        [&](const std::string& body) {
            std::unique_lock<std::mutex> lock(mutex);
            sent.push_back(body);
            const size_t attempt = sent.size();
            cv.notify_all();
            if (attempt == 1) {
                if (!cv.wait_for(lock, std::chrono::seconds(5),
                                 [&] { return releaseFirst; })) return false;
                return false;
            }
            if (attempt == 2) {
                if (!cv.wait_for(lock, std::chrono::seconds(5),
                                 [&] { return releaseSecond; })) return false;
            }
            return true;
        }, Options(temp));

    RS_CHECK(!reporter.Enqueue("not-before-start"));
    RS_CHECK(reporter.QueuedCount() == 0);
    RS_CHECK(reporter.Start());
    RS_CHECK(reporter.GetSpoolStatus() == "ready");
    RS_CHECK(reporter.Enqueue("persisted-body"));
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return !sent.empty(); });
        RS_CHECK(sent.front() == "persisted-body");
    }
    const auto files = SpoolFiles(temp.Spool());
    RS_CHECK(files.size() == 1);

    /* Directory and record DACLs must be protected and owner-only. */
    HANDLE directory = CreateFileW(temp.Spool().c_str(), READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    RS_CHECK(directory != INVALID_HANDLE_VALUE);
    RS_CHECK(ProtectedDaclSddl(directory) == "D:P(A;;FA;;;OW)");
    CloseHandle(directory);
    HANDLE record = CreateFileW(files.front().c_str(), READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    RS_CHECK(record != INVALID_HANDLE_VALUE);
    RS_CHECK(ProtectedDaclSddl(record) == "D:P(A;;FA;;;OW)");
    CloseHandle(record);

    {
        std::lock_guard<std::mutex> lock(mutex);
        releaseFirst = true;
    }
    cv.notify_all();
    reporter.Stop();
    RS_CHECK(reporter.QueuedCount() == 1);
    RS_CHECK(SpoolFiles(temp.Spool()).size() == 1);

    /* Restarting this same Reporter must not replay the same file twice into
     * memory. The one unacked item is retried once and ACK removes it. */
    RS_CHECK(reporter.Start());
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return sent.size() == 2; });
        RS_CHECK(sent[1] == "persisted-body");
    }
    const auto retryFiles = SpoolFiles(temp.Spool());
    RS_CHECK(retryFiles.size() == 1);
    RS_CHECK(retryFiles[0] == files[0]);
    {
        std::lock_guard<std::mutex> lock(mutex);
        releaseSecond = true;
    }
    cv.notify_all();
    for (unsigned attempt = 0; attempt < 50 && reporter.QueuedCount() != 0;
         ++attempt) Sleep(20);
    reporter.Stop();
    RS_CHECK(reporter.QueuedCount() == 0);
    RS_CHECK(sent.size() == 2);
    RS_CHECK(sent[0] == sent[1]);
    RS_CHECK(SpoolFiles(temp.Spool()).empty());
    }

    std::vector<std::string> restartedSends;
    edr::Reporter restarted("", "", 8,
        [&](const std::string& body) {
            restartedSends.push_back(body);
            return true;
        }, Options(temp));
    RS_CHECK(restarted.Start());
    RS_CHECK(restarted.QueuedCount() == 0);
    restarted.Stop();
    RS_CHECK(restartedSends.empty());
}

void TestSpoolBoundsRejectWithoutEvictingDurableBacklog() {
    TempDirectory temp;
    std::mutex mutex;
    std::condition_variable cv;
    bool release = false;
    auto options = Options(temp);
    options.maxRecords = 1;
    options.maxBytes = 512;
    options.maxItemBytes = 64;
    edr::Reporter reporter("", "", 8,
        [&](const std::string&) {
            std::unique_lock<std::mutex> lock(mutex);
            cv.notify_all();
            cv.wait_for(lock, std::chrono::seconds(5), [&] { return release; });
            return false;
        }, options);
    RS_CHECK(reporter.Start());
    RS_CHECK(reporter.Enqueue("A"));
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return !SpoolFiles(temp.Spool()).empty(); });
    }
    RS_CHECK(!reporter.Enqueue("B"));
    RS_CHECK(reporter.QueuedCount() == 1);
    RS_CHECK(reporter.DroppedCount() == 1);
    RS_CHECK(SpoolFiles(temp.Spool()).size() == 1);

    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    cv.notify_all();
    reporter.Stop();
}

void TestSpoolRejectsOversizeAndCorruptRecoveryFailsClosed() {
    {
        TempDirectory temp;
        auto options = Options(temp);
        options.maxItemBytes = 4;
        edr::Reporter reporter("", "", 8,
                               [](const std::string&) { return true; }, options);
        RS_CHECK(reporter.Start());
        RS_CHECK(!reporter.Enqueue("12345"));
        RS_CHECK(reporter.QueuedCount() == 0);
        RS_CHECK(SpoolFiles(temp.Spool()).empty());
        reporter.Stop();
    }
    {
        TempDirectory temp;
        auto options = Options(temp);
        options.maxBytes = 160;
        options.maxItemBytes = 128;
        edr::Reporter reporter("", "", 8,
                               [](const std::string&) { return true; }, options);
        RS_CHECK(reporter.Start());
        RS_CHECK(!reporter.Enqueue(std::string(32, 'x')));
        RS_CHECK(reporter.QueuedCount() == 0);
        RS_CHECK(SpoolFiles(temp.Spool()).empty());
        reporter.Stop();
    }
    {
        TempDirectory temp;
        RS_CHECK(CreateOwnerPinnedDirectory(temp.Spool()) != FALSE);
        std::string descriptorError;
        PSECURITY_DESCRIPTOR descriptor =
            edr::CreateOwnerOnlyDescriptor(descriptorError);
        RS_CHECK(descriptor != nullptr);
        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
        HANDLE corrupt = CreateFileW((temp.Spool() + L"\\corrupt.spool").c_str(),
            GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        LocalFree(descriptor);
        RS_CHECK(corrupt != INVALID_HANDLE_VALUE);
        const char bytes[] = "partial-record";
        DWORD written = 0;
        RS_CHECK(WriteFile(corrupt, bytes, sizeof(bytes) - 1, &written, nullptr));
        RS_CHECK(written == sizeof(bytes) - 1);
        CloseHandle(corrupt);

        edr::Reporter reporter("", "", 8,
                               [](const std::string&) { return true; },
                               Options(temp));
        RS_CHECK(!reporter.Start());
        RS_CHECK(reporter.GetSpoolStatus().find("failed") != std::string::npos);
        RS_CHECK(reporter.GetSpoolStatus().find("invalid magic") != std::string::npos);
        RS_CHECK(reporter.SpoolErrorCount() > 0);
        RS_CHECK(!reporter.Enqueue("must-not-fall-back-to-memory"));
        RS_CHECK(reporter.QueuedCount() == 0);
        RS_CHECK(GetFileAttributesW(
            (temp.Spool() + L"\\corrupt.spool").c_str()) != INVALID_FILE_ATTRIBUTES);
    }
}

void TestExistingSpoolIgnoresUnownedFiles() {
    TempDirectory temp;
    RS_CHECK(CreateOwnerPinnedDirectory(temp.Spool()) != FALSE);
    HANDLE keep = CreateFileW((temp.Spool() + L"\\keep.txt").c_str(),
        GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    RS_CHECK(keep != INVALID_HANDLE_VALUE);
    CloseHandle(keep);

    edr::Reporter reporter("", "", 8,
                           [](const std::string&) { return true; },
                           Options(temp));
    RS_CHECK(reporter.Start());
    RS_CHECK(reporter.GetSpoolStatus() == "ready");
    RS_CHECK(GetFileAttributesW(
        (temp.Spool() + L"\\keep.txt").c_str()) != INVALID_FILE_ATTRIBUTES);
    reporter.Stop();
}

void TestFreshReporterRecoversAfterTransportException() {
    TempDirectory temp;
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool called = false;
        edr::Reporter reporter("", "", 8,
            [&](const std::string& body) -> bool {
                RS_CHECK(body == "survives-restart");
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    called = true;
                }
                cv.notify_all();
                throw std::runtime_error("simulated transport failure");
            }, Options(temp));
        RS_CHECK(reporter.Start());
        RS_CHECK(reporter.Enqueue("survives-restart"));
        {
            std::unique_lock<std::mutex> lock(mutex);
            WaitFor(cv, lock, [&] { return called; });
        }
        reporter.Stop();
        RS_CHECK(reporter.QueuedCount() == 1);
        RS_CHECK(SpoolFiles(temp.Spool()).size() == 1);
    }

    const auto existing = SpoolFiles(temp.Spool());
    RS_CHECK(existing.size() == 1);
    HANDLE existingDirectory = CreateFileW(temp.Spool().c_str(), READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    RS_CHECK(existingDirectory != INVALID_HANDLE_VALUE);
    RS_CHECK(ProtectedDaclSddl(existingDirectory) == "D:P(A;;FA;;;OW)");
    CloseHandle(existingDirectory);
    HANDLE existingRecord = CreateFileW(existing.front().c_str(), READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    RS_CHECK(existingRecord != INVALID_HANDLE_VALUE);
    RS_CHECK(ProtectedDaclSddl(existingRecord) == "D:P(A;;FA;;;OW)");
    CloseHandle(existingRecord);

    std::mutex mutex;
    std::condition_variable cv;
    std::vector<std::string> delivered;
    edr::Reporter recovered("", "", 8,
        [&](const std::string& body) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                delivered.push_back(body);
            }
            cv.notify_all();
            return true;
        }, Options(temp));
    RS_CHECK(recovered.Start());
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return delivered.size() == 1; });
    }
    for (unsigned attempt = 0; attempt < 50 && recovered.QueuedCount() != 0;
         ++attempt) Sleep(20);
    recovered.Stop();
    RS_CHECK(delivered.size() == 1);
    RS_CHECK(delivered[0] == "survives-restart");
    RS_CHECK(SpoolFiles(temp.Spool()).empty());
}

void TestAcknowledgmentFailureStopsWorkerAndPreservesItem() {
    TempDirectory temp;
    auto options = Options(temp);
    options.beforeAcknowledge = [] { return false; };
    std::mutex mutex;
    std::condition_variable cv;
    bool posted = false;
    edr::Reporter reporter("https://collector.test/ingest", "", 8,
        [&](const std::string& body) {
            RS_CHECK(body == "keep-after-ack-failure");
            {
                std::lock_guard<std::mutex> lock(mutex);
                posted = true;
            }
            cv.notify_all();
            return true;
        }, options);
    RS_CHECK(reporter.Start());
    RS_CHECK(reporter.Enqueue("keep-after-ack-failure"));
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return posted; });
    }
    for (unsigned attempt = 0; attempt < 500 &&
         reporter.GetRuntimeState() != "worker_failed"; ++attempt) Sleep(10);
    RS_CHECK(reporter.GetRuntimeState() == "worker_failed");
    RS_CHECK(reporter.GetSpoolStatus().find("failed") != std::string::npos);
    RS_CHECK(reporter.QueuedCount() == 1);
    RS_CHECK(!reporter.Enqueue("reject-after-ack-failure"));
    RS_CHECK(SpoolFiles(temp.Spool()).size() == 1);
    reporter.Stop();
}

void TestLiveSpoolOwnerExclusionAndStopLifetime() {
    TempDirectory temp;
    {
        edr::Reporter owner("", "", 8,
            [](const std::string&) { return false; }, Options(temp));
        RS_CHECK(owner.Start());

        edr::Reporter contender("", "", 8,
            [](const std::string&) { return true; }, Options(temp));
        RS_CHECK(!contender.Start());
        RS_CHECK(contender.GetSpoolStatus().find("failed") != std::string::npos);

        owner.Stop();
        /* Stop drains the worker but retains the object's lock/handles. */
        edr::Reporter stoppedOwnerContender("", "", 8,
            [](const std::string&) { return true; }, Options(temp));
        RS_CHECK(!stoppedOwnerContender.Start());
    }

    edr::Reporter afterOwnerDestruction("", "", 8,
        [](const std::string&) { return true; }, Options(temp));
    RS_CHECK(afterOwnerDestruction.Start());
    RS_CHECK(afterOwnerDestruction.GetSpoolStatus() == "ready");
    afterOwnerDestruction.Stop();
}

void TestInvalidDirectoryStringsDoNotTouchTruncatedPath() {
    TempDirectory temp;
    const std::string root = Utf8(temp.Root());
    const std::string originalAcl = [&] {
        HANDLE directory = CreateFileW(temp.Root().c_str(), READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        RS_CHECK(directory != INVALID_HANDLE_VALUE);
        const std::string acl = ProtectedDaclSddl(directory);
        CloseHandle(directory);
        return acl;
    }();

    auto nulOptions = Options(temp);
    nulOptions.directory = root + std::string(1, '\0') + "\\should-not-open";
    edr::Reporter nulReporter("", "", 8,
        [](const std::string&) { return true; }, nulOptions);
    RS_CHECK(!nulReporter.Start());
    RS_CHECK(nulReporter.GetSpoolStatus().find("failed") != std::string::npos);
    nulReporter.Stop();

    HANDLE after = CreateFileW(temp.Root().c_str(), READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
            FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    RS_CHECK(after != INVALID_HANDLE_VALUE);
    RS_CHECK(ProtectedDaclSddl(after) == originalAcl);
    CloseHandle(after);

    auto malformedOptions = Options(temp);
    malformedOptions.directory = std::string("C:\\bad\\") +
        static_cast<char>(0xC3) + "(";
    edr::Reporter malformed("", "", 8,
        [](const std::string&) { return true; }, malformedOptions);
    RS_CHECK(!malformed.Start());
    RS_CHECK(malformed.GetSpoolStatus().find("failed") != std::string::npos);
}

void TestRecoveryRejectsDifferentDestinationAndPreservesBacklog() {
    TempDirectory temp;
    const auto options = Options(temp);
    const std::string originalBody = "keep-for-original-endpoint";
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool attempted = false;
        edr::Reporter original("https://collector.test/ingest", "secret-one", 8,
            [&](const std::string& body) {
                RS_CHECK(body == originalBody);
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    attempted = true;
                }
                cv.notify_all();
                return false;
            }, options);
        RS_CHECK(original.Start());
        RS_CHECK(original.Enqueue(originalBody));
        {
            std::unique_lock<std::mutex> lock(mutex);
            WaitFor(cv, lock, [&] { return attempted; });
        }
        original.Stop();
        RS_CHECK(original.QueuedCount() == 1);
        RS_CHECK(SpoolFiles(temp.Spool()).size() == 1);
    }

    const auto filesBeforeMismatch = SpoolFiles(temp.Spool());
    RS_CHECK(filesBeforeMismatch.size() == 1);
    {
        edr::Reporter changedPath("https://collector.test/ingest/events", "secret-one",
            8, [](const std::string&) { return true; }, options);
        RS_CHECK(!changedPath.Start());
        RS_CHECK(changedPath.GetSpoolStatus().find("destination") != std::string::npos);
        RS_CHECK(SpoolFiles(temp.Spool()) == filesBeforeMismatch);
        changedPath.Stop();
    }

    /* API-key rotation at the same exact URL preserves the configured
     * destination contract; key material itself is never written to disk. */
    {
        edr::Reporter rotatedKey("https://collector.test/ingest", "secret-two", 8,
            [](const std::string&) { return false; }, options);
        RS_CHECK(rotatedKey.Start());
        RS_CHECK(rotatedKey.QueuedCount() == 1);
        RS_CHECK(SpoolFiles(temp.Spool()) == filesBeforeMismatch);
        rotatedKey.Stop();
    }

    for (const auto& path : filesBeforeMismatch) {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        RS_CHECK(file != INVALID_HANDLE_VALUE);
        LARGE_INTEGER size = {};
        RS_CHECK(GetFileSizeEx(file, &size) != FALSE && size.QuadPart > 0);
        std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
        DWORD read = 0;
        RS_CHECK(ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()),
                          &read, nullptr) != FALSE);
        RS_CHECK(read == bytes.size());
        CloseHandle(file);
        RS_CHECK(bytes.find("secret-one") == std::string::npos);
        RS_CHECK(bytes.find("secret-two") == std::string::npos);
        RS_CHECK(bytes.find("https://collector.test") == std::string::npos);
    }
}

void TestLegacyUnboundRecordFailsExplicitlyAndIsPreserved() {
    TempDirectory temp;
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool attempted = false;
        edr::Reporter writer("https://collector.test/ingest", "secret", 8,
            [&](const std::string&) {
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    attempted = true;
                }
                cv.notify_all();
                return false;
            }, Options(temp));
        RS_CHECK(writer.Start());
        RS_CHECK(writer.Enqueue("legacy-envelope-upgrade-test"));
        {
            std::unique_lock<std::mutex> lock(mutex);
            WaitFor(cv, lock, [&] { return attempted; });
        }
        writer.Stop();
        RS_CHECK(writer.QueuedCount() == 1);
    }
    const auto files = SpoolFiles(temp.Spool());
    RS_CHECK(files.size() == 1);
    const char bytes[] = "EDR-SPOOL-1\nlegacy-record";
    HANDLE legacy = CreateFileW(files.front().c_str(), GENERIC_WRITE,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    RS_CHECK(legacy != INVALID_HANDLE_VALUE);
    LARGE_INTEGER zero = {};
    RS_CHECK(SetFilePointerEx(legacy, zero, nullptr, FILE_BEGIN) != FALSE);
    DWORD written = 0;
    RS_CHECK(WriteFile(legacy, bytes, sizeof(bytes) - 1, &written, nullptr) != FALSE);
    RS_CHECK(written == sizeof(bytes) - 1);
    RS_CHECK(SetEndOfFile(legacy) != FALSE);
    RS_CHECK(FlushFileBuffers(legacy) != FALSE);
    CloseHandle(legacy);
    const std::wstring path = files.front();

    edr::Reporter reporter("https://collector.test/ingest", "secret", 8,
        [](const std::string&) { return true; }, Options(temp));
    RS_CHECK(!reporter.Start());
    RS_CHECK(reporter.GetSpoolStatus().find("legacy spool") != std::string::npos);
    HANDLE preserved = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    RS_CHECK(preserved != INVALID_HANDLE_VALUE);
    char actual[sizeof(bytes)] = {};
    DWORD read = 0;
    RS_CHECK(ReadFile(preserved, actual, sizeof(bytes) - 1, &read, nullptr) != FALSE);
    RS_CHECK(read == sizeof(bytes) - 1);
    RS_CHECK(std::string(actual, read) == std::string(bytes, sizeof(bytes) - 1));
    CloseHandle(preserved);
    reporter.Stop();
}

} // namespace

void RunReporterSpoolTests() {
    std::fprintf(stderr, "[reporter_spool] durable enqueue/restart/ack\n");
    TestDurableEnqueuePersistsBeforePostAndRestartReusesOneItem();
    std::fprintf(stderr, "[reporter_spool] bounded backlog\n");
    TestSpoolBoundsRejectWithoutEvictingDurableBacklog();
    std::fprintf(stderr, "[reporter_spool] oversize/corrupt recovery\n");
    TestSpoolRejectsOversizeAndCorruptRecoveryFailsClosed();
    std::fprintf(stderr, "[reporter_spool] unknown file preservation\n");
    TestExistingSpoolIgnoresUnownedFiles();
    std::fprintf(stderr, "[reporter_spool] restart after callback exception\n");
    TestFreshReporterRecoversAfterTransportException();
    std::fprintf(stderr, "[reporter_spool] acknowledgment failure\n");
    TestAcknowledgmentFailureStopsWorkerAndPreservesItem();
    std::fprintf(stderr, "[reporter_spool] exclusive live owner\n");
    TestLiveSpoolOwnerExclusionAndStopLifetime();
    std::fprintf(stderr, "[reporter_spool] invalid path strings\n");
    TestInvalidDirectoryStringsDoNotTouchTruncatedPath();
    std::fprintf(stderr, "[reporter_spool] changed destination binding\n");
    TestRecoveryRejectsDifferentDestinationAndPreservesBacklog();
    std::fprintf(stderr, "[reporter_spool] legacy unbound record\n");
    TestLegacyUnboundRecordFailsExplicitlyAndIsPreserved();
}
