#include <chrono>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#include "owner_only_sd.h"
#include "reporter.h"

namespace {

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("reporter metrics test failed at line " +
                                 std::to_string(line) + ": " + expression);
    }
}

#define CHECK(condition) Check((condition), #condition, __LINE__)

template <typename Predicate>
void WaitFor(std::condition_variable& cv, std::unique_lock<std::mutex>& lock,
             Predicate predicate) {
    CHECK(cv.wait_for(lock, std::chrono::seconds(5), predicate));
}

template <typename Predicate>
void WaitForStats(const edr::Reporter& reporter, Predicate predicate) {
    for (int attempt = 0; attempt < 5000; ++attempt) {
        if (predicate(reporter.GetDeliveryStats())) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(predicate(reporter.GetDeliveryStats()));
}

std::string Utf8Path(const std::wstring& value) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                         value.data(),
                                         static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    CHECK(size > 0);
    std::string result(static_cast<size_t>(size), '\0');
    CHECK(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                              value.data(), static_cast<int>(value.size()),
                              result.data(), size, nullptr, nullptr) == size);
    return result;
}

class TempDirectory {
public:
    TempDirectory() {
        wchar_t temp[MAX_PATH] = {};
        const DWORD tempLength = GetTempPathW(MAX_PATH, temp);
        CHECK(tempLength > 0 && tempLength < MAX_PATH);
        wchar_t unique[MAX_PATH] = {};
        CHECK(GetTempFileNameW(temp, L"edr", 0, unique) != 0);
        CHECK(DeleteFileW(unique) != FALSE);

        std::string descriptorError;
        PSECURITY_DESCRIPTOR descriptor =
            edr::CreateOwnerOnlyDescriptor(descriptorError);
        CHECK(descriptor != nullptr);
        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
        const BOOL created = CreateDirectoryW(unique, &attributes);
        LocalFree(descriptor);
        CHECK(created != FALSE);
        m_root = unique;
        m_spool = m_root + L"\\spool";
    }

    ~TempDirectory() {
        const std::wstring pattern = m_spool + L"\\*";
        WIN32_FIND_DATAW entry{};
        HANDLE find = FindFirstFileW(pattern.c_str(), &entry);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    DeleteFileW((m_spool + L"\\" + entry.cFileName).c_str());
            } while (FindNextFileW(find, &entry));
            FindClose(find);
        }
        RemoveDirectoryW(m_spool.c_str());
        RemoveDirectoryW(m_root.c_str());
    }

    const std::wstring& Spool() const { return m_spool; }

private:
    std::wstring m_root;
    std::wstring m_spool;
};

void CheckConservation(const edr::Reporter::DeliveryStats& stats) {
    CHECK(stats.attempts == stats.succeeded + stats.failed +
          (stats.inProgress ? 1U : 0U));
}

void TestAttemptIsVisibleBeforePostAndWhileBlocked() {
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false;
    bool release = false;
    edr::Reporter* reporterPointer = nullptr;
    edr::Reporter reporter("", "", 4, [&](const std::string&) {
        const auto during = reporterPointer->GetDeliveryStats();
        CHECK(during.attempts == 1);
        CHECK(during.succeeded == 0);
        CHECK(during.failed == 0);
        CHECK(during.inProgress);
        CHECK(during.lastAttempt100ns != 0);
        CheckConservation(during);
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        cv.notify_all();
        WaitFor(cv, lock, [&] { return release; });
        return true;
    });
    reporterPointer = &reporter;
    CHECK(reporter.Enqueue("one"));
    CHECK(reporter.Start());
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return entered; });
    }
    auto during = reporter.GetDeliveryStats();
    CHECK(during.attempts == 1 && during.inProgress);
    CheckConservation(during);
    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    cv.notify_all();
    reporter.Stop();
    const auto after = reporter.GetDeliveryStats();
    CHECK(after.attempts == 1 && after.succeeded == 1 && after.failed == 0);
    CHECK(after.consecutiveFailures == 0 && !after.inProgress);
    CHECK(after.lastAttempt100ns != 0 && after.lastSuccess100ns != 0);
    CHECK(after.lastSuccess100ns >= after.lastAttempt100ns);
    CheckConservation(after);
}

void TestFailureThenSuccessResetsConsecutiveFailures() {
    std::mutex mutex;
    std::condition_variable cv;
    int calls = 0;
    bool secondEntered = false;
    bool releaseSecond = false;
    edr::Reporter reporter("", "", 4, [&](const std::string&) {
        std::unique_lock<std::mutex> lock(mutex);
        ++calls;
        cv.notify_all();
        if (calls == 1) return false;
        secondEntered = true;
        cv.notify_all();
        WaitFor(cv, lock, [&] { return releaseSecond; });
        return true;
    });
    CHECK(reporter.Enqueue("retry-me"));
    CHECK(reporter.Start());
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return calls == 1; });
    }
    WaitForStats(reporter, [](const auto& stats) { return stats.failed == 1; });
    auto failed = reporter.GetDeliveryStats();
    CHECK(failed.attempts == 1 && failed.failed == 1);
    CHECK(failed.succeeded == 0 && failed.consecutiveFailures == 1);
    CHECK(!failed.inProgress && failed.lastAttempt100ns != 0);
    CheckConservation(failed);
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return secondEntered; });
    }
    failed = reporter.GetDeliveryStats();
    CHECK(failed.attempts == 2 && failed.failed == 1 && failed.inProgress);
    CHECK(failed.consecutiveFailures == 1);
    CheckConservation(failed);
    {
        std::lock_guard<std::mutex> lock(mutex);
        releaseSecond = true;
    }
    cv.notify_all();
    WaitForStats(reporter, [](const auto& stats) {
        return stats.succeeded == 1 && !stats.inProgress;
    });
    reporter.Stop();
    const auto delivered = reporter.GetDeliveryStats();
    CHECK(delivered.attempts == 2 && delivered.failed == 1);
    CHECK(delivered.succeeded == 1 && delivered.consecutiveFailures == 0);
    CHECK(!delivered.inProgress && delivered.lastSuccess100ns != 0);
    CheckConservation(delivered);
}

void TestExceptionCountsAsFailedAttempt() {
    std::mutex mutex;
    std::condition_variable cv;
    int calls = 0;
    bool secondEntered = false;
    bool releaseSecond = false;
    edr::Reporter reporter("", "", 4, [&](const std::string&) -> bool {
        std::unique_lock<std::mutex> lock(mutex);
        ++calls;
        cv.notify_all();
        if (calls == 1) throw std::runtime_error("synthetic post exception");
        secondEntered = true;
        cv.notify_all();
        WaitFor(cv, lock, [&] { return releaseSecond; });
        return false;
    });
    CHECK(reporter.Enqueue("exception-then-failure"));
    CHECK(reporter.Start());
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return calls == 1; });
    }
    WaitForStats(reporter, [](const auto& stats) { return stats.failed == 1; });
    auto stats = reporter.GetDeliveryStats();
    CHECK(stats.attempts == 1 && stats.failed == 1);
    CHECK(stats.consecutiveFailures == 1 && !stats.inProgress);
    CheckConservation(stats);
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return secondEntered; });
    }
    stats = reporter.GetDeliveryStats();
    CHECK(stats.attempts == 2 && stats.failed == 1 && stats.inProgress);
    CHECK(stats.consecutiveFailures == 1);
    CheckConservation(stats);
    {
        std::lock_guard<std::mutex> lock(mutex);
        releaseSecond = true;
    }
    cv.notify_all();
    WaitForStats(reporter, [](const auto& stats) {
        return stats.failed == 2 && !stats.inProgress;
    });
    reporter.Stop();
    stats = reporter.GetDeliveryStats();
    CHECK(stats.attempts == 2 && stats.failed == 2 && stats.succeeded == 0);
    CHECK(stats.consecutiveFailures == 2 && !stats.inProgress);
    CheckConservation(stats);
}

void TestAcceptedPostCountsAsSuccessWhenSpoolAckFails() {
    TempDirectory temp;
    std::mutex mutex;
    std::condition_variable cv;
    bool posted = false;
    edr::ReporterSpoolOptions spoolOptions;
    spoolOptions.directory = Utf8Path(temp.Spool());
    spoolOptions.beforeAcknowledge = [] { return false; };
    {
        edr::Reporter reporter("https://collector.test/ingest", "", 4,
            [&](const std::string& body) {
                CHECK(body == "accepted-before-ack-failure");
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    posted = true;
                }
                cv.notify_all();
                return true;
            }, spoolOptions);
        CHECK(reporter.Start());
        CHECK(reporter.Enqueue("accepted-before-ack-failure"));
        {
            std::unique_lock<std::mutex> lock(mutex);
            WaitFor(cv, lock, [&] { return posted; });
        }
        for (int i = 0; i < 500 && reporter.GetRuntimeState() != "worker_failed"; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        CHECK(reporter.GetRuntimeState() == "worker_failed");
        const auto stats = reporter.GetDeliveryStats();
        CHECK(stats.attempts == 1 && stats.succeeded == 1 && stats.failed == 0);
        CHECK(stats.consecutiveFailures == 0 && !stats.inProgress);
        CHECK(stats.lastAttempt100ns != 0 && stats.lastSuccess100ns != 0);
        CHECK(reporter.QueuedCount() == 1);
        CheckConservation(stats);
        reporter.Stop();
    }
}

void TestCountersAccumulateAcrossStopAndRestart() {
    std::mutex mutex;
    std::condition_variable cv;
    bool firstEntered = false;
    bool releaseFirst = false;
    int calls = 0;
    edr::Reporter reporter("", "", 4, [&](const std::string&) {
        std::unique_lock<std::mutex> lock(mutex);
        ++calls;
        if (calls == 1) {
            firstEntered = true;
            cv.notify_all();
            WaitFor(cv, lock, [&] { return releaseFirst; });
        }
        cv.notify_all();
        return true;
    });
    CHECK(reporter.Enqueue("first"));
    CHECK(reporter.Start());
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return firstEntered; });
    }
    CHECK(reporter.Enqueue("second"));
    std::thread stopper([&] { reporter.Stop(); });
    for (int i = 0; i < 500 && reporter.GetRuntimeState() != "stopping"; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    CHECK(reporter.GetRuntimeState() == "stopping");
    {
        std::lock_guard<std::mutex> lock(mutex);
        releaseFirst = true;
    }
    cv.notify_all();
    stopper.join();
    auto stats = reporter.GetDeliveryStats();
    CHECK(stats.attempts == 1 && stats.succeeded == 1 && !stats.inProgress);
    CHECK(reporter.Start());
    WaitForStats(reporter, [](const auto& stats) { return stats.succeeded == 2; });
    reporter.Stop();
    stats = reporter.GetDeliveryStats();
    CHECK(calls == 2);
    CHECK(stats.attempts == 2 && stats.succeeded == 2 && stats.failed == 0);
    CHECK(stats.consecutiveFailures == 0 && !stats.inProgress);
    CheckConservation(stats);
}

void TestConcurrentSnapshotsPreserveConservation() {
    std::mutex mutex;
    std::condition_variable cv;
    bool release = false;
    bool entered = false;
    edr::Reporter reporter("", "", 4, [&](const std::string&) {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        cv.notify_all();
        WaitFor(cv, lock, [&] { return release; });
        return true;
    });
    CHECK(reporter.Enqueue("snapshot"));
    CHECK(reporter.Start());
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return entered; });
    }
    std::atomic<bool> stopReaders{false};
    std::atomic<bool> invalidSnapshot{false};
    std::thread reader([&] {
        while (!stopReaders.load()) {
            const auto stats = reporter.GetDeliveryStats();
            if (stats.attempts != stats.succeeded + stats.failed +
                                      (stats.inProgress ? 1U : 0U))
                invalidSnapshot.store(true);
        }
    });
    for (int i = 0; i < 1000; ++i) CheckConservation(reporter.GetDeliveryStats());
    stopReaders.store(true);
    reader.join();
    CHECK(!invalidSnapshot.load());
    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    cv.notify_all();
    reporter.Stop();
    CheckConservation(reporter.GetDeliveryStats());
}

} // namespace

int main() {
    try {
        TestAttemptIsVisibleBeforePostAndWhileBlocked();
        TestFailureThenSuccessResetsConsecutiveFailures();
        TestExceptionCountsAsFailedAttempt();
        TestAcceptedPostCountsAsSuccessWhenSpoolAckFails();
        TestCountersAccumulateAcrossStopAndRestart();
        TestConcurrentSnapshotsPreserveConservation();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "reporter metrics tests passed\n";
    return 0;
}
