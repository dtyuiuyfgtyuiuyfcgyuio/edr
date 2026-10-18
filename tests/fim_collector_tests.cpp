#include <windows.h>

#include <chrono>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector.h"
#include "collector_fim.h"
#include "threat_intel_detector.h"
#include "rule_engine.h"

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}

std::string ToUtf8(const std::wstring& value) {
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    Require(bytes > 0, "temporary path converts to UTF-8");
    std::string result(static_cast<size_t>(bytes), '\0');
    Require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(),
        static_cast<int>(value.size()), &result[0], bytes, nullptr, nullptr) == bytes,
        "UTF-8 path conversion completes");
    return result;
}

class TempDir {
public:
    TempDir() {
        wchar_t root[MAX_PATH] = {};
        Require(GetTempPathW(MAX_PATH, root) != 0, "temporary root is available");
        wchar_t unique[MAX_PATH] = {};
        Require(GetTempFileNameW(root, L"fim", 0, unique) != 0,
                "unique temporary name is available");
        Require(DeleteFileW(unique) != FALSE, "temporary name file is removed");
        Require(CreateDirectoryW(unique, nullptr) != FALSE, "private temp directory is created");
        m_root = unique;
    }
    ~TempDir() {
        for (const auto& file : m_files) DeleteFileW(file.c_str());
        RemoveDirectoryW(m_root.c_str());
    }
    std::wstring AddPath(const wchar_t* leaf) {
        auto path = m_root + L"\\" + leaf;
        m_files.push_back(path);
        return path;
    }
private:
    std::wstring m_root;
    std::vector<std::wstring> m_files;
};

void PutFixtureFile(const std::wstring& path, const char* data, size_t size) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        std::fprintf(stderr, "CreateFileW failed with %lu for fixture path\n",
                     static_cast<unsigned long>(GetLastError()));
    Require(file != INVALID_HANDLE_VALUE, "fixture file opens for writing");
    DWORD written = 0;
    const BOOL ok = WriteFile(file, data, static_cast<DWORD>(size), &written, nullptr);
    CloseHandle(file);
    Require(ok && written == size, "fixture content is written");
}

void RewriteFixtureFile(const std::wstring& path, const char* data, size_t size) {
    HANDLE file = INVALID_HANDLE_VALUE;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        file = CreateFileW(path.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) break;
        const DWORD error = GetLastError();
        Require(error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED,
                "temporary file lock is the only retryable rewrite failure");
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    Require(file != INVALID_HANDLE_VALUE, "temporary file becomes writable between snapshots");
    LARGE_INTEGER start = {};
    DWORD written = 0;
    const BOOL seeked = SetFilePointerEx(file, start, nullptr, FILE_BEGIN);
    const BOOL wrote = seeked && WriteFile(file, data, static_cast<DWORD>(size),
                                           &written, nullptr);
    const BOOL sized = wrote && SetEndOfFile(file);
    CloseHandle(file);
    Require(sized && written == size, "same-size fixture rewrite completes");
}

std::string Field(const edr::Event& event, const char* name) {
    const auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

class Recorder final : public edr::ISink {
public:
    void OnEvent(const edr::Event& event) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_events.push_back(event);
    }
    std::vector<edr::Event> Events() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_events;
    }
private:
    mutable std::mutex m_mutex;
    std::vector<edr::Event> m_events;
};

bool WaitForEvents(Recorder& recorder, size_t count) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (recorder.Events().size() >= count) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return recorder.Events().size() >= count;
}

bool WaitUntil(const std::function<bool()>& ready) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (ready()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return ready();
}

edr::FimSnapshot Complete(uint64_t size, const char* digest) {
    edr::FimSnapshot snapshot;
    snapshot.status = edr::FimSnapshotStatus::Complete;
    snapshot.size = size;
    snapshot.sha256 = digest;
    return snapshot;
}

void MissingWatchPathCanAppearAndBeRemoved() {
    TempDir temp;
    const auto path = temp.AddPath(L"appears.bin");
    const auto pathUtf8 = ToUtf8(path);
    edr::EventBus bus(32);
    Recorder recorder;
    bus.Start(&recorder);
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateFimCollector(40, 1024 * 1024, {pathUtf8}));
    Require(collector->Start(&bus), "FIM collector starts for a fixed missing path");
    std::this_thread::sleep_for(std::chrono::milliseconds(180));
    PutFixtureFile(path, "first", 5);
    Require(WaitForEvents(recorder, 1), "missing-to-present transition emits added");
    auto events = recorder.Events();
    Require(Field(events[0], "fim_action") == "added", "appearance action is added");
    Require(Field(events[0], "fim_size") == "5", "added event has the real file size");
    Require(Field(events[0], "fim_sha256").size() == 64, "added event carries SHA-256");
    collector->Stop();
    bus.Stop();
    Require(DeleteFileW(path.c_str()) != FALSE, "fixture file is removed before temp cleanup");
}

void SameSizeContentChangeAndRemovalAreReported() {
    TempDir temp;
    const auto path = temp.AddPath(L"changes.bin");
    PutFixtureFile(path, "first", 5);
    edr::EventBus bus(32);
    Recorder recorder;
    bus.Start(&recorder);
    std::unique_ptr<edr::ICollector> collector(edr::CreateFimCollector(
        40, 1024 * 1024, {ToUtf8(path)}));
    Require(collector->Start(&bus), "FIM collector starts for an existing file");
    std::this_thread::sleep_for(std::chrono::milliseconds(180));
    RewriteFixtureFile(path, "other", 5);
    Require(WaitForEvents(recorder, 1), "same-size content change emits modified");
    auto events = recorder.Events();
    Require(Field(events[0], "fim_action") == "modified", "content change action is modified");
    Require(Field(events[0], "fim_sha256").size() == 64, "modified event has the verified digest");
    Require(DeleteFileW(path.c_str()) != FALSE, "fixture deletion is successful");
    Require(WaitForEvents(recorder, 2), "present-to-missing transition emits removed");
    events = recorder.Events();
    Require(Field(events[1], "fim_action") == "removed", "deletion action is removed");
    collector->Stop();
    bus.Stop();
}

void FailedQueriesRetainBaselineAndAreVisibleInHealth() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(32);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&calls](const std::string&, uint64_t) {
        const unsigned call = calls.fetch_add(1);
        if (call == 0) return Complete(5, std::string(64, 'a').c_str());
        if (call == 1) {
            edr::FimSnapshot denied;
            denied.status = edr::FimSnapshotStatus::Missing;
            denied.statusCode = ERROR_ACCESS_DENIED;
            return denied;
        }
        return Complete(5, std::string(64, 'b').c_str());
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateFimCollector(30, 1024, {"C:\\fim-test.bin"}, query));
    Require(collector->Start(&bus), "collector accepts its deterministic query seam");
    Require(WaitForEvents(recorder, 1),
            "successful hash after an access failure compares against the retained baseline");
    const auto events = recorder.Events();
    Require(Field(events[0], "fim_action") == "modified",
            "failed observation does not turn a same-size content change into added");
    collector->Stop();
    bus.Stop();
}

void PersistentFailureAndOversizedFileAreReportedInHealth() {
    std::unique_ptr<edr::ICollector> failed(edr::CreateFimCollector(
        20, 8, {"C:\\denied.bin"}, [](const std::string&, uint64_t) {
            edr::FimSnapshot snapshot;
            snapshot.status = edr::FimSnapshotStatus::Failed;
            snapshot.statusCode = ERROR_ACCESS_DENIED;
            return snapshot;
        }));
    edr::EventBus bus(8);
    Require(failed->Start(&bus), "failure fixture starts");
    Require(WaitUntil([&] {
        const auto health = failed->GetHealthSnapshot();
        const auto count = health.counters.find("watch_files_failed_current");
        return count != health.counters.end() && count->second == 1 &&
               health.sourceErrors != 0;
    }), "persistent access failure is visible in collector health");
    failed->Stop();

    std::unique_ptr<edr::ICollector> oversized(edr::CreateFimCollector(
        20, 8, {"C:\\large.bin"}, [](const std::string&, uint64_t) {
            edr::FimSnapshot snapshot;
            snapshot.status = edr::FimSnapshotStatus::Failed;
            snapshot.statusCode = ERROR_FILE_TOO_LARGE;
            snapshot.size = 9;
            snapshot.oversized = true;
            return snapshot;
        }));
    Require(oversized->Start(&bus), "oversized fixture starts");
    Require(WaitUntil([&] {
        const auto health = oversized->GetHealthSnapshot();
        const auto count = health.counters.find("watch_files_oversized_uncovered_current");
        return count != health.counters.end() && count->second == 1 &&
               health.state == "coverage_degraded";
    }), "oversized watch file is explicitly uncovered in health");
    oversized->Stop();
}

void InvalidSnapshotsNeverCreateFalseTransitions() {
    std::vector<std::pair<const char*, std::function<edr::FimSnapshot()>>> invalid;
    invalid.push_back({"unknown enum", [] {
        edr::FimSnapshot result;
        result.status = static_cast<edr::FimSnapshotStatus>(99);
        return result;
    }});
    invalid.push_back({"non-hex digest", [] {
        auto result = Complete(5, std::string(64, 'g').c_str());
        return result;
    }});
    invalid.push_back({"size above max", [] {
        return Complete(9, std::string(64, 'b').c_str());
    }});
    invalid.push_back({"oversized without matching status", [] {
        edr::FimSnapshot result;
        result.status = edr::FimSnapshotStatus::Failed;
        result.statusCode = ERROR_ACCESS_DENIED;
        result.size = 9;
        result.oversized = true;
        return result;
    }});
    invalid.push_back({"not found with payload", [] {
        edr::FimSnapshot result;
        result.status = edr::FimSnapshotStatus::Missing;
        result.statusCode = ERROR_FILE_NOT_FOUND;
        result.size = 1;
        return result;
    }});

    for (const auto& testCase : invalid) {
        std::atomic<unsigned> calls{0};
        std::atomic<unsigned> invalidObservations{0};
        std::atomic<bool> publishValid{false};
        edr::EventBus bus(16);
        Recorder recorder;
        bus.Start(&recorder);
        auto query = [&](const std::string&, uint64_t) {
            if (calls.fetch_add(1) == 0) return Complete(5, std::string(64, 'a').c_str());
            if (publishValid.load()) return Complete(5, std::string(64, 'b').c_str());
            invalidObservations.fetch_add(1);
            return testCase.second();
        };
        std::unique_ptr<edr::ICollector> collector(edr::CreateFimCollector(
            15, 8, {"C:\\invalid-snapshot.bin"}, query));
        Require(collector->Start(&bus), "invalid-snapshot fixture starts");
        Require(WaitUntil([&] { return invalidObservations.load() >= 2; }),
                "invalid snapshot is observed more than once");
        Require(recorder.Events().empty(), testCase.first);
        publishValid.store(true);
        Require(WaitForEvents(recorder, 1),
                "valid snapshot after invalid data compares with the retained baseline");
        const auto events = recorder.Events();
        Require(events.size() == 1 && Field(events[0], "fim_action") == "modified",
                "invalid observation does not synthesize removed or added");
        collector->Stop();
        bus.Stop();
    }
}

void InvalidWatchConfigurationIsRejectedAndFatalWorkerStops() {
    edr::EventBus bus(8);
    std::unique_ptr<edr::ICollector> nulPath(edr::CreateFimCollector(
        20, 8, {std::string("C:\\a\0b", 6)}));
    Require(!nulPath->Start(&bus), "embedded NUL watch path is rejected");
    Require(nulPath->GetHealthSnapshot().state == "config_error",
            "invalid watch configuration is visible in health");
    std::unique_ptr<edr::ICollector> invalidUtf8(edr::CreateFimCollector(
        20, 8, {std::string("\xff", 1)}));
    Require(!invalidUtf8->Start(&bus), "invalid UTF-8 watch path is rejected");
    std::vector<std::string> tooMany(257, "C:\\a");
    std::unique_ptr<edr::ICollector> excessive(edr::CreateFimCollector(
        20, 8, std::move(tooMany)));
    Require(!excessive->Start(&bus), "excessive watch count is rejected");
    std::unique_ptr<edr::ICollector> tooLong(edr::CreateFimCollector(
        20, 8, {std::string(32769, 'x')}));
    Require(!tooLong->Start(&bus), "excessive UTF-8 path bytes are rejected");
    std::vector<std::string> overBudget(33, std::string(32768, 'x'));
    std::unique_ptr<edr::ICollector> overBudgetPaths(edr::CreateFimCollector(
        20, 8, std::move(overBudget)));
    Require(!overBudgetPaths->Start(&bus), "aggregate UTF-8 path budget is enforced");

    std::unique_ptr<edr::ICollector> fatal(edr::CreateFimCollector(
        20, 8, {"C:\\throw.bin"}, [](const std::string&, uint64_t) -> edr::FimSnapshot {
            throw 7;
        }));
    Require(fatal->Start(&bus), "fatal query worker starts");
    Require(WaitUntil([&] {
        const auto health = fatal->GetHealthSnapshot();
        return !health.running && health.state == "source_error";
    }), "query exception terminates the worker with source error health");
    Require(!fatal->Start(&bus), "joinable failed worker is not reported as started");
    fatal->Stop();
}

void StopAbandonsPendingSnapshotResultsAndRemainingPaths() {
    std::atomic<unsigned> calls{0};
    std::atomic<bool> blockedQueryEntered{false};
    std::atomic<bool> releaseQuery{false};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&](const std::string&, uint64_t) {
        const unsigned call = calls.fetch_add(1);
        if (call == 2) {
            blockedQueryEntered.store(true);
            while (!releaseQuery.load()) Sleep(1);
            return Complete(5, std::string(64, 'b').c_str());
        }
        return Complete(5, std::string(64, 'a').c_str());
    };
    std::unique_ptr<edr::ICollector> collector(edr::CreateFimCollector(
        15, 8, {"C:\\first.bin", "C:\\second.bin"}, query));
    Require(collector->Start(&bus), "stop snapshot fixture starts");
    Require(WaitUntil([&] { return blockedQueryEntered.load(); }),
            "second-round first query enters the controlled wait");
    std::atomic<bool> stopCallStarted{false};
    std::thread stopper([&] {
        stopCallStarted.store(true);
        collector->Stop();
    });
    Require(WaitUntil([&] { return stopCallStarted.load(); }), "stop call starts");
    Sleep(30);
    releaseQuery.store(true);
    stopper.join();
    Require(calls.load() == 3,
            "stop abandons the in-flight result and skips remaining watch paths");
    Require(recorder.Events().empty(), "stop does not emit an in-flight snapshot result");
    bus.Stop();
}

void RestartClearsCurrentFailureCounters() {
    std::atomic<bool> recover{false};
    edr::EventBus bus(8);
    std::unique_ptr<edr::ICollector> collector(edr::CreateFimCollector(
        20, 8, {"C:\\restart.bin", "C:\\restart-large.bin"},
        [&recover](const std::string& path, uint64_t) {
            if (recover.load()) return Complete(1, std::string(64, 'a').c_str());
            edr::FimSnapshot failed;
            if (path == "C:\\restart-large.bin") {
                failed.status = edr::FimSnapshotStatus::Failed;
                failed.statusCode = ERROR_FILE_TOO_LARGE;
                failed.size = 9;
                failed.oversized = true;
            } else {
                failed.status = edr::FimSnapshotStatus::Failed;
                failed.statusCode = ERROR_ACCESS_DENIED;
            }
            return failed;
        }));
    Require(collector->Start(&bus), "first health generation starts");
    Require(WaitUntil([&] {
        const auto health = collector->GetHealthSnapshot();
        return health.counters.at("watch_files_failed_current") == 1 &&
               health.counters.at("watch_files_oversized_uncovered_current") == 1;
    }), "failed and oversized paths are present in current health");
    collector->Stop();
    recover.store(true);
    Require(collector->Start(&bus), "recovered health generation restarts");
    const auto restarted = collector->GetHealthSnapshot();
    Require(restarted.counters.at("watch_files_failed_current") == 0 &&
            restarted.counters.at("watch_files_oversized_uncovered_current") == 0,
            "restart clears current failure and uncovered counters");
    collector->Stop();
}

void OverflowAndRestartHaveBoundedLifecycle() {
    TempDir temp;
    const auto path = temp.AddPath(L"overflow.bin");
    PutFixtureFile(path, "first", 5);
    edr::EventBus bus(1); // Deliberately leave the queue undrained.
    edr::Event blocker;
    Require(bus.Push(blocker), "overflow queue is seeded before collector start");
    std::unique_ptr<edr::ICollector> collector(edr::CreateFimCollector(
        25, 1024, {ToUtf8(path)}));
    Require(collector->Start(&bus), "overflow fixture starts");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    RewriteFixtureFile(path, "other", 5);
    Require(WaitUntil([&] { return bus.DroppedCount() != 0; }),
            "event bus overflow is observed while emitting a change");
    const auto health = collector->GetHealthSnapshot();
    Require(health.busDropped != 0, "overflow appears in this collector health");
    collector->Stop();
    Require(collector->Start(&bus), "collector restarts after Stop");
    std::this_thread::sleep_for(std::chrono::milliseconds(75));
    collector->Stop();
}

void FileChangesMatchIocsBeforeExecution(const char* rulesPath) {
    TempDir temp;
    const auto path = temp.AddPath(L"ioc-artifact.bin");
    const auto pathUtf8 = ToUtf8(path);
    edr::EventBus bus(32);
    Recorder recorder;
    bus.Start(&recorder);
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateFimCollector(40, 1024 * 1024, {pathUtf8}));
    Require(collector->Start(&bus), "native FIM starts for the IOC integration");
    Require(WaitUntil([&] {
        const auto health = collector->GetHealthSnapshot();
        const auto found = health.counters.find("successful_snapshots");
        return found != health.counters.end() && found->second != 0;
    }), "a complete missing baseline is established before creating the artifact");
    PutFixtureFile(path, "first", 5);
    Require(WaitForEvents(recorder, 1), "native file creation emits a hashed event");
    Require(DeleteFileW(path.c_str()) != FALSE, "the owned artifact is removed");
    Require(WaitForEvents(recorder, 2), "native removal emits a separate event");
    collector->Stop();
    bus.Stop();
    const auto events = recorder.Events();
    Require(events.size() == 2 && events[0].pid == 0, "artifact evidence has no invented process actor");
    const std::string digest = "a7937b64b8caa58f03721bb6bacf5c78cb235febe0e70b1b84cd99541461a08e";
    Require(Field(events[0], edr::field::kFimSha256) == digest, "native hash equals the known SHA-256 of benign fixture bytes");
    const std::string feed = "{\"indicators\":[{\"id\":\"TI-FILE\",\"type\":\"sha256\",\"value\":\"" +
        digest + "\",\"confidence\":\"high\",\"source\":\"synthetic-test\"}]}";
    const auto feedPath = temp.AddPath(L"feed.json");
    PutFixtureFile(feedPath, feed.data(), feed.size());
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    Require(detector.LoadIndicators(ToUtf8(feedPath), error), "the synthetic IOC feed loads");
    edr::RuleEngine engine;
    engine.LoadFromFile(rulesPath);
    size_t alerts = 0;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        if (alert.ruleId == "EDR-520") {
            Require(alert.action == "alert", "artifact IOC rule only alerts");
            ++alerts;
        }
    });
    auto added = events[0];
    detector.Enrich(added);
    Require(Field(added, edr::field::kThreatIntelScore) == "85", "native creation reaches the IOC matcher without execution");
    engine.OnEvent(added);
    Require(alerts == 1, "native creation reaches the production artifact IOC rule");
    auto removed = events[1];
    detector.Enrich(removed);
    engine.OnEvent(removed);
    Require(Field(removed, edr::field::kThreatIntelScore).empty() && alerts == 1,
            "a historical hash on a removed file never reports a present artifact");
}

} // namespace

int main(int argc, char** argv) {
    if (argc > 2) return 1;
    if (argc == 2) FileChangesMatchIocsBeforeExecution(argv[1]);
    MissingWatchPathCanAppearAndBeRemoved();
    SameSizeContentChangeAndRemovalAreReported();
    FailedQueriesRetainBaselineAndAreVisibleInHealth();
    PersistentFailureAndOversizedFileAreReportedInHealth();
    InvalidSnapshotsNeverCreateFalseTransitions();
    InvalidWatchConfigurationIsRejectedAndFatalWorkerStops();
    StopAbandonsPendingSnapshotResultsAndRemainingPaths();
    RestartClearsCurrentFailureCounters();
    OverflowAndRestartHaveBoundedLifecycle();
    std::puts("FIM collector regression tests passed");
    return 0;
}
