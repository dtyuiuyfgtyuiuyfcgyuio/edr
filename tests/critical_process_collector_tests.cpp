#include <windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "collector.h"
#include "collector_critical_process.h"

namespace {
edr::CriticalProcessToolhelpApi FailCreateApi() {
    auto api = edr::CriticalProcessToolhelpApi::Native();
    api.createSnapshot = [] { return INVALID_HANDLE_VALUE; };
    return api;
}

edr::CriticalProcessToolhelpApi ScriptedToolhelpApi(
    const std::vector<std::tuple<bool, DWORD, std::wstring>>& entries,
    DWORD terminalError, std::function<void()> onClose = {}) {
    struct State {
        size_t index = 0;
        DWORD error = ERROR_SUCCESS;
        std::vector<std::tuple<bool, DWORD, std::wstring>> entries;
        DWORD terminalError = ERROR_SUCCESS;
    };
    auto state = std::make_shared<State>();
    state->entries = entries;
    state->terminalError = terminalError;
    edr::CriticalProcessToolhelpApi api;
    api.createSnapshot = [] { return reinterpret_cast<HANDLE>(1); };
    api.first = [state](HANDLE, LPPROCESSENTRY32W output) {
        state->index = 0;
        if (state->entries.empty()) {
            state->error = state->terminalError;
            return FALSE;
        }
        const auto& entry = state->entries.front();
        if (!std::get<0>(entry)) {
            state->error = std::get<1>(entry);
            return FALSE;
        }
        wcsncpy_s(output->szExeFile, std::get<2>(entry).c_str(), _TRUNCATE);
        state->error = ERROR_SUCCESS;
        return TRUE;
    };
    api.next = [state](HANDLE, LPPROCESSENTRY32W output) {
        ++state->index;
        if (state->index >= state->entries.size()) {
            state->error = state->terminalError;
            return FALSE;
        }
        const auto& entry = state->entries[state->index];
        if (!std::get<0>(entry)) {
            state->error = std::get<1>(entry);
            return FALSE;
        }
        wcsncpy_s(output->szExeFile, std::get<2>(entry).c_str(), _TRUNCATE);
        state->error = ERROR_SUCCESS;
        return TRUE;
    };
    api.lastError = [state] { return state->error; };
    api.close = [onClose = std::move(onClose)](HANDLE) {
        if (onClose) onClose();
    };
    return api;
}

void Require(bool ok, const char* reason) {
    if (!ok) throw std::runtime_error(reason);
}

bool WaitUntil(const std::function<bool()>& ready) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    do {
        if (ready()) return true;
        Sleep(5);
    } while (std::chrono::steady_clock::now() < until);
    return ready();
}

class Recorder : public edr::ISink {
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

class Script {
public:
    void Set(edr::CriticalProcessSnapshot next) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_next = std::move(next);
        m_sequence.clear();
        m_sequenceIndex = 0;
        m_calls = 0;
    }
    void SetSequence(std::vector<edr::CriticalProcessSnapshot> sequence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_sequence = std::move(sequence);
        m_sequenceIndex = 0;
        m_calls = 0;
    }
    edr::CriticalProcessQuery Query() {
        return [this] {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_calls;
            if (m_sequenceIndex < m_sequence.size())
                return m_sequence[m_sequenceIndex++];
            return m_next;
        };
    }
    bool CalledAtLeast(unsigned count) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_calls >= count;
    }
    unsigned Calls() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_calls;
    }
private:
    mutable std::mutex m_mutex;
    edr::CriticalProcessSnapshot m_next;
    std::vector<edr::CriticalProcessSnapshot> m_sequence;
    size_t m_sequenceIndex = 0;
    unsigned m_calls = 0;
};

class Fixture {
public:
    explicit Fixture(Script& script, uint32_t pollMs = 20,
                     size_t capacity = 64) : bus(capacity) {
        bus.Start(&recorder);
        collector.reset(edr::CreateCriticalProcessCollector(
            pollMs, 2, {"MsMpEng.exe"}, script.Query()));
        Require(collector->Start(&bus), "critical process worker starts");
    }
    ~Fixture() { collector->Stop(); bus.Stop(); }
    edr::EventBus bus;
    Recorder recorder;
    std::unique_ptr<edr::ICollector> collector;
};

edr::CriticalProcessSnapshot Complete(std::set<std::string> images = {}) {
    return {edr::CriticalProcessSnapshotStatus::Complete, std::move(images)};
}

class ReleaseBlockedQueryAndJoin {
public:
    ReleaseBlockedQueryAndJoin(std::mutex& mutex,
                               std::condition_variable& wake,
                               bool& release,
                               std::thread& stopper)
        : m_mutex(mutex), m_wake(wake), m_release(release), m_stopper(stopper) {}
    ~ReleaseBlockedQueryAndJoin() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_release = true;
        }
        m_wake.notify_all();
        if (m_stopper.joinable()) m_stopper.join();
    }

private:
    std::mutex& m_mutex;
    std::condition_variable& m_wake;
    bool& m_release;
    std::thread& m_stopper;
};

void StopDuringBlockedQueryDiscardsReturnedSnapshot() {
    edr::EventBus bus(8);
    Recorder recorder;
    bus.Start(&recorder);

    std::mutex queryMutex;
    std::condition_variable queryWake;
    std::atomic<bool> blockedQueryEntered{false};
    bool releaseBlockedQuery = false;
    unsigned calls = 0;
    std::unique_ptr<edr::ICollector> collector(edr::CreateCriticalProcessCollector(
        1, 1, {"MsMpEng.exe"}, [&]() {
            if (++calls == 1) return Complete({"msmpeng.exe"});
            std::unique_lock<std::mutex> lock(queryMutex);
            blockedQueryEntered.store(true);
            queryWake.notify_all();
            queryWake.wait(lock, [&] { return releaseBlockedQuery; });
            return Complete();
        }));
    Require(collector->Start(&bus), "blocked-query collector starts");

    std::atomic<bool> stopStarted{false};
    std::atomic<bool> stopReturned{false};
    std::thread stopper;
    ReleaseBlockedQueryAndJoin releaseGuard(
        queryMutex, queryWake, releaseBlockedQuery, stopper);
    Require(WaitUntil([&] {
        const auto health = collector->GetHealthSnapshot();
        return blockedQueryEntered &&
            health.counters.at("successful_snapshots") == 1;
    }), "complete present seed is recorded before the next query blocks");
    const auto seededHealth = collector->GetHealthSnapshot();
    Require(seededHealth.lastSuccess100ns != 0 && recorder.Events().empty(),
            "present seed establishes successful baseline without events");

    stopper = std::thread([&] {
        stopStarted.store(true);
        collector->Stop();
        stopReturned.store(true);
    });
    Require(WaitUntil([&] { return stopStarted.load(); }),
            "stop thread begins while source query remains blocked");
    Sleep(40);
    Require(!stopReturned.load(), "stop waits for the blocked source query");

    {
        std::lock_guard<std::mutex> lock(queryMutex);
        releaseBlockedQuery = true;
    }
    queryWake.notify_all();
    stopper.join();

    const auto stoppedHealth = collector->GetHealthSnapshot();
    Require(recorder.Events().empty(),
            "snapshot returned after stop emits no false termination");
    Require(stoppedHealth.counters.at("successful_snapshots") == 1 &&
                stoppedHealth.lastSuccess100ns == seededHealth.lastSuccess100ns,
            "snapshot returned after stop does not advance success health");
    bus.Stop();
}

void RepeatedFailuresAndPartialEnumerationNeverReportMissing() {
    Script script;
    script.Set({});
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.CalledAtLeast(3); }),
            "failed snapshots keep retrying");
    auto health = fixture.collector->GetHealthSnapshot();
    Require(fixture.recorder.Events().empty(), "failed startup emits no termination");
    Require(health.sourceErrors >= 3 && health.state == "source_error" &&
                health.lastSuccess100ns == 0,
            "initial failures are visible without claiming successful sampling");

    script.Set(Complete());
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "complete empty snapshots count as real missing observations");
    const auto event = fixture.recorder.Events()[0];
    Require(event.fields.at(edr::field::kCriticalProcessAction) == "terminated",
            "threshold is reached from complete missing snapshots");
}

void FailedSnapshotsPreserveMissingCountAndRecoveryState() {
    Script script;
    script.Set(Complete());
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "two complete missing snapshots report termination");

    script.Set({edr::CriticalProcessSnapshotStatus::Failed, {"msmpeng.exe"}});
    Require(WaitUntil([&] {
        return fixture.collector->GetHealthSnapshot().sourceErrors > 0;
    }), "failed snapshot is observable");
    Sleep(60);
    Require(fixture.recorder.Events().size() == 1,
            "failure after termination preserves the report without recovery");

    script.Set(Complete({"msmpeng.exe"}));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 2; }),
            "complete presence after reported missing emits recovery");
    Require(fixture.recorder.Events()[1].fields.at(edr::field::kCriticalProcessAction) ==
                "recovered",
            "recovery action remains part of the event contract");
}

void FailedSnapshotDoesNotResetAnUnreportedMissingCount() {
    Script script;
    script.SetSequence({Complete({"msmpeng.exe"}), Complete(),
        {edr::CriticalProcessSnapshotStatus::Failed, {}}, Complete()});
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "second complete missing observation reaches threshold across failure");
    Require(script.CalledAtLeast(4) &&
                fixture.collector->GetHealthSnapshot().sourceErrors == 1,
            "one failed partial poll is kept between the two complete absences");
}

void NativeFirstAndNextErrorsFailClosedWhileNoMoreFilesIsEmpty() {
    auto api = FailCreateApi();
    auto result = edr::ReadCriticalProcessSnapshot(api);
    Require(result.status == edr::CriticalProcessSnapshotStatus::Failed,
            "snapshot creation failure is not a complete empty result");

    api = ScriptedToolhelpApi(
        {{false, ERROR_ACCESS_DENIED, L""}}, ERROR_NO_MORE_FILES);
    result = edr::ReadCriticalProcessSnapshot(api);
    Require(result.status == edr::CriticalProcessSnapshotStatus::Failed,
            "Process32First failure other than no-more-files fails the snapshot");

    api = ScriptedToolhelpApi(
        {{true, ERROR_SUCCESS, L"MsMpEng.exe"}, {false, ERROR_ACCESS_DENIED, L""}},
        ERROR_ACCESS_DENIED);
    result = edr::ReadCriticalProcessSnapshot(api);
    Require(result.status == edr::CriticalProcessSnapshotStatus::Failed &&
                result.images.empty(),
            "mid-enumeration failure discards partial process names");

    api = ScriptedToolhelpApi({}, ERROR_NO_MORE_FILES);
    result = edr::ReadCriticalProcessSnapshot(api);
    Require(result.status == edr::CriticalProcessSnapshotStatus::Complete &&
                result.images.empty(),
            "Process32First no-more-files is a valid complete empty snapshot");
}

void NativeEnumerationAlwaysClosesSnapshotAndRejectsUnboundedInputs() {
    size_t closes = 0;
    auto api = ScriptedToolhelpApi(
        {{true, ERROR_SUCCESS, L"MsMpEng.exe"}, {false, ERROR_NO_MORE_FILES, L""}},
        ERROR_NO_MORE_FILES, [&] { ++closes; });
    auto result = edr::ReadCriticalProcessSnapshot(api, 1);
    Require(result.status == edr::CriticalProcessSnapshotStatus::Complete && closes == 1,
            "valid native enumeration closes its snapshot handle");

    closes = 0;
    api = ScriptedToolhelpApi(
        {{true, ERROR_SUCCESS, L"MsMpEng.exe"}, {false, ERROR_ACCESS_DENIED, L""}},
        ERROR_ACCESS_DENIED, [&] { ++closes; });
    result = edr::ReadCriticalProcessSnapshot(api);
    Require(result.status == edr::CriticalProcessSnapshotStatus::Failed && closes == 1,
            "failed native enumeration also closes its snapshot handle");

    closes = 0;
    api = ScriptedToolhelpApi(
        {{true, ERROR_SUCCESS, L"one.exe"}, {true, ERROR_SUCCESS, L"two.exe"}},
        ERROR_NO_MORE_FILES, [&] { ++closes; });
    result = edr::ReadCriticalProcessSnapshot(api, 1);
    Require(result.status == edr::CriticalProcessSnapshotStatus::Failed &&
                result.images.empty() && closes == 1,
            "process enumeration cap rejects an over-limit partial snapshot");

    Require(!edr::CriticalProcessConfigIsValid({std::string(1025, 'x')}),
            "oversized configured image names are rejected");
    Require(!edr::CriticalProcessConfigIsValid({std::string("a\0b", 3)}),
            "embedded NUL configured image names are rejected");
    std::vector<std::string> tooManyNames(257, "agent.exe");
    Require(!edr::CriticalProcessConfigIsValid(tooManyNames),
            "configured image count is bounded");
}

void ActualCollectorRejectsDirectoryQualifiedImageNames() {
    const std::vector<std::string> pathConfiguredImage = {
        "C:\\Windows\\MsMpEng.exe"};
    edr::EventBus bus(8);
    Recorder recorder;
    bus.Start(&recorder);
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateCriticalProcessCollector(1, 1, pathConfiguredImage,
            [] { return Complete(); }));
    Require(!collector->Start(&bus),
            "collector refuses a configured path it can never match to a process basename");
    Require(!edr::CriticalProcessConfigIsValid(pathConfiguredImage),
            "configured protected images must be basename-only");
    Sleep(40);
    Require(recorder.Events().empty(),
            "invalid directory-qualified configuration emits no termination");
    collector->Stop();
    bus.Stop();
}

void RealProcessSnapshotIsReadOnlyAndComplete() {
    const auto snapshot = edr::ReadCriticalProcessSnapshot(
        edr::CriticalProcessToolhelpApi::Native());
    Require(snapshot.status == edr::CriticalProcessSnapshotStatus::Complete,
            "read-only native process enumeration returns a complete bounded snapshot");
}

void HealthTracksSuccessOverflowStopFatalAndDeadWorkerRestart() {
    Script script;
    script.Set(Complete({"msmpeng.exe"}));
    Fixture fixture(script, 20, 0);
    Require(WaitUntil([&] {
        const auto health = fixture.collector->GetHealthSnapshot();
        return health.running && health.lastSuccess100ns != 0;
    }), "health records active worker and successful source timestamp");
    script.Set(Complete());
    Require(WaitUntil([&] {
        return fixture.collector->GetHealthSnapshot().eventsPushed != 0;
    }), "termination is submitted even when bus capacity is zero");
    auto health = fixture.collector->GetHealthSnapshot();
    Require(health.busDropped == 1 && health.sourceErrors == 0,
            "bus overflow is tracked independently from source failures");
    const auto stopStart = std::chrono::steady_clock::now();
    fixture.collector->Stop();
    Require(std::chrono::steady_clock::now() - stopStart < std::chrono::milliseconds(500),
            "stop wakes a worker waiting on a long poll interval");
    health = fixture.collector->GetHealthSnapshot();
    Require(!health.running && health.state == "stopped",
            "stop updates worker health");

    Script slowScript;
    slowScript.Set(Complete({"msmpeng.exe"}));
    Fixture slowFixture(slowScript, 5000);
    Require(WaitUntil([&] {
        return slowFixture.collector->GetHealthSnapshot().lastSuccess100ns != 0;
    }), "long-interval worker completes its initial source read");
    const auto slowStopStart = std::chrono::steady_clock::now();
    slowFixture.collector->Stop();
    Require(std::chrono::steady_clock::now() - slowStopStart <
                std::chrono::milliseconds(500),
            "stop wakes a worker waiting on a long poll interval");

    edr::EventBus bus(8);
    std::mutex fatalMutex;
    std::condition_variable fatalWake;
    int fatalCalls = 0;
    bool restartQueryEntered = false;
    bool releaseRestartQuery = false;
    std::unique_ptr<edr::ICollector> fatal(edr::CreateCriticalProcessCollector(
        5000, 2, {"MsMpEng.exe"}, [&]() -> edr::CriticalProcessSnapshot {
            std::unique_lock<std::mutex> lock(fatalMutex);
            ++fatalCalls;
            if (fatalCalls == 1) throw std::runtime_error("injected query failure");
            restartQueryEntered = true;
            fatalWake.notify_all();
            fatalWake.wait(lock, [&] { return releaseRestartQuery; });
            return Complete({"msmpeng.exe"});
        }));
    Require(fatal->Start(&bus), "fatal-query worker starts");
    Require(WaitUntil([&] {
        const auto sample = fatal->GetHealthSnapshot();
        return sample.supported && !sample.running &&
            sample.state == "source_error" && sample.sourceErrors != 0;
    }), "fatal query is contained and visible in health");
    Require(!fatal->Start(&bus), "dead joinable worker cannot claim restart succeeded");
    fatal->Stop();
    Require(fatal->GetHealthSnapshot().state == "stopped",
            "explicit stop clears fatal as the visible worker state");
    Require(fatal->Start(&bus), "joining the failed worker permits explicit restart");
    {
        std::unique_lock<std::mutex> lock(fatalMutex);
        Require(fatalWake.wait_for(lock, std::chrono::seconds(3),
                    [&] { return restartQueryEntered; }),
                "restarted source query reaches its controlled wait");
    }
    auto restartingHealth = fatal->GetHealthSnapshot();
    Require(restartingHealth.running && restartingHealth.state == "starting" &&
                restartingHealth.sourceErrors != 0,
            "restart resets current source state while retaining cumulative error count");
    {
        std::lock_guard<std::mutex> lock(fatalMutex);
        releaseRestartQuery = true;
    }
    fatalWake.notify_all();
    Require(WaitUntil([&] {
        return fatal->GetHealthSnapshot().state == "running";
    }), "successful query restores running source health after restart");
    fatal->Stop();
    Require(fatal->GetHealthSnapshot().state == "stopped",
            "stop after successful restart reports stopped");
    bus.Stop();
}

void ZeroPollIntervalIsClampedAwayFromBusyLooping() {
    Script script;
    script.Set(Complete({"msmpeng.exe"}));
    Fixture fixture(script, 0);
    Sleep(250);
    Require(script.Calls() < 1000,
            "zero poll interval is clamped to a non-busy bounded wait");
}

} // namespace

int main() {
    try {
        RepeatedFailuresAndPartialEnumerationNeverReportMissing();
        FailedSnapshotsPreserveMissingCountAndRecoveryState();
        FailedSnapshotDoesNotResetAnUnreportedMissingCount();
        NativeFirstAndNextErrorsFailClosedWhileNoMoreFilesIsEmpty();
        NativeEnumerationAlwaysClosesSnapshotAndRejectsUnboundedInputs();
        ActualCollectorRejectsDirectoryQualifiedImageNames();
        RealProcessSnapshotIsReadOnlyAndComplete();
        StopDuringBlockedQueryDiscardsReturnedSnapshot();
        HealthTracksSuccessOverflowStopFatalAndDeadWorkerRestart();
        ZeroPollIntervalIsClampedAwayFromBusyLooping();
        std::puts("critical process collector tests passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "critical process collector tests failed: %s\n", error.what());
        return 1;
    }
}
