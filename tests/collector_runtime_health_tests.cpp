#include "collector_runtime_health_tests.h"

#include <windows.h>

#include <cstdio>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "collector.h"
#include "collector_runtime_health.h"
#include "event_bus.h"

namespace edr {
ICollector* CreateDriverCollector();
ICollector* CreateFileFallbackCollector(std::vector<std::string> dirs);
ICollector* CreateNetFallbackCollector(uint32_t pollMs);
ICollector* CreateProcPollCollector(bool fullImage);
}

namespace {

#define CRH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("collector runtime health test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

bool WaitForSnapshot(const edr::ICollector& collector,
                     const std::function<bool(const edr::CollectorHealthSnapshot&)>&
                         predicate,
                     edr::CollectorHealthSnapshot& snapshot,
                     DWORD timeoutMs = 5000) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    do {
        snapshot = collector.GetHealthSnapshot();
        if (predicate(snapshot)) return true;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    snapshot = collector.GetHealthSnapshot();
    return predicate(snapshot);
}

std::string ToUtf8(const std::wstring& value) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    CRH_CHECK(size > 0);
    std::string result(static_cast<size_t>(size), '\0');
    CRH_CHECK(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), &result[0], size, nullptr, nullptr) == size);
    return result;
}

void TestDriverHealthDoesNotRequireOpeningDevice() {
    std::unique_ptr<edr::ICollector> driver(edr::CreateDriverCollector());
    const auto sample = driver->GetHealthSnapshot();
    CRH_CHECK(sample.supported);
    CRH_CHECK(!sample.running);
    CRH_CHECK(sample.state == "stopped");
    CRH_CHECK(sample.countersAvailable);
    CRH_CHECK(sample.counters.at("worker_active") == 0);
    CRH_CHECK(sample.counters.find("kernel_queue_dropped") == sample.counters.end());
}

void TestDriverQueueCounterAppearsOnlyAfterStatsObservation() {
    edr::CollectorRuntimeHealth health;
    auto sample = health.Snapshot();
    CRH_CHECK(sample.counters.find("kernel_queue_dropped") == sample.counters.end());

    /* EDR_EVT_STATS carries ULONG in the legacy reserved wire field. */
    edr::ObserveDriverStatsHealth(health, EDR_EVT_PROCESS_START, 0xfffffff0u);
    sample = health.Snapshot();
    CRH_CHECK(sample.counters.find("kernel_queue_dropped") == sample.counters.end());
    edr::ObserveDriverStatsHealth(health, EDR_EVT_STATS, 0xfffffff0u);
    sample = health.Snapshot();
    CRH_CHECK(sample.counters.at("kernel_queue_dropped") == 0xfffffff0u);
    CRH_CHECK(sample.counters.at("kernel_queue_dropped_counter_bits") == 32);
    edr::ObserveDriverStatsHealth(health, EDR_EVT_STATS, 3u); // observable wrap
    sample = health.Snapshot();
    CRH_CHECK(sample.counters.at("kernel_queue_dropped") == 3u);
}

void TestRuntimeHealthSeparatesSubmissionFromOverflow() {
    edr::CollectorRuntimeHealth health;
    health.WorkerStarted();
    health.RecordEventSubmitted(false);
    health.RecordEventSubmitted(true); // eviction of an older queued event
    auto sample = health.Snapshot();
    CRH_CHECK(sample.running);
    CRH_CHECK(sample.state == "starting");
    CRH_CHECK(sample.counters.at("events_submitted") == 2);
    CRH_CHECK(sample.counters.at("bus_overflow_observed") == 1);
    health.RecordSnapshotSuccess();
    sample = health.Snapshot();
    CRH_CHECK(sample.state == "running");
    CRH_CHECK(sample.counters.at("source_available") == 1);
    health.RecordSourceError();
    sample = health.Snapshot();
    CRH_CHECK(sample.state == "source_error");
    CRH_CHECK(sample.counters.at("source_available") == 0);
    health.WorkerStopped();
}

void TestWatchHealthStaysStartingUntilSetupSettles() {
    edr::CollectorRuntimeHealth health;
    health.WorkerStarted();
    auto sample = health.Snapshot("no_active_watches", 0, true, false);
    CRH_CHECK(sample.running);
    CRH_CHECK(sample.state == "starting");

    health.RecordSourceError();
    sample = health.Snapshot("no_active_watches", 0, true, false);
    CRH_CHECK(sample.state == "starting");

    sample = health.Snapshot("no_active_watches", 0, true, true);
    CRH_CHECK(sample.state == "no_active_watches");
    health.WorkerStopped();
}

void TestInvalidFileWatchReportsNoAvailableWatches() {
    wchar_t temporary[MAX_PATH] = {};
    CRH_CHECK(GetTempPathW(MAX_PATH, temporary) > 0);
    const std::wstring invalidPath = std::wstring(temporary) +
        L"edr-runtime-health-missing-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64()) + L"\\watch";
    edr::EventBus bus;
    std::unique_ptr<edr::ICollector> fileWatch(
        edr::CreateFileFallbackCollector({ToUtf8(invalidPath)}));
    CRH_CHECK(fileWatch->Start(&bus));

    edr::CollectorHealthSnapshot sample;
    CRH_CHECK(WaitForSnapshot(*fileWatch,
        [](const edr::CollectorHealthSnapshot& value) {
            return value.supported && !value.running &&
                   value.state == "no_active_watches";
        }, sample));
    CRH_CHECK(!sample.running);
    CRH_CHECK(sample.counters.at("active_watches") == 0);
    CRH_CHECK(sample.counters.at("source_errors") >= 1);
    fileWatch->Stop();
}

void TestNetworkPollReportsSuccessfulSnapshotAndStoppedState() {
    edr::EventBus bus;
    std::unique_ptr<edr::ICollector> network(edr::CreateNetFallbackCollector(25));
    CRH_CHECK(network->Start(&bus));
    edr::CollectorHealthSnapshot sample;
    CRH_CHECK(WaitForSnapshot(*network,
        [](const edr::CollectorHealthSnapshot& value) {
            return value.supported && value.lastSuccess100ns != 0;
        }, sample));
    CRH_CHECK(sample.counters.at("successful_snapshots") >= 1);
    CRH_CHECK(sample.counters.at("events_submitted") == sample.eventsPushed);
    network->Stop();
    sample = network->GetHealthSnapshot();
    CRH_CHECK(!sample.running);
    CRH_CHECK(sample.state == "stopped");
    CRH_CHECK(sample.lastSuccess100ns != 0);
}

void TestProcessPollReportsSuccessfulSnapshotAndStoppedState() {
    edr::EventBus bus;
    std::unique_ptr<edr::ICollector> process(edr::CreateProcPollCollector(false));
    CRH_CHECK(process->Start(&bus));
    edr::CollectorHealthSnapshot sample;
    CRH_CHECK(WaitForSnapshot(*process,
        [](const edr::CollectorHealthSnapshot& value) {
            return value.supported && value.lastSuccess100ns != 0;
        }, sample));
    CRH_CHECK(sample.counters.at("successful_snapshots") >= 1);
    CRH_CHECK(sample.counters.at("events_submitted") == sample.eventsPushed);
    process->Stop();
    sample = process->GetHealthSnapshot();
    CRH_CHECK(!sample.running);
    CRH_CHECK(sample.state == "stopped");
    CRH_CHECK(sample.lastSuccess100ns != 0);
}

} // namespace

void RunCollectorRuntimeHealthTests() {
    std::fprintf(stderr, "[collector_health] stopped driver without device open\n");
    TestDriverHealthDoesNotRequireOpeningDevice();
    std::fprintf(stderr, "[collector_health] observed driver queue counter\n");
    TestDriverQueueCounterAppearsOnlyAfterStatsObservation();
    std::fprintf(stderr, "[collector_health] source state and bus overflow\n");
    TestRuntimeHealthSeparatesSubmissionFromOverflow();
    std::fprintf(stderr, "[collector_health] watch startup state\n");
    TestWatchHealthStaysStartingUntilSetupSettles();
    std::fprintf(stderr, "[collector_health] invalid file-watch source\n");
    TestInvalidFileWatchReportsNoAvailableWatches();
    std::fprintf(stderr, "[collector_health] network poll sample\n");
    TestNetworkPollReportsSuccessfulSnapshotAndStoppedState();
    std::fprintf(stderr, "[collector_health] process poll sample\n");
    TestProcessPollReportsSuccessfulSnapshotAndStoppedState();
}
