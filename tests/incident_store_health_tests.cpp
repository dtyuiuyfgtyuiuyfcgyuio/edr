/*
 * incident_store_health_tests.cpp - bounded persistence and write-health
 * tests for the incident JSONL ledger.
 */
#include "incident_store_health_tests.h"

#include <windows.h>

#include <atomic>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <stdexcept>
#include <string>
#include <thread>

#include "incident_store.h"

namespace {

#define ISH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("incident store health test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

std::string TempPath(const char* prefix) {
    char directory[MAX_PATH] = {};
    ISH_CHECK(GetTempPathA(MAX_PATH, directory) != 0);
    return std::string(directory) + prefix +
        std::to_string(GetCurrentProcessId()) + ".jsonl";
}

void RemoveIfPresent(const std::string& path) {
    DeleteFileA(path.c_str());
}

std::string ReadAll(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    ISH_CHECK(input.is_open());
    std::string bytes((std::istreambuf_iterator<char>(input)),
                      std::istreambuf_iterator<char>());
    ISH_CHECK(!input.bad());
    return bytes;
}

edr::Incident MakeIncident(const std::string& id) {
    edr::Incident incident;
    incident.id = id;
    incident.host = "health-test-host";
    incident.severity = "high";
    incident.alertCount = 1;
    return incident;
}

bool WriteAndFlush(HANDLE file, const std::string& line) {
    if (line.empty() || line.back() != '\n') return false;
    DWORD written = 0;
    return WriteFile(file, line.data(), static_cast<DWORD>(line.size()),
                     &written, nullptr) != FALSE &&
        written == line.size() && FlushFileBuffers(file) != FALSE;
}

void TestIncidentStoreReportsPerInstanceCapacityExhaustion() {
    const std::string path = TempPath("edr-incident-health-cap-");
    RemoveIfPresent(path);
    {
        edr::IncidentStore store(path, false, 2);
        ISH_CHECK(store.Open());
        auto status = store.GetWriteStatus();
        ISH_CHECK(status.enabled && status.open && status.writable);
        ISH_CHECK(!status.truncated && status.writeFailures == 0 &&
                  status.dropped == 0 && status.chainSequence == 0 &&
                  status.lastError.empty());

        store.OnIncidentOpened(MakeIncident("health-cap-1"));
        store.OnIncidentClosed(MakeIncident("health-cap-2"));
        status = store.GetWriteStatus();
        ISH_CHECK(store.RecordCount() == 2);
        ISH_CHECK(status.open && !status.writable && !status.truncated);
        ISH_CHECK(status.chainSequence == 2 && status.dropped == 0);

        store.OnIncidentOpened(MakeIncident("health-cap-dropped-1"));
        status = store.GetWriteStatus();
        ISH_CHECK(store.RecordCount() == 2);
        ISH_CHECK(status.open && !status.writable && status.truncated);
        ISH_CHECK(status.writeFailures == 0 && status.dropped == 1);
        ISH_CHECK(status.chainSequence == 2 && !status.lastError.empty());

        store.OnIncidentClosed(MakeIncident("health-cap-dropped-2"));
        status = store.GetWriteStatus();
        ISH_CHECK(status.truncated && status.dropped == 2);
        ISH_CHECK(status.chainSequence == 2 && store.RecordCount() == 2);
        store.Close();
    }

    /* The cap is per object instance. A new instance replays the full chain,
     * starts a fresh per-instance write allowance, and continues sequence 3. */
    {
        edr::IncidentStore reopened(path, false, 1);
        ISH_CHECK(reopened.Open());
        auto status = reopened.GetWriteStatus();
        ISH_CHECK(status.open && status.writable && !status.truncated);
        ISH_CHECK(status.chainSequence == 2 && reopened.RecordCount() == 0);
        reopened.OnIncidentOpened(MakeIncident("health-cap-after-reopen"));
        status = reopened.GetWriteStatus();
        ISH_CHECK(reopened.RecordCount() == 1 && status.chainSequence == 3);
        ISH_CHECK(!status.writable && !status.truncated);
        reopened.OnIncidentClosed(MakeIncident("health-cap-after-reopen-dropped"));
        status = reopened.GetWriteStatus();
        ISH_CHECK(reopened.RecordCount() == 1 && status.chainSequence == 3);
        ISH_CHECK(status.truncated && status.dropped == 1);
        reopened.Close();
    }
    {
        edr::IncidentStore verifier(path, false, 10);
        ISH_CHECK(verifier.Open());
        ISH_CHECK(verifier.GetWriteStatus().chainSequence == 3);
        verifier.Close();
    }
    RemoveIfPresent(path);
}

void TestIncidentStoreAppendFailureAndThrowLatchWithoutAdvancing() {
    for (bool shouldThrow : {false, true}) {
        const std::string prefix = shouldThrow
            ? "edr-incident-health-throw-"
            : "edr-incident-health-fail-";
        const std::string path = TempPath(prefix.c_str());
        RemoveIfPresent(path);
        size_t appendCalls = 0;
        edr::IncidentStore store(
            path, false, 10, {},
            [&](HANDLE file, const std::string& line) {
                ++appendCalls;
                ISH_CHECK(file != INVALID_HANDLE_VALUE);
                ISH_CHECK(!line.empty() && line.back() == '\n');
                if (shouldThrow)
                    throw std::runtime_error("injected append exception");
                return false;
            });
        ISH_CHECK(store.Open());

        store.OnIncidentOpened(MakeIncident("health-write-failure"));
        auto status = store.GetWriteStatus();
        ISH_CHECK(appendCalls == 1 && store.RecordCount() == 0);
        ISH_CHECK(status.enabled && status.open && !status.writable);
        ISH_CHECK(!status.truncated && status.writeFailures == 1);
        ISH_CHECK(status.dropped == 1 && status.chainSequence == 0);
        ISH_CHECK(!status.lastError.empty());

        store.OnIncidentClosed(MakeIncident("health-write-after-latch"));
        status = store.GetWriteStatus();
        ISH_CHECK(appendCalls == 1 && store.RecordCount() == 0);
        ISH_CHECK(status.writeFailures == 1 && status.dropped == 2);
        ISH_CHECK(status.chainSequence == 0 && !status.writable);
        store.Close();
        store.Close();
        ISH_CHECK(ReadAll(path).empty());
        RemoveIfPresent(path);
    }
}

void TestIncidentStoreWriteStatusIsConsistentDuringConcurrentWrites() {
    const std::string path = TempPath("edr-incident-health-concurrent-");
    RemoveIfPresent(path);
    edr::IncidentStore store(path, false, 300, {}, WriteAndFlush);
    ISH_CHECK(store.Open());

    std::atomic<bool> writerDone{false};
    std::atomic<bool> consistent{true};
    std::thread reader([&]() {
        do {
            const auto status = store.GetWriteStatus();
            if (!status.enabled || !status.open ||
                status.writable !=
                    (!status.truncated && status.writeFailures == 0)) {
                consistent.store(false);
            }
            std::this_thread::yield();
        } while (!writerDone.load());
    });

    for (size_t index = 0; index < 160; ++index) {
        store.OnIncidentOpened(MakeIncident(
            "health-concurrent-" + std::to_string(index)));
    }
    writerDone.store(true);
    reader.join();

    const auto finalStatus = store.GetWriteStatus();
    ISH_CHECK(consistent.load());
    ISH_CHECK(finalStatus.open && finalStatus.writable);
    ISH_CHECK(finalStatus.writeFailures == 0 && finalStatus.dropped == 0);
    ISH_CHECK(finalStatus.chainSequence == 160 && store.RecordCount() == 160);
    store.Close();
    RemoveIfPresent(path);
}

} // namespace

void RunIncidentStoreHealthTests() {
    TestIncidentStoreReportsPerInstanceCapacityExhaustion();
    TestIncidentStoreAppendFailureAndThrowLatchWithoutAdvancing();
    TestIncidentStoreWriteStatusIsConsistentDuringConcurrentWrites();
}
