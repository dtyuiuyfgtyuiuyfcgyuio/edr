#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"
#include "collector_service.h"

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}

edr::ServiceCollectorEntry Service(const char* name, const char* startType,
                                   const char* imagePath,
                                   bool configAvailable = true) {
    edr::ServiceCollectorEntry entry;
    entry.name = name;
    entry.displayName = name;
    entry.state = "running";
    entry.startType = startType;
    entry.imagePath = imagePath;
    entry.configAvailable = configAvailable;
    return entry;
}

edr::ServiceCollectorSnapshot Complete(
    std::initializer_list<edr::ServiceCollectorEntry> services) {
    edr::ServiceCollectorSnapshot snapshot;
    snapshot.complete = true;
    snapshot.services.assign(services.begin(), services.end());
    return snapshot;
}

edr::ServiceCollectorSnapshot Failed() {
    edr::ServiceCollectorSnapshot snapshot;
    snapshot.complete = false;
    return snapshot;
}

class ScriptedQuery {
public:
    void Push(edr::ServiceCollectorSnapshot snapshot) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_results.push_back(std::move(snapshot));
    }

    edr::ServiceCollectorQuery Callback() {
        return [this] { return Next(); };
    }

    bool WaitForCalls(size_t expected) {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_cv.wait_for(lock, std::chrono::seconds(4), [&] {
            return m_calls >= expected;
        });
    }

private:
    edr::ServiceCollectorSnapshot Next() {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_calls;
        edr::ServiceCollectorSnapshot result;
        if (!m_results.empty()) {
            result = std::move(m_results.front());
            m_results.pop_front();
            m_last = result;
        } else {
            result = m_last;
        }
        m_cv.notify_all();
        return result;
    }

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<edr::ServiceCollectorSnapshot> m_results;
    edr::ServiceCollectorSnapshot m_last;
    size_t m_calls = 0;
};

class EventRecorder : public edr::ISink {
public:
    void OnEvent(const edr::Event& event) override {
        auto action = event.fields.find(edr::field::kServiceAction);
        auto name = event.fields.find(edr::field::kServiceName);
        std::lock_guard<std::mutex> lock(m_mutex);
        m_events.emplace_back(
            action == event.fields.end() ? "" : action->second,
            name == event.fields.end() ? "" : name->second);
        m_cv.notify_all();
    }

    size_t Count(const char* action) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t count = 0;
        for (const auto& event : m_events)
            if (event.first == action) ++count;
        return count;
    }

    bool WaitForCount(size_t expected) {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_cv.wait_for(lock, std::chrono::seconds(3), [&] {
            return m_events.size() >= expected;
        });
    }

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<std::pair<std::string, std::string>> m_events;
};

class CollectorFixture {
public:
    explicit CollectorFixture(ScriptedQuery& query, size_t busCapacity = 64,
                              bool startConsumer = true)
        : m_bus(busCapacity) {
        if (startConsumer) m_bus.Start(&m_recorder);
        m_collector.reset(edr::CreateServiceCollector(100, query.Callback()));
        Require(m_collector->Start(&m_bus), "service collector starts");
    }

    ~CollectorFixture() {
        Stop();
        m_bus.Stop();
    }

    bool WaitForEvents(size_t count) { return m_recorder.WaitForCount(count); }
    size_t EventCount(const char* action) const { return m_recorder.Count(action); }
    edr::CollectorHealthSnapshot Health() const {
        return m_collector->GetHealthSnapshot();
    }

    void Stop() {
        if (m_collector) m_collector->Stop();
    }

private:
    edr::EventBus m_bus;
    EventRecorder m_recorder;
    std::unique_ptr<edr::ICollector> m_collector;
};

template <typename Predicate>
bool WaitUntil(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return predicate();
}

void ServiceHealthIsSupportedBeforeStart() {
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateServiceCollector(1000));
    Require(collector != nullptr, "service collector factory returns an instance");
    const auto snapshot = collector->GetHealthSnapshot();
    Require(snapshot.supported,
            "service health is supported before the worker starts");
    Require(snapshot.state == "stopped",
            "unstarted service collector reports stopped");
}

void ValidEmptySnapshotReportsRemovedService() {
    ScriptedQuery query;
    query.Push(Complete({Service("DemoSvc", "auto", "C:\\demo.exe")}));
    CollectorFixture fixture(query);
    Require(query.WaitForCalls(1), "initial service baseline is sampled");
    query.Push(Complete({}));
    Require(fixture.WaitForEvents(1), "valid empty sample emits a removal");
    Require(fixture.EventCount("removed") == 1,
            "valid empty sample emits exactly one removed event");
}

void FailedEmptySnapshotPreservesBaselineAndRecoversQuietly() {
    ScriptedQuery query;
    query.Push(Complete({Service("DemoSvc", "auto", "C:\\demo.exe")}));
    CollectorFixture fixture(query);
    Require(query.WaitForCalls(1), "initial service baseline is sampled");
    query.Push(Failed());
    Require(query.WaitForCalls(2), "failed sample is observed");
    Require(WaitUntil([&] { return fixture.Health().state == "source_error"; }),
            "failed sample is visible in health");
    query.Push(Complete({Service("DemoSvc", "auto", "C:\\demo.exe")}));
    Require(query.WaitForCalls(3), "complete source sample recovers");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    Require(fixture.EventCount("removed") == 0 &&
                fixture.EventCount("added") == 0,
            "failure and recovery do not flood false remove/add events");
    Require(WaitUntil([&] { return fixture.Health().state == "running"; }),
            "successful sample clears source-error state");
}

void InitialBaselineDoesNotEmitModifiedEvents() {
    ScriptedQuery query;
    query.Push(Complete({Service("DemoSvc", "auto", "C:\\demo.exe")}));
    CollectorFixture fixture(query);
    Require(query.WaitForCalls(1), "initial service baseline is sampled");
    query.Push(Complete({Service("DemoSvc", "auto", "C:\\demo.exe")}));
    Require(query.WaitForCalls(2), "first poll after baseline completes");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    Require(fixture.EventCount("modified") == 0,
            "baseline config is complete before the first diff");
}

void StartTypeChangesEmitModifiedEvents() {
    ScriptedQuery query;
    query.Push(Complete({Service("DemoSvc", "auto", "C:\\demo.exe")}));
    CollectorFixture fixture(query);
    Require(query.WaitForCalls(1), "initial service baseline is sampled");
    query.Push(Complete({Service("DemoSvc", "manual", "C:\\demo.exe")}));
    Require(fixture.WaitForEvents(1), "start-type change emits an event");
    Require(fixture.EventCount("modified") == 1,
            "start-type change is classified as modified");
}

void ConfigQueryFailureAndRecoveryDoNotInventChanges() {
    ScriptedQuery query;
    query.Push(Complete({Service("DemoSvc", "auto", "C:\\demo.exe")}));
    CollectorFixture fixture(query);
    Require(query.WaitForCalls(1), "initial service baseline is sampled");
    query.Push(Complete({Service("DemoSvc", "", "", false)}));
    Require(query.WaitForCalls(2), "config query failure is sampled");
    Require(WaitUntil([&] {
                return fixture.Health().state == "config_degraded";
            }),
            "config query failure degrades health");
    query.Push(Complete({Service("DemoSvc", "auto", "C:\\demo.exe")}));
    Require(query.WaitForCalls(3), "config query recovers");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    Require(fixture.EventCount("modified") == 0,
            "missing config fields do not cause a false modification");
    Require(WaitUntil([&] { return fixture.Health().state == "running"; }),
            "config recovery clears degraded health");
}

void EnumerationFailureTakesPrecedenceOverPriorConfigDegradation() {
    ScriptedQuery query;
    query.Push(Complete({Service("DemoSvc", "", "", false)}));
    CollectorFixture fixture(query);
    Require(query.WaitForCalls(1), "config-degraded baseline is sampled");
    Require(WaitUntil([&] {
                return fixture.Health().state == "config_degraded";
            }),
            "unavailable service config degrades health");

    query.Push(Failed());
    Require(query.WaitForCalls(2), "incomplete enumeration is sampled");
    Require(WaitUntil([&] { return fixture.Health().sourceErrors > 0; }),
            "incomplete enumeration increments source errors");
    Require(fixture.Health().state == "source_error",
            "enumeration failure takes precedence over prior config degradation");
}

void FailedFirstConfigThenKnownValueOnlyEstablishesBaseline() {
    ScriptedQuery query;
    query.Push(Complete({Service("DemoSvc", "", "", false)}));
    CollectorFixture fixture(query);
    Require(query.WaitForCalls(1), "incomplete config baseline is sampled");
    query.Push(Complete({Service("DemoSvc", "auto", "C:\\demo.exe")}));
    Require(query.WaitForCalls(2), "first known config is sampled");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    Require(fixture.EventCount("modified") == 0,
            "first known config establishes baseline without false modification");
}

void BusOverflowCountsSubmittedServiceEvents() {
    ScriptedQuery query;
    query.Push(Complete({}));
    CollectorFixture fixture(query, 1, false);
    Require(query.WaitForCalls(1), "initial empty baseline is sampled");
    query.Push(Complete({Service("SvcA", "auto", "C:\\a.exe"),
                         Service("SvcB", "auto", "C:\\b.exe")}));
    Require(query.WaitForCalls(2), "two additions are sampled");
    Require(WaitUntil([&] { return fixture.Health().eventsPushed == 2; }),
            "both service additions reach the bus");
    const auto health = fixture.Health();
    Require(health.eventsPushed == 2,
            "Push false still counts the submitted current event");
    Require(health.busDropped == 1,
            "one evicted older event is reported as bus overflow");
}

void SourceFailureIsVisibleAndExplicitStopReportsStopped() {
    std::mutex mutex;
    std::condition_variable cv;
    bool called = false;
    auto query = [&]() -> edr::ServiceCollectorSnapshot {
        {
            std::lock_guard<std::mutex> lock(mutex);
            called = true;
        }
        cv.notify_all();
        throw std::runtime_error("injected SCM source failure");
    };
    edr::EventBus bus(8);
    EventRecorder recorder;
    bus.Start(&recorder);
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateServiceCollector(100, query));
    Require(collector->Start(&bus), "collector thread starts before source failure");
    {
        std::unique_lock<std::mutex> lock(mutex);
        Require(cv.wait_for(lock, std::chrono::seconds(4), [&] { return called; }),
                "source query is attempted");
    }
    Require(WaitUntil([&] {
                const auto sample = collector->GetHealthSnapshot();
                return sample.state == "source_error" && !sample.running;
            }),
            "fatal source worker exits with an observable error");
    auto failed = collector->GetHealthSnapshot();
    Require(failed.supported && failed.state == "source_error" && !failed.running,
            "fatal source failure is supported, visible, and worker-stopped");
    collector->Stop();
    Require(collector->GetHealthSnapshot().state == "stopped",
            "explicit Stop clears the fatal source state to stopped");
    bus.Stop();
}

} // namespace

int main() {
    ServiceHealthIsSupportedBeforeStart();
    ValidEmptySnapshotReportsRemovedService();
    FailedEmptySnapshotPreservesBaselineAndRecoversQuietly();
    InitialBaselineDoesNotEmitModifiedEvents();
    StartTypeChangesEmitModifiedEvents();
    ConfigQueryFailureAndRecoveryDoNotInventChanges();
    EnumerationFailureTakesPrecedenceOverPriorConfigDegradation();
    FailedFirstConfigThenKnownValueOnlyEstablishesBaseline();
    BusOverflowCountsSubmittedServiceEvents();
    SourceFailureIsVisibleAndExplicitStopReportsStopped();
    std::puts("service collector tests passed");
    return 0;
}
