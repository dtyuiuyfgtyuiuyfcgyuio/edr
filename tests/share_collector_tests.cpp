#include <windows.h>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>
#include "collector.h"
#include "collector_share.h"

namespace {
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
edr::ShareCollectorSnapshot Complete(
    std::vector<edr::ShareCollectorEntry> entries = {}) {
    return {true, std::move(entries)};
}
edr::ShareCollectorEntry Share(const char* name, const char* path = "C:\\data") {
    return {name, path, "disk", "private fixture"};
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
    void Set(edr::ShareCollectorSnapshot next) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_next = std::move(next);
        m_calls = 0;
    }
    edr::ShareCollectorQuery Query() {
        return [this] {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_calls;
            return m_next;
        };
    }
    bool SampledTwice() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_calls >= 2;
    }
private:
    std::mutex m_mutex;
    edr::ShareCollectorSnapshot m_next;
    unsigned m_calls = 0;
};
class Fixture {
public:
    explicit Fixture(Script& script, size_t capacity = 64, bool consume = true)
        : bus(capacity) {
        if (consume) bus.Start(&recorder);
        collector.reset(edr::CreateShareCollector(25, script.Query()));
        Require(collector->Start(&bus), "share worker starts");
    }
    ~Fixture() { collector->Stop(); bus.Stop(); }
    edr::EventBus bus;
    Recorder recorder;
    std::unique_ptr<edr::ICollector> collector;
};
void PaginationIsBoundedAndAllOrNothing() {
    unsigned calls = 0;
    auto snapshot = edr::ReadShareCollectorSnapshot([&](uint32_t resume) {
        ++calls;
        if (resume == 0) return edr::ShareCollectorPage{ERROR_MORE_DATA, 7, {Share("one")}};
        Require(resume == 7, "resume is forwarded unchanged");
        return edr::ShareCollectorPage{ERROR_SUCCESS, 0, {Share("two")}};
    });
    Require(snapshot.complete && snapshot.shares.size() == 2 && calls == 2,
            "all successful pages form one complete snapshot");
    snapshot = edr::ReadShareCollectorSnapshot([](uint32_t resume) {
        return resume == 0 ? edr::ShareCollectorPage{ERROR_MORE_DATA, 7, {Share("one")}} :
                            edr::ShareCollectorPage{ERROR_ACCESS_DENIED, 0, {Share("partial")}};
    });
    Require(!snapshot.complete && snapshot.shares.empty(), "later page failure discards partial data");
    snapshot = edr::ReadShareCollectorSnapshot([](uint32_t) {
        return edr::ShareCollectorPage{ERROR_MORE_DATA, 0, {Share("one")}};
    });
    Require(!snapshot.complete, "nonadvancing resume fails");
    calls = 0;
    snapshot = edr::ReadShareCollectorSnapshot([&](uint32_t resume) {
        ++calls;
        return edr::ShareCollectorPage{ERROR_MORE_DATA, resume == 7 ? 9u : 7u,
                                      {Share(std::to_string(calls).c_str())}};
    });
    Require(!snapshot.complete && calls == 3, "resume cycles terminate");
    snapshot = edr::ReadShareCollectorSnapshot([](uint32_t resume) {
        return edr::ShareCollectorPage{static_cast<uint32_t>(resume ? ERROR_SUCCESS : ERROR_MORE_DATA),
                                      7, {Share("duplicate")}};
    });
    Require(!snapshot.complete, "duplicate names cannot silently replace an entry");
    snapshot = edr::ReadShareCollectorSnapshot([](uint32_t) {
        return edr::ShareCollectorPage{ERROR_SUCCESS, 0, {Share("long", std::string(4097, 'x').c_str())}};
    });
    Require(!snapshot.complete, "oversized field fails closed");
    calls = 0;
    snapshot = edr::ReadShareCollectorSnapshot([&](uint32_t resume) {
        ++calls;
        return edr::ShareCollectorPage{ERROR_MORE_DATA, resume + 1,
                                      {Share(std::to_string(calls).c_str())}};
    });
    Require(!snapshot.complete && calls == 256, "pagination budget terminates a growing enumeration");
    snapshot = edr::ReadShareCollectorSnapshot([](uint32_t) {
        auto entry = Share("embedded");
        entry.name = std::string("embedded\0name", 13);
        return edr::ShareCollectorPage{ERROR_SUCCESS, 0, {entry}};
    });
    Require(!snapshot.complete, "embedded NUL fails closed");
    snapshot = edr::ReadShareCollectorSnapshot([](uint32_t) {
        return edr::ShareCollectorPage{ERROR_SUCCESS, 0, {Share("\xc3\x28")}};
    });
    Require(!snapshot.complete, "invalid UTF-8 fails closed");
    snapshot = edr::ReadShareCollectorSnapshot([](uint32_t) {
        std::vector<edr::ShareCollectorEntry> many;
        for (unsigned i = 0; i < 1100; ++i)
            many.push_back(Share(std::to_string(i).c_str(), std::string(4096, 'x').c_str()));
        return edr::ShareCollectorPage{ERROR_SUCCESS, 0, std::move(many)};
    });
    Require(!snapshot.complete, "aggregate payload cannot exceed the charged budget");
    snapshot = edr::ReadShareCollectorSnapshot([](uint32_t) {
        return edr::ShareCollectorPage{ERROR_SUCCESS, 0, {}};
    });
    Require(snapshot.complete && snapshot.shares.empty(), "valid empty native snapshot is complete");
}
void EmptyBaselineKeepsPolling() {
    Script script;
    script.Set(Complete());
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.SampledTwice(); }),
            "complete empty share baseline must keep polling");
    script.Set(Complete({Share("new-share")}));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "share appearing after empty baseline is emitted");
    const auto events = fixture.recorder.Events();
    Require(events[0].fields.at(edr::field::kShareAction) == "added",
            "new share is added");
}
void FailuresNeverPublishPartialOrEraseBaseline() {
    Script script;
    script.Set(Complete({Share("stable")}));
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.SampledTwice(); }), "baseline sampled");
    script.Set({false, {Share("partial")}});
    Require(WaitUntil([&] { return script.SampledTwice(); }), "failed samples retried");
    Require(fixture.recorder.Events().empty(), "partial share list emits nothing");
    script.Set(Complete({Share("stable")}));
    Require(WaitUntil([&] { return script.SampledTwice(); }), "recovery sampled");
    Require(fixture.recorder.Events().empty(), "unchanged recovery stays quiet");
    script.Set(Complete());
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "complete empty removes existing share");
    Require(fixture.recorder.Events()[0].fields.at(edr::field::kShareAction) == "removed",
            "removed action preserved");
}
void FailedStartupSeedsQuietlyAndModificationsAreObserved() {
    Script script;
    script.Set({});
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.SampledTwice(); }), "failed startup retries");
    script.Set(Complete({Share("recovered")}));
    Require(WaitUntil([&] { return script.SampledTwice(); }), "first success seeds");
    Require(fixture.recorder.Events().empty(), "first valid list does not burst");
    script.Set(Complete({Share("recovered", "C:\\changed")}));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "changed path emitted");
    Require(fixture.recorder.Events()[0].fields.at(edr::field::kShareAction) == "modified",
            "modified action preserved");
}
void HealthFailureRecoveryStopAndOverflow() {
    Script script;
    script.Set(Complete({Share("baseline")}));
    Fixture fixture(script, 1, false);
    Require(WaitUntil([&] {
        auto h = fixture.collector->GetHealthSnapshot();
        return h.running && h.lastSuccess100ns != 0;
    }), "complete snapshot is observable");
    script.Set({});
    Require(WaitUntil([&] {
        auto h = fixture.collector->GetHealthSnapshot();
        return h.state == "source_error" && h.sourceErrors > 0;
    }), "failure is observable while worker retries");
    script.Set(Complete({Share("baseline"), Share("one"), Share("two")}));
    Require(WaitUntil([&] {
        auto h = fixture.collector->GetHealthSnapshot();
        return h.state == "running" && h.eventsPushed == 2;
    }), "successful recovery publishes two real additions");
    auto h = fixture.collector->GetHealthSnapshot();
    Require(h.busDropped == 1 && fixture.bus.SnapshotStats().pending == 1,
            "overflow counts old evicted event, latest event is submitted");
    fixture.collector->Stop();
    h = fixture.collector->GetHealthSnapshot();
    Require(!h.running && h.state == "stopped", "stopped health is explicit");
    Require(fixture.collector->Start(&fixture.bus), "stopped share collector can restart");
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().running; }), "restart worker running");
    Sleep(60);
    Require(fixture.collector->GetHealthSnapshot().eventsPushed == 2, "restart seeds without a burst");
}
void FatalQueryFailureDoesNotEscapeWorker() {
    Recorder recorder;
    edr::EventBus bus(8);
    bus.Start(&recorder);
    std::unique_ptr<edr::ICollector> collector(edr::CreateShareCollector(25,
        []() -> edr::ShareCollectorSnapshot { throw std::runtime_error("injected"); }));
    Require(collector->Start(&bus), "thread starts before injected query failure");
    Require(WaitUntil([&] {
        auto h = collector->GetHealthSnapshot();
        return h.supported && !h.running && h.state == "source_error";
    }), "fatal query records failure and exits safely");
    Require(!collector->Start(&bus), "dead joinable worker cannot claim a running start");
    collector->Stop();
    bus.Stop();
}
} // namespace
int main() {
    try {
        EmptyBaselineKeepsPolling();
        PaginationIsBoundedAndAllOrNothing();
        FailuresNeverPublishPartialOrEraseBaseline();
        FailedStartupSeedsQuietlyAndModificationsAreObserved();
        HealthFailureRecoveryStopAndOverflow();
        FatalQueryFailureDoesNotEscapeWorker();
        std::puts("share collector tests passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "share collector tests failed: %s\n", error.what());
        return 1;
    }
}
