#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"
#include "collector_usb.h"

namespace {
void Require(bool ok, const char* reason) {
    if (!ok) throw std::runtime_error(reason);
}

bool WaitUntil(const std::function<bool()>& ready) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    do {
        if (ready()) return true;
        Sleep(5);
    } while (std::chrono::steady_clock::now() < until);
    return ready();
}

using Snapshot = edr::UsbSnapshot;
using Observation = edr::UsbDriveObservation;

Snapshot Empty() {
    Snapshot value;
    value.driveSetChecked = true;
    for (auto& drive : value.drives) drive.status = edr::UsbDriveStatus::Missing;
    return value;
}

Observation Present(std::string serial, std::string label = "disk") {
    Observation value;
    value.status = edr::UsbDriveStatus::Present;
    value.metadataKnown = true;
    value.serial = std::move(serial);
    value.volumeName = std::move(label);
    value.fileSystem = "NTFS";
    return value;
}

Observation Failed() {
    Observation value;
    value.status = edr::UsbDriveStatus::Failed;
    return value;
}

Observation UnknownMetadata() {
    Observation value;
    value.status = edr::UsbDriveStatus::Present;
    value.metadataKnown = false;
    return value;
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

class Script {
public:
    void Set(Snapshot next) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_next = std::move(next);
    }
    edr::UsbCollectorQuery Query() {
        return [this] {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_calls;
            return m_next;
        };
    }
    unsigned Calls() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_calls;
    }
private:
    mutable std::mutex m_mutex;
    Snapshot m_next = Empty();
    unsigned m_calls = 0;
};

class BlockingScript {
public:
    void Set(Snapshot next) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_next = std::move(next);
    }
    void BlockNext(Snapshot next) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_next = std::move(next);
        m_blockNext = true;
        m_entered = false;
        m_released = false;
    }
    bool WaitUntilEntered() {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_cv.wait_for(lock, std::chrono::seconds(4), [this] { return m_entered; });
    }
    void Release() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_released = true;
        m_cv.notify_all();
    }
    edr::UsbCollectorQuery Query() {
        return [this] {
            std::unique_lock<std::mutex> lock(m_mutex);
            ++m_calls;
            if (m_blockNext) {
                m_blockNext = false;
                m_entered = true;
                m_cv.notify_all();
                m_cv.wait(lock, [this] { return m_released; });
            }
            return m_next;
        };
    }
private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    Snapshot m_next = Empty();
    unsigned m_calls = 0;
    bool m_blockNext = false;
    bool m_entered = false;
    bool m_released = false;
};

class BlockedQueryReleaseGuard {
public:
    explicit BlockedQueryReleaseGuard(BlockingScript& script,
                                     std::thread* stopper = nullptr)
        : m_script(script), m_stopper(stopper) {}
    ~BlockedQueryReleaseGuard() {
        m_script.Release();
        if (m_stopper && m_stopper->joinable()) m_stopper->join();
    }
private:
    BlockingScript& m_script;
    std::thread* m_stopper;
};

class Fixture {
public:
    explicit Fixture(Script& script, uint32_t pollMs = 10,
                     size_t capacity = 64, bool consume = true)
        : bus(capacity) {
        if (consume) bus.Start(&recorder);
        collector.reset(edr::CreateUsbCollector(pollMs, 5000, script.Query()));
        Require(collector->Start(&bus), "USB collector starts");
    }
    ~Fixture() { collector->Stop(); bus.Stop(); }
    edr::EventBus bus;
    Recorder recorder;
    std::unique_ptr<edr::ICollector> collector;
};

Snapshot WithDriveA(Observation drive) {
    Snapshot value = Empty();
    value.drives[4] = std::move(drive);
    return value;
}

void CompleteEmptySnapshotSeedsAndRemoves() {
    Script script;
    script.Set(WithDriveA(Present("11111111")));
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "reliable initial drive set seeds baseline");
    script.Set(Empty());
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "complete empty drive set removes prior removable drive");
    const auto event = fixture.recorder.Events().front();
    Require(event.fields.at(edr::field::kUsbAction) == "removed", "removal action retained");
    Require(event.fields.at(edr::field::kUsbDriveLetter) == "E:", "drive letter retained");
}

void SameLetterSerialReplacementEmitsBothTransitionsDespiteDedupWindow() {
    Script script;
    script.Set(WithDriveA(Present("11111111", "first")));
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "initial media seeds");
    script.Set(WithDriveA(Present("22222222", "second")));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 2; }),
            "serial replacement emits removal and addition in one poll");
    const auto events = fixture.recorder.Events();
    Require(events[0].fields.at(edr::field::kUsbAction) == "removed" &&
                events[0].fields.at(edr::field::kUsbSerial) == "11111111",
            "old serial is removed first");
    Require(events[1].fields.at(edr::field::kUsbAction) == "added" &&
                events[1].fields.at(edr::field::kUsbSerial) == "22222222",
            "new serial is added second");
}

void UnknownAndPartialObservationsPreserveBaselineAndHealth() {
    Script script;
    Snapshot initial = WithDriveA(Present("11111111"));
    initial.drives[5] = Present("55555555", "other-drive");
    script.Set(initial);
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "initial media seeds");
    Snapshot uncertain = WithDriveA(Failed());
    uncertain.driveSetChecked = false;
    script.Set(uncertain);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().sourceErrors != 0; }),
            "unknown drive observation is visible in health");
    Sleep(80);
    Require(fixture.recorder.Events().empty(),
            "incomplete or failed drive observations do not erase prior baselines");
    auto health = fixture.collector->GetHealthSnapshot();
    Require(health.state == "source_error" && health.sourceErrors != 0,
            "successful unrelated observations cannot mask source failure");
    Snapshot recovery = WithDriveA(Present("11111111"));
    recovery.drives[5] = Present("55555555", "other-drive");
    recovery.driveSetChecked = true;
    script.Set(recovery);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().state == "running"; }),
            "complete recovery restores source health");
    Require(fixture.recorder.Events().empty(),
            "incomplete missing bits preserve unrelated known drive baselines");
}

void FailedInitialDriveDoesNotBlockIndependentDriveTransitions() {
    Script script;
    Snapshot initial = Empty();
    initial.drives[4] = Failed();
    initial.drives[5] = Present("55555555", "seeded-drive");
    script.Set(initial);
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.Calls() >= 2; }),
            "failed initial snapshot is retried while monitoring other letters");
    Snapshot changed = initial;
    changed.drives[6] = Present("66666666", "new-drive");
    script.Set(changed);
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "reliable new drive is reported while another letter remains failed");
    const auto event = fixture.recorder.Events().front();
    Require(event.fields.at(edr::field::kUsbAction) == "added" &&
                event.fields.at(edr::field::kUsbDriveLetter) == "G:",
            "independent drive change keeps existing event contract");
    Require(WaitUntil([&] {
        const auto health = fixture.collector->GetHealthSnapshot();
        return health.countersAvailable && health.counters.count("pending_drive_baselines") != 0;
    }), "per-drive initialization metrics become available");
    auto health = fixture.collector->GetHealthSnapshot();
    Require(health.counters.at("pending_drive_baselines") == 1 &&
                health.counters.at("current_failed_drives") == 1,
            "one failed letter remains pending while other letters seed");
}

void UnknownMetadataRetainsLastKnownSerialUntilReliableRecovery() {
    Script script;
    script.Set(WithDriveA(Present("11111111")));
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "initial media seeds");
    Observation unknown = UnknownMetadata();
    script.Set(WithDriveA(unknown));
    Sleep(80);
    Require(fixture.recorder.Events().empty(), "unknown metadata does not imply replacement");
    Require(fixture.collector->GetHealthSnapshot().counters.at("metadata_unknown_drives") == 1,
            "metadata gaps are reported separately from failed drive status");
    script.Set(WithDriveA(Present("22222222", "replacement")));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 2; }),
            "different serial after unknown metadata is detected");
    const auto events = fixture.recorder.Events();
    Require(events[0].fields.at(edr::field::kUsbSerial) == "11111111" &&
                events[1].fields.at(edr::field::kUsbSerial) == "22222222",
            "last reliable serial survives metadata gaps");
}

void InvalidMetadataIsRejectedWithoutChangingBaseline() {
    Script script;
    script.Set(WithDriveA(Present("11111111")));
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "reliable initial media seeds");
    const auto reject = [&](Observation invalid, const char* reason) {
        const unsigned before = script.Calls();
        script.Set(WithDriveA(std::move(invalid)));
        Require(WaitUntil([&] { return script.Calls() > before; }), reason);
        Sleep(60);
        Require(fixture.recorder.Events().empty(),
                "invalid metadata cannot fabricate a serial replacement");
        const auto health = fixture.collector->GetHealthSnapshot();
        Require(health.counters.count("current_failed_drives") != 0 &&
                    health.counters.at("current_failed_drives") > 0,
                "invalid metadata increments current failed drive count");
    };
    reject(Present("not-hex!", "invalid"),
           "malformed serial is reported as source failure");
    auto contradictory = UnknownMetadata();
    contradictory.serial = "11111111";
    reject(std::move(contradictory), "unknown metadata cannot carry a stale serial");
    auto nulLabel = Present("11111111", std::string("bad\0label", 9));
    reject(std::move(nulLabel), "embedded NUL label is rejected");
    auto oversizedFs = Present("11111111");
    oversizedFs.fileSystem = std::string(4097, 'F');
    reject(std::move(oversizedFs), "oversized file system string is rejected");
    auto invalidUtf8 = Present("11111111", std::string("\xC0\xAF", 2));
    reject(std::move(invalidUtf8), "invalid UTF-8 label is rejected");
    auto unknownEnum = Present("11111111");
    unknownEnum.status = static_cast<edr::UsbDriveStatus>(255);
    reject(std::move(unknownEnum), "unknown drive status enum is rejected");
    Require(fixture.recorder.Events().empty(),
            "invalid metadata cannot fabricate a serial replacement");
    script.Set(WithDriveA(Present("11111111", "recovered")));
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().state == "running"; }),
            "valid metadata restores source health");
    Require(fixture.recorder.Events().empty(), "recovery with original serial remains silent");
}

void RemovableBecomingNonremovableIsRemoval() {
    Script script;
    script.Set(WithDriveA(Present("11111111")));
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "initial media seeds");
    Snapshot fixed = Empty();
    fixed.drives[4].status = edr::UsbDriveStatus::Missing;
    script.Set(fixed);
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "known non-removable transition reports removal");
}

void QueryExceptionsAreContainedAndWorkerCanRestart() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    std::unique_ptr<edr::ICollector> collector(edr::CreateUsbCollector(10, 100,
        [&]() -> Snapshot {
            if (++calls == 1) throw std::runtime_error("scripted query failure");
            return Empty();
        }));
    Require(collector->Start(&bus), "worker starts");
    Require(WaitUntil([&] {
        const auto health = collector->GetHealthSnapshot();
        return health.sourceErrors != 0 && health.state == "source_error";
    }), "query exception is contained and recorded");
    Require(collector->GetHealthSnapshot().counters.at("current_failed_drives") == 26,
            "fatal whole-snapshot failure marks every drive currently unobserved");
    Require(collector->Start(&bus), "dead joinable worker is joined and restarted");
    Require(WaitUntil([&] { return collector->GetHealthSnapshot().running; }),
            "restarted worker reports active");
    collector->Stop();
    Require(collector->GetHealthSnapshot().state == "stopped",
            "explicit stop after fatal worker reports stopped");
    bus.Stop();
}

void FatalWorkerExplicitStopReportsStopped() {
    edr::EventBus bus(16);
    std::unique_ptr<edr::ICollector> collector(edr::CreateUsbCollector(10, 100,
        []() -> Snapshot { throw std::runtime_error("scripted fatal query"); }));
    Require(collector->Start(&bus), "fatal-state worker starts");
    Require(WaitUntil([&] {
        const auto health = collector->GetHealthSnapshot();
        return !health.running && health.state == "source_error";
    }), "fatal query is visible before explicit stop");
    collector->Stop();
    Require(collector->GetHealthSnapshot().state == "stopped",
            "explicit stop clears fatal runtime state");
    bus.Stop();
}

void EventStringsRespectThe4096ByteBound() {
    Script script;
    auto drive = Present("12345678", std::string(4096, 'L'));
    drive.fileSystem = std::string(4096, 'F');
    script.Set(WithDriveA(std::move(drive)));
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "bounded candidate snapshot is sampled");
    const auto health = fixture.collector->GetHealthSnapshot();
    Require(health.countersAvailable && health.counters.at("successful_snapshots") != 0,
            "successful scan is exposed in health");
    script.Set(Empty());
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "bounded observation still reports presence");
    const auto event = fixture.recorder.Events().front();
    for (const auto& field : event.fields) {
        Require(field.second.size() <= 4096, "event field fits fixed bound");
        Require(field.second.find('\0') == std::string::npos, "event field has no embedded NUL");
    }
}

void EmptyVolumeLabelIsValidMetadata() {
    Script script;
    script.Set(WithDriveA(Present("12345678", "")));
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "empty volume label remains a successful metadata read");
    script.Set(Empty());
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "empty-label device can still be removed normally");
    Require(fixture.recorder.Events()[0].fields.count(edr::field::kUsbDeviceName) == 0,
            "empty label is omitted from event fields");
}

void RestartSeedsCurrentStateAndPreservesCumulativeHealth() {
    Script script;
    script.Set(WithDriveA(Present("11111111")));
    Fixture fixture(script);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "initial state is sampled");
    const auto beforeStop = fixture.collector->GetHealthSnapshot();
    fixture.collector->Stop();
    script.Set(Empty());
    Require(fixture.collector->Start(&fixture.bus), "collector starts after stop");
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().state == "running"; }),
            "restart seeds the current complete snapshot");
    Sleep(80);
    Require(fixture.recorder.Events().empty(), "state changes while stopped are not replayed");
    Require(fixture.collector->GetHealthSnapshot().counters.at("successful_snapshots") >=
                beforeStop.counters.at("successful_snapshots"),
            "restart retains cumulative health counters");
    script.Set(WithDriveA(Present("22222222")));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "changes after restart baseline are still observed");
}

void RestartClearsCurrentSourceStateUntilFirstQueryReturns() {
    BlockingScript script;
    Snapshot initial = Empty();
    initial.drives[0] = Present("11111111");
    script.Set(initial);
    edr::EventBus bus(64);
    Recorder recorder;
    bus.Start(&recorder);
    std::unique_ptr<edr::ICollector> collector(edr::CreateUsbCollector(10, 0, script.Query()));
    BlockedQueryReleaseGuard releaseGuard(script);
    Require(collector->Start(&bus), "collector starts for health restart test");
    Require(WaitUntil([&] { return collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "first run records a successful sample");

    Snapshot partial = Empty();
    partial.driveSetChecked = false;
    partial.drives[0] = Failed();
    script.Set(partial);
    Require(WaitUntil([&] { return collector->GetHealthSnapshot().state == "source_error"; }),
            "first run records a current source error");
    const auto beforeStop = collector->GetHealthSnapshot();
    const auto successfulBefore = beforeStop.counters.at("successful_snapshots");
    const auto errorsBefore = beforeStop.sourceErrors;
    collector->Stop();

    script.BlockNext(Empty());
    Require(collector->Start(&bus), "collector restarts for blocked-query health test");
    Require(script.WaitUntilEntered(), "restarted worker entered its blocked query");
    const auto whileBlocked = collector->GetHealthSnapshot();
    const bool restartStartsCleanly = whileBlocked.running && whileBlocked.state == "starting";
    const bool countersPreserved = whileBlocked.sourceErrors == errorsBefore &&
        whileBlocked.counters.at("successful_snapshots") == successfulBefore;

    script.Release();
    Require(WaitUntil([&] { return collector->GetHealthSnapshot().state == "running"; }),
            "first successful restarted sample restores running state");
    Require(collector->GetHealthSnapshot().counters.at("successful_snapshots") > successfulBefore,
            "restarted sample increments successful snapshot count");
    collector->Stop();
    bus.Stop();
    Require(restartStartsCleanly,
            "restart clears current source state until its first result");
    Require(countersPreserved, "restart preserves cumulative health counters");
}

void StopDuringBlockedQueryDoesNotApplyItsResult() {
    BlockingScript script;
    script.Set(WithDriveA(Present("11111111")));
    edr::EventBus bus(64);
    Recorder recorder;
    bus.Start(&recorder);
    std::unique_ptr<edr::ICollector> collector(edr::CreateUsbCollector(10, 0, script.Query()));
    std::atomic<bool> stopCallStarted{false};
    std::thread stopper;
    BlockedQueryReleaseGuard releaseGuard(script, &stopper);
    Require(collector->Start(&bus), "collector starts for blocked stop test");
    Require(WaitUntil([&] { return collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "initial baseline is sampled before blocked stop test");
    script.BlockNext(Empty());
    Require(script.WaitUntilEntered(), "worker entered the blocked removal query");

    stopper = std::thread([&] {
        stopCallStarted.store(true);
        collector->Stop();
    });
    Require(WaitUntil([&] { return stopCallStarted.load(); }), "stop call begins");
    Sleep(40);
    script.Release();
    stopper.join();
    Require(recorder.Events().empty(), "query result returned after Stop does not emit removal");
    bus.Stop();
}

void ZeroPollIsClampedAndOverflowIsReported() {
    Script script;
    script.Set(WithDriveA(Present("11111111")));
    Fixture fixture(script, 0, 1, false);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "zero poll still takes a bounded scan interval");
    script.Set(WithDriveA(Present("22222222")));
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().eventsPushed != 0; }),
            "event submission continues with clamped poll");
    Require(fixture.collector->GetHealthSnapshot().busDropped != 0,
            "event bus overflow is visible in collector health");
}

void NativeQueryRunsAsReadOnlySmoke() {
    edr::EventBus bus(16);
    std::unique_ptr<edr::ICollector> collector(edr::CreateUsbCollector(100, 0));
    Require(collector->Start(&bus), "native query worker starts");
    Require(WaitUntil([&] {
        const auto health = collector->GetHealthSnapshot();
        return health.supported && health.running && health.countersAvailable &&
            health.counters.at("successful_snapshots") + health.sourceErrors > 0;
    }), "native logical-drive scan executes without changing devices");
    collector->Stop();
    Require(!collector->GetHealthSnapshot().running, "native smoke stops cleanly");
    bus.Stop();
}

} // namespace

int main() {
    try {
        CompleteEmptySnapshotSeedsAndRemoves();
        SameLetterSerialReplacementEmitsBothTransitionsDespiteDedupWindow();
        UnknownAndPartialObservationsPreserveBaselineAndHealth();
        FailedInitialDriveDoesNotBlockIndependentDriveTransitions();
        UnknownMetadataRetainsLastKnownSerialUntilReliableRecovery();
        InvalidMetadataIsRejectedWithoutChangingBaseline();
        RemovableBecomingNonremovableIsRemoval();
        QueryExceptionsAreContainedAndWorkerCanRestart();
        FatalWorkerExplicitStopReportsStopped();
        EventStringsRespectThe4096ByteBound();
        EmptyVolumeLabelIsValidMetadata();
        RestartSeedsCurrentStateAndPreservesCumulativeHealth();
        StopDuringBlockedQueryDoesNotApplyItsResult();
        RestartClearsCurrentSourceStateUntilFirstQueryReturns();
        ZeroPollIsClampedAndOverflowIsReported();
        NativeQueryRunsAsReadOnlySmoke();
        std::puts("USB collector tests passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "USB collector tests failed: %s\n", error.what());
        return 1;
    }
}
