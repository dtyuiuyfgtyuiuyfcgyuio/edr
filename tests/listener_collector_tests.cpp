#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include "collector.h"
#include "collector_listener.h"

namespace {
using Domain = edr::ListenerTableDomain;
using Entry = edr::ListenerCollectorEntry;
using Snapshot = edr::ListenerCollectorSnapshot;
using Frame = std::array<Snapshot, 4>;
void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}
template <typename Predicate> bool WaitUntil(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return predicate();
}
Snapshot Complete(std::initializer_list<Entry> entries = {}) {
    Snapshot snapshot;
    snapshot.complete = true;
    snapshot.listeners.assign(entries.begin(), entries.end());
    return snapshot;
}
Frame EmptyFrame() { return {Complete(), Complete(), Complete(), Complete()}; }
Entry Listener(uint16_t port = 12345, uint32_t pid = 0, uint32_t scope = 0) {
    Entry entry;
    entry.localPort = port;
    entry.pid = pid;
    entry.scopeId = scope;
    return entry;
}
class ScriptedQuery {
public:
    void Push(Frame frame) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_frames.push_back(std::move(frame));
    }
    edr::ListenerCollectorQuery Callback() {
        return [this](Domain domain) {
            std::lock_guard<std::mutex> lock(m_mutex);
            const size_t index = static_cast<size_t>(domain);
            if (index == 0 && !m_frames.empty()) {
                m_last = std::move(m_frames.front());
                m_frames.pop_front();
            }
            if (index == 3) ++m_rounds;
            return m_last[index];
        };
    }
    bool WaitRounds(size_t count) {
        return WaitUntil([&] {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_rounds >= count;
        });
    }
private:
    std::mutex m_mutex;
    std::deque<Frame> m_frames;
    Frame m_last = EmptyFrame();
    size_t m_rounds = 0;
};
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
    bool WaitCount(size_t expected) {
        return WaitUntil([&] { return Events().size() >= expected; });
    }
private:
    mutable std::mutex m_mutex;
    std::vector<edr::Event> m_events;
};
std::string Field(const edr::Event& event, const char* name) {
    const auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}
class Fixture {
public:
    Fixture(ScriptedQuery& query, size_t capacity = 64, bool consume = true)
        : bus(capacity) {
        if (consume) bus.Start(&recorder);
        collector.reset(edr::CreateListenerCollector(50, query.Callback()));
        Require(collector->Start(&bus), "listener worker starts");
    }
    ~Fixture() { collector->Stop(); bus.Stop(); }
    edr::CollectorHealthSnapshot Health() const { return collector->GetHealthSnapshot(); }
    edr::EventBus bus;
    Recorder recorder;
    std::unique_ptr<edr::ICollector> collector;
};

void InitialHealth() {
    std::unique_ptr<edr::ICollector> collector(edr::CreateListenerCollector(100));
    const auto health = collector->GetHealthSnapshot();
    Require(health.supported, "listener health is supported before Start");
    Require(!health.running && health.state == "stopped", "unstarted listener is stopped");
    Require(!collector->Start(nullptr), "null bus is rejected");
    Require(health.counters.find("tcp6.available") == health.counters.end(),
            "unobserved table availability is absent");
}
void FailedDomainIsIsolatedAndRecoveryIsQuiet() {
    for (size_t failedDomain = 0; failedDomain < 4; ++failedDomain) {
        ScriptedQuery query;
        Frame baseline = EmptyFrame();
        for (auto& domain : baseline) domain = Complete({Listener()});
        query.Push(baseline);
        Fixture fixture(query);
        Require(query.WaitRounds(1), "four-domain baseline queried");
        Frame failed = baseline;
        failed[failedDomain] = Snapshot{};
        // Partial rows must be discarded too.
        failed[failedDomain].listeners.push_back(Listener(44444));
        const size_t unaffected = (failedDomain + 1) % 4;
        failed[unaffected] = Complete({Listener(), Listener(23456)});
        query.Push(failed);
        Require(fixture.recorder.WaitCount(1), "healthy domain emits while another fails");
        Require(WaitUntil([&] { return fixture.Health().state == "source_error"; }),
                "one failed domain degrades aggregate health regardless of query order");
        const char* names[] = {"tcp4", "udp4", "tcp6", "udp6"};
        auto health = fixture.Health();
        const std::string prefix = std::string(names[failedDomain]) + ".";
        Require(health.counters.at(prefix + "available") == 0,
                "failed domain reports unavailable");
        Require(health.counters.at(prefix + "source_errors") > 0 && health.sourceErrors > 0,
                "domain and aggregate source errors accumulate");
        Require(health.counters.at(prefix + "listeners") == 1,
                "failed domain retains last complete listener count");
        Frame recovered = failed;
        recovered[failedDomain] = baseline[failedDomain];
        query.Push(recovered);
        Require(WaitUntil([&] { return fixture.Health().state == "running"; }),
                "recovered complete tables restore running health");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        Require(fixture.recorder.Events().size() == 1,
                "partial failure and recovery invent no removals or duplicate additions");
        Require(fixture.Health().counters.at(prefix + "source_errors") >=
                    health.counters.at(prefix + "source_errors"),
                "recovery keeps historical errors");
    }
}
void FirstFailureThenSuccessSeedsEachDomain() {
    ScriptedQuery query;
    query.Push(Frame{});
    Fixture fixture(query);
    Require(query.WaitRounds(1), "initial failure sampled");
    Require(WaitUntil([&] { return fixture.Health().sourceErrors >= 4; }),
            "initial four failed domains recorded");
    Frame recovered = EmptyFrame();
    for (auto& domain : recovered) domain = Complete({Listener()});
    query.Push(recovered);
    Require(WaitUntil([&] { return fixture.Health().state == "running"; }),
            "first successful sample completes");
    Require(fixture.recorder.Events().empty(), "first success after failure seeds without burst");
    query.Push(EmptyFrame());
    Require(fixture.recorder.WaitCount(4), "confirmed empty snapshots remove four seeded listeners");
    for (const auto& event : fixture.recorder.Events())
        Require(Field(event, edr::field::kListenerAction) == "removed", "empty yields removals");
}
void AddressFamiliesScopesAndProtocolsAreDistinct() {
    ScriptedQuery query;
    query.Push(EmptyFrame());
    Fixture fixture(query);
    Require(query.WaitRounds(1), "empty baseline seeded");
    Frame added = EmptyFrame();
    added[0] = Complete({Listener()});
    added[1] = Complete({Listener()});
    Entry scoped = Listener(12345, 0, 7);
    scoped.address[0] = 0xfe;
    scoped.address[1] = 0x80;
    scoped.address[15] = 1;
    Entry otherScope = scoped;
    otherScope.scopeId = 9;
    added[2] = Complete({Listener(), scoped, otherScope});
    added[3] = Complete({Listener()});
    query.Push(added);
    Require(fixture.recorder.WaitCount(6), "family, protocol, and scope produce six distinct additions");
    size_t ipv4 = 0, ipv6 = 0, scopedCount = 0;
    for (const auto& event : fixture.recorder.Events()) {
        const std::string family = Field(event, edr::field::kListenerAddressFamily);
        const std::string ip = Field(event, edr::field::kListenerIp);
        if (family == "ipv4") { ++ipv4; Require(ip == "*", "IPv4 wildcard remains star"); }
        if (family == "ipv6") {
            ++ipv6;
            if (ip == "fe80::1%7" || ip == "fe80::1%9") ++scopedCount;
        }
        Require(Field(event, edr::field::kListenerPort) == "12345", "old port field retained");
    }
    Require(ipv4 == 2 && ipv6 == 4 && scopedCount == 2, "scope and family rendered correctly");
    query.Push(EmptyFrame());
    Require(fixture.recorder.WaitCount(12), "all distinct keys remove independently");
}
void RemovalUsesSavedInstanceAndRejectsBareImage() {
    ScriptedQuery query;
    Entry trusted = Listener(12345, GetCurrentProcessId());
    trusted.imagePath = "C:\\old-instance.exe";
    trusted.processStartTime100ns = 42;
    Entry bare = Listener(23456, GetCurrentProcessId());
    bare.imagePath = "C:\\unbound.exe";
    Frame baseline = EmptyFrame();
    baseline[0] = Complete({trusted, bare});
    query.Push(baseline);
    Fixture fixture(query);
    Require(query.WaitRounds(1), "saved process context baseline queried");
    query.Push(EmptyFrame());
    Require(fixture.recorder.WaitCount(2), "two metadata removals observed");
    for (const auto& event : fixture.recorder.Events()) {
        if (Field(event, edr::field::kListenerPort) == "12345") {
            Require(Field(event, edr::field::kListenerProcess) == trusted.imagePath &&
                    event.processStartTime100ns == 42,
                    "removed uses saved old image+birth instead of querying current same PID");
        } else {
            Require(Field(event, edr::field::kListenerProcess).empty(),
                    "bare image metadata is not attributed");
        }
    }
}
void OverflowAndStopHealth() {
    ScriptedQuery query;
    query.Push(EmptyFrame());
    Fixture fixture(query, 1, false);
    Require(query.WaitRounds(1), "overflow baseline sampled");
    Frame additions = EmptyFrame();
    additions[0] = Complete({Listener(11111), Listener(22222)});
    query.Push(additions);
    Require(WaitUntil([&] { return fixture.Health().eventsPushed == 2; }),
            "both events counted including Push false");
    Require(fixture.Health().busDropped == 1 && fixture.bus.DroppedCount() == 1,
            "overflow health agrees with bus eviction");
    fixture.collector->Stop();
    Require(!fixture.Health().running && fixture.Health().state == "stopped",
            "explicit stop reports stopped with retained counters");
    Require(fixture.Health().eventsPushed == 2, "Stop retains submitted count");
}
void WorkerExceptionHealth() {
    edr::EventBus bus(8);
    std::unique_ptr<edr::ICollector> collector(edr::CreateListenerCollector(50,
        [](Domain) -> Snapshot { throw std::runtime_error("injected source exception"); }));
    Require(collector->Start(&bus), "worker exception happens after Start");
    Require(WaitUntil([&] { const auto health = collector->GetHealthSnapshot();
        return health.state == "source_error" && !health.running; }),
        "exception leaves stopped worker and visible source error");
    Require(collector->GetHealthSnapshot().counters.at("worker_exceptions") == 1,
            "fatal worker exception counted once");
    Require(!collector->Start(&bus), "Start does not claim a dead joinable worker is running");
    collector->Stop();
    Require(collector->GetHealthSnapshot().state == "stopped", "explicit Stop dominates exception state");
}

void SamePidDifferentCreationTimeReplacesInstance() {
    ScriptedQuery query;
    auto before = Listener(12345, 9988);
    before.processStartTime100ns = 100;
    before.imagePath = "C:\\before.exe";
    Frame first = EmptyFrame();
    first[0] = Complete({before});
    query.Push(first);
    Fixture fixture(query);
    Require(query.WaitRounds(1), "PID-reuse baseline seeded");
    auto after = before;
    after.processStartTime100ns = 200;
    after.imagePath = "C:\\after.exe";
    Frame replacement = EmptyFrame();
    replacement[0] = Complete({after});
    query.Push(replacement);
    Require(fixture.recorder.WaitCount(2), "same endpoint and PID with new process birth replaces instance");
    for (const auto& event : fixture.recorder.Events()) {
        const bool removed = Field(event, edr::field::kListenerAction) == "removed";
        Require(event.processStartTime100ns == (removed ? 100u : 200u),
                "PID reuse events preserve the corresponding exact instance");
        Require(Field(event, edr::field::kListenerProcess) ==
                    (removed ? before.imagePath : after.imagePath),
                "PID reuse removal retains the old image");
    }
}

void InvalidMetadataAndDuplicateSnapshotsPreserveBaseline() {
    const std::string invalidPaths[] = {std::string(4097, 'x'), std::string("a\0b", 3),
        std::string("\xc0\xaf", 2), std::string("\xed\xa0\x80", 3)};
    for (size_t test = 0; test < 5; ++test) {
        ScriptedQuery query;
        auto entry = Listener(12345, 9988);
        entry.processStartTime100ns = 100;
        entry.imagePath = "C:\\valid.exe";
        Frame first = EmptyFrame();
        first[0] = Complete({entry});
        query.Push(first);
        Fixture fixture(query);
        Require(query.WaitRounds(1), "metadata validation baseline seeded");
        Frame invalid = EmptyFrame();
        if (test < 4) {
            entry.imagePath = invalidPaths[test];
            invalid[0] = Complete({entry});
        } else {
            auto conflicting = entry;
            conflicting.processStartTime100ns = 200;
            conflicting.imagePath = "C:\\other.exe";
            invalid[0] = Complete({entry, conflicting});
        }
        query.Push(invalid);
        Require(WaitUntil([&] { return fixture.Health().state == "source_error"; }),
                "invalid path or duplicate key invalidates domain snapshot");
        Require(fixture.Health().counters.at("tcp4.listeners") == 1,
                "invalid data preserves previous listener baseline");
        query.Push(first);
        Require(WaitUntil([&] { return fixture.Health().state == "running"; }),
                "valid snapshot recovers after invalid metadata");
        Require(fixture.recorder.Events().empty(), "invalid metadata creates no synthetic changes");
    }
}

void IdenticalDuplicateSnapshotRowsCollapse() {
    ScriptedQuery query;
    auto entry = Listener(23456, 1234);
    entry.imagePath = "C:\\same.exe";
    entry.processStartTime100ns = 100;
    Frame first = EmptyFrame();
    first[0] = Complete({entry});
    query.Push(first);
    Fixture fixture(query);
    Require(query.WaitRounds(1), "duplicate-collapse baseline seeded");
    Frame duplicate = EmptyFrame();
    duplicate[0] = Complete({entry, entry});
    query.Push(duplicate);
    Require(query.WaitRounds(2), "identical endpoint context duplicate sampled");
    Require(WaitUntil([&] { return fixture.Health().state == "running"; }),
            "identical endpoint context duplicate remains a complete snapshot");
    Require(fixture.Health().counters.at("tcp4.listeners") == 1,
            "duplicate socket rows retain one semantic endpoint");
    Require(fixture.recorder.Events().empty(),
            "adding or collapsing duplicate rows does not create listener events");
    query.Push(first);
    Require(query.WaitRounds(3), "duplicate endpoint reduction sampled");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    Require(fixture.recorder.Events().empty() &&
            fixture.Health().counters.at("tcp4.listeners") == 1,
            "reducing duplicate rows to one does not emit a false removal");
}

void RetainedMemoryBudgetRejectsLargeContextSnapshot() {
    ScriptedQuery query;
    query.Push(EmptyFrame());
    Fixture fixture(query);
    Require(query.WaitRounds(1), "memory-budget baseline seeded");
    Frame huge = EmptyFrame();
    huge[0].listeners.reserve(5000);
    for (uint32_t pid = 1; pid <= 5000; ++pid) {
        Entry entry = Listener(12345, pid);
        entry.imagePath = std::string(4096, 'x');
        entry.processStartTime100ns = 100;
        huge[0].listeners.push_back(std::move(entry));
    }
    query.Push(std::move(huge));
    Require(WaitUntil([&] { return fixture.Health().state == "source_error"; }),
            "retained map+paths exceeding 16MiB invalidate snapshot");
    Require(fixture.recorder.Events().empty() && fixture.Health().counters.at("tcp4.listeners") == 0,
            "over-budget snapshot preserves empty baseline without an event burst");
}

void UnknownContextDoesNotInventListenerChanges() {
    ScriptedQuery query;
    Entry entry = Listener(12345, 9988);
    entry.imagePath = "C:\\same.exe";
    entry.processStartTime100ns = 100;
    Frame first = EmptyFrame();
    first[0] = Complete({entry});
    query.Push(first);
    Fixture fixture(query);
    Require(query.WaitRounds(1), "known-context baseline seeded");
    Frame unknown = first;
    unknown[0].listeners[0].imagePath.clear();
    unknown[0].listeners[0].processStartTime100ns = 0;
    query.Push(unknown);
    Require(query.WaitRounds(2), "unknown context sampled");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    Require(fixture.recorder.Events().empty(), "missing context is not a confirmed listener replacement");
    query.Push(first);
    Require(query.WaitRounds(4), "known context recovers");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    Require(fixture.recorder.Events().empty(), "context recovery does not invent listener changes");
}

void UnknownContextPreservesReliableHistoryAndFirstKnownSeeds() {
    for (size_t scenario = 0; scenario < 2; ++scenario) {
        ScriptedQuery query;
        Entry before = Listener(12345, 9988);
        if (scenario == 0) {
            before.imagePath = "C:\\before.exe";
            before.processStartTime100ns = 100;
        }
        Frame first = EmptyFrame();
        first[0] = Complete({before});
        query.Push(first);
        Fixture fixture(query);
        Require(query.WaitRounds(1), "context-history baseline seeded");
        Frame unknown = first;
        unknown[0].listeners[0].imagePath.clear();
        unknown[0].listeners[0].processStartTime100ns = 0;
        query.Push(unknown);
        Require(query.WaitRounds(2), "context-history unavailable sample queried");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        auto after = before;
        after.imagePath = "C:\\after.exe";
        after.processStartTime100ns = 200;
        Frame last = first;
        last[0] = Complete({after});
        query.Push(last);
        if (scenario == 0) {
            Require(fixture.recorder.WaitCount(2), "birth A through unknown to birth B replaces listener");
            for (const auto& event : fixture.recorder.Events()) {
                const bool removed = Field(event, edr::field::kListenerAction) == "removed";
                Require(event.processStartTime100ns == (removed ? 100u : 200u),
                        "unknown sampling retains reliable historical birth");
                Require(Field(event, edr::field::kListenerProcess) ==
                        (removed ? before.imagePath : after.imagePath),
                        "replacement removal retains reliable historical image");
            }
        } else {
            Require(query.WaitRounds(4), "first reliable context sampled");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            Require(fixture.recorder.Events().empty(), "initial unknown to first known emits no extra addition");
        }
    }
}

void RestartResetsCurrentDomainsAndZeroPollWaits() {
    std::atomic<bool> block{false}, entered{false}, release{false};
    std::atomic<unsigned> calls{0};
    auto query = [&](Domain) {
        calls.fetch_add(1);
        if (block.load()) {
            entered.store(true);
            while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return Complete({Listener()});
    };
    edr::EventBus bus(8);
    std::unique_ptr<edr::ICollector> collector(edr::CreateListenerCollector(0, query));
    Require(collector->Start(&bus), "zero-poll collector starts");
    Require(WaitUntil([&] { return collector->GetHealthSnapshot().state == "running"; }),
            "zero-poll collector samples all tables");
    const unsigned before = calls.load();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    Require(calls.load() - before < 1000, "zero poll is clamped and does not busy-spin");
    collector->Stop();
    const auto historical = collector->GetHealthSnapshot().counters.at("tcp4.successful_snapshots");
    block.store(true);
    Require(collector->Start(&bus), "stopped collector can restart");
    Require(WaitUntil([&] { return entered.load(); }), "restarted worker entered sampling seam");
    const auto starting = collector->GetHealthSnapshot();
    Require(starting.running && starting.state == "starting" &&
            starting.counters.find("tcp4.available") == starting.counters.end() &&
            starting.counters.find("tcp4.listeners") == starting.counters.end(),
            "restart does not present stale current table availability or listener count");
    Require(starting.counters.at("tcp4.successful_snapshots") >= historical,
            "restart preserves lifetime success counters");
    release.store(true);
    Require(WaitUntil([&] { return collector->GetHealthSnapshot().state == "running"; }),
            "restart fresh baseline completes");
    collector->Stop();
    Require(collector->GetHealthSnapshot().eventsPushed == 0,
            "restart seeds all domains without an event burst");
}

void NativeTableBounds() {
    const Domain domains[] = {Domain::Tcp4, Domain::Udp4, Domain::Tcp6, Domain::Udp6};
    for (const Domain domain : domains) {
        size_t calls = 0;
        auto snapshot = edr::QueryListenerCollectorTable(domain,
            [&](Domain observed, void*, uint32_t* bytes) -> uint32_t {
                Require(observed == domain, "raw query keeps its requested domain");
                ++calls;
                *bytes += 128;
                return ERROR_INSUFFICIENT_BUFFER;
            });
        Require(!snapshot.complete && snapshot.listeners.empty() &&
                calls == 1 + edr::kListenerTableMaxDataCalls,
                "continually resizing table fails within five total calls");
        calls = 0;
        snapshot = edr::QueryListenerCollectorTable(domain,
            [&](Domain, void*, uint32_t* bytes) -> uint32_t {
                ++calls; *bytes = edr::kListenerTableMaxBytes + 1;
                return ERROR_INSUFFICIENT_BUFFER;
            });
        Require(!snapshot.complete && calls == 1, "oversized probe rejected before allocation");
        calls = 0;
        snapshot = edr::QueryListenerCollectorTable(domain,
            [&](Domain, void* buffer, uint32_t* bytes) -> uint32_t {
                ++calls; *bytes = 128;
                (void)buffer;
                return ERROR_INSUFFICIENT_BUFFER;
            });
        Require(!snapshot.complete && calls == 2, "non-growing retry rejected");
        snapshot = edr::QueryListenerCollectorTable(domain,
            [](Domain, void* buffer, uint32_t* bytes) -> uint32_t {
                if (!buffer) { *bytes = 4; return ERROR_INSUFFICIENT_BUFFER; }
                DWORD count = 1;
                std::memcpy(buffer, &count, 4);
                return NO_ERROR;
            });
        Require(!snapshot.complete && snapshot.listeners.empty(), "row count outside actual buffer rejected");
        snapshot = edr::QueryListenerCollectorTable(domain,
            [](Domain, void* buffer, uint32_t* bytes) -> uint32_t {
                if (!buffer) { *bytes = 128; return ERROR_INSUFFICIENT_BUFFER; }
                DWORD count = static_cast<DWORD>(edr::kListenerTableMaxEntries + 1);
                std::memcpy(buffer, &count, 4);
                return NO_ERROR;
            });
        Require(!snapshot.complete, "row budget rejected");
        snapshot = edr::QueryListenerCollectorTable(domain,
            [](Domain, void* buffer, uint32_t* bytes) -> uint32_t {
                if (!buffer) { *bytes = 4; return ERROR_INSUFFICIENT_BUFFER; }
                *bytes = 5;
                return NO_ERROR;
            });
        Require(!snapshot.complete, "reported success larger than allocation rejected");
        snapshot = edr::QueryListenerCollectorTable(domain,
            [](Domain, void*, uint32_t* bytes) -> uint32_t { *bytes = 0; return NO_ERROR; });
        Require(!snapshot.complete, "zero-byte success does not establish an empty table");
        snapshot = edr::QueryListenerCollectorTable(domain,
            [](Domain, void* buffer, uint32_t* bytes) -> uint32_t {
                if (!buffer) { *bytes = 4; return ERROR_INSUFFICIENT_BUFFER; }
                DWORD count = 0;
                std::memcpy(buffer, &count, 4);
                return NO_ERROR;
            });
        Require(snapshot.complete && snapshot.listeners.empty(), "actual empty table header is complete");
        snapshot = edr::QueryListenerCollectorTable(domain,
            [](Domain, void* buffer, uint32_t* bytes) -> uint32_t {
                if (!buffer) { *bytes = 128; return ERROR_INSUFFICIENT_BUFFER; }
                return ERROR_ACCESS_DENIED;
            });
        Require(!snapshot.complete, "API failure is incomplete");
    }
}
void NativeResizeAndIpv6Row() {
    size_t calls = 0;
    const uint32_t needed = static_cast<uint32_t>(offsetof(MIB_TCP6TABLE_OWNER_PID, table) +
                                               sizeof(MIB_TCP6ROW_OWNER_PID));
    const auto snapshot = edr::QueryListenerCollectorTable(Domain::Tcp6,
        [&](Domain, void* buffer, uint32_t* bytes) -> uint32_t {
            ++calls;
            if (!buffer) { *bytes = 4; return ERROR_INSUFFICIENT_BUFFER; }
            if (*bytes < needed) { *bytes = needed; return ERROR_INSUFFICIENT_BUFFER; }
            const DWORD count = 1;
            MIB_TCP6ROW_OWNER_PID row{};
            row.ucLocalAddr[0] = 0xfe;
            row.ucLocalAddr[1] = 0x80;
            row.ucLocalAddr[15] = 1;
            row.dwLocalScopeId = 12;
            row.dwLocalPort = htons(12345);
            std::memcpy(buffer, &count, sizeof(count));
            std::memcpy(static_cast<uint8_t*>(buffer) + offsetof(MIB_TCP6TABLE_OWNER_PID, table),
                        &row, sizeof(row));
            *bytes = needed;
            return NO_ERROR;
        });
    Require(snapshot.complete && snapshot.listeners.size() == 1 && calls == 3,
            "bounded resizing can succeed with one IPv6 row");
    Require(snapshot.listeners[0].scopeId == 12 && snapshot.listeners[0].localPort == 12345 &&
            snapshot.listeners[0].address[15] == 1, "IPv6 row preserves address scope and port");
}

void NativeDuplicateAndRetainedRowBudget() {
    const uint32_t needed = static_cast<uint32_t>(offsetof(MIB_UDP6TABLE_OWNER_PID, table) +
                                                2 * sizeof(MIB_UDP6ROW_OWNER_PID));
    const auto duplicate = edr::QueryListenerCollectorTable(Domain::Udp6,
        [&](Domain, void* buffer, uint32_t* bytes) -> uint32_t {
            if (!buffer) { *bytes = needed; return ERROR_INSUFFICIENT_BUFFER; }
            const DWORD count = 2;
            std::memcpy(buffer, &count, sizeof(count));
            *bytes = needed;
            return NO_ERROR;
        });
    Require(duplicate.complete && duplicate.listeners.size() == 1,
            "identical native endpoint rows collapse before process enrichment");
    const auto overRetained = edr::QueryListenerCollectorTable(Domain::Udp4,
        [](Domain, void* buffer, uint32_t* bytes) -> uint32_t {
            const uint32_t size = static_cast<uint32_t>(offsetof(MIB_UDPTABLE_OWNER_PID, table) +
                edr::kListenerTableMaxEntries * sizeof(MIB_UDPROW_OWNER_PID));
            if (!buffer) { *bytes = size; return ERROR_INSUFFICIENT_BUFFER; }
            const DWORD count = static_cast<DWORD>(edr::kListenerTableMaxEntries);
            std::memcpy(buffer, &count, sizeof(count));
            *bytes = size;
            return NO_ERROR;
        });
    Require(!overRetained.complete && overRetained.listeners.empty(),
            "native retained fixed-entry charge rejects rows before vector allocation");
}

void NativeIpv6LoopbackProbe() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        std::puts("LIMITED: Winsock unavailable; native IPv6 loopback probe skipped");
        return;
    }
    const SOCKET tcp = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    const SOCKET udp = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (tcp == INVALID_SOCKET || udp == INVALID_SOCKET) {
        if (tcp != INVALID_SOCKET) closesocket(tcp);
        if (udp != INVALID_SOCKET) closesocket(udp);
        WSACleanup();
        std::puts("LIMITED: IPv6 sockets unavailable; native loopback probe skipped");
        return;
    }
    sockaddr_in6 address{};
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_loopback;
    if (bind(tcp, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(tcp, 1) != 0 || bind(udp, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        std::printf("LIMITED: IPv6 loopback bind/listen failed (%d); probe skipped\n", WSAGetLastError());
        closesocket(tcp); closesocket(udp); WSACleanup();
        return;
    }
    int length = sizeof(address);
    Require(getsockname(tcp, reinterpret_cast<sockaddr*>(&address), &length) == 0,
            "TCP6 random loopback port resolved");
    const uint16_t tcpPort = ntohs(address.sin6_port);
    length = sizeof(address);
    Require(getsockname(udp, reinterpret_cast<sockaddr*>(&address), &length) == 0,
            "UDP6 random loopback port resolved");
    const uint16_t udpPort = ntohs(address.sin6_port);
    const auto tcpSnapshot = edr::QueryListenerCollectorTable(Domain::Tcp6);
    const auto udpSnapshot = edr::QueryListenerCollectorTable(Domain::Udp6);
    Require(tcpSnapshot.complete && udpSnapshot.complete, "native IPv6 API tables are complete");
    bool haveTcp = false, haveUdp = false;
    for (const auto& entry : tcpSnapshot.listeners)
        if (entry.localPort == tcpPort && entry.pid == GetCurrentProcessId() && entry.address[15] == 1) {
            haveTcp = true;
            Require(!entry.imagePath.empty() && entry.processStartTime100ns != 0,
                    "native same-handle image+process birth attributed");
        }
    for (const auto& entry : udpSnapshot.listeners)
        if (entry.localPort == udpPort && entry.pid == GetCurrentProcessId() && entry.address[15] == 1)
            haveUdp = true;
    Require(haveTcp && haveUdp, "real TCP6 and UDP6 ::1 rows are present without external traffic");
    closesocket(tcp); closesocket(udp); WSACleanup();
    std::puts("PASS: native TCP6/UDP6 ::1 bind/listen and read-only tables");
}
} // namespace
int main() {
    InitialHealth();
    SamePidDifferentCreationTimeReplacesInstance();
    UnknownContextDoesNotInventListenerChanges();
    UnknownContextPreservesReliableHistoryAndFirstKnownSeeds();
    RestartResetsCurrentDomainsAndZeroPollWaits();
    FailedDomainIsIsolatedAndRecoveryIsQuiet();
    FirstFailureThenSuccessSeedsEachDomain();
    AddressFamiliesScopesAndProtocolsAreDistinct();
    RemovalUsesSavedInstanceAndRejectsBareImage();
    OverflowAndStopHealth();
    WorkerExceptionHealth();
    InvalidMetadataAndDuplicateSnapshotsPreserveBaseline();
    IdenticalDuplicateSnapshotRowsCollapse();
    RetainedMemoryBudgetRejectsLargeContextSnapshot();
    NativeTableBounds();
    NativeResizeAndIpv6Row();
    NativeDuplicateAndRetainedRowBudget();
    NativeIpv6LoopbackProbe();
    std::puts("listener collector tests passed (18 groups)");
}
