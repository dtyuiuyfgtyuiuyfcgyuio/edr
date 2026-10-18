#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"
#include "collector_hook_scan.h"

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        throw std::runtime_error(message);
    }
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

bool WaitUntil(const std::function<bool()>& predicate) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(4);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return predicate();
}

edr::HookScanRootSnapshot Complete(
        std::map<std::string, edr::HookScanTargetSnapshot> targets) {
    edr::HookScanRootSnapshot root;
    root.status = edr::HookScanSnapshotStatus::Complete;
    root.targets = std::move(targets);
    return root;
}

edr::HookScanTargetSnapshot Target(edr::HookScanSnapshotStatus status,
                                   std::string key = {}, std::string value = {}) {
    edr::HookScanTargetSnapshot target;
    target.status = status;
    if (!key.empty()) target.values.emplace(std::move(key), std::move(value));
    return target;
}

edr::HookScanSnapshot Snapshot(
        edr::HookScanRootSnapshot ifeo,
        edr::HookScanRootSnapshot com) {
    edr::HookScanSnapshot snapshot;
    snapshot.ifeo = std::move(ifeo);
    snapshot.hkcuCom = std::move(com);
    return snapshot;
}

class ScopedRegistryKey {
public:
    ~ScopedRegistryKey() { Close(); }
    HKEY* Out() {
        Close();
        return &m_key;
    }
    HKEY Get() const { return m_key; }
    void Close() {
        if (m_key != nullptr) {
            RegCloseKey(m_key);
            m_key = nullptr;
        }
    }
private:
    HKEY m_key = nullptr;
};

class PrivateRegistryTree {
public:
    PrivateRegistryTree() {
        static std::atomic<uint64_t> next{0};
        m_suffix = std::to_string(GetCurrentProcessId()) + "_" +
            std::to_string(GetTickCount64()) + "_" +
            std::to_string(next.fetch_add(1));
        m_path = L"Software\\CodexHookScanTest_";
        m_path.append(m_suffix.begin(), m_suffix.end());
        HKEY key = nullptr;
        DWORD disposition = 0;
        const LONG status = RegCreateKeyExW(HKEY_CURRENT_USER, m_path.c_str(),
            0, nullptr, 0, KEY_READ | KEY_WRITE, nullptr, &key, &disposition);
        if (key != nullptr) RegCloseKey(key);
        m_owned = status == ERROR_SUCCESS &&
                  disposition == REG_CREATED_NEW_KEY;
    }
    ~PrivateRegistryTree() {
        if (m_owned) RegDeleteTreeW(HKEY_CURRENT_USER, m_path.c_str());
    }
    bool OwnsRoot() const { return m_owned; }
    std::wstring Path(const wchar_t* suffix) const {
        std::wstring result = m_path;
        if (suffix != nullptr && *suffix != L'\\') result.push_back(L'\\');
        if (suffix != nullptr) result.append(suffix);
        return result;
    }
    std::string Prefix(const char* suffix) const {
        std::string result = "HKCU\\Software\\CodexHookScanTest_" + m_suffix;
        if (suffix != nullptr && *suffix != '\\') result.push_back('\\');
        if (suffix != nullptr) result.append(suffix);
        return result;
    }
private:
    std::wstring m_path;
    std::string m_suffix;
    bool m_owned = false;
};

void FailedTargetRetainsBaselineAndDoesNotBlockOtherRoot() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(32);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        const unsigned call = calls.fetch_add(1);
        if (call == 0) {
            return Snapshot(
                Complete({{"image.exe", Target(
                    edr::HookScanSnapshotStatus::Complete,
                    "HKLM\\IFEO\\image.exe\\Debugger", "old")}}),
                Complete({{"{clsid}", Target(
                    edr::HookScanSnapshotStatus::Complete,
                    "HKCU\\CLSID\\{clsid}\\InprocServer32", "com-old")}}));
        }
        if (call == 1) {
            return Snapshot(
                Complete({{"image.exe", Target(
                    edr::HookScanSnapshotStatus::Failed,
                    "HKLM\\IFEO\\image.exe\\Debugger", "partial")}}),
                Complete({{"{clsid}", Target(
                    edr::HookScanSnapshotStatus::Complete,
                    "HKCU\\CLSID\\{clsid}\\InprocServer32", "com-new")}}));
        }
        if (call == 2) return Snapshot(
            Complete({{"image.exe", Target(
                edr::HookScanSnapshotStatus::Complete,
                "HKLM\\IFEO\\image.exe\\Debugger", "old")}}),
            Complete({{"{clsid}", Target(
                edr::HookScanSnapshotStatus::Complete,
                "HKCU\\CLSID\\{clsid}\\InprocServer32", "com-new")}}));
        return Snapshot(
            Complete({{"image.exe", Target(
                edr::HookScanSnapshotStatus::Complete,
                "HKLM\\IFEO\\image.exe\\Debugger", "later-change")}}),
            Complete({{"{clsid}", Target(
                edr::HookScanSnapshotStatus::Complete,
                "HKCU\\CLSID\\{clsid}\\InprocServer32", "com-new")}}));
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "injected hook scan starts");
    Require(WaitUntil([&] { return calls.load() >= 4; }),
            "scanner completes failure, recovery, quiet, and changed passes");
    Require(WaitUntil([&] { return recorder.Events().size() >= 2; }),
            "later real IFEO change is emitted after recovery");
    const auto events = recorder.Events();
    Require(events.size() == 2 &&
            events[0].fields.at(edr::field::kRegKey) ==
                "HKCU\\CLSID\\{clsid}\\InprocServer32" &&
            events[0].fields.at(edr::field::kRegValue) == "com-new" &&
            events[1].fields.at(edr::field::kRegKey) ==
                "HKLM\\IFEO\\image.exe\\Debugger" &&
            events[1].fields.at(edr::field::kRegValue) == "later-change",
            "other root commits during failure, recovery stays quiet, later IFEO write is detected");
    const auto health = collector->GetHealthSnapshot();
    Require(health.counters.at("targets_failed_current") == 0,
            "recovered target clears current failure health");
    Require(health.lastSuccess100ns != 0,
            "successful target snapshots publish last-success time");
    collector->Stop();
    bus.Stop();
}

void InitialFailureDoesNotSeedAnEmptyBaseline() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        if (calls.fetch_add(1) == 0) {
            return Snapshot(
                {edr::HookScanSnapshotStatus::Failed, {}},
                {edr::HookScanSnapshotStatus::Failed, {}});
        }
        return Snapshot(
            Complete({{"new.exe", Target(
                edr::HookScanSnapshotStatus::Complete,
                "HKLM\\IFEO\\new.exe\\Debugger", "new-value")}}),
            {edr::HookScanSnapshotStatus::Missing, {}});
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "first-failure fixture starts");
    Require(WaitUntil([&] { return calls.load() >= 2; }),
            "successful sample follows first-pass failures");
    Require(recorder.Events().empty(),
            "first complete target sample seeds without a false REG_WRITE");
    Require(WaitUntil([&] {
        return collector->GetHealthSnapshot().lastSuccess100ns != 0;
    }), "health records successful recovery after initial failure");
    collector->Stop();
    bus.Stop();
}

void MissingRootIsAConclusiveEmptySnapshot() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        if (calls.fetch_add(1) == 0) {
            return Snapshot(
                Complete({{"gone.exe", Target(
                    edr::HookScanSnapshotStatus::Complete,
                    "HKLM\\IFEO\\gone.exe\\Debugger", "old")}}),
                {edr::HookScanSnapshotStatus::Missing, {}});
        }
        return Snapshot({edr::HookScanSnapshotStatus::Missing, {}},
                        {edr::HookScanSnapshotStatus::Missing, {}});
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "missing-root fixture starts");
    Require(WaitUntil([&] { return calls.load() >= 2; }),
            "missing root is sampled after seed");
    Require(WaitUntil([&] {
        const auto health = collector->GetHealthSnapshot();
        return health.counters.at("roots_missing_current") == 2;
    }), "current missing-root state is visible independently of successful reads");
    Require(collector->GetHealthSnapshot().counters.at("source_available") == 0,
            "missing roots cannot be masked by the other domain success");
    Require(recorder.Events().empty(),
            "confirmed missing roots preserve REG_WRITE-only event contract");
    collector->Stop();
    bus.Stop();
}

void NativeComReadUsesOnlyPrivateHkcuFixture() {
    PrivateRegistryTree tree;
    Require(tree.OwnsRoot(), "unique private HKCU COM root is newly created");
    const std::wstring path = tree.Path(L"CLSID\\{test}\\LocalServer32");
    ScopedRegistryKey key;
    DWORD disposition = 0;
    Require(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0,
            KEY_READ | KEY_WRITE, nullptr, key.Out(), &disposition) == ERROR_SUCCESS,
            "private HKCU test key is created");
    const wchar_t value[] = L"C:\\fixture\\com-server.exe";
    Require(RegSetValueExW(key.Get(), nullptr, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(value), sizeof(value)) == ERROR_SUCCESS,
            "private HKCU default value is written");
    key.Close();

    const std::wstring rootPath = tree.Path(L"CLSID");
    const std::string rootPrefix = tree.Prefix("CLSID");
    const auto result = edr::ReadHookScanRegistryRoot(
        HKEY_CURRENT_USER, rootPath, rootPrefix,
        edr::HookScanSurface::HkcuCom, 32);
    Require(result.status == edr::HookScanSnapshotStatus::Complete &&
            result.targets.size() == 1,
            "native COM subtree is read as one complete bounded target");
    const auto& values = result.targets.begin()->second.values;
    Require(values.size() == 1 && values.begin()->second ==
            "C:\\fixture\\com-server.exe",
            "native COM default value survives strict UTF-16 conversion");
}

void NativeIfeoReadUsesNamedDebuggerValue() {
    PrivateRegistryTree tree;
    Require(tree.OwnsRoot(), "unique private HKCU IFEO root is newly created");
    const std::wstring path = tree.Path(L"IFEO\\sample.exe");
    const std::wstring rootPath = tree.Path(L"IFEO");
    const std::string rootPrefix = tree.Prefix("IFEO");
    ScopedRegistryKey key;
    DWORD disposition = 0;
    Require(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0,
            KEY_READ | KEY_WRITE, nullptr, key.Out(), &disposition) == ERROR_SUCCESS,
            "private HKCU IFEO-shaped test key is created");
    const wchar_t lure[] = L"default-value-is-not-the-debugger";
    const wchar_t debugger[] = L"C:\\fixture\\debugger.exe";
    Require(RegSetValueExW(key.Get(), nullptr, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(lure), sizeof(lure)) == ERROR_SUCCESS,
            "private IFEO default-value lure is written");
    Require(RegSetValueExW(key.Get(), L"Debugger", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(debugger), sizeof(debugger)) == ERROR_SUCCESS,
            "named IFEO Debugger value is written");
    key.Close();

    auto result = edr::ReadHookScanRegistryRoot(
        HKEY_CURRENT_USER, rootPath, rootPrefix,
        edr::HookScanSurface::Ifeo, 16);
    Require(result.status == edr::HookScanSnapshotStatus::Complete &&
            result.targets.size() == 1,
            "IFEO-shaped private tree returns one complete image target");
    const auto& values = result.targets.begin()->second.values;
    Require(values.size() == 1 && values.begin()->first ==
            rootPrefix + "\\sample.exe\\Debugger" &&
            values.begin()->second == "C:\\fixture\\debugger.exe",
            "scanner reports the named Debugger data and ignores the default lure");

    Require(RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0,
                          KEY_READ | KEY_WRITE, key.Out()) == ERROR_SUCCESS,
            "private IFEO test key can be reopened");
    Require(RegDeleteValueW(key.Get(), L"Debugger") == ERROR_SUCCESS,
            "named Debugger is removed while default lure remains");
    key.Close();
    result = edr::ReadHookScanRegistryRoot(
        HKEY_CURRENT_USER, rootPath, rootPrefix,
        edr::HookScanSurface::Ifeo, 16);
    Require(result.status == edr::HookScanSnapshotStatus::Complete &&
            result.targets.begin()->second.values.empty(),
            "default-value lure without named Debugger is quiet");

    Require(RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0,
                          KEY_READ | KEY_WRITE, key.Out()) == ERROR_SUCCESS,
            "private IFEO test key can be reopened for invalid type case");
    const BYTE binary[] = {0x41, 0x42};
    Require(RegSetValueExW(key.Get(), L"Debugger", 0, REG_BINARY, binary,
                           sizeof(binary)) == ERROR_SUCCESS,
            "invalid named Debugger type is written");
    key.Close();
    result = edr::ReadHookScanRegistryRoot(
        HKEY_CURRENT_USER, rootPath, rootPrefix,
        edr::HookScanSurface::Ifeo, 16);
    Require(result.status == edr::HookScanSnapshotStatus::Complete &&
            result.targets.begin()->second.status ==
                edr::HookScanSnapshotStatus::Failed,
            "wrong-type named Debugger fails the target snapshot closed");

    Require(RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0,
                          KEY_READ | KEY_WRITE, key.Out()) == ERROR_SUCCESS,
            "private IFEO test key can be reopened for payload limit case");
    std::vector<wchar_t> oversized(33001, L'x');
    Require(RegSetValueExW(key.Get(), L"Debugger", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(oversized.data()),
            static_cast<DWORD>(oversized.size() * sizeof(wchar_t))) == ERROR_SUCCESS,
            "oversized named Debugger payload is written");
    key.Close();
    result = edr::ReadHookScanRegistryRoot(
        HKEY_CURRENT_USER, rootPath, rootPrefix,
        edr::HookScanSurface::Ifeo, 16);
    Require(result.status == edr::HookScanSnapshotStatus::Complete &&
            result.targets.begin()->second.status ==
                edr::HookScanSnapshotStatus::Failed,
            "oversized target payload is rejected without a partial snapshot");

    Require(RegCreateKeyExW(HKEY_CURRENT_USER,
            tree.Path(L"IFEO\\other.exe").c_str(), 0, nullptr, 0,
            KEY_READ | KEY_WRITE, nullptr, key.Out(), &disposition) == ERROR_SUCCESS,
            "second private IFEO target is created for target-count limit");
    key.Close();
    result = edr::ReadHookScanRegistryRoot(
        HKEY_CURRENT_USER, rootPath, rootPrefix,
        edr::HookScanSurface::Ifeo, 1);
    Require(result.status == edr::HookScanSnapshotStatus::Failed,
            "target count beyond configured limit rejects whole root snapshot");

    const std::wstring longEmptyName(200, L'x');
    const std::wstring longEmptyPath = tree.Path(
        (std::wstring(L"IFEO\\") + longEmptyName).c_str());
    Require(RegCreateKeyExW(HKEY_CURRENT_USER, longEmptyPath.c_str(), 0, nullptr,
            0, KEY_READ | KEY_WRITE, nullptr, key.Out(), &disposition) == ERROR_SUCCESS,
            "long empty private IFEO target is created");
    key.Close();
    edr::HookScanReadLimits tightRootBudget;
    tightRootBudget.maxRootPayloadBytes = 500;
    result = edr::ReadHookScanRegistryRoot(
        HKEY_CURRENT_USER, rootPath, rootPrefix,
        edr::HookScanSurface::Ifeo, 16, tightRootBudget);
    Require(result.status == edr::HookScanSnapshotStatus::Failed,
            "root charge counts long names and nodes even for targets with no hook value");
}

void InitialTargetLocalRejectsRecoverQuietlyThenDetectChanges() {
    PrivateRegistryTree tree;
    Require(tree.OwnsRoot(), "UTF-8 expansion fixture owns a unique HKCU root");
    const std::wstring rawValuePath = tree.Path(L"IFEO\\wide.exe");
    const std::wstring rootPath = tree.Path(L"IFEO");
    const std::string rootPrefix = tree.Prefix("IFEO");
    ScopedRegistryKey key;
    DWORD disposition = 0;
    Require(RegCreateKeyExW(HKEY_CURRENT_USER, rawValuePath.c_str(), 0,
            nullptr, 0, KEY_READ | KEY_WRITE, nullptr, key.Out(),
            &disposition) == ERROR_SUCCESS,
            "UTF-8 expansion fixture target is created");
    std::vector<wchar_t> wideValue(21847, static_cast<wchar_t>(0x0800));
    wideValue.back() = L'\0';
    Require((wideValue.size() * sizeof(wchar_t)) <= 64 * 1024 &&
            RegSetValueExW(key.Get(), L"Debugger", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(wideValue.data()),
                static_cast<DWORD>(wideValue.size() * sizeof(wchar_t))) ==
                ERROR_SUCCESS,
            "BMP registry payload fits raw-byte limit while UTF-8 expansion exceeds collector limit");
    key.Close();

    const auto native = edr::ReadHookScanRegistryRoot(
        HKEY_CURRENT_USER, rootPath, rootPrefix,
        edr::HookScanSurface::Ifeo, 16);
    Require(native.status == edr::HookScanSnapshotStatus::Complete &&
            native.targets.at("wide.exe").status ==
                edr::HookScanSnapshotStatus::Complete &&
            native.targets.at("wide.exe").values.begin()->second.size() >
                64 * 1024,
            "native scanner accepts bounded raw UTF-16 and returns expanded UTF-8 value");

    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        const unsigned call = calls.fetch_add(1);
        if (call == 0) {
            auto initial = native;
            auto& extra = initial.targets["extra.exe"];
            extra.status = edr::HookScanSnapshotStatus::Complete;
            extra.values = {{"value-a", "a"}, {"value-b", "b"},
                            {"value-c", "c"}};
            return Snapshot(std::move(initial),
                {edr::HookScanSnapshotStatus::Missing, {}});
        }
        const std::string wideKey = rootPrefix + "\\wide.exe\\Debugger";
        const std::string extraKey = rootPrefix + "\\extra.exe\\Debugger";
        const std::string phase = call == 1 ? "first-valid" : "later-change";
        return Snapshot(Complete({
            {"extra.exe", Target(edr::HookScanSnapshotStatus::Complete,
                                  extraKey, phase)},
            {"wide.exe", Target(edr::HookScanSnapshotStatus::Complete,
                                 wideKey, phase)},
        }), {edr::HookScanSnapshotStatus::Missing, {}});
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "target-local reject recovery fixture starts");
    Require(WaitUntil([&] {
        return calls.load() >= 2 &&
            collector->GetHealthSnapshot().counters.at("targets_failed_current") == 0;
    }),
            "initial rejects and first valid recovery pass are committed");
    Require(recorder.Events().empty(),
            "initial target-local rejects recover quietly on first valid read");
    Require(WaitUntil([&] {
        return calls.load() >= 4 && recorder.Events().size() == 2;
    }), "later actual changes on both recovered targets emit REG_WRITE");
    const auto events = recorder.Events();
    Require(events[0].fields.at(edr::field::kRegValue) == "later-change" &&
            events[1].fields.at(edr::field::kRegValue) == "later-change",
            "post-recovery changes, rather than first valid values, are emitted");
    collector->Stop();
    bus.Stop();
}

void FatalQueryStopRestartAndZeroPollAreBounded() {
    edr::EventBus bus(8);
    auto empty = [] {
        return Snapshot(Complete({}), Complete({}));
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(0, 16, empty));
    Require(collector->Start(&bus), "zero-poll collector starts");
    Require(WaitUntil([&] {
        return collector->GetHealthSnapshot().lastSuccess100ns != 0;
    }), "zero-poll setting still takes its initial snapshot");
    const auto callsBeforeStop = collector->GetHealthSnapshot().counters.at(
        "successful_snapshots");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    Require(collector->GetHealthSnapshot().counters.at("successful_snapshots") ==
            callsBeforeStop,
            "zero poll uses the safe default interval instead of spinning");
    collector->Stop();
    Require(collector->GetHealthSnapshot().state == "stopped",
            "explicit stop publishes stopped health");
    Require(collector->Start(&bus), "stopped worker can restart");
    Require(WaitUntil([&] {
        return collector->GetHealthSnapshot().counters.at("successful_snapshots") >
               callsBeforeStop;
    }), "restarted worker takes a fresh seed snapshot");
    collector->Stop();

    std::atomic<bool> queryEntered{false};
    std::atomic<bool> releaseQuery{false};
    std::unique_ptr<edr::ICollector> starting(edr::CreateHookScanCollector(
        1, 16, [&] {
            queryEntered.store(true);
            while (!releaseQuery.load()) Sleep(1);
            return empty();
        }));
    Require(starting->Start(&bus), "starting-health fixture starts");
    Require(WaitUntil([&] { return queryEntered.load(); }),
            "worker reaches its deliberately blocked first query");
    auto startingHealth = starting->GetHealthSnapshot();
    Require(startingHealth.state == "starting" &&
            startingHealth.counters.at("targets_pending_current") == 1 &&
            startingHealth.counters.at("source_available") == 0,
            "restart reports current pending state until this run completes a snapshot");
    releaseQuery.store(true);
    Require(WaitUntil([&] {
        return starting->GetHealthSnapshot().counters.at("targets_pending_current") == 0;
    }), "pending current state clears when the new run finishes");
    starting->Stop();

    std::unique_ptr<edr::ICollector> fatal(edr::CreateHookScanCollector(
        1, 16, []() -> edr::HookScanSnapshot { throw std::runtime_error("query"); }));
    Require(fatal->Start(&bus), "fatal query fixture starts");
    Require(WaitUntil([&] {
        const auto health = fatal->GetHealthSnapshot();
        return !health.running && health.state == "source_error";
    }), "uncaught query failure terminates worker with source error state");
    fatal->Stop();
}

void BusOverflowIsCountedWithoutLosingSubmittedEvents() {
    std::atomic<unsigned> calls{0};
    auto query = [&] {
        const bool changed = calls.fetch_add(1) != 0;
        return Snapshot(
            Complete({
                {"a.exe", Target(edr::HookScanSnapshotStatus::Complete,
                    "HKLM\\IFEO\\a.exe\\Debugger", changed ? "new-a" : "old-a")},
                {"b.exe", Target(edr::HookScanSnapshotStatus::Complete,
                    "HKLM\\IFEO\\b.exe\\Debugger", changed ? "new-b" : "old-b")},
            }),
            {edr::HookScanSnapshotStatus::Missing, {}});
    };
    edr::EventBus fullBus(0);
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&fullBus), "overflow fixture starts");
    Require(WaitUntil([&] {
        const auto health = collector->GetHealthSnapshot();
        return health.busDropped == 2 && health.eventsPushed == 2;
    }), "both attempted writes are counted when the event queue rejects them");
    collector->Stop();
}

void MalformedRootCannotErasePriorTargets() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        const unsigned call = calls.fetch_add(1);
        if (call == 0) {
            return Snapshot(
                Complete({{"keep.exe", Target(
                    edr::HookScanSnapshotStatus::Complete,
                    "HKLM\\IFEO\\keep.exe\\Debugger",
                    "same")}}),
                {edr::HookScanSnapshotStatus::Missing, {}});
        }
        if (call >= 2) {
            return Snapshot(
                Complete({{"keep.exe", Target(
                    edr::HookScanSnapshotStatus::Complete,
                    "HKLM\\IFEO\\keep.exe\\Debugger", "changed")}}),
                {edr::HookScanSnapshotStatus::Missing, {}});
        }
        auto malformed = Complete({
            {std::string("invalid\0target", 14), Target(
                edr::HookScanSnapshotStatus::Complete,
                "HKLM\\IFEO\\invalid\\Debugger", "partial")}});
        return Snapshot(std::move(malformed),
                        {edr::HookScanSnapshotStatus::Missing, {}});
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "malformed-root fixture starts");
    Require(WaitUntil([&] { return calls.load() >= 4; }),
            "valid recovery and later change follow the malformed root");
    Require(WaitUntil([&] { return recorder.Events().size() == 1; }),
            "later real update remains detectable after rejected root");
    const auto events = recorder.Events();
    Require(events.size() == 1 &&
            events[0].fields.at(edr::field::kRegValue) == "changed",
            "malformed root does not erase the retained baseline or emit partial data");
    collector->Stop();
    bus.Stop();
}

void RetainedBudgetCountsEmptyNamesAndScalesLinearly() {
    const std::string shortName = "ifeo\\x.exe";
    const std::string longName = "ifeo\\" + std::string(12000, 'x');
    const size_t shortCharge = edr::EstimateHookScanTargetCharge(shortName, {});
    const size_t longCharge = edr::EstimateHookScanTargetCharge(longName, {});
    Require(longCharge > shortCharge && longCharge >= longName.size(),
            "empty target names contribute to conservative retained charge");

    edr::HookScanBudgetLimits limits;
    limits.maxTargets = 20000;
    limits.maxValues = 20000;
    limits.maxBytes = longCharge + 1;
    edr::HookScanRetainedBudget boundary(limits);
    Require(boundary.Set(longName, {}),
            "empty target at the computed retained budget fits");
    Require(!boundary.Set(longName + "y", {}),
            "one more long empty target exceeds retained budget");

    edr::HookScanRetainedBudget many({20000, 20000, 16 * 1024 * 1024});
    constexpr size_t kTargets = 10000;
    for (size_t i = 0; i < kTargets; ++i)
        Require(many.Set("ifeo\\target" + std::to_string(i), {}),
                "bounded many-target baseline accepts each empty target");
    Require(many.CandidateItemsExamined() == kTargets,
            "incremental production budget examines each target once instead of rescanning baseline");
    for (size_t i = 0; i < kTargets; ++i)
        Require(many.Set("ifeo\\target" + std::to_string(i),
                         {{"key", "value"}}),
                "incremental replacement remains within retained limits");
    Require(many.CandidateItemsExamined() == kTargets * 3,
            "replacement accounting work grows with changed target contents only");
}

void CompleteEmptyIfeoRootThenNewTargetEmits() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        if (calls.fetch_add(1) == 0)
            return Snapshot(Complete({}), {edr::HookScanSnapshotStatus::Missing, {}});
        return Snapshot(Complete({{"new.exe", Target(
            edr::HookScanSnapshotStatus::Complete,
            "HKLM\\IFEO\\new.exe\\Debugger", "debugger.exe")}}),
            {edr::HookScanSnapshotStatus::Missing, {}});
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "empty-IFEO-root fixture starts");
    Require(WaitUntil([&] { return recorder.Events().size() == 1; }),
            "IFEO target added after a complete empty root emits REG_WRITE");
    const auto events = recorder.Events();
    Require(events[0].fields.at(edr::field::kRegKey) ==
                "HKLM\\IFEO\\new.exe\\Debugger" &&
            events[0].fields.at(edr::field::kRegValue) == "debugger.exe",
            "new IFEO event keeps the established key and value shape");
    collector->Stop();
    bus.Stop();
}

void InitiallyMissingRootThenTargetEmits() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        if (calls.fetch_add(1) == 0)
            return Snapshot({edr::HookScanSnapshotStatus::Missing, {}},
                {edr::HookScanSnapshotStatus::Missing, {}});
        return Snapshot(Complete({{"later.exe", Target(
            edr::HookScanSnapshotStatus::Complete,
            "HKLM\\IFEO\\later.exe\\Debugger", "debugger.exe")}}),
            {edr::HookScanSnapshotStatus::Missing, {}});
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "initially-missing-root fixture starts");
    Require(WaitUntil([&] { return recorder.Events().size() == 1; }),
            "target added after reliable missing root emits REG_WRITE");
    collector->Stop();
    bus.Stop();
}

void TargetSurfacedDuringRootFailureDiffsAfterRecovery() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        const unsigned call = calls.fetch_add(1);
        if (call == 0)
            return Snapshot(Complete({}),
                {edr::HookScanSnapshotStatus::Missing, {}});
        if (call == 1)
            return Snapshot({edr::HookScanSnapshotStatus::Failed, {}},
                {edr::HookScanSnapshotStatus::Missing, {}});
        return Snapshot(Complete({{"during-outage.exe", Target(
            edr::HookScanSnapshotStatus::Complete,
            "HKLM\\IFEO\\during-outage.exe\\Debugger", "debugger.exe")}}),
            {edr::HookScanSnapshotStatus::Missing, {}});
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "root-outage fixture starts");
    Require(WaitUntil([&] { return recorder.Events().size() == 1; }),
            "target surfaced during root outage diffs against last reliable root");
    collector->Stop();
    bus.Stop();
}

void ObservedClsidRootThenNewComTargetEmits() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        if (calls.fetch_add(1) == 0)
            return Snapshot({edr::HookScanSnapshotStatus::Missing, {}},
                Complete({{"old-clsid", Target(edr::HookScanSnapshotStatus::Complete)}}));
        return Snapshot({edr::HookScanSnapshotStatus::Missing, {}},
            Complete({
                {"old-clsid", Target(edr::HookScanSnapshotStatus::Complete)},
                {"new-clsid", Target(edr::HookScanSnapshotStatus::Complete,
                    "HKCU\\CLSID\\new-clsid\\LocalServer32", "server.exe")},
            }));
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "observed-CLSID-root fixture starts");
    Require(WaitUntil([&] { return recorder.Events().size() == 1; }),
            "new COM target in an observed root emits REG_WRITE");
    const auto events = recorder.Events();
    Require(events[0].fields.at(edr::field::kRegKey) ==
                "HKCU\\CLSID\\new-clsid\\LocalServer32",
            "new COM event preserves the existing registry key shape");
    collector->Stop();
    bus.Stop();
}

void InitialChildFailureRecoverySeedsQuietlyThenDetectsChange() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        const unsigned call = calls.fetch_add(1);
        if (call == 0)
            return Snapshot(Complete({{"unknown.exe", Target(
                edr::HookScanSnapshotStatus::Failed)}}),
                {edr::HookScanSnapshotStatus::Missing, {}});
        return Snapshot(Complete({{"unknown.exe", Target(
            edr::HookScanSnapshotStatus::Complete,
            "HKLM\\IFEO\\unknown.exe\\Debugger",
            call == 1 ? "first-readable" : "later-change")}}),
            {edr::HookScanSnapshotStatus::Missing, {}});
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "initial-child-failure fixture starts");
    Require(WaitUntil([&] { return recorder.Events().size() == 1; }),
            "change after failed child recovery remains observable");
    const auto events = recorder.Events();
    Require(events[0].fields.at(edr::field::kRegValue) == "later-change",
            "first reliable child recovery seeds quietly before later change");
    collector->Stop();
    bus.Stop();
}

void DeletedTargetReaddedAfterReliableAbsenceEmits() {
    std::atomic<unsigned> calls{0};
    edr::EventBus bus(16);
    Recorder recorder;
    bus.Start(&recorder);
    auto query = [&] {
        const unsigned call = calls.fetch_add(1);
        if (call == 1)
            return Snapshot(Complete({}), {edr::HookScanSnapshotStatus::Missing, {}});
        return Snapshot(Complete({{"readded.exe", Target(
            edr::HookScanSnapshotStatus::Complete,
            "HKLM\\IFEO\\readded.exe\\Debugger", "debugger.exe")}}),
            {edr::HookScanSnapshotStatus::Missing, {}});
    };
    std::unique_ptr<edr::ICollector> collector(
        edr::CreateHookScanCollector(1, 16, query));
    Require(collector->Start(&bus), "delete-and-readd fixture starts");
    Require(WaitUntil([&] { return recorder.Events().size() == 1; }),
            "reintroduced target emits after a complete absence was observed");
    const auto events = recorder.Events();
    Require(events[0].fields.at(edr::field::kRegValue) == "debugger.exe",
            "re-added target reports current hook value");
    collector->Stop();
    bus.Stop();
}

} // namespace

void RunHookScanCollectorTests() {
    FailedTargetRetainsBaselineAndDoesNotBlockOtherRoot();
    InitialFailureDoesNotSeedAnEmptyBaseline();
    MissingRootIsAConclusiveEmptySnapshot();
    NativeComReadUsesOnlyPrivateHkcuFixture();
    NativeIfeoReadUsesNamedDebuggerValue();
    InitialTargetLocalRejectsRecoverQuietlyThenDetectChanges();
    FatalQueryStopRestartAndZeroPollAreBounded();
    BusOverflowIsCountedWithoutLosingSubmittedEvents();
    MalformedRootCannotErasePriorTargets();
    RetainedBudgetCountsEmptyNamesAndScalesLinearly();
    CompleteEmptyIfeoRootThenNewTargetEmits();
    InitiallyMissingRootThenTargetEmits();
    TargetSurfacedDuringRootFailureDiffsAfterRecovery();
    ObservedClsidRootThenNewComTargetEmits();
    InitialChildFailureRecoverySeedsQuietlyThenDetectsChange();
    DeletedTargetReaddedAfterReliableAbsenceEmits();
}

int main() {
    try {
        RunHookScanCollectorTests();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "hook scan tests failed: %s\n", error.what());
        return 1;
    }
    std::fprintf(stderr, "hook scan tests passed\n");
    return 0;
}
