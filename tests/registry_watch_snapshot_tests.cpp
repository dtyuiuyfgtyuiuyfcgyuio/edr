#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "collector_reg_watch.h"

namespace edr { ICollector* CreateRegWatchCollector(); }

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        throw std::runtime_error(message);
    }
}

edr::RegistrySnapshot Snapshot(const char* key, const char* value) {
    return {{key, value}};
}

void FailedTargetSampleDoesNotReplaceItsBaseline() {
    edr::RegistrySnapshotTracker state;
    std::vector<std::pair<std::string, std::string>> changed;
    Require(state.Apply("HKLM\\TargetA", edr::RegistrySnapshotStatus::Complete,
                        Snapshot("HKLM\\TargetA\\Run", "one"), false, false,
                        changed) && changed.empty(),
            "initial complete sample establishes baseline without events");
    Require(!state.Apply("HKLM\\TargetA", edr::RegistrySnapshotStatus::Failed,
                         Snapshot("HKLM\\TargetA\\Run", "partial"),
                         false, true, changed) && changed.empty(),
            "failed target sample emits no partial changes");
    Require(state.Apply("HKLM\\TargetA", edr::RegistrySnapshotStatus::Complete,
                        Snapshot("HKLM\\TargetA\\Run", "one"), false, true,
                        changed) && changed.empty(),
            "recovery against unchanged trusted baseline emits no duplicate");
    Require(state.Apply("HKLM\\TargetA", edr::RegistrySnapshotStatus::Complete,
                        Snapshot("HKLM\\TargetA\\Run", "two"), false, true,
                        changed),
            "complete changed target sample commits");
    Require(changed.size() == 1 && changed.front().first == "HKLM\\TargetA\\Run" &&
                changed.front().second == "two",
            "a real change after recovery is emitted exactly once");
}

void FirstCompleteSampleAfterFailureSeedsWithoutFalseWriteEvents() {
    edr::RegistrySnapshotTracker state;
    std::vector<std::pair<std::string, std::string>> changed;
    Require(!state.Apply("HKLM\\TargetA", edr::RegistrySnapshotStatus::Failed,
                         Snapshot("HKLM\\TargetA\\Run", "partial"), false,
                         true, changed) && changed.empty(),
            "failed initial sample establishes no baseline or events");
    Require(state.Apply("HKLM\\TargetA", edr::RegistrySnapshotStatus::Complete,
                        Snapshot("HKLM\\TargetA\\Run", "current"), false,
                        true, changed) && changed.empty(),
            "first complete static sample after failure seeds without false writes");
}

void TargetBaselinesRemainIsolatedAndMissingMeansCompleteEmpty() {
    edr::RegistrySnapshotTracker state;
    const auto a = Snapshot("shared-value", "a");
    const auto b = Snapshot("shared-value", "b");
    std::vector<std::pair<std::string, std::string>> changed;
    state.Apply("scope-A", edr::RegistrySnapshotStatus::Complete, a, false, false, changed);
    state.Apply("scope-B", edr::RegistrySnapshotStatus::Complete, b, false, false, changed);
    Require(state.Apply("scope-A", edr::RegistrySnapshotStatus::Missing, {}, false,
                        true, changed) && changed.empty(),
            "a known absent optional key is accepted as a complete empty sample");
    Require(state.Apply("scope-B", edr::RegistrySnapshotStatus::Complete, b, false,
                        true, changed) && changed.empty(),
            "one target becoming absent does not alter another target baseline");
    Require(state.Apply("scope-A", edr::RegistrySnapshotStatus::Complete, a, false,
                        true, changed), "recreated target snapshot commits");
    const auto& appeared = changed;
    Require(appeared.size() == 1 && appeared.front().second == "a",
            "a key appearing after a complete missing sample is emitted once");
}

void IncompleteDynamicEnumerationRetainsTargetsUntilACompleteUnloadSample() {
    edr::RegistrySnapshotTracker state;
    std::vector<std::pair<std::string, std::string>> changed;
    state.Apply("HKU\\S-1-5-21-userA", edr::RegistrySnapshotStatus::Complete,
                Snapshot("HKU\\userA\\policy", "unchanged"), true, false, changed);
    state.ReconcileDynamicTargets({"HKU\\S-1-5-21-userA"}, false);
    Require(state.HasTarget("HKU\\S-1-5-21-userA"),
            "failed HKU enumeration retains prior dynamic target state");
    Require(state.Apply("HKU\\S-1-5-21-userA",
                        edr::RegistrySnapshotStatus::Missing, {}, true, true,
                        changed, true) && changed.empty(),
            "missing path during incomplete HKU enumeration preserves baseline");
    Require(state.Apply("HKU\\S-1-5-21-userA",
                        edr::RegistrySnapshotStatus::Complete,
                        Snapshot("HKU\\userA\\policy", "unchanged"),
                        true, true, changed) && changed.empty(),
            "preserved dynamic baseline avoids false re-add on recovery");

    state.ReconcileDynamicTargets({}, true);
    Require(!state.HasTarget("HKU\\S-1-5-21-userA"),
            "complete enumeration forgets an unloaded user's old baseline");
    Require(state.Apply(
        "HKU\\S-1-5-21-userA", edr::RegistrySnapshotStatus::Complete,
        Snapshot("HKU\\userA\\policy", "unchanged"), true, true, changed),
        "reloaded user target commits");
    Require(changed.size() == 1 && changed.front().second == "unchanged",
            "a later loaded SID is a new target and reports its current value once");
}

void RetainedBaselinesRespectAggregateValueAndPayloadBudgets() {
    edr::RegistrySnapshotLimits limits;
    limits.maxTargets = 2;
    limits.maxDynamicTargets = 0;
    limits.maxValuesPerTarget = 2;
    limits.maxTotalValues = 2;
    limits.maxPayloadBytesPerTarget = 64;
    limits.maxTotalPayloadBytes = 64;
    edr::RegistrySnapshotTracker state(limits);
    std::vector<std::pair<std::string, std::string>> changed;
    Require(state.Apply("static-A", edr::RegistrySnapshotStatus::Complete,
                        Snapshot("k", "v"), false, false, changed),
            "first target fits the explicitly small fixture budget");
    Require(!state.Apply("dynamic-A", edr::RegistrySnapshotStatus::Complete,
                         Snapshot("k2", "v2"), true, true, changed),
            "candidate exceeding the dynamic target quota is rejected");
    Require(!state.HasTarget("dynamic-A"),
            "rejected new target does not consume baseline capacity");
    Require(!state.Apply("static-A", edr::RegistrySnapshotStatus::Complete,
                         {{"k", "new"}, {"k2", "new2"}, {"k3", "new3"}},
                         false, true, changed),
            "candidate exceeding per-target value budget is rejected atomically");
    Require(state.Apply("static-A", edr::RegistrySnapshotStatus::Complete,
                        Snapshot("k", "v"), false, true, changed) && changed.empty(),
            "over-budget candidate leaves old trusted baseline untouched");
    const std::string totalBudgetValue(62, 'x');
    Require(!state.Apply("static-B", edr::RegistrySnapshotStatus::Complete,
                         Snapshot("z", totalBudgetValue.c_str()), false, true,
                         changed),
            "candidate within per-target budget but beyond total retained bytes is rejected");
    Require(!state.HasTarget("static-B"),
            "aggregate budget rejection does not publish a partial new target");
}

void RegistryTargetFailureCountersDriveDegradedHealth() {
    edr::RegistryWatchHealth health;
    health.ConfigureTargets(5);
    health.RecordReadFailure();
    health.RecordNotificationArmFailure();
    health.PublishCoverage(5, 1, 1, 1);
    edr::CollectorHealthSnapshot raw;
    raw.supported = true;
    raw.running = true;
    raw.state = "running";
    auto sample = health.ApplyTo(raw);
    Require(sample.supported && sample.running && sample.state == "degraded",
            "source failures report a supported running degraded watcher");
    Require(sample.counters.at("configured_targets") == 5 &&
                sample.counters.at("active_watches") == 5 &&
                sample.counters.at("missing_targets") == 1 &&
                sample.counters.at("read_failures") == 1 &&
                sample.counters.at("notification_arm_failures") == 1,
            "health exposes target coverage, missing optional targets, and failures");
    health.PublishCoverage(5, 0, 0, 0);
    sample = health.ApplyTo(raw);
    Require(sample.state == "running" && sample.counters.at("missing_targets") == 0,
            "successful recovery restores running health and clears current missing count");
    health.RecordReadFailure();
    health.PublishCoverage(5, 0, 1, 0);
    sample = health.ApplyTo(raw);
    Require(sample.state == "degraded" && sample.counters.at("active_watches") == 5 &&
                sample.counters.at("current_read_failures") == 1,
            "active notifications do not mask a target's failed checked read");
    health.PublishCoverage(5, 0, 0, 0);
    sample = health.ApplyTo(raw);
    Require(sample.state == "running" && sample.counters.at("read_failures") == 2,
            "complete recovered cycle restores health but retains cumulative failures");
    raw.state = "starting";
    Require(health.ApplyTo(raw).state == "starting",
            "active watches do not prove the first snapshot has completed");
    raw.state = "source_error";
    Require(health.ApplyTo(raw).state == "source_error",
            "coverage does not hide an independent runtime source failure");
}

void StoppedCollectorHasNoActiveNotificationWatches() {
    edr::EventBus bus(16);
    std::unique_ptr<edr::ICollector> collector(edr::CreateRegWatchCollector());
    Require(collector->Start(&bus), "start a read-only registry watcher");
    collector->Stop();
    const auto health = collector->GetHealthSnapshot();
    Require(health.supported && !health.running &&
                health.counters.at("active_watches") == 0,
            "stopped collector reports no retained active watches");
}

void CurrentUserTemporaryKeyCanBeReadCompletely() {
    const std::wstring subkey = L"Software\\edr-regwatch-snapshot-test-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
    HKEY key = nullptr;
    DWORD disposition = 0;
    Require(RegCreateKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, nullptr, 0,
                KEY_ALL_ACCESS, nullptr, &key, &disposition) == ERROR_SUCCESS &&
                disposition == REG_CREATED_NEW_KEY,
            "create a test-owned current-user registry key");
    struct Cleanup {
        const std::wstring& path;
        HKEY& key;
        ~Cleanup() {
            if (key) RegCloseKey(key);
            RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str());
        }
    } cleanup{subkey, key};
    const wchar_t value[] = L"C:\\test-owned\\watch.exe";
    Require(RegSetValueExW(key, L"Run", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(value), sizeof(value)) == ERROR_SUCCESS,
            "write a test-owned value");
    const wchar_t secondary[] = L"secondary";
    Require(RegSetValueExW(key, L"Other", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(secondary), sizeof(secondary)) ==
                ERROR_SUCCESS,
            "write a second test-owned value for the scan-limit case");
    const auto result = edr::ReadRegistrySnapshotValuesChecked(
        key, "HKCU\\edr-test", {L"Run"});
    Require(result.status == edr::RegistrySnapshotStatus::Complete &&
                result.values.size() == 1 &&
                result.values.at("HKCU\\edr-test\\Run") ==
                    "C:\\test-owned\\watch.exe",
            "checked reader returns a complete bounded current-user snapshot");
    edr::RegistrySnapshotLimits limits;
    limits.maxEnumeratedValues = 1;
    const auto overLimit = edr::ReadRegistrySnapshotValuesChecked(
        key, "HKCU\\edr-test", {}, limits);
    Require(overLimit.status == edr::RegistrySnapshotStatus::Failed &&
                overLimit.values.empty(),
            "enumeration over the explicit scan budget fails without partial values");
}

} // namespace

int main() {
    try {
        FailedTargetSampleDoesNotReplaceItsBaseline();
        FirstCompleteSampleAfterFailureSeedsWithoutFalseWriteEvents();
        TargetBaselinesRemainIsolatedAndMissingMeansCompleteEmpty();
        IncompleteDynamicEnumerationRetainsTargetsUntilACompleteUnloadSample();
        RetainedBaselinesRespectAggregateValueAndPayloadBudgets();
        RegistryTargetFailureCountersDriveDegradedHealth();
        StoppedCollectorHasNoActiveNotificationWatches();
        CurrentUserTemporaryKeyCanBeReadCompletely();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
    std::puts("registry watch snapshot tests passed");
    return 0;
}
