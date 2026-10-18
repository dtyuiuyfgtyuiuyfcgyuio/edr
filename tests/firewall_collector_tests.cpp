#include <windows.h>

#include <chrono>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "collector.h"
#include "collector_firewall.h"

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

edr::FirewallCollectorSnapshot Complete(
    std::map<std::string, std::string> values = {}) {
    return {edr::FirewallSnapshotStatus::Complete, std::move(values)};
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
    void Set(edr::FirewallCollectorSnapshot next) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_next = std::move(next);
        m_calls = 0;
    }
    edr::FirewallCollectorQuery Query() {
        return [this] {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_calls;
            return m_next;
        };
    }
    bool SampledTwice() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_calls >= 2;
    }
private:
    mutable std::mutex m_mutex;
    edr::FirewallCollectorSnapshot m_next;
    unsigned m_calls = 0;
};

class Fixture {
public:
    explicit Fixture(Script& script, size_t capacity = 64, bool consume = true)
        : bus(capacity) {
        if (consume) bus.Start(&recorder);
        collector.reset(edr::CreateFirewallCollector(25, script.Query()));
        Require(collector->Start(&bus), "firewall worker starts");
    }
    ~Fixture() { collector->Stop(); bus.Stop(); }
    edr::EventBus bus;
    Recorder recorder;
    std::unique_ptr<edr::ICollector> collector;
};

void FailedAndPartialSnapshotsRetainBaselineAndRetry() {
    Script script;
    script.Set(Complete({{"rule-id", "v2|Action=Allow|Dir=In|Name=stable"}}));
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.SampledTwice(); }), "complete baseline sampled");
    script.Set({edr::FirewallSnapshotStatus::Failed, {{"rule-id", "partial"}}});
    Require(WaitUntil([&] { return script.SampledTwice(); }), "failed source is retried");
    Require(fixture.recorder.Events().empty(), "failed partial snapshot emits no changes");
    const auto failed = fixture.collector->GetHealthSnapshot();
    Require(failed.supported && failed.sourceErrors > 0 && failed.state == "source_error",
            "failed snapshot is visible in collector health");
    script.Set(Complete({{"rule-id", "v2|Action=Allow|Dir=In|Name=stable"}}));
    Require(WaitUntil([&] {
        return fixture.collector->GetHealthSnapshot().state == "running";
    }), "complete recovery restores source health");
    Require(fixture.recorder.Events().empty(), "unchanged recovery emits no duplicate");
    script.Set(Complete({{"rule-id", "v2|Action=Allow|Dir=In|Name=renamed"}}));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "unmapped display-name change is still detected from raw rule value");
    Require(fixture.recorder.Events()[0].fields.at(edr::field::kFirewallRuleName) == "rule-id",
            "raw change keeps rule_name mapped to registry value id");
    script.Set(Complete({{"rule-id", "v2|Action=Block|Dir=In|Name=stable"}}));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 2; }),
            "change after recovery is emitted");
    Require(fixture.recorder.Events()[1].fields.at(edr::field::kFirewallAction) == "modified",
            "modified action remains part of the existing event contract");
    Require(fixture.recorder.Events()[1].fields.at(edr::field::kFirewallRuleName) == "rule-id",
            "event rule name remains the registry value id");
}

void InitialFailureAndEmptySeedRemainQuietAndKeepPolling() {
    Script script;
    script.Set({});
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.SampledTwice(); }), "failed startup keeps retrying");
    Require(fixture.recorder.Events().empty(), "failed startup does not fabricate removals");
    script.Set(Complete());
    Require(WaitUntil([&] {
        return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0;
    }), "complete empty snapshot seeds baseline");
    Sleep(60);
    Require(fixture.recorder.Events().empty(), "first complete empty snapshot is silent");
    script.Set(Complete({{"new-rule", "v2|Action=Allow|Dir=Out"}}));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "collector continues after empty seed and reports new rules");
    Require(fixture.recorder.Events()[0].fields.at(edr::field::kFirewallAction) == "added",
            "new rule is reported as added");
}

void ExplicitMissingIsACompleteEmptySnapshotAndContinuesWatching() {
    Script script;
    script.Set(Complete({{"rule-id", "v2|Action=Allow|Dir=In"}}));
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.SampledTwice(); }), "baseline sampled");
    script.Set({edr::FirewallSnapshotStatus::Missing, {}});
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "explicitly missing key removes prior rules");
    auto events = fixture.recorder.Events();
    Require(events[0].fields.at(edr::field::kFirewallAction) == "removed",
            "missing key emits a removed event for prior rule");
    auto health = fixture.collector->GetHealthSnapshot();
    Require(health.countersAvailable && health.counters.at("key_missing") == 1 &&
                health.state == "source_missing",
            "missing key is explicit in health coverage");
    script.Set(Complete());
    Require(WaitUntil([&] {
        return fixture.collector->GetHealthSnapshot().state == "running";
    }), "collector recovers from missing key");
    script.Set(Complete({{"returned-rule", "v2|Action=Block|Dir=In"}}));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 2; }),
            "rules are observed after key returns");
    Require(fixture.recorder.Events()[1].fields.at(edr::field::kFirewallAction) == "added",
            "rule after missing period is added");
}

void CompleteEmptySnapshotRemovesRulesAndKeepsPolling() {
    Script script;
    script.Set(Complete({{"existing", "v2|Action=Allow|Dir=In"}}));
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.SampledTwice(); }), "baseline sampled");
    script.Set(Complete());
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 1; }),
            "complete empty snapshot removes previous rules");
    Require(fixture.recorder.Events()[0].fields.at(edr::field::kFirewallAction) == "removed",
            "complete empty snapshot emits removed action");
    script.Set(Complete({{"after-empty", "v2|Action=Allow|Dir=Out"}}));
    Require(WaitUntil([&] { return fixture.recorder.Events().size() == 2; }),
            "collector keeps observing after complete empty snapshot");
    Require(fixture.recorder.Events()[1].fields.at(edr::field::kFirewallAction) == "added",
            "rule after complete empty snapshot is added");
}

void SnapshotValidationRejectsBadAndOverBudgetCandidatesAtomically() {
    Script script;
    script.Set(Complete({{"stable", "v2|Action=Allow|Dir=In"}}));
    Fixture fixture(script);
    Require(WaitUntil([&] { return script.SampledTwice(); }), "baseline sampled");
    auto invalidUtf8 = Complete({{"stable", std::string("v2|Name=\xc3\x28", 10)}});
    script.Set(std::move(invalidUtf8));
    Require(WaitUntil([&] {
        auto health = fixture.collector->GetHealthSnapshot();
        return health.sourceErrors > 0 && health.state == "source_error";
    }), "invalid UTF-8 candidate is rejected");
    Require(fixture.recorder.Events().empty(), "invalid candidate emits no partial change");
    script.Set(Complete({{"stable", "v2|Action=Allow|Dir=In"}}));
    Require(WaitUntil([&] {
        return fixture.collector->GetHealthSnapshot().state == "running";
    }), "valid snapshot restores health");
    script.Set(Complete({{"stable", std::string(32769, 'x')}}));
    Require(WaitUntil([&] {
        auto health = fixture.collector->GetHealthSnapshot();
        return health.sourceErrors > 1 && health.state == "source_error";
    }), "oversized candidate is rejected as a whole");
    Require(fixture.recorder.Events().empty(), "over-budget candidate emits no deletions");
}

void CurrentUserRegistryKeyUsesTheNativeCheckedReader() {
    const std::wstring subkey = L"Software\\edr-firewall-snapshot-test-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    HKEY key = nullptr;
    DWORD disposition = 0;
    Require(RegCreateKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, nullptr, 0,
        KEY_ALL_ACCESS, nullptr, &key, &disposition) == ERROR_SUCCESS &&
        disposition == REG_CREATED_NEW_KEY, "create a test-owned HKCU key");
    struct Cleanup {
        const std::wstring& path;
        HKEY& key;
        ~Cleanup() {
            if (key) RegCloseKey(key);
            RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str());
        }
    } cleanup{subkey, key};
    const wchar_t valid[] = L"v2|Action=Allow|Dir=In";
    Require(RegSetValueExW(key, L"rule-one", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(valid), sizeof(valid)) == ERROR_SUCCESS,
        "write a test-owned firewall value");
    const DWORD binary = 7;
    Require(RegSetValueExW(key, L"binary", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&binary), sizeof(binary)) == ERROR_SUCCESS,
        "write a wrong-type value to prove whole-snapshot rejection");
    auto rejected = edr::ReadFirewallRegistrySnapshot(key);
    Require(rejected.status == edr::FirewallSnapshotStatus::Failed && rejected.values.empty(),
        "wrong registry type fails the complete candidate");
    Require(RegDeleteValueW(key, L"binary") == ERROR_SUCCESS, "remove wrong-type fixture value");
    const wchar_t invalidUtf16[] = {L'x', static_cast<wchar_t>(0xd800), L'\0'};
    Require(RegSetValueExW(key, L"invalid-utf16", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(invalidUtf16), sizeof(invalidUtf16)) == ERROR_SUCCESS,
        "write malformed UTF-16 in the test-owned value");
    rejected = edr::ReadFirewallRegistrySnapshot(key);
    Require(rejected.status == edr::FirewallSnapshotStatus::Failed && rejected.values.empty(),
        "invalid UTF-16 rejects the complete candidate");
    Require(RegDeleteValueW(key, L"invalid-utf16") == ERROR_SUCCESS,
        "remove malformed UTF-16 fixture value");
    const wchar_t embeddedNul[] = {L'a', L'\0', L'b', L'\0'};
    Require(RegSetValueExW(key, L"embedded-nul", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(embeddedNul), sizeof(embeddedNul)) == ERROR_SUCCESS,
        "write embedded NUL in the test-owned value");
    rejected = edr::ReadFirewallRegistrySnapshot(key);
    Require(rejected.status == edr::FirewallSnapshotStatus::Failed && rejected.values.empty(),
        "embedded NUL rejects the complete candidate");
    Require(RegDeleteValueW(key, L"embedded-nul") == ERROR_SUCCESS,
        "remove embedded-NUL fixture value");
    auto accepted = edr::ReadFirewallRegistrySnapshot(key);
    Require(accepted.status == edr::FirewallSnapshotStatus::Complete &&
        accepted.values.size() == 1 && accepted.values.at("rule-one") ==
            "v2|Action=Allow|Dir=In",
        "native checked reader returns the test-owned complete snapshot");
    const wchar_t changed[] = L"v2|Action=Block|Dir=Out";
    const auto recovered = edr::ReadFirewallRegistrySnapshot(key, {},
        [&](size_t attempt, size_t valuesRead) {
            if (attempt != 0 || valuesRead != 1) return;
            Sleep(20);
            Require(RegSetValueExW(key, L"rule-one", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(changed), sizeof(changed)) == ERROR_SUCCESS,
                "mutate test-owned key after first value was read");
        });
    Require(recovered.status == edr::FirewallSnapshotStatus::Complete &&
        recovered.values.size() == 1 && recovered.values.at("rule-one") ==
            "v2|Action=Block|Dir=Out",
        "a concurrent last-write change rejects the mixed candidate and retries");
    const wchar_t allowAgain[] = L"v2|Action=Allow|Dir=In";
    const auto unstable = edr::ReadFirewallRegistrySnapshot(key, {},
        [&](size_t attempt, size_t valuesRead) {
            if (valuesRead != 1) return;
            Sleep(20);
            const wchar_t* replacement = (attempt % 2 == 0) ? allowAgain : changed;
            const DWORD replacementBytes = (attempt % 2 == 0) ? sizeof(allowAgain) : sizeof(changed);
            Require(RegSetValueExW(key, L"rule-one", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(replacement), replacementBytes) == ERROR_SUCCESS,
                "keep mutating test-owned key during each snapshot attempt");
        });
    Require(unstable.status == edr::FirewallSnapshotStatus::Failed && unstable.values.empty(),
        "repeated concurrent changes exhaust bounded snapshot retries");
    edr::FirewallSnapshotLimits limits;
    limits.maxEnumeratedValues = 0;
    rejected = edr::ReadFirewallRegistrySnapshot(key, limits);
    Require(rejected.status == edr::FirewallSnapshotStatus::Failed && rejected.values.empty(),
        "enumeration exceeding configured bounds fails closed");
    limits = {};
    limits.maxTotalPayloadBytes = 8;
    rejected = edr::ReadFirewallRegistrySnapshot(key, limits);
    Require(rejected.status == edr::FirewallSnapshotStatus::Failed && rejected.values.empty(),
        "aggregate payload exceeding configured bounds fails closed");
}

void HealthReportsOverflowStopAndRestart() {
    Script script;
    script.Set(Complete({{"baseline", "v2|Action=Allow"}}));
    Fixture fixture(script, 1, false);
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().lastSuccess100ns != 0; }),
            "initial complete snapshot is healthy");
    script.Set(Complete({{"baseline", "v2|Action=Block"}, {"added", "v2|Action=Allow"}}));
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().eventsPushed == 2; }),
            "modified and added events submit");
    auto health = fixture.collector->GetHealthSnapshot();
    Require(health.busDropped == 1 && fixture.bus.SnapshotStats().pending == 1,
            "event bus eviction is reported as overflow");
    fixture.collector->Stop();
    health = fixture.collector->GetHealthSnapshot();
    Require(!health.running && health.state == "stopped", "stop updates worker health");
    Require(fixture.collector->Start(&fixture.bus), "collector can restart after explicit stop");
    Require(WaitUntil([&] { return fixture.collector->GetHealthSnapshot().running; }),
            "restarted worker is active");
    Sleep(60);
    Require(fixture.collector->GetHealthSnapshot().eventsPushed == 2,
            "restart seeds current state without replaying a burst");
}

void FatalQueryFailureIsContainedAndVisible() {
    edr::EventBus bus(8);
    std::unique_ptr<edr::ICollector> collector(edr::CreateFirewallCollector(25,
        []() -> edr::FirewallCollectorSnapshot { throw std::runtime_error("injected"); }));
    Require(collector->Start(&bus), "worker starts before fatal query");
    Require(WaitUntil([&] {
        auto health = collector->GetHealthSnapshot();
        return health.supported && !health.running && health.state == "source_error";
    }), "fatal query is contained and recorded");
    Require(!collector->Start(&bus), "dead joinable worker cannot claim start succeeded");
    collector->Stop();
    bus.Stop();
}
} // namespace

int main() {
    try {
        FailedAndPartialSnapshotsRetainBaselineAndRetry();
        InitialFailureAndEmptySeedRemainQuietAndKeepPolling();
        ExplicitMissingIsACompleteEmptySnapshotAndContinuesWatching();
        CompleteEmptySnapshotRemovesRulesAndKeepsPolling();
        SnapshotValidationRejectsBadAndOverBudgetCandidatesAtomically();
        CurrentUserRegistryKeyUsesTheNativeCheckedReader();
        HealthReportsOverflowStopAndRestart();
        FatalQueryFailureIsContainedAndVisible();
        std::puts("firewall collector tests passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "firewall collector tests failed: %s\n", error.what());
        return 1;
    }
}
