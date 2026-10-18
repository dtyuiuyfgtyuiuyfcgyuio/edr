#include "dispatch_timing_tests.h"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

#include "config.h"
#include "dispatch_timing.h"
#include "dispatch_timing_scope.h"
#include "health_heartbeat.h"

namespace {

using edr::DispatchTiming;

#define DT_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("dispatch timing test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

/* Every counter value is rendered as a decimal string so the wiring can
 * stoull it into HealthComponent::counters (uint64_t map). */
uint64_t CounterValue(const std::map<std::string, std::string>& counters,
                      const std::string& key) {
    const auto it = counters.find(key);
    DT_CHECK(it != counters.end());
    return std::stoull(it->second);
}

bool HasCounter(const std::map<std::string, std::string>& counters,
                const std::string& key) {
    return counters.find(key) != counters.end();
}

bool LoadConfigJson(const std::string& json, edr::Config& cfg) {
    wchar_t directory[MAX_PATH] = {}, filename[MAX_PATH] = {};
    DT_CHECK(GetTempPathW(MAX_PATH, directory) != 0);
    DT_CHECK(GetTempFileNameW(directory, L"dtc", 0, filename) != 0);
    struct Cleanup {
        const wchar_t* path;
        ~Cleanup() { DeleteFileW(path); }
    } cleanup{filename};
    std::ofstream out(edr::WideToUtf8(filename), std::ios::binary | std::ios::trunc);
    out << json;
    out.close();
    DT_CHECK(static_cast<bool>(out));
    std::string error;
    return edr::LoadConfigFile(edr::WideToUtf8(filename), cfg, error);
}

void SlowEventsRemainVisibleDuringWarningCooldown() {
    DispatchTiming timing(true, 100, 3600);
    timing.RecordEvent(16, 100); /* equality is within budget */
    timing.RecordEvent(16, 101);
    timing.RecordEvent(2, 300);  /* slow, but its warning is throttled */
    timing.RecordEvent(3, 50);
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(CounterValue(counters, "dispatch.04_slow_events") == 2);
    DT_CHECK(CounterValue(counters, "dispatch.02_slow_warns") == 1);
    DT_CHECK(CounterValue(counters, "dispatch.05_slow_threshold_us") == 100);
    DT_CHECK(CounterValue(counters, "dispatch.T16.slow_count") == 1);
    DT_CHECK(CounterValue(counters, "dispatch.T02.slow_count") == 1);
    DT_CHECK(CounterValue(counters, "dispatch.T03.slow_count") == 0);
    DT_CHECK(timing.TotalEvents() == 4);
}

void ZeroThresholdKeepsTimingWithoutSlowClassification() {
    DispatchTiming timing(true, 0, 0);
    timing.RecordEvent(16, 999999999);
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(CounterValue(counters, "dispatch.04_slow_events") == 0);
    DT_CHECK(CounterValue(counters, "dispatch.02_slow_warns") == 0);
    DT_CHECK(CounterValue(counters, "dispatch.T16.slow_count") == 0);
    DT_CHECK(CounterValue(counters, "dispatch.T16.max_us") == 999999999);
}

void NestedTimingConfigIsAccepted() {
    edr::Config cfg;
    DT_CHECK(LoadConfigJson(R"({"health":{"enable":true,"poll_seconds":30,
        "dispatch_timing":{"enable":true,"slow_warn_us":100,"warn_cooldown_seconds":0}}})", cfg));
    DT_CHECK(cfg.healthEnable && cfg.healthPollSeconds == 30);
    DT_CHECK(cfg.healthDispatchTimingEnable);
    DT_CHECK(cfg.healthDispatchSlowWarnUs == 100);
    DT_CHECK(cfg.healthDispatchWarnCooldownSeconds == 0);
    DispatchTiming timing(cfg.healthDispatchTimingEnable,
        cfg.healthDispatchSlowWarnUs, cfg.healthDispatchWarnCooldownSeconds);
    timing.RecordEvent(1, 101);
    timing.RecordEvent(2, 101);
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(CounterValue(counters, "dispatch.02_slow_warns") == 2);
    DT_CHECK(CounterValue(counters, "dispatch.04_slow_events") == 2);
}

void MissingTimingConfigPreservesLegacyBehavior() {
    for (const char* json : {"{}", R"({"health":{"enable":true}})",
        R"({"health":{"dispatch_timing":{}}})"}) {
        edr::Config cfg;
        DT_CHECK(LoadConfigJson(json, cfg));
        DT_CHECK(cfg.healthDispatchTimingEnable);
        DT_CHECK(cfg.healthDispatchSlowWarnUs == 50000);
        DT_CHECK(cfg.healthDispatchWarnCooldownSeconds == 30);
    }
}

void TimingConfigAcceptsBoundsAndIndependentDisable() {
    edr::Config cfg;
    DT_CHECK(LoadConfigJson(R"({"health":{"enable":true,"dispatch_timing":{
        "enable":false,"slow_warn_us":0,"warn_cooldown_seconds":86400}}})", cfg));
    DT_CHECK(cfg.healthEnable && !cfg.healthDispatchTimingEnable);
    DT_CHECK(cfg.healthDispatchSlowWarnUs == 0 && cfg.healthDispatchWarnCooldownSeconds == 86400);
    DT_CHECK(LoadConfigJson(R"({"health":{"dispatch_timing":{"slow_warn_us":60000000}}})", cfg));
    DT_CHECK(cfg.healthDispatchSlowWarnUs == 60000000);
}

void InvalidTimingConfigDoesNotPartiallyApply() {
    for (const char* value : {"null", "[]", "true", "1", R"({"enable":1})",
        R"({"enable":"true"})", R"({"slow_warn_us":-1})",
        R"({"slow_warn_us":60000001})", R"({"slow_warn_us":1.5})",
        R"({"slow_warn_us":"100"})", R"({"slow_warn_us":null})",
        R"({"slow_warn_us":true})", R"({"slow_warn_us":18446744073709551615})",
        R"({"warn_cooldown_seconds":-1})", R"({"warn_cooldown_seconds":86401})",
        R"({"warn_cooldown_seconds":0.5})", R"({"warn_cooldown_seconds":"30"})",
        R"({"warn_cooldown_seconds":false})", R"({"unknown":1})",
        R"({"enable":false,"slow_warn_us":-1})"}) {
        edr::Config cfg;
        cfg.healthEnable = true;
        cfg.healthPollSeconds = 60;
        cfg.healthDispatchTimingEnable = false;
        cfg.healthDispatchSlowWarnUs = 123;
        cfg.healthDispatchWarnCooldownSeconds = 45;
        const std::string json = std::string("{\"health\":{\"enable\":false,\"poll_seconds\":30,\"dispatch_timing\":") + value + "}}";
        DT_CHECK(!LoadConfigJson(json, cfg));
        DT_CHECK(cfg.healthEnable && cfg.healthPollSeconds == 60);
        DT_CHECK(!cfg.healthDispatchTimingEnable);
        DT_CHECK(cfg.healthDispatchSlowWarnUs == 123 && cfg.healthDispatchWarnCooldownSeconds == 45);
    }
}

void DispatchHealthExplicitlyReportsDisabled() {
    DispatchTiming disabled(false, 100, 30);
    for (const DispatchTiming* timing : {static_cast<const DispatchTiming*>(nullptr),
        static_cast<const DispatchTiming*>(&disabled)}) {
        const auto component = edr::SampleDispatchTimingHealth(timing);
        DT_CHECK(component.name == "dispatch" && component.state == "disabled");
        DT_CHECK(!component.countersAvailable && component.counters.empty());
    }
}

void DispatchHealthPreservesNumericCountersAndBudget() {
    DispatchTiming timing(true, 100, 3600);
    for (uint16_t type = 0; type < 64; ++type) timing.RecordEvent(type, 101 + type);
    timing.RecordEvent(100, 999);
    const auto component = edr::SampleDispatchTimingHealth(&timing);
    DT_CHECK(component.name == "dispatch" && component.state == "running");
    DT_CHECK(component.countersAvailable && component.counters.size() <= 64);
    DT_CHECK(component.counters.at("dispatch.04_slow_events") == 65);
    DT_CHECK(component.counters.at("dispatch.05_slow_threshold_us") == 100);
    DT_CHECK(component.counters.at("dispatch.T63.slow_count") == 1);
    DT_CHECK(component.counters.at("dispatch.other.slow_count") == 1);
    DT_CHECK(component.counters.at("dispatch.03_omitted_types") == 51);
}

void RecordStatsMeanMaxCount() {
    DispatchTiming timing(true, 0, 0); /* slow warnings off here */
    timing.RecordEvent(16, 100);
    timing.RecordEvent(16, 300);
    timing.RecordEvent(16, 200);

    DT_CHECK(timing.TotalEvents() == 3);
    DT_CHECK(timing.TrackedTypes() == 1);

    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(CounterValue(counters, "dispatch.T16.count") == 3);
    DT_CHECK(CounterValue(counters, "dispatch.T16.total_us") == 600);
    DT_CHECK(CounterValue(counters, "dispatch.T16.max_us") == 300);
    /* mean = total / count = 200us */
    DT_CHECK(CounterValue(counters, "dispatch.T16.total_us") /
                 CounterValue(counters, "dispatch.T16.count") == 200);
    DT_CHECK(CounterValue(counters, "dispatch.00_total_events") == 3);
    DT_CHECK(CounterValue(counters, "dispatch.01_tracked_types") == 1);
    DT_CHECK(CounterValue(counters, "dispatch.02_slow_warns") == 0);
    DT_CHECK(CounterValue(counters, "dispatch.03_omitted_types") == 0);
}

void MultiTypeIsolation() {
    DispatchTiming timing(true, 0, 0);
    timing.RecordEvent(1, 10);
    timing.RecordEvent(2, 20);
    timing.RecordEvent(1, 30);
    timing.RecordEvent(5, 7); /* zero-padded T05 key naming */

    DT_CHECK(timing.TrackedTypes() == 3);
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(CounterValue(counters, "dispatch.T01.count") == 2);
    DT_CHECK(CounterValue(counters, "dispatch.T01.total_us") == 40);
    DT_CHECK(CounterValue(counters, "dispatch.T01.max_us") == 30);
    DT_CHECK(CounterValue(counters, "dispatch.T02.count") == 1);
    DT_CHECK(CounterValue(counters, "dispatch.T02.total_us") == 20);
    DT_CHECK(CounterValue(counters, "dispatch.T02.max_us") == 20);
    DT_CHECK(HasCounter(counters, "dispatch.T05.count"));
    DT_CHECK(CounterValue(counters, "dispatch.T05.max_us") == 7);
    DT_CHECK(CounterValue(counters, "dispatch.00_total_events") == 4);
}

void DisabledIsFullNoOp() {
    DispatchTiming timing(false, 1000, 3600);
    timing.RecordEvent(16, 5000);
    timing.RecordEvent(300, 9000);
    timing.RecordEvent(2, 1);

    DT_CHECK(timing.TotalEvents() == 0);
    DT_CHECK(timing.TrackedTypes() == 0);
    DT_CHECK(!timing.Enabled());
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters); /* must not touch the map at all */
    DT_CHECK(counters.empty());
}

void SlowWarnRateLimitedBySharedCooldown() {
    /* 1h cooldown: no expiry can occur inside the test. */
    DispatchTiming timing(true, 1000, 3600);
    timing.RecordEvent(16, 1500); /* slow -> warn #1 */
    timing.RecordEvent(16, 2000); /* slow, same type -> throttled */
    timing.RecordEvent(2, 1500);  /* slow, other type -> throttled too
                                     (cooldown is shared across types) */
    timing.RecordEvent(3, 500);   /* below threshold -> no warn */

    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(CounterValue(counters, "dispatch.02_slow_warns") == 1);
}

void SlowWarnCooldownExpiryAllowsNext() {
    DispatchTiming timing(true, 1000, 1); /* 1s cooldown */
    timing.RecordEvent(16, 1500);         /* warn #1 */
    timing.RecordEvent(16, 1500);         /* inside cooldown -> throttled */
    {
        std::map<std::string, std::string> counters;
        timing.AppendCounters(counters);
        DT_CHECK(CounterValue(counters, "dispatch.02_slow_warns") == 1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    timing.RecordEvent(16, 1500); /* cooldown elapsed -> warn #2 */
    timing.RecordEvent(16, 1500); /* re-armed cooldown -> throttled */
    {
        std::map<std::string, std::string> counters;
        timing.AppendCounters(counters);
        DT_CHECK(CounterValue(counters, "dispatch.02_slow_warns") == 2);
    }
}

void SlotOverflowFoldsIntoOther() {
    DispatchTiming timing(true, 0, 0);
    timing.RecordEvent(63, 700);  /* last direct slot */
    timing.RecordEvent(64, 900);  /* first type beyond the table */
    timing.RecordEvent(300, 100); /* far beyond, same other bucket */

    DT_CHECK(timing.TrackedTypes() == 2);
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(CounterValue(counters, "dispatch.T63.count") == 1);
    DT_CHECK(CounterValue(counters, "dispatch.T63.max_us") == 700);
    DT_CHECK(CounterValue(counters, "dispatch.other.count") == 2);
    DT_CHECK(CounterValue(counters, "dispatch.other.total_us") == 1000);
    DT_CHECK(CounterValue(counters, "dispatch.other.max_us") == 900);
    DT_CHECK(CounterValue(counters, "dispatch.00_total_events") == 3);
    DT_CHECK(CounterValue(counters, "dispatch.03_omitted_types") == 0);
}

void CountersStayWithinChannelBudget() {
    /* 30 active direct types + the other bucket: 31 buckets x 4 keys
     * cannot fit the 64-key channel budget of health_heartbeat, so
     * AppendCounters must keep the summary keys, the other bucket and
     * the slowest direct types - and account for the rest. */
    DispatchTiming timing(true, 0, 0);
    for (uint16_t type = 0; type < 30; ++type)
        timing.RecordEvent(type, 1000u + type); /* T29 is the slowest */
    timing.RecordEvent(400, 5000); /* other bucket, global worst */

    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    /* 6 summary + 4 other + 13 direct types x 4 = 62, within 64. */
    DT_CHECK(counters.size() == 62);
    /* First key in health_heartbeat's std::map iteration order. */
    DT_CHECK(counters.begin()->first == "dispatch.00_total_events");
    DT_CHECK(HasCounter(counters, "dispatch.00_total_events"));
    DT_CHECK(HasCounter(counters, "dispatch.01_tracked_types"));
    DT_CHECK(HasCounter(counters, "dispatch.02_slow_warns"));
    DT_CHECK(HasCounter(counters, "dispatch.03_omitted_types"));
    DT_CHECK(HasCounter(counters, "dispatch.04_slow_events"));
    DT_CHECK(HasCounter(counters, "dispatch.05_slow_threshold_us"));
    DT_CHECK(CounterValue(counters, "dispatch.01_tracked_types") == 31);
    DT_CHECK(CounterValue(counters, "dispatch.03_omitted_types") == 17);
    /* The other bucket is always rendered. */
    DT_CHECK(CounterValue(counters, "dispatch.other.max_us") == 5000);
    DT_CHECK(CounterValue(counters, "dispatch.other.count") == 1);
    /* Slowest direct types survive the budget; the tail does not. */
    DT_CHECK(CounterValue(counters, "dispatch.T29.max_us") == 1029);
    DT_CHECK(HasCounter(counters, "dispatch.T29.count"));
    DT_CHECK(HasCounter(counters, "dispatch.T17.count"));
    DT_CHECK(!HasCounter(counters, "dispatch.T16.count"));
    DT_CHECK(!HasCounter(counters, "dispatch.T00.count"));
}

void EmptyEnabledEmitsSummaryOnly() {
    DispatchTiming timing(true, 0, 0);
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(counters.size() == 6);
    DT_CHECK(CounterValue(counters, "dispatch.00_total_events") == 0);
    DT_CHECK(CounterValue(counters, "dispatch.01_tracked_types") == 0);
    DT_CHECK(CounterValue(counters, "dispatch.02_slow_warns") == 0);
    DT_CHECK(CounterValue(counters, "dispatch.03_omitted_types") == 0);
    DT_CHECK(CounterValue(counters, "dispatch.04_slow_events") == 0);
    DT_CHECK(CounterValue(counters, "dispatch.05_slow_threshold_us") == 0);
}

void TotalEventsAggregatesAcrossTypes() {
    DispatchTiming timing(true, 0, 0);
    timing.RecordEvent(1, 5);
    timing.RecordEvent(2, 7);
    timing.RecordEvent(2, 9);
    timing.RecordEvent(100, 1);
    DT_CHECK(timing.TotalEvents() == 4);
    DT_CHECK(timing.TrackedTypes() == 3);
}

void ConcurrentRecordersKeepTotalsConsistent() {
    /* Production has a single writer (the consumer thread); this stress
     * deliberately exceeds that contract to prove the counters are
     * atomic and never torn for the concurrent health-thread reader. */
    DispatchTiming timing(true, 0, 0);
    constexpr int kThreads = 4;
    constexpr int kPerThread = 20000;
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&timing, t, perThread = kPerThread] {
            for (int i = 0; i < perThread; ++i)
                timing.RecordEvent(static_cast<uint16_t>(t + 1), 1);
        });
    }
    for (auto& worker : workers) worker.join();

    DT_CHECK(timing.TotalEvents() == kThreads * kPerThread);
    DT_CHECK(timing.TrackedTypes() == kThreads);
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    for (int t = 0; t < kThreads; ++t) {
        const std::string prefix =
            "dispatch.T0" + std::to_string(t + 1);
        DT_CHECK(CounterValue(counters, prefix + ".count") == kPerThread);
        DT_CHECK(CounterValue(counters, prefix + ".total_us") ==
                 kPerThread);
        DT_CHECK(CounterValue(counters, prefix + ".max_us") == 1);
    }
    DT_CHECK(CounterValue(counters, "dispatch.00_total_events") ==
             kThreads * kPerThread);
}

void ScopeWithNullOrDisabledTimingDoesNotRecord() {
    {
        edr::DispatchTimingScope scope(nullptr, 16);
    }
    DispatchTiming disabled(false, 0, 0);
    {
        edr::DispatchTimingScope scope(&disabled, 16);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    DT_CHECK(disabled.TotalEvents() == 0);
    DT_CHECK(disabled.TrackedTypes() == 0);
}

void ScopeRecordsElapsedSinkDuration() {
    DispatchTiming timing(true, 0, 0);
    {
        edr::DispatchTimingScope scope(&timing, 16);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    DT_CHECK(timing.TotalEvents() == 1);
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(CounterValue(counters, "dispatch.T16.count") == 1);
    DT_CHECK(CounterValue(counters, "dispatch.T16.total_us") > 0);
    DT_CHECK(CounterValue(counters, "dispatch.T16.max_us") > 0);
}

void ScopeRecordsDuringExceptionUnwindAndPreservesException() {
    DispatchTiming timing(true, 0, 0);
    bool caughtOriginal = false;
    try {
        edr::DispatchTimingScope scope(&timing, 2);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        throw std::runtime_error("sink failure marker");
    } catch (const std::runtime_error& e) {
        caughtOriginal = std::string(e.what()) == "sink failure marker";
    }

    DT_CHECK(caughtOriginal);
    DT_CHECK(timing.TotalEvents() == 1);
    std::map<std::string, std::string> counters;
    timing.AppendCounters(counters);
    DT_CHECK(CounterValue(counters, "dispatch.T02.count") == 1);
    DT_CHECK(CounterValue(counters, "dispatch.T02.total_us") > 0);
}

} // namespace

void RunDispatchTimingTests() {
    std::fprintf(stderr, "[dispatch_timing] SlowEventsRemainVisibleDuringWarningCooldown\n");
    SlowEventsRemainVisibleDuringWarningCooldown();
    std::fprintf(stderr, "[dispatch_timing] ZeroThresholdKeepsTimingWithoutSlowClassification\n");
    ZeroThresholdKeepsTimingWithoutSlowClassification();
    std::fprintf(stderr, "[dispatch_timing] NestedTimingConfigIsAccepted\n");
    NestedTimingConfigIsAccepted();
    std::fprintf(stderr, "[dispatch_timing] MissingTimingConfigPreservesLegacyBehavior\n");
    MissingTimingConfigPreservesLegacyBehavior();
    std::fprintf(stderr, "[dispatch_timing] TimingConfigAcceptsBoundsAndIndependentDisable\n");
    TimingConfigAcceptsBoundsAndIndependentDisable();
    std::fprintf(stderr, "[dispatch_timing] InvalidTimingConfigDoesNotPartiallyApply\n");
    InvalidTimingConfigDoesNotPartiallyApply();
    std::fprintf(stderr, "[dispatch_timing] DispatchHealthExplicitlyReportsDisabled\n");
    DispatchHealthExplicitlyReportsDisabled();
    std::fprintf(stderr, "[dispatch_timing] DispatchHealthPreservesNumericCountersAndBudget\n");
    DispatchHealthPreservesNumericCountersAndBudget();
    std::fprintf(stderr, "[dispatch_timing] RecordStatsMeanMaxCount\n");
    RecordStatsMeanMaxCount();
    std::fprintf(stderr, "[dispatch_timing] MultiTypeIsolation\n");
    MultiTypeIsolation();
    std::fprintf(stderr, "[dispatch_timing] DisabledIsFullNoOp\n");
    DisabledIsFullNoOp();
    std::fprintf(stderr,
        "[dispatch_timing] SlowWarnRateLimitedBySharedCooldown\n");
    SlowWarnRateLimitedBySharedCooldown();
    std::fprintf(stderr,
        "[dispatch_timing] SlowWarnCooldownExpiryAllowsNext\n");
    SlowWarnCooldownExpiryAllowsNext();
    std::fprintf(stderr, "[dispatch_timing] SlotOverflowFoldsIntoOther\n");
    SlotOverflowFoldsIntoOther();
    std::fprintf(stderr, "[dispatch_timing] CountersStayWithinChannelBudget\n");
    CountersStayWithinChannelBudget();
    std::fprintf(stderr, "[dispatch_timing] EmptyEnabledEmitsSummaryOnly\n");
    EmptyEnabledEmitsSummaryOnly();
    std::fprintf(stderr,
        "[dispatch_timing] TotalEventsAggregatesAcrossTypes\n");
    TotalEventsAggregatesAcrossTypes();
    std::fprintf(stderr,
        "[dispatch_timing] ConcurrentRecordersKeepTotalsConsistent\n");
    ConcurrentRecordersKeepTotalsConsistent();
    std::fprintf(stderr,
        "[dispatch_timing] ScopeWithNullOrDisabledTimingDoesNotRecord\n");
    ScopeWithNullOrDisabledTimingDoesNotRecord();
    std::fprintf(stderr,
        "[dispatch_timing] ScopeRecordsElapsedSinkDuration\n");
    ScopeRecordsElapsedSinkDuration();
    std::fprintf(stderr,
        "[dispatch_timing] ScopeRecordsDuringExceptionUnwindAndPreservesException\n");
    ScopeRecordsDuringExceptionUnwindAndPreservesException();
    std::fprintf(stderr, "[dispatch_timing] all passed\n");
}
