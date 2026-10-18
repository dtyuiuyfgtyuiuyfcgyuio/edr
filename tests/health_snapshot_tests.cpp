#include "health_snapshot_tests.h"

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

#include "event_bus.h"
#include "health_heartbeat.h"
#include "json_lite.h"
#include "reporter.h"

namespace {

#define HS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("health snapshot test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

jsonlite::Value Snapshot(const std::vector<edr::HealthComponent>& components,
                         bool diagnosticsAvailable = true) {
    edr::EventBus bus;
    edr::HealthHeartbeat heartbeat(1, &bus, nullptr, "snapshot-test", nullptr,
        nullptr, diagnosticsAvailable
            ? edr::HealthHeartbeat::DiagnosticsFn([&components] {
                  return components;
              })
            : edr::HealthHeartbeat::DiagnosticsFn{});
    return jsonlite::parse(heartbeat.Snapshot(17));
}

bool IsStrictUtf8(const std::string& text) {
    size_t i = 0;
    while (i < text.size()) {
        const unsigned char first = static_cast<unsigned char>(text[i]);
        if (first <= 0x7f) {
            ++i;
            continue;
        }

        size_t length = 0;
        uint32_t codePoint = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            length = 2;
            codePoint = first & 0x1f;
        } else if (first >= 0xe0 && first <= 0xef) {
            length = 3;
            codePoint = first & 0x0f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            length = 4;
            codePoint = first & 0x07;
        } else {
            return false;
        }
        if (text.size() - i < length) return false;
        for (size_t j = 1; j < length; ++j) {
            const unsigned char next = static_cast<unsigned char>(text[i + j]);
            if ((next & 0xc0) != 0x80) return false;
            codePoint = (codePoint << 6) | (next & 0x3f);
        }
        if ((length == 3 && codePoint < 0x800) ||
            (length == 4 && codePoint < 0x10000) ||
            (codePoint >= 0xd800 && codePoint <= 0xdfff) ||
            codePoint > 0x10ffff) {
            return false;
        }
        i += length;
    }
    return true;
}

void TestComponentLimitBoundaryAndNullBus() {
    std::vector<edr::HealthComponent> exact(256);
    for (size_t i = 0; i < exact.size(); ++i) {
        exact[i].name = "component-" + std::to_string(i);
        exact[i].state = "running";
    }
    auto sample = Snapshot(exact);
    HS_CHECK(sample.find("components")->array.size() == 256);
    HS_CHECK(!sample.find("components_truncated")->asBool());

    exact.push_back(edr::HealthComponent{});
    sample = Snapshot(exact);
    HS_CHECK(sample.find("components")->array.size() == 256);
    HS_CHECK(sample.find("components_truncated")->asBool());

    edr::HealthHeartbeat noBus(1, nullptr, nullptr, "", nullptr, nullptr);
    const auto nullBus = jsonlite::parse(noBus.Snapshot());
    HS_CHECK(nullBus.find("bus_pending")->type == jsonlite::Type::Null);
    HS_CHECK(nullBus.find("bus_dropped")->type == jsonlite::Type::Null);
    for (const char* key : {"bus_capacity", "bus_high_watermark", "bus_in_flight",
         "bus_overflow_dropped", "bus_consumer_failed", "bus_abandoned",
         "bus_consumed", "bus_deduplicated", "bus_oldest_pending_ms"}) {
        HS_CHECK(nullBus.find(key) != nullptr);
        HS_CHECK(nullBus.find(key)->type == jsonlite::Type::Null);
    }
}

void TestEventBusLossBreakdown() {
    edr::EventBus bus(1);
    edr::Event event;
    event.ts100ns = UINT64_MAX;
    HS_CHECK(bus.Push(event));
    HS_CHECK(!bus.Push(event));
    edr::HealthHeartbeat heartbeat(1, &bus, nullptr, "snapshot-test");
    auto sample = jsonlite::parse(heartbeat.Snapshot());
    for (const char* key : {"bus_capacity", "bus_high_watermark", "bus_in_flight",
         "bus_overflow_dropped", "bus_consumer_failed", "bus_abandoned",
         "bus_consumed", "bus_deduplicated", "bus_oldest_pending_ms"})
        HS_CHECK(sample.find(key) != nullptr);
    HS_CHECK(sample.find("bus_capacity")->asNumber() == 1);
    HS_CHECK(sample.find("bus_high_watermark")->asNumber() == 1);
    HS_CHECK(sample.find("bus_pending")->asNumber() == 1);
    HS_CHECK(sample.find("bus_overflow_dropped")->asNumber() == 1);
    HS_CHECK(sample.find("bus_consumer_failed")->asNumber() == 0);
    bus.Stop();
    sample = jsonlite::parse(heartbeat.Snapshot());
    HS_CHECK(sample.find("bus_dropped")->asNumber() == 2);
    HS_CHECK(sample.find("bus_abandoned")->asNumber() == 1);
    HS_CHECK(sample.find("bus_pending")->asNumber() == 0);
    HS_CHECK(sample.find("bus_oldest_pending_ms")->asNumber() == 0);
}

void TestCounterLimitAndUnavailableCounters() {
    edr::HealthComponent component;
    component.name = "counter-source";
    component.countersAvailable = true;
    for (size_t i = 0; i < 64; ++i)
        component.counters.emplace("counter-" + std::to_string(i), i);
    auto sample = Snapshot({component});
    const auto& exactCounters = sample.find("components")->array[0];
    HS_CHECK(exactCounters.find("counters")->object.size() == 64);
    HS_CHECK(!exactCounters.find("counters_truncated")->asBool());

    component.counters.emplace("counter-64", 64);
    sample = Snapshot({component});
    const auto& limitedCounters = sample.find("components")->array[0];
    HS_CHECK(limitedCounters.find("counters")->object.size() == 64);
    HS_CHECK(limitedCounters.find("counters_truncated")->asBool());

    edr::HealthComponent unavailable;
    unavailable.name = "unsupported-source";
    unavailable.state = "unsupported";
    unavailable.countersAvailable = false;
    unavailable.counters.emplace("must_not_leak", 9);
    sample = Snapshot({unavailable});
    const auto& unavailableOutput = sample.find("components")->array[0];
    HS_CHECK(unavailableOutput.find("counters")->type == jsonlite::Type::Null);
    HS_CHECK(unavailableOutput.find("counters_truncated") == nullptr);
}

void TestDisabledAndUnavailableDiagnosticsAreIsolated() {
    edr::EventBus bus;
    edr::HealthHeartbeat disabled(1, &bus, nullptr, "kept-summary", nullptr,
                                  nullptr);
    auto sample = jsonlite::parse(disabled.Snapshot());
    HS_CHECK(sample.find("diagnostics")->asString() == "unsupported");
    HS_CHECK(sample.find("components")->array.empty());
    HS_CHECK(!sample.find("components_truncated")->asBool());
    HS_CHECK(sample.find("collectors")->asString() == "kept-summary");
    HS_CHECK(sample.find("uptime_s")->asNumber() == 0);
    HS_CHECK(!sample.find("reporter_enabled")->asBool());
    HS_CHECK(sample.find("reporter_queued")->type == jsonlite::Type::Null);
    HS_CHECK(sample.find("reporter_dropped")->type == jsonlite::Type::Null);
    HS_CHECK(sample.find("reporter_spool_state")->asString() == "disabled");
    HS_CHECK(sample.find("reporter_spool_errors")->type == jsonlite::Type::Null);
    HS_CHECK(!sample.find("event_reporter_enabled")->asBool());
    HS_CHECK(sample.find("event_reporter_queued")->type == jsonlite::Type::Null);
    HS_CHECK(sample.find("event_reporter_dropped")->type == jsonlite::Type::Null);

    edr::HealthHeartbeat unavailable(1, &bus, nullptr, "kept-summary", nullptr,
        nullptr, []() -> std::vector<edr::HealthComponent> {
            throw std::runtime_error("diagnostics unavailable");
        });
    sample = jsonlite::parse(unavailable.Snapshot(23));
    HS_CHECK(sample.find("diagnostics")->asString() == "unavailable");
    HS_CHECK(sample.find("components")->array.empty());
    HS_CHECK(!sample.find("components_truncated")->asBool());
    HS_CHECK(sample.find("collectors")->asString() == "kept-summary");
    HS_CHECK(sample.find("uptime_s")->asNumber() == 23);
}

void TestMalformedUtf8IsNotEmitted() {
    edr::HealthComponent component;
    component.name = std::string("bad-\xc0", 5); // illegal leading byte
    component.state = std::string("bad-\x80", 5); // stray continuation
    component.lastSuccess100ns = std::string("bad-\xe2\x82", 6);
    component.replayState = std::string("bad-\xf4\x90\x80\x80", 8);
    component.countersAvailable = true;
    component.counters.emplace(std::string("bad-\xed\xa0\x80", 7), 1);

    const std::string malformedSummary("summary-\xc0", 9);
    edr::EventBus bus;
    edr::HealthHeartbeat heartbeat(1, &bus, nullptr, malformedSummary,
        nullptr, nullptr, [&component] {
            return std::vector<edr::HealthComponent>{component};
        });
    const std::string output = heartbeat.Snapshot();
    HS_CHECK(IsStrictUtf8(output));
    const auto parsed = jsonlite::parse(output);
    const std::string replacement("\xef\xbf\xbd", 3);
    const auto hasReplacement = [&replacement](const std::string& value) {
        return value.find(replacement) != std::string::npos;
    };
    const std::string& parsedSummary = parsed.find("collectors")->asString();
    HS_CHECK(IsStrictUtf8(parsedSummary));
    HS_CHECK(parsedSummary.find("summary-") == 0);
    HS_CHECK(hasReplacement(parsedSummary));
    const auto& parsedComponent = parsed.find("components")->array[0];
    const std::string& parsedName = parsedComponent.find("name")->asString();
    const std::string& parsedState = parsedComponent.find("state")->asString();
    const std::string& parsedLastSuccess =
        parsedComponent.find("last_success_100ns")->asString();
    const std::string& parsedReplayState =
        parsedComponent.find("replay_state")->asString();
    HS_CHECK(IsStrictUtf8(parsedName));
    HS_CHECK(IsStrictUtf8(parsedState));
    HS_CHECK(IsStrictUtf8(parsedLastSuccess));
    HS_CHECK(IsStrictUtf8(parsedReplayState));
    HS_CHECK(parsedName == std::string("bad-") + replacement);
    HS_CHECK(parsedState.find("bad-") == 0 && hasReplacement(parsedState));
    HS_CHECK(parsedLastSuccess.find("bad-") == 0 && hasReplacement(parsedLastSuccess));
    HS_CHECK(parsedReplayState.find("bad-") == 0 && hasReplacement(parsedReplayState));
    for (const auto& counter : parsedComponent.find("counters")->object) {
        HS_CHECK(IsStrictUtf8(counter.first));
        HS_CHECK(counter.first.find("bad-") == 0 && hasReplacement(counter.first));
    }
}

void TestUtf8SanitizationPreservesThe4096ByteLimit() {
    edr::HealthComponent component;
    component.name = std::string(4095, 'n') + "\xc0"; // replacement expands at limit
    component.state = std::string(4094, 's') + "\xe4\xb8\xad"; // scalar crosses limit

    edr::EventBus bus;
    const std::string summary = std::string(4095, 'm') + "\x80";
    edr::HealthHeartbeat heartbeat(1, &bus, nullptr, summary, nullptr, nullptr,
        [&component] { return std::vector<edr::HealthComponent>{component}; });
    const std::string output = heartbeat.Snapshot();
    HS_CHECK(IsStrictUtf8(output));
    const auto parsed = jsonlite::parse(output);
    const std::string& parsedSummary = parsed.find("collectors")->asString();
    const auto& parsedComponent = parsed.find("components")->array[0];
    const std::string& parsedName = parsedComponent.find("name")->asString();
    const std::string& parsedState = parsedComponent.find("state")->asString();
    HS_CHECK(IsStrictUtf8(parsedSummary));
    HS_CHECK(IsStrictUtf8(parsedName));
    HS_CHECK(IsStrictUtf8(parsedState));
    HS_CHECK(parsedSummary.size() <= 4096);
    HS_CHECK(parsedName.size() <= 4096);
    HS_CHECK(parsedState.size() == 4094);
    HS_CHECK(parsedSummary == std::string(4095, 'm'));
    HS_CHECK(parsedName == std::string(4095, 'n'));
}

void TestHealthStringsRoundTripJsonEscapesAndNul() {
    std::string expected = "before";
    expected.push_back('\0');
    expected += " quote\" slash\\ line\nend";
    edr::HealthComponent component;
    component.name = expected;

    edr::EventBus bus;
    edr::HealthHeartbeat heartbeat(1, &bus, nullptr, expected, nullptr, nullptr,
        [&component] { return std::vector<edr::HealthComponent>{component}; });
    const std::string output = heartbeat.Snapshot();
    HS_CHECK(output.find('\0') == std::string::npos);
    HS_CHECK(output.find("\\u0000") != std::string::npos);
    const auto parsed = jsonlite::parse(output);
    HS_CHECK(parsed.find("collectors")->asString() == expected);
    HS_CHECK(parsed.find("components")->array[0].find("name")->asString() ==
             expected);
}

void TestReporterSpoolFailuresStayPerReporter() {
    edr::Reporter failedAlert("", "", 2, {},
        edr::ReporterSpoolOptions{"health-alert-spool-never-opened"});
    edr::Reporter untouchedEvent("https://example.invalid/ingest", "", 2, {},
        edr::ReporterSpoolOptions{"health-event-spool-never-opened"});
    HS_CHECK(!failedAlert.Start());

    edr::HealthHeartbeat heartbeat(1, nullptr, nullptr, "", &failedAlert,
                                    &untouchedEvent);
    const auto sample = jsonlite::parse(heartbeat.Snapshot());
    HS_CHECK(sample.find("reporter_runtime_state")->asString() == "start_failed");
    const std::string& alertSpoolState =
        sample.find("reporter_spool_state")->asString();
    HS_CHECK(alertSpoolState.find("failed: ") == 0);
    HS_CHECK(alertSpoolState.find("endpoint is not configured") !=
             std::string::npos);
    HS_CHECK(sample.find("reporter_spool_errors")->asNumber() > 0);
    HS_CHECK(sample.find("event_reporter_runtime_state")->asString() ==
             "not_started");
    HS_CHECK(sample.find("event_reporter_spool_state")->asString() ==
             "not_started");
    HS_CHECK(sample.find("event_reporter_spool_errors")->asNumber() == 0);
}

} // namespace

void RunHealthSnapshotTests() {
    std::fprintf(stderr, "[health_snapshot] event bus delivery diagnostics\n");
    TestEventBusLossBreakdown();
    std::fprintf(stderr, "[health_snapshot] component truncation boundary\n");
    TestComponentLimitBoundaryAndNullBus();
    std::fprintf(stderr, "[health_snapshot] counter limit and availability\n");
    TestCounterLimitAndUnavailableCounters();
    std::fprintf(stderr, "[health_snapshot] diagnostics failure isolation\n");
    TestDisabledAndUnavailableDiagnosticsAreIsolated();
    std::fprintf(stderr, "[health_snapshot] malformed UTF-8 fields\n");
    TestMalformedUtf8IsNotEmitted();
    std::fprintf(stderr, "[health_snapshot] UTF-8 bounded-prefix behavior\n");
    TestUtf8SanitizationPreservesThe4096ByteLimit();
    std::fprintf(stderr, "[health_snapshot] JSON escaping round trip\n");
    TestHealthStringsRoundTripJsonEscapesAndNul();
    std::fprintf(stderr, "[health_snapshot] reporter spool field isolation\n");
    TestReporterSpoolFailuresStayPerReporter();
}
