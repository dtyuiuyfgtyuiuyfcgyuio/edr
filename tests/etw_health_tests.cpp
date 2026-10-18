/* Fake-query tests for ETW session health projection. */
#include "etw_health_tests.h"

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

#include <windows.h>

#include "etw_health.h"

namespace {

#define ETW_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("ETW health test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

void TestSessionLossCountersAndIdentity() {
    std::wstring queried;
    edr::EtwSessionQueryFn query = [&](const std::wstring& name) {
        queried = name;
        edr::EtwSessionQueryResult result;
        result.queryStatus = ERROR_SUCCESS;
        result.eventsLost = 11;
        result.logBuffersLost = 2;
        result.realTimeBuffersLost = 3;
        return result;
    };
    const auto sample = edr::SampleEtwSessionHealth(
        L"EDR-Test-Session", true, query);
    ETW_CHECK(queried == L"EDR-Test-Session");
    ETW_CHECK(sample.supported && sample.running && sample.state == "running");
    ETW_CHECK(sample.countersAvailable);
    ETW_CHECK(sample.counters.at("worker_active") == 1);
    ETW_CHECK(sample.counters.at("session_query_available") == 1);
    ETW_CHECK(sample.counters.at("session_query_status") == ERROR_SUCCESS);
    ETW_CHECK(sample.counters.at("events_lost") == 11);
    ETW_CHECK(sample.counters.at("log_buffers_lost") == 2);
    ETW_CHECK(sample.counters.at("realtime_buffers_lost") == 3);
}

void TestQueryFailureIsExplicitWithoutInventedLossValues() {
    edr::EtwSessionQueryFn query = [](const std::wstring&) {
        edr::EtwSessionQueryResult result;
        result.queryStatus = ERROR_WMI_INSTANCE_NOT_FOUND;
        return result;
    };
    const auto sample = edr::SampleEtwSessionHealth(L"EDR-Missing", true, query);
    ETW_CHECK(sample.supported && sample.running &&
              sample.state == "session_query_failed");
    ETW_CHECK(sample.countersAvailable);
    ETW_CHECK(sample.counters.at("worker_active") == 1);
    ETW_CHECK(sample.counters.at("session_query_available") == 0);
    ETW_CHECK(sample.counters.at("session_query_status") ==
              ERROR_WMI_INSTANCE_NOT_FOUND);
    ETW_CHECK(sample.counters.find("events_lost") == sample.counters.end());
    ETW_CHECK(sample.counters.find("log_buffers_lost") == sample.counters.end());
    ETW_CHECK(sample.counters.find("realtime_buffers_lost") == sample.counters.end());
}

void TestStoppedWorkerRemainsObservable() {
    edr::EtwSessionQueryFn query = [](const std::wstring&) {
        edr::EtwSessionQueryResult result;
        result.queryStatus = ERROR_SUCCESS;
        result.eventsLost = 4;
        return result;
    };
    const auto sample = edr::SampleEtwSessionHealth(L"EDR-Stopped", false, query);
    ETW_CHECK(sample.supported && !sample.running && sample.state == "stopped");
    ETW_CHECK(sample.countersAvailable);
    ETW_CHECK(sample.counters.at("worker_active") == 0);
    ETW_CHECK(sample.counters.at("session_query_available") == 1);
    ETW_CHECK(sample.counters.at("events_lost") == 4);
}

void TestQueryExceptionFailsExplicitly() {
    edr::EtwSessionQueryFn query = [](const std::wstring&) -> edr::EtwSessionQueryResult {
        throw std::runtime_error("injected query failure");
    };
    const auto sample = edr::SampleEtwSessionHealth(L"EDR-Throw", false, query);
    ETW_CHECK(sample.supported && !sample.running &&
              sample.state == "session_query_failed");
    ETW_CHECK(sample.countersAvailable);
    ETW_CHECK(sample.counters.at("session_query_available") == 0);
    ETW_CHECK(sample.counters.at("session_query_status") != ERROR_SUCCESS);
}

void TestInvalidSessionNamesFailBeforeQuery() {
    const auto empty = edr::QueryEtwSessionByName(L"");
    const auto embeddedNull = edr::QueryEtwSessionByName(
        std::wstring(L"EDR-Test\0Other", 14));
    const auto tooLong = edr::QueryEtwSessionByName(
        std::wstring(1025, L'x'));
    ETW_CHECK(empty.queryStatus == ERROR_INVALID_NAME);
    ETW_CHECK(embeddedNull.queryStatus == ERROR_INVALID_NAME);
    ETW_CHECK(tooLong.queryStatus == ERROR_INVALID_NAME);
}

void TestRealUniqueMissingSessionLookup() {
    const std::wstring uniqueName = L"EDR-Health-Missing-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
    const auto result = edr::QueryEtwSessionByName(uniqueName);
    ETW_CHECK(result.queryStatus != ERROR_SUCCESS);
}

} // namespace

void RunEtwHealthTests() {
    std::fprintf(stderr, "[etw_health] loss counters/session identity\n");
    TestSessionLossCountersAndIdentity();
    std::fprintf(stderr, "[etw_health] query failure\n");
    TestQueryFailureIsExplicitWithoutInventedLossValues();
    std::fprintf(stderr, "[etw_health] stopped worker\n");
    TestStoppedWorkerRemainsObservable();
    std::fprintf(stderr, "[etw_health] callback exception\n");
    TestQueryExceptionFailsExplicitly();
    std::fprintf(stderr, "[etw_health] invalid names\n");
    TestInvalidSessionNamesFailBeforeQuery();
    std::fprintf(stderr, "[etw_health] real missing session\n");
    TestRealUniqueMissingSessionLookup();
}
