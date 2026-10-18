/* Standalone regression tests for LogonSuccessDetector. */
#include <windows.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "logon_success_detector.h"

namespace {

void Check(bool value, const char* expression, int line) {
    if (!value) {
        throw std::runtime_error("logon success detector assertion at line " +
                                 std::to_string(line) + ": " + expression);
    }
}
#define CHECK(x) Check((x), #x, __LINE__)

uint64_t Now100ns() {
    FILETIME now{};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

edr::Event MakeLogon(const char* operation, const char* ip, uint64_t time,
                     const char* source = "security_log",
                     const char* endpoint = "host-a",
                     const char* domain = "CONTOSO",
                     const char* user = "alice",
                     const char* logonType = "3") {
    edr::Event event;
    event.type = EDR_EVT_LOGON;
    event.ts100ns = time;
    event.source = source ? source : "";
    event.fields[edr::field::kOperationType] = operation;
    if (ip) event.fields[edr::field::kSrcIp] = ip;
    if (endpoint) event.fields[edr::field::kEndpointId] = endpoint;
    if (domain) event.fields[edr::field::kTargetDomain] = domain;
    if (user) event.fields[edr::field::kTargetUser] = user;
    if (logonType) event.fields[edr::field::kLogonType] = logonType;
    return event;
}

bool Has(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

void TestInspectsAndDisabled() {
    CHECK(edr::LogonSuccessDetector::Inspects(EDR_EVT_LOGON));
    CHECK(!edr::LogonSuccessDetector::Inspects(EDR_EVT_PROCESS_START));
    edr::LogonSuccessDetector detector(false, 300, 32, 3);
    const uint64_t now = Now100ns();
    for (int i = 0; i < 4; ++i) {
        auto event = MakeLogon("LOGON_FAILURE", "192.0.2.9",
                               now + i * 10000000ULL);
        detector.Enrich(event);
    }
    auto success = MakeLogon("LOGON", "192.0.2.9", now + 50000000ULL);
    detector.Enrich(success);
    CHECK(!Has(success, "logon_success_score"));
    CHECK(detector.StateCount() == 0);

    edr::LogonSuccessDetector minClamped(true, 300, 32, 1);
    auto singleFailure = MakeLogon("LOGON_FAILURE", "192.0.2.10", Now100ns());
    minClamped.Enrich(singleFailure);
    auto singleSuccess = MakeLogon("LOGON", "192.0.2.10",
                                   Now100ns() + 10000000ULL);
    minClamped.Enrich(singleSuccess);
    CHECK(!Has(singleSuccess, "logon_success_score"));
}

void TestThresholdCanonicalKeyAndSingleUse() {
    edr::LogonSuccessDetector detector(true, 300, 32, 3);
    const uint64_t now = Now100ns();
    for (int i = 0; i < 2; ++i) {
        auto event = MakeLogon("LOGON_FAILURE", "192.0.2.9",
                               now + i * 10000000ULL, "security_log", "host-a",
                               "Contoso", "Alice");
        detector.Enrich(event);
    }
    auto otherDomain = MakeLogon("LOGON", "192.0.2.9", now + 25000000ULL,
                                 "security_log", "host-a", "OTHER", "alice");
    detector.Enrich(otherDomain);
    CHECK(!Has(otherDomain, "logon_success_score"));
    auto otherIp = MakeLogon("LOGON", "192.0.2.10", now + 26000000ULL,
                             "security_log", "host-a", "CONTOSO", "alice");
    detector.Enrich(otherIp);
    CHECK(!Has(otherIp, "logon_success_score"));

    auto third = MakeLogon("LOGON_FAILURE", "192.0.2.9", now + 30000000ULL,
                           "security_log", "host-a", "CONTOSO", "ALICE");
    detector.Enrich(third);
    auto success = MakeLogon("LOGON", "192.0.2.9", now + 40000000ULL,
                             "security_log", "host-a", "contoso", "alice");
    detector.Enrich(success);
    CHECK(success.fields.at("logon_success_score") == "75");
    CHECK(success.fields.at("logon_success_failures") == "3");
    CHECK(success.fields.at("logon_success_window_seconds") == "300");
    CHECK(detector.StateCount() == 3); // Consumed successes retain tombstones.

    auto duplicate = MakeLogon("LOGON", "192.0.2.9", now + 50000000ULL);
    detector.Enrich(duplicate);
    CHECK(!Has(duplicate, "logon_success_score"));
}

void TestRemoteTypesAndAddressValidation() {
    edr::LogonSuccessDetector detector(true, 300, 32, 2);
    const uint64_t now = Now100ns();
    auto rejectPair = [&](const char* ip, const char* type) {
        auto failure = MakeLogon("LOGON_FAILURE", ip, now, "security_log",
                                 "host-a", "D", "u", type);
        detector.Enrich(failure);
        auto success = MakeLogon("LOGON", ip, now + 10000000ULL,
                                 "security_log", "host-a", "D", "u", type);
        detector.Enrich(success);
        CHECK(!Has(success, "logon_success_score"));
    };
    rejectPair("127.0.0.1", "3");
    rejectPair("::1", "10");
    rejectPair("0.0.0.0", "3");
    rejectPair("::", "3");
    rejectPair("-", "3");
    rejectPair("192.0.2.8", "2");

    auto v4a = MakeLogon("LOGON_FAILURE", "192.0.2.8", now + 20000000ULL,
                         "security_log", "host-a", "D", "v4", "10");
    detector.Enrich(v4a);
    auto v4b = MakeLogon("LOGON_FAILURE", "192.0.2.8", now + 30000000ULL,
                         "security_log", "host-a", "D", "v4", "10");
    detector.Enrich(v4b);
    auto v4ok = MakeLogon("LOGON", "192.0.2.8", now + 40000000ULL,
                          "security_log", "host-a", "D", "v4", "10");
    detector.Enrich(v4ok);
    CHECK(Has(v4ok, "logon_success_score"));

    auto v6a = MakeLogon("LOGON_FAILURE", "2001:db8::5", now + 50000000ULL,
                         "security_log", "host-a", "D", "v6", "3");
    detector.Enrich(v6a);
    auto v6b = MakeLogon("LOGON_FAILURE", "2001:0DB8:0:0:0:0:0:5",
                         now + 60000000ULL, "security_log", "host-a", "D",
                         "V6", "3");
    detector.Enrich(v6b);
    auto v6ok = MakeLogon("LOGON", "2001:db8::5", now + 70000000ULL,
                          "security_log", "host-a", "D", "v6", "3");
    detector.Enrich(v6ok);
    CHECK(Has(v6ok, "logon_success_score"));

    auto upnFailure = MakeLogon("LOGON_FAILURE", "2001:db8::8",
                                now + 80000000ULL, "security_log", "host-a",
                                "", "Bob@Example.COM", "3");
    detector.Enrich(upnFailure);
    auto upnFailure2 = MakeLogon("LOGON_FAILURE", "2001:db8::8",
                                 now + 90000000ULL, "security_log", "host-a",
                                 "", "bob@example.com", "3");
    detector.Enrich(upnFailure2);
    auto upnSuccess = MakeLogon("LOGON", "2001:db8::8",
                                now + 100000000ULL, "security_log", "host-a",
                                "example.com", "BOB", "3");
    detector.Enrich(upnSuccess);
    CHECK(Has(upnSuccess, "logon_success_score"));
}

void TestScopeAndInvalidFields() {
    edr::LogonSuccessDetector detector(true, 300, 64, 2);
    const uint64_t now = Now100ns();
    auto first = MakeLogon("LOGON_FAILURE", "198.51.100.9", now);
    detector.Enrich(first);
    auto differentEndpoint = MakeLogon("LOGON", "198.51.100.9",
                                       now + 10000000ULL, "security_log",
                                       "host-b");
    detector.Enrich(differentEndpoint);
    CHECK(!Has(differentEndpoint, "logon_success_score"));
    auto differentSource = MakeLogon("LOGON", "198.51.100.9",
                                     now + 20000000ULL, "other_source", "host-a");
    detector.Enrich(differentSource);
    CHECK(!Has(differentSource, "logon_success_score"));

    auto invalidDomain = MakeLogon("LOGON_FAILURE", "203.0.113.1",
                                   now + 30000000ULL);
    invalidDomain.fields[edr::field::kTargetDomain] = std::string("d\0x", 3);
    detector.Enrich(invalidDomain);
    auto noPair = MakeLogon("LOGON", "203.0.113.1", now + 40000000ULL);
    detector.Enrich(noPair);
    CHECK(!Has(noPair, "logon_success_score"));

    auto tooLong = MakeLogon("LOGON_FAILURE", "203.0.113.2",
                             now + 50000000ULL);
    tooLong.fields[edr::field::kTargetUser] = std::string(256, 'u');
    detector.Enrich(tooLong);
    auto noLongPair = MakeLogon("LOGON", "203.0.113.2", now + 60000000ULL);
    noLongPair.fields[edr::field::kTargetUser] = std::string(256, 'u');
    detector.Enrich(noLongPair);
    CHECK(!Has(noLongPair, "logon_success_score"));
}

void TestDelimitedScopeValuesDoNotCollide() {
    edr::LogonSuccessDetector detector(true, 300, 32, 2);
    const uint64_t now = Now100ns();
    auto failure = MakeLogon("LOGON_FAILURE", "198.51.100.40", now,
                             "source|part", "endpoint", "DOM", "user");
    detector.Enrich(failure);
    auto wrongScope = MakeLogon("LOGON", "198.51.100.40", now + 10000000ULL,
                                "source", "part|endpoint", "DOM", "user");
    detector.Enrich(wrongScope);
    CHECK(!Has(wrongScope, "logon_success_score"));
    auto wrongAccount = MakeLogon("LOGON", "198.51.100.40",
                                  now + 20000000ULL, "source|part", "endpoint",
                                  "DOM|other", "user");
    detector.Enrich(wrongAccount);
    CHECK(!Has(wrongAccount, "logon_success_score"));
}

void TestWindowOrderingFutureAndCapacity() {
    edr::LogonSuccessDetector detector(true, 30, 2, 2);
    const uint64_t now = Now100ns();
    auto a = MakeLogon("LOGON_FAILURE", "198.51.100.1", now);
    detector.Enrich(a);
    auto late = MakeLogon("LOGON_FAILURE", "198.51.100.1", now - 10000000ULL);
    detector.Enrich(late); // out of order must not roll the state back
    auto future = MakeLogon("LOGON_FAILURE", "198.51.100.1",
                            now + 301ULL * 10000000ULL);
    detector.Enrich(future);
    auto success = MakeLogon("LOGON", "198.51.100.1", now + 10000000ULL);
    detector.Enrich(success);
    CHECK(!Has(success, "logon_success_score"));

    auto b1 = MakeLogon("LOGON_FAILURE", "198.51.100.2", now + 20000000ULL);
    auto b2 = MakeLogon("LOGON_FAILURE", "198.51.100.2", now + 21000000ULL);
    detector.Enrich(b1);
    detector.Enrich(b2);
    auto expired = MakeLogon("LOGON", "198.51.100.2",
                             now + 51ULL * 10000000ULL);
    detector.Enrich(expired);
    CHECK(!Has(expired, "logon_success_score"));

    for (int i = 1; i <= 8; ++i) {
        auto event = MakeLogon("LOGON_FAILURE",
            ("198.51.100." + std::to_string(i + 10)).c_str(),
            now + (60 + i) * 10000000ULL);
        detector.Enrich(event);
        CHECK(detector.StateCount() <= 2);
    }
}

void TestSuccessConsumesSubthresholdRun() {
    edr::LogonSuccessDetector detector(true, 300, 32, 3);
    const uint64_t now = Now100ns();
    auto failure = MakeLogon("LOGON_FAILURE", "192.0.2.90", now);
    detector.Enrich(failure);
    auto firstSuccess = MakeLogon("LOGON", "192.0.2.90", now + 10000000ULL);
    detector.Enrich(firstSuccess);
    CHECK(!Has(firstSuccess, "logon_success_score"));
    auto laterFailure = MakeLogon("LOGON_FAILURE", "192.0.2.90",
                                  now + 20000000ULL);
    detector.Enrich(laterFailure);
    auto laterSuccess = MakeLogon("LOGON", "192.0.2.90",
                                  now + 30000000ULL);
    detector.Enrich(laterSuccess);
    CHECK(!Has(laterSuccess, "logon_success_score"));
}

void TestTombstoneRejectsDelayedEventsAndExpires() {
    edr::LogonSuccessDetector detector(true, 30, 32, 2);
    const uint64_t now = Now100ns();
    auto first = MakeLogon("LOGON_FAILURE", "192.0.2.91", now);
    auto second = MakeLogon("LOGON_FAILURE", "192.0.2.91",
                            now + 10000000ULL);
    detector.Enrich(first);
    detector.Enrich(second);
    auto success = MakeLogon("LOGON", "192.0.2.91", now + 20000000ULL);
    detector.Enrich(success);
    CHECK(Has(success, "logon_success_score"));
    CHECK(detector.StateCount() == 1); // consumed episode tombstone

    auto delayed1 = MakeLogon("LOGON_FAILURE", "192.0.2.91",
                              now + 15000000ULL);
    auto delayed2 = MakeLogon("LOGON_FAILURE", "192.0.2.91",
                              now + 16000000ULL);
    detector.Enrich(delayed1);
    detector.Enrich(delayed2);
    auto delayedSuccess = MakeLogon("LOGON", "192.0.2.91",
                                   now + 17000000ULL);
    detector.Enrich(delayedSuccess);
    CHECK(!Has(delayedSuccess, "logon_success_score"));

    /* A new, ordered episode after the consumed success can still alert. */
    auto fresh1 = MakeLogon("LOGON_FAILURE", "192.0.2.91",
                            now + 30000000ULL);
    auto fresh2 = MakeLogon("LOGON_FAILURE", "192.0.2.91",
                            now + 31000000ULL);
    detector.Enrich(fresh1);
    detector.Enrich(fresh2);
    auto freshSuccess = MakeLogon("LOGON", "192.0.2.91",
                                 now + 32000000ULL);
    detector.Enrich(freshSuccess);
    CHECK(Has(freshSuccess, "logon_success_score"));

    auto expired = MakeLogon("LOGON_FAILURE", "192.0.2.91",
                             now + 640000000ULL);
    detector.Enrich(expired);
    CHECK(detector.StateCount() == 1);

    auto successFirst = MakeLogon("LOGON", "192.0.2.92", now + 700000000ULL);
    detector.Enrich(successFirst);
    auto delayedFailure1 = MakeLogon("LOGON_FAILURE", "192.0.2.92",
                                     now + 690000000ULL);
    auto delayedFailure2 = MakeLogon("LOGON_FAILURE", "192.0.2.92",
                                     now + 695000000ULL);
    detector.Enrich(delayedFailure1);
    detector.Enrich(delayedFailure2);
    auto repeat = MakeLogon("LOGON", "192.0.2.92", now + 710000000ULL);
    detector.Enrich(repeat);
    CHECK(!Has(repeat, "logon_success_score"));
}

} // namespace

int main() {
    try {
        TestInspectsAndDisabled();
        TestThresholdCanonicalKeyAndSingleUse();
        TestRemoteTypesAndAddressValidation();
        TestScopeAndInvalidFields();
        TestDelimitedScopeValuesDoNotCollide();
        TestWindowOrderingFutureAndCapacity();
        TestSuccessConsumesSubthresholdRun();
        TestTombstoneRejectsDelayedEventsAndExpires();
        std::cout << "logon_success_detector_tests: all tests passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
