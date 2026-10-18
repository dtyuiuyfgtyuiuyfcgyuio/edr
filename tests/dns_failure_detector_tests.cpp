/* Focused behavior tests for DnsFailureDetector. */
#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>

#include "dns_failure_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define DNS_FAILURE_CHECK(c) Check((c), #c, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error("dns failure detector check failed at line " +
                                 std::to_string(line) + ": " + expression);
}

uint64_t CurrentFileTime() {
    FILETIME now{};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

edr::Event Query(const char* status, const char* name, uint64_t timestamp,
                 uint32_t pid = 4200, uint64_t processStart = 0,
                 const char* endpoint = "host-a", const char* source = "dns_etw",
                 const char* image = "C:\\Program Files\\App\\client.exe") {
    edr::Event event;
    event.type = EDR_EVT_DNS_QUERY;
    event.ts100ns = timestamp;
    event.pid = pid;
    event.processStartTime100ns = processStart == 0 ? 1 : processStart;
    event.source = source;
    event.disposition = edr::EventDisposition::ReportAndEvaluate;
    event.fields[std::string(edr::field::kType)] = "DNS_QUERY";
    event.fields[std::string(edr::field::kSource)] = source;
    event.fields[std::string(edr::field::kEndpointId)] = endpoint;
    event.fields[std::string(edr::field::kImage)] = image;
    event.fields[std::string(edr::field::kDnsQueryName)] = name;
    if (status != nullptr) event.fields[std::string(edr::field::kDnsQueryStatus)] = status;
    event.fields[std::string("dns_phase")] = "completed";
    return event;
}

bool Has(const edr::Event& event, const char* key) {
    return event.fields.find(std::string(key)) != event.fields.end();
}

const std::string& Value(const edr::Event& event, const char* key) {
    return event.fields.at(std::string(key));
}

void TestExactDnsStatusesAndFailureMetrics() {
    edr::DnsFailureDetector detector(true, 60, 64, 3, 2, 60, 2);
    const uint64_t now = CurrentFileTime();
    edr::Event first = Query("9003", "alpha.example.com", now);
    first.fields[std::string(edr::field::kDnsEntropy)] = "4.0";
    detector.Enrich(first);
    DNS_FAILURE_CHECK(!Has(first, "dns_failure_score"));

    edr::Event success = Query("0", "beta.example.com", now + 1);
    detector.Enrich(success);
    DNS_FAILURE_CHECK(!Has(success, "dns_failure_score"));

    edr::Event status3 = Query("3", "gamma.example.com", now + 2);
    status3.fields[std::string(edr::field::kDnsEntropy)] = "4.2";
    detector.Enrich(status3);
    DNS_FAILURE_CHECK(!Has(status3, "dns_failure_score"));

    edr::Event secondFailure = Query("9003", "gamma.example.com", now + 3);
    secondFailure.fields[std::string(edr::field::kDnsEntropy)] = "4.2";
    detector.Enrich(secondFailure);
    DNS_FAILURE_CHECK(Has(secondFailure, "dns_failure_score"));
    DNS_FAILURE_CHECK(Value(secondFailure, "dns_failure_score") == "75");
    DNS_FAILURE_CHECK(Value(secondFailure, "dns_failure_query_count") == "3");
    DNS_FAILURE_CHECK(Value(secondFailure, "dns_failure_nxdomain_count") == "2");
    DNS_FAILURE_CHECK(Value(secondFailure, "dns_failure_distinct_names") == "2");
    DNS_FAILURE_CHECK(Value(secondFailure, "dns_failure_percent") == "66");
    DNS_FAILURE_CHECK(Value(secondFailure, "dns_failure_high_entropy_count") == "2");
    DNS_FAILURE_CHECK(Value(secondFailure, "dns_failure_window_seconds") == "60");
}

void TestMinimumSampleDistinctFailuresAndSuccesses() {
    edr::DnsFailureDetector detector(true, 60, 64, 4, 3, 60, 2);
    const uint64_t now = CurrentFileTime();
    edr::Event event;
    for (uint64_t i = 0; i < 4; ++i) {
        event = Query("9003", "same.example.com", now + i);
        detector.Enrich(event);
        DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
    }

    edr::DnsFailureDetector successDetector(true, 60, 64, 4, 3, 60, 2);
    for (uint64_t i = 0; i < 4; ++i) {
        event = Query("0", (i % 2) ? "two.example.com" : "one.example.com",
                      now + i);
        successDetector.Enrich(event);
        DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
    }
}

void TestSoftScoreAndOneEmissionPerEpisode() {
    edr::DnsFailureDetector detector(true, 60, 64, 4, 3, 75, 2);
    const uint64_t now = CurrentFileTime();
    edr::Event event;
    const char* names[] = {"one.example.com", "two.example.com",
                           "three.example.com"};
    for (uint64_t i = 0; i < 3; ++i) {
        event = Query("9003", names[i], now + i);
        event.fields[std::string(edr::field::kDnsEntropy)] = "2.0";
        detector.Enrich(event);
        DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
    }
    event = Query("0", "four.example.com", now + 3);
    detector.Enrich(event);
    DNS_FAILURE_CHECK(Value(event, "dns_failure_score") == "55");
    DNS_FAILURE_CHECK(Value(event, "dns_failure_query_count") == "4");
    DNS_FAILURE_CHECK(Value(event, "dns_failure_percent") == "75");
    DNS_FAILURE_CHECK(Value(event, "dns_failure_high_entropy_count") == "0");

    event = Query("9003", "five.example.com", now + 4);
    event.fields[std::string(edr::field::kDnsEntropy)] = "4.1";
    detector.Enrich(event);
    DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));

    // High-entropy evidence may promote one already-emitted soft episode once.
    const char* upgradeNames[] = {"one.example.com", "two.example.com",
                                  "three.example.com", "four.example.com",
                                  "five.example.com"};
    edr::DnsFailureDetector upgrade(true, 60, 64, 3, 3, 100, 2);
    edr::Event upgraded;
    for (uint64_t i = 0; i < 5; ++i) {
        event = Query("9003", upgradeNames[i], now + 10 + i);
        if (i == 0 || i == 3) event.fields[std::string(edr::field::kDnsEntropy)] = "4.0";
        upgrade.Enrich(event);
        if (i == 2) DNS_FAILURE_CHECK(Value(event, "dns_failure_score") == "55");
        if (i == 3) upgraded = event;
    }
    DNS_FAILURE_CHECK(Value(upgraded, "dns_failure_score") == "75");
    DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
}

void TestMinDistinctIsIndependentAndEndpointsMayBeAbsent() {
    edr::DnsFailureDetector detector(true, 60, 64, 2, 4, 100, 1);
    const uint64_t now = CurrentFileTime();
    const char* names[] = {"one.example.com", "two.example.com",
                           "three.example.com", "four.example.com"};
    edr::Event event;
    for (uint64_t i = 0; i < 4; ++i) {
        event = Query("9003", names[i], now + i);
        event.fields.erase(std::string(edr::field::kEndpointId));
        detector.Enrich(event);
        if (i < 3) DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
    }
    DNS_FAILURE_CHECK(Value(event, "dns_failure_score") == "55");
}

void TestHighEntropyFailuresReachSeventyFive() {
    edr::DnsFailureDetector detector(true, 60, 64, 3, 3, 100, 2);
    const uint64_t now = CurrentFileTime();
    edr::Event event;
    const char* names[] = {"one.example.com", "two.example.com",
                           "three.example.com"};
    for (uint64_t i = 0; i < 3; ++i) {
        event = Query("9003", names[i], now + i);
        event.fields[std::string(edr::field::kDnsEntropy)] = i < 2 ? "3.6" : "4.1";
        detector.Enrich(event);
    }
    DNS_FAILURE_CHECK(Value(event, "dns_failure_score") == "75");
    DNS_FAILURE_CHECK(Value(event, "dns_failure_high_entropy_count") == "3");
}

void TestUnknownStatusAndInvalidEntropyAreNotEvidence() {
    edr::DnsFailureDetector detector(true, 60, 64, 2, 2, 60, 1);
    const uint64_t now = CurrentFileTime();
    edr::Event event = Query("3", "one.example.com", now);
    event.fields[std::string(edr::field::kDnsEntropy)] = "4.9";
    detector.Enrich(event);
    event = Query("09003", "two.example.com", now + 1);
    event.fields[std::string(edr::field::kDnsEntropy)] = "4.9";
    detector.Enrich(event);
    event = Query("9003", "three.example.com", now + 2);
    event.fields[std::string(edr::field::kDnsEntropy)] = "NaN";
    detector.Enrich(event);
    event = Query("9003", "four.example.com", now + 3);
    event.fields[std::string(edr::field::kDnsEntropy)] = "4.1trailing";
    detector.Enrich(event);
    DNS_FAILURE_CHECK(Value(event, "dns_failure_score") == "55");
    DNS_FAILURE_CHECK(Value(event, "dns_failure_query_count") == "2");
    DNS_FAILURE_CHECK(Value(event, "dns_failure_nxdomain_count") == "2");
    DNS_FAILURE_CHECK(Value(event, "dns_failure_high_entropy_count") == "0");
}

void TestInvalidAndLocalNamesAreIgnored() {
    edr::DnsFailureDetector detector(true, 60, 64, 1, 1, 1, 1);
    const uint64_t now = CurrentFileTime();
    const char* names[] = {"localhost", "host.local", "1.2.3.4",
                           "4.3.2.1.in-addr.arpa", "::1", "bad..example.com",
                           "xn--bcher-kva.de", "single", "name.test",
                           "-bad.example.com", "bad-.example.com"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        edr::Event event = Query("9003", names[i], now + i);
        event.fields[std::string(edr::field::kDnsEntropy)] = "4.0";
        detector.Enrich(event);
        DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
    }
    DNS_FAILURE_CHECK(detector.StateCount() == 0);
}

void TestProcessEndpointAndSourceScopesDoNotCollide() {
    edr::DnsFailureDetector detector(true, 60, 64, 2, 2, 100, 1);
    const uint64_t now = CurrentFileTime();
    edr::Event event = Query("9003", "one.example.com", now, 100, now - 1);
    detector.Enrich(event);
    event = Query("9003", "two.example.com", now + 1, 100, now);
    detector.Enrich(event);
    DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
    DNS_FAILURE_CHECK(detector.StateCount() == 2);

    edr::Event bare = Query("9003", "one.example.com", now + 2, 0, 0);
    bare.processIdentity = "4200";
    detector.Enrich(bare);
    DNS_FAILURE_CHECK(detector.StateCount() == 2);
    bare.processIdentity = "pid:4200";
    detector.Enrich(bare);
    DNS_FAILURE_CHECK(detector.StateCount() == 2);
    bare.processIdentity = "pid4200";
    detector.Enrich(bare);
    DNS_FAILURE_CHECK(detector.StateCount() == 2);

    edr::Event byIdentity = Query("9003", "one.example.com", now + 3, 0, 0);
    byIdentity.processIdentity = "{12345678-1234-1234-1234-123456789abc}";
    byIdentity.fields[std::string(edr::field::kImage)] = "C:\\程序\\客户.exe";
    detector.Enrich(byIdentity);
    DNS_FAILURE_CHECK(detector.StateCount() == 3);

    edr::Event invalidCreation = Query("9003", "one.example.com", now + 4,
                                       101, now + 5, "host-a", "dns_etw",
                                       "C:\\App\\client.exe");
    invalidCreation.processIdentity = "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}";
    detector.Enrich(invalidCreation);
    DNS_FAILURE_CHECK(detector.StateCount() == 3);

    edr::Event otherEndpoint = Query("9003", "one.example.com", now + 5,
                                     100, now - 1, "host-b", "dns_etw");
    detector.Enrich(otherEndpoint);
    DNS_FAILURE_CHECK(detector.StateCount() == 4);
    edr::Event otherSource = Query("9003", "one.example.com", now + 6,
                                   100, now - 1, "host-a", "dns_other");
    detector.Enrich(otherSource);
    DNS_FAILURE_CHECK(detector.StateCount() == 5);
}

void TestSlidingExpiryAllowsANewEpisodeAndRejectsLateFutureEvents() {
    edr::DnsFailureDetector detector(true, 10, 64, 3, 3, 75, 1);
    const uint64_t now = CurrentFileTime();
    const char* firstNames[] = {"one.example.com", "two.example.com",
                                "three.example.com"};
    edr::Event event;
    for (uint64_t i = 0; i < 3; ++i) {
        event = Query("9003", firstNames[i], now + i);
        event.fields[std::string(edr::field::kDnsEntropy)] = "4.0";
        detector.Enrich(event);
    }
    DNS_FAILURE_CHECK(Value(event, "dns_failure_score") == "75");

    event = Query("0", "safe.example.com", now + 12ULL * 10000000ULL);
    detector.Enrich(event);
    DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
    DNS_FAILURE_CHECK(Value(event, "dns_failure_query_count") == "1");

    const char* secondNames[] = {"four.example.com", "five.example.com",
                                 "six.example.com"};
    for (uint64_t i = 0; i < 3; ++i) {
        event = Query("9003", secondNames[i], now + (13ULL + i) * 10000000ULL);
        event.fields[std::string(edr::field::kDnsEntropy)] = "4.0";
        detector.Enrich(event);
    }
    DNS_FAILURE_CHECK(Value(event, "dns_failure_score") == "75");

    const uint64_t wallNow = CurrentFileTime();
    event = Query("9003", "late.example.com", wallNow - 1);
    detector.Enrich(event);
    DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
    event = Query("9003", "future.example.com",
                  wallNow + 301ULL * 10000000ULL);
    detector.Enrich(event);
    DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
}

void TestOnlyCompletedEvaluatedDnsEventsAndBoundedDisabledState() {
    edr::DnsFailureDetector detector(true, 60, 1, 1, 1, 1, 1);
    const uint64_t now = CurrentFileTime();
    edr::Event started = Query("9003", "one.example.com", now);
    started.disposition = edr::EventDisposition::ReportOnly;
    detector.Enrich(started);
    edr::Event phase = Query("9003", "one.example.com", now + 1);
    phase.fields[std::string("dns_phase")] = "started";
    detector.Enrich(phase);
    DNS_FAILURE_CHECK(detector.StateCount() == 0);
    DNS_FAILURE_CHECK(!Has(started, "dns_failure_score"));

    edr::Event event = Query("9003", "one.example.com", now + 2, 1);
    detector.Enrich(event);
    DNS_FAILURE_CHECK(Has(event, "dns_failure_score"));
    event = Query("9003", "two.example.com", now + 3, 2);
    detector.Enrich(event);
    DNS_FAILURE_CHECK(detector.StateCount() <= 1);
    DNS_FAILURE_CHECK(!edr::DnsFailureDetector::Inspects(EDR_EVT_LOGON));
    DNS_FAILURE_CHECK(edr::DnsFailureDetector::Inspects(EDR_EVT_DNS_QUERY));

    edr::DnsFailureDetector disabled(false, 60, 8, 1, 1, 1, 1);
    event = Query("9003", "disabled.example.com", now + 4);
    disabled.Enrich(event);
    DNS_FAILURE_CHECK(disabled.StateCount() == 0);
    DNS_FAILURE_CHECK(!Has(event, "dns_failure_score"));
}

} // namespace

int main() {
    try {
        TestExactDnsStatusesAndFailureMetrics();
        TestMinimumSampleDistinctFailuresAndSuccesses();
        TestSoftScoreAndOneEmissionPerEpisode();
        TestMinDistinctIsIndependentAndEndpointsMayBeAbsent();
        TestHighEntropyFailuresReachSeventyFive();
        TestUnknownStatusAndInvalidEntropyAreNotEvidence();
        TestInvalidAndLocalNamesAreIgnored();
        TestProcessEndpointAndSourceScopesDoNotCollide();
        TestSlidingExpiryAllowsANewEpisodeAndRejectsLateFutureEvents();
        TestOnlyCompletedEvaluatedDnsEventsAndBoundedDisabledState();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
    std::puts("dns failure detector tests passed");
    return 0;
}
