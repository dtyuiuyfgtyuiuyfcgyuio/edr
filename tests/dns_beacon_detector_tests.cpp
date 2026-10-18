/*
 * dns_beacon_detector_tests.cpp - Unit tests for DnsBeaconDetector.
 */
#include "dns_beacon_detector_tests.h"

#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>

#include "dns_beacon_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define DNS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "dns beacon detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event DnsQuery(uint32_t pid, const char* image, const char* domain,
                    const char* entropy, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_DNS_QUERY;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.processStartTime100ns = pid == 0 ? 0 : 1;
    event.source = "dns_test";
    event.disposition = edr::EventDisposition::ReportAndEvaluate;
    event.fields[edr::field::kType] = "DNS_QUERY";
    event.fields[edr::field::kSource] = event.source;
    event.fields[edr::field::kEndpointId] = "endpoint-a";
    event.fields["dns_phase"] = "completed";
    if (image) event.fields[edr::field::kImage] = image;
    if (domain) event.fields[edr::field::kDnsQueryName] = domain;
    if (entropy) event.fields[edr::field::kDnsEntropy] = entropy;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

uint64_t CurrentFileTime() {
    FILETIME now{};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

/* V1: pid-keyed attribution; fires when minQueryCount and
 * minHighEntropyCount are both met. */
void TestPidAttributionFlagged() {
    /* min 10 queries, min 5 high-entropy */
    edr::DnsBeaconDetector det(true, 300, 4096, 10, 5);
    const uint64_t base = 100000000000ULL;
    const char* image = "C:\\evil\\loader.exe";
    edr::Event last;

    for (int i = 0; i < 10; ++i) {
        last = DnsQuery(1001, image, "xyzrandomdomain.com", "3.9",
                        base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(last);
    }

    DNS_CHECK(HasField(last, edr::field::kDnsBeaconScore));
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconScore) == "10");
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconQueryCount) == "10");
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconHighEntropyCount) == "10");
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconWindowSeconds) == "300");
    DNS_CHECK(det.StateCount() == 1);
}

/* V2: does NOT fire when query count threshold is met but high-entropy
 * count is below minHighEntropyCount. */
void TestHighEntropyThresholdNotMet() {
    /* min 10 queries, but need 5 high-entropy; supply only low-entropy. */
    edr::DnsBeaconDetector det(true, 300, 4096, 10, 5);
    const uint64_t base = 200000000000ULL;
    edr::Event last;

    for (int i = 0; i < 15; ++i) {
        /* entropy "2.0" is below 3.5 threshold */
        last = DnsQuery(1002, "C:\\sys\\curl.exe", "example.com", "2.0",
                        base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(last);
    }

    DNS_CHECK(!HasField(last, edr::field::kDnsBeaconScore));
    DNS_CHECK(HasField(last, edr::field::kDnsBeaconQueryCount));
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconQueryCount) == "15");
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconHighEntropyCount) == "0");
}

/* V3: fires when minHighEntropyCount is 0 (volume-only mode). */
void TestVolumeOnlyMode() {
    edr::DnsBeaconDetector det(true, 300, 4096, 10, 0);
    const uint64_t base = 300000000000ULL;
    edr::Event last;

    for (int i = 0; i < 10; ++i) {
        last = DnsQuery(1003, "C:\\evil\\bot.exe", "normal.com", nullptr,
                        base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(last);
    }

    DNS_CHECK(HasField(last, edr::field::kDnsBeaconScore));
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconQueryCount) == "10");
    /* No entropy field supplied; highEntropyCount stays 0; satisfied by 0. */
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconHighEntropyCount) == "0");
}

/* V4: events without image and without pid are skipped (no attribution). */
void TestNoAttribution() {
    edr::DnsBeaconDetector det(true, 300, 4096, 5, 0);
    edr::Event event = DnsQuery(0, nullptr, "evil.io", "4.0", 1000);
    det.Enrich(event);
    DNS_CHECK(!HasField(event, edr::field::kDnsBeaconScore));
    DNS_CHECK(det.StateCount() == 0);
}

/* V5: window expiry resets the flag; fields re-fire after threshold re-met. */
void TestWindowExpiry() {
    edr::DnsBeaconDetector det(true, 60, 4096, 3, 0);
    const uint64_t base = 400000000000ULL;
    const char* image = "C:\\evil\\bot.exe";

    edr::Event a = DnsQuery(2001, image, "a.com", "2.0", base);
    det.Enrich(a);
    edr::Event b = DnsQuery(2001, image, "b.com", "2.0", base + 1000000ULL);
    det.Enrich(b);
    edr::Event c = DnsQuery(2001, image, "c.com", "2.0", base + 2000000ULL);
    det.Enrich(c);
    DNS_CHECK(HasField(c, edr::field::kDnsBeaconScore));

    /* Advance past 60s window to expire the key. */
    edr::Event d = DnsQuery(2001, image, "d.com", "2.0",
                            base + 700000000ULL); /* +70s */
    det.Enrich(d);
    DNS_CHECK(!HasField(d, edr::field::kDnsBeaconScore));
    DNS_CHECK(det.StateCount() == 1); /* re-created */

    /* Re-hit threshold in the new window. */
    edr::Event e = DnsQuery(2001, image, "e.com", "2.0",
                            base + 710000000ULL);
    det.Enrich(e);
    edr::Event f = DnsQuery(2001, image, "f.com", "2.0",
                            base + 720000000ULL);
    det.Enrich(f);
    DNS_CHECK(HasField(f, edr::field::kDnsBeaconScore));
    DNS_CHECK(f.fields.at(edr::field::kDnsBeaconQueryCount) == "3");
}

/* V6: disabled detector is a no-op. */
void TestDisabled() {
    edr::DnsBeaconDetector det(false, 300, 4096, 3, 0);
    const uint64_t base = 500000000000ULL;
    edr::Event last;
    for (int i = 0; i < 5; ++i) {
        last = DnsQuery(3001, "C:\\evil\\a.exe", "evil.com", "4.5",
                        base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(last);
    }
    DNS_CHECK(!HasField(last, edr::field::kDnsBeaconScore));
    DNS_CHECK(det.StateCount() == 0);
}

/* V7: capacity eviction bounds state size. */
void TestCapacityEviction() {
    edr::DnsBeaconDetector det(true, 300, 2, 5, 0);
    const uint64_t base = 600000000000ULL;
    for (uint32_t pid = 1; pid <= 3; ++pid) {
        edr::Event ev = DnsQuery(pid, "C:\\a.exe", "x.com", "4.0",
                                 base + static_cast<uint64_t>(pid) * 1000000ULL);
        det.Enrich(ev);
    }
    DNS_CHECK(det.StateCount() <= 2);
}

/* Image-only or PID-only attribution must not combine unrelated processes. */
void TestWeakIdentityDoesNotAccumulate() {
    edr::DnsBeaconDetector det(true, 300, 4096, 3, 0);
    const uint64_t base = 700000000000ULL;
    edr::Event imageOnly = DnsQuery(0, "C:\\Windows\\System32\\svchost.exe",
                                    "normal.com", "2.0", base);
    imageOnly.processIdentity.clear();
    det.Enrich(imageOnly);
    DNS_CHECK(!HasField(imageOnly, edr::field::kDnsBeaconScore));
    DNS_CHECK(det.StateCount() == 0);

    edr::Event pidOnly = DnsQuery(42, "C:\\Windows\\System32\\svchost.exe",
                                  "normal.com", "2.0", base + 1000000ULL);
    pidOnly.processStartTime100ns = 0;
    det.Enrich(pidOnly);
    DNS_CHECK(!HasField(pidOnly, edr::field::kDnsBeaconScore));
    DNS_CHECK(det.StateCount() == 0);
}

void TestStrictSlidingWindowAndExactBoundary() {
    edr::DnsBeaconDetector det(true, 10, 16, 2, 0);
    const uint64_t base = 800000000000ULL;
    auto a = DnsQuery(51, "C:\\app\\agent.exe", "a.example", "2.0", base);
    det.Enrich(a);
    auto b = DnsQuery(51, "C:\\app\\agent.exe", "b.example", "2.0",
                      base + 50000000ULL);
    det.Enrich(b);
    DNS_CHECK(HasField(b, edr::field::kDnsBeaconScore));
    DNS_CHECK(b.fields.at(edr::field::kDnsBeaconQueryCount) == "2");
    auto c = DnsQuery(51, "C:\\app\\agent.exe", "c.example", "2.0",
                      base + 100000000ULL);
    det.Enrich(c);
    DNS_CHECK(!HasField(c, edr::field::kDnsBeaconScore));
    DNS_CHECK(c.fields.at(edr::field::kDnsBeaconQueryCount) == "2");
    DNS_CHECK(c.fields.at(edr::field::kDnsBeaconHighEntropyCount) == "0");
}

void TestEntropyExpiresInsideSlidingWindow() {
    edr::DnsBeaconDetector det(true, 10, 16, 3, 1);
    const uint64_t base = 900000000000ULL;
    auto high = DnsQuery(52, "C:\\app\\agent.exe", "random1.example", "4.0", base);
    det.Enrich(high);
    auto low1 = DnsQuery(52, "C:\\app\\agent.exe", "normal.example", "2.0",
                         base + 50000000ULL);
    det.Enrich(low1);
    auto low2 = DnsQuery(52, "C:\\app\\agent.exe", "normal2.example", "2.0",
                         base + 100000000ULL);
    det.Enrich(low2);
    DNS_CHECK(!HasField(low2, edr::field::kDnsBeaconScore));
    DNS_CHECK(low2.fields.at(edr::field::kDnsBeaconQueryCount) == "2");
    DNS_CHECK(low2.fields.at(edr::field::kDnsBeaconHighEntropyCount) == "0");
}

void TestStableIdentitySeparatesEndpointSourceAndPidReuse() {
    edr::DnsBeaconDetector det(true, 300, 16, 2, 0);
    const uint64_t base = 1000000000000ULL;
    auto first = DnsQuery(61, "C:\\app\\agent.exe", "a.example", "2.0", base);
    det.Enrich(first);

    auto otherEndpoint = DnsQuery(61, "C:\\app\\agent.exe", "b.example", "2.0",
                                  base + 1000000ULL);
    otherEndpoint.fields[edr::field::kEndpointId] = "endpoint-b";
    det.Enrich(otherEndpoint);
    DNS_CHECK(!HasField(otherEndpoint, edr::field::kDnsBeaconScore));

    auto otherSource = DnsQuery(61, "C:\\app\\agent.exe", "c.example", "2.0",
                                base + 2000000ULL);
    otherSource.source = "dns_other";
    otherSource.fields[edr::field::kSource] = "dns_other";
    det.Enrich(otherSource);
    DNS_CHECK(!HasField(otherSource, edr::field::kDnsBeaconScore));

    auto reusedPid = DnsQuery(61, "C:\\app\\agent.exe", "d.example", "2.0",
                              base + 3000000ULL);
    reusedPid.processStartTime100ns = 2;
    det.Enrich(reusedPid);
    DNS_CHECK(!HasField(reusedPid, edr::field::kDnsBeaconScore));
    DNS_CHECK(det.StateCount() == 4);
}

void TestGuidNormalizationAndInvalidIdentity() {
    edr::DnsBeaconDetector det(true, 300, 16, 2, 0);
    const uint64_t base = 1100000000000ULL;
    auto first = DnsQuery(0, "C:\\app\\agent.exe", "a.example", "2.0", base);
    first.processIdentity = "{12345678-1234-1234-1234-123456789ABC}";
    first.processStartTime100ns = 0;
    det.Enrich(first);

    auto second = DnsQuery(0, "C:\\app\\agent.exe", "b.example", "2.0",
                           base + 1000000ULL);
    second.processIdentity = "12345678-1234-1234-1234-123456789abc";
    second.processStartTime100ns = 0;
    det.Enrich(second);
    DNS_CHECK(HasField(second, edr::field::kDnsBeaconScore));

    auto zeroGuid = DnsQuery(0, "C:\\app\\agent.exe", "c.example", "2.0",
                             base + 2000000ULL);
    zeroGuid.processIdentity = "00000000-0000-0000-0000-000000000000";
    zeroGuid.processStartTime100ns = 0;
    det.Enrich(zeroGuid);
    DNS_CHECK(!HasField(zeroGuid, edr::field::kDnsBeaconScore));
}

void TestInvalidMetadataDoesNotAccumulateOrRunDga() {
    edr::DnsBeaconDetector det(true, 300, 16, 1, 0);
    const uint64_t base = CurrentFileTime();
    auto reportOnly = DnsQuery(71, "C:\\app\\agent.exe", "zzzzxxxqvabcde.example",
                              "4.5", base);
    reportOnly.disposition = edr::EventDisposition::ReportOnly;
    det.Enrich(reportOnly);
    DNS_CHECK(!HasField(reportOnly, edr::field::kDnsBeaconScore));
    DNS_CHECK(!HasField(reportOnly, edr::field::kDnsDgaScore));

    auto zeroTime = DnsQuery(71, "C:\\app\\agent.exe", "zzzzxxxqvabcde.example",
                             "4.5", 0);
    det.Enrich(zeroTime);
    DNS_CHECK(!HasField(zeroTime, edr::field::kDnsBeaconScore));
    DNS_CHECK(!HasField(zeroTime, edr::field::kDnsDgaScore));

    auto future = DnsQuery(71, "C:\\app\\agent.exe", "zzzzxxxqvabcde.example",
                           "4.5", base + 3010000000ULL);
    det.Enrich(future);
    DNS_CHECK(!HasField(future, edr::field::kDnsBeaconScore));
    DNS_CHECK(!HasField(future, edr::field::kDnsDgaScore));

    auto incomplete = DnsQuery(71, "C:\\app\\agent.exe", "zzzzxxxqvabcde.example",
                               "4.5", base + 1000000ULL);
    incomplete.fields["dns_phase"] = "started";
    det.Enrich(incomplete);
    DNS_CHECK(!HasField(incomplete, edr::field::kDnsBeaconScore));
    DNS_CHECK(!HasField(incomplete, edr::field::kDnsDgaScore));
    DNS_CHECK(det.StateCount() == 0);
}

void TestSourceConflictAndFutureProcessBirthAreRejected() {
    edr::DnsBeaconDetector det(true, 300, 16, 1, 0);
    const uint64_t now = CurrentFileTime();
    auto conflict = DnsQuery(81, "C:\\app\\agent.exe", "a.example", "2.0", now);
    conflict.fields[edr::field::kSource] = "different";
    det.Enrich(conflict);
    DNS_CHECK(det.StateCount() == 0);

    auto bornLater = DnsQuery(82, "C:\\app\\agent.exe", "b.example", "2.0", now + 1);
    bornLater.processStartTime100ns = now + 2;
    bornLater.processIdentity = "12345678-1234-1234-1234-123456789abc";
    det.Enrich(bornLater);
    DNS_CHECK(det.StateCount() == 0);
}

void TestOutOfOrderEventCannotRewindOrChangeWindow() {
    edr::DnsBeaconDetector det(true, 10, 16, 2, 0);
    const uint64_t base = 1200000000000ULL;
    auto a = DnsQuery(91, "C:\\app\\agent.exe", "a.example", "2.0", base);
    det.Enrich(a);
    auto newer = DnsQuery(91, "C:\\app\\agent.exe", "b.example", "2.0",
                          base + 100000000ULL);
    det.Enrich(newer);
    DNS_CHECK(!HasField(newer, edr::field::kDnsBeaconScore));
    auto old = DnsQuery(91, "C:\\app\\agent.exe", "old.example", "2.0",
                        base + 50000000ULL);
    det.Enrich(old);
    DNS_CHECK(!HasField(old, edr::field::kDnsBeaconScore));
    auto next = DnsQuery(91, "C:\\app\\agent.exe", "next.example", "2.0",
                         base + 110000000ULL);
    det.Enrich(next);
    DNS_CHECK(HasField(next, edr::field::kDnsBeaconScore));
    DNS_CHECK(next.fields.at(edr::field::kDnsBeaconQueryCount) == "2");
}

void TestScoreBandUpgradeAndWindowRearm() {
    edr::DnsBeaconDetector det(true, 60, 16, 10, 0);
    const uint64_t base = 1300000000000ULL;
    edr::Event tenth;
    for (int i = 0; i < 10; ++i) {
        tenth = DnsQuery(101, "C:\\app\\agent.exe", "a.example", "2.0",
                         base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(tenth);
    }
    DNS_CHECK(HasField(tenth, edr::field::kDnsBeaconScore));
    DNS_CHECK(tenth.fields.at(edr::field::kDnsBeaconScore) == "10");
    auto sameBand = DnsQuery(101, "C:\\app\\agent.exe", "b.example", "2.0",
                             base + 10000000ULL);
    det.Enrich(sameBand);
    DNS_CHECK(!HasField(sameBand, edr::field::kDnsBeaconScore));

    edr::Event twentieth;
    for (int i = 11; i < 20; ++i) {
        twentieth = DnsQuery(101, "C:\\app\\agent.exe", "c.example", "2.0",
                             base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(twentieth);
    }
    DNS_CHECK(HasField(twentieth, edr::field::kDnsBeaconScore));
    DNS_CHECK(twentieth.fields.at(edr::field::kDnsBeaconScore) == "20");

    auto cooled = DnsQuery(101, "C:\\app\\agent.exe", "d.example", "2.0",
                           base + 800000000ULL);
    det.Enrich(cooled);
    DNS_CHECK(!HasField(cooled, edr::field::kDnsBeaconScore));
    edr::Event rearmed;
    for (int i = 1; i < 10; ++i) {
        rearmed = DnsQuery(101, "C:\\app\\agent.exe", "e.example", "2.0",
                           cooled.ts100ns + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(rearmed);
    }
    DNS_CHECK(HasField(rearmed, edr::field::kDnsBeaconScore));
}

void TestObservationBudgetKeepsConfiguredHighThresholdReachable() {
    edr::DnsBeaconDetector det(true, 300, 2, 100000, 100000);
    const uint64_t base = 1400000000000ULL;
    edr::Event last;
    for (uint32_t i = 0; i < 100000; ++i) {
        last = DnsQuery(111, "C:\\app\\agent.exe", "a.example", "4.2",
                        base + static_cast<uint64_t>(i) * 1000ULL);
        det.Enrich(last);
    }
    DNS_CHECK(HasField(last, edr::field::kDnsBeaconScore));
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconQueryCount) == "100000");
    DNS_CHECK(last.fields.at(edr::field::kDnsBeaconHighEntropyCount) == "100000");
    auto competing = DnsQuery(112, "C:\\other\\agent.exe", "b.example", "2.0",
                              base + 100001000ULL);
    det.Enrich(competing);
    auto restarted = DnsQuery(111, "C:\\app\\agent.exe", "c.example", "2.0",
                              base + 100002000ULL);
    det.Enrich(restarted);
    DNS_CHECK(!HasField(restarted, edr::field::kDnsBeaconScore));
    DNS_CHECK(restarted.fields.at(edr::field::kDnsBeaconQueryCount) == "1");
    DNS_CHECK(det.StateCount() <= 2);
}

void TestMalformedEntropyDoesNotCountAsHighEntropy() {
    edr::DnsBeaconDetector det(true, 300, 16, 2, 1);
    const uint64_t base = 1500000000000ULL;
    auto malformed = DnsQuery(121, "C:\\app\\agent.exe", "a.example", "nan", base);
    det.Enrich(malformed);
    auto tooHigh = DnsQuery(121, "C:\\app\\agent.exe", "b.example", "8.1",
                            base + 1000000ULL);
    det.Enrich(tooHigh);
    DNS_CHECK(!HasField(tooHigh, edr::field::kDnsBeaconScore));
    DNS_CHECK(tooHigh.fields.at(edr::field::kDnsBeaconHighEntropyCount) == "0");
}

void TestLocalScopeAndFieldSourceFallback() {
    edr::DnsBeaconDetector det(true, 30, 16, 2, 0);
    const uint64_t base = 1600000000000ULL;
    auto first = DnsQuery(131, "C:\\app\\agent.exe", "a.example", "2.0", base);
    first.fields.erase(edr::field::kEndpointId);
    det.Enrich(first);
    auto next = DnsQuery(131, "C:\\app\\agent.exe", "b.example", "2.0", base + 1);
    next.fields.erase(edr::field::kEndpointId);
    next.source.clear();
    det.Enrich(next);
    DNS_CHECK(HasField(next, edr::field::kDnsBeaconScore));
    DNS_CHECK(next.fields.at(edr::field::kDnsBeaconQueryCount) == "2");
    auto explicitEmpty = DnsQuery(132, "C:\\app\\agent.exe", "c.example", "2.0", base + 2);
    explicitEmpty.fields[edr::field::kEndpointId] = "";
    det.Enrich(explicitEmpty);
    DNS_CHECK(!HasField(explicitEmpty, edr::field::kDnsBeaconQueryCount));
    DNS_CHECK(det.StateCount() == 1);
}

void TestSingleQueryEpisodeRearmsAfterCompleteExpiry() {
    edr::DnsBeaconDetector det(true, 30, 16, 1, 0);
    const uint64_t base = 1700000000000ULL;
    auto first = DnsQuery(141, "C:\\app\\agent.exe", "a.example", "2.0", base);
    det.Enrich(first);
    DNS_CHECK(HasField(first, edr::field::kDnsBeaconScore));
    auto next = DnsQuery(141, "C:\\app\\agent.exe", "b.example", "2.0",
                         base + 30ULL * 10000000ULL);
    det.Enrich(next);
    DNS_CHECK(HasField(next, edr::field::kDnsBeaconScore));
    DNS_CHECK(next.fields.at(edr::field::kDnsBeaconQueryCount) == "1");
}

void TestMalformedTrailingDotsStayOutsideLexicalDga() {
    edr::DnsBeaconDetector det(true, 30, 16, 20, 10);
    auto event = DnsQuery(0, nullptr, "qzxvbnmkjhgfdstrpl.com..", nullptr, 1000);
    det.Enrich(event);
    DNS_CHECK(!HasField(event, edr::field::kDnsDgaScore));
    DNS_CHECK(det.StateCount() == 0);
}

void TestUnicodeImageAndUntrustedGuidInputs() {
    edr::DnsBeaconDetector det(true, 30, 16, 2, 0);
    const uint64_t base = 1800000000000ULL;
    auto first = DnsQuery(151, "C:\\工具\\agent.exe", "a.example", "2.0", base);
    det.Enrich(first);
    auto second = DnsQuery(151, "C:\\工具\\agent.exe", "b.example", "2.0", base + 1);
    det.Enrich(second);
    DNS_CHECK(HasField(second, edr::field::kDnsBeaconScore));
    const std::string invalidUtf8("\xc0\xaf", 2);
    auto badImage = DnsQuery(152, invalidUtf8.c_str(), "c.example", "2.0", base + 2);
    det.Enrich(badImage);
    DNS_CHECK(!HasField(badImage, edr::field::kDnsBeaconQueryCount));
    for (const auto* identity : {"151", "pid:151", "12345678-1234-1234-1234-123456789abz",
                                "{00000000-0000-0000-0000-000000000000}"}) {
        auto weak = DnsQuery(0, "C:\\app\\agent.exe", "d.example", "2.0", base + 3);
        weak.processIdentity = identity;
        det.Enrich(weak);
        DNS_CHECK(!HasField(weak, edr::field::kDnsBeaconQueryCount));
    }
    DNS_CHECK(det.StateCount() == 1);
}

void TestReliableInstanceSurvivesImageAliasesAndMissingImage() {
    edr::DnsBeaconDetector det(true, 30, 16, 2, 0);
    const uint64_t base = 1850000000000ULL;
    auto first = DnsQuery(156, "C:\\app\\agent.exe", "a.example", "2.0", base);
    det.Enrich(first);
    auto alias = DnsQuery(156, "\\Device\\HarddiskVolume3\\app\\agent.exe",
                          "b.example", "2.0", base + 1);
    det.Enrich(alias);
    DNS_CHECK(HasField(alias, edr::field::kDnsBeaconScore));
    DNS_CHECK(alias.fields.at(edr::field::kDnsBeaconQueryCount) == "2");
    auto noImage = DnsQuery(0, nullptr, "c.example", "2.0", base + 2);
    noImage.processIdentity = "12345678-1234-1234-1234-123456789abc";
    det.Enrich(noImage);
    auto guidNext = DnsQuery(0, "C:\\other\\worker.exe", "d.example", "2.0", base + 3);
    guidNext.processIdentity = "{12345678-1234-1234-1234-123456789ABC}";
    det.Enrich(guidNext);
    DNS_CHECK(HasField(guidNext, edr::field::kDnsBeaconScore));
    DNS_CHECK(guidNext.fields.at(edr::field::kDnsBeaconQueryCount) == "2");
    DNS_CHECK(det.StateCount() == 2);
}

void TestBudgetDiscardCannotManufactureNewEpisode() {
    edr::DnsBeaconDetector det(true, 300, 16, 10, 5);
    const uint64_t base = 1900000000000ULL;
    edr::Event event;
    for (uint32_t i = 0; i < 100005; ++i) {
        event = DnsQuery(161, "C:\\app\\agent.exe", "a.example", i < 5 ? "4.2" : "2.0", base + i);
        det.Enrich(event);
    }
    DNS_CHECK(!HasField(event, edr::field::kDnsBeaconScore));
    DNS_CHECK(event.fields.at(edr::field::kDnsBeaconQueryCount) == "100000");
    DNS_CHECK(event.fields.at(edr::field::kDnsBeaconHighEntropyCount) == "0");
    for (uint32_t i = 0; i < 5; ++i) {
        event = DnsQuery(161, "C:\\app\\agent.exe", "b.example", "4.2", base + 100005 + i);
        det.Enrich(event);
        DNS_CHECK(!HasField(event, edr::field::kDnsBeaconScore));
    }
    auto expired = DnsQuery(161, "C:\\app\\agent.exe", "c.example", "2.0",
                            base + 301ULL * 10000000ULL);
    det.Enrich(expired);
    DNS_CHECK(expired.fields.at(edr::field::kDnsBeaconQueryCount) == "1");
    for (uint32_t i = 1; i < 10; ++i) {
        event = DnsQuery(161, "C:\\app\\agent.exe", "d.example", "4.2",
                         expired.ts100ns + i);
        det.Enrich(event);
    }
    DNS_CHECK(event.fields.at(edr::field::kDnsBeaconScore) == "10");
}

/* V9: Inspects() is true only for DNS_QUERY. */
void TestInspects() {
    DNS_CHECK(edr::DnsBeaconDetector::Inspects(EDR_EVT_DNS_QUERY));
    DNS_CHECK(!edr::DnsBeaconDetector::Inspects(EDR_EVT_NET_CONNECT));
    DNS_CHECK(!edr::DnsBeaconDetector::Inspects(EDR_EVT_PROCESS_START));
    DNS_CHECK(!edr::DnsBeaconDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void RunCase(const char* name, void (*test)(), bool& failed) {
    std::printf("[dns_beacon] %s\n", name);
    try {
        test();
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[dns_beacon] FAIL %s: %s\n", name, ex.what());
        failed = true;
    }
}

} // namespace

void RunDnsBeaconDetectorTests() {
    bool failed = false;
    RunCase("TestPidAttributionFlagged", TestPidAttributionFlagged, failed);
    RunCase("TestHighEntropyThresholdNotMet", TestHighEntropyThresholdNotMet, failed);
    RunCase("TestVolumeOnlyMode", TestVolumeOnlyMode, failed);
    RunCase("TestNoAttribution", TestNoAttribution, failed);
    RunCase("TestWindowExpiry", TestWindowExpiry, failed);
    RunCase("TestDisabled", TestDisabled, failed);
    RunCase("TestCapacityEviction", TestCapacityEviction, failed);
    RunCase("TestWeakIdentityDoesNotAccumulate", TestWeakIdentityDoesNotAccumulate, failed);
    RunCase("TestStrictSlidingWindowAndExactBoundary", TestStrictSlidingWindowAndExactBoundary, failed);
    RunCase("TestEntropyExpiresInsideSlidingWindow", TestEntropyExpiresInsideSlidingWindow, failed);
    RunCase("TestStableIdentitySeparatesEndpointSourceAndPidReuse", TestStableIdentitySeparatesEndpointSourceAndPidReuse, failed);
    RunCase("TestGuidNormalizationAndInvalidIdentity", TestGuidNormalizationAndInvalidIdentity, failed);
    RunCase("TestInvalidMetadataDoesNotAccumulateOrRunDga", TestInvalidMetadataDoesNotAccumulateOrRunDga, failed);
    RunCase("TestSourceConflictAndFutureProcessBirthAreRejected", TestSourceConflictAndFutureProcessBirthAreRejected, failed);
    RunCase("TestOutOfOrderEventCannotRewindOrChangeWindow", TestOutOfOrderEventCannotRewindOrChangeWindow, failed);
    RunCase("TestScoreBandUpgradeAndWindowRearm", TestScoreBandUpgradeAndWindowRearm, failed);
    RunCase("TestObservationBudgetKeepsConfiguredHighThresholdReachable", TestObservationBudgetKeepsConfiguredHighThresholdReachable, failed);
    RunCase("TestMalformedEntropyDoesNotCountAsHighEntropy", TestMalformedEntropyDoesNotCountAsHighEntropy, failed);
    RunCase("TestLocalScopeAndFieldSourceFallback", TestLocalScopeAndFieldSourceFallback, failed);
    RunCase("TestSingleQueryEpisodeRearmsAfterCompleteExpiry", TestSingleQueryEpisodeRearmsAfterCompleteExpiry, failed);
    RunCase("TestMalformedTrailingDotsStayOutsideLexicalDga", TestMalformedTrailingDotsStayOutsideLexicalDga, failed);
    RunCase("TestUnicodeImageAndUntrustedGuidInputs", TestUnicodeImageAndUntrustedGuidInputs, failed);
    RunCase("TestReliableInstanceSurvivesImageAliasesAndMissingImage", TestReliableInstanceSurvivesImageAliasesAndMissingImage, failed);
    RunCase("TestBudgetDiscardCannotManufactureNewEpisode", TestBudgetDiscardCannotManufactureNewEpisode, failed);
    RunCase("TestInspects", TestInspects, failed);
    if (failed) throw std::runtime_error("one or more dns beacon detector tests failed");
    std::printf("[dns_beacon] all passed\n");
}
