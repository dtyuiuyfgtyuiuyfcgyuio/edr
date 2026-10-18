/*
 * logon_brute_force_detector_tests.cpp - Unit tests for LogonBruteForceDetector.
 */
#include "logon_brute_force_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "logon_brute_force_detector.h"

namespace {

#define BF_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "logon brute-force detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event LogonFailure(const char* srcIp, const char* targetUser,
                        uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_LOGON;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "LOGON";
    event.fields[edr::field::kOperationType] = "LOGON_FAILURE";
    if (srcIp) event.fields[edr::field::kSrcIp] = srcIp;
    if (targetUser) event.fields[edr::field::kTargetUser] = targetUser;
    return event;
}

edr::Event LogonSuccess(const char* srcIp, uint64_t ts100ns) {
    edr::Event event = LogonFailure(srcIp, "Administrator", ts100ns);
    event.fields[edr::field::kOperationType] = "LOGON";
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

void TestInspects() {
    BF_CHECK(edr::LogonBruteForceDetector::Inspects(EDR_EVT_LOGON));
    BF_CHECK(!edr::LogonBruteForceDetector::Inspects(EDR_EVT_PROCESS_START));
    BF_CHECK(!edr::LogonBruteForceDetector::Inspects(EDR_EVT_ACCOUNT_CHANGE));
}

void TestDisabled() {
    edr::LogonBruteForceDetector detector(false, 300, 8192, 10, 600);
    for (uint64_t t = 1000000000; t <= 1000000000 + 30 * 10000000ULL;
         t += 10000000ULL) {
        edr::Event event = LogonFailure("10.0.0.9", "Administrator", t);
        detector.Enrich(event);
        BF_CHECK(!HasField(event, edr::field::kLogonBruteScore));
        BF_CHECK(!HasField(event, edr::field::kLogonBruteFailures));
    }
    BF_CHECK(detector.StateCount() == 0);
}

void TestNonFailureAndUnattributableIgnored() {
    edr::LogonBruteForceDetector detector(true, 300, 8192, 3, 0);
    const uint64_t base = 200000000000ULL;

    /* Successful logons are not counted. */
    for (uint64_t t = base; t < base + 20 * 10000000ULL; t += 10000000ULL) {
        edr::Event success = LogonSuccess("10.0.0.9", t);
        detector.Enrich(success);
        BF_CHECK(!HasField(success, edr::field::kLogonBruteFailures));
    }
    BF_CHECK(detector.StateCount() == 0);

    /* Local interactive failures (IpAddress "-") are skipped. */
    edr::Event local = LogonFailure("-", "Administrator", base);
    detector.Enrich(local);
    BF_CHECK(!HasField(local, edr::field::kLogonBruteFailures));
    BF_CHECK(detector.StateCount() == 0);

    /* Empty source IP is skipped. */
    edr::Event noIp = LogonFailure("", "Administrator", base + 10000000);
    detector.Enrich(noIp);
    BF_CHECK(detector.StateCount() == 0);

    /* Missing target user is skipped. */
    edr::Event noUser = LogonFailure("10.0.0.9", nullptr, base + 20000000);
    detector.Enrich(noUser);
    BF_CHECK(detector.StateCount() == 0);
}

void TestFlaggedAtThreshold() {
    edr::LogonBruteForceDetector detector(true, 300, 8192, 3, 0);
    const uint64_t base = 300000000000ULL;
    const char* srcIp = "10.0.0.77";
    const char* user = "svc_backup";

    edr::Event first = LogonFailure(srcIp, user, base);
    detector.Enrich(first);
    BF_CHECK(!HasField(first, edr::field::kLogonBruteFailures));

    edr::Event second = LogonFailure(srcIp, user, base + 10000000);
    detector.Enrich(second);
    BF_CHECK(!HasField(second, edr::field::kLogonBruteFailures));

    /* Third failure crosses the threshold: fields are stamped with the batch
     * count and the counter resets. */
    edr::Event third = LogonFailure(srcIp, user, base + 20000000);
    detector.Enrich(third);
    BF_CHECK(third.fields.at(edr::field::kLogonBruteScore) == "3");
    BF_CHECK(third.fields.at(edr::field::kLogonBruteFailures) == "3");
    BF_CHECK(third.fields.at(edr::field::kLogonBruteTargetUser) == user);
    BF_CHECK(third.fields.at(edr::field::kLogonBruteSrcIp) == srcIp);
    BF_CHECK(third.fields.at(edr::field::kLogonBruteWindowSeconds) == "300");

    /* The next failures must form a fresh batch of 3 before emitting again. */
    for (int i = 0; i < 2; ++i) {
        edr::Event partial =
            LogonFailure(srcIp, user, base + (30 + i) * 10000000ULL);
        detector.Enrich(partial);
        BF_CHECK(!HasField(partial, edr::field::kLogonBruteFailures));
    }
    edr::Event freshBatch =
        LogonFailure(srcIp, user, base + 32 * 10000000ULL);
    detector.Enrich(freshBatch);
    BF_CHECK(freshBatch.fields.at(edr::field::kLogonBruteFailures) == "3");
    BF_CHECK(freshBatch.fields.at(edr::field::kLogonBruteScore) == "3");
}

void TestScoreCappedAt100() {
    /* A single batch larger than 100 caps the score at 100. */
    edr::LogonBruteForceDetector detector(true, 300, 8192, 150, 0);
    const uint64_t base = 400000000000ULL;
    const char* srcIp = "10.0.0.88";

    edr::Event last;
    for (uint32_t i = 0; i < 150; ++i) {
        last = LogonFailure(srcIp, "user",
                            base + static_cast<uint64_t>(i) * 10000000ULL);
        detector.Enrich(last);
    }
    BF_CHECK(HasField(last, edr::field::kLogonBruteFailures));
    BF_CHECK(last.fields.at(edr::field::kLogonBruteFailures) == "150");
    BF_CHECK(last.fields.at(edr::field::kLogonBruteScore) == "100");
}

void TestDedupCooldown() {
    /* minFailures=3, dedup=600s. After an emit, further threshold-crossing
     * failures are suppressed until the cooldown elapses. */
    edr::LogonBruteForceDetector detector(true, 86400, 8192, 3, 600);
    const uint64_t base = 500000000000ULL;
    const char* srcIp = "10.0.0.99";
    const char* user = "Administrator";

    edr::Event e1 = LogonFailure(srcIp, user, base);
    detector.Enrich(e1);
    edr::Event e2 = LogonFailure(srcIp, user, base + 10000000);
    detector.Enrich(e2);
    edr::Event e3 = LogonFailure(srcIp, user, base + 20000000);
    detector.Enrich(e3);
    BF_CHECK(HasField(e3, edr::field::kLogonBruteFailures));

    /* Three more failures within the 600s cooldown: emission is suppressed
     * but the counter keeps accumulating (3 -> 6). */
    for (int i = 0; i < 3; ++i) {
        edr::Event suppressed = LogonFailure(
            srcIp, user, base + (10 + i) * 10000000ULL);
        detector.Enrich(suppressed);
        BF_CHECK(!HasField(suppressed, edr::field::kLogonBruteFailures));
    }

    /* While the cooldown (600s = 6e9 100ns ticks) is still active, failures
     * keep accumulating and stay suppressed. */
    const uint64_t cooldown = 600 * 10000000ULL;
    edr::Event late = LogonFailure(srcIp, user, base + cooldown + 10000000ULL);
    detector.Enrich(late);
    BF_CHECK(!HasField(late, edr::field::kLogonBruteFailures));

    /* The first failure at/after the cooldown boundary emits with the
     * accumulated count (3 suppressed + late + this one = 5), then the
     * counter resets and a fresh cooldown starts. */
    edr::Event late2 =
        LogonFailure(srcIp, user, base + cooldown + 20000000ULL);
    detector.Enrich(late2);
    BF_CHECK(HasField(late2, edr::field::kLogonBruteFailures));
    BF_CHECK(late2.fields.at(edr::field::kLogonBruteFailures) == "5");

    /* The counter was reset by the emit, so the next failure alone is below
     * the threshold. */
    edr::Event late3 =
        LogonFailure(srcIp, user, base + cooldown + 30000000ULL);
    detector.Enrich(late3);
    BF_CHECK(!HasField(late3, edr::field::kLogonBruteFailures));
}

void TestWindowExpiry() {
    edr::LogonBruteForceDetector detector(true, 60, 8192, 3, 0);
    const uint64_t base = 600000000000ULL;
    const char* srcIp = "192.168.1.20";
    const char* user = "user1";

    edr::Event a = LogonFailure(srcIp, user, base);
    detector.Enrich(a);
    edr::Event b = LogonFailure(srcIp, user, base + 10000000);
    detector.Enrich(b);
    edr::Event c = LogonFailure(srcIp, user, base + 20000000);
    detector.Enrich(c);
    BF_CHECK(HasField(c, edr::field::kLogonBruteFailures));

    /* 70s later the key is idle past the 60s window and is dropped; a new
     * failure starts a fresh counter. */
    edr::Event late = LogonFailure(srcIp, user, base + 700000000ULL);
    detector.Enrich(late);
    BF_CHECK(!HasField(late, edr::field::kLogonBruteFailures));
    BF_CHECK(detector.StateCount() == 1);
}

void TestCapacityEviction() {
    edr::LogonBruteForceDetector detector(true, 86400, 2, 10, 0);
    const uint64_t base = 700000000000ULL;
    for (uint32_t i = 1; i <= 4; ++i) {
        edr::Event event = LogonFailure(
            ("10.0.0." + std::to_string(i)).c_str(), "user",
            base + static_cast<uint64_t>(i) * 10000000ULL);
        detector.Enrich(event);
    }
    BF_CHECK(detector.StateCount() <= 2);
}

} // namespace

void RunLogonBruteForceDetectorTests() {
    TestInspects();
    TestDisabled();
    TestNonFailureAndUnattributableIgnored();
    TestFlaggedAtThreshold();
    TestScoreCappedAt100();
    TestDedupCooldown();
    TestWindowExpiry();
    TestCapacityEviction();
}
