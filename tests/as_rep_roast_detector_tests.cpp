/*
 * as_rep_roast_detector_tests.cpp - Unit tests for AsRepRoastDetector.
 */
#include "as_rep_roast_detector_tests.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "as_rep_roast_detector.h"

namespace {

#define CHECK_ASREP(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "as-rep roast detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event TgtRequest(uint64_t ts100ns, const char* user,
                      const char* domain, const char* preAuth,
                      const char* ip) {
    edr::Event event;
    event.type = EDR_EVT_LOGON;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "LOGON";
    event.fields[edr::field::kOperationType] = "TGT_REQUEST";
    event.fields[edr::field::kTargetUser] = user;
    event.fields[edr::field::kTargetDomain] = domain;
    event.fields[edr::field::kPreAuthType] = preAuth;
    event.fields[edr::field::kSrcIp] = ip;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kAsRepRoastScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunAsRepRoastDetectorTests() {
    std::fprintf(stderr, "[as-rep] TestDisabled\n");
    {
        edr::AsRepRoastDetector detector(false, 300, 2048, 300);
        edr::Event event = TgtRequest(
            1000 * kSecond, "backupacct", "CORP", "0", "10.0.0.5");
        detector.Enrich(event);
        CHECK_ASREP(!HasScore(event));
    }
    std::fprintf(stderr, "[as-rep] TestSingleSuspicious\n");
    {
        edr::AsRepRoastDetector detector(true, 300, 2048, 300);
        edr::Event event = TgtRequest(
            1000 * kSecond, "backupacct", "CORP", "0", "10.0.0.5");
        detector.Enrich(event);
        CHECK_ASREP(HasScore(event));
        CHECK_ASREP(event.fields.at(edr::field::kAsRepRoastScore) == "65");
        CHECK_ASREP(event.fields.at(edr::field::kAsRepRoastVerdict) ==
                    "suspicious");
        CHECK_ASREP(event.fields.at(edr::field::kAsRepRoastTarget) ==
                    "backupacct@corp");
    }
    std::fprintf(stderr, "[as-rep] TestRepeatedMalicious\n");
    {
        edr::AsRepRoastDetector detector(true, 300, 2048, 300);
        edr::Event first = TgtRequest(
            1000 * kSecond, "backupacct", "CORP", "0", "10.0.0.5");
        detector.Enrich(first);
        CHECK_ASREP(HasScore(first));
        edr::Event second = TgtRequest(
            1010 * kSecond, "backupacct", "CORP", "0", "10.0.0.5");
        detector.Enrich(second);
        CHECK_ASREP(HasScore(second));
        CHECK_ASREP(second.fields.at(edr::field::kAsRepRoastScore) == "80");
        CHECK_ASREP(second.fields.at(edr::field::kAsRepRoastVerdict) ==
                    "malicious");
        edr::Event third = TgtRequest(
            1020 * kSecond, "backupacct", "CORP", "0", "10.0.0.5");
        detector.Enrich(third);
        CHECK_ASREP(third.fields.at(edr::field::kAsRepRoastScore) == "90");
    }
    std::fprintf(stderr, "[as-rep] TestPreAuthedIgnored\n");
    {
        edr::AsRepRoastDetector detector(true, 300, 2048, 300);
        edr::Event event = TgtRequest(
            1000 * kSecond, "jsmith", "CORP", "15", "10.0.0.5");
        detector.Enrich(event);
        CHECK_ASREP(!HasScore(event));
        edr::Event hex = TgtRequest(
            1001 * kSecond, "jsmith", "CORP", "0x0f", "10.0.0.5");
        detector.Enrich(hex);
        CHECK_ASREP(!HasScore(hex));
    }
    std::fprintf(stderr, "[as-rep] TestWindowReset\n");
    {
        edr::AsRepRoastDetector detector(true, 300, 2048, 300);
        edr::Event first = TgtRequest(
            1000 * kSecond, "svc_audit", "CORP", "0", "10.0.0.7");
        detector.Enrich(first);
        CHECK_ASREP(HasScore(first));
        /* 301s later the window resets: a lone request scores 65 again. */
        edr::Event late = TgtRequest(
            1000 * kSecond + 301 * kSecond, "svc_audit", "CORP", "0",
            "10.0.0.7");
        detector.Enrich(late);
        CHECK_ASREP(late.fields.at(edr::field::kAsRepRoastScore) == "65");
    }
    std::fprintf(stderr, "[as-rep] TestDistinctAccounts\n");
    {
        edr::AsRepRoastDetector detector(true, 300, 2048, 300);
        /* Different target accounts are independent keys: each first hit
         * scores 65. */
        edr::Event a = TgtRequest(
            1000 * kSecond, "acct1", "CORP", "0", "10.0.0.9");
        detector.Enrich(a);
        CHECK_ASREP(HasScore(a));
        edr::Event b = TgtRequest(
            1010 * kSecond, "acct2", "CORP", "0", "10.0.0.9");
        detector.Enrich(b);
        CHECK_ASREP(b.fields.at(edr::field::kAsRepRoastScore) == "65");
    }
    std::fprintf(stderr, "[as-rep] TestInspects\n");
    {
        CHECK_ASREP(edr::AsRepRoastDetector::Inspects(EDR_EVT_LOGON));
        CHECK_ASREP(!edr::AsRepRoastDetector::Inspects(EDR_EVT_PROCESS_START));
        CHECK_ASREP(!edr::AsRepRoastDetector::Inspects(EDR_EVT_REG_WRITE));
    }
    std::fprintf(stderr, "[as-rep] all passed\n");
}
