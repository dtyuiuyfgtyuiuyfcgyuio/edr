/*
 * golden_ticket_detector_tests.cpp - Unit tests for GoldenTicketDetector.
 */
#include "golden_ticket_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "golden_ticket_detector.h"

namespace {

#define CHECK_GT(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "golden ticket detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event KerberosEvent(uint64_t ts100ns, const char* operation,
                         const char* user, const char* encryption,
                         const char* ip) {
    edr::Event event;
    event.type = EDR_EVT_LOGON;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "LOGON";
    event.fields[edr::field::kOperationType] = operation;
    event.fields[edr::field::kTargetUser] = user;
    event.fields[edr::field::kTgsTicketEncryptionType] = encryption;
    event.fields[edr::field::kSrcIp] = ip;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kGoldenTicketScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunGoldenTicketDetectorTests() {
    std::fprintf(stderr, "[golden-ticket] TestDisabled\n");
    {
        edr::GoldenTicketDetector detector(false, 600, 4096, 2);
        edr::Event event = KerberosEvent(
            1000 * kSecond, "TGT_REQUEST", "krbtgt", "0x17", "10.0.0.9");
        detector.Enrich(event);
        CHECK_GT(!HasScore(event));
    }
    std::fprintf(stderr, "[golden-ticket] TestNormalTicketIgnored\n");
    {
        edr::GoldenTicketDetector detector(true, 600, 4096, 2);
        edr::Event event = KerberosEvent(
            1000 * kSecond, "TGT_REQUEST", "jdoe", "0x12", "10.0.0.9");
        detector.Enrich(event);
        CHECK_GT(!HasScore(event));
    }
    std::fprintf(stderr, "[golden-ticket] TestKrbtgtTgtRequest\n");
    {
        edr::GoldenTicketDetector detector(true, 600, 4096, 2);
        edr::Event event = KerberosEvent(
            1000 * kSecond, "TGT_REQUEST", "krbtgt", "0x12", "10.0.0.9");
        detector.Enrich(event);
        CHECK_GT(HasScore(event));
        CHECK_GT(event.fields.at(edr::field::kGoldenTicketScore) == "90");
        CHECK_GT(event.fields.at(edr::field::kGoldenTicketVerdict) ==
                 "MALICIOUS");
        CHECK_GT(event.fields.at(edr::field::kGoldenTicketSignals)
                     .find("krbtgt_tgt_request") != std::string::npos);
    }
    std::fprintf(stderr, "[golden-ticket] TestRc4TgtRequest\n");
    {
        edr::GoldenTicketDetector detector(true, 600, 4096, 2);
        edr::Event event = KerberosEvent(
            1000 * kSecond, "TGT_REQUEST", "jdoe", "0x17", "10.0.0.9");
        detector.Enrich(event);
        CHECK_GT(HasScore(event));
        CHECK_GT(event.fields.at(edr::field::kGoldenTicketScore) == "80");
        CHECK_GT(event.fields.at(edr::field::kGoldenTicketVerdict) ==
                 "MALICIOUS");
        CHECK_GT(event.fields.at(edr::field::kGoldenTicketSignals)
                     .find("rc4_encrypted_tgt") != std::string::npos);
    }
    std::fprintf(stderr, "[golden-ticket] TestKrbtgtServiceTicket\n");
    {
        edr::GoldenTicketDetector detector(true, 600, 4096, 2);
        edr::Event event = KerberosEvent(
            1000 * kSecond, "TGS_REQUEST", "krbtgt", "0x12", "10.0.0.9");
        detector.Enrich(event);
        CHECK_GT(HasScore(event));
        CHECK_GT(event.fields.at(edr::field::kGoldenTicketScore) == "85");
        CHECK_GT(event.fields.at(edr::field::kGoldenTicketSignals)
                     .find("krbtgt_service_ticket") != std::string::npos);
    }
    std::fprintf(stderr, "[golden-ticket] TestCombinedMaxScore\n");
    {
        edr::GoldenTicketDetector detector(true, 600, 4096, 2);
        edr::Event first = KerberosEvent(
            1000 * kSecond, "TGT_REQUEST", "krbtgt", "0x17", "10.0.0.9");
        detector.Enrich(first);
        CHECK_GT(HasScore(first));
        edr::Event second = KerberosEvent(
            1010 * kSecond, "TGS_REQUEST", "krbtgt", "0x12", "10.0.0.9");
        detector.Enrich(second);
        CHECK_GT(second.fields.size() > 0);
        CHECK_GT(second.fields.at(edr::field::kGoldenTicketScore) == "100");
        CHECK_GT(second.fields.at(edr::field::kGoldenTicketVerdict) ==
                 "MALICIOUS");
    }
    std::fprintf(stderr, "[golden-ticket] TestDecimalEncryptionValue\n");
    {
        edr::GoldenTicketDetector detector(true, 600, 4096, 2);
        edr::Event event = KerberosEvent(
            1000 * kSecond, "TGT_REQUEST", "jdoe", "23", "10.0.0.9");
        detector.Enrich(event);
        CHECK_GT(HasScore(event));
        CHECK_GT(event.fields.at(edr::field::kGoldenTicketScore) == "80");
    }
    std::fprintf(stderr, "[golden-ticket] TestWindowExpiry\n");
    {
        edr::GoldenTicketDetector detector(true, 600, 4096, 2);
        edr::Event first = KerberosEvent(
            1000 * kSecond, "TGT_REQUEST", "krbtgt", "0x12", "10.0.0.9");
        detector.Enrich(first);
        CHECK_GT(HasScore(first));
        /* Beyond the 600s window the source state expires. */
        edr::Event late = KerberosEvent(
            2000 * kSecond, "TGT_REQUEST", "krbtgt", "0x12", "10.0.0.9");
        detector.Enrich(late);
        CHECK_GT(late.fields.at(edr::field::kGoldenTicketScore) == "90");
    }
    std::fprintf(stderr, "[golden-ticket] All tests passed\n");
}
