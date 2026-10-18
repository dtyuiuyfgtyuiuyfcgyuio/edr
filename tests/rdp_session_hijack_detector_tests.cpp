/*
 * rdp_session_hijack_detector_tests.cpp - Unit tests for
 * RdpSessionHijackDetector (T1563.002).
 */
#include "rdp_session_hijack_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "rdp_session_hijack_detector.h"

namespace {

#define RDP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "rdp session hijack detector test failed at line " +
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
    return event.fields.find(edr::field::kRdpSessionHijackScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunRdpSessionHijackDetectorTests() {
    std::fprintf(stderr, "[rdp-hijack] TestDisabled\n");
    {
        edr::RdpSessionHijackDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "tscon.exe", "tscon.exe 2 /dest:rdp-tcp#3");
        detector.Enrich(event);
        RDP_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[rdp-hijack] TestSessionHijackDest\n");
    {
        /* tscon with /dest -> 90 malicious. */
        edr::RdpSessionHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "tscon.exe", "tscon.exe 2 /dest:rdp-tcp#3");
        detector.Enrich(event);
        RDP_CHECK(HasScore(event));
        RDP_CHECK(event.fields.at(edr::field::kRdpSessionHijackScore) ==
                  "90");
        RDP_CHECK(event.fields.at(edr::field::kRdpSessionHijackVerdict) ==
                  "MALICIOUS");
        RDP_CHECK(event.fields.at(edr::field::kRdpSessionHijackSignals) ==
                  "tscon_session_hijack");
        RDP_CHECK(event.fields.at(edr::field::kRdpSessionHijackDest) ==
                  "rdp-tcp#3");
    }
    std::fprintf(stderr, "[rdp-hijack] TestWithPassword\n");
    {
        /* tscon with /password -> 100 malicious. */
        edr::RdpSessionHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\tscon.exe",
            "tscon.exe 1 /password:secret /dest:console");
        detector.Enrich(event);
        RDP_CHECK(event.fields.at(edr::field::kRdpSessionHijackScore) ==
                  "100");
        RDP_CHECK(event.fields.at(edr::field::kRdpSessionHijackSignals) ==
                  "tscon_with_password");
    }
    std::fprintf(stderr, "[rdp-hijack] TestConsoleSwitch\n");
    {
        /* Plain tscon (interactive console switch) -> 75 malicious. */
        edr::RdpSessionHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "tscon.exe", "tscon.exe 1");
        detector.Enrich(event);
        RDP_CHECK(event.fields.at(edr::field::kRdpSessionHijackScore) ==
                  "75");
        RDP_CHECK(event.fields.at(edr::field::kRdpSessionHijackVerdict) ==
                  "MALICIOUS");
    }
    std::fprintf(stderr, "[rdp-hijack] TestNonTsconIgnored\n");
    {
        /* Any other process is never scored. */
        edr::RdpSessionHijackDetector detector(true, 55, 300, 1024);
        edr::Event notepad = ProcEvent(
            1000 * kSecond, "notepad.exe", "notepad notes.txt");
        detector.Enrich(notepad);
        RDP_CHECK(!HasScore(notepad));

        /* tscon.exe with no command line still scores the base case. */
        edr::Event bare = ProcEvent(
            1001 * kSecond, "tscon.exe", nullptr);
        detector.Enrich(bare);
        RDP_CHECK(HasScore(bare));
    }
    std::fprintf(stderr, "[rdp-hijack] TestDedupWindow\n");
    {
        edr::RdpSessionHijackDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1000 * kSecond, "tscon.exe", "tscon.exe 2 /dest:rdp-tcp#3");
        detector.Enrich(first);
        RDP_CHECK(HasScore(first));
        edr::Event repeat = ProcEvent(
            1010 * kSecond, "tscon.exe", "tscon.exe 2 /dest:rdp-tcp#3");
        detector.Enrich(repeat);
        RDP_CHECK(!HasScore(repeat));
        edr::Event expired = ProcEvent(
            1000 * kSecond + 301 * kSecond, "tscon.exe",
            "tscon.exe 2 /dest:rdp-tcp#3");
        detector.Enrich(expired);
        RDP_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[rdp-hijack] TestInspects\n");
    {
        RDP_CHECK(edr::RdpSessionHijackDetector::Inspects(
            EDR_EVT_PROCESS_START));
        RDP_CHECK(!edr::RdpSessionHijackDetector::Inspects(
            EDR_EVT_REG_WRITE));
        RDP_CHECK(!edr::RdpSessionHijackDetector::Inspects(
            EDR_EVT_DNS_QUERY));
    }
    std::fprintf(stderr, "[rdp-hijack] all passed\n");
}
