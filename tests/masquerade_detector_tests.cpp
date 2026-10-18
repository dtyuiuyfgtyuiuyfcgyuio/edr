/*
 * masquerade_detector_tests.cpp - Unit tests for MasqueradeDetector.
 */
#include "masquerade_detector_tests.h"

#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "masquerade_detector.h"

namespace {

#define MASQ_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "masquerade detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(uint64_t ts100ns, const char* image) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    if (image != nullptr) {
        event.fields[edr::field::kImage] = image;
    }
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kMasqueradeScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunMasqueradeDetectorTests() {
    std::fprintf(stderr, "[masquerade] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::MasqueradeDetector detector(false, 55, 300, 1024);
        edr::Event event =
            ProcessStart(1000 * kSecond, "C:\\temp\\svch0st.exe");
        detector.Enrich(event);
        MASQ_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[masquerade] TestRtlo\n");
    {
        /* RTLO in the path -> 85 malicious. */
        edr::MasqueradeDetector detector(true, 55, 300, 1024);
        std::string path = "C:\\Users\\alice\\Downloads\\invoice";
        path += "\xE2\x80\xAE";
        path += "exe.txt.exe";
        edr::Event event =
            ProcessStart(1000 * kSecond, path.c_str());
        detector.Enrich(event);
        MASQ_CHECK(HasScore(event));
        MASQ_CHECK(event.fields.at(edr::field::kMasqueradeScore) == "85");
        MASQ_CHECK(event.fields.at(edr::field::kMasqueradeVerdict) ==
                   "malicious");
    }
    std::fprintf(stderr, "[masquerade] TestLookalikeBasename\n");
    {
        /* System-binary lookalike basename -> 80 malicious. */
        edr::MasqueradeDetector detector(true, 55, 300, 1024);
        edr::Event event =
            ProcessStart(1000 * kSecond, "C:\\Users\\alice\\svch0st.exe");
        detector.Enrich(event);
        MASQ_CHECK(event.fields.at(edr::field::kMasqueradeScore) == "80");
        MASQ_CHECK(event.fields.at(edr::field::kMasqueradeVerdict) ==
                   "malicious");

        /* The real basename from the real directory stays silent here
         * (directory checks are the hollowing detector's job). */
        edr::Event legit = ProcessStart(
            1001 * kSecond,
            "C:\\Windows\\System32\\svchost.exe");
        detector.Enrich(legit);
        MASQ_CHECK(!HasScore(legit));
    }
    std::fprintf(stderr, "[masquerade] TestDoubleExtension\n");
    {
        /* Double extension -> 70 suspicious. */
        edr::MasqueradeDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcessStart(
            1000 * kSecond, "C:\\Users\\alice\\Documents\\resume.pdf.exe");
        detector.Enrich(event);
        MASQ_CHECK(event.fields.at(edr::field::kMasqueradeScore) == "70");
        MASQ_CHECK(event.fields.at(edr::field::kMasqueradeVerdict) ==
                   "suspicious");
    }
    std::fprintf(stderr, "[masquerade] TestWhitespacePadding\n");
    {
        /* Whitespace padding before .exe -> 60 suspicious. */
        edr::MasqueradeDetector detector(true, 55, 300, 1024);
        edr::Event event =
            ProcessStart(1000 * kSecond, "C:\\Users\\alice\\setup .exe");
        detector.Enrich(event);
        MASQ_CHECK(event.fields.at(edr::field::kMasqueradeScore) == "60");

        /* Trailing dot after .exe -> 60 suspicious. */
        edr::Event dotted = ProcessStart(1001 * kSecond,
                                         "C:\\tools\\crack.exe.");
        detector.Enrich(dotted);
        MASQ_CHECK(dotted.fields.at(edr::field::kMasqueradeScore) == "60");
    }
    std::fprintf(stderr, "[masquerade] TestOrdinaryIgnored\n");
    {
        /* Ordinary executables and documents never score. */
        edr::MasqueradeDetector detector(true, 55, 300, 1024);
        edr::Event notepad = ProcessStart(
            1000 * kSecond, "C:\\Windows\\System32\\notepad.exe");
        detector.Enrich(notepad);
        MASQ_CHECK(!HasScore(notepad));

        edr::Event doc = ProcessStart(
            1001 * kSecond, "C:\\Users\\alice\\report.pdf");
        detector.Enrich(doc);
        MASQ_CHECK(!HasScore(doc));

        edr::Event missingImage =
            ProcessStart(1002 * kSecond, nullptr);
        detector.Enrich(missingImage);
        MASQ_CHECK(!HasScore(missingImage));
    }
    std::fprintf(stderr, "[masquerade] TestDedupWindow\n");
    {
        /* Dedup window: same path only alerts once until expiry. */
        edr::MasqueradeDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcessStart(
            2000 * kSecond, "C:\\Users\\alice\\invoice.pdf.exe");
        detector.Enrich(first);
        MASQ_CHECK(HasScore(first));
        edr::Event repeat = ProcessStart(
            2100 * kSecond, "C:\\Users\\alice\\invoice.pdf.exe");
        detector.Enrich(repeat);
        MASQ_CHECK(!HasScore(repeat));
        edr::Event expired = ProcessStart(
            2400 * kSecond, "c:\\users\\alice\\INVOICE.PDF.EXE");
        detector.Enrich(expired); /* case-insensitive key */
        MASQ_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[masquerade] TestInspects\n");
    {
        /* Inspects: only PROCESS_START. */
        MASQ_CHECK(
            edr::MasqueradeDetector::Inspects(EDR_EVT_PROCESS_START));
        MASQ_CHECK(!edr::MasqueradeDetector::Inspects(EDR_EVT_REG_WRITE));
        MASQ_CHECK(
            !edr::MasqueradeDetector::Inspects(EDR_EVT_FILE_INTEGRITY));
    }
    std::fprintf(stderr, "[masquerade] all passed\n");
}
