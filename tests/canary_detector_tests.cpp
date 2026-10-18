/*
 * canary_detector_tests.cpp - Unit tests for CanaryDetector.
 */
#include "canary_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "canary_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define CANARY_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "canary detector test failed at line " + std::to_string(line) +
            ": " + expression);
}

/* CLAUDE.md: test event constructors must set ts100ns explicitly so the
 * dedup-window tests stay reproducible. */
edr::Event CanariEvent(uint64_t ts100ns, const char* action,
                       const char* path) {
    edr::Event event;
    event.type = EDR_EVT_FILE_INTEGRITY;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_INTEGRITY";
    event.fields[edr::field::kSource] = "canary";
    event.fields[edr::field::kCanaryFlag] = "true";
    event.fields[edr::field::kFimAction] = action;
    event.fields[edr::field::kFimPath] = path;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kCanaryScore) != event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL; /* FILETIME ticks per second */

} // namespace

void RunCanaryDetectorTests() {
    {
        /* Disabled detector never stamps. */
        edr::CanaryDetector detector(false, 300, 1024);
        edr::Event event = CanariEvent(1000 * kSecond, "modified",
            "c:\\users\\alice\\documents\\salary.docx");
        detector.Enrich(event);
        CANARY_CHECK(!HasScore(event));
        CANARY_CHECK(detector.StateCount() == 0);
    }
    {
        /* Plain FIM events without the canary flag are ignored. */
        edr::CanaryDetector detector(true, 300, 1024);
        edr::Event event = CanariEvent(1000 * kSecond, "modified",
            "c:\\watch\\config.ini");
        event.fields.erase(edr::field::kCanaryFlag);
        detector.Enrich(event);
        CANARY_CHECK(!HasScore(event));
        CANARY_CHECK(detector.StateCount() == 0);
    }
    {
        /* Read access on a canary: 60 SUSPICIOUS. */
        edr::CanaryDetector detector(true, 300, 1024);
        edr::Event event = CanariEvent(1000 * kSecond, "accessed",
            "c:\\users\\alice\\documents\\passwords_backup.docx");
        detector.Enrich(event);
        CANARY_CHECK(HasScore(event));
        CANARY_CHECK(event.fields.at(edr::field::kCanaryScore) == "60");
        CANARY_CHECK(event.fields.at(edr::field::kCanaryVerdict) ==
                     "suspicious");
        CANARY_CHECK(detector.StateCount() == 1);
    }
    {
        /* Modification: 80 MALICIOUS. */
        edr::CanaryDetector detector(true, 300, 1024);
        edr::Event event = CanariEvent(1000 * kSecond, "modified",
            "c:\\users\\alice\\documents\\budget.xlsx");
        detector.Enrich(event);
        CANARY_CHECK(event.fields.at(edr::field::kCanaryScore) == "80");
        CANARY_CHECK(event.fields.at(edr::field::kCanaryVerdict) ==
                     "malicious");
    }
    {
        /* Deletion: 90 MALICIOUS. */
        edr::CanaryDetector detector(true, 300, 1024);
        edr::Event event = CanariEvent(1000 * kSecond, "removed",
            "c:\\users\\alice\\documents\\keys.txt");
        detector.Enrich(event);
        CANARY_CHECK(event.fields.at(edr::field::kCanaryScore) == "90");
        CANARY_CHECK(event.fields.at(edr::field::kCanaryVerdict) ==
                     "malicious");
    }
    {
        /* Baseline "added" carries no attacker signal. */
        edr::CanaryDetector detector(true, 300, 1024);
        edr::Event event = CanariEvent(1000 * kSecond, "added",
            "c:\\canaries\\bait.docx");
        detector.Enrich(event);
        CANARY_CHECK(!HasScore(event));
        CANARY_CHECK(detector.StateCount() == 0);
    }
    {
        /* Dedup: same path inside the window suppresses; different path
         * still stamps; after expiry the same path re-arms. */
        edr::CanaryDetector detector(true, 300, 1024);
        edr::Event first = CanariEvent(1000 * kSecond, "accessed",
            "c:\\canary\\a.docx");
        detector.Enrich(first);
        CANARY_CHECK(HasScore(first));

        edr::Event repeat = CanariEvent(1100 * kSecond, "accessed",
            "c:\\canary\\a.docx");
        detector.Enrich(repeat);
        CANARY_CHECK(!HasScore(repeat));

        edr::Event other = CanariEvent(1200 * kSecond, "accessed",
            "c:\\canary\\b.docx");
        detector.Enrich(other);
        CANARY_CHECK(HasScore(other));

        edr::Event expired = CanariEvent(1400 * kSecond, "accessed",
            "c:\\canary\\a.docx");
        detector.Enrich(expired);
        CANARY_CHECK(HasScore(expired));
        CANARY_CHECK(detector.StateCount() == 2);
    }
    {
        /* Inspects: only FILE_INTEGRITY. */
        CANARY_CHECK(edr::CanaryDetector::Inspects(EDR_EVT_FILE_INTEGRITY));
        CANARY_CHECK(
            !edr::CanaryDetector::Inspects(EDR_EVT_REG_WRITE));
        CANARY_CHECK(!edr::CanaryDetector::Inspects(EDR_EVT_PROCESS_START));
    }
}
