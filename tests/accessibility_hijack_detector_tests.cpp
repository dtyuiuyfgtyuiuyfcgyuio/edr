/*
 * accessibility_hijack_detector_tests.cpp - Unit tests for the accessibility
 * feature hijack detector.
 */
#include "accessibility_hijack_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "accessibility_hijack_detector.h"

namespace {

#define AH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "accessibility hijack detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event MakeEvent(uint16_t type) {
    edr::Event event;
    event.type = type;
    event.ts100ns = 10000000ULL;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(
        edr::field::kAccessibilityHijackScore) != event.fields.end();
}

uint32_t Score(const edr::Event& event) {
    return static_cast<uint32_t>(std::stoul(
        event.fields.at(edr::field::kAccessibilityHijackScore)));
}

} // namespace

void RunAccessibilityHijackDetectorTests() {
    std::fprintf(stderr, "[accessibility-hijack] TestDisabled\n");
    {
        auto event = MakeEvent(EDR_EVT_REG_WRITE);
        event.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Image File Execution Options\\sethc.exe";
        event.fields[edr::field::kRegValue] = "Debugger";
        edr::AccessibilityHijackDetector detector(false, 55);
        detector.Enrich(event);
        AH_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[accessibility-hijack] TestIfeoDriverShape\n");
    {
        /* Driver shape: bare key in reg_key, value name in reg_value. */
        auto event = MakeEvent(EDR_EVT_REG_WRITE);
        event.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Image File Execution Options\\sethc.exe";
        event.fields[edr::field::kRegValue] = "Debugger";
        edr::AccessibilityHijackDetector detector(true, 55);
        detector.Enrich(event);
        AH_CHECK(HasScore(event));
        AH_CHECK(Score(event) == 85);
        AH_CHECK(event.fields.at(edr::field::kAccessibilityHijackTarget) ==
                 "sethc.exe");
        AH_CHECK(event.fields.at(edr::field::kAccessibilityHijackVerdict) ==
                 "malicious");
    }

    std::fprintf(stderr, "[accessibility-hijack] TestIfeoSnapshotShape\n");
    {
        /* Sysmon/reg-watch shape: value component appended to key. */
        auto event = MakeEvent(EDR_EVT_REG_WRITE);
        event.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Image File Execution Options\\utilman.exe\\Debugger";
        event.fields[edr::field::kRegValue] =
            "C:\\Users\\public\\payload.exe";
        edr::AccessibilityHijackDetector detector(true, 55);
        detector.Enrich(event);
        AH_CHECK(HasScore(event));
        AH_CHECK(Score(event) == 85);
        AH_CHECK(event.fields.at(edr::field::kAccessibilityHijackTarget) ==
                 "utilman.exe");
    }

    std::fprintf(stderr, "[accessibility-hijack] TestSilentProcessExit\n");
    {
        auto event = MakeEvent(EDR_EVT_REG_WRITE);
        event.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\ErrorReporting"
            "\\SilentProcessExit\\osk.exe\\MonitorProcess";
        event.fields[edr::field::kRegValue] =
            "C:\\Temp\\launcher.exe";
        edr::AccessibilityHijackDetector detector(true, 55);
        detector.Enrich(event);
        AH_CHECK(HasScore(event));
        AH_CHECK(Score(event) == 85);
        AH_CHECK(event.fields.at(edr::field::kAccessibilityHijackSignals).find(
                     "SilentProcessExit") != std::string::npos);
    }

    std::fprintf(stderr, "[accessibility-hijack] TestSystemFileReplacement\n");
    {
        auto event = MakeEvent(EDR_EVT_FILE_RENAME);
        event.fields[edr::field::kOldFilePath] = "C:\\Temp\\evil.exe";
        event.fields[edr::field::kFilePath] =
            "C:\\Windows\\System32\\sethc.exe";
        edr::AccessibilityHijackDetector detector(true, 55);
        detector.Enrich(event);
        AH_CHECK(Score(event) == 90);
        AH_CHECK(event.fields.at(edr::field::kAccessibilityHijackVerdict) ==
                 "malicious");
    }

    std::fprintf(stderr, "[accessibility-hijack] TestUserWritableExecution\n");
    {
        auto event = MakeEvent(EDR_EVT_PROCESS_START);
        event.fields[edr::field::kImagePath] =
            "C:\\Users\\Public\\Downloads\\narrator.exe";
        edr::AccessibilityHijackDetector detector(true, 55);
        detector.Enrich(event);
        AH_CHECK(Score(event) == 80);
    }

    std::fprintf(stderr, "[accessibility-hijack] TestBenignPathsSilent\n");
    {
        edr::AccessibilityHijackDetector detector(true, 55);
        auto system = MakeEvent(EDR_EVT_PROCESS_START);
        system.fields[edr::field::kImagePath] =
            "C:\\Windows\\System32\\utilman.exe";
        detector.Enrich(system);
        AH_CHECK(!HasScore(system));

        auto unrelated = MakeEvent(EDR_EVT_FILE_CREATE);
        unrelated.fields[edr::field::kFilePath] = "C:\\Temp\\notepad.exe";
        detector.Enrich(unrelated);
        AH_CHECK(!HasScore(unrelated));

        auto wrongRegistry = MakeEvent(EDR_EVT_REG_WRITE);
        wrongRegistry.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Update";
        wrongRegistry.fields[edr::field::kRegValue] = "Debugger";
        detector.Enrich(wrongRegistry);
        AH_CHECK(!HasScore(wrongRegistry));
    }

    std::fprintf(stderr, "[accessibility-hijack] TestMinScoreFilter\n");
    {
        edr::AccessibilityHijackDetector strict(true, 70);
        auto staged = MakeEvent(EDR_EVT_FILE_CREATE);
        staged.fields[edr::field::kFilePath] =
            "C:\\Users\\Public\\magnify.exe";
        strict.Enrich(staged);
        AH_CHECK(!HasScore(staged));

        auto executed = MakeEvent(EDR_EVT_PROCESS_START);
        executed.fields[edr::field::kImagePath] =
            "C:\\Users\\Public\\magnify.exe";
        strict.Enrich(executed);
        AH_CHECK(HasScore(executed));
        AH_CHECK(Score(executed) == 80);
    }

    std::fprintf(stderr, "[accessibility-hijack] TestInspects\n");
    {
        AH_CHECK(edr::AccessibilityHijackDetector::Inspects(
            EDR_EVT_PROCESS_START));
        AH_CHECK(edr::AccessibilityHijackDetector::Inspects(
            EDR_EVT_REG_WRITE));
        AH_CHECK(edr::AccessibilityHijackDetector::Inspects(
            EDR_EVT_FILE_RENAME));
        AH_CHECK(!edr::AccessibilityHijackDetector::Inspects(
            EDR_EVT_LOGON));
    }

    std::fprintf(stderr, "[accessibility-hijack] all passed\n");
}