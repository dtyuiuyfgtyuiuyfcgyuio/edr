/*
 * ntds_dit_detector_tests.cpp - Unit tests for NtdsDitDetector.
 */
#include "ntds_dit_detector_tests.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "ntds_dit_detector.h"

namespace {

#define CHECK_DIT(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "ntds dit detector test failed at line " + std::to_string(line) +
            ": " + expression);
}

edr::Event Proc(uint64_t ts100ns, const char* command) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = "cmd.exe";
    event.fields[edr::field::kCommandLine] = command;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kNtdsDitScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunNtdsDitDetectorTests() {
    std::fprintf(stderr, "[ntds-dit] TestDisabled\n");
    {
        edr::NtdsDitDetector detector(false, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "ntdsutil \"activate instance ntds\" \"ifm\" "
            "\"create full C:\\temp\\dump\" quit quit");
        detector.Enrich(event);
        CHECK_DIT(!HasScore(event));
    }
    std::fprintf(stderr, "[ntds-dit] TestShadowPivot\n");
    {
        edr::NtdsDitDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "cmd /c copy "
            "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\"
            "NTDS\\ntds.dit C:\\Users\\Public\\ntds.dit");
        detector.Enrich(event);
        CHECK_DIT(HasScore(event));
        CHECK_DIT(event.fields.at(edr::field::kNtdsDitScore) == "90");
        CHECK_DIT(event.fields.at(edr::field::kNtdsDitVerdict) == "malicious");
    }
    std::fprintf(stderr, "[ntds-dit] TestNtdsutilIfm\n");
    {
        edr::NtdsDitDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "ntdsutil \"activate instance ntds\" \"ifm\" "
            "\"create full C:\\temp\" quit quit");
        detector.Enrich(event);
        CHECK_DIT(event.fields.at(edr::field::kNtdsDitScore) == "85");
        CHECK_DIT(event.fields.at(edr::field::kNtdsDitVerdict) == "malicious");
    }
    std::fprintf(stderr, "[ntds-dit] TestEsentutl\n");
    {
        edr::NtdsDitDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "esentutl /y /vss "
            "C:\\Windows\\NTDS\\ntds.dit /d C:\\temp\\ntds.dit");
        detector.Enrich(event);
        CHECK_DIT(event.fields.at(edr::field::kNtdsDitScore) == "80");
    }
    std::fprintf(stderr, "[ntds-dit] TestPowerShellCopy\n");
    {
        edr::NtdsDitDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "powershell -c \"Copy-Item "
            "C:\\Windows\\NTDS\\ntds.dit C:\\temp\\a.dit\"");
        detector.Enrich(event);
        CHECK_DIT(event.fields.at(edr::field::kNtdsDitScore) == "80");
    }
    std::fprintf(stderr, "[ntds-dit] TestCopyTool\n");
    {
        edr::NtdsDitDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "robocopy C:\\Windows\\NTDS C:\\temp ntds.dit");
        detector.Enrich(event);
        CHECK_DIT(event.fields.at(edr::field::kNtdsDitScore) == "70");
    }
    std::fprintf(stderr, "[ntds-dit] TestPlainReference\n");
    {
        edr::NtdsDitDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "dir C:\\Windows\\NTDS\\ntds.dit");
        detector.Enrich(event);
        CHECK_DIT(event.fields.at(edr::field::kNtdsDitScore) == "60");
        CHECK_DIT(event.fields.at(edr::field::kNtdsDitVerdict) ==
                  "suspicious");
    }
    std::fprintf(stderr, "[ntds-dit] TestBenignSilent\n");
    {
        edr::NtdsDitDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond, "notepad notes.txt");
        detector.Enrich(event);
        CHECK_DIT(!HasScore(event));
        edr::Event dir = Proc(
            1001 * kSecond, "dir C:\\Windows\\System32");
        detector.Enrich(dir);
        CHECK_DIT(!HasScore(dir));
    }
    std::fprintf(stderr, "[ntds-dit] TestDedup\n");
    {
        edr::NtdsDitDetector detector(true, 55, 300, 1024);
        edr::Event first = Proc(
            1000 * kSecond,
            "ntdsutil \"activate instance ntds\" \"ifm\" "
            "\"create full C:\\temp\" quit quit");
        detector.Enrich(first);
        CHECK_DIT(HasScore(first));
        edr::Event repeat = Proc(
            1010 * kSecond,
            "ntdsutil \"activate instance ntds\" \"ifm\" "
            "\"create full C:\\temp\" quit quit");
        detector.Enrich(repeat);
        CHECK_DIT(!HasScore(repeat));
        edr::Event expired = Proc(
            1000 * kSecond + 301 * kSecond,
            "ntdsutil \"activate instance ntds\" \"ifm\" "
            "\"create full C:\\temp\" quit quit");
        detector.Enrich(expired);
        CHECK_DIT(HasScore(expired));
    }
    std::fprintf(stderr, "[ntds-dit] TestInspects\n");
    {
        CHECK_DIT(edr::NtdsDitDetector::Inspects(EDR_EVT_PROCESS_START));
        CHECK_DIT(!edr::NtdsDitDetector::Inspects(EDR_EVT_REG_WRITE));
        CHECK_DIT(!edr::NtdsDitDetector::Inspects(EDR_EVT_LOGON));
    }
    std::fprintf(stderr, "[ntds-dit] all passed\n");
}
