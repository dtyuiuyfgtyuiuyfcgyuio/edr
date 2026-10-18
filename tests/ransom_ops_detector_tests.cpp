/*
 * ransom_ops_detector_tests.cpp - Unit tests for RansomOpsDetector.
 */
#include "ransom_ops_detector_tests.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "ransom_ops_detector.h"

namespace {

#define CHECK_OPS(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "ransom ops detector test failed at line " +
            std::to_string(line) + ": " + expression);
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
    return event.fields.find(edr::field::kRansomOpsScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunRansomOpsDetectorTests() {
    std::fprintf(stderr, "[ransom-ops] TestDisabled\n");
    {
        edr::RansomOpsDetector detector(false, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "sc stop windefend");
        detector.Enrich(event);
        CHECK_OPS(!HasScore(event));
    }
    std::fprintf(stderr, "[ransom-ops] TestSingleCriticalStop\n");
    {
        edr::RansomOpsDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond, "sc stop windefend");
        detector.Enrich(event);
        CHECK_OPS(HasScore(event));
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsScore) == "75");
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsVerdict) ==
                  "malicious");
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsSignals).find(
                      "critical service") != std::string::npos);
    }
    std::fprintf(stderr, "[ransom-ops] TestMultiCriticalStop\n");
    {
        edr::RansomOpsDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "sc stop windefend & sc stop wscsvc & sc stop vss");
        detector.Enrich(event);
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsScore) == "90");
    }
    std::fprintf(stderr, "[ransom-ops] TestDisableService\n");
    {
        edr::RansomOpsDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "sc config windefend start= disabled");
        detector.Enrich(event);
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsScore) == "75");
    }
    std::fprintf(stderr, "[ransom-ops] TestTaskDelete\n");
    {
        edr::RansomOpsDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "schtasks /delete /tn \"\\Windows\\Update\\Defender\" /f");
        detector.Enrich(event);
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsScore) == "65");
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsVerdict) ==
                  "suspicious");
    }
    std::fprintf(stderr, "[ransom-ops] TestDefensiveKill\n");
    {
        edr::RansomOpsDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond, "taskkill /f /im msmpeng.exe");
        detector.Enrich(event);
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsScore) == "70");
    }
    std::fprintf(stderr, "[ransom-ops] TestStartupWipe\n");
    {
        edr::RansomOpsDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "reg delete "
            "\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
            "Updater\" /f");
        detector.Enrich(event);
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsScore) == "70");
    }
    std::fprintf(stderr, "[ransom-ops] TestComboEscalation\n");
    {
        edr::RansomOpsDetector detector(true, 55, 300, 1024);
        edr::Event event = Proc(
            1000 * kSecond,
            "sc stop windefend & schtasks /delete /tn \"X\" /f & "
            "taskkill /f /im msmpeng.exe");
        detector.Enrich(event);
        /* critical stop (75) + task delete + defensive kill, two distinct
         * extra signals -> +15 -> 90. */
        CHECK_OPS(event.fields.at(edr::field::kRansomOpsScore) == "90");
    }
    std::fprintf(stderr, "[ransom-ops] TestBenignSilent\n");
    {
        edr::RansomOpsDetector detector(true, 55, 300, 1024);
        edr::Event notepad = Proc(
            1000 * kSecond, "notepad notes.txt");
        detector.Enrich(notepad);
        CHECK_OPS(!HasScore(notepad));
        edr::Event scQuery = Proc(
            1001 * kSecond, "sc query windefend");
        detector.Enrich(scQuery);
        CHECK_OPS(!HasScore(scQuery));
        edr::Event taskList = Proc(
            1002 * kSecond, "taskkill /?");
        detector.Enrich(taskList);
        CHECK_OPS(!HasScore(taskList));
    }
    std::fprintf(stderr, "[ransom-ops] TestDedup\n");
    {
        edr::RansomOpsDetector detector(true, 55, 300, 1024);
        edr::Event first = Proc(
            1000 * kSecond, "sc stop windefend");
        detector.Enrich(first);
        CHECK_OPS(HasScore(first));
        edr::Event repeat = Proc(
            1010 * kSecond, "sc stop windefend");
        detector.Enrich(repeat);
        CHECK_OPS(!HasScore(repeat));
        edr::Event expired = Proc(
            1000 * kSecond + 301 * kSecond, "sc stop windefend");
        detector.Enrich(expired);
        CHECK_OPS(HasScore(expired));
    }
    std::fprintf(stderr, "[ransom-ops] TestInspects\n");
    {
        CHECK_OPS(edr::RansomOpsDetector::Inspects(EDR_EVT_PROCESS_START));
        CHECK_OPS(!edr::RansomOpsDetector::Inspects(EDR_EVT_LOGON));
        CHECK_OPS(!edr::RansomOpsDetector::Inspects(EDR_EVT_REG_WRITE));
    }
    std::fprintf(stderr, "[ransom-ops] all passed\n");
}
