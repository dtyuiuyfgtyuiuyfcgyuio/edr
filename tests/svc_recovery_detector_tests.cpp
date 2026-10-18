/*
 * svc_recovery_detector_tests.cpp - Unit tests for SvcRecoveryDetector (T1037.004).
 */
#include "svc_recovery_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "svc_recovery_detector.h"

namespace {

#define SR_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "svc recovery detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event RegDataEvent(uint64_t ts100ns, const char* fullKey,
                        const char* data) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = fullKey;
    event.fields[edr::field::kRegValue] = data;
    return event;
}

edr::Event RegNameEvent(uint64_t ts100ns, const char* regKey,
                        const char* valueName) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = regKey;
    event.fields[edr::field::kRegValue] = valueName;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kSvcRecoveryScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunSvcRecoveryDetectorTests() {
    std::fprintf(stderr, "[svc-recovery] TestDisabled\n");
    {
        edr::SvcRecoveryDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\sc.exe",
            "sc failure EvilSvc command= \"C:\\Temp\\evil.exe\"");
        detector.Enrich(event);
        SR_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[svc-recovery] TestScFailureInterpreter\n");
    {
        edr::SvcRecoveryDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(1001 * kSecond,
            "C:\\Windows\\System32\\sc.exe",
            "sc failure EvilSvc command= \"powershell.exe -c calc\"");
        detector.Enrich(event);
        SR_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[svc-recovery] TestScFailureWritable\n");
    {
        edr::SvcRecoveryDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(1002 * kSecond,
            "C:\\Windows\\System32\\sc.exe",
            "sc failure EvilSvc command= \"C:\\Users\\Public\\evil.exe\"");
        detector.Enrich(event);
        SR_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[svc-recovery] TestRegWritable\n");
    {
        edr::SvcRecoveryDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(1003 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\FailureCommand",
            "C:\\Users\\bob\\AppData\\evil.exe");
        detector.Enrich(event);
        SR_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[svc-recovery] TestNonSystem\n");
    {
        edr::SvcRecoveryDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(1004 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\FailureActions",
            "C:\\Program Files\\Evil\\helper.exe");
        detector.Enrich(event);
        SR_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[svc-recovery] TestSystem32Silent\n");
    {
        edr::SvcRecoveryDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(1005 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinSvc\\FailureCommand",
            "C:\\Windows\\System32\\restart.exe");
        detector.Enrich(event);
        SR_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[svc-recovery] TestNameOnly\n");
    {
        edr::SvcRecoveryDetector detector(true, 55, 300, 1024);
        edr::Event event = RegNameEvent(1006 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc",
            "FailureActions");
        detector.Enrich(event);
        SR_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[svc-recovery] TestReadOnlySilent\n");
    {
        edr::SvcRecoveryDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(1007 * kSecond,
            "C:\\Windows\\System32\\sc.exe",
            "sc qfailure EvilSvc");
        detector.Enrich(event);
        SR_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[svc-recovery] all passed\n");
}
