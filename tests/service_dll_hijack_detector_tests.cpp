/*
 * service_dll_hijack_detector_tests.cpp - Unit tests for ServiceDllHijackDetector (T1574.011).
 */
#include "service_dll_hijack_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "service_dll_hijack_detector.h"

namespace {

#define SD_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "service dll hijack detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* script) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    event.fields[edr::field::kScriptBlockText] = script;
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
    auto it = event.fields.find(edr::field::kServiceDllHijackScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunServiceDllHijackDetectorTests() {
    std::fprintf(stderr, "[service-dll] TestDisabled\n");
    {
        edr::ServiceDllHijackDetector detector(false, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\Parameters\\ServiceDll",
            "C:\\Users\\bob\\AppData\\evil.dll");
        detector.Enrich(event);
        SD_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[service-dll] TestWritableDir\n");
    {
        edr::ServiceDllHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1001 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\Parameters\\ServiceDll",
            "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.dll");
        detector.Enrich(event);
        SD_CHECK(Score(event) == "90");
        SD_CHECK(event.fields.at(edr::field::kServiceDllHijackVerdict) == "malicious");
    }
    std::fprintf(stderr, "[service-dll] TestNonSystem\n");
    {
        edr::ServiceDllHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1002 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\Parameters\\ServiceDll",
            "C:\\Program Files\\Evil\\helper.dll");
        detector.Enrich(event);
        SD_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[service-dll] TestSystem32Silent\n");
    {
        edr::ServiceDllHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1003 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinSvc\\Parameters\\ServiceDll",
            "C:\\Windows\\System32\\svchost.dll");
        detector.Enrich(event);
        SD_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[service-dll] TestNameOnly\n");
    {
        edr::ServiceDllHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = RegNameEvent(
            1004 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\Parameters",
            "ServiceDll");
        detector.Enrich(event);
        SD_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[service-dll] TestReadOnlySilent\n");
    {
        edr::ServiceDllHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1005 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\Parameters\" /v ServiceDll");
        detector.Enrich(event);
        SD_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[service-dll] TestCommandPlane\n");
    {
        edr::ServiceDllHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1006 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\Parameters\" /v ServiceDll /t REG_EXPAND_SZ /d \"C:\\Users\\Public\\evil.dll\" /f");
        detector.Enrich(event);
        SD_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[service-dll] TestMinScoreGate\n");
    {
        edr::ServiceDllHijackDetector detector(true, 80, 300, 1024);
        edr::Event event = RegNameEvent(
            1007 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\Parameters",
            "ServiceDll");
        detector.Enrich(event);
        SD_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[service-dll] all passed\n");
}
