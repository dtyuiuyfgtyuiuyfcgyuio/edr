/*
 * appinit_dll_detector_tests.cpp - Unit tests for AppinitDllDetector
 * (T1546.010 / T1546.009).
 */
#include "appinit_dll_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "appinit_dll_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define AI_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "appinit dll detector test failed at line " +
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

edr::Event RegEvent(uint64_t ts100ns, const char* key, const char* value) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    if (value != nullptr)
        event.fields[edr::field::kRegValue] = value;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kAppinitDllScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunAppinitDllDetectorTests() {
    std::fprintf(stderr, "[appinit-dll] TestDisabled\n");
    {
        edr::AppinitDllDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4100 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT"
            "\\CurrentVersion\\Windows\" /v AppInit_DLLs "
            "/d C:\\Temp\\evil.dll /f");
        detector.Enrich(event);
        AI_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[appinit-dll] TestRegAddAppInit\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4101 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT"
            "\\CurrentVersion\\Windows\" /v AppInit_DLLs "
            "/d C:\\Temp\\evil.dll /f");
        detector.Enrich(event);
        AI_CHECK(Score(event) == "90");
        AI_CHECK(event.fields.at(edr::field::kAppinitDllVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[appinit-dll] TestAppCertDlls\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4102 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control"
            "\\Session Manager\\AppCertDlls\" /v evil "
            "/d C:\\Temp\\cert.dll /f");
        detector.Enrich(event);
        AI_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[appinit-dll] TestLoadAppInitEnable\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4103 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT"
            "\\CurrentVersion\\Windows\" /v LoadAppInit_DLLs /d 1 /t "
            "REG_DWORD /f");
        detector.Enrich(event);
        AI_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[appinit-dll] TestRequireSignedDisable\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4104 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT"
            "\\CurrentVersion\\Windows\" /v RequireSignedAppInit_DLLs "
            "/d 0 /t REG_DWORD /f");
        detector.Enrich(event);
        AI_CHECK(Score(event) == "70");
        AI_CHECK(event.fields.at(edr::field::kAppinitDllVerdict) ==
                 "suspicious");
    }
    std::fprintf(stderr, "[appinit-dll] TestPowerShellWrite\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            4105 * kSecond,
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\"
            "Windows NT\\CurrentVersion\\Windows' -Name AppInit_DLLs "
            "-Value 'C:\\Users\\Public\\hook.dll'");
        detector.Enrich(event);
        AI_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[appinit-dll] TestRegWriteDriverShape\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            4106 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Windows",
            "AppInit_DLLs");
        detector.Enrich(event);
        AI_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[appinit-dll] TestRegWriteSnapshotShape\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            4107 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Windows\\AppInit_DLLs",
            "C:\\Temp\\evil.dll");
        detector.Enrich(event);
        AI_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[appinit-dll] TestSnapshotEmptySilent\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            4108 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Windows\\AppInit_DLLs",
            "");
        detector.Enrich(event);
        AI_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[appinit-dll] TestInspectionSilent\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event query = ProcEvent(
            4109 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT"
            "\\CurrentVersion\\Windows\" /v AppInit_DLLs");
        detector.Enrich(query);
        AI_CHECK(Score(query).empty());
        edr::Event get = ScriptEvent(
            4110 * kSecond,
            "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT"
            "\\CurrentVersion\\Windows' | Select AppInit_DLLs");
        detector.Enrich(get);
        AI_CHECK(Score(get).empty());
    }
    std::fprintf(stderr, "[appinit-dll] TestLoadAppInitDisableSilent\n");
    {
        edr::AppinitDllDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4111 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT"
            "\\CurrentVersion\\Windows\" /v LoadAppInit_DLLs /d 0 /f");
        detector.Enrich(event);
        AI_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[appinit-dll] all passed\n");
}
