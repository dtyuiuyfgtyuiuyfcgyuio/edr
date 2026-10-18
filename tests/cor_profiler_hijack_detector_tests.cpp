/*
 * cor_profiler_hijack_detector_tests.cpp - Unit tests for
 * CorProfilerHijackDetector (T1574.012).
 */
#include "cor_profiler_hijack_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "cor_profiler_hijack_detector.h"

namespace {

#define CP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "cor profiler hijack detector test failed at line " +
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

edr::Event RegEvent(uint64_t ts100ns, const char* key,
                    const char* value) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    if (key != nullptr) event.fields[edr::field::kRegKey] = key;
    if (value != nullptr) event.fields[edr::field::kRegValue] = value;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kCorProfilerHijackScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunCorProfilerHijackDetectorTests() {
    std::fprintf(stderr, "[cor-profiler] TestDisabled\n");
    {
        edr::CorProfilerHijackDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "setx COR_ENABLE_PROFILING 1");
        detector.Enrich(event);
        CP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[cor-profiler] TestSetxArming\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "setx COR_ENABLE_PROFILING 1");
        detector.Enrich(event);
        CP_CHECK(Score(event) == "80");
        CP_CHECK(event.fields.at(edr::field::kCorProfilerHijackVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[cor-profiler] TestSetxClsid\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "setx COR_PROFILER {846F5F1C-F9AE-4B07-969E-05C26BC060D8}");
        detector.Enrich(event);
        CP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[cor-profiler] TestRegAddCombo\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\Software\\Microsoft\\.NET /v "
            "COR_ENABLE_PROFILING /t REG_DWORD /d 1 /f");
        detector.Enrich(event);
        CP_CHECK(Score(event) == "90");
        edr::Event named = ProcEvent(
            1010 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\Software\\Microsoft\\.NET /v COR_PROFILER "
            "/t REG_SZ /d {846F5F1C-F9AE-4B07-969E-05C26BC060D8} /f");
        detector.Enrich(named);
        CP_CHECK(Score(named) == "90");
    }
    std::fprintf(stderr, "[cor-profiler] TestPowerShellSetEnvVar\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_POWERSHELL_SCRIPT;
        event.ts100ns = 1000 * kSecond;
        event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        event.fields[edr::field::kScriptBlockText] =
            "[Environment]::SetEnvironmentVariable("
            "\"COR_ENABLE_PROFILING\", \"1\", \"Machine\"); "
            "[Environment]::SetEnvironmentVariable("
            "\"COR_PROFILER\", \"{846F5F1C-...}\", \"Machine\")";
        detector.Enrich(event);
        CP_CHECK(Score(event) == "95");
    }
    std::fprintf(stderr, "[cor-profiler] TestCoreClrVariant\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "setx CORECLR_ENABLE_PROFILING 1");
        detector.Enrich(event);
        CP_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[cor-profiler] TestRegistryPlane\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
            "\\Environment",
            "COR_PROFILER");
        detector.Enrich(event);
        CP_CHECK(Score(event) == "90");
        CP_CHECK(event.fields.at(edr::field::kCorProfilerHijackVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[cor-profiler] TestRegistryPlaneSnapshotShape\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 300, 1024);
        /* Snapshot shape appends the value name to the key path. */
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
            "\\Environment\\COR_ENABLE_PROFILING",
            "1");
        detector.Enrich(event);
        CP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[cor-profiler] TestRemovalSilent\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg delete HKLM\\Software\\Microsoft\\.NET /v COR_PROFILER /f");
        detector.Enrich(event);
        CP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[cor-profiler] TestUnrelatedCommandSilent\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "setx PATH %PATH%;C:\\Tools");
        detector.Enrich(event);
        CP_CHECK(Score(event).empty());
        edr::Event reg = RegEvent(
            1001 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Updater");
        detector.Enrich(reg);
        CP_CHECK(Score(reg).empty());
    }
    std::fprintf(stderr, "[cor-profiler] TestDedupWindow\n");
    {
        edr::CorProfilerHijackDetector detector(true, 55, 60, 1024);
        const char* cmd = "setx COR_ENABLE_PROFILING 1";
        edr::Event first = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe", cmd);
        detector.Enrich(first);
        CP_CHECK(!Score(first).empty());
        edr::Event second = ProcEvent(
            1030 * kSecond, "C:\\Windows\\System32\\cmd.exe", cmd);
        detector.Enrich(second);
        CP_CHECK(Score(second).empty());
        edr::Event third = ProcEvent(
            1100 * kSecond, "C:\\Windows\\System32\\cmd.exe", cmd);
        detector.Enrich(third);
        CP_CHECK(!Score(third).empty());
    }
    std::fprintf(stderr, "[cor-profiler] all passed\n");
}
