/*
 * winrm_abuse_detector_tests.cpp - Unit tests for WinrmAbuseDetector
 * (T1021.006 command-plane remote execution).
 */
#include "winrm_abuse_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "winrm_abuse_detector.h"

namespace {

#define WR_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "winrm abuse detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event TextEvent(uint16_t type, uint64_t ts100ns, const char* image,
                     const char* commandLine) {
    edr::Event event;
    event.type = type;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] =
        type == EDR_EVT_POWERSHELL_SCRIPT ? "POWERSHELL_SCRIPT"
                                          : "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kWinrmAbuseScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunWinrmAbuseDetectorTests() {
    std::fprintf(stderr, "[winrm] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::WinrmAbuseDetector detector(false, 55, 300, 1024);
        edr::Event event = TextEvent(
            EDR_EVT_PROCESS_START, 1000 * kSecond,
            "C:\\Windows\\System32\\winrs.exe",
            "winrs -r:dc01.corp.lab whoami");
        detector.Enrich(event);
        WR_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[winrm] TestWinrsInvocation\n");
    {
        edr::WinrmAbuseDetector detector(true, 55, 300, 1024);
        /* Full path invocation -> 85 malicious. */
        edr::Event event = TextEvent(
            EDR_EVT_PROCESS_START, 1000 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\winrs.exe -r:dc01.corp.lab "
            "cmd /c whoami");
        detector.Enrich(event);
        WR_CHECK(HasScore(event));
        WR_CHECK(event.fields.at(edr::field::kWinrmAbuseScore) == "85");
        WR_CHECK(event.fields.at(edr::field::kWinrmAbuseVerdict) ==
                 "malicious");

        /* Extension-less bare token also hits... */
        edr::Event bare = TextEvent(
            EDR_EVT_PROCESS_START, 1001 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "winrs -r:dc02 dir C:\\");
        detector.Enrich(bare);
        WR_CHECK(HasScore(bare));

        /* ...but prose containing "winrssrv" never does. */
        edr::Event prose = TextEvent(
            EDR_EVT_PROCESS_START, 1002 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "net use \\\\winrssrv01\\share");
        detector.Enrich(prose);
        WR_CHECK(!HasScore(prose));
    }
    std::fprintf(stderr, "[winrm] TestPowerShellRemoting\n");
    {
        edr::WinrmAbuseDetector detector(true, 55, 300, 1024);
        /* Script body lives in kScriptBlockText only. */
        edr::Event script = TextEvent(
            EDR_EVT_POWERSHELL_SCRIPT, 1000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            nullptr);
        script.fields[edr::field::kScriptBlockText] =
            "$s = New-PSSession -ComputerName dc01.corp.lab\n"
            "Invoke-Command -Session $s -ScriptBlock { whoami }";
        detector.Enrich(script);
        WR_CHECK(HasScore(script));
        WR_CHECK(script.fields.at(edr::field::kWinrmAbuseScore) == "80");

        /* Command-line variant with -ComputerName. */
        edr::Event cmdline = TextEvent(
            EDR_EVT_PROCESS_START, 1001 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -c Invoke-Command -ComputerName srv05 "
            "-ScriptBlock { ipconfig }");
        detector.Enrich(cmdline);
        WR_CHECK(HasScore(cmdline));
        WR_CHECK(cmdline.fields.at(edr::field::kWinrmAbuseScore) == "80");

        /* Local-session cmdlet without a remote target stays silent. */
        edr::Event local = TextEvent(
            EDR_EVT_POWERSHELL_SCRIPT, 1002 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            nullptr);
        local.fields[edr::field::kScriptBlockText] =
            "$s = New-PSSessionConfigurationOption";
        detector.Enrich(local);
        WR_CHECK(!HasScore(local));
    }
    std::fprintf(stderr, "[winrm] TestWinrmConfigManipulation\n");
    {
        edr::WinrmAbuseDetector detector(true, 55, 300, 1024);
        edr::Event remote = TextEvent(
            EDR_EVT_PROCESS_START, 1000 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "winrm invoke Create wmicimv2/Win32_Process -r:srv03 "
            "@{CommandLine=\"calc.exe\"}");
        detector.Enrich(remote);
        WR_CHECK(HasScore(remote));
        WR_CHECK(remote.fields.at(edr::field::kWinrmAbuseScore) == "75");

        edr::Event quickconfig = TextEvent(
            EDR_EVT_PROCESS_START, 1001 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "winrm quickconfig -q");
        detector.Enrich(quickconfig);
        WR_CHECK(HasScore(quickconfig));
        WR_CHECK(quickconfig.fields.at(edr::field::kWinrmAbuseScore) ==
                 "60");
        WR_CHECK(quickconfig.fields.at(edr::field::kWinrmAbuseVerdict) ==
                 "suspicious");
    }
    std::fprintf(stderr, "[winrm] TestDedupWindow\n");
    {
        edr::WinrmAbuseDetector detector(true, 55, 60, 1024);
        edr::Event first = TextEvent(
            EDR_EVT_PROCESS_START, 1000 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "winrs -r:dc01 whoami");
        detector.Enrich(first);
        WR_CHECK(HasScore(first));

        edr::Event second = TextEvent(
            EDR_EVT_PROCESS_START, 1010 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "winrs -r:dc01 whoami");
        detector.Enrich(second);
        WR_CHECK(!HasScore(second));   /* within dedup window */

        edr::Event third = TextEvent(
            EDR_EVT_PROCESS_START, 1100 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "winrs -r:dc01 whoami");
        detector.Enrich(third);
        WR_CHECK(HasScore(third));     /* window elapsed */
    }
    std::fprintf(stderr, "[winrm] all passed\n");
}
