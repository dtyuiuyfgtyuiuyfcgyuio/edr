/*
 * etw_script_tamper_detector_tests.cpp - Unit tests for
 * EtwScriptTamperDetector.
 */
#include "etw_script_tamper_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "etw_script_tamper_detector.h"

namespace {

#define ETS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "etw script tamper detector test failed at line " +
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

/* House contract: a POWERSHELL_SCRIPT event carries its body ONLY in
 * kScriptBlockText - never kCommandLine/kImage. */
edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptBody) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptBody;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kEtwScriptScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunEtwScriptTamperDetectorTests() {
    std::fprintf(stderr, "[etw-script] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::EtwScriptTamperDetector detector(false, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            1000 * kSecond,
            "[System.Management.Automation.Tracing.PSEtwLogProvider]"
            "::get_EventProviders()");
        detector.Enrich(event);
        ETS_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[etw-script] TestPSEtwLogProviderStrip\n");
    {
        edr::EtwScriptTamperDetector detector(true, 55, 300, 1024);
        /* Provider strip (reflection + provider enumeration). */
        edr::Event strip = ScriptEvent(
            1000 * kSecond,
            "$p=[System.Management.Automation.Tracing.PSEtwLogProvider];"
            "$e=$p::get_EventProviders()");
        detector.Enrich(strip);
        ETS_CHECK(HasScore(strip));
        ETS_CHECK(strip.fields.at(edr::field::kEtwScriptScore) == "85");
        ETS_CHECK(strip.fields.at(edr::field::kEtwScriptVerdict) ==
                  "malicious");

        /* Bare PSEtwLogProvider mention stays suspicious. */
        edr::Event bare = ScriptEvent(
            2000 * kSecond,
            "Write-Host [System.Management.Automation.Tracing."
            "PSEtwLogProvider] exists");
        detector.Enrich(bare);
        ETS_CHECK(HasScore(bare));
        ETS_CHECK(bare.fields.at(edr::field::kEtwScriptScore) == "70");
        ETS_CHECK(bare.fields.at(edr::field::kEtwScriptVerdict) ==
                  "suspicious");

        /* min_score above the reference band suppresses it. */
        edr::EtwScriptTamperDetector strict(true, 75, 300, 1024);
        edr::Event strictHit = ScriptEvent(
            3000 * kSecond,
            "Write-Host [System.Management.Automation.Tracing."
            "PSEtwLogProvider] exists");
        strict.Enrich(strictHit);
        ETS_CHECK(!HasScore(strictHit));
    }
    std::fprintf(stderr, "[etw-script] TestEtwEventWritePatch\n");
    {
        edr::EtwScriptTamperDetector detector(true, 55, 300, 1024);
        /* Patch pair: target + memory-write primitive -> 90. */
        edr::Event patch = ScriptEvent(
            1000 * kSecond,
            "$a=[Runtime.InteropServices.Marshal]::GetDelegateForFunction"
            "Pointer; VirtualProtect $addr 1 0x40; patch etweventwrite");
        detector.Enrich(patch);
        ETS_CHECK(HasScore(patch));
        ETS_CHECK(patch.fields.at(edr::field::kEtwScriptScore) == "90");
        ETS_CHECK(patch.fields.at(edr::field::kEtwScriptSignals) ==
                  "EtwEventWrite patch in script");

        /* Bare EtwEventWrite reference -> 60 suspicious. */
        edr::Event ref = ScriptEvent(
            2000 * kSecond,
            "blog notes: ntdll!EtwEventWrite prologue bytes");
        detector.Enrich(ref);
        ETS_CHECK(HasScore(ref));
        ETS_CHECK(ref.fields.at(edr::field::kEtwScriptScore) == "60");
        ETS_CHECK(ref.fields.at(edr::field::kEtwScriptVerdict) ==
                  "suspicious");
    }
    std::fprintf(stderr, "[etw-script] TestTraceSessionCmdlets\n");
    {
        edr::EtwScriptTamperDetector detector(true, 55, 300, 1024);
        edr::Event stop = ScriptEvent(
            1000 * kSecond,
            "Stop-EtwTraceSession -Name \"Microsoft-Windows-PowerShell\"");
        detector.Enrich(stop);
        ETS_CHECK(HasScore(stop));
        ETS_CHECK(stop.fields.at(edr::field::kEtwScriptScore) == "80");

        edr::Event traffic = ProcEvent(
            2000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -c Set-EtwTrafficPolicy -ErrorAction 0");
        detector.Enrich(traffic);
        ETS_CHECK(HasScore(traffic));
        ETS_CHECK(traffic.fields.at(edr::field::kEtwScriptScore) == "80");
    }
    std::fprintf(stderr, "[etw-script] TestLogmanTelemetryTarget\n");
    {
        edr::EtwScriptTamperDetector detector(true, 55, 300, 1024);
        /* logman against a telemetry session name -> 75. */
        edr::Event hit = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\logman.exe",
            "logman stop sysmon -ets");
        detector.Enrich(hit);
        ETS_CHECK(HasScore(hit));
        ETS_CHECK(hit.fields.at(edr::field::kEtwScriptScore) == "75");
        ETS_CHECK(hit.fields.at(edr::field::kEtwScriptVerdict) ==
                  "malicious");

        /* logman against an arbitrary user session never fires. */
        edr::Event miss = ProcEvent(
            2000 * kSecond, "C:\\Windows\\System32\\logman.exe",
            "logman stop perf_capture -ets");
        detector.Enrich(miss);
        ETS_CHECK(!HasScore(miss));
    }
    std::fprintf(stderr, "[etw-script] TestAutologgerAndWevtutil\n");
    {
        edr::EtwScriptTamperDetector detector(true, 55, 300, 1024);
        /* Autologger start-key disable -> 70. */
        edr::Event autoLogger = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\"
            "Autologger\\Sysmon\\Start /d 0 /f");
        detector.Enrich(autoLogger);
        ETS_CHECK(HasScore(autoLogger));
        ETS_CHECK(autoLogger.fields.at(edr::field::kEtwScriptScore) ==
                  "70");
        ETS_CHECK(autoLogger.fields.at(edr::field::kEtwScriptVerdict) ==
                  "suspicious");

        /* wevtutil channel disable -> 70. */
        edr::Event wevt = ProcEvent(
            2000 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
            "wevtutil sl Microsoft-Windows-PowerShell/Operational "
            "/e:false");
        detector.Enrich(wevt);
        ETS_CHECK(HasScore(wevt));
        ETS_CHECK(wevt.fields.at(edr::field::kEtwScriptScore) == "70");

        /* Autologger without a write primitive never fires. */
        edr::Event read = ProcEvent(
            3000 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\"
            "Autologger\\Sysmon\\Start");
        detector.Enrich(read);
        ETS_CHECK(!HasScore(read));
    }
    std::fprintf(stderr, "[etw-script] TestScriptFaceContract\n");
    {
        /* A POWERSHELL_SCRIPT event carries its body ONLY in
         * kScriptBlockText (house contract); such an event without any
         * body must stay silent rather than leak across faces. */
        edr::EtwScriptTamperDetector detector(true, 55, 300, 1024);
        edr::Event bodyless =
            ProcEvent(1000 * kSecond, "powershell.exe", nullptr);
        bodyless.type = EDR_EVT_POWERSHELL_SCRIPT;
        bodyless.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        detector.Enrich(bodyless);
        ETS_CHECK(!HasScore(bodyless));

        /* PROCESS_START one-liner on the command plane does fire. */
        edr::Event cmdFace = ProcEvent(
            2000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
            "powershell.exe",
            "powershell -enc <b64 of Remove-EtwTraceSession sysmon>");
        detector.Enrich(cmdFace);
        ETS_CHECK(HasScore(cmdFace));
    }
    std::fprintf(stderr, "[etw-script] TestDedupAndBelowMin\n");
    {
        /* Identical script inside the dedup window fires once. */
        edr::EtwScriptTamperDetector detector(true, 55, 300, 1024);
        const char* body =
            "Stop-EtwTraceSession -Name Microsoft-Windows-PowerShell";
        edr::Event first = ScriptEvent(1000 * kSecond, body);
        detector.Enrich(first);
        ETS_CHECK(HasScore(first));

        edr::Event second = ScriptEvent(1010 * kSecond, body);
        detector.Enrich(second);
        ETS_CHECK(!HasScore(second));

        /* Same script after the window closes fires again. */
        edr::Event later = ScriptEvent(1400 * kSecond, body);
        detector.Enrich(later);
        ETS_CHECK(HasScore(later));
    }
    {
        /* min_score above all family scores suppresses stamping. */
        edr::EtwScriptTamperDetector detector(true, 95, 300, 1024);
        edr::Event event = ScriptEvent(
            1000 * kSecond,
            "[System.Management.Automation.Tracing.PSEtwLogProvider]"
            "::get_EventProviders()");
        detector.Enrich(event);
        ETS_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[etw-script] all passed\n");
}
