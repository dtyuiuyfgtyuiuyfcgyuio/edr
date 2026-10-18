/*
 * av_tamper_detector_tests.cpp - Unit tests for AvTamperDetector.
 */
#include "av_tamper_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "av_tamper_detector.h"

namespace {

#define AVT_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "av tamper detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* body) {
    /* Producer contract: POWERSHELL_SCRIPT events carry the script body
     * in kScriptBlockText only - never in kCommandLine/kImage (see
     * powershell_parser / reassembler). */
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = body;
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

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kAvTamperScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunAvTamperDetectorTests() {
    std::fprintf(stderr, "[av-tamper] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::AvTamperDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\WindowsPowerShell"
                            "\\v1.0\\powershell.exe",
            "powershell Set-MpPreference -DisableRealtimeMonitoring $true");
        detector.Enrich(event);
        AVT_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[av-tamper] TestDisableCapability\n");
    {
        /* Set-MpPreference disabling realtime monitoring -> 90. */
        edr::AvTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\WindowsPowerShell"
                            "\\v1.0\\powershell.exe",
            "powershell -c Set-MpPreference -DisableRealtimeMonitoring 1");
        detector.Enrich(event);
        AVT_CHECK(HasScore(event));
        AVT_CHECK(event.fields.at(edr::field::kAvTamperScore) == "90");
        AVT_CHECK(event.fields.at(edr::field::kAvTamperVerdict) ==
                  "malicious");
    }
    {
        /* Disable switch without a Defender cmdlet never fires
         * (unrelated product vocabulary). */
        edr::AvTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "app.exe --disablerealtimemonitoring");
        detector.Enrich(event);
        AVT_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[av-tamper] TestExclusion\n");
    {
        /* Exclusion path addition -> 80 suspicious (75+ is malicious;
         * 80 stays malicious per band contract). */
        edr::AvTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            1000 * kSecond,
            "Add-MpPreference -ExclusionPath 'C:\\temp\\tools'");
        detector.Enrich(event);
        AVT_CHECK(HasScore(event));
        AVT_CHECK(event.fields.at(edr::field::kAvTamperScore) == "80");
        AVT_CHECK(event.fields.at(edr::field::kAvTamperSignals) ==
                  "defender exclusion added");
    }
    std::fprintf(stderr, "[av-tamper] TestMpCmdRun\n");
    {
        /* Signature removal -> 75. */
        edr::AvTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond,
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform"
            "\\4.18\\MpCmdRun.exe",
            "MpCmdRun.exe -RemoveDefinitions -All");
        detector.Enrich(event);
        AVT_CHECK(HasScore(event));
        AVT_CHECK(event.fields.at(edr::field::kAvTamperScore) == "75");
    }
    std::fprintf(stderr, "[av-tamper] TestUninstall\n");
    {
        /* MSI uninstall of Defender -> 85. */
        edr::AvTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
            "msiexec /x windows-defender-package /qn");
        detector.Enrich(event);
        AVT_CHECK(HasScore(event));
        AVT_CHECK(event.fields.at(edr::field::kAvTamperScore) == "85");
    }
    std::fprintf(stderr, "[av-tamper] TestRegistryPolicy\n");
    {
        /* Policies key disable write -> 85 (driver shape: value NAME in
         * kRegValue, bare key in kRegKey). */
        edr::AvTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            "DisableAntiSpyware");
        detector.Enrich(event);
        AVT_CHECK(HasScore(event));
        AVT_CHECK(event.fields.at(edr::field::kAvTamperScore) == "85");

        /* Snapshot shape (sysmon/reg_watch/reg_baseline): kRegKey
         * carries the full path INCLUDING the value name and kRegValue
         * holds the DATA. Same write must still hit. */
        edr::Event snap = RegEvent(
            1500 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
            "\\DisableAntiSpyware",
            "0x00000001");
        detector.Enrich(snap);
        AVT_CHECK(HasScore(snap));
        AVT_CHECK(snap.fields.at(edr::field::kAvTamperScore) == "85");

        /* WDigest re-enable, both shapes -> 85. */
        edr::Event wdigestDriver = RegEvent(
            1750 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
            "\\WDigest",
            "UseLogonCredential");
        detector.Enrich(wdigestDriver);
        AVT_CHECK(HasScore(wdigestDriver));
        AVT_CHECK(wdigestDriver.fields.at(edr::field::kAvTamperScore) ==
                  "85");
        edr::Event wdigestSnap = RegEvent(
            1760 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\WDigest"
            "\\UseLogonCredential",
            "0x00000001");
        detector.Enrich(wdigestSnap);
        AVT_CHECK(HasScore(wdigestSnap));
        AVT_CHECK(wdigestSnap.fields.at(edr::field::kAvTamperScore) ==
                  "85");

        /* Exclusions subkey write -> 75. */
        edr::Event excl = RegEvent(
            2000 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
            "\\Exclusions\\Paths",
            "c1");
        detector.Enrich(excl);
        AVT_CHECK(HasScore(excl));
        AVT_CHECK(excl.fields.at(edr::field::kAvTamperScore) == "75");

        /* Unrelated policy write never fires. */
        edr::Event benign = RegEvent(
            3000 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
            "DisableOSUpgrade");
        detector.Enrich(benign);
        AVT_CHECK(!HasScore(benign));

        /* Defender policy key with an unrelated value name never fires. */
        edr::Event other = RegEvent(
            4000 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            "PUAProtection");
        detector.Enrich(other);
        AVT_CHECK(!HasScore(other));
    }
    std::fprintf(stderr, "[av-tamper] TestDedupAndCapacity\n");
    {
        /* Identical command inside the dedup window fires once. */
        edr::AvTamperDetector detector(true, 55, 300, 1024);
        const char* cmd =
            "powershell Set-MpPreference -DisableScriptScanning 1";
        edr::Event first = ProcEvent(1000 * kSecond, "powershell.exe", cmd);
        edr::Event second = ProcEvent(1010 * kSecond, "powershell.exe", cmd);
        detector.Enrich(first);
        detector.Enrich(second);
        AVT_CHECK(HasScore(first));
        AVT_CHECK(!HasScore(second));

        /* After the window it re-arms. */
        edr::Event third = ProcEvent(
            1000 * kSecond + 301 * kSecond, "powershell.exe", cmd);
        detector.Enrich(third);
        AVT_CHECK(HasScore(third));
    }
    {
        /* State capacity reset keeps the detector live. */
        edr::AvTamperDetector detector(true, 55, 300, 2);
        for (int i = 0; i < 4; ++i) {
            std::string cmd =
                "powershell Set-MpPreference -DisableIOAVProtection " +
                std::to_string(i);
            edr::Event event = ProcEvent(
                (1000 + i) * kSecond, "powershell.exe", cmd.c_str());
            detector.Enrich(event);
            AVT_CHECK(HasScore(event));
        }
    }
    std::fprintf(stderr, "[av-tamper] TestBelowMinScoreSilent\n");
    {
        /* min_score above every family score suppresses stamping. */
        edr::AvTamperDetector detector(true, 95, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "powershell.exe",
            "Set-MpPreference -DisableCatchupQuickScan 1"); /* 90 < 95 */
        detector.Enrich(event);
        AVT_CHECK(!HasScore(event));
    }
}
