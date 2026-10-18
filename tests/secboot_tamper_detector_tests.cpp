/*
 * secboot_tamper_detector_tests.cpp - Unit tests for
 * SecbootTamperDetector (VBS / HVCI / Credential Guard disable).
 */
#include "secboot_tamper_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "secboot_tamper_detector.h"

namespace {

#define SB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "secboot tamper detector test failed at line " +
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

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kSecbootTamperScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunSecbootTamperDetectorTests() {
    std::fprintf(stderr, "[secboot] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::SecbootTamperDetector detector(false, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "LsaCfgFlags");
        detector.Enrich(event);
        SB_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[secboot] TestVbsDisableRegistry\n");
    {
        /* Driver shape: bare value name in kRegValue -> 85 malicious. */
        edr::SecbootTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            "EnableVirtualizationBasedSecurity");
        detector.Enrich(event);
        SB_CHECK(HasScore(event));
        SB_CHECK(event.fields.at(edr::field::kSecbootTamperScore) == "85");
        SB_CHECK(event.fields.at(edr::field::kSecbootTamperVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[secboot] TestHvciSnapshotShape\n");
    {
        /* Snapshot shape: full path incl. value name in kRegKey, data
         * in kRegValue. Zero data -> fires; nonzero data -> hardening,
         * silent. */
        edr::SecbootTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
            "\\HypervisorEnforcedCodeIntegrity",
            "0x00000000");
        detector.Enrich(event);
        SB_CHECK(HasScore(event));
        SB_CHECK(event.fields.at(edr::field::kSecbootTamperSignals) ==
                 "HVCI disabled via registry");

        edr::Event hardened = RegEvent(
            1001 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
            "\\HypervisorEnforcedCodeIntegrity",
            "1");
        detector.Enrich(hardened);
        SB_CHECK(!HasScore(hardened));
    }
    std::fprintf(stderr, "[secboot] TestCredentialGuard\n");
    {
        edr::SecbootTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "LsaCfgFlags");
        detector.Enrich(event);
        SB_CHECK(HasScore(event));
        SB_CHECK(event.fields.at(edr::field::kSecbootTamperScore) == "80");
    }
    std::fprintf(stderr, "[secboot] TestCommandLinePlane\n");
    {
        edr::SecbootTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = TextEvent(
            EDR_EVT_PROCESS_START, 1000 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard "
            "/v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f");
        detector.Enrich(event);
        SB_CHECK(HasScore(event));
        SB_CHECK(event.fields.at(edr::field::kSecbootTamperScore) == "80");

        /* PowerShell script body lives in kScriptBlockText only. */
        edr::Event script = TextEvent(
            EDR_EVT_POWERSHELL_SCRIPT, 1001 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            nullptr);
        script.fields[edr::field::kScriptBlockText] =
            "$p | Set-ItemProperty -Name HypervisorEnforcedCodeIntegrity "
            "-Value 0";
        detector.Enrich(script);
        SB_CHECK(HasScore(script));
        SB_CHECK(script.fields.at(edr::field::kSecbootTamperScore) == "75" ||
                 script.fields.at(edr::field::kSecbootTamperScore) == "80");
    }
    std::fprintf(stderr, "[secboot] TestBenignSilent\n");
    {
        edr::SecbootTamperDetector detector(true, 55, 300, 1024);
        /* Unrelated Lsa value and unrelated registry write stay silent.
         * min_score isolation: fresh instance at default threshold. */
        edr::Event benign = RegEvent(
            1000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "RestrictAnonymous");
        detector.Enrich(benign);
        SB_CHECK(!HasScore(benign));

        edr::Event cmd = TextEvent(
            EDR_EVT_PROCESS_START, 1001 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa "
            "/v LsaCfgFlags");
        detector.Enrich(cmd);
        SB_CHECK(!HasScore(cmd));
    }
    std::fprintf(stderr, "[secboot] TestDedupWindow\n");
    {
        edr::SecbootTamperDetector detector(true, 55, 60, 1024);
        edr::Event first = RegEvent(
            1000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "LsaCfgFlags");
        detector.Enrich(first);
        SB_CHECK(HasScore(first));

        edr::Event second = RegEvent(
            1010 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "LsaCfgFlags");
        detector.Enrich(second);
        SB_CHECK(!HasScore(second));   /* within dedup window */

        edr::Event third = RegEvent(
            1100 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "LsaCfgFlags");
        detector.Enrich(third);
        SB_CHECK(HasScore(third));     /* window elapsed */
    }
    std::fprintf(stderr, "[secboot] all passed\n");
}
