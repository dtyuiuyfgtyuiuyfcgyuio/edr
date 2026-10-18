/*
 * shadow_copy_detector_tests.cpp - Unit tests for ShadowCopyDetector.
 */
#include "shadow_copy_detector_tests.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "shadow_copy_detector.h"

namespace {

#define SHADOW_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "shadow copy detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* command) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (command != nullptr) {
        event.fields[edr::field::kCommandLine] = command;
    }
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kShadowCopyScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunShadowCopyDetectorTests() {
    std::fprintf(stderr, "[shadow-copy] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::ShadowCopyDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "vssadmin.exe",
            "vssadmin delete shadows /all /quiet");
        detector.Enrich(event);
        SHADOW_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[shadow-copy] TestVssadminAll\n");
    {
        /* Delete all shadow copies -> 90 malicious. */
        edr::ShadowCopyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "vssadmin.exe",
            "vssadmin delete shadows /all /quiet");
        detector.Enrich(event);
        SHADOW_CHECK(HasScore(event));
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyScore) == "90");
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyVerdict) ==
                     "malicious");
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopySignals).find(
                         "vssadmin") != std::string::npos);
    }
    std::fprintf(stderr, "[shadow-copy] TestVssadminVolume\n");
    {
        /* Per-volume delete -> 75 malicious. */
        edr::ShadowCopyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "vssadmin.exe",
            "vssadmin delete shadows /for=C:");
        detector.Enrich(event);
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyScore) == "75");
    }
    std::fprintf(stderr, "[shadow-copy] TestWmicDelete\n");
    {
        /* WMI shadowcopy delete -> 75. */
        edr::ShadowCopyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "wmic.exe",
            "wmic shadowcopy delete");
        detector.Enrich(event);
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyScore) == "75");
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyVerdict) ==
                     "malicious");
    }
    std::fprintf(stderr, "[shadow-copy] TestPowerShellRemove\n");
    {
        /* PowerShell WMI removal -> 70 suspicious. */
        edr::ShadowCopyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "powershell.exe",
            "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject");
        detector.Enrich(event);
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyScore) == "70");
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyVerdict) ==
                     "suspicious");
    }
    std::fprintf(stderr, "[shadow-copy] TestWbadminCatalog\n");
    {
        /* Backup catalog deletion -> 70. */
        edr::ShadowCopyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "wbadmin.exe",
            "wbadmin delete catalog -backupTarget:\\\\server\\share");
        detector.Enrich(event);
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyScore) == "70");
    }
    std::fprintf(stderr, "[shadow-copy] TestBcdeditRecoveryOff\n");
    {
        /* Disable boot recovery -> 60. */
        edr::ShadowCopyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "bcdedit.exe",
            "bcdedit /set {default} recoveryenabled no");
        detector.Enrich(event);
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyScore) == "60");
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyVerdict) ==
                     "suspicious");
    }
    std::fprintf(stderr, "[shadow-copy] TestCombinedEscalation\n");
    {
        /* Shadow wipe + recovery disable -> 95. */
        edr::ShadowCopyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "cmd.exe",
            "vssadmin delete shadows /all /quiet & "
            "bcdedit /set {default} recoveryenabled no");
        detector.Enrich(event);
        SHADOW_CHECK(event.fields.at(edr::field::kShadowCopyScore) == "95");
    }
    std::fprintf(stderr, "[shadow-copy] TestBenignSilent\n");
    {
        /* Ordinary commands never score. */
        edr::ShadowCopyDetector detector(true, 55, 300, 1024);
        edr::Event notepad = ProcEvent(
            1000 * kSecond, "notepad.exe", "notepad notes.txt");
        detector.Enrich(notepad);
        SHADOW_CHECK(!HasScore(notepad));

        edr::Event vssList = ProcEvent(
            1001 * kSecond, "vssadmin.exe", "vssadmin list shadows");
        detector.Enrich(vssList);
        SHADOW_CHECK(!HasScore(vssList));

        edr::Event noCommand = ProcEvent(
            1002 * kSecond, "C:\\Windows\\System32\\vssadmin.exe", nullptr);
        detector.Enrich(noCommand);
        SHADOW_CHECK(!HasScore(noCommand));
    }
    std::fprintf(stderr, "[shadow-copy] TestDedupWindow\n");
    {
        /* Same signal within the window fires once. */
        edr::ShadowCopyDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1000 * kSecond, "vssadmin.exe",
            "vssadmin delete shadows /all /quiet");
        detector.Enrich(first);
        SHADOW_CHECK(HasScore(first));
        edr::Event repeat = ProcEvent(
            1010 * kSecond, "vssadmin.exe",
            "vssadmin delete shadows /all /quiet");
        detector.Enrich(repeat);
        SHADOW_CHECK(!HasScore(repeat));
        edr::Event expired = ProcEvent(
            1000 * kSecond + 301 * kSecond, "vssadmin.exe",
            "vssadmin delete shadows /all /quiet");
        detector.Enrich(expired);
        SHADOW_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[shadow-copy] TestInspects\n");
    {
        /* Only PROCESS_START is inspected. */
        SHADOW_CHECK(
            edr::ShadowCopyDetector::Inspects(EDR_EVT_PROCESS_START));
        SHADOW_CHECK(!edr::ShadowCopyDetector::Inspects(EDR_EVT_REG_WRITE));
        SHADOW_CHECK(!edr::ShadowCopyDetector::Inspects(EDR_EVT_DNS_QUERY));
    }
    std::fprintf(stderr, "[shadow-copy] all passed\n");
}
