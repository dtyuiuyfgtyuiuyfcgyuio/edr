/*
 * reg_cred_hunt_detector_tests.cpp - Unit tests for RegCredHuntDetector
 * (T1552.002 Credentials in Registry).
 */
#include "reg_cred_hunt_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "reg_cred_hunt_detector.h"

namespace {

#define RC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "reg cred hunt detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kRegCredHuntScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunRegCredHuntDetectorTests() {
    std::fprintf(stderr, "[reg-cred-hunt] TestDisabled\n");
    {
        edr::RegCredHuntDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5000 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query HKLM /f password /t REG_SZ /s");
        detector.Enrich(event);
        RC_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[reg-cred-hunt] TestHiveWideSearch\n");
    {
        edr::RegCredHuntDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5000 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query HKLM /f password /t REG_SZ /s");
        detector.Enrich(event);
        RC_CHECK(Score(event) == "90");
        RC_CHECK(event.fields.at(
            edr::field::kRegCredHuntVerdict) == "malicious");
    }
    std::fprintf(stderr, "[reg-cred-hunt] TestPowerShellRecursiveSearch\n");
    {
        edr::RegCredHuntDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            5001 * kSecond,
            "Get-ChildItem HKLM:\\SOFTWARE -Recurse | "
            "Select-String -Pattern 'password'");
        detector.Enrich(event);
        RC_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[reg-cred-hunt] TestAutologonSecretRead\n");
    {
        edr::RegCredHuntDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5002 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\Winlogon\" /v DefaultPassword");
        detector.Enrich(event);
        RC_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[reg-cred-hunt] TestPuttyStoreRead\n");
    {
        edr::RegCredHuntDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5003 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\" /s");
        detector.Enrich(event);
        RC_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[reg-cred-hunt] TestWinlogonSweepLowerBand\n");
    {
        edr::RegCredHuntDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5004 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\Winlogon\" /s");
        detector.Enrich(event);
        RC_CHECK(Score(event) == "70");
        RC_CHECK(event.fields.at(
            edr::field::kRegCredHuntVerdict) == "suspicious");
    }
    std::fprintf(stderr, "[reg-cred-hunt] TestWriteIsNotTheft\n");
    {
        /* Setting an autologon password is configuration; the persistence
         * detectors own that plane, so this must stay silent. */
        edr::RegCredHuntDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5005 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\Winlogon\" /v DefaultPassword /d Hunter2 /f");
        detector.Enrich(event);
        RC_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[reg-cred-hunt] TestBenignSilent\n");
    {
        edr::RegCredHuntDetector detector(true, 55, 300, 1024);
        /* Enumerating a key with no credential selector. */
        edr::Event plainQuery = ProcEvent(
            5006 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\"
            "CurrentVersion\" /v ProgramFilesDir");
        detector.Enrich(plainQuery);
        RC_CHECK(Score(plainQuery).empty());

        /* A credential word with no registry read verb at all. */
        edr::Event unrelated = ProcEvent(
            5007 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "echo password reset requested > ticket.txt");
        detector.Enrich(unrelated);
        RC_CHECK(Score(unrelated).empty());
    }
    std::fprintf(stderr, "[reg-cred-hunt] all passed\n");
}
