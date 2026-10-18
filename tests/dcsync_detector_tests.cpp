/*
 * dcsync_detector_tests.cpp - Unit tests for DcsyncDetector (T1003.006).
 */
#include "dcsync_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "dcsync_detector.h"

namespace {

#define DCSYNC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "dcsync detector test failed at line " +
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
    return event.fields.find(edr::field::kDcsyncScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunDcsyncDetectorTests() {
    std::fprintf(stderr, "[dcsync] TestDisabled\n");
    {
        edr::DcsyncDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"lsadump::dcsync /domain:corp.local\"");
        detector.Enrich(event);
        DCSYNC_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[dcsync] TestMimikatz\n");
    {
        /* mimikatz lsadump::dcsync -> 90 malicious. */
        edr::DcsyncDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"lsadump::dcsync /domain:corp.local /all\"");
        detector.Enrich(event);
        DCSYNC_CHECK(HasScore(event));
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncScore) == "90");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncVerdict) ==
                     "MALICIOUS");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncSignals) ==
                     "mimikatz_dcsync");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncTools) ==
                     "mimikatz");
    }
    std::fprintf(stderr, "[dcsync] TestSecretsdump\n");
    {
        /* impacket secretsdump -just-dc -> 85 malicious. */
        edr::DcsyncDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "python.exe",
            "python3 secretsdump.py -just-dc-ntlm corp.local/admin@10.0.0.5");
        detector.Enrich(event);
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncScore) == "85");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncVerdict) ==
                     "MALICIOUS");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncSignals) ==
                     "secretsdump_dcsync");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncTools) ==
                     "impacket");
    }
    std::fprintf(stderr, "[dcsync] TestInvokeDcsync\n");
    {
        /* Invoke-DCSync -> 85 malicious. */
        edr::DcsyncDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "powershell.exe",
            "powershell -c \"Invoke-DCSync -PWDumpFormat\"");
        detector.Enrich(event);
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncScore) == "85");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncSignals) ==
                     "invoke_dcsync");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncTools) ==
                     "powershell");
    }
    std::fprintf(stderr, "[dcsync] TestDcsyncTool\n");
    {
        /* standalone dcsync.py -> 80 malicious. */
        edr::DcsyncDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "python.exe",
            "python3 dcsync.py corp.local/admin:pass@10.0.0.5 -all");
        detector.Enrich(event);
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncScore) == "80");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncVerdict) ==
                     "MALICIOUS");
        DCSYNC_CHECK(event.fields.at(edr::field::kDcsyncSignals) ==
                     "dcsync_tool");
    }
    std::fprintf(stderr, "[dcsync] TestLocalSecretsdumpSilent\n");
    {
        /* Local (non-DCSync) secretsdump is out of scope. */
        edr::DcsyncDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "python.exe",
            "python3 secretsdump.py -ntds ntds.dit -system system.hiv");
        detector.Enrich(event);
        DCSYNC_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[dcsync] TestBenignSilent\n");
    {
        edr::DcsyncDetector detector(true, 55, 300, 1024);
        edr::Event notepad = ProcEvent(
            1000 * kSecond, "notepad.exe", "notepad notes.txt");
        detector.Enrich(notepad);
        DCSYNC_CHECK(!HasScore(notepad));

        edr::Event net = ProcEvent(
            1001 * kSecond, "cmd.exe", "net use \\\\10.0.0.5\\share");
        detector.Enrich(net);
        DCSYNC_CHECK(!HasScore(net));
    }
    std::fprintf(stderr, "[dcsync] TestDedupWindow\n");
    {
        edr::DcsyncDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1000 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"lsadump::dcsync /all\"");
        detector.Enrich(first);
        DCSYNC_CHECK(HasScore(first));
        edr::Event repeat = ProcEvent(
            1010 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"lsadump::dcsync /all\"");
        detector.Enrich(repeat);
        DCSYNC_CHECK(!HasScore(repeat));
        edr::Event expired = ProcEvent(
            1000 * kSecond + 301 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"lsadump::dcsync /all\"");
        detector.Enrich(expired);
        DCSYNC_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[dcsync] TestScriptBlockPlane\n");
    {
        /* Script-block logging delivers the body in kScriptBlockText only
         * - never kCommandLine/kImage. Invoke-DCSync is a script-plane
         * token, so this plane must be inspected. */
        edr::DcsyncDetector detector(true, 55, 300, 1024);
        edr::Event script;
        script.type = EDR_EVT_POWERSHELL_SCRIPT;
        script.ts100ns = 2000 * kSecond;
        script.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        script.fields[edr::field::kScriptBlockText] =
            "Import-Module .\\Invoke-DCSync.ps1\n"
            "Invoke-DCSync -Domain corp.local -PWDumpFormat";
        detector.Enrich(script);
        DCSYNC_CHECK(HasScore(script));
        DCSYNC_CHECK(script.fields.at(edr::field::kDcsyncScore) == "85");
        DCSYNC_CHECK(script.fields.at(edr::field::kDcsyncSignals) ==
                     "invoke_dcsync");

        /* A benign script body stays silent. */
        edr::Event benign;
        benign.type = EDR_EVT_POWERSHELL_SCRIPT;
        benign.ts100ns = 2001 * kSecond;
        benign.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        benign.fields[edr::field::kScriptBlockText] =
            "Get-ADUser -Filter * | Select-Object SamAccountName";
        detector.Enrich(benign);
        DCSYNC_CHECK(!HasScore(benign));
    }
    std::fprintf(stderr, "[dcsync] TestDedupIsPerCommand\n");
    {
        /* Dedup keys on the command text, so a different DCSync command
         * inside the window still alerts (keying on the signal category
         * would swallow it). */
        edr::DcsyncDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            3000 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"lsadump::dcsync /user:krbtgt\"");
        detector.Enrich(first);
        DCSYNC_CHECK(HasScore(first));

        edr::Event other = ProcEvent(
            3005 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"lsadump::dcsync /user:administrator\"");
        detector.Enrich(other);
        DCSYNC_CHECK(HasScore(other));
    }
    std::fprintf(stderr, "[dcsync] TestInspects\n");
    {
        DCSYNC_CHECK(edr::DcsyncDetector::Inspects(EDR_EVT_PROCESS_START));
        DCSYNC_CHECK(
            edr::DcsyncDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
        DCSYNC_CHECK(!edr::DcsyncDetector::Inspects(EDR_EVT_REG_WRITE));
        DCSYNC_CHECK(!edr::DcsyncDetector::Inspects(EDR_EVT_FILE_CREATE));
    }
    std::fprintf(stderr, "[dcsync] all passed\n");
}
