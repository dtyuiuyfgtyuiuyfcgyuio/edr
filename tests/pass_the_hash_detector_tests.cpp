/*
 * pass_the_hash_detector_tests.cpp - Unit tests for PassTheHashDetector
 * (T1550.002).
 */
#include "pass_the_hash_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "pass_the_hash_detector.h"

namespace {

#define PTH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "pass the hash detector test failed at line " +
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
    return event.fields.find(edr::field::kPassTheHashScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunPassTheHashDetectorTests() {
    std::fprintf(stderr, "[pass-the-hash] TestDisabled\n");
    {
        edr::PassTheHashDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"sekurlsa::pth /user:admin /ntlm:abc\"");
        detector.Enrich(event);
        PTH_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[pass-the-hash] TestMimikatzPth\n");
    {
        /* mimikatz sekurlsa::pth -> 90 malicious. */
        edr::PassTheHashDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"sekurlsa::pth /user:admin /ntlm:abc\"");
        detector.Enrich(event);
        PTH_CHECK(HasScore(event));
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashScore) == "90");
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashVerdict) ==
                  "MALICIOUS");
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashSignals) ==
                  "mimikatz_pth");
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashTools) ==
                  "mimikatz");
    }
    std::fprintf(stderr, "[pass-the-hash] TestImpacketHashes\n");
    {
        /* Impacket psexec -hashes -> 85 malicious. */
        edr::PassTheHashDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "python.exe",
            "python psexec.py -hashes :deadbeef admin@10.0.0.5");
        detector.Enrich(event);
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashScore) == "85");
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashSignals) ==
                  "impacket_pth");
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashTools) ==
                  "impacket");
    }
    std::fprintf(stderr, "[pass-the-hash] TestEvilWinrm\n");
    {
        /* evil-winrm -H <hash> -> 85 malicious. */
        edr::PassTheHashDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "evil-winrm.rb",
            "evil-winrm -i 10.0.0.5 -u admin -H deadbeef");
        detector.Enrich(event);
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashScore) == "85");
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashSignals) ==
                  "evil_winrm_pth");
    }
    std::fprintf(stderr, "[pass-the-hash] TestCrackMapExec\n");
    {
        /* crackmapexec -H -> 80 malicious. */
        edr::PassTheHashDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "crackmapexec",
            "crackmapexec smb 10.0.0.0/24 -u admin -H deadbeef");
        detector.Enrich(event);
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashScore) == "80");
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashSignals) ==
                  "crackmapexec_pth");
    }
    std::fprintf(stderr, "[pass-the-hash] TestSambaPthTool\n");
    {
        /* pth-winexe -> 75 malicious. */
        edr::PassTheHashDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "pth-winexe",
            "pth-winexe -U admin%deadbeef //10.0.0.5 cmd");
        detector.Enrich(event);
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashScore) == "75");
        PTH_CHECK(event.fields.at(edr::field::kPassTheHashSignals) ==
                  "samba_pth_tool");
    }
    std::fprintf(stderr, "[pass-the-hash] TestBenignSilent\n");
    {
        edr::PassTheHashDetector detector(true, 55, 300, 1024);
        /* Logon password dumping is out of scope for this detector. */
        edr::Event logonpasswords = ProcEvent(
            1000 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"sekurlsa::logonpasswords\"");
        detector.Enrich(logonpasswords);
        PTH_CHECK(!HasScore(logonpasswords));

        edr::Event notepad = ProcEvent(
            1001 * kSecond, "notepad.exe", "notepad notes.txt");
        detector.Enrich(notepad);
        PTH_CHECK(!HasScore(notepad));
    }
    std::fprintf(stderr, "[pass-the-hash] TestDedupWindow\n");
    {
        edr::PassTheHashDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1000 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"sekurlsa::pth /user:admin /ntlm:abc\"");
        detector.Enrich(first);
        PTH_CHECK(HasScore(first));
        edr::Event repeat = ProcEvent(
            1010 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"sekurlsa::pth /user:admin /ntlm:abc\"");
        detector.Enrich(repeat);
        PTH_CHECK(!HasScore(repeat));
        edr::Event expired = ProcEvent(
            1000 * kSecond + 301 * kSecond, "mimikatz.exe",
            "mimikatz.exe \"sekurlsa::pth /user:admin /ntlm:abc\"");
        detector.Enrich(expired);
        PTH_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[pass-the-hash] TestInspects\n");
    {
        PTH_CHECK(edr::PassTheHashDetector::Inspects(EDR_EVT_PROCESS_START));
        PTH_CHECK(!edr::PassTheHashDetector::Inspects(EDR_EVT_REG_WRITE));
        PTH_CHECK(!edr::PassTheHashDetector::Inspects(EDR_EVT_FILE_CREATE));
    }
    std::fprintf(stderr, "[pass-the-hash] all passed\n");
}
