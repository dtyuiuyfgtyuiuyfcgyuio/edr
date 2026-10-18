/*
 * remote_exec_detector_tests.cpp - Unit tests for RemoteExecDetector
 * (T1021.002/T1021.006/T1053.005).
 */
#include "remote_exec_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "remote_exec_detector.h"

namespace {

#define REMOTE_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "remote exec detector test failed at line " +
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
    return event.fields.find(edr::field::kRemoteExecScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunRemoteExecDetectorTests() {
    std::fprintf(stderr, "[remote-exec] TestDisabled\n");
    {
        edr::RemoteExecDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "PsExec.exe",
            "PsExec.exe \\\\10.0.0.5 -accepteula cmd.exe");
        detector.Enrich(event);
        REMOTE_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[remote-exec] TestPsExec\n");
    {
        /* PsExec with a remote target -> 80 malicious. */
        edr::RemoteExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "PsExec.exe",
            "PsExec.exe \\\\10.0.0.5 -accepteula cmd.exe");
        detector.Enrich(event);
        REMOTE_CHECK(HasScore(event));
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecScore) == "80");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecVerdict) ==
                     "MALICIOUS");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecSignals) ==
                     "psexec_remote");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecTools) ==
                     "psexec");
    }
    std::fprintf(stderr, "[remote-exec] TestWmicRemote\n");
    {
        /* wmic /node: + process call create -> 75 malicious. */
        edr::RemoteExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "wmic.exe",
            "wmic /node:10.0.0.5 process call create \"cmd.exe\"");
        detector.Enrich(event);
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecScore) == "75");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecVerdict) ==
                     "MALICIOUS");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecSignals) ==
                     "wmic_remote_exec");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecTools) ==
                     "wmic");
    }
    std::fprintf(stderr, "[remote-exec] TestWinrs\n");
    {
        /* winrs -r:host -> 75 malicious. */
        edr::RemoteExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "winrs.exe",
            "winrs -r:10.0.0.5 whoami");
        detector.Enrich(event);
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecScore) == "75");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecVerdict) ==
                     "MALICIOUS");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecSignals) ==
                     "winrs_remote");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecTools) ==
                     "winrs");
    }
    std::fprintf(stderr, "[remote-exec] TestScRemoteService\n");
    {
        /* sc \\host create/start -> 75 malicious. */
        edr::RemoteExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "sc.exe",
            "sc \\\\10.0.0.5 create EvilSvc binPath= C:\\evil.exe");
        detector.Enrich(event);
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecScore) == "75");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecVerdict) ==
                     "MALICIOUS");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecSignals) ==
                     "sc_remote_service");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecTools) == "sc");
    }
    std::fprintf(stderr, "[remote-exec] TestSchtasksRemote\n");
    {
        /* schtasks /create with /s host -> 70 suspicious. */
        edr::RemoteExecDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "schtasks.exe",
            "schtasks /create /s 10.0.0.5 /tn EvilTask /tr calc.exe /sc once");
        detector.Enrich(event);
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecScore) == "70");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecVerdict) ==
                     "SUSPICIOUS");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecSignals) ==
                     "schtasks_remote");
        REMOTE_CHECK(event.fields.at(edr::field::kRemoteExecTools) ==
                     "schtasks");
    }
    std::fprintf(stderr, "[remote-exec] TestBenignSilent\n");
    {
        edr::RemoteExecDetector detector(true, 55, 300, 1024);
        /* Local PsExec usage (no UNC target) is out of scope. */
        edr::Event localPsExec = ProcEvent(
            1000 * kSecond, "PsExec.exe", "PsExec.exe -accepteula cmd.exe");
        detector.Enrich(localPsExec);
        REMOTE_CHECK(!HasScore(localPsExec));

        /* Local schtasks usage (no /s host) is out of scope. */
        edr::Event localTask = ProcEvent(
            1001 * kSecond, "schtasks.exe",
            "schtasks /create /tn DailyTask /tr calc.exe /sc daily");
        detector.Enrich(localTask);
        REMOTE_CHECK(!HasScore(localTask));

        edr::Event notepad = ProcEvent(
            1002 * kSecond, "notepad.exe", "notepad notes.txt");
        detector.Enrich(notepad);
        REMOTE_CHECK(!HasScore(notepad));

        /* A host whose name merely starts with "winrs" is not a winrs
         * invocation (same boundary contract as winrm_abuse). */
        edr::Event winrsHost = ProcEvent(
            1003 * kSecond, "robocopy.exe",
            "robocopy \\\\winrssrv01\\share C:\\bak -r 3");
        detector.Enrich(winrsHost);
        REMOTE_CHECK(!HasScore(winrsHost));

        /* sc.exe against a local service is out of scope. */
        edr::Event localSc = ProcEvent(
            1004 * kSecond, "sc.exe", "sc.exe query EvilSvc");
        detector.Enrich(localSc);
        REMOTE_CHECK(!HasScore(localSc));
    }
    std::fprintf(stderr, "[remote-exec] TestScSpellings\n");
    {
        /* The remote-service form must be recognized with the .exe
         * spelling too, not only the bare "sc \\host" one. */
        edr::RemoteExecDetector detector(true, 55, 300, 1024);
        edr::Event withExe = ProcEvent(
            1200 * kSecond, "sc.exe",
            "sc.exe \\\\10.0.0.9 create EvilSvc binPath= C:\\evil.exe");
        detector.Enrich(withExe);
        REMOTE_CHECK(HasScore(withExe));
        REMOTE_CHECK(withExe.fields.at(edr::field::kRemoteExecSignals) ==
                     "sc_remote_service");
    }
    std::fprintf(stderr, "[remote-exec] TestDedupIsPerCommand\n");
    {
        /* Dedup keys on the command text, so a second remote-execution
         * command against a different host still alerts. */
        edr::RemoteExecDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1300 * kSecond, "PsExec.exe", "PsExec.exe \\\\10.0.0.5 cmd.exe");
        detector.Enrich(first);
        REMOTE_CHECK(HasScore(first));

        edr::Event otherHost = ProcEvent(
            1305 * kSecond, "PsExec.exe", "PsExec.exe \\\\10.0.0.6 cmd.exe");
        detector.Enrich(otherHost);
        REMOTE_CHECK(HasScore(otherHost));
    }
    std::fprintf(stderr, "[remote-exec] TestDedupWindow\n");
    {
        edr::RemoteExecDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1000 * kSecond, "PsExec.exe",
            "PsExec.exe \\\\10.0.0.5 cmd.exe");
        detector.Enrich(first);
        REMOTE_CHECK(HasScore(first));
        edr::Event repeat = ProcEvent(
            1010 * kSecond, "PsExec.exe",
            "PsExec.exe \\\\10.0.0.5 cmd.exe");
        detector.Enrich(repeat);
        REMOTE_CHECK(!HasScore(repeat));
        edr::Event expired = ProcEvent(
            1000 * kSecond + 301 * kSecond, "PsExec.exe",
            "PsExec.exe \\\\10.0.0.5 cmd.exe");
        detector.Enrich(expired);
        REMOTE_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[remote-exec] TestInspects\n");
    {
        REMOTE_CHECK(edr::RemoteExecDetector::Inspects(EDR_EVT_PROCESS_START));
        REMOTE_CHECK(!edr::RemoteExecDetector::Inspects(EDR_EVT_REG_WRITE));
        REMOTE_CHECK(!edr::RemoteExecDetector::Inspects(EDR_EVT_FILE_CREATE));
    }
    std::fprintf(stderr, "[remote-exec] all passed\n");
}
