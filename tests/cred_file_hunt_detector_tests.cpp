/*
 * cred_file_hunt_detector_tests.cpp - Unit tests for
 * CredentialFileHuntDetector.
 */
#include "cred_file_hunt_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "cred_file_hunt_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define CF_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "cred file hunt detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptBody) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptBody;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kCredFileHuntScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunCredFileHuntDetectorTests() {
    std::fprintf(stderr, "[cred-file-hunt] TestDisabled\n");
    {
        edr::CredentialFileHuntDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\findstr.exe",
            "findstr /s /i password *.txt");
        detector.Enrich(event);
        CF_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[cred-file-hunt] TestSearchCommands\n");
    {
        edr::CredentialFileHuntDetector detector(true, 55, 300, 1024);
        edr::Event findstr = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\findstr.exe",
            "findstr /s /i password *.txt");
        detector.Enrich(findstr);
        CF_CHECK(Score(findstr) == "75");
        CF_CHECK(findstr.fields.at(edr::field::kCredFileHuntVerdict) ==
                 "malicious");

        edr::Event select = ScriptEvent(
            1010 * kSecond,
            "Select-String -Path .\\**\\* -Pattern password -Recurse");
        detector.Enrich(select);
        CF_CHECK(Score(select) == "75");

        edr::Event grep = ProcEvent(
            1020 * kSecond,
            "C:\\Windows\\System32\\bash.exe",
            "grep -R password /home/user");
        detector.Enrich(grep);
        CF_CHECK(Score(grep) == "75");
    }

    std::fprintf(stderr, "[cred-file-hunt] TestCredentialFilesAndKeys\n");
    {
        edr::CredentialFileHuntDetector detector(true, 55, 300, 1024);
        edr::Event creds = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "type C:\\Temp\\credentials.txt");
        detector.Enrich(creds);
        CF_CHECK(Score(creds) == "75");

        edr::Event key = ProcEvent(
            1010 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Users\\bob\\.ssh\\id_rsa C:\\Temp\\loot.txt");
        detector.Enrich(key);
        CF_CHECK(Score(key) == "75");

        edr::Event winscp = ProcEvent(
            1020 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "type %APPDATA%\\WinSCP.ini");
        detector.Enrich(winscp);
        CF_CHECK(Score(winscp) == "70");
    }

    std::fprintf(stderr, "[cred-file-hunt] TestNetUseSaveCred\n");
    {
        edr::CredentialFileHuntDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\net.exe",
            "net use \\server\\share /savecred");
        detector.Enrich(event);
        CF_CHECK(Score(event) == "65");
    }

    std::fprintf(stderr, "[cred-file-hunt] TestCleanTrafficSilent\n");
    {
        edr::CredentialFileHuntDetector detector(true, 55, 300, 1024);
        edr::Event clean = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\notepad.exe",
            "notepad readme.txt");
        detector.Enrich(clean);
        CF_CHECK(Score(clean).empty());
        CF_CHECK(clean.fields.find(edr::field::kCredFileHuntVerdict) ==
                 clean.fields.end());
    }

    std::fprintf(stderr, "[cred-file-hunt] TestDedupWindow\n");
    {
        edr::CredentialFileHuntDetector detector(true, 55, 60, 1024);
        const char* cmd = "findstr /s /i password *.txt";
        edr::Event first = ProcEvent(1000 * kSecond,
                                     "C:\\Windows\\System32\\findstr.exe",
                                     cmd);
        detector.Enrich(first);
        CF_CHECK(!Score(first).empty());

        edr::Event second = ProcEvent(1030 * kSecond,
                                      "C:\\Windows\\System32\\findstr.exe",
                                      cmd);
        detector.Enrich(second);
        CF_CHECK(Score(second).empty());

        edr::Event third = ProcEvent(1100 * kSecond,
                                     "C:\\Windows\\System32\\findstr.exe",
                                     cmd);
        detector.Enrich(third);
        CF_CHECK(!Score(third).empty());
    }

    std::fprintf(stderr, "[cred-file-hunt] all passed\n");
}
