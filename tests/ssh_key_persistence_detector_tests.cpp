/*
 * ssh_key_persistence_detector_tests.cpp - Unit tests for
 * SshKeyPersistenceDetector (T1098.004).
 */
#include "ssh_key_persistence_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "ssh_key_persistence_detector.h"

namespace {

#define SSH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "ssh key persistence detector test failed at line " +
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

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kSshKeyPersistScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunSshKeyPersistenceDetectorTests() {
    std::fprintf(stderr, "[ssh-key-persist] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::SshKeyPersistenceDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "echo ssh-rsa AAAA >> C:\\Users\\svc\\.ssh\\authorized_keys");
        detector.Enrich(event);
        SSH_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[ssh-key-persist] TestEchoAppend\n");
    {
        edr::SshKeyPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "echo ssh-rsa AAAAB3NzaC1yc2E "
            ">> C:\\Users\\svc\\.ssh\\authorized_keys");
        detector.Enrich(event);
        SSH_CHECK(Score(event) == "85");
        SSH_CHECK(event.fields.at(
            edr::field::kSshKeyPersistVerdict) == "malicious");
    }
    std::fprintf(stderr, "[ssh-key-persist] TestPowerShellSetContent\n");
    {
        edr::SshKeyPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1001 * kSecond, "C:\\Windows\\System32\\WindowsPowerShell"
                            "\\v1.0\\powershell.exe",
            "Set-Content -Path C:\\ProgramData\\ssh\\"
            "administrators_authorized_keys -Value $key");
        detector.Enrich(event);
        SSH_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[ssh-key-persist] TestKeygenChain\n");
    {
        edr::SshKeyPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1002 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "ssh-keygen -t rsa -f key && copy key "
            "C:\\Users\\svc\\.ssh\\authorized_keys");
        detector.Enrich(event);
        SSH_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[ssh-key-persist] TestRedirectOnly\n");
    {
        /* authorized_keys + bare redirect scores lower band. */
        edr::SshKeyPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1003 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "type pub.key > C:\\Users\\svc\\.ssh\\authorized_keys");
        detector.Enrich(event);
        SSH_CHECK(Score(event) == "70");
    }
    std::fprintf(stderr, "[ssh-key-persist] TestFilePlaneKeyStore\n");
    {
        /* FILE_CREATE of the key store itself. */
        edr::SshKeyPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_FILE_CREATE;
        event.ts100ns = 1004 * kSecond;
        event.fields[edr::field::kType] = "FILE_CREATE";
        event.fields[edr::field::kFilePath] =
            "C:\\Users\\svc\\.ssh\\authorized_keys";
        detector.Enrich(event);
        SSH_CHECK(Score(event) == "80");
        SSH_CHECK(event.fields.at(
            edr::field::kSshKeyPersistVerdict) == "malicious");
    }
    std::fprintf(stderr, "[ssh-key-persist] TestInteractiveSshSilent\n");
    {
        /* Genuine interactive usage never scores. */
        edr::SshKeyPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event plain = ProcEvent(
            1005 * kSecond,
            "C:\\Windows\\System32\\OpenSSH\\ssh.exe", nullptr);
        detector.Enrich(plain);
        SSH_CHECK(Score(plain).empty());
        edr::Event keygen = ProcEvent(
            1006 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "ssh-keygen -t ed25519 -f C:\\Users\\bob\\.ssh\\id_ed25519");
        detector.Enrich(keygen);
        SSH_CHECK(Score(keygen).empty());
        edr::Event unrelated = ProcEvent(
            1007 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy report.txt C:\\Temp\\report.txt");
        detector.Enrich(unrelated);
        SSH_CHECK(Score(unrelated).empty());
    }
    std::fprintf(stderr, "[ssh-key-persist] all passed\n");
}
