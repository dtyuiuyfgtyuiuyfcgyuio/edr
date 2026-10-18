/*
 * private_key_detector_tests.cpp - Unit tests for PrivateKeyDetector.
 */
#include "private_key_detector_tests.h"

#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "private_key_detector.h"

namespace {

#define PKEY_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "private key detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event FileEvent(uint16_t type, uint64_t ts100ns, const char* path,
                     const char* image) {
    edr::Event event;
    event.type = type;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] =
        type == EDR_EVT_FILE_READ ? "FILE_READ" : "FILE_CREATE";
    event.fields[edr::field::kFilePath] = path;
    if (image != nullptr)
        event.fields[edr::field::kImage] = image;
    return event;
}

edr::Event ProcessStart(uint64_t ts100ns, const char* image,
                        const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    if (image != nullptr)
        event.fields[edr::field::kImage] = image;
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event ScriptBlock(uint64_t ts100ns, const char* body) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    /* House contract: script bodies live only in kScriptBlockText. */
    event.fields[edr::field::kScriptBlockText] = body;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kPrivateKeyScore) !=
           event.fields.end();
}

uint32_t Score(const edr::Event& event) {
    return static_cast<uint32_t>(
        std::stoul(event.fields.at(edr::field::kPrivateKeyScore)));
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace


void RunPrivateKeyDetectorTests() {
    std::fprintf(stderr, "[private_key] TestDisabled\n");
    {
        edr::PrivateKeyDetector detector(false, 55, 300, 1024);
        auto event = FileEvent(EDR_EVT_FILE_READ, kSecond,
            "C:\\Users\\bob\\.ssh\\id_rsa", "C:\\temp\\evil.exe");
        detector.Enrich(event);
        PKEY_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[private_key] FileReadIdRsa\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 300, 1024);
        auto event = FileEvent(EDR_EVT_FILE_READ, 10 * kSecond,
            "C:\\Users\\bob\\.ssh\\id_rsa", "C:\\temp\\evil.exe");
        detector.Enrich(event);
        PKEY_CHECK(HasScore(event));
        PKEY_CHECK(Score(event) == 75);
        PKEY_CHECK(event.fields.at(edr::field::kPrivateKeyVerdict) ==
                   "malicious");
    }

    std::fprintf(stderr, "[private_key] WhitelistedSshReaderSilent\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 300, 1024);
        auto event = FileEvent(EDR_EVT_FILE_READ, 10 * kSecond,
            "C:\\Users\\bob\\.ssh\\id_rsa",
            "C:\\Windows\\System32\\OpenSSH\\ssh.exe");
        detector.Enrich(event);
        PKEY_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[private_key] FileCreateTransient\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 300, 1024);
        auto event = FileEvent(EDR_EVT_FILE_CREATE, 10 * kSecond,
            "C:\\Users\\Public\\id_rsa", "C:\\temp\\evil.exe");
        detector.Enrich(event);
        PKEY_CHECK(HasScore(event));
        PKEY_CHECK(Score(event) == 85);
        PKEY_CHECK(event.fields.at(edr::field::kPrivateKeyVerdict) ==
                   "malicious");
    }

    std::fprintf(stderr, "[private_key] FileCreateKeygenSilent\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 300, 1024);
        /* ssh-keygen writing into the user's own .ssh dir is legit. */
        auto event = FileEvent(EDR_EVT_FILE_CREATE, 10 * kSecond,
            "C:\\Users\\bob\\.ssh\\id_rsa",
            "C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe");
        detector.Enrich(event);
        PKEY_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[private_key] CertutilExportPfx\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 300, 1024);
        auto event = ProcessStart(10 * kSecond,
            "C:\\Windows\\System32\\certutil.exe",
            "certutil -exportPFX -p pw My 5bfa136c38c9db4f6c8a8f1d25ee60f5 "
            "C:\\temp\\out.pfx");
        detector.Enrich(event);
        PKEY_CHECK(HasScore(event));
        PKEY_CHECK(Score(event) == 90);
        PKEY_CHECK(event.fields.at(edr::field::kPrivateKeyVerdict) ==
                   "malicious");
    }

    std::fprintf(stderr, "[private_key] MimikatzCryptoModule\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 300, 1024);
        auto event = ProcessStart(10 * kSecond, "C:\\temp\\mimikatz.exe",
            "mimikatz.exe crypto::certificates /export");
        detector.Enrich(event);
        PKEY_CHECK(HasScore(event));
        PKEY_CHECK(Score(event) == 90);
    }

    std::fprintf(stderr, "[private_key] CopyVerbKeyFile\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 300, 1024);
        auto event = ProcessStart(10 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "cmd /c copy C:\\Users\\bob\\.ssh\\id_rsa C:\\temp\\");
        detector.Enrich(event);
        PKEY_CHECK(HasScore(event));
        PKEY_CHECK(Score(event) == 70);
        PKEY_CHECK(event.fields.at(edr::field::kPrivateKeyVerdict) ==
                   "suspicious");
    }

    std::fprintf(stderr, "[private_key] BareMention\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 300, 1024);
        auto event = ScriptBlock(10 * kSecond,
            "Get-ChildItem C:\\Users\\bob -Recurse -Filter *.pfx");
        detector.Enrich(event);
        PKEY_CHECK(HasScore(event));
        PKEY_CHECK(Score(event) == 55);
    }

    std::fprintf(stderr, "[private_key] DedupSuppressesRepeat\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 60, 1024);
        auto first = FileEvent(EDR_EVT_FILE_READ, 10 * kSecond,
            "C:\\Users\\bob\\.ssh\\id_rsa", "C:\\temp\\evil.exe");
        detector.Enrich(first);
        PKEY_CHECK(HasScore(first));

        auto second = FileEvent(EDR_EVT_FILE_READ, 20 * kSecond,
            "C:\\Users\\bob\\.ssh\\id_rsa", "C:\\temp\\evil.exe");
        detector.Enrich(second);
        PKEY_CHECK(!HasScore(second));

        /* Different process -> not suppressed. */
        auto third = FileEvent(EDR_EVT_FILE_READ, 30 * kSecond,
            "C:\\Users\\bob\\.ssh\\id_rsa", "C:\\temp\\other.exe");
        detector.Enrich(third);
        PKEY_CHECK(HasScore(third));
    }

    std::fprintf(stderr, "[private_key] MinScoreFiltersLowSignals\n");
    {
        edr::PrivateKeyDetector detector(true, 70, 300, 1024);
        /* Bare mention scores 55, filtered by min_score=70. */
        auto event = ScriptBlock(10 * kSecond,
            "Get-ChildItem C:\\Users\\bob -Recurse -Filter *.pfx");
        detector.Enrich(event);
        PKEY_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[private_key] NonKeyFileSilent\n");
    {
        edr::PrivateKeyDetector detector(true, 55, 300, 1024);
        auto event = FileEvent(EDR_EVT_FILE_READ, 10 * kSecond,
            "C:\\Users\\bob\\Documents\\notes.txt", "C:\\temp\\evil.exe");
        detector.Enrich(event);
        PKEY_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[private_key] all passed\n");
}
