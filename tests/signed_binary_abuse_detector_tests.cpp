/*
 * signed_binary_abuse_detector_tests.cpp - Unit tests for
 * SignedBinaryAbuseDetector (T1218 proxy execution).
 */
#include "signed_binary_abuse_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "signed_binary_abuse_detector.h"

namespace {

#define SB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "signed binary abuse detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kSignedBinaryAbuseScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunSignedBinaryAbuseDetectorTests() {
    std::fprintf(stderr, "[signed-binary] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::SignedBinaryAbuseDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5000 * kSecond, "C:\\Windows\\SysWOW64\\mavinject.exe",
            "mavinject 4321 /INJECTRUNNING C:\\Temp\\evil.dll");
        detector.Enrich(event);
        SB_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[signed-binary] TestMavInject\n");
    {
        edr::SignedBinaryAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5000 * kSecond, "C:\\Windows\\SysWOW64\\mavinject.exe",
            "mavinject 4321 /INJECTRUNNING C:\\Temp\\evil.dll");
        detector.Enrich(event);
        SB_CHECK(Score(event) == "90");
        SB_CHECK(event.fields.at(
            edr::field::kSignedBinaryAbuseVerdict) == "malicious");
    }
    std::fprintf(stderr, "[signed-binary] TestRegisterCimProvider\n");
    {
        edr::SignedBinaryAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5001 * kSecond,
            "C:\\Windows\\System32\\register-cimprovider.exe",
            "register-cimprovider -path C:\\Temp\\implant.dll "
            "-namespace root");
        detector.Enrich(event);
        SB_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[signed-binary] TestInfDefaultInstall\n");
    {
        edr::SignedBinaryAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5002 * kSecond,
            "C:\\Windows\\System32\\infdefaultinstall.exe",
            "InfDefaultInstall.exe C:\\Temp\\payload.inf");
        detector.Enrich(event);
        SB_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[signed-binary] TestXwizard\n");
    {
        edr::SignedBinaryAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5003 * kSecond, "C:\\Windows\\System32\\xwizard.exe",
            "xwizard.exe RunWizard {077AA2CE-9E41-4DFE-99F8-39D53ABCC52A}");
        detector.Enrich(event);
        SB_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[signed-binary] TestVerClsid\n");
    {
        edr::SignedBinaryAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            5004 * kSecond, "C:\\Windows\\System32\\verclsid.exe",
            "verclsid.exe /c /CLSID:{0D43FE01-F093-11CF-8940-00A0C9054228}");
        detector.Enrich(event);
        SB_CHECK(Score(event) == "70");
        SB_CHECK(event.fields.at(
            edr::field::kSignedBinaryAbuseVerdict) == "suspicious");
    }
    std::fprintf(stderr, "[signed-binary] TestBenignSilent\n");
    {
        /* Bare signed binaries with no payload arguments stay silent. */
        edr::SignedBinaryAbuseDetector detector(true, 55, 300, 1024);
        edr::Event bareXwizard = ProcEvent(
            5005 * kSecond, "C:\\Windows\\System32\\xwizard.exe", nullptr);
        detector.Enrich(bareXwizard);
        SB_CHECK(Score(bareXwizard).empty());

        edr::Event unrelated = ProcEvent(
            5006 * kSecond, "C:\\Windows\\System32\\notepad.exe",
            "notepad.exe C:\\notes.txt");
        detector.Enrich(unrelated);
        SB_CHECK(Score(unrelated).empty());
    }
    std::fprintf(stderr, "[signed-binary] all passed\n");
}
