/*
 * logon_script_persist_detector_tests.cpp - Unit tests for
 * LogonScriptPersistDetector (T1037.001 Logon Script,
 * T1547.014 Active Setup).
 */
#include "logon_script_persist_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "logon_script_persist_detector.h"

namespace {

#define LS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "logon script persist detector test failed at line " +
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

edr::Event RegEvent(uint64_t ts100ns, const char* regKey,
                    const char* regValue) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = regKey;
    if (regValue != nullptr)
        event.fields[edr::field::kRegValue] = regValue;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kLogonScriptScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunLogonScriptPersistDetectorTests() {
    std::fprintf(stderr, "[logon-script] TestDisabled\n");
    {
        edr::LogonScriptPersistDetector detector(false, 55, 300, 1024);
        edr::Event event = RegEvent(
            8000 * kSecond,
            "HKCU\\Environment", "UserInitMprLogonScript");
        detector.Enrich(event);
        LS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[logon-script] TestUserInitMprLogonScript\n");
    {
        edr::LogonScriptPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            8000 * kSecond,
            "HKCU\\Environment", "UserInitMprLogonScript");
        detector.Enrich(event);
        LS_CHECK(Score(event) == "90");
        LS_CHECK(event.fields.at(
            edr::field::kLogonScriptVerdict) == "malicious");
    }
    std::fprintf(stderr, "[logon-script] TestActiveSetupStubPath\n");
    {
        edr::LogonScriptPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            8001 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed "
            "Components\\{DEADBEEF-1234}",
            "StubPath");
        detector.Enrich(event);
        LS_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[logon-script] TestCommandPlaneRegAdd\n");
    {
        edr::LogonScriptPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            8002 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKCU\\Environment /v UserInitMprLogonScript /t "
            "REG_SZ /d C:\\Temp\\payload.bat /f");
        detector.Enrich(event);
        LS_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[logon-script] TestGroupPolicyScriptPlanted\n");
    {
        edr::LogonScriptPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            8003 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy evil.vbs \"C:\\Windows\\System32\\GroupPolicy\\User\\"
            "Scripts\\Logon\\evil.vbs\"");
        detector.Enrich(event);
        LS_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[logon-script] TestActiveSetupBareLowerBand\n");
    {
        /* Component registered with no explicit payload token yet. */
        edr::LogonScriptPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            8004 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed "
            "Components\\{CAFEBABE}",
            "Version");
        detector.Enrich(event);
        LS_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[logon-script] TestReadOnlySilent\n");
    {
        edr::LogonScriptPersistDetector detector(true, 55, 300, 1024);
        edr::Event query = ProcEvent(
            8005 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query HKCU\\Environment /v UserInitMprLogonScript");
        detector.Enrich(query);
        LS_CHECK(Score(query).empty());

        edr::Event gpresult = ProcEvent(
            8006 * kSecond, "C:\\Windows\\System32\\gpresult.exe",
            "gpresult /scope user /v");
        detector.Enrich(gpresult);
        LS_CHECK(Score(gpresult).empty());

        /* An ordinary Environment value write. */
        edr::Event unrelated = RegEvent(
            8007 * kSecond, "HKCU\\Environment", "JAVA_HOME");
        detector.Enrich(unrelated);
        LS_CHECK(Score(unrelated).empty());
    }
    std::fprintf(stderr, "[logon-script] all passed\n");
}
