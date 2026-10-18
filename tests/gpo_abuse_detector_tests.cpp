/*
 * gpo_abuse_detector_tests.cpp - Unit tests for GpoAbuseDetector
 * (T1484.001).
 */
#include "gpo_abuse_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "gpo_abuse_detector.h"

namespace {

#define GP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "gpo abuse detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kGpoAbuseScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunGpoAbuseDetectorTests() {
    std::fprintf(stderr, "[gpo-abuse] TestDisabled\n");
    {
        edr::GpoAbuseDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3000 * kSecond, "C:\\Users\\Public\\SharpGPOAbuse.exe",
            "SharpGPOAbuse.exe --gponame Test --taskname upd "
            "--taskrun C:\\Windows\\Temp\\p.exe");
        detector.Enrich(event);
        GP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[gpo-abuse] TestSharpGpoAbuse\n");
    {
        edr::GpoAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3001 * kSecond, "C:\\Users\\Public\\SharpGPOAbuse.exe",
            "SharpGPOAbuse.exe --gponame Test --taskname upd "
            "--taskrun C:\\Windows\\Temp\\p.exe");
        detector.Enrich(event);
        GP_CHECK(Score(event) == "90");
        GP_CHECK(event.fields.at(edr::field::kGpoAbuseVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[gpo-abuse] TestRegistryPolStage\n");
    {
        edr::GpoAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3002 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy registry.pol "
            "\\\\dc\\sysvol\\corp.local\\Policies\\{GUID}\\Machine\\");
        detector.Enrich(event);
        GP_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[gpo-abuse] TestNewGpoScript\n");
    {
        edr::GpoAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            3003 * kSecond,
            "New-GPO -Name 'Update' | New-GPLink -Target "
            "'OU=Workstations,DC=corp,DC=local'");
        detector.Enrich(event);
        GP_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[gpo-abuse] TestLgpo\n");
    {
        edr::GpoAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3004 * kSecond, "C:\\Tools\\LGPO.exe",
            "LGPO.exe /gpo C:\\Temp\\policy /n Test");
        detector.Enrich(event);
        GP_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[gpo-abuse] TestSecedit\n");
    {
        edr::GpoAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3005 * kSecond, "C:\\Windows\\System32\\secedit.exe",
            "secedit /configure /db secedit.sdb /cfg evil.inf");
        detector.Enrich(event);
        GP_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[gpo-abuse] TestRegWritePlane\n");
    {
        edr::GpoAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.ts100ns = 3006 * kSecond;
        event.fields[edr::field::kType] = "REG_WRITE";
        event.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\Group Policy\\Scripts\\Startup";
        event.fields[edr::field::kRegValue] = "0";
        detector.Enrich(event);
        GP_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[gpo-abuse] TestInspectionSilent\n");
    {
        edr::GpoAbuseDetector detector(true, 55, 300, 1024);
        edr::Event gpresult = ProcEvent(
            3007 * kSecond, "C:\\Windows\\System32\\gpresult.exe",
            "gpresult /r");
        detector.Enrich(gpresult);
        GP_CHECK(Score(gpresult).empty());
        edr::Event getGpo = ScriptEvent(
            3008 * kSecond, "Get-GPO -All | Select DisplayName");
        detector.Enrich(getGpo);
        GP_CHECK(Score(getGpo).empty());
    }
    std::fprintf(stderr, "[gpo-abuse] all passed\n");
}
