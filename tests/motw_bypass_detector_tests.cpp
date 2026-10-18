/*
 * motw_bypass_detector_tests.cpp - Unit tests for
 * MotwBypassDetector (T1553.005).
 */
#include "motw_bypass_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "motw_bypass_detector.h"

namespace {

#define MB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "motw bypass detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kMotwBypassScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunMotwBypassDetectorTests() {
    std::fprintf(stderr, "[motw-bypass] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::MotwBypassDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            6000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell"
            "\\v1.0\\powershell.exe",
            "Unblock-File C:\\Users\\bob\\Downloads\\invoice.pdf.exe");
        detector.Enrich(event);
        MB_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[motw-bypass] TestUnblockFile\n");
    {
        edr::MotwBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            6000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell"
            "\\v1.0\\powershell.exe",
            "Unblock-File C:\\Users\\bob\\Downloads\\invoice.pdf.exe");
        detector.Enrich(event);
        MB_CHECK(Score(event) == "75");
        MB_CHECK(event.fields.at(
            edr::field::kMotwBypassVerdict) == "malicious");
    }
    std::fprintf(stderr, "[motw-bypass] TestAdsDelete\n");
    {
        edr::MotwBypassDetector detector(true, 55, 300, 1024);
        edr::Event cmdDel = ProcEvent(
            6001 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "del C:\\Users\\bob\\Downloads\\setup.exe:Zone.Identifier");
        detector.Enrich(cmdDel);
        MB_CHECK(Score(cmdDel) == "85");

        edr::Event psRemove;
        psRemove.type = EDR_EVT_POWERSHELL_SCRIPT;
        psRemove.ts100ns = 6002 * kSecond;
        psRemove.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        psRemove.fields[edr::field::kScriptBlockText] =
            "Remove-Item C:\\Temp\\loader.dll:Zone.Identifier";
        detector.Enrich(psRemove);
        MB_CHECK(Score(psRemove) == "85");
    }
    std::fprintf(stderr, "[motw-bypass] TestFileDeletePlane\n");
    {
        /* FILE_DELETE plane: the ADS stream itself deleted. */
        edr::MotwBypassDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_FILE_DELETE;
        event.ts100ns = 6003 * kSecond;
        event.fields[edr::field::kType] = "FILE_DELETE";
        event.fields[edr::field::kFilePath] =
            "C:\\Users\\bob\\Downloads\\crack.exe:Zone.Identifier";
        detector.Enrich(event);
        MB_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[motw-bypass] TestRegistryPolicy\n");
    {
        /* Registry plane: Attachment Manager MOTW disable policy. */
        edr::MotwBypassDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.ts100ns = 6004 * kSecond;
        event.fields[edr::field::kType] = "REG_WRITE";
        event.fields[edr::field::kRegKey] =
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\Policies\\Attachments";
        event.fields[edr::field::kRegValue] = "SaveZoneInformation=2";
        detector.Enrich(event);
        MB_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[motw-bypass] TestAdsRecon\n");
    {
        /* dir /r enumeration is the low-band precursor. */
        edr::MotwBypassDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            6005 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "dir /r C:\\Users\\bob\\Downloads");
        detector.Enrich(event);
        MB_CHECK(Score(event) == "55");
    }
    std::fprintf(stderr, "[motw-bypass] TestInspectionSilent\n");
    {
        /* Read-only stream inspection never scores. */
        edr::MotwBypassDetector detector(true, 55, 300, 1024);
        edr::Event inspect;
        inspect.type = EDR_EVT_POWERSHELL_SCRIPT;
        inspect.ts100ns = 6006 * kSecond;
        inspect.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        inspect.fields[edr::field::kScriptBlockText] =
            "Get-Content C:\\Temp\\a.exe -Stream Zone.Identifier";
        detector.Enrich(inspect);
        MB_CHECK(Score(inspect).empty());

        edr::Event unrelated = ProcEvent(
            6007 * kSecond, "C:\\Windows\\System32\\notepad.exe",
            "notepad.exe C:\\notes.txt");
        detector.Enrich(unrelated);
        MB_CHECK(Score(unrelated).empty());
    }
    std::fprintf(stderr, "[motw-bypass] all passed\n");
}
