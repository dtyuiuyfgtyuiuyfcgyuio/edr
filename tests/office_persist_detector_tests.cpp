/*
 * office_persist_detector_tests.cpp - Unit tests for
 * OfficePersistDetector (T1137).
 */
#include "office_persist_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "office_persist_detector.h"

namespace {

#define OP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "office persist detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kOfficePersistScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunOfficePersistDetectorTests() {
    std::fprintf(stderr, "[office-persist] TestDisabled\n");
    {
        edr::OfficePersistDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            7000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy payload.wll C:\\Users\\bob\\AppData\\Roaming\\"
            "Microsoft\\Word\\STARTUP\\evil.wll");
        detector.Enrich(event);
        OP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[office-persist] TestVbaProjectOtm\n");
    {
        edr::OfficePersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            7000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Temp\\VbaProject.OTM C:\\Users\\bob\\AppData\\"
            "Roaming\\Microsoft\\Outlook\\VbaProject.OTM");
        detector.Enrich(event);
        OP_CHECK(Score(event) == "90");
        OP_CHECK(event.fields.at(
            edr::field::kOfficePersistVerdict) == "malicious");
    }
    std::fprintf(stderr, "[office-persist] TestComAddinRegAdd\n");
    {
        edr::OfficePersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            7001 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\"
            "Addins\\EvilAddin /v LoadBehavior /t REG_DWORD /d 3 /f");
        detector.Enrich(event);
        OP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[office-persist] TestRegWritePlane\n");
    {
        edr::OfficePersistDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.ts100ns = 7002 * kSecond;
        event.fields[edr::field::kType] = "REG_WRITE";
        event.fields[edr::field::kRegKey] =
            "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Addins\\"
            "Backdoor";
        event.fields[edr::field::kRegValue] = "LoadBehavior";
        detector.Enrich(event);
        OP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[office-persist] TestWllFileCreate\n");
    {
        edr::OfficePersistDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_FILE_CREATE;
        event.ts100ns = 7003 * kSecond;
        event.fields[edr::field::kType] = "FILE_CREATE";
        event.fields[edr::field::kFilePath] =
            "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Word\\"
            "STARTUP\\macro.wll";
        detector.Enrich(event);
        OP_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[office-persist] TestXlstartXlam\n");
    {
        edr::OfficePersistDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_FILE_CREATE;
        event.ts100ns = 7004 * kSecond;
        event.fields[edr::field::kType] = "FILE_CREATE";
        event.fields[edr::field::kFilePath] =
            "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Excel\\"
            "XLSTART\\persist.xlam";
        detector.Enrich(event);
        OP_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[office-persist] TestScriptAddInsAdd\n");
    {
        edr::OfficePersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            7005 * kSecond,
            "$excel.Application.AddIns.Add('C:\\Temp\\evil.xlam')");
        detector.Enrich(event);
        OP_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[office-persist] TestReadOnlySilent\n");
    {
        edr::OfficePersistDetector detector(true, 55, 300, 1024);
        edr::Event listing = ProcEvent(
            7006 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "dir C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Word\\"
            "STARTUP");
        detector.Enrich(listing);
        OP_CHECK(Score(listing).empty());

        edr::Event winword = ProcEvent(
            7007 * kSecond,
            "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
            "WINWORD.EXE /n");
        detector.Enrich(winword);
        OP_CHECK(Score(winword).empty());

        /* .xlsx under XLSTART must not be treated as an .xla add-in. */
        edr::Event xlsx;
        xlsx.type = EDR_EVT_FILE_CREATE;
        xlsx.ts100ns = 7008 * kSecond;
        xlsx.fields[edr::field::kType] = "FILE_CREATE";
        xlsx.fields[edr::field::kFilePath] =
            "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Excel\\"
            "XLSTART\\budget.xlsx";
        detector.Enrich(xlsx);
        OP_CHECK(Score(xlsx).empty());
    }
    std::fprintf(stderr, "[office-persist] TestXlstartXlaCommand\n");
    {
        edr::OfficePersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            7009 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Temp\\persist.xla C:\\Users\\bob\\AppData\\"
            "Roaming\\Microsoft\\Excel\\XLSTART\\persist.xla");
        detector.Enrich(event);
        OP_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[office-persist] all passed\n");
}
