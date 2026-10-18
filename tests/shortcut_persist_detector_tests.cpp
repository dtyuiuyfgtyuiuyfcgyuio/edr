/*
 * shortcut_persist_detector_tests.cpp - Unit tests for
 * ShortcutPersistDetector (T1547.009).
 */
#include "shortcut_persist_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "shortcut_persist_detector.h"

namespace {

#define SP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "shortcut persist detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kShortcutPersistScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunShortcutPersistDetectorTests() {
    std::fprintf(stderr, "[shortcut-persist] TestDisabled\n");
    {
        edr::ShortcutPersistDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            8000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy payload.lnk C:\\Users\\bob\\AppData\\Roaming\\"
            "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk");
        detector.Enrich(event);
        SP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[shortcut-persist] TestCreateShortcut\n");
    {
        edr::ShortcutPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            8000 * kSecond,
            "$s = (New-Object -ComObject WScript.Shell)."
            "CreateShortcut('C:\\Users\\bob\\AppData\\Roaming\\"
            "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
            "update.lnk'); $s.TargetPath='C:\\Temp\\beacon.exe'; "
            "$s.Save()");
        detector.Enrich(event);
        SP_CHECK(Score(event) == "90");
        SP_CHECK(event.fields.at(
            edr::field::kShortcutPersistVerdict) == "malicious");
    }
    std::fprintf(stderr, "[shortcut-persist] TestCopyLnk\n");
    {
        edr::ShortcutPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            8001 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Temp\\payload.lnk C:\\Users\\bob\\AppData\\"
            "Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\"
            "Startup\\payload.lnk");
        detector.Enrich(event);
        SP_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[shortcut-persist] TestFileCreateLnk\n");
    {
        edr::ShortcutPersistDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_FILE_CREATE;
        event.ts100ns = 8002 * kSecond;
        event.fields[edr::field::kType] = "FILE_CREATE";
        event.fields[edr::field::kFilePath] =
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\"
            "StartUp\\backdoor.lnk";
        detector.Enrich(event);
        SP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[shortcut-persist] TestUrlShortcut\n");
    {
        edr::ShortcutPersistDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_FILE_CREATE;
        event.ts100ns = 8003 * kSecond;
        event.fields[edr::field::kType] = "FILE_CREATE";
        event.fields[edr::field::kFilePath] =
            "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\"
            "Start Menu\\Programs\\Startup\\phish.url";
        detector.Enrich(event);
        SP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[shortcut-persist] TestBenignSilent\n");
    {
        edr::ShortcutPersistDetector detector(true, 55, 300, 1024);
        edr::Event browse = ProcEvent(
            8004 * kSecond, "C:\\Windows\\explorer.exe",
            "explorer.exe C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\"
            "Windows\\Start Menu\\Programs\\Startup");
        detector.Enrich(browse);
        SP_CHECK(Score(browse).empty());

        edr::Event doc = ProcEvent(
            8005 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy notes.txt C:\\Users\\bob\\AppData\\Roaming\\"
            "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\notes.txt");
        detector.Enrich(doc);
        SP_CHECK(Score(doc).empty());

        edr::Event desktop = ProcEvent(
            8006 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy payload.lnk C:\\Users\\bob\\Desktop\\payload.lnk");
        detector.Enrich(desktop);
        SP_CHECK(Score(desktop).empty());
    }
    std::fprintf(stderr, "[shortcut-persist] all passed\n");
}
