/*
 * hook_persistence_detector_tests.cpp - Unit tests for
 * HookPersistenceDetector (T1546.008 / T1546.012 / T1546.015).
 */
#include "hook_persistence_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "hook_persistence_detector.h"

namespace {

#define HOOK_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "hook persistence detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event RegWrite(uint64_t ts100ns, const char* key, const char* value) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kSource] = "registry_watch";
    event.fields[edr::field::kRegKey] = key;
    event.fields[edr::field::kRegValue] = value;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kHookPersistScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunHookPersistenceDetectorTests() {
    const char* kSethcDebugger =
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        "\\Image File Execution Options\\sethc.exe\\Debugger";

    {
        /* Disabled detector never stamps. */
        edr::HookPersistenceDetector detector(false, 55, 300, 1024);
        edr::Event event = RegWrite(1000 * kSecond, kSethcDebugger,
                                    "c:\\temp\\backdoor.exe");
        detector.Enrich(event);
        HOOK_CHECK(!HasScore(event));
        HOOK_CHECK(detector.StateCount() == 0);
    }
    {
        /* T1546.008: debugger on an accessibility binary -> 85 malicious. */
        edr::HookPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = RegWrite(1000 * kSecond, kSethcDebugger,
                                    "C:\\Windows\\System32\\cmd.exe");
        detector.Enrich(event);
        HOOK_CHECK(HasScore(event));
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistScore) == "85");
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistVerdict) ==
                   "malicious");
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistTechnique) ==
                   "T1546.008");
        HOOK_CHECK(detector.StateCount() == 1);
    }
    {
        /* T1546.012: interpreter-launching debugger on a normal image
         * -> 75 malicious. Case-insensitive key handling. */
        edr::HookPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = RegWrite(1000 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\IMAGE FILE EXECUTION OPTIONS\\notepad.exe\\Debugger",
            "cmd.exe /c powershell -enc AAAA");
        detector.Enrich(event);
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistScore) == "75");
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistVerdict) ==
                   "malicious");
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistTechnique) ==
                   "T1546.012");
    }
    {
        /* T1546.012: benign-looking debugger -> 60 suspicious. */
        edr::HookPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = RegWrite(1000 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Image File Execution Options\\notepad.exe\\Debugger",
            "\"C:\\Program Files\\Windbg\\windbg.exe\"");
        detector.Enrich(event);
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistScore) == "60");
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistVerdict) ==
                   "suspicious");
    }
    {
        /* Empty debugger value never scores. */
        edr::HookPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = RegWrite(1000 * kSecond, kSethcDebugger, "");
        detector.Enrich(event);
        HOOK_CHECK(!HasScore(event));
        HOOK_CHECK(detector.StateCount() == 0);
    }
    {
        /* T1546.015: HKCU COM server into user-writable dir -> 75. */
        edr::HookPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = RegWrite(1000 * kSecond,
            "HKCU\\SOFTWARE\\Classes\\CLSID"
            "\\{11111111-2222-3333-4444-555555555555}\\InprocServer32",
            "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.dll");
        detector.Enrich(event);
        HOOK_CHECK(HasScore(event));
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistScore) == "75");
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistVerdict) ==
                   "malicious");
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistTechnique) ==
                   "T1546.015");
    }
    {
        /* T1546.015: HKCU COM server with ordinary path -> 65 suspicious. */
        edr::HookPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = RegWrite(1000 * kSecond,
            "HKCU\\SOFTWARE\\Classes\\CLSID"
            "\\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\\LocalServer32",
            "\"C:\\Program Files\\Vendor\\app.exe\" /embedding");
        detector.Enrich(event);
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistScore) == "65");
        HOOK_CHECK(event.fields.at(edr::field::kHookPersistVerdict) ==
                   "suspicious");
    }
    {
        /* Machine hive pointing at system locations is benign. */
        edr::HookPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event event = RegWrite(1000 * kSecond,
            "HKLM\\SOFTWARE\\Classes\\CLSID"
            "\\{00000000-0000-0000-0000-000000000000}\\InprocServer32",
            "C:\\Windows\\System32\\comctl32.dll");
        detector.Enrich(event);
        HOOK_CHECK(!HasScore(event));
        HOOK_CHECK(detector.StateCount() == 0);
    }
    {
        /* Unrelated registry keys never score. */
        edr::HookPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event runKey = RegWrite(1000 * kSecond,
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "evil=c:\\temp\\x.exe");
        detector.Enrich(runKey);
        HOOK_CHECK(!HasScore(runKey));
    }
    {
        /* Dedup window suppresses repeats of the same key; a different
         * key still stamps; expiry re-arms. */
        edr::HookPersistenceDetector detector(true, 55, 300, 1024);
        edr::Event first =
            RegWrite(1000 * kSecond, kSethcDebugger, "c:\\b1.exe");
        detector.Enrich(first);
        HOOK_CHECK(HasScore(first));

        edr::Event repeat =
            RegWrite(1100 * kSecond, kSethcDebugger, "c:\\b1.exe");
        detector.Enrich(repeat);
        HOOK_CHECK(!HasScore(repeat));

        const char* kUtilmanDebugger =
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Image File Execution Options\\utilman.exe\\Debugger";
        edr::Event other =
            RegWrite(1200 * kSecond, kUtilmanDebugger, "c:\\b2.exe");
        detector.Enrich(other);
        HOOK_CHECK(HasScore(other));

        edr::Event expired =
            RegWrite(1400 * kSecond, kSethcDebugger, "c:\\b1.exe");
        detector.Enrich(expired);
        HOOK_CHECK(HasScore(expired));
        HOOK_CHECK(detector.StateCount() == 2);
    }
    {
        /* Inspects: only REG_WRITE. */
        HOOK_CHECK(
            edr::HookPersistenceDetector::Inspects(EDR_EVT_REG_WRITE));
        HOOK_CHECK(
            !edr::HookPersistenceDetector::Inspects(EDR_EVT_FILE_INTEGRITY));
        HOOK_CHECK(
            !edr::HookPersistenceDetector::Inspects(EDR_EVT_PROCESS_START));
    }
}
