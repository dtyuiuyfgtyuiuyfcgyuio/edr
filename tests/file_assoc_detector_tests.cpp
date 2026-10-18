/*
 * file_assoc_detector_tests.cpp - Unit tests for FileAssocDetector
 * (T1546.001 Change Default File Association).
 */
#include "file_assoc_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "file_assoc_detector.h"

namespace {

#define FA_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "file assoc detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptText) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PS_SCRIPT";
    /* House contract: the PS script body lives ONLY in
     * kScriptBlockText, never kCommandLine. */
    event.fields[edr::field::kScriptBlockText] = scriptText;
    return event;
}

/* Sysmon/reg_watch snapshot shape: full key path including the value
 * name + the DATA in kRegValue. */
edr::Event RegDataEvent(uint64_t ts100ns, const char* fullKey,
                        const char* data) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = fullKey;
    event.fields[edr::field::kRegValue] = data;
    return event;
}

/* Driver/imonitor shape: bare key + value NAME only. */
edr::Event RegNameEvent(uint64_t ts100ns, const char* regKey,
                        const char* valueName) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = regKey;
    event.fields[edr::field::kRegValue] = valueName;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kFileAssocScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunFileAssocDetectorTests() {
    std::fprintf(stderr, "[file-assoc] TestDisabled\n");
    {
        edr::FileAssocDetector detector(false, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1000 * kSecond,
            "HKCU\\Software\\Classes\\txtfile\\shell\\open\\command",
            "powershell.exe -File C:\\Users\\bob\\AppData\\evil.ps1");
        detector.Enrich(event);
        FA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[file-assoc] TestRegInterpreterPayload\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1001 * kSecond,
            "HKCU\\Software\\Classes\\txtfile\\shell\\open\\command",
            "powershell.exe -WindowStyle Hidden -File img.ps1");
        detector.Enrich(event);
        FA_CHECK(Score(event) == "90");
        FA_CHECK(event.fields.at(
            edr::field::kFileAssocVerdict) == "malicious");
    }
    std::fprintf(stderr, "[file-assoc] TestRegWritablePath\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1002 * kSecond,
            "HKCU\\Software\\Classes\\txtfile\\shell\\open\\command",
            "C:\\Users\\Public\\open_txt.exe \"%1\"");
        detector.Enrich(event);
        FA_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[file-assoc] TestRegPayloadExt\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1003 * kSecond,
            "HKCU\\Software\\Classes\\txtfile\\shell\\open\\command",
            "D:\\tools\\viewer.exe \"%1\"");
        detector.Enrich(event);
        FA_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[file-assoc] TestStockNotepadSilent\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1004 * kSecond,
            "HKCU\\Software\\Classes\\txtfile\\shell\\open\\command",
            "C:\\Windows\\system32\\NOTEPAD.EXE %1");
        detector.Enrich(event);
        FA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[file-assoc] TestHkcrMergedView\n");
    {
        /* reg add via the HKCR merged view must land in the same band. */
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1005 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKCR\\txtfile\\shell\\open\\command\" /ve /d "
            "\"cmd.exe /c evil.bat\" /f");
        detector.Enrich(event);
        FA_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[file-assoc] TestFtypeWrite\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1006 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "ftype txtfile=C:\\Temp\\viewer.exe \"%1\"");
        detector.Enrich(event);
        FA_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[file-assoc] TestFtypeQuerySilent\n");
    {
        /* A bare `ftype txtfile` is a read-only query: no '=' at all. */
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1007 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "ftype txtfile");
        detector.Enrich(event);
        FA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[file-assoc] TestAssocQuerySilent\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1008 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "assoc .txt");
        detector.Enrich(event);
        FA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[file-assoc] TestDriverNameOnlyShape\n");
    {
        /* Driver shape carries only the value name: slot touched with
         * no data observed. */
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = RegNameEvent(
            1009 * kSecond,
            "HKCU\\Software\\Classes\\txtfile\\shell\\open\\command",
            "(default)");
        detector.Enrich(event);
        FA_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[file-assoc] TestUnrelatedRegWriteSilent\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1010 * kSecond,
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "C:\\Users\\bob\\AppData\\evil.exe");
        detector.Enrich(event);
        FA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[file-assoc] TestPowerShellPlane\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            1011 * kSecond,
            "Set-ItemProperty 'HKCU:\\Software\\Classes\\txtfile\\shell\\"
            "open\\command' -Value 'powershell -File evil.ps1'");
        detector.Enrich(event);
        FA_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[file-assoc] TestPowerShellNoBodySilent\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(1012 * kSecond, "");
        detector.Enrich(event);
        FA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[file-assoc] TestMinScoreGate\n");
    {
        edr::FileAssocDetector detector(true, 80, 300, 1024);
        edr::Event event = RegNameEvent(
            1013 * kSecond,
            "HKCU\\Software\\Classes\\txtfile\\shell\\open\\command",
            "(default)");
        detector.Enrich(event);
        FA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[file-assoc] TestDedupWindow\n");
    {
        edr::FileAssocDetector detector(true, 55, 300, 1024);
        const char* cmd =
            "reg add \"HKCR\\txtfile\\shell\\open\\command\" /ve /d "
            "\"cmd.exe /c evil.bat\" /f";
        edr::Event first = ProcEvent(2000 * kSecond,
                                     "C:\\Windows\\System32\\reg.exe", cmd);
        detector.Enrich(first);
        FA_CHECK(Score(first) == "90");

        edr::Event dup = ProcEvent(2001 * kSecond,
                                   "C:\\Windows\\System32\\reg.exe", cmd);
        detector.Enrich(dup);
        FA_CHECK(Score(dup).empty());

        edr::Event later = ProcEvent(
            (2000 + 400) * kSecond,
            "C:\\Windows\\System32\\reg.exe", cmd);
        detector.Enrich(later);
        FA_CHECK(Score(later) == "90");
    }
    std::fprintf(stderr, "[file-assoc] all passed\n");
}
