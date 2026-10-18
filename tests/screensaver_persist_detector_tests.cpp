/*
 * screensaver_persist_detector_tests.cpp - Unit tests for
 * ScreensaverPersistDetector (T1546.002 Event Triggered Execution:
 * Screensaver, formerly T1180).
 */
#include "screensaver_persist_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "screensaver_persist_detector.h"

namespace {

#define SS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "screensaver persist detector test failed at line " +
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

/* Driver/imonitor REG_WRITE shape: bare key + value NAME. */
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

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kScreensaverPersistScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunScreensaverPersistDetectorTests() {
    std::fprintf(stderr, "[screensaver] TestDisabled\n");
    {
        edr::ScreensaverPersistDetector detector(false, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1000 * kSecond,
            "HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE",
            "C:\\Users\\bob\\AppData\\evil.scr");
        detector.Enrich(event);
        SS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[screensaver] TestRegDataShapeInterpreter\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1001 * kSecond,
            "HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE",
            "powershell.exe -WindowStyle hidden -File lock.scr.ps1");
        detector.Enrich(event);
        SS_CHECK(Score(event) == "90");
        SS_CHECK(event.fields.at(
            edr::field::kScreensaverPersistVerdict) == "malicious");
    }
    std::fprintf(stderr, "[screensaver] TestRegDataShapeWritableDir\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1002 * kSecond,
            "HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE",
            "C:\\Users\\Public\\update.scr");
        detector.Enrich(event);
        SS_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[screensaver] TestRegDataShapePayloadExt\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1003 * kSecond,
            "HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE",
            "D:\\tools\\custom.exe");
        detector.Enrich(event);
        SS_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[screensaver] TestStockScreensaverSilent\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1004 * kSecond,
            "HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE",
            "C:\\Windows\\System32\\Ribbons.scr");
        detector.Enrich(event);
        SS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[screensaver] TestRegNameShape\n");
    {
        /* Driver shape carries only the name: slot registered with no
         * payload token observed. */
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegNameEvent(
            1005 * kSecond,
            "HKCU\\Control Panel\\Desktop",
            "SCRNSAVE.EXE");
        detector.Enrich(event);
        SS_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[screensaver] TestUnrelatedRegWriteSilent\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegDataEvent(
            1006 * kSecond,
            "HKCU\\Control Panel\\Desktop\\WallPaper",
            "C:\\Users\\bob\\AppData\\img.bmp");
        detector.Enrich(event);
        SS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[screensaver] TestCommandLineRegAdd\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1007 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKCU\\Control Panel\\Desktop\" /v SCRNSAVE.EXE "
            "/t REG_SZ /d \"C:\\Users\\bob\\AppData\\evil.scr\" /f");
        detector.Enrich(event);
        SS_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[screensaver] TestCommandLineQuotedInterpreter\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1008 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "reg add \"HKCU\\Control Panel\\Desktop\" /v SCRNSAVE.EXE "
            "/t REG_SZ /d \"cmd.exe /c calc.exe\" /f");
        detector.Enrich(event);
        SS_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[screensaver] TestCommandLineNoPayloadToken\n");
    {
        /* reg add mentioning the slot with no /d still creates it. */
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1009 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKCU\\Control Panel\\Desktop\" /v SCRNSAVE.EXE /f");
        detector.Enrich(event);
        SS_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[screensaver] TestReadOnlyQuerySilent\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1010 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKCU\\Control Panel\\Desktop\" /v SCRNSAVE.EXE");
        detector.Enrich(event);
        SS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[screensaver] TestPowerShellScriptPlane\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            1011 * kSecond,
            "Set-ItemProperty 'HKCU:\\Control Panel\\Desktop' "
            "-Name SCRNSAVE.EXE -Value 'C:\\Temp\\payload.exe'");
        detector.Enrich(event);
        SS_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[screensaver] TestPowerShellNoBodySilent\n");
    {
        /* House contract: no-body PS events must stay silent; the
         * command-plane test above covers the PS surface. */
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(1012 * kSecond, "");
        detector.Enrich(event);
        SS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[screensaver] TestMinScoreGate\n");
    {
        edr::ScreensaverPersistDetector detector(true, 80, 300, 1024);
        edr::Event event = RegNameEvent(
            1013 * kSecond,
            "HKCU\\Control Panel\\Desktop",
            "SCRNSAVE.EXE");
        detector.Enrich(event);
        SS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[screensaver] TestDedupWindow\n");
    {
        edr::ScreensaverPersistDetector detector(true, 55, 300, 1024);
        const char* cmd =
            "reg add \"HKCU\\Control Panel\\Desktop\" /v SCRNSAVE.EXE "
            "/t REG_SZ /d \"C:\\Users\\bob\\AppData\\evil.scr\" /f";
        edr::Event first = ProcEvent(2000 * kSecond,
                                     "C:\\Windows\\System32\\reg.exe", cmd);
        detector.Enrich(first);
        SS_CHECK(Score(first) == "90");

        /* Same key inside the dedup window: suppressed. */
        edr::Event dup = ProcEvent(2001 * kSecond,
                                   "C:\\Windows\\System32\\reg.exe", cmd);
        detector.Enrich(dup);
        SS_CHECK(Score(dup).empty());

        /* After the window: re-armed. */
        edr::Event later = ProcEvent(
            (2000 + 400) * kSecond,
            "C:\\Windows\\System32\\reg.exe", cmd);
        detector.Enrich(later);
        SS_CHECK(Score(later) == "90");
    }
    std::fprintf(stderr, "[screensaver] all passed\n");
}
