/*
 * history_tamper_detector_tests.cpp - Unit tests for
 * HistoryTamperDetector (T1070.003 / T1562.003).
 */
#include "history_tamper_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "history_tamper_detector.h"

namespace {

#define HT_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "history tamper detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kHistoryTamperScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunHistoryTamperDetectorTests() {
    std::fprintf(stderr, "[history-tamper] TestDisabled\n");
    {
        edr::HistoryTamperDetector detector(false, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            7000 * kSecond,
            "Set-PSReadLineOption -HistorySaveStyle SaveNothing");
        detector.Enrich(event);
        HT_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[history-tamper] TestCaptureDisabled\n");
    {
        /* Disabling capture outranks deleting the file: every later
         * command in the session becomes invisible. */
        edr::HistoryTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            7000 * kSecond,
            "Set-PSReadLineOption -HistorySaveStyle SaveNothing");
        detector.Enrich(event);
        HT_CHECK(Score(event) == "90");
        HT_CHECK(event.fields.at(
            edr::field::kHistoryTamperVerdict) == "malicious");
    }
    std::fprintf(stderr, "[history-tamper] TestHistoryFileDeleted\n");
    {
        edr::HistoryTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            7001 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "del /f /q \"%APPDATA%\\Microsoft\\Windows\\PowerShell\\"
            "PSReadLine\\ConsoleHost_history.txt\"");
        detector.Enrich(event);
        HT_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[history-tamper] TestFileDeletePlane\n");
    {
        /* FILE_DELETE of the history file: the delete IS the verb, so no
         * command-plane verb is required. */
        edr::HistoryTamperDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_FILE_DELETE;
        event.ts100ns = 7002 * kSecond;
        event.fields[edr::field::kType] = "FILE_DELETE";
        event.fields[edr::field::kFilePath] =
            "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\"
            "PowerShell\\PSReadLine\\ConsoleHost_history.txt";
        detector.Enrich(event);
        HT_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[history-tamper] TestSavePathRedirected\n");
    {
        edr::HistoryTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            7003 * kSecond,
            "Set-PSReadLineOption -HistorySavePath $env:TEMP\\x.txt");
        detector.Enrich(event);
        HT_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[history-tamper] TestClearHistoryLowerBand\n");
    {
        /* In-memory buffer only; the on-disk file may survive. */
        edr::HistoryTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(7004 * kSecond, "Clear-History");
        detector.Enrich(event);
        HT_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[history-tamper] TestBareReferenceLowBand\n");
    {
        edr::HistoryTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            7005 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "dir \"%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\"
            "ConsoleHost_history.txt\"");
        detector.Enrich(event);
        HT_CHECK(Score(event) == "60");
        HT_CHECK(event.fields.at(
            edr::field::kHistoryTamperVerdict) == "suspicious");
    }
    std::fprintf(stderr, "[history-tamper] TestReadOnlySilent\n");
    {
        edr::HistoryTamperDetector detector(true, 55, 300, 1024);
        edr::Event readIt = ScriptEvent(
            7006 * kSecond,
            "Get-Content (Get-PSReadLineOption).HistorySavePath");
        detector.Enrich(readIt);
        HT_CHECK(Score(readIt).empty());

        edr::Event getHistory = ScriptEvent(7007 * kSecond, "Get-History");
        detector.Enrich(getHistory);
        HT_CHECK(Score(getHistory).empty());

        /* Deleting an unrelated file. */
        edr::Event unrelated = ProcEvent(
            7008 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "del /f /q C:\\Temp\\build.log");
        detector.Enrich(unrelated);
        HT_CHECK(Score(unrelated).empty());
    }
    std::fprintf(stderr, "[history-tamper] all passed\n");
}
