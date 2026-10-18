/*
 * timestomp_detector_tests.cpp - Unit tests for TimestompDetector.
 */
#include "timestomp_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "timestomp_detector.h"

namespace {

#define TS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "timestomp detector test failed at line " +
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

edr::Event SysmonFileTimeEvent(uint64_t ts100ns, const char* path,
                               const char* current, const char* previous) {
    edr::Event event;
    event.type = EDR_EVT_FILE_INTEGRITY;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_INTEGRITY";
    event.fields[edr::field::kSource] = "sysmon";
    event.fields[edr::field::kSysmonEventId] = "2";
    event.fields[edr::field::kFilePath] = path;
    event.fields[edr::field::kFileCreationTime] = current;
    event.fields[edr::field::kFilePreviousCreationTime] = previous;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kTimestompScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunTimestompDetectorTests() {
    std::fprintf(stderr, "[timestomp] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::TimestompDetector detector(false, 55, 300, 1024);
        edr::Event event =
            ProcEvent(1000 * kSecond, "C:\\temp\\timestomp.exe",
                      "timestomp.exe C:\\Windows\\svchost.exe /set M:12");
        detector.Enrich(event);
        TS_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[timestomp] TestSysmonFileTimeChange\n");
    {
        edr::TimestompDetector detector(true, 55, 300, 1024);
        edr::Event event = SysmonFileTimeEvent(
            1000 * kSecond, "C:\\Windows\\Temp\\svc.exe",
            "2024-01-01 00:00:00.000", "2026-08-27 08:00:00.000");
        detector.Enrich(event);
        TS_CHECK(HasScore(event));
        TS_CHECK(event.fields.at(edr::field::kTimestompScore) == "95");
        TS_CHECK(event.fields.at(edr::field::kTimestompVerdict) ==
                 "malicious");
        TS_CHECK(event.fields.at(edr::field::kTimestompCommand) ==
                 "c:\\windows\\temp\\svc.exe");

        edr::Event duplicate = SysmonFileTimeEvent(
            1010 * kSecond, "C:\\WINDOWS\\TEMP\\SVC.EXE",
            "2023-01-01 00:00:00.000", "2026-08-27 08:00:00.000");
        detector.Enrich(duplicate);
        TS_CHECK(!HasScore(duplicate));

        edr::Event unchanged = SysmonFileTimeEvent(
            2000 * kSecond, "C:\\Windows\\Temp\\same.exe",
            "2026-08-27 08:00:00.000", "2026-08-27 08:00:00.000");
        detector.Enrich(unchanged);
        TS_CHECK(!HasScore(unchanged));

        edr::Event wrongId = SysmonFileTimeEvent(
            2100 * kSecond, "C:\\Windows\\Temp\\other.exe",
            "2024-01-01 00:00:00.000", "2026-08-27 08:00:00.000");
        wrongId.fields[edr::field::kSysmonEventId] = "11";
        detector.Enrich(wrongId);
        TS_CHECK(!HasScore(wrongId));
    }
    std::fprintf(stderr, "[timestomp] TestDedicatedTool\n");
    {
        /* timestomp.exe invocation -> 85 malicious. */
        edr::TimestompDetector detector(true, 55, 300, 1024);
        edr::Event event =
            ProcEvent(1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
                      "cmd /c C:\\temp\\timestomp.exe payload.exe -z");
        detector.Enrich(event);
        TS_CHECK(HasScore(event));
        TS_CHECK(event.fields.at(edr::field::kTimestompScore) == "85");
        TS_CHECK(event.fields.at(edr::field::kTimestompVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[timestomp] TestPowerShellAssignment\n");
    {
        /* Property assignment -> 70 suspicious. */
        edr::TimestompDetector detector(true, 55, 300, 1024);
        edr::Event event =
            ProcEvent(1000 * kSecond,
                      "C:\\Windows\\System32\\WindowsPowerShell"
                      "\\v1.0\\powershell.exe",
                      "powershell -c (Get-Item svc.exe).LastWriteTime = "
                      "'2024-01-01'");
        detector.Enrich(event);
        TS_CHECK(HasScore(event));
        TS_CHECK(event.fields.at(edr::field::kTimestompScore) == "70");
        TS_CHECK(event.fields.at(edr::field::kTimestompVerdict) ==
                 "suspicious");
    }
    {
        /* CreationTime assignment via variable -> 70. */
        edr::TimestompDetector detector(true, 55, 300, 1024);
        edr::Event event =
            ProcEvent(1000 * kSecond,
                      "C:\\Windows\\System32\\WindowsPowerShell"
                      "\\v1.0\\powershell.exe",
                      "powershell -c $f.CreationTime = Get-Date 2019");
        detector.Enrich(event);
        TS_CHECK(HasScore(event));
        TS_CHECK(event.fields.at(edr::field::kTimestompScore) == "70");
    }
    {
        /* Plain property read (no '=' after the property) never fires:
         * Get-ChildItem | select LastWriteTime is benign inventory. */
        edr::TimestompDetector detector(true, 55, 300, 1024);
        edr::Event event =
            ProcEvent(1000 * kSecond,
                      "C:\\Windows\\System32\\WindowsPowerShell"
                      "\\v1.0\\powershell.exe",
                      "powershell -c Get-Item a.txt | "
                      "select LastWriteTime");
        detector.Enrich(event);
        TS_CHECK(!HasScore(event));
    }
    {
        /* Assignment shape required: an unrelated later assignment or
         * an -eq comparison on the same line must NOT hit (the old
         * any-'=' heuristic false-positived here). */
        edr::TimestompDetector detector(true, 55, 300, 1024);
        edr::Event cmp =
            ProcEvent(1000 * kSecond,
                      "C:\\Windows\\System32\\WindowsPowerShell"
                      "\\v1.0\\powershell.exe",
                      "powershell -c (Get-Item a.txt).lastwritetime -eq "
                      "(Get-Item b.txt).lastwritetime");
        detector.Enrich(cmp);
        TS_CHECK(!HasScore(cmp));

        edr::Event later =
            ProcEvent(1100 * kSecond,
                      "C:\\Windows\\System32\\WindowsPowerShell"
                      "\\v1.0\\powershell.exe",
                      "powershell -c $_.LastWriteTime } | Out-File log; "
                      "$stamp = New-TimeSpan");
        detector.Enrich(later);
        TS_CHECK(!HasScore(later));
    }
    {
        /* Extension-less Meterpreter spelling at command position 0. */
        edr::TimestompDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "timestomp C:\\Windows\\Temp\\svc.exe -z \"20240101\"");
        detector.Enrich(event);
        TS_CHECK(HasScore(event));
        TS_CHECK(event.fields.at(edr::field::kTimestompScore) == "85");

        /* Prose mentioning timestomping never fires. */
        edr::Event prose = ProcEvent(
            2000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "analyze.exe --report timestomping survey.docx");
        detector.Enrich(prose);
        TS_CHECK(!HasScore(prose));
    }
    std::fprintf(stderr, "[timestomp] TestDotNetSetter\n");
    {
        /* [IO.File]::SetLastWriteTime -> 70. */
        edr::TimestompDetector detector(true, 55, 300, 1024);
        edr::Event event =
            ProcEvent(1000 * kSecond,
                      "C:\\Windows\\System32\\WindowsPowerShell"
                      "\\v1.0\\powershell.exe",
                      "powershell -c [IO.File]::SetLastWriteTime($p,$t)");
        detector.Enrich(event);
        TS_CHECK(HasScore(event));
        TS_CHECK(event.fields.at(edr::field::kTimestompScore) == "70");

        /* SetLastAccessTime variant also hits. */
        edr::Event access =
            ProcEvent(2000 * kSecond,
                      "C:\\Windows\\System32\\WindowsPowerShell"
                      "\\v1.0\\powershell.exe",
                      "powershell -c "
                      "[System.IO.File]::SetCreationTime($p,$d)");
        detector.Enrich(access);
        TS_CHECK(HasScore(access));
    }
    std::fprintf(stderr, "[timestomp] TestBenignCommands\n");
    {
        edr::TimestompDetector detector(true, 55, 300, 1024);
        /* Ordinary commands never fire. */
        TS_CHECK([&] {
            edr::Event e = ProcEvent(1000 * kSecond,
                                     "C:\\Windows\\System32\\cmd.exe",
                                     "cmd /c dir C:\\Windows");
            detector.Enrich(e);
            return !HasScore(e);
        }());
        TS_CHECK([&] {
            edr::Event e = ProcEvent(
                2000 * kSecond,
                "C:\\Windows\\System32\\robocopy.exe",
                "robocopy C:\\src D:\\dst /MIR");
            detector.Enrich(e);
            return !HasScore(e);
        }());
    }
    std::fprintf(stderr, "[timestomp] TestDedupWindow\n");
    {
        /* Identical command inside the dedup window fires once and
         * re-arms after it. */
        edr::TimestompDetector detector(true, 55, 300, 1024);
        const char* cmd =
            "powershell -c (Get-Item x.exe).LastWriteTime='2020'";
        edr::Event first = ProcEvent(1000 * kSecond, "powershell.exe", cmd);
        detector.Enrich(first);
        TS_CHECK(HasScore(first));

        edr::Event second = ProcEvent(1010 * kSecond, "powershell.exe", cmd);
        detector.Enrich(second);
        TS_CHECK(!HasScore(second));

        edr::Event third = ProcEvent(
            1000 * kSecond + 301 * kSecond, "powershell.exe", cmd);
        detector.Enrich(third);
        TS_CHECK(HasScore(third));
    }
}
