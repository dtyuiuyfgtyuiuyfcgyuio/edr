/*
 * path_interception_detector_tests.cpp - Unit tests for
 * PathInterceptionDetector (T1574.007/008).
 */
#include "path_interception_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "path_interception_detector.h"

namespace {

#define PI_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "path interception detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kPathInterceptScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunPathInterceptionDetectorTests() {
    std::fprintf(stderr, "[path-intercept] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::PathInterceptionDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "setx PATH \"%APPDATA%\\evil;%PATH%\"");
        detector.Enrich(event);
        PI_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[path-intercept] TestSetxWritableDir\n");
    {
        edr::PathInterceptionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "setx PATH \"%APPDATA%\\evil;%PATH%\"");
        detector.Enrich(event);
        PI_CHECK(Score(event) == "85");
        PI_CHECK(event.fields.at(
            edr::field::kPathInterceptVerdict) == "malicious");
    }
    std::fprintf(stderr, "[path-intercept] TestSetxPlain\n");
    {
        /* setx PATH without a writable dir is the lower band. */
        edr::PathInterceptionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4001 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "setx PATH \"C:\\Tools;%PATH%\"");
        detector.Enrich(event);
        PI_CHECK(Score(event) == "65");
        PI_CHECK(event.fields.at(
            edr::field::kPathInterceptVerdict) == "suspicious");
    }
    std::fprintf(stderr, "[path-intercept] TestRegAddMachine\n");
    {
        edr::PathInterceptionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4002 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
            "Session Manager\\Environment /v Path /d "
            "C:\\Users\\Public\\bin;%PATH% /f");
        detector.Enrich(event);
        PI_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[path-intercept] TestPsSetEnvVar\n");
    {
        edr::PathInterceptionDetector detector(true, 55, 300, 1024);
        edr::Event script;
        script.type = EDR_EVT_POWERSHELL_SCRIPT;
        script.ts100ns = 4003 * kSecond;
        script.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        script.fields[edr::field::kScriptBlockText] =
            "[Environment]::SetEnvironmentVariable(\"Path\", "
            "\"$env:TEMP\\implant;\" + $old, \"Machine\")";
        detector.Enrich(script);
        PI_CHECK(Score(script) == "85");
    }
    std::fprintf(stderr, "[path-intercept] TestRegWritePlane\n");
    {
        /* Registry plane, snapshot shape (sysmon / reg_watch /
         * reg_baseline): kRegKey carries the value name, kRegValue the
         * data. A writable directory in the data is the malicious band. */
        edr::PathInterceptionDetector detector(true, 55, 300, 1024);
        edr::Event snapshot;
        snapshot.type = EDR_EVT_REG_WRITE;
        snapshot.ts100ns = 4004 * kSecond;
        snapshot.fields[edr::field::kType] = "REG_WRITE";
        snapshot.fields[edr::field::kRegKey] =
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
            "\\Environment\\Path";
        snapshot.fields[edr::field::kRegValue] =
            "C:\\ProgramData\\tools;%PATH%";
        detector.Enrich(snapshot);
        PI_CHECK(Score(snapshot) == "90");

        /* Bare shape (driver / imonitor): kRegKey is the key, kRegValue
         * the value name. No data to inspect, so the lower band. */
        edr::Event bare;
        bare.type = EDR_EVT_REG_WRITE;
        bare.ts100ns = 4007 * kSecond;
        bare.fields[edr::field::kType] = "REG_WRITE";
        bare.fields[edr::field::kRegKey] =
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
            "\\Environment";
        bare.fields[edr::field::kRegValue] = "Path";
        detector.Enrich(bare);
        PI_CHECK(Score(bare) == "75");
    }
    std::fprintf(stderr, "[path-intercept] TestRegWriteNeighbourValues\n");
    {
        /* Values that merely contain "path" as a substring live next to
         * Path under the same key and must never fire. */
        edr::PathInterceptionDetector detector(true, 55, 300, 1024);
        const char* const kNeighbours[] = {"PATHEXT", "PSModulePath",
                                           "DevicePath"};
        uint64_t ts = 4020;
        for (const char* value : kNeighbours) {
            edr::Event bare;
            bare.type = EDR_EVT_REG_WRITE;
            bare.ts100ns = ts++ * kSecond;
            bare.fields[edr::field::kType] = "REG_WRITE";
            bare.fields[edr::field::kRegKey] =
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
                "\\Environment";
            bare.fields[edr::field::kRegValue] = value;
            detector.Enrich(bare);
            PI_CHECK(Score(bare).empty());

            edr::Event snapshot;
            snapshot.type = EDR_EVT_REG_WRITE;
            snapshot.ts100ns = ts++ * kSecond;
            snapshot.fields[edr::field::kType] = "REG_WRITE";
            snapshot.fields[edr::field::kRegKey] =
                std::string("HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
                            "Session Manager\\Environment\\") + value;
            snapshot.fields[edr::field::kRegValue] = ".COM;.EXE;.BAT";
            detector.Enrich(snapshot);
            PI_CHECK(Score(snapshot).empty());
        }
    }
    std::fprintf(stderr, "[path-intercept] TestRegWritePlaneDedup\n");
    {
        /* A polling registry collector re-reporting the same value must
         * not re-alert inside the dedup window. */
        edr::PathInterceptionDetector detector(true, 55, 60, 1024);
        auto regEvent = [](uint64_t ts) {
            edr::Event event;
            event.type = EDR_EVT_REG_WRITE;
            event.ts100ns = ts;
            event.fields[edr::field::kType] = "REG_WRITE";
            event.fields[edr::field::kRegKey] =
                "HKCU\\Environment\\Path";
            event.fields[edr::field::kRegValue] =
                "C:\\Users\\Public\\bin;%PATH%";
            return event;
        };
        edr::Event first = regEvent(5000 * kSecond);
        detector.Enrich(first);
        PI_CHECK(Score(first) == "90");

        edr::Event repeat = regEvent(5010 * kSecond);
        detector.Enrich(repeat);
        PI_CHECK(Score(repeat).empty());

        edr::Event later = regEvent(5100 * kSecond);
        detector.Enrich(later);
        PI_CHECK(Score(later) == "90");
    }
    std::fprintf(stderr, "[path-intercept] TestEnvAssignPrepend\n");
    {
        /* A bare $env:Path assignment is a write, not a display: the
         * classic in-process prepend must score when the injected entry
         * is user-writable. */
        edr::PathInterceptionDetector detector(true, 55, 300, 1024);
        edr::Event prepend;
        prepend.type = EDR_EVT_POWERSHELL_SCRIPT;
        prepend.ts100ns = 6000 * kSecond;
        prepend.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        prepend.fields[edr::field::kScriptBlockText] =
            "$env:Path = \"C:\\Users\\Public\\bin;$env:Path\"";
        detector.Enrich(prepend);
        PI_CHECK(Score(prepend) == "80");

        /* An equality comparison is not an assignment. */
        edr::Event compare;
        compare.type = EDR_EVT_POWERSHELL_SCRIPT;
        compare.ts100ns = 6001 * kSecond;
        compare.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        compare.fields[edr::field::kScriptBlockText] =
            "if ($env:Path == $expected) { Write-Host ok }";
        detector.Enrich(compare);
        PI_CHECK(Score(compare).empty());

        /* Prepending a non-writable directory is ordinary shell setup. */
        edr::Event benign;
        benign.type = EDR_EVT_POWERSHELL_SCRIPT;
        benign.ts100ns = 6002 * kSecond;
        benign.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        benign.fields[edr::field::kScriptBlockText] =
            "$env:Path = \"C:\\Program Files\\Git\\cmd;$env:Path\"";
        detector.Enrich(benign);
        PI_CHECK(Score(benign).empty());
    }
    std::fprintf(stderr, "[path-intercept] TestReadOnlySilent\n");
    {
        /* Read-only PATH display never scores. */
        edr::PathInterceptionDetector detector(true, 55, 300, 1024);
        edr::Event echo = ProcEvent(
            4005 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "echo %PATH%");
        detector.Enrich(echo);
        PI_CHECK(Score(echo).empty());

        edr::Event gci;
        gci.type = EDR_EVT_POWERSHELL_SCRIPT;
        gci.ts100ns = 4006 * kSecond;
        gci.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        gci.fields[edr::field::kScriptBlockText] =
            "$env:Path -split ';' | ForEach-Object { gci $_ }";
        detector.Enrich(gci);
        PI_CHECK(Score(gci).empty());
    }
    std::fprintf(stderr, "[path-intercept] all passed\n");
}
