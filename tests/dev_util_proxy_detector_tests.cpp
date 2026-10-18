/*
 * dev_util_proxy_detector_tests.cpp - Unit tests for
 * DevUtilProxyDetector (T1127 / T1218.004).
 */
#include "dev_util_proxy_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "dev_util_proxy_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define DU_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "dev util proxy detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kDevUtilProxyScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunDevUtilProxyDetectorTests() {
    std::fprintf(stderr, "[dev-util] TestDisabled\n");
    {
        edr::DevUtilProxyDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2000 * kSecond,
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"
            "\\MSBuild.exe",
            "MSBuild.exe C:\\Users\\Public\\inline.csproj "
            "/p:UsingTask=CodeTaskFactory");
        detector.Enrich(event);
        DU_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[dev-util] TestMsbuildInline\n");
    {
        edr::DevUtilProxyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2001 * kSecond,
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"
            "\\MSBuild.exe",
            "MSBuild.exe C:\\Users\\Public\\inline.csproj "
            "/p:UsingTask=CodeTaskFactory");
        detector.Enrich(event);
        DU_CHECK(Score(event) == "90");
        DU_CHECK(event.fields.at(edr::field::kDevUtilProxyVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[dev-util] TestCscTemp\n");
    {
        edr::DevUtilProxyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2002 * kSecond,
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
            "csc.exe /t:exe /out:%TEMP%\\payload.exe %TEMP%\\payload.cs");
        detector.Enrich(event);
        DU_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[dev-util] TestInstallUtil\n");
    {
        edr::DevUtilProxyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2003 * kSecond,
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"
            "\\InstallUtil.exe",
            "InstallUtil.exe /logfile= /LogToConsole=false "
            "C:\\Users\\Public\\evil.dll");
        detector.Enrich(event);
        DU_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[dev-util] TestWorkflowCompiler\n");
    {
        edr::DevUtilProxyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2004 * kSecond,
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"
            "\\Microsoft.Workflow.Compiler.exe",
            "Microsoft.Workflow.Compiler.exe input.xml results.xml");
        detector.Enrich(event);
        DU_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[dev-util] TestMsbuildUserProj\n");
    {
        edr::DevUtilProxyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2005 * kSecond,
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"
            "\\MSBuild.exe",
            "MSBuild.exe C:\\Users\\Public\\stage.csproj");
        detector.Enrich(event);
        DU_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[dev-util] TestBareMsbuildSilent\n");
    {
        edr::DevUtilProxyDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2006 * kSecond,
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\MSBuild\\"
            "Current\\Bin\\MSBuild.exe",
            "MSBuild.exe C:\\src\\app\\app.csproj /t:Build");
        detector.Enrich(event);
        DU_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[dev-util] TestScriptPlaneCsc\n");
    {
        edr::DevUtilProxyDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            2007 * kSecond,
            "& $env:windir\\Microsoft.NET\\Framework64\\v4.0.30319\\"
            "csc.exe /t:exe /out:$env:TEMP\\a.exe $env:TEMP\\a.cs");
        detector.Enrich(event);
        DU_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[dev-util] all passed\n");
}
