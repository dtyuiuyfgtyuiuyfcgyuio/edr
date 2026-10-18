/*
 * iis_module_detector_tests.cpp - Unit tests for IisModuleDetector
 * (T1505.004).
 */
#include "iis_module_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "iis_module_detector.h"

namespace {

#define IM_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "iis module detector test failed at line " +
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

edr::Event FileEvent(uint64_t ts100ns, const char* image,
                     const char* path) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kFilePath] = path;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kIisModuleScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunIisModuleDetectorTests() {
    std::fprintf(stderr, "[iis-module] TestDisabled\n");
    {
        edr::IisModuleDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4300 * kSecond,
            "C:\\Windows\\System32\\inetsrv\\appcmd.exe",
            "appcmd add module /name:evil /image:C:\\Temp\\evil.dll");
        detector.Enrich(event);
        IM_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[iis-module] TestAppcmdAddModule\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4301 * kSecond,
            "C:\\Windows\\System32\\inetsrv\\appcmd.exe",
            "appcmd add module /name:evil /image:C:\\Temp\\evil.dll");
        detector.Enrich(event);
        IM_CHECK(Score(event) == "90");
        IM_CHECK(event.fields.at(edr::field::kIisModuleVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[iis-module] TestAppcmdInstallModule\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4302 * kSecond,
            "C:\\Windows\\System32\\inetsrv\\appcmd.exe",
            "appcmd install module /name:mod "
            "/image:C:\\Users\\Public\\m.dll");
        detector.Enrich(event);
        IM_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[iis-module] TestNewWebGlobalModule\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            4303 * kSecond,
            "New-WebGlobalModule -Name evil "
            "-Image C:\\Temp\\evil.dll");
        detector.Enrich(event);
        IM_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[iis-module] TestAppcmdSetConfig\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4304 * kSecond,
            "C:\\Windows\\System32\\inetsrv\\appcmd.exe",
            "appcmd set config /section:system.webServer/globalModules "
            "/+[name='evil',image='C:\\Temp\\e.dll']");
        detector.Enrich(event);
        IM_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[iis-module] TestApplicationHostOverwrite\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4305 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Temp\\applicationHost.config "
            "C:\\Windows\\System32\\inetsrv\\config\\"
            "applicationHost.config");
        detector.Enrich(event);
        IM_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[iis-module] TestDllDropInetsrv\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event event = FileEvent(
            4306 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\inetsrv\\evil.dll");
        detector.Enrich(event);
        IM_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[iis-module] TestDllDropInetpub\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event event = FileEvent(
            4307 * kSecond, "C:\\Users\\bob\\dropper.exe",
            "C:\\inetpub\\wwwroot\\bin\\mod.dll");
        detector.Enrich(event);
        IM_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[iis-module] TestInstallerWriterSilent\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event w3wp = FileEvent(
            4308 * kSecond,
            "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
            "C:\\Windows\\System32\\inetsrv\\aspnetcore.dll");
        detector.Enrich(w3wp);
        IM_CHECK(Score(w3wp).empty());
        edr::Event msi = FileEvent(
            4309 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
            "C:\\Windows\\System32\\inetsrv\\rewrite.dll");
        detector.Enrich(msi);
        IM_CHECK(Score(msi).empty());
    }
    std::fprintf(stderr, "[iis-module] TestListModuleSilent\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event list = ProcEvent(
            4310 * kSecond,
            "C:\\Windows\\System32\\inetsrv\\appcmd.exe",
            "appcmd list module");
        detector.Enrich(list);
        IM_CHECK(Score(list).empty());
        edr::Event get = ScriptEvent(
            4311 * kSecond, "Get-WebGlobalModule | Format-Table");
        detector.Enrich(get);
        IM_CHECK(Score(get).empty());
    }
    std::fprintf(stderr, "[iis-module] TestBareAppcmdSilent\n");
    {
        edr::IisModuleDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4312 * kSecond,
            "C:\\Windows\\System32\\inetsrv\\appcmd.exe",
            "appcmd.exe");
        detector.Enrich(event);
        IM_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[iis-module] all passed\n");
}
