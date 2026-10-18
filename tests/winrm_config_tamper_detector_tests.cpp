/*
 * winrm_config_tamper_detector_tests.cpp - Unit tests for
 * WinrmConfigTamperDetector (T1021.006 preparation plane).
 */
#include "winrm_config_tamper_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "winrm_config_tamper_detector.h"

namespace {

#define WC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "winrm config tamper detector test failed at line " +
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
    auto it = event.fields.find(
        edr::field::kWinrmConfigTamperScore);
    return it == event.fields.end() ? "" : it->second;
}

std::string Verdict(const edr::Event& event) {
    auto it = event.fields.find(
        edr::field::kWinrmConfigTamperVerdict);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunWinrmConfigTamperDetectorTests() {
    std::fprintf(stderr, "[winrm-config] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::WinrmConfigTamperDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell"
            "\\v1.0\\powershell.exe",
            "Set-Item WSMan:\\localhost\\Client\\TrustedHosts "
            "-Value * -Force");
        detector.Enrich(event);
        WC_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[winrm-config] TestTrustedHostsWildcard\n");
    {
        edr::WinrmConfigTamperDetector detector(true, 55, 300, 1024);
        edr::Event ps = ProcEvent(
            2000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell"
            "\\v1.0\\powershell.exe",
            "Set-Item WSMan:\\localhost\\Client\\TrustedHosts "
            "-Value * -Force");
        detector.Enrich(ps);
        WC_CHECK(Score(ps) == "85");
        WC_CHECK(Verdict(ps) == "malicious");

        edr::Event winrm = ProcEvent(
            2001 * kSecond,
            "C:\\Windows\\System32\\winrm.cmd",
            "winrm set winrm/config/client "
            "@{TrustedHosts=\"*\"}");
        detector.Enrich(winrm);
        WC_CHECK(Score(winrm) == "85");
    }
    std::fprintf(stderr, "[winrm-config] TestTrustedHostsList\n");
    {
        edr::WinrmConfigTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2002 * kSecond,
            "C:\\Windows\\System32\\winrm.cmd",
            "winrm set winrm/config/client "
            "@{TrustedHosts=\"10.0.0.5\"}");
        detector.Enrich(event);
        WC_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[winrm-config] TestEnablePsRemoting\n");
    {
        edr::WinrmConfigTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2003 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell"
            "\\v1.0\\powershell.exe",
            "Enable-PSRemoting -Force");
        detector.Enrich(event);
        WC_CHECK(Score(event) == "75");
        WC_CHECK(Verdict(event) == "malicious");
    }
    std::fprintf(stderr, "[winrm-config] TestQuickconfig\n");
    {
        edr::WinrmConfigTamperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            2004 * kSecond,
            "C:\\Windows\\System32\\winrm.cmd",
            "winrm quickconfig -q");
        detector.Enrich(event);
        WC_CHECK(Score(event) == "65");
        WC_CHECK(Verdict(event) == "suspicious");
    }
    std::fprintf(stderr, "[winrm-config] TestRegWritePlane\n");
    {
        /* Registry plane: TrustedHosts value write. */
        edr::WinrmConfigTamperDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.ts100ns = 2005 * kSecond;
        event.fields[edr::field::kType] = "REG_WRITE";
        event.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\WSMAN\\Client";
        event.fields[edr::field::kRegValue] = "trustedhosts *";
        detector.Enrich(event);
        WC_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[winrm-config] TestInspectionSilent\n");
    {
        /* Read-only WinRM inspection never scores. */
        edr::WinrmConfigTamperDetector detector(true, 55, 300, 1024);
        edr::Event identify = ProcEvent(
            2006 * kSecond,
            "C:\\Windows\\System32\\winrm.cmd",
            "winrm identify -r:10.0.0.5");
        detector.Enrich(identify);
        WC_CHECK(Score(identify).empty());
        edr::Event getcfg = ProcEvent(
            2007 * kSecond,
            "C:\\Windows\\System32\\winrm.cmd",
            "winrm get winrm/config");
        detector.Enrich(getcfg);
        WC_CHECK(Score(getcfg).empty());
    }
    std::fprintf(stderr, "[winrm-config] all passed\n");
}
