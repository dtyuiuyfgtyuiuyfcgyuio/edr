/*
 * lsa_package_detector_tests.cpp - Unit tests for LsaPackageDetector
 * (T1547.005 / T1556.002).
 */
#include "lsa_package_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "lsa_package_detector.h"

namespace {

#define LP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "lsa package detector test failed at line " +
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

edr::Event RegEvent(uint64_t ts100ns, const char* key, const char* value) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    if (value != nullptr)
        event.fields[edr::field::kRegValue] = value;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kLsaPackageScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunLsaPackageDetectorTests() {
    std::fprintf(stderr, "[lsa-package] TestDisabled\n");
    {
        edr::LsaPackageDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4000 * kSecond, "C:\\Temp\\mimikatz.exe",
            "mimikatz.exe \"privilege::debug\" \"misc::memssp\"");
        detector.Enrich(event);
        LP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[lsa-package] TestMemssp\n");
    {
        edr::LsaPackageDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4001 * kSecond, "C:\\Temp\\mimikatz.exe",
            "mimikatz.exe privilege::debug misc::memssp");
        detector.Enrich(event);
        LP_CHECK(Score(event) == "90");
        LP_CHECK(event.fields.at(edr::field::kLsaPackageVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[lsa-package] TestMimilib\n");
    {
        edr::LsaPackageDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4002 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa "
            "/v \"Security Packages\" /d mimilib /t REG_MULTI_SZ");
        detector.Enrich(event);
        LP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[lsa-package] TestRegAddNotification\n");
    {
        edr::LsaPackageDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4003 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa "
            "/v \"Notification Packages\" /d evilfilter /f");
        detector.Enrich(event);
        LP_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[lsa-package] TestPowerShellWrite\n");
    {
        edr::LsaPackageDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            4004 * kSecond,
            "Set-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            "-Name 'Authentication Packages' -Value 'evilpkg'");
        detector.Enrich(event);
        LP_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[lsa-package] TestRegWriteDriverShape\n");
    {
        edr::LsaPackageDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            4005 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "Security Packages");
        detector.Enrich(event);
        LP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[lsa-package] TestRegWriteSnapshotShape\n");
    {
        edr::LsaPackageDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            4006 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
            "\\Notification Packages",
            "C:\\Temp\\filter.dll");
        detector.Enrich(event);
        LP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[lsa-package] TestSnapshotEmptySilent\n");
    {
        edr::LsaPackageDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            4007 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
            "\\Security Packages",
            "");
        detector.Enrich(event);
        LP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[lsa-package] TestInspectionSilent\n");
    {
        edr::LsaPackageDetector detector(true, 55, 300, 1024);
        edr::Event query = ProcEvent(
            4008 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa "
            "/v \"Security Packages\"");
        detector.Enrich(query);
        LP_CHECK(Score(query).empty());
        edr::Event get = ScriptEvent(
            4009 * kSecond,
            "Get-ItemProperty "
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa");
        detector.Enrich(get);
        LP_CHECK(Score(get).empty());
    }
    std::fprintf(stderr, "[lsa-package] TestEmptyScriptSilent\n");
    {
        edr::LsaPackageDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(4010 * kSecond, "");
        detector.Enrich(event);
        LP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[lsa-package] TestMinScoreIsolation\n");
    {
        edr::LsaPackageDetector high(true, 95, 300, 1024);
        edr::Event event = ProcEvent(
            4011 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa "
            "/v \"Security Packages\" /d extra /f");
        high.Enrich(event);
        LP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[lsa-package] all passed\n");
}
