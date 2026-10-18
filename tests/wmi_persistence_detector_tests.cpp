/*
 * wmi_persistence_detector_tests.cpp - Unit tests for
 * WmiPersistenceDetector and the production rule it feeds.
 */
#include "wmi_persistence_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"
#include "wmi_persistence_detector.h"

namespace {

#define WP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "wmi persistence detector test failed at line " +
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

edr::Event WmiEvent(const std::string& operation, const std::string& query,
                    const std::string& consumer, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_WMI_EVENT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "WMI_EVENT";
    event.fields[edr::field::kOperationType] = operation;
    event.fields[edr::field::kWmiQuery] = query;
    event.fields[edr::field::kWmiProviderName] = consumer;
    event.fields[edr::field::kWmiOperation] = "ActiveScriptEventConsumer";
    return event;
}

edr::Event ProcessStart(uint32_t pid, uint32_t ppid,
                        const std::string& image, const std::string& command,
                        uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.ppid = ppid;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kCommandLine] = command;
    return event;
}

void TestSingleSubscriptionTriggers() {
    edr::WmiPersistenceDetector detector(true, 600, 4096, 1);
    const uint64_t base = 1000000000ULL;
    detector.Enrich(WmiEvent(
        "TEMPORARY_EVENT_SUBSCRIPTION",
        "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE "
        "TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = "
        "'C:\\Users\\a\\evil.exe'",
        "", base));
    edr::Event proc = ProcessStart(
        4001, 100, "C:\\Users\\a\\evil.exe", "C:\\Users\\a\\evil.exe",
        base + 10000000ULL);
    detector.Enrich(proc);
    WP_CHECK(proc.fields.at(edr::field::kWmiPersistenceScore) == "55");
    WP_CHECK(proc.fields.at(edr::field::kWmiPersistenceMatches) == "1");
    WP_CHECK(proc.fields.at(edr::field::kWmiPersistenceVerdict) == "SUSPICIOUS");
    WP_CHECK(proc.fields.at(edr::field::kWmiPersistenceWindowSeconds) == "600");
}

void TestMultipleSubscriptionsMalicious() {
    edr::WmiPersistenceDetector detector(true, 600, 4096, 2);
    const uint64_t base = 2000000000ULL;
    detector.Enrich(WmiEvent(
        "PERMANENT_EVENT_SUBSCRIPTION",
        "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE "
        "TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = "
        "'C:\\Users\\a\\evil.exe'",
        "evil-sub-1", base));
    detector.Enrich(WmiEvent(
        "FILTER_TO_CONSUMER_BINDING",
        "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE "
        "TargetInstance ISA 'Win32_Process' AND TargetInstance.ExecutablePath "
        "= 'C:\\Users\\a\\evil.exe'",
        "evil-sub-2", base + 10000000ULL));
    edr::Event proc = ProcessStart(
        4002, 100, "C:\\Users\\a\\evil.exe", "C:\\Users\\a\\evil.exe",
        base + 20000000ULL);
    detector.Enrich(proc);
    WP_CHECK(proc.fields.at(edr::field::kWmiPersistenceScore) == "90");
    WP_CHECK(proc.fields.at(edr::field::kWmiPersistenceMatches) == "2");
    WP_CHECK(proc.fields.at(edr::field::kWmiPersistenceVerdict) == "MALICIOUS");
}

void TestNoSubscriptionNoStamp() {
    edr::WmiPersistenceDetector detector(true, 600, 4096, 1);
    const uint64_t base = 3000000000ULL;
    edr::Event proc = ProcessStart(
        4003, 100, "C:\\Users\\a\\evil.exe", "C:\\Users\\a\\evil.exe",
        base);
    detector.Enrich(proc);
    WP_CHECK(proc.fields.find(edr::field::kWmiPersistenceScore) ==
             proc.fields.end());
}

void TestExpiredSubscriptionResets() {
    edr::WmiPersistenceDetector detector(true, 1, 4096, 1);
    const uint64_t base = 4000000000ULL;
    detector.Enrich(WmiEvent(
        "TEMPORARY_EVENT_SUBSCRIPTION",
        "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE "
        "TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = "
        "'C:\\Users\\a\\evil.exe'",
        "", base));
    edr::Event proc = ProcessStart(
        4004, 100, "C:\\Users\\a\\evil.exe", "C:\\Users\\a\\evil.exe",
        base + 11000000ULL);
    detector.Enrich(proc);
    WP_CHECK(proc.fields.find(edr::field::kWmiPersistenceScore) ==
             proc.fields.end());
}

void TestCommandLineTokenMatches() {
    edr::WmiPersistenceDetector detector(true, 600, 4096, 1);
    const uint64_t base = 5000000000ULL;
    detector.Enrich(WmiEvent(
        "TEMPORARY_EVENT_SUBSCRIPTION",
        "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE "
        "TargetInstance ISA 'Win32_Process' AND TargetInstance.CommandLine "
        "LIKE '%C:\\Users\\a\\shadow.ps1%'",
        "", base));
    edr::Event proc = ProcessStart(
        4005, 100,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell -w hidden C:\\Users\\a\\shadow.ps1",
        base + 10000000ULL);
    detector.Enrich(proc);
    WP_CHECK(proc.fields.at(edr::field::kWmiPersistenceScore) == "55");
    WP_CHECK(proc.fields.at(edr::field::kWmiPersistenceMatchText).find(
                 "shadow.ps1") != std::string::npos);
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::WmiPersistenceDetector detector(true, 600, 4096, 1);
    const uint64_t base = 6000000000ULL;
    detector.Enrich(WmiEvent(
        "TEMPORARY_EVENT_SUBSCRIPTION",
        "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE "
        "TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = "
        "'C:\\Users\\a\\evil.exe'",
        "", base));
    edr::Event proc = ProcessStart(
        4006, 100, "C:\\Users\\a\\evil.exe", "C:\\Users\\a\\evil.exe",
        base + 10000000ULL);
    detector.Enrich(proc);
    engine.OnEvent(proc);
    WP_CHECK(Has(hits, "EDR-303"));
}

} // namespace

void RunWmiPersistenceDetectorTests() {
    TestSingleSubscriptionTriggers();
    TestMultipleSubscriptionsMalicious();
    TestNoSubscriptionNoStamp();
    TestExpiredSubscriptionResets();
    TestCommandLineTokenMatches();
    TestProductionRule();
}
