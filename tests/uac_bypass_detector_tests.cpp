/*
 * uac_bypass_detector_tests.cpp - Unit tests for UacBypassDetector and the
 * production rule it feeds.
 */
#include "uac_bypass_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"
#include "uac_bypass_detector.h"

namespace {

#define UB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "uac bypass detector test failed at line " +
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

edr::Event RegWrite(const std::string& key, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    event.fields[edr::field::kRegValue] = "1";
    return event;
}

edr::Event ProcessStart(const std::string& image, const std::string& command,
                        uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kCommandLine] = command;
    return event;
}

void TestSingleKeyTriggersSuspicious() {
    edr::UacBypassDetector detector(true, 600, 1024, 1);
    const uint64_t base = 1000000000ULL;
    detector.Enrich(RegWrite(
        "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command", base));
    edr::Event proc = ProcessStart(
        "C:\\Windows\\System32\\fodhelper.exe", "fodhelper.exe",
        base + 10000000ULL);
    detector.Enrich(proc);
    UB_CHECK(proc.fields.at(edr::field::kUacBypassScore) == "55");
    UB_CHECK(proc.fields.at(edr::field::kUacBypassCount) == "1");
    UB_CHECK(proc.fields.at(edr::field::kUacBypassVerdict) == "SUSPICIOUS");
    UB_CHECK(proc.fields.at(edr::field::kUacBypassWindowSeconds) == "600");
}

void TestTwoKeysMalicious() {
    edr::UacBypassDetector detector(true, 600, 1024, 2);
    const uint64_t base = 2000000000ULL;
    detector.Enrich(RegWrite(
        "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command", base));
    detector.Enrich(RegWrite(
        "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command",
        base + 10000000ULL));
    edr::Event proc = ProcessStart(
        "C:\\Windows\\System32\\eventvwr.exe", "eventvwr.exe",
        base + 20000000ULL);
    detector.Enrich(proc);
    UB_CHECK(proc.fields.at(edr::field::kUacBypassScore) == "90");
    UB_CHECK(proc.fields.at(edr::field::kUacBypassCount) == "2");
    UB_CHECK(proc.fields.at(edr::field::kUacBypassVerdict) == "MALICIOUS");
    UB_CHECK(proc.fields.at(edr::field::kUacBypassKeys).find("ms-settings") !=
             std::string::npos);
    UB_CHECK(proc.fields.at(edr::field::kUacBypassKeys).find("mscfile") !=
             std::string::npos);
}

void TestNoBypassKeyNoStamp() {
    edr::UacBypassDetector detector(true, 600, 1024, 1);
    const uint64_t base = 3000000000ULL;
    detector.Enrich(RegWrite(
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil", base));
    edr::Event proc = ProcessStart(
        "C:\\Windows\\System32\\fodhelper.exe", "fodhelper.exe",
        base + 10000000ULL);
    detector.Enrich(proc);
    UB_CHECK(proc.fields.find(edr::field::kUacBypassScore) ==
             proc.fields.end());
}

void TestNonElevatedBinaryNoStamp() {
    edr::UacBypassDetector detector(true, 600, 1024, 1);
    const uint64_t base = 4000000000ULL;
    detector.Enrich(RegWrite(
        "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command", base));
    edr::Event proc = ProcessStart(
        "C:\\Windows\\System32\\notepad.exe", "notepad.exe",
        base + 10000000ULL);
    detector.Enrich(proc);
    UB_CHECK(proc.fields.find(edr::field::kUacBypassScore) ==
             proc.fields.end());
}

void TestWindowExpiryResets() {
    edr::UacBypassDetector detector(true, 1, 1024, 1);
    const uint64_t base = 5000000000ULL;
    detector.Enrich(RegWrite(
        "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command", base));
    edr::Event proc = ProcessStart(
        "C:\\Windows\\System32\\fodhelper.exe", "fodhelper.exe",
        base + 11000000ULL);
    detector.Enrich(proc);
    UB_CHECK(proc.fields.find(edr::field::kUacBypassScore) ==
             proc.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::UacBypassDetector detector(true, 600, 1024, 1);
    const uint64_t base = 6000000000ULL;
    detector.Enrich(RegWrite(
        "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command", base));
    edr::Event proc = ProcessStart(
        "C:\\Windows\\System32\\computerdefaults.exe",
        "computerdefaults.exe", base + 10000000ULL);
    detector.Enrich(proc);
    engine.OnEvent(proc);
    UB_CHECK(Has(hits, "EDR-302"));
}

} // namespace

void RunUacBypassDetectorTests() {
    TestSingleKeyTriggersSuspicious();
    TestTwoKeysMalicious();
    TestNoBypassKeyNoStamp();
    TestNonElevatedBinaryNoStamp();
    TestWindowExpiryResets();
    TestProductionRule();
}
