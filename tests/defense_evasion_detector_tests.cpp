/*
 * defense_evasion_detector_tests.cpp - Unit tests for DefenseEvasionDetector.
 */
#include "defense_evasion_detector_tests.h"

#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>

#include "config.h"
#include "defense_evasion_detector.h"
#include "edr_event.h"
#include "event_bus.h"

using namespace edr;

namespace {

#define DV_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "defense evasion detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(const std::string& image,
                        const std::string& commandLine,
                        uint64_t ts100ns, uint32_t pid = 100) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event EtwTamper(const std::string& type, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_ETW_TAMPER;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "ETW_TAMPER";
    event.fields[edr::field::kEtwTamperType] = type;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

void TestClassifier() {
    DV_CHECK(ClassifyDefenseEvasionEvent(
        ProcessStart("C:\\Windows\\System32\\sc.exe",
                     "sc stop WinDefend", 1000)) ==
        "security_service_tamper");
    DV_CHECK(ClassifyDefenseEvasionEvent(
        ProcessStart("C:\\Windows\\System32\\wevtutil.exe",
                     "wevtutil cl System", 1000)) ==
        "audit_log_tamper");
    DV_CHECK(ClassifyDefenseEvasionEvent(
        ProcessStart("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                     "Set-MpPreference -DisableRealtimeMonitoring $true",
                     1000)) == "defender_disable");
    DV_CHECK(ClassifyDefenseEvasionEvent(
        EtwTamper("etw_event_write_patched", 1000)) == "etw_patch");
    DV_CHECK(ClassifyDefenseEvasionEvent(
        ProcessStart("C:\\Windows\\System32\\notepad.exe",
                     "notepad C:\\temp\\x.txt", 1000)).empty());
}

void TestCorrelation() {
    edr::DefenseEvasionDetector detector(true, 300, 1024, 2, 600);
    const uint64_t base = 100000000000ULL;

    edr::Event first = ProcessStart(
        "C:\\Windows\\System32\\sc.exe", "sc stop WinDefend",
        base + 10000000ULL);
    detector.Enrich(first);
    DV_CHECK(!HasField(first, edr::field::kDefenseEvasionScore));

    edr::Event second = ProcessStart(
        "C:\\Windows\\System32\\wevtutil.exe", "wevtutil cl System",
        base + 20000000ULL);
    detector.Enrich(second);
    DV_CHECK(HasField(second, edr::field::kDefenseEvasionScore));
    DV_CHECK(second.fields.at(edr::field::kDefenseEvasionCount) == "2");
    DV_CHECK(second.fields.at(edr::field::kDefenseEvasionVerdict) ==
             "multi_stage_defense_evasion");

    edr::Event duplicate = ProcessStart(
        "C:\\Windows\\System32\\sc.exe", "net stop WinDefend",
        base + 30000000ULL);
    detector.Enrich(duplicate);
    DV_CHECK(!HasField(duplicate, edr::field::kDefenseEvasionScore));
}

void TestInspectionsAndDisabled() {
    DV_CHECK(edr::DefenseEvasionDetector::Inspects(EDR_EVT_PROCESS_START));
    DV_CHECK(edr::DefenseEvasionDetector::Inspects(EDR_EVT_ETW_TAMPER));
    DV_CHECK(!edr::DefenseEvasionDetector::Inspects(EDR_EVT_FILE_CREATE));

    edr::DefenseEvasionDetector disabled(false, 300, 1024, 2, 600);
    edr::Event event = ProcessStart(
        "C:\\Windows\\System32\\sc.exe", "sc stop WinDefend", 1000);
    disabled.Enrich(event);
    DV_CHECK(!HasField(event, edr::field::kDefenseEvasionScore));
    DV_CHECK(disabled.StateCount() == 0);
}

void TestConfigStrictAtomic() {
    const char* path = "edr-native-defense-evasion-config.json";
    std::ofstream out(path, std::ios::binary);
    out << R"({"defense_evasion":{"enable":true,"window_seconds":180,"state_capacity":512,"min_techniques":3,"dedup_seconds":120}})";
    out.close();

    std::string error;
    edr::Config config;
    DV_CHECK(edr::LoadConfigFile(path, config, error));
    DV_CHECK(config.defenseEvasionEnable);
    DV_CHECK(config.defenseEvasionWindowSeconds == 180);
    DV_CHECK(config.defenseEvasionStateCapacity == 512);
    DV_CHECK(config.defenseEvasionMinTechniques == 3);
    DV_CHECK(config.defenseEvasionDedupSeconds == 120);

    std::ofstream bad(path, std::ios::binary);
    bad << R"({"defense_evasion":{"enable":true,"bogus":1}})";
    bad.close();
    edr::Config unchanged;
    DV_CHECK(!edr::LoadConfigFile(path, unchanged, error));
    DV_CHECK(!unchanged.defenseEvasionEnable);

    std::remove(path);
}

} // namespace

void RunDefenseEvasionDetectorTests() {
    TestClassifier();
    TestCorrelation();
    TestInspectionsAndDisabled();
    TestConfigStrictAtomic();
}
