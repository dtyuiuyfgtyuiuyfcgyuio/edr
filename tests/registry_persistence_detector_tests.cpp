/*
 * registry_persistence_detector_tests.cpp - Unit tests for
 * RegistryPersistenceDetector and the production rule it feeds.
 */
#include "registry_persistence_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "registry_persistence_detector.h"
#include "rule_engine.h"

namespace {

#define RP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "registry persistence detector test failed at line " +
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

edr::Event RegWrite(const std::string& key, const std::string& value,
                    uint32_t pid, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    event.fields[edr::field::kRegValue] = value;
    return event;
}

void TestSingleRunKeyNoVerdict() {
    edr::RegistryPersistenceDetector detector(true, 300, 2048);
    const uint64_t base = 1000000000ULL;
    edr::Event ev = RegWrite(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater",
        "C:\\Program Files\\Vendor\\updater.exe", 5001, base);
    detector.Enrich(ev);
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceScore) == "40");
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceCount) == "1");
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceMechanisms) ==
             "run_key");
    RP_CHECK(ev.fields.find(edr::field::kRegistryPersistenceVerdict) ==
             ev.fields.end());
}

void TestTwoMechanismsSuspicious() {
    edr::RegistryPersistenceDetector detector(true, 300, 2048);
    const uint64_t base = 2000000000ULL;
    detector.Enrich(RegWrite(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
        "C:\\Temp\\evil.exe", 5002, base));
    edr::Event ev = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil",
        "C:\\Windows\\System32\\evilsvc.exe", 5002,
        base + 10000000ULL);
    detector.Enrich(ev);
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceScore) == "55");
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceVerdict) ==
             "SUSPICIOUS");
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceCount) == "2");
}

void TestSuspiciousServicePath() {
    edr::RegistryPersistenceDetector detector(true, 300, 2048);
    const uint64_t base = 3000000000ULL;
    /* Service whose ImagePath is powershell.exe from ProgramData is both a
     * service registration and a suspicious_service_path mechanism. */
    edr::Event ev = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\malware",
        "powershell.exe -enc AAA==", 5003, base);
    detector.Enrich(ev);
    const std::string mechanisms =
        ev.fields.at(edr::field::kRegistryPersistenceMechanisms);
    RP_CHECK(mechanisms.find("service_registration") != std::string::npos);
    RP_CHECK(mechanisms.find("suspicious_service_path") != std::string::npos);
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceScore) == "55");
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceVerdict) ==
             "SUSPICIOUS");
}

void TestRepeatedWritesSuspicious() {
    edr::RegistryPersistenceDetector detector(true, 300, 2048);
    const uint64_t base = 4000000000ULL;
    edr::Event ev;
    for (int i = 0; i < 5; ++i) {
        ev = RegWrite(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\persist",
            "C:\\Users\\x\\Downloads\\a.exe", 5004,
            base + i * 10000000ULL);
        detector.Enrich(ev);
    }
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceScore) == "60");
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceCount) == "5");
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceVerdict) ==
             "SUSPICIOUS");
}

void TestIfeoDebugger() {
    edr::RegistryPersistenceDetector detector(true, 300, 2048);
    const uint64_t base = 5000000000ULL;
    edr::Event ev = RegWrite(
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
        "Execution Options\\svchost.exe\\Debugger",
        "C:\\Windows\\Temp\\evil.exe", 5005, base);
    detector.Enrich(ev);
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceScore) == "40");
    RP_CHECK(ev.fields.at(edr::field::kRegistryPersistenceMechanisms) ==
             "ifeo_debugger");
}

void TestNonPersistenceKeyNoStamp() {
    edr::RegistryPersistenceDetector detector(true, 300, 2048);
    const uint64_t base = 6000000000ULL;
    edr::Event ev = RegWrite(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell "
        "Folders",
        "C:\\Users\\x", 5006, base);
    detector.Enrich(ev);
    RP_CHECK(ev.fields.find(edr::field::kRegistryPersistenceScore) ==
             ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::RegistryPersistenceDetector detector(false, 300, 2048);
    const uint64_t base = 7000000000ULL;
    edr::Event ev = RegWrite(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x",
        "C:\\Temp\\x.exe", 5007, base);
    detector.Enrich(ev);
    RP_CHECK(ev.fields.find(edr::field::kRegistryPersistenceScore) ==
             ev.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::RegistryPersistenceDetector detector(true, 300, 2048);
    const uint64_t base = 8000000000ULL;
    detector.Enrich(RegWrite(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\a",
        "C:\\Temp\\a.exe", 5008, base));
    edr::Event ev = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\b",
        "C:\\Temp\\b.exe", 5008, base + 10000000ULL);
    detector.Enrich(ev);
    engine.OnEvent(ev);
    RP_CHECK(Has(hits, "EDR-331"));
}

} // namespace

void RunRegistryPersistenceDetectorTests() {
    TestSingleRunKeyNoVerdict();
    TestTwoMechanismsSuspicious();
    TestSuspiciousServicePath();
    TestRepeatedWritesSuspicious();
    TestIfeoDebugger();
    TestNonPersistenceKeyNoStamp();
    TestDisabledNoStamp();
    TestProductionRule();
}
