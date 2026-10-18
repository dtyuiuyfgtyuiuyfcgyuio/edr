#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "config.h"
#include "defender_parser.h"
#include "edr_event.h"
#include "rule_engine.h"

using namespace edr;

namespace {

int g_failures = 0;

#define CHECK(expression) do { \
    if (!(expression)) { \
        std::cerr << "check failed at line " << __LINE__ << ": " \
                  << #expression << "\n"; \
        ++g_failures; \
    } \
} while (0)

std::wstring DefenderXml(unsigned int id, const wchar_t* data,
    const wchar_t* timestamp = L"2026-08-05T01:02:03.1234567Z") {
    return L"<Event><System><EventID>" + std::to_wstring(id) +
        L"</EventID><Execution ProcessID='4321'/><TimeCreated SystemTime='" +
        timestamp + L"'/></System><EventData>" + data +
        L"</EventData></Event>";
}

Event Parse(const std::wstring& xml) {
    Event event;
    CHECK(ParseDefenderXml(xml, event));
    return event;
}

void TestMalwareDetected() {
    Event event = Parse(DefenderXml(1116,
        L"<Data Name='Threat ID'>2147720990</Data>"
        L"<Data Name='Threat Name'>Trojan:Win32/Test&amp;Sample</Data>"
        L"<Data Name='Severity Name'>Severe</Data>"
        L"<Data Name='Category Name'>Trojan</Data>"
        L"<Data Name='Path'>file:_C:\\Temp\\payload.exe</Data>"
        L"<Data Name='Detection User'>LAB\\analyst</Data>"
        L"<Data Name='Process Name'>C:\\Temp\\payload.exe</Data>"));
    CHECK(event.type == EDR_EVT_DEFENDER);
    CHECK(event.source == "defender_log");
    CHECK(event.pid == 4321);
    CHECK(event.fields.at(field::kType) == "DEFENDER");
    CHECK(event.fields.at(field::kOperationType) == "MALWARE_DETECTED");
    CHECK(event.fields.at(field::kThreatName) ==
          "Trojan:Win32/Test&Sample");
    CHECK(event.fields.at(field::kThreatSeverity) == "Severe");
    CHECK(event.fields.at(field::kDetectionPath) ==
          "file:_C:\\Temp\\payload.exe");
    CHECK(event.fields.at(field::kTimestampProvenance) ==
          "defender_system_time");
    CHECK(event.ts100ns != 0);
}

void TestActionAndConfigurationEvents() {
    Event action = Parse(DefenderXml(1117,
        L"<Data Name='ThreatName'>Virus:Win32/Test</Data>"
        L"<Data Name='ActionName'>Quarantine</Data>"
        L"<Data Name='StatusDescription'>The operation completed successfully.</Data>"));
    CHECK(action.fields.at(field::kOperationType) == "ACTION_TAKEN");
    CHECK(action.fields.at(field::kDefenderAction) == "Quarantine");

    Event disabled = Parse(DefenderXml(5001, L""));
    CHECK(disabled.fields.at(field::kOperationType) ==
          "REALTIME_PROTECTION_DISABLED");

    Event changed = Parse(DefenderXml(5007,
        L"<Data Name='Old Value'>DisableRealtimeMonitoring = 0x0</Data>"
        L"<Data Name='New Value'>DisableRealtimeMonitoring = 0x1</Data>"));
    CHECK(changed.fields.at(field::kOperationType) == "CONFIG_CHANGED");
    CHECK(changed.fields.at(field::kDefenderNewValue) ==
          "DisableRealtimeMonitoring = 0x1");
}

void TestInvalidAndFallback() {
    Event event;
    CHECK(!ParseDefenderXml(DefenderXml(1000, L""), event));
    CHECK(!ParseDefenderXml(
        L"<Event><System><EventID>abc</EventID></System></Event>", event));
    Event fallback = Parse(DefenderXml(5001, L"", L"invalid"));
    CHECK(fallback.ts100ns != 0);
    CHECK(fallback.fields.at(field::kTimestampProvenance) ==
          "collector_time_fallback");
}

void WriteConfig(const char* json) {
    std::ofstream output("edr-defender-test-config.json", std::ios::binary);
    output << json;
}

void TestProductionRules() {
    RuleEngine engine;
    try {
        engine.LoadFromFile("..\\rules\\rules.json");
    } catch (const std::exception& error) {
        std::cerr << "production rule load failed: " << error.what() << "\n";
        ++g_failures;
        return;
    }
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) {
        hits.push_back(alert.ruleId);
    });
    auto matched = [&](const Event& event, const char* ruleId) {
        hits.clear();
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), ruleId) != hits.end();
    };

    Event detected;
    detected.type = EDR_EVT_DEFENDER;
    detected.fields[field::kType] = "DEFENDER";
    detected.fields[field::kOperationType] = "MALWARE_DETECTED";
    CHECK(matched(detected, "EDR-106"));

    Event disabled = detected;
    disabled.fields[field::kOperationType] =
        "REALTIME_PROTECTION_DISABLED";
    CHECK(matched(disabled, "EDR-107"));

    Event changed = detected;
    changed.fields[field::kOperationType] = "CONFIG_CHANGED";
    changed.fields[field::kDefenderNewValue] =
        "DisableBehaviorMonitoring = 0x1";
    CHECK(matched(changed, "EDR-108"));

    Event action = detected;
    action.fields[field::kOperationType] = "ACTION_TAKEN";
    action.fields[field::kDefenderStatus] =
        "The operation completed successfully.";
    CHECK(!matched(action, "EDR-109"));
    action.fields[field::kDefenderStatus] = "Remediation failed";
    CHECK(matched(action, "EDR-109"));
}

void TestConfig() {
    Config defaults;
    CHECK(!defaults.enableDefenderLog);
    CHECK(defaults.defenderQueueCapacity == 512);
    CHECK(defaults.defenderWorkers == 2);
    CHECK(defaults.defenderMaxXmlBytes == 256 * 1024);

    std::string error;
    WriteConfig(R"({"enable_defender_log":true,"defender_queue_capacity":64,"defender_workers":8,"defender_max_xml_bytes":4096})");
    Config valid;
    CHECK(LoadConfigFile("edr-defender-test-config.json", valid, error));
    CHECK(valid.enableDefenderLog && valid.defenderQueueCapacity == 64);
    CHECK(valid.defenderWorkers == 8 && valid.defenderMaxXmlBytes == 4096);

    for (const char* json : {
        R"({"enable_defender_log":"true"})",
        R"({"defender_queue_capacity":63})",
        R"({"defender_queue_capacity":8193})",
        R"({"defender_workers":0})",
        R"({"defender_workers":9})",
        R"({"defender_max_xml_bytes":4095})",
        R"({"defender_max_xml_bytes":524289})",
        R"({"enable_defender_log":true,"enable_defender_log":false})"}) {
        WriteConfig(json);
        Config unchanged;
        unchanged.defenderWorkers = 7;
        CHECK(!LoadConfigFile(
            "edr-defender-test-config.json", unchanged, error));
        CHECK(!unchanged.enableDefenderLog && unchanged.defenderWorkers == 7);
    }
    DeleteFileA("edr-defender-test-config.json");
}

} // namespace

int main() {
    TestMalwareDetected();
    TestActionAndConfigurationEvents();
    TestInvalidAndFallback();
    TestConfig();
    TestProductionRules();
    if (g_failures != 0) return 1;
    std::cout << "Defender parser tests passed\n";
    return 0;
}

