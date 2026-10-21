#include <windows.h>
#include <winevt.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "defender_parser.h"
#include "edr_event.h"
#include "rule_engine.h"

namespace {
using namespace edr;
int failures = 0;

#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "CFA check failed at line %d: %s\n", __LINE__, \
                 #condition); ++failures; } } while (0)

struct CfaCase {
    unsigned id;
    const char* operation;
    const char* rule;
    const char* severity;
    const char* action;
};

const CfaCase cases[] = {
    {1123, "CFA_BLOCKED", "EDR-525", "medium", "alert"},
    {1124, "CFA_AUDITED", "EDR-526", "low", "log"},
    {1127, "CFA_SECTOR_WRITE_BLOCKED", "EDR-527", "high", "alert"},
    {1128, "CFA_SECTOR_WRITE_AUDITED", "EDR-528", "low", "log"},
};

std::wstring Xml(unsigned id, const std::wstring& data) {
    return L"<Event><System><EventID>" + std::to_wstring(id) +
        L"</EventID><Execution ProcessID='4321'/>"
        L"<TimeCreated SystemTime='2026-10-19T03:04:05.1234567Z'/>"
        L"</System><EventData>" + data + L"</EventData></Event>";
}

const wchar_t* Data() {
    return L"<Data Name='ID'>detection&amp;identifier</Data>"
        L"<Data Name='User'>LAB\\analyst</Data>"
        L"<Data Name='Path'>C:\\Users\\analyst\\Documents\\one &amp; two.docx</Data>"
        L"<Data Name='Process Name'>C:\\Tools\\editor.exe</Data>";
}

std::string Field(const Event& event, const char* key) {
    const auto found = event.fields.find(key);
    return found == event.fields.end() ? std::string() : found->second;
}

void TestParserAndQuery() {
    const std::wstring query = DefenderSubscriptionQuery();
    for (const auto& test : cases) {
        Event event;
        const bool parsed = ParseDefenderXml(Xml(test.id, Data()), event);
        CHECK(parsed);
        CHECK(query.find(L"EventID=" + std::to_wstring(test.id)) !=
              std::wstring::npos);
        if (!parsed) continue;
        CHECK(event.type == EDR_EVT_DEFENDER);
        CHECK(event.source == "defender_log");
        CHECK(Field(event, field::kDefenderEventId) == std::to_string(test.id));
        CHECK(Field(event, field::kOperationType) == test.operation);
        CHECK(Field(event, field::kDetectionUser) == "LAB\\analyst");
        CHECK(Field(event, field::kDetectionPath) ==
              "C:\\Users\\analyst\\Documents\\one & two.docx");
        CHECK(Field(event, field::kProcessName) == "C:\\Tools\\editor.exe");
        CHECK(Field(event, field::kCfaDetectionId) == "detection&identifier");
        CHECK(Field(event, field::kAsrRuleId).empty());
        CHECK(Field(event, field::kDefenderProviderPid) == "4321");
        CHECK(event.pid == 0 && event.ppid == 0);
        CHECK(event.processStartTime100ns == 0 && event.processIdentity.empty());
        CHECK(Field(event, field::kPid).empty());
        CHECK(Field(event, field::kImage).empty());
        CHECK(Field(event, field::kUserSid).empty());
        CHECK(Field(event, field::kTimestampProvenance) == "defender_system_time");

        Event missing;
        CHECK(ParseDefenderXml(Xml(test.id, L""), missing));
        CHECK(Field(missing, field::kDetectionUser).empty());
        CHECK(Field(missing, field::kCfaDetectionId).empty());
    }
    EVT_HANDLE result = EvtQuery(nullptr, L"Application", query.c_str(),
                                EvtQueryChannelPath);
    CHECK(result != nullptr);
    if (result) EvtClose(result);
    Event unsupported;
    CHECK(!ParseDefenderXml(Xml(1125, Data()), unsupported));
    CHECK(!ParseDefenderXml(Xml(1126, Data()), unsupported));
}

void TestRules(const char* path) {
    RuleEngine engine;
    engine.LoadFromFile(path);
    std::vector<Alert> alerts;
    engine.SetAlertCallback([&](const Alert& alert) { alerts.push_back(alert); });
    auto hits = [&](const Event& event, const CfaCase& test) {
        alerts.clear();
        engine.OnEvent(event);
        return std::count_if(alerts.begin(), alerts.end(), [&](const Alert& alert) {
            return alert.ruleId == test.rule;
        });
    };
    for (const auto& test : cases) {
        Event event;
        if (!ParseDefenderXml(Xml(test.id, Data()), event)) continue;
        CHECK(hits(event, test) == 1);
        for (const auto& alert : alerts) {
            if (alert.ruleId != test.rule) continue;
            CHECK(alert.severity == test.severity);
            CHECK(alert.action == test.action);
            CHECK(alert.event != nullptr && alert.event->pid == 0);
        }
        for (const auto& other : cases) {
            if (other.id != test.id) CHECK(hits(event, other) == 0);
        }
        for (const char* key : {field::kType, field::kSource,
                field::kDefenderEventId, field::kOperationType,
                field::kDetectionPath, field::kProcessName}) {
            Event missing = event;
            missing.fields.erase(key);
            CHECK(hits(missing, test) == 0);
            Event wrong = event;
            wrong.fields[key] = (key == field::kDetectionPath ||
                                 key == field::kProcessName) ? " \t " : "wrong";
            CHECK(hits(wrong, test) == 0);
        }
    }
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    TestParserAndQuery();
    try {
        TestRules(argv[1]);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "CFA rule error: %s\n", error.what());
        return 1;
    }
    if (failures) return 1;
    std::puts("Defender CFA parser and production rule tests passed");
    return 0;
}
