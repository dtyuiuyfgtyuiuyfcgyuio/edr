/*
 * rdp_parser_tests.cpp - Unit tests for ParseRdpXml and RDP rules.
 */
#include "rdp_parser_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "rdp_parser.h"
#include "rule_engine.h"

namespace {

#define RDP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "rdp parser test failed at line " + std::to_string(line) +
            ": " + expression);
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

std::wstring SessionXml(unsigned int id, const wchar_t* data) {
    return L"<Event><System><Provider Name='Microsoft-Windows-"
           L"TerminalServices-LocalSessionManager'/><EventID>" +
           std::to_wstring(id) +
           L"</EventID><Execution ProcessID='884'/><TimeCreated "
           L"SystemTime='2026-08-17T01:02:03.1234567Z'/></System>"
           L"<EventData>" +
           std::wstring(data) + L"</EventData></Event>";
}

void TestSessionLogon() {
    edr::Event event;
    RDP_CHECK(edr::ParseRdpXml(
        SessionXml(21,
                   L"<Data Name='User'>LAB\\analyst</Data>"
                   L"<Data Name='SessionID'>2</Data>"
                   L"<Data Name='Address'>192.0.2.10</Data>"),
        event));
    RDP_CHECK(event.type == EDR_EVT_RDP_SESSION);
    RDP_CHECK(event.source == "rdp_log");
    RDP_CHECK(event.pid == 884);
    RDP_CHECK(event.fields.at(edr::field::kType) == "RDP_SESSION");
    RDP_CHECK(event.fields.at(edr::field::kRdpAction) == "logon");
    RDP_CHECK(event.fields.at(edr::field::kRdpUser) == "analyst");
    RDP_CHECK(event.fields.at(edr::field::kRdpDomain) == "LAB");
    RDP_CHECK(event.fields.at(edr::field::kRdpSessionId) == "2");
    RDP_CHECK(event.fields.at(edr::field::kRdpSourceIp) == "192.0.2.10");
    RDP_CHECK(event.fields.at(edr::field::kTimestampProvenance) ==
              "rdp_system_time");
}

void TestReconnectAndAuth() {
    edr::Event reconnect;
    RDP_CHECK(edr::ParseRdpXml(
        SessionXml(25, L"<Data Name='User'>admin</Data>"
                       L"<Data Name='SessionID'>3</Data>"),
        reconnect));
    RDP_CHECK(reconnect.fields.at(edr::field::kRdpAction) == "reconnect");
    RDP_CHECK(reconnect.fields.at(edr::field::kRdpUser) == "admin");

    const std::wstring auth =
        L"<Event><System><EventID>1149</EventID>"
        L"<TimeCreated SystemTime='2026-08-17T01:02:03.1234567Z'/>"
        L"</System><UserData><EventXML>"
        L"<Param1>alice</Param1><Param2>CORP</Param2>"
        L"<Param3>198.51.100.20</Param3>"
        L"</EventXML></UserData></Event>";
    edr::Event event;
    RDP_CHECK(edr::ParseRdpXml(auth, event));
    RDP_CHECK(event.fields.at(edr::field::kRdpAction) == "auth_success");
    RDP_CHECK(event.fields.at(edr::field::kRdpUser) == "alice");
    RDP_CHECK(event.fields.at(edr::field::kRdpDomain) == "CORP");
    RDP_CHECK(event.fields.at(edr::field::kRdpSourceIp) == "198.51.100.20");
}

void TestUnknownEventRejected() {
    edr::Event event;
    RDP_CHECK(!edr::ParseRdpXml(SessionXml(99, L""), event));
}

void TestProductionRules() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::Event logon;
    logon.type = EDR_EVT_RDP_SESSION;
    logon.fields[edr::field::kType] = "RDP_SESSION";
    logon.fields[edr::field::kRdpAction] = "logon";
    engine.OnEvent(logon);
    RDP_CHECK(std::find(hits.begin(), hits.end(), "EDR-258") != hits.end());

    hits.clear();
    edr::Event reconnect;
    reconnect.type = EDR_EVT_RDP_SESSION;
    reconnect.fields[edr::field::kType] = "RDP_SESSION";
    reconnect.fields[edr::field::kRdpAction] = "reconnect";
    engine.OnEvent(reconnect);
    RDP_CHECK(std::find(hits.begin(), hits.end(), "EDR-259") != hits.end());
}

} // namespace

void RunRdpParserTests() {
    TestSessionLogon();
    TestReconnectAndAuth();
    TestUnknownEventRejected();
    TestProductionRules();
}
