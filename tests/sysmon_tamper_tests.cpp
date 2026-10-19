#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <windows.h>
#include <winevt.h>

#include "edr_event.h"
#include "process_tree_builder.h"
#include "rule_engine.h"
#include "sysmon_parser.h"

namespace {

using namespace edr;

#define CHECK(expression) do { \
    if (!(expression)) { \
        std::fprintf(stderr, "check failed at line %d: %s\n", __LINE__, \
                     #expression); \
        ++g_failures; \
    } \
} while (0)

int g_failures = 0;

std::wstring TamperXml(const wchar_t* processId = L"4242",
                       const wchar_t* image = L"C:\\Temp\\sample.exe",
                       const wchar_t* type = L"Image is replaced",
                       const wchar_t* processGuid =
                           L"{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}") {
    std::wstring xml =
        L"<Event><System><EventID Version='5'>25</EventID>"
        L"<Execution ProcessID='4'/>"
        L"<TimeCreated SystemTime='2026-10-19T03:04:05.1234567Z'/>"
        L"</System><EventData><Data Name='RuleName'>rule-tamper</Data>"
        L"<Data Name='ProcessGuid'>" + std::wstring(processGuid) +
        L"</Data><Data Name='ProcessId'>" + processId +
        L"</Data><Data Name='Image'>" + image +
        L"</Data><Data Name='Type'>" + type +
        L"</Data><Data Name='User'>NT AUTHORITY\\SYSTEM</Data>"
        L"</EventData></Event>";
    return xml;
}

bool ParseTamper(const std::wstring& xml, Event& event) {
    return ParseSysmonXml(xml, event);
}

bool HasAlert(RuleEngine& engine, const Event& event) {
    bool matched = false;
    engine.SetAlertCallback([&](const Alert& alert) {
        if (alert.ruleId == "EDR-524") matched = true;
    });
    engine.OnEvent(event);
    engine.SetAlertCallback({});
    return matched;
}

void TestEvent25MapsToDistinctTamperingEvent() {
    Event event;
    const bool parsed = ParseTamper(TamperXml(), event);
    CHECK(parsed);
    if (!parsed) return;
    CHECK(event.type == EDR_EVT_PROCESS_TAMPERING);
    CHECK(event.type != EDR_EVT_PROCESS_START);
    CHECK(event.type != EDR_EVT_PROCESS_ACCESS);
    CHECK(event.fields.at(field::kType) == "PROCESS_TAMPERING");
    CHECK(event.pid == 4242);
    CHECK(event.fields.at(field::kPid) == "4242");
    CHECK(event.fields.at(field::kImage) == "C:\\Temp\\sample.exe");
    CHECK(event.fields.at(field::kActorImage) == "C:\\Temp\\sample.exe");
    CHECK(event.fields.at(field::kProcessTamperingType) == "Image is replaced");
    CHECK(event.processIdentity == "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}");
    CHECK(event.source == "sysmon");
    CHECK(event.fields.at(field::kSource) == "sysmon");
    CHECK(event.fields.at(field::kSysmonEventId) == "25");
    CHECK(event.fields.at(field::kSysmonRuleName) == "rule-tamper");
    CHECK(event.fields.at(field::kUserId) == "NT AUTHORITY\\SYSTEM");
    CHECK(event.fields.at(field::kSourceTimestamp) ==
          "2026-10-19T03:04:05.1234567Z");
    CHECK(event.ts100ns != 0);
    CHECK(event.processStartTime100ns == 0);
}

void TestEvent25RejectsInvalidPidAndMissingRequiredFields() {
    Event event;
    const bool maxPidParsed = ParseTamper(TamperXml(L"4294967295"), event);
    CHECK(maxPidParsed);
    if (maxPidParsed) CHECK(event.pid == 4294967295u);
    CHECK(!ParseTamper(TamperXml(L"0"), event));
    CHECK(!ParseTamper(TamperXml(L"4294967296"), event));
    CHECK(!ParseTamper(TamperXml(L"42x"), event));
    CHECK(!ParseTamper(TamperXml(L"-1"), event));
    CHECK(!ParseTamper(TamperXml(L""), event));
    CHECK(!ParseTamper(TamperXml(L"42", L""), event));
    CHECK(!ParseTamper(TamperXml(L"42", L"C:\\Temp\\sample.exe", L""), event));
}

void TestUnknownTamperingTypeIsPreservedVerbatim() {
    Event event;
    const bool parsed = ParseTamper(TamperXml(L"77", L"C:\\Temp\\future.exe",
                                               L"future-sysmon-type-v99"), event);
    CHECK(parsed);
    if (!parsed) return;
    CHECK(event.fields.at(field::kProcessTamperingType) ==
          "future-sysmon-type-v99");

    Event missingGuid;
    const bool parsedWithoutGuid = ParseTamper(
        TamperXml(L"77", L"C:\\Temp\\future.exe", L"future-sysmon-type-v99", L""),
        missingGuid);
    CHECK(parsedWithoutGuid);
    if (parsedWithoutGuid) CHECK(missingGuid.processIdentity.empty());
}

void TestTamperingDoesNotRewriteProcessAncestry() {
    ProcessTreeBuilder tree;
    Event start;
    start.type = EDR_EVT_PROCESS_START;
    start.pid = 4242;
    start.ppid = 1000;
    start.fields[field::kImage] = "C:\\Temp\\original.exe";
    tree.Observe(start);
    CHECK(tree.GetAncestors(4242) == std::vector<uint32_t>{1000});
    Event tamper;
    CHECK(ParseTamper(TamperXml(), tamper));
    tree.Observe(tamper);
    CHECK(tree.GetAncestors(4242) == std::vector<uint32_t>{1000});
    CHECK(tree.GetProcessTreeJson(4242).find("original.exe") != std::string::npos);
    tamper.pid = 9999;
    tree.Observe(tamper);
    CHECK(!tree.HasProcess(9999));
    start.ppid = 2000;
    tree.Observe(start);
    CHECK(tree.GetAncestors(4242) == std::vector<uint32_t>{2000});
}

void TestExistingProcessCreateMappingIsUnchanged() {
    const std::wstring xml =
        L"<Event><System><EventID Version='5'>1</EventID>"
        L"<TimeCreated SystemTime='2026-10-19T03:04:05.1234567Z'/>"
        L"</System><EventData><Data Name='ProcessGuid'>{CREATE-GUID}</Data>"
        L"<Data Name='ProcessId'>51</Data><Data Name='Image'>C:\\create.exe</Data>"
        L"<Data Name='UtcTime'>2026-10-19 03:04:05.1234567</Data>"
        L"</EventData></Event>";
    Event event;
    CHECK(ParseSysmonXml(xml, event));
    CHECK(event.type == EDR_EVT_PROCESS_START);
    CHECK(event.pid == 51);
    CHECK(event.processIdentity == "{CREATE-GUID}");
    CHECK(event.processStartTime100ns != 0);
}

bool ContainsEventId(const std::wstring& query, unsigned int id) {
    const std::wstring token = L"EventID=" + std::to_wstring(id);
    size_t position = query.find(token);
    while (position != std::wstring::npos) {
        const size_t end = position + token.size();
        if (end == query.size() || query.compare(end, 4, L" or ") == 0 ||
            query[end] == L')') return true;
        position = query.find(token, end);
    }
    return false;
}

void TestSubscriptionQueryKeepsOptionalIdsAndAlwaysIncludesEvent25() {
    for (unsigned int mask = 0; mask < 16; ++mask) {
        const bool imageLoad = (mask & 1) != 0;
        const bool processAccess = (mask & 2) != 0;
        const bool remoteThread = (mask & 4) != 0;
        const bool namedPipe = (mask & 8) != 0;
        const std::wstring query = SysmonSubscriptionQuery(
            imageLoad, processAccess, remoteThread, namedPipe);
        for (unsigned int id : {1u, 2u, 3u, 5u, 6u, 11u, 12u, 13u, 14u, 22u, 25u})
            CHECK(ContainsEventId(query, id));
        CHECK(ContainsEventId(query, 7u) == imageLoad);
        CHECK(ContainsEventId(query, 10u) == processAccess);
        CHECK(ContainsEventId(query, 8u) == remoteThread);
        CHECK(ContainsEventId(query, 17u) == namedPipe);
        CHECK(ContainsEventId(query, 18u) == namedPipe);

        EVT_HANDLE result = EvtQuery(nullptr,
            L"Application", query.c_str(),
            EvtQueryChannelPath);
        if (result != nullptr) {
            EvtClose(result);
        } else {
            CHECK(result != nullptr);
        }
    }
}

void TestProductionRuleRequiresEveryTamperingGate(const char* rulesPath) {
    RuleEngine engine;
    engine.LoadFromFile(rulesPath);
    Event event;
    CHECK(ParseTamper(TamperXml(), event));

    bool matched = false;
    bool highSeverity = false;
    bool mappedTechnique = false;
    engine.SetAlertCallback([&](const Alert& alert) {
        if (alert.ruleId != "EDR-524") return;
        matched = true;
        highSeverity = alert.severity == "high";
        for (const auto& technique : alert.mitreAttack)
            mappedTechnique = mappedTechnique || technique == "T1055.012";
    });
    engine.OnEvent(event);
    CHECK(matched);
    CHECK(highSeverity);
    CHECK(mappedTechnique);
    engine.SetAlertCallback({});

    Event wrongSource = event;
    wrongSource.source = "other";
    wrongSource.fields[field::kSource] = "other";
    CHECK(!HasAlert(engine, wrongSource));

    Event wrongId = event;
    wrongId.fields[field::kSysmonEventId] = "24";
    CHECK(!HasAlert(engine, wrongId));

    Event wrongType = event;
    wrongType.fields[field::kType] = "PROCESS_START";
    CHECK(!HasAlert(engine, wrongType));

    Event emptyRawType = event;
    emptyRawType.fields[field::kProcessTamperingType].clear();
    CHECK(!HasAlert(engine, emptyRawType));

    Event emptyImage = event;
    emptyImage.fields[field::kImage].clear();
    CHECK(!HasAlert(engine, emptyImage));

    Event emptyPid = event;
    emptyPid.fields[field::kPid].clear();
    CHECK(!HasAlert(engine, emptyPid));

    Event processStart;
    CHECK(ParseSysmonXml(
        L"<Event><System><EventID>1</EventID></System><EventData>"
        L"<Data Name='ProcessId'>51</Data><Data Name='Image'>C:\\create.exe</Data>"
        L"</EventData></Event>", processStart));
    CHECK(!HasAlert(engine, processStart));
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: edr_sysmon_tamper_tests <rules.json>\n");
        return 2;
    }
    TestEvent25MapsToDistinctTamperingEvent();
    TestEvent25RejectsInvalidPidAndMissingRequiredFields();
    TestUnknownTamperingTypeIsPreservedVerbatim();
    TestTamperingDoesNotRewriteProcessAncestry();
    TestExistingProcessCreateMappingIsUnchanged();
    TestSubscriptionQueryKeepsOptionalIdsAndAlwaysIncludesEvent25();
    TestProductionRuleRequiresEveryTamperingGate(argv[1]);
    if (g_failures != 0) {
        std::fprintf(stderr, "%d Sysmon tampering check(s) failed\n", g_failures);
        return 1;
    }
    std::puts("Sysmon Event 25 tests passed");
    return 0;
}
