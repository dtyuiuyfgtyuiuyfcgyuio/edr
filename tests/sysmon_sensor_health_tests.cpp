#include <cstdio>
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

int g_failures = 0;

#define CHECK(expression) do { \
    if (!(expression)) { \
        std::fprintf(stderr, "check failed at line %d: %s\n", __LINE__, \
                     #expression); \
        ++g_failures; \
    } \
} while (0)

std::wstring EventXml(unsigned id, const std::wstring& data) {
    return L"<Event><System><Provider Name='Microsoft-Windows-Sysmon'/>"
        L"<EventID Version='4'>" + std::to_wstring(id) +
        L"</EventID><Execution ProcessID='4' ThreadID='16'/>"
        L"<TimeCreated SystemTime='2026-10-20T10:11:12.1234567Z'/>"
        L"<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        L"</System><EventData>" + data + L"</EventData></Event>";
}

std::wstring Field(const wchar_t* name, const wchar_t* value) {
    return std::wstring(L"<Data Name='") + name + L"'>" + value +
        L"</Data>";
}

std::wstring SensorData() {
    // These tempting values are decoys: EIDs 4/16/255 are provider events,
    // not process observations, so they must never become process identity.
    return Field(L"ProcessId", L"9876") +
        Field(L"Image", L"C:\\Temp\\provider.exe") +
        Field(L"ProcessGuid", L"{11111111-2222-3333-4444-555555555555}");
}

bool HasField(const Event& event, const char* name, const char* expected) {
    const auto found = event.fields.find(name);
    return found != event.fields.end() && found->second == expected;
}

void CheckNoProcessIdentity(const Event& event) {
    CHECK(event.pid == 0);
    CHECK(event.ppid == 0);
    CHECK(event.processStartTime100ns == 0);
    CHECK(event.processIdentity.empty());
    CHECK(event.parentProcessIdentity.empty());
    CHECK(event.fields.count(field::kPid) == 0);
    CHECK(event.fields.count(field::kPpid) == 0);
    CHECK(event.fields.count(field::kImage) == 0);
    CHECK(event.fields.count("process_guid") == 0);
}

void TestEvent4ServiceStateAndOptionalFields() {
    Event event;
    const bool parsed = ParseSysmonXml(
        EventXml(4, Field(L"State", L"Stopped") +
            Field(L"Version", L"15.0") + Field(L"SchemaVersion", L"4.90") +
            SensorData()), event);
    CHECK(parsed);
    if (!parsed) return;
    CHECK(event.type == EDR_EVT_AUDIT_LOG);
    CHECK(HasField(event, field::kType, "AUDIT_LOG"));
    CHECK(event.source == "sysmon");
    CHECK(HasField(event, field::kSource, "sysmon"));
    CHECK(HasField(event, field::kSysmonEventId, "4"));
    CHECK(HasField(event, field::kOperationType,
                   "SYSMON_SERVICE_STATE_CHANGED"));
    CHECK(HasField(event, "sysmon_service_state", "Stopped"));
    CHECK(HasField(event, "sysmon_service_version", "15.0"));
    CHECK(HasField(event, "sysmon_schema_version", "4.90"));
    CHECK(event.fields.count(field::kAuditLogEventId) == 0);
    CheckNoProcessIdentity(event);

    Event sparse;
    const bool sparseParsed = ParseSysmonXml(EventXml(4, L""), sparse);
    CHECK(sparseParsed);
    if (sparseParsed) {
        CHECK(HasField(sparse, field::kOperationType,
                       "SYSMON_SERVICE_STATE_CHANGED"));
        CHECK(sparse.fields.count("sysmon_service_state") == 0);
        CHECK(sparse.fields.count("sysmon_service_version") == 0);
        CHECK(sparse.fields.count("sysmon_schema_version") == 0);
        CheckNoProcessIdentity(sparse);
    }
}

void TestEvent16ConfigurationChangeAndOptionalFields() {
    Event event;
    const bool parsed = ParseSysmonXml(
        EventXml(16, Field(L"Configuration",
            L"&lt;Sysmon schemaversion='4.90' /&gt;") +
            Field(L"ConfigurationFileHash", L"SHA256=0123456789abcdef") +
            SensorData()), event);
    CHECK(parsed);
    if (!parsed) return;
    CHECK(event.type == EDR_EVT_AUDIT_LOG);
    CHECK(HasField(event, field::kType, "AUDIT_LOG"));
    CHECK(event.source == "sysmon");
    CHECK(HasField(event, field::kSource, "sysmon"));
    CHECK(HasField(event, field::kSysmonEventId, "16"));
    CHECK(HasField(event, field::kOperationType, "SYSMON_CONFIG_CHANGED"));
    CHECK(HasField(event, "sysmon_configuration",
                   "<Sysmon schemaversion='4.90' />"));
    CHECK(HasField(event, "sysmon_configuration_file_hash",
                   "SHA256=0123456789abcdef"));
    CHECK(event.fields.count(field::kAuditLogEventId) == 0);
    CheckNoProcessIdentity(event);

    Event sparse;
    const bool sparseParsed = ParseSysmonXml(EventXml(16, L""), sparse);
    CHECK(sparseParsed);
    if (sparseParsed) {
        CHECK(HasField(sparse, field::kOperationType,
                       "SYSMON_CONFIG_CHANGED"));
        CHECK(sparse.fields.count("sysmon_configuration") == 0);
        CHECK(sparse.fields.count("sysmon_configuration_file_hash") == 0);
        CheckNoProcessIdentity(sparse);
    }
}

void TestEvent255ErrorAndOptionalFields() {
    Event event;
    const bool parsed = ParseSysmonXml(
        EventXml(255, Field(L"ID", L"6") +
            Field(L"Description", L"Failed to initialize event filter") +
            SensorData()), event);
    CHECK(parsed);
    if (!parsed) return;
    CHECK(event.type == EDR_EVT_AUDIT_LOG);
    CHECK(HasField(event, field::kType, "AUDIT_LOG"));
    CHECK(event.source == "sysmon");
    CHECK(HasField(event, field::kSource, "sysmon"));
    CHECK(HasField(event, field::kSysmonEventId, "255"));
    CHECK(HasField(event, field::kOperationType, "SYSMON_ERROR"));
    CHECK(HasField(event, "sysmon_error_id", "6"));
    CHECK(HasField(event, "sysmon_error_description",
                   "Failed to initialize event filter"));
    CHECK(event.fields.count(field::kAuditLogEventId) == 0);
    CheckNoProcessIdentity(event);

    Event sparse;
    const bool sparseParsed = ParseSysmonXml(EventXml(255, L""), sparse);
    CHECK(sparseParsed);
    if (sparseParsed) {
        CHECK(HasField(sparse, field::kOperationType, "SYSMON_ERROR"));
        CHECK(sparse.fields.count("sysmon_error_id") == 0);
        CHECK(sparse.fields.count("sysmon_error_description") == 0);
        CheckNoProcessIdentity(sparse);
    }
}

void TestUnknownAndMalformedEventsRemainRejected() {
    Event event;
    CHECK(!ParseSysmonXml(EventXml(30, L""), event));
    CHECK(ParseSysmonXml(EventXml(16, L""), event));
    if (HasField(event, field::kSysmonEventId, "16")) {
        CHECK(HasField(event, field::kOperationType,
                       "SYSMON_CONFIG_CHANGED"));
        CHECK(event.fields.count("sysmon_configuration") == 0);
    }
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

size_t EventIdPredicateCount(const std::wstring& query) {
    size_t count = 0;
    size_t position = 0;
    while ((position = query.find(L"EventID=", position)) !=
           std::wstring::npos) {
        ++count;
        position += 8;
    }
    return count;
}

void TestQueryIncludesSensorEventsAndNativeXpathAcceptsAllSwitches() {
    for (unsigned int mask = 0; mask < 16; ++mask) {
        const bool imageLoad = (mask & 1) != 0;
        const bool processAccess = (mask & 2) != 0;
        const bool remoteThread = (mask & 4) != 0;
        const bool namedPipe = (mask & 8) != 0;
        const std::wstring query = SysmonSubscriptionQuery(
            imageLoad, processAccess, remoteThread, namedPipe);
        for (unsigned int id : {1u, 2u, 3u, 4u, 5u, 6u, 11u, 12u, 13u,
                                14u, 16u, 22u, 23u, 25u, 26u, 255u})
            CHECK(ContainsEventId(query, id));
        CHECK(ContainsEventId(query, 7u) == imageLoad);
        CHECK(ContainsEventId(query, 10u) == processAccess);
        CHECK(ContainsEventId(query, 8u) == remoteThread);
        CHECK(ContainsEventId(query, 17u) == namedPipe);
        CHECK(ContainsEventId(query, 18u) == namedPipe);
        const size_t expectedCount = 16 + (imageLoad ? 1 : 0) +
            (processAccess ? 1 : 0) + (remoteThread ? 1 : 0) +
            (namedPipe ? 2 : 0);
        CHECK(EventIdPredicateCount(query) == expectedCount);
        CHECK(EventIdPredicateCount(query) <= 21);

        EVT_HANDLE result = EvtQuery(nullptr, L"Application", query.c_str(),
                                     EvtQueryChannelPath);
        CHECK(result != nullptr);
        if (result != nullptr) EvtClose(result);

        HANDLE signal = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        CHECK(signal != nullptr);
        if (signal != nullptr) {
            EVT_HANDLE subscription = EvtSubscribe(
                nullptr, signal, L"Application", query.c_str(), nullptr,
                nullptr, nullptr, EvtSubscribeToFutureEvents);
            if (subscription == nullptr) {
                std::fprintf(stderr,
                    "EvtSubscribe failed for switch mask %u: %lu\n", mask,
                    GetLastError());
                CHECK(subscription != nullptr);
            } else {
                EvtClose(subscription);
            }
            CloseHandle(signal);
        }
    }
}

void TestSensorEventsDoNotMutateProcessTree() {
    ProcessTreeBuilder tree;
    Event process;
    process.type = EDR_EVT_PROCESS_START;
    process.pid = 9876;
    process.ppid = 1234;
    process.fields[field::kImage] = "C:\\Temp\\real-process.exe";
    tree.Observe(process);
    CHECK(tree.GetAncestors(9876) == std::vector<uint32_t>{1234});

    for (unsigned int id : {4u, 16u, 255u}) {
        Event sensor;
        CHECK(ParseSysmonXml(EventXml(id, SensorData()), sensor));
        tree.Observe(sensor);
        CHECK(tree.GetAncestors(9876) == std::vector<uint32_t>{1234});
        CHECK(tree.GetProcessTreeJson(9876).find("real-process.exe") !=
              std::string::npos);
        CHECK(!tree.HasProcess(0));
    }
}

struct ExpectedRule {
    const char* id;
    const char* severity;
    const char* action;
    unsigned int eventId;
    const char* operation;
    std::wstring data;
};

bool HasRule(RuleEngine& engine, const Event& event, const char* ruleId,
             const char* severity = nullptr, const char* action = nullptr) {
    bool matched = false;
    engine.SetAlertCallback([&](const Alert& alert) {
        if (alert.ruleId != ruleId) return;
        matched = true;
        if (severity != nullptr) CHECK(alert.severity == severity);
        if (action != nullptr) CHECK(alert.action == action);
    });
    engine.OnEvent(event);
    engine.SetAlertCallback({});
    return matched;
}

void TestProductionRulesMatchExactSensorContracts(const char* rulesPath) {
    RuleEngine engine;
    engine.LoadFromFile(rulesPath);
    const ExpectedRule expected[] = {
        {"EDR-531", "low", "log", 4,
         "SYSMON_SERVICE_STATE_CHANGED",
         Field(L"State", L"Running") + Field(L"Version", L"15.0") +
             Field(L"SchemaVersion", L"4.90")},
        {"EDR-532", "low", "log", 16, "SYSMON_CONFIG_CHANGED",
         Field(L"Configuration", L"&lt;Sysmon /&gt;") +
             Field(L"ConfigurationFileHash", L"SHA256=abc")},
        {"EDR-533", "medium", "alert", 255, "SYSMON_ERROR",
         Field(L"ID", L"6") + Field(L"Description", L"filter failure")}
    };

    for (const auto& item : expected) {
        Event event;
        const bool parsed = ParseSysmonXml(EventXml(item.eventId, item.data),
                                           event);
        CHECK(parsed);
        if (!parsed) continue;
        CHECK(HasRule(engine, event, item.id, item.severity, item.action));

        Event wrongType = event;
        wrongType.fields[field::kType] = "PROCESS_START";
        CHECK(!HasRule(engine, wrongType, item.id));
        Event wrongSource = event;
        wrongSource.source = "other";
        wrongSource.fields[field::kSource] = "other";
        CHECK(!HasRule(engine, wrongSource, item.id));
        Event wrongId = event;
        wrongId.fields[field::kSysmonEventId] = "999";
        CHECK(!HasRule(engine, wrongId, item.id));
        Event wrongOperation = event;
        wrongOperation.fields[field::kOperationType] = "OTHER";
        CHECK(!HasRule(engine, wrongOperation, item.id));
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr,
            "usage: edr_sysmon_sensor_health_tests <production-rules.json>\n");
        return 2;
    }
    TestEvent4ServiceStateAndOptionalFields();
    TestEvent16ConfigurationChangeAndOptionalFields();
    TestEvent255ErrorAndOptionalFields();
    TestUnknownAndMalformedEventsRemainRejected();
    TestQueryIncludesSensorEventsAndNativeXpathAcceptsAllSwitches();
    TestSensorEventsDoNotMutateProcessTree();
    TestProductionRulesMatchExactSensorContracts(argv[1]);
    if (g_failures != 0) {
        std::fprintf(stderr, "%d Sysmon sensor-health check(s) failed\n",
                     g_failures);
        return 1;
    }
    std::puts("Sysmon sensor-health tests passed");
    return 0;
}
