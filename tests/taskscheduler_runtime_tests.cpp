#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include <windows.h>
#include <winevt.h>

#include "edr_event.h"
#include "event_bus.h"
#include "persistence_burst_detector.h"
#include "persistence_chain_detector.h"
#include "task_abuse_detector.h"
#include "taskscheduler_parser.h"

namespace edr {
std::wstring BuildTaskSchedulerSubscriptionQuery();
}

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

std::wstring RuntimeXml(unsigned int id, unsigned int version,
                        const std::wstring& fields,
                        const wchar_t* userSid = L"S-1-5-18") {
    return L"<Event><System><EventID Version='" + std::to_wstring(version) +
        L"'>" + std::to_wstring(id) + L"</EventID>"
        L"<Execution ProcessID='777' ThreadID='9'/>"
        L"<Security UserID='" + std::wstring(userSid) + L"'/>"
        L"<TimeCreated SystemTime='2026-10-19T03:04:05.1234567Z'/>"
        L"</System><EventData>" + fields + L"</EventData></Event>";
}

std::wstring Data(const wchar_t* name, const std::wstring& value) {
    return L"<Data Name='" + std::wstring(name) + L"'>" + value +
           L"</Data>";
}

std::wstring TaskInstanceId() {
    return L"{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}";
}

std::wstring TaskEvents(unsigned int id, unsigned int version,
                        const std::wstring& taskName = L"\\Vendor\\Update",
                        const std::wstring& extra = L"") {
    return RuntimeXml(id, version,
        Data(L"TaskName", taskName) + extra);
}

void CheckRuntime(unsigned int id, unsigned int version,
                  const char* operation, const std::wstring& extra,
                  const char* expectedInstance = nullptr,
                  const char* expectedAction = nullptr,
                  const char* expectedCode = nullptr,
                  const char* expectedEnginePid = nullptr) {
    Event event;
    const bool parsed = ParseTaskSchedulerXml(
        TaskEvents(id, version, L"\\Vendor\\Update", extra), event);
    CHECK(parsed);
    if (!parsed) return;
    CHECK(event.type == EDR_EVT_TASK_SCHEDULER);
    CHECK(event.source == "taskscheduler_log");
    CHECK(event.fields.at(field::kType) == "TASK_SCHEDULER");
    CHECK(event.fields.at(field::kTaskSchedulerEventId) == std::to_string(id));
    CHECK(event.fields.at(field::kOperationType) == operation);
    CHECK(event.fields.at(field::kTaskName) == "\\Vendor\\Update");
    CHECK(event.fields.at(field::kTaskEventUserSid) == "S-1-5-18");
    CHECK(event.fields.count(field::kTaskInstanceId) ==
          (expectedInstance != nullptr ? 1u : 0u));
    if (expectedInstance != nullptr)
        CHECK(event.fields.at(field::kTaskInstanceId) == expectedInstance);
    CHECK(event.fields.count(field::kTaskActionName) ==
          (expectedAction != nullptr ? 1u : 0u));
    if (expectedAction != nullptr)
        CHECK(event.fields.at(field::kTaskActionName) == expectedAction);
    CHECK(event.fields.count(field::kTaskResultCode) ==
          (expectedCode != nullptr ? 1u : 0u));
    if (expectedCode != nullptr)
        CHECK(event.fields.at(field::kTaskResultCode) == expectedCode);
    CHECK(event.fields.count(field::kTaskEnginePid) ==
          (expectedEnginePid != nullptr ? 1u : 0u));
    if (expectedEnginePid != nullptr)
        CHECK(event.fields.at(field::kTaskEnginePid) == expectedEnginePid);

    // Scheduler metadata never establishes a process identity or start time.
    CHECK(event.pid == 0);
    CHECK(event.ppid == 0);
    CHECK(event.processIdentity.empty());
    CHECK(event.processStartTime100ns == 0);
    CHECK(event.fields.count(field::kPid) == 0);
    CHECK(event.fields.count(field::kImage) == 0);
    CHECK(event.fields.count(field::kUserId) == 0);
    CHECK(event.ts100ns != 0);
}

void TestTaskLifecycleAndActionVersions() {
    CheckRuntime(100, 0, "TASK_STARTED",
        Data(L"UserContext", L"CORP\\svc-task") +
        Data(L"InstanceId", TaskInstanceId()),
        "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}");
    CheckRuntime(102, 0, "TASK_COMPLETED",
        Data(L"UserContext", L"CORP\\svc-task") +
        Data(L"InstanceId", TaskInstanceId()),
        "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}");
    CheckRuntime(200, 0, "TASK_ACTION_STARTED",
        Data(L"ActionName", L"C:\\Tools\\job.exe") +
        Data(L"TaskInstanceId", TaskInstanceId()),
        "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}",
        "C:\\Tools\\job.exe");
    CheckRuntime(200, 1, "TASK_ACTION_STARTED",
        Data(L"ActionName", L"C:\\Tools\\job.exe") +
        Data(L"TaskInstanceId", TaskInstanceId()) +
        Data(L"EnginePID", L"4321"),
        "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}",
        "C:\\Tools\\job.exe", nullptr, "4321");
    CheckRuntime(201, 0, "TASK_ACTION_COMPLETED",
        Data(L"ActionName", L"C:\\Tools\\job.exe") +
        Data(L"TaskInstanceId", TaskInstanceId()),
        "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}",
        "C:\\Tools\\job.exe");
    CheckRuntime(201, 1, "TASK_ACTION_COMPLETED",
        Data(L"ActionName", L"C:\\Tools\\job.exe") +
        Data(L"TaskInstanceId", TaskInstanceId()) +
        Data(L"ResultCode", L"0") + Data(L"EnginePID", L"4321"),
        "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}",
        "C:\\Tools\\job.exe", "0", "4321");
    CheckRuntime(201, 2, "TASK_ACTION_COMPLETED",
        Data(L"ActionName", L"C:\\Tools\\job.exe") +
        Data(L"TaskInstanceId", TaskInstanceId()) +
        Data(L"ResultCode", L"2147942405") + Data(L"EnginePID", L"4321"),
        "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}",
        "C:\\Tools\\job.exe", "2147942405", "4321");
    CheckRuntime(202, 1, "TASK_ACTION_FAILED",
        Data(L"ActionName", L"C:\\Tools\\job.exe") +
        Data(L"TaskInstanceId", TaskInstanceId()) +
        Data(L"ResultCode", L"2147942405") + Data(L"EnginePID", L"4321"),
        "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}",
        "C:\\Tools\\job.exe", "2147942405", "4321");
    CheckRuntime(203, 0, "TASK_ACTION_START_FAILED",
        Data(L"ActionName", L"C:\\Tools\\job.exe") +
        Data(L"TaskInstanceId", TaskInstanceId()) +
        Data(L"ResultCode", L"2147942405"),
        "{7C2B39E1-14A1-4F0C-A242-8D981AAB9853}",
        "C:\\Tools\\job.exe", "2147942405");
    // EnginePID is provider metadata. Zero is a valid UInt32 observation,
    // not a process target and not a reason to discard the task event.
    CheckRuntime(200, 1, "TASK_ACTION_STARTED",
        Data(L"ActionName", L"C:\\Tools\\job.exe") +
        Data(L"EnginePID", L"0"), nullptr, "C:\\Tools\\job.exe", nullptr, "0");
    std::puts("PASS Task Scheduler runtime event IDs and provider versions");
}

void TestRequiredAndOptionalFieldValidation() {
    Event event;
    const auto instance = Data(L"InstanceId", TaskInstanceId());
    CHECK(!ParseTaskSchedulerXml(TaskEvents(100, 0, L"", instance), event));
    CHECK(!ParseTaskSchedulerXml(TaskEvents(200, 0, L"\\Vendor\\Update",
        Data(L"TaskInstanceId", TaskInstanceId())), event));
    CHECK(!ParseTaskSchedulerXml(TaskEvents(200, 0, L"",
        Data(L"ActionName", L"job.exe")), event));
    CHECK(!ParseTaskSchedulerXml(TaskEvents(201, 1, L"\\Vendor\\Update",
        Data(L"ActionName", L"job.exe") +
        Data(L"TaskInstanceId", TaskInstanceId()) +
        Data(L"ResultCode", L"4294967296")), event));
    CHECK(!ParseTaskSchedulerXml(TaskEvents(202, 1, L"\\Vendor\\Update",
        Data(L"ActionName", L"job.exe") +
        Data(L"EnginePID", L"-1")), event));
    CHECK(!ParseTaskSchedulerXml(TaskEvents(203, 0, L"\\Vendor\\Update",
        Data(L"ActionName", L"job.exe") +
        Data(L"ResultCode", L"12x")), event));
    CHECK(!ParseTaskSchedulerXml(TaskEvents(100, 0, L"\\Vendor\\Update",
        Data(L"InstanceId", L"not-a-guid")), event));
    CHECK(!ParseTaskSchedulerXml(TaskEvents(200, 0, L"\\Vendor\\Update",
        Data(L"ActionName", L"job.exe") +
        Data(L"TaskInstanceId", L"not-a-guid")), event));
    CHECK(!ParseTaskSchedulerXml(TaskEvents(200, 1, L"\\Vendor\\Update",
        Data(L"ActionName", L"job.exe") +
        Data(L"EnginePID", L"4294967296")), event));

    // Missing optional result/engine fields are preserved as absent. A
    // completed event without ResultCode does not assert action success.
    const bool parsed = ParseTaskSchedulerXml(TaskEvents(201, 0,
        L"\\Vendor\\Update", Data(L"ActionName", L"job.exe")), event);
    CHECK(parsed);
    if (parsed) {
        CHECK(event.fields.count(field::kTaskResultCode) == 0);
        CHECK(event.fields.count(field::kTaskEnginePid) == 0);
    }
    const bool taskStartWithoutInstance = ParseTaskSchedulerXml(
        TaskEvents(100, 0, L"\\Vendor\\Update"), event);
    CHECK(taskStartWithoutInstance);
    if (taskStartWithoutInstance)
        CHECK(event.fields.count(field::kTaskInstanceId) == 0);
    std::puts("PASS Task Scheduler required and optional field validation");
}

void TestTaskUserContextAndEventSubjectStayDistinct() {
    Event event;
    const bool parsed = ParseTaskSchedulerXml(RuntimeXml(100, 0,
        Data(L"TaskName", L"\\Vendor\\Update") +
        Data(L"UserContext", L"CORP\\svc-task") +
        Data(L"InstanceId", TaskInstanceId()), L"S-1-5-21-111-222-333-1001"),
        event);
    CHECK(parsed);
    if (!parsed) return;
    CHECK(event.fields.at(field::kTaskUserContext) == "CORP\\svc-task");
    CHECK(event.fields.at(field::kTaskEventUserSid) ==
          "S-1-5-21-111-222-333-1001");
    CHECK(event.fields.count(field::kUserId) == 0);
    CHECK(event.pid == 0);

    Event absentTaskContext;
    const bool parsedWithoutContext = ParseTaskSchedulerXml(RuntimeXml(100, 0,
        Data(L"TaskName", L"\\Vendor\\Update") +
        Data(L"InstanceId", TaskInstanceId()),
        L"S-1-5-21-111-222-333-1001"), absentTaskContext);
    CHECK(parsedWithoutContext);
    if (parsedWithoutContext) {
        CHECK(absentTaskContext.fields.count(field::kTaskUserContext) == 0);
        CHECK(absentTaskContext.fields.at(field::kTaskEventUserSid) ==
              "S-1-5-21-111-222-333-1001");
    }
    std::puts("PASS Task Scheduler task context and event subject separation");
}

void TestXmlEntitiesAreDecodedInTaskAndActionFields() {
    Event event;
    const bool parsed = ParseTaskSchedulerXml(TaskEvents(200, 0,
        L"\\Vendor\\A&amp;B",
        Data(L"ActionName", L"C:\\Program Files\\A &amp; B.exe") +
        Data(L"TaskInstanceId", TaskInstanceId())), event);
    CHECK(parsed);
    if (!parsed) return;
    CHECK(event.fields.at(field::kTaskName) == "\\Vendor\\A&B");
    CHECK(event.fields.at(field::kTaskActionName) ==
          "C:\\Program Files\\A & B.exe");
    std::puts("PASS Task Scheduler XML entities decode in task/action values");
}

void TestRuntimeEventsDoNotBecomePersistenceWritesOrTaskAbuse() {
    const std::vector<unsigned int> ids = {100, 102, 200, 201, 202, 203};
    TaskAbuseDetector::Settings settings;
    settings.enabled = true;
    settings.deleteBurstThreshold = 1;
    TaskAbuseDetector taskAbuse(settings);
    PersistenceBurstDetector persistence(true, 60, 32, 55, 0);
    for (unsigned int id : ids) {
        std::wstring extra = id == 100 || id == 102
            ? Data(L"UserContext", L"SYSTEM") +
              Data(L"InstanceId", TaskInstanceId())
            : Data(L"ActionName", L"C:\\Temp\\powershell.exe") +
              Data(L"TaskInstanceId", TaskInstanceId());
        if (id == 201 || id == 202 || id == 203)
            extra += Data(L"ResultCode", L"1");
        if (id == 200 || id == 202 || id == 201)
            extra += Data(L"EnginePID", L"4321");
        const unsigned int version = id == 100 || id == 102 || id == 203
            ? 0u : (id == 201 ? 2u : 1u);
        Event event;
        CHECK(ParseTaskSchedulerXml(TaskEvents(id, version,
            L"\\Temp\\report.pdf.exe", extra), event));
        if (event.fields.empty()) continue;
        taskAbuse.Enrich(event);
        persistence.Enrich(event);
        CHECK(event.fields.count(field::kTaskAbuseScore) == 0);
        CHECK(event.fields.count(field::kPersistBurstScore) == 0);
        PersistenceChainDetector chain(true, 60, 32, 2);
        chain.Enrich(event);
        CHECK(chain.StateCount() == 0);
        CHECK(event.fields.count(field::kPersistChainScore) == 0);
    }
    CHECK(taskAbuse.StateCount() == 0);
    CHECK(persistence.StateCount() == 0);
    std::puts("PASS runtime events do not become persistence/task-abuse evidence");
}

void TestLegacyTaskConfigurationEventsRemainSupported() {
    const struct { unsigned int id; const char* operation; } cases[] = {
        {106, "TASK_REGISTERED"}, {140, "TASK_UPDATED"},
        {141, "TASK_DELETED"}
    };
    for (const auto& item : cases) {
        Event event;
        const bool parsed = ParseTaskSchedulerXml(TaskEvents(item.id, 0,
            L"\\Vendor\\Legacy", Data(L"UserContext", L"SYSTEM")), event);
        CHECK(parsed);
        if (!parsed) continue;
        CHECK(event.fields.at(field::kOperationType) == item.operation);
        CHECK(event.fields.at(field::kTaskName) == "\\Vendor\\Legacy");
        CHECK(event.fields.at(field::kTaskUserContext) == "SYSTEM");
    }
    std::puts("PASS legacy Task Scheduler configuration events remain supported");
}

void TestSubscriptionQueryMatchesParserContractAndHasValidXPath() {
    const std::wstring query = BuildTaskSchedulerSubscriptionQuery();
    const std::set<unsigned int> expected = {
        100, 102, 106, 140, 141, 200, 201, 202, 203
    };
    std::set<unsigned int> selected;
    size_t cursor = 0;
    while ((cursor = query.find(L"EventID=", cursor)) != std::wstring::npos) {
        cursor += 8;
        size_t digits = 0;
        const unsigned long id = std::stoul(query.substr(cursor), &digits);
        CHECK(digits != 0 && id <= 65535);
        if (digits != 0 && id <= 65535)
            CHECK(selected.insert(static_cast<unsigned int>(id)).second);
        cursor += digits;
    }
    CHECK(selected == expected);

    EVT_HANDLE result = EvtQuery(nullptr, L"Application", query.c_str(),
                                 EvtQueryChannelPath);
    CHECK(result != nullptr);
    if (result != nullptr) EvtClose(result);
    std::puts("PASS Task Scheduler subscription/parser ID contract and XPath syntax");
}

} // namespace

int main() {
    TestTaskLifecycleAndActionVersions();
    TestRequiredAndOptionalFieldValidation();
    TestTaskUserContextAndEventSubjectStayDistinct();
    TestXmlEntitiesAreDecodedInTaskAndActionFields();
    TestRuntimeEventsDoNotBecomePersistenceWritesOrTaskAbuse();
    TestLegacyTaskConfigurationEventsRemainSupported();
    TestSubscriptionQueryMatchesParserContractAndHasValidXPath();
    if (g_failures != 0) {
        std::fprintf(stderr, "%d Task Scheduler runtime check(s) failed\n",
                     g_failures);
        return 1;
    }
    std::puts("Task Scheduler runtime tests passed");
    return 0;
}
