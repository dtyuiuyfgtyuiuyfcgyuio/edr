/* Native Security audit-policy and scheduled-task evidence contracts. */
#include <algorithm>
#include <cstdio>
#include <functional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <windows.h>
#include <winevt.h>

#include "edr_event.h"
#include "config.h"
#include "rule_engine.h"
#include "security_log_parser.h"
#include "security_log_subscription.h"
#include "xml_util.h"

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

std::wstring Data(const wchar_t* name, const std::wstring& value) {
    return std::wstring(L"<Data Name='") + name + L"'>" + value +
           L"</Data>";
}

std::wstring Subject() {
    return Data(L"SubjectUserSid", L"S-1-5-21-100-200-300-1001") +
        Data(L"SubjectUserName", L"native-user") +
        Data(L"SubjectDomainName", L"NATIVE-DOMAIN") +
        Data(L"SubjectLogonId", L"0x123456");
}

std::wstring Xml(unsigned int id, unsigned int version,
                 const std::wstring& data,
                 const std::wstring& eventIdAttributes = L"",
                 bool includeVersionElement = true) {
    return L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        L"<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        L"<EventID" + eventIdAttributes + L">" +
        std::to_wstring(id) + L"</EventID>" +
        (includeVersionElement ? L"<Version>" + std::to_wstring(version) +
            L"</Version>" : L"") +
        L"<TimeCreated SystemTime='2026-10-20T10:00:00.1234567Z'/>"
        L"<Execution ProcessID='888' ThreadID='999'/><Channel>Security</Channel>"
        L"<Computer>CONTRACT-HOST</Computer></System><EventData>" + data +
        L"</EventData></Event>";
}

Event Parse(unsigned int id, unsigned int version,
            const std::wstring& data,
            const std::wstring& eventIdAttributes = L"") {
    Event event;
    CHECK(ParseSecurityLogXml(Xml(id, version, data, eventIdAttributes), event));
    CHECK(event.source == "security_log");
    CHECK(event.fields.at(field::kSource) == "security_log");
    CHECK(event.fields.at(field::kSecurityEventId) == std::to_string(id));
    return event;
}

Event TaskEvent(unsigned int id, unsigned int version,
                const std::wstring& taskName,
                const std::wstring& content,
                const std::wstring& extra = L"") {
    const wchar_t* contentName = id == 4698 ? L"TaskContent" : L"TaskContentNew";
    return Parse(id, version, Subject() + Data(L"TaskName", taskName) +
        Data(contentName, content) + extra);
}

void CheckNoProcessIdentity(const Event& event) {
    CHECK(event.pid == 0);
    CHECK(event.ppid == 0);
    CHECK(event.processStartTime100ns == 0);
    CHECK(event.processIdentity.empty());
    CHECK(event.fields.count(field::kPid) == 0);
    CHECK(event.fields.count(field::kPpid) == 0);
    CHECK(event.fields.count(field::kImage) == 0);
    CHECK(event.fields.count(field::kTaskUserContext) == 0);
}

void Test4719PreservesNativeAuditEvidence() {
    Event event = Parse(4719, 1, Subject() +
        Data(L"CategoryId", L"%%8273") +
        Data(L"SubcategoryId", L"%%5400") +
        Data(L"SubcategoryGuid", L"{0CCE9215-69AE-11D9-BED3-505054503030}") +
        Data(L"AuditPolicyChanges", L"%%8448") +
        Data(L"ClientProcessId", L"4242") +
        Data(L"ClientProcessStartKey", L"123456789"));
    CHECK(event.type == EDR_EVT_AUDIT_LOG);
    CHECK(event.fields.at(field::kAuditLogEventId) == "4719");
    CHECK(event.fields.at(field::kAuditPolicyCategoryId) == "%%8273");
    CHECK(event.fields.at(field::kAuditPolicySubcategoryId) == "%%5400");
    CHECK(event.fields.at(field::kAuditPolicySubcategoryGuid) ==
          "{0CCE9215-69AE-11D9-BED3-505054503030}");
    CHECK(event.fields.at(field::kAuditPolicyChanges) == "%%8448");
    CHECK(event.fields.at(field::kLogonId) == "0x123456");
    CheckNoProcessIdentity(event);
}

void Test4719UsesOnlyNativeFieldNames() {
    Event event = Parse(4719, 0, Subject() +
        Data(L"Category", L"wrong-category") +
        Data(L"Subcategory", L"wrong-subcategory") +
        Data(L"PolicyChanges", L"wrong-changes") +
        Data(L"AuditPolicyChanges", L"native-changes"));
    CHECK(event.fields.count(field::kAuditPolicyCategoryId) == 0);
    CHECK(event.fields.count(field::kAuditPolicySubcategoryId) == 0);
    CHECK(event.fields.at(field::kAuditPolicyChanges) == "native-changes");
    CHECK(event.fields.at(field::kLogonId) == "0x123456");
}

void Test1104ExistingAuditSemanticsRemain() {
    Event event = Parse(1104, 0, L"");
    CHECK(event.type == EDR_EVT_AUDIT_LOG);
    CHECK(event.fields.at(field::kAuditLogEventId) == "1104");
    CHECK(event.fields.at(field::kOperationType) == "SECURITY_LOG_FULL");
    CHECK(event.fields.count(field::kAuditPolicyCategoryId) == 0);
    CHECK(event.fields.count(field::kAuditPolicySubcategoryId) == 0);
    CHECK(event.fields.count(field::kAuditPolicySubcategoryGuid) == 0);
    CHECK(event.fields.count(field::kAuditPolicyChanges) == 0);
}

void CheckTask(unsigned int id, unsigned int version, const char* operation,
               const std::wstring& content) {
    Event event = TaskEvent(id, version, L"\\Vendor\\Nightly", content);
    CHECK(event.type == EDR_EVT_TASK_SCHEDULER);
    CHECK(event.fields.at(field::kType) == "TASK_SCHEDULER");
    CHECK(event.fields.at(field::kOperationType) == operation);
    CHECK(event.fields.at(field::kTaskName) == "\\Vendor\\Nightly");
    CHECK(event.fields.at(field::kTaskContent) == WideToUtf8(content.c_str()));
    CHECK(event.fields.at(field::kTaskContentStatus) == "captured");
    CHECK(event.fields.at(field::kSubjectUserName) == "native-user");
    CHECK(event.fields.at(field::kLogonId) == "0x123456");
    CheckNoProcessIdentity(event);
}

void TestTaskRegistrationAndUpdateContent() {
    const std::wstring utf8Content = L"<Task><URI>任务/晚上</URI> café</Task>";
    CheckTask(4698, 0, "TASK_REGISTERED", utf8Content);
    CheckTask(4698, 1, "TASK_REGISTERED", utf8Content);
    CheckTask(4702, 0, "TASK_UPDATED", utf8Content);
    CheckTask(4702, 1, "TASK_UPDATED", utf8Content);
}

void TestTaskRequiresNativeTaskNameAndDoesNotAlias() {
    for (unsigned int id : {4698u, 4702u}) {
        const wchar_t* contentName = id == 4698 ? L"TaskContent" : L"TaskContentNew";
        Event event;
        CHECK(!ParseSecurityLogXml(Xml(id, 0,
            Subject() + Data(contentName, L"<Task/>") +
            Data(L"Name", L"\\Alias\\Task")), event));
        CHECK(!ParseSecurityLogXml(Xml(id, 0,
            Subject() + Data(L"TaskName", L"") + Data(contentName, L"<Task/>")), event));
    }
}

void TestTaskContentStatusAndBoundedUtf8() {
    Event missing = Parse(4698, 0,
        Subject() + Data(L"TaskName", L"\\Vendor\\Missing"));
    CHECK(missing.fields.at(field::kTaskContentStatus) == "missing");
    CHECK(missing.fields.count(field::kTaskContent) == 0);

    Event empty = Parse(4702, 0, Subject() +
        Data(L"TaskName", L"\\Vendor\\Empty") + Data(L"TaskContentNew", L""));
    CHECK(empty.fields.at(field::kTaskContentStatus) == "missing");
    CHECK(empty.fields.count(field::kTaskContent) == 0);

    Event max = Parse(4698, 0, Subject() +
        Data(L"TaskName", L"\\Vendor\\Max") +
        Data(L"TaskContent", std::wstring(32768, L'x')));
    CHECK(max.fields.at(field::kTaskContentStatus) == "captured");
    CHECK(max.fields.at(field::kTaskContent).size() == 32768);

    Event over = Parse(4702, 0, Subject() +
        Data(L"TaskName", L"\\Vendor\\Over") +
        Data(L"TaskContentNew", std::wstring(32769, L'x')));
    CHECK(over.fields.at(field::kTaskContentStatus) == "omitted_oversize");
    CHECK(over.fields.count(field::kTaskContent) == 0);
}

void TestTaskUtf8ByteLimitAndInvalidUtf16() {
    const std::wstring exact = std::wstring(10922, static_cast<wchar_t>(0x4E2D)) + L"xx";
    Event max = Parse(4698, 0, Subject() + Data(L"TaskName", L"\\Vendor\\Utf8Max") +
        Data(L"TaskContent", exact));
    CHECK(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, exact.data(),
        static_cast<int>(exact.size()), nullptr, 0, nullptr, nullptr) == 32768);
    CHECK(max.fields.at(field::kTaskContentStatus) == "captured");
    CHECK(max.fields.at(field::kTaskContent).size() == 32768);

    const std::wstring tooLarge = exact + static_cast<wchar_t>(0x4E2D);
    Event over = Parse(4702, 0, Subject() + Data(L"TaskName", L"\\Vendor\\Utf8Over") +
        Data(L"TaskContentNew", tooLarge));
    CHECK(over.fields.at(field::kTaskContentStatus) == "omitted_oversize");
    CHECK(over.fields.count(field::kTaskContent) == 0);

    const std::wstring invalid(1, static_cast<wchar_t>(0xD800));
    Event malformed = Parse(4698, 0, Subject() +
        Data(L"TaskName", L"\\Vendor\\Invalid") + Data(L"TaskContent", invalid));
    CHECK(malformed.fields.at(field::kTaskContentStatus) == "invalid_encoding");
    CHECK(malformed.fields.count(field::kTaskContent) == 0);
}

void TestVersionOneClientFieldsRemainMetadata() {
    const std::wstring extras = Data(L"ClientProcessId", L"4242") +
        Data(L"ParentProcessId", L"3131") +
        Data(L"ClientProcessStartKey", L"123456789") +
        Data(L"RpcCallClientLocality", L"1") +
        Data(L"FQDN", L"client.example.test") +
        Data(L"ProcessId", L"9999") + Data(L"Image", L"C:\\decoy.exe") +
        Data(L"UserContext", L"decoy-user");
    for (unsigned int id : {4698u, 4702u}) {
        const wchar_t* contentName = id == 4698 ? L"TaskContent" : L"TaskContentNew";
        Event event = Parse(id, 1, Subject() + Data(L"TaskName", L"\\Vendor\\V1") +
            Data(contentName, L"<Task/>") + extras);
        CHECK(event.fields.at(field::kTaskClientPid) == "4242");
        CHECK(event.fields.at(field::kTaskClientParentPid) == "3131");
        CHECK(event.fields.at(field::kTaskClientStartKey) == "123456789");
        CHECK(event.fields.at(field::kTaskRpcLocality) == "1");
        CHECK(event.fields.at(field::kTaskClientFqdn) == "client.example.test");
        CHECK(event.fields.count(field::kTaskUserContext) == 0);
        CheckNoProcessIdentity(event);
    }

    Event conflictingAttribute = Parse(4698, 1,
        Subject() + Data(L"TaskName", L"\\Native\\VersionWins") +
        Data(L"TaskContent", L"<Task />") +
        Data(L"ClientProcessId", L"4242"), L" Version='0'");
    CHECK(conflictingAttribute.fields.at(field::kTaskClientPid) == "4242");
    CheckNoProcessIdentity(conflictingAttribute);

    Event noVersionElement;
    CHECK(ParseSecurityLogXml(Xml(4698, 1,
        Subject() + Data(L"TaskName", L"\\Native\\Versionless") +
        Data(L"TaskContent", L"<Task />") +
        Data(L"ClientProcessId", L"4242"), L"", false), noVersionElement));
    CHECK(noVersionElement.fields.at(field::kTaskName) == "\\Native\\Versionless");
    CHECK(noVersionElement.fields.count(field::kTaskClientPid) == 0);
}

void TestTaskFieldConflictsAndUnsupportedIds() {
    Event event = Parse(4698, 1, Subject() +
        Data(L"TaskName", L"\\Native\\Task") +
        Data(L"TaskContent", L"<Native/>") +
        Data(L"TaskContentNew", L"<Decoy/>") +
        Data(L"Task", L"<WrongAlias/>") +
        Data(L"ClientProcessId", L"4242") +
        Data(L"ProcessId", L"9999") + Data(L"Image", L"C:\\decoy.exe"));
    CHECK(event.fields.at(field::kTaskName) == "\\Native\\Task");
    CHECK(event.fields.at(field::kTaskContent) == "<Native/>");
    CHECK(event.fields.at(field::kTaskClientPid) == "4242");
    CheckNoProcessIdentity(event);

    Event unsupported;
    CHECK(!ParseSecurityLogXml(Xml(4699, 0, L""), unsupported));
}

bool Hits(RuleEngine& engine, const Event& event, const char* ruleId) {
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) {
        hits.push_back(alert.ruleId);
    });
    engine.OnEvent(event);
    engine.SetAlertCallback({});
    return std::find(hits.begin(), hits.end(), ruleId) != hits.end();
}

bool HasRuleResult(RuleEngine& engine, const Event& event, const char* ruleId,
                   const char* severity, const char* action) {
    bool matched = false;
    engine.SetAlertCallback([&](const Alert& alert) {
        if (alert.ruleId == ruleId && alert.severity == severity &&
            alert.action == action)
            matched = true;
    });
    engine.OnEvent(event);
    engine.SetAlertCallback({});
    return matched;
}

void Run(const char* name, const std::function<void()>& test) {
    try {
        test();
        std::printf("PASS %s\n", name);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL %s: %s\n", name, error.what());
        ++g_failures;
    }
}

void TestProductionRules(const char* rulesPath) {
    RuleEngine engine;
    engine.LoadFromFile(rulesPath);

    Event policy = Parse(4719, 0, Subject() +
        Data(L"CategoryId", L"%%8273") +
        Data(L"SubcategoryId", L"%%5400") +
        Data(L"SubcategoryGuid", L"{0CCE9215-69AE-11D9-BED3-505054503030}") +
        Data(L"AuditPolicyChanges", L"%%8448"));
    CHECK(HasRuleResult(engine, policy, "EDR-529", "low", "log"));

    Event logFull = Parse(1104, 0, L"");
    CHECK(HasRuleResult(engine, logFull, "EDR-530", "medium", "alert"));

    Event registered = TaskEvent(4698, 0, L"\\Vendor\\nativeTaskName",
        L"<Task><Actions/></Task>");
    CHECK(HasRuleResult(engine, registered, "EDR-032", "high", "alert"));
    Event updated = TaskEvent(4702, 0, L"\\Vendor\\nativeTaskName",
        L"<Task><Actions/></Task>");
    CHECK(HasRuleResult(engine, updated, "EDR-033", "medium", "alert"));

    Event wrongType = policy;
    wrongType.fields[field::kType] = "TASK_SCHEDULER";
    CHECK(!Hits(engine, wrongType, "EDR-529"));
    Event wrongSource = policy;
    wrongSource.fields[field::kSource] = "other_log";
    CHECK(!Hits(engine, wrongSource, "EDR-529"));
    Event wrongId = policy;
    wrongId.fields[field::kSecurityEventId] = "4718";
    CHECK(!Hits(engine, wrongId, "EDR-529"));
    Event wrongPolicyOperation = policy;
    wrongPolicyOperation.fields[field::kOperationType] = "SECURITY_LOG_FULL";
    CHECK(!Hits(engine, wrongPolicyOperation, "EDR-529"));

    Event wrongLogFullId = logFull;
    wrongLogFullId.fields[field::kSecurityEventId] = "1102";
    CHECK(!Hits(engine, wrongLogFullId, "EDR-530"));
    Event wrongLogFullOperation = logFull;
    wrongLogFullOperation.fields[field::kOperationType] = "AUDIT_POLICY_CHANGED";
    CHECK(!Hits(engine, wrongLogFullOperation, "EDR-530"));

    Event registeredWrongType = registered;
    registeredWrongType.fields[field::kType] = "OTHER_EVENT";
    CHECK(!Hits(engine, registeredWrongType, "EDR-032"));
    Event registeredWrongOperation = registered;
    registeredWrongOperation.fields[field::kOperationType] = "TASK_UPDATED";
    CHECK(!Hits(engine, registeredWrongOperation, "EDR-032"));
    Event registeredMissingName = registered;
    registeredMissingName.fields.erase(field::kTaskName);
    CHECK(!Hits(engine, registeredMissingName, "EDR-032"));

    Event updatedWrongType = updated;
    updatedWrongType.fields[field::kType] = "OTHER_EVENT";
    CHECK(!Hits(engine, updatedWrongType, "EDR-033"));
    Event updatedWrongOperation = updated;
    updatedWrongOperation.fields[field::kOperationType] = "TASK_REGISTERED";
    CHECK(!Hits(engine, updatedWrongOperation, "EDR-033"));
    Event updatedMissingName = updated;
    updatedMissingName.fields.erase(field::kTaskName);
    CHECK(!Hits(engine, updatedMissingName, "EDR-033"));
}

void TestSecuritySubscriptionIncludesIdsAndValidQuery() {
    const std::wstring& query = SecurityLogSubscriptionQuery();
    const std::set<unsigned int> expected = {
        1100, 1102, 1104, 4616, 4624, 4625, 4672, 4697, 4698, 4702,
        4719, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4740,
        4756, 4768, 4769
    };
    std::set<unsigned int> selected;
    size_t selectors = 0;
    size_t cursor = 0;
    while ((cursor = query.find(L"<Select Path=\"Security\">", cursor)) !=
           std::wstring::npos) {
        const size_t start = query.find(L'>', cursor) + 1;
        const size_t end = query.find(L"</Select>", start);
        CHECK(end != std::wstring::npos);
        if (end == std::wstring::npos) break;
        const std::wstring selector = query.substr(start, end - start);
        CHECK(selector.rfind(L"*[System[(", 0) == 0);
        CHECK(selector.size() >= 3 &&
              selector.substr(selector.size() - 3) == L")]]");
        size_t idCursor = 0;
        size_t count = 0;
        while ((idCursor = selector.find(L"EventID=", idCursor)) !=
               std::wstring::npos) {
            idCursor += 8;
            size_t consumed = 0;
            const unsigned long id = std::stoul(selector.substr(idCursor), &consumed);
            CHECK(consumed != 0 && id <= 65535);
            if (consumed != 0 && id <= 65535)
                CHECK(selected.insert(static_cast<unsigned int>(id)).second);
            idCursor += consumed;
            ++count;
        }
        CHECK(count > 0 && count <= 10);
        ++selectors;
        cursor = end + 9;
    }
    CHECK(selected == expected);
    CHECK(selected.size() == kSecurityLogEventIds.size());
    CHECK(std::find(kSecurityLogEventIds.begin(), kSecurityLogEventIds.end(),
                    4698) != kSecurityLogEventIds.end());
    CHECK(std::find(kSecurityLogEventIds.begin(), kSecurityLogEventIds.end(),
                    4702) != kSecurityLogEventIds.end());
    CHECK(selectors == 3);

    std::wstring syntaxQuery = query;
    const std::wstring securityPath = L"Path=\"Security\"";
    const std::wstring applicationPath = L"Path=\"Application\"";
    size_t pathOffset = 0;
    while ((pathOffset = syntaxQuery.find(securityPath, pathOffset)) !=
           std::wstring::npos) {
        syntaxQuery.replace(pathOffset, securityPath.size(), applicationPath);
        pathOffset += applicationPath.size();
    }
    EVT_HANDLE result = EvtQuery(nullptr, L"Application", syntaxQuery.c_str(),
                                 EvtQueryChannelPath);
    CHECK(result != nullptr);
    if (result != nullptr) EvtClose(result);
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr,
            "usage: edr_security_audit_visibility_tests <production-rules.json>\n");
        return 2;
    }
    Run("4719 preserves native audit evidence", Test4719PreservesNativeAuditEvidence);
    Run("4719 maps only provider field names", Test4719UsesOnlyNativeFieldNames);
    Run("1104 keeps existing audit semantics", Test1104ExistingAuditSemanticsRemain);
    Run("4698 and 4702 capture versioned native content",
        TestTaskRegistrationAndUpdateContent);
    Run("task events require a native nonempty task name",
        TestTaskRequiresNativeTaskNameAndDoesNotAlias);
    Run("task content status and UTF8 size bound",
        TestTaskContentStatusAndBoundedUtf8);
    Run("task content rejects invalid UTF16 and counts UTF8 bytes",
        TestTaskUtf8ByteLimitAndInvalidUtf16);
    Run("version one client metadata never becomes process identity",
        TestVersionOneClientFieldsRemainMetadata);
    Run("task fields reject aliases and unsupported IDs",
        TestTaskFieldConflictsAndUnsupportedIds);
    Run("native records reach strict production rules",
        [&] { TestProductionRules(argv[1]); });
    Run("subscription IDs and grouped XPath are valid",
        TestSecuritySubscriptionIncludesIdsAndValidQuery);
    if (g_failures != 0) {
        std::fprintf(stderr, "%d Security audit visibility check(s) failed\n",
                     g_failures);
        return 1;
    }
    std::puts("Security audit visibility tests passed");
    return 0;
}
