#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "privilege_escalation_detector.h"
#include "privilege_escalation_detector_tests.h"
#include "privilege_log_parser.h"
#include "rule_engine.h"
#include "sysmon_parser.h"

namespace {
using namespace edr;
constexpr uint64_t kSecond = 10000000ULL;
constexpr uint64_t kBase = 1000 * kSecond;
const char* kGuid = "{7c2b39e1-14a1-4f0c-a242-8d981aab9853}";
#define CHECK(x) do { if (!(x)) throw std::runtime_error( \
    std::string(__func__) + ":" + std::to_string(__LINE__) + ": " #x); } while (0)

Event Signal(uint16_t type, uint64_t time = kBase, uint32_t pid = 42) {
    Event event;
    event.type = type;
    event.pid = pid;
    event.ts100ns = time;
    event.source = "sysmon";
    event.processIdentity = kGuid;
    event.fields[field::kEndpointId] = "endpoint-a";
    event.fields[field::kImage] = "C:\\Windows\\System32\\svchost.exe";
    event.fields[field::kServiceImagePath] = "C:\\Temp\\test-service.exe";
    event.fields[field::kPrivileges] = "SeDebugPrivilege";
    event.fields[field::kTargetImage] = "C:\\Windows\\System32\\lsass.exe";
    event.fields[field::kAccessMask] = "40";
    return event;
}

bool Score(const Event& event, const char* expected) {
    auto found = event.fields.find(field::kPrivEscScore);
    return found != event.fields.end() && found->second == expected;
}

bool Unstamped(const Event& event) {
    return event.fields.count(field::kPrivEscScore) == 0;
}

void TestReliableInstance() {
    PrivilegeEscalationDetector detector(true, 10, 8);
    auto first = Signal(EDR_EVT_SERVICE_INSTALL);
    detector.Enrich(first);
    auto second = Signal(EDR_EVT_PRIVILEGE, kBase + kSecond);
    detector.Enrich(second);
    CHECK(Score(second, "80"));
    CHECK(second.fields.at(field::kPrivEscVerdict) == "MALICIOUS");
}

void TestInstanceScopeIsolation() {
    for (int variation = 0; variation < 6; ++variation) {
        PrivilegeEscalationDetector detector(true, 10, 8);
        auto first = Signal(EDR_EVT_SERVICE_INSTALL);
        if (variation == 1) first.processStartTime100ns = kBase - 2 * kSecond;
        detector.Enrich(first);
        auto second = Signal(EDR_EVT_PRIVILEGE, kBase + kSecond);
        switch (variation) {
        case 0: second.processIdentity = "{8c2b39e1-14a1-4f0c-a242-8d981aab9853}"; break;
        case 1: second.processStartTime100ns = kBase - kSecond; break;
        case 2: second.fields[field::kEndpointId] = "endpoint-b"; break;
        case 3: second.source = "security"; break;
        case 4: second.pid = 43; break;
        case 5: second.fields[field::kSource] = "etw"; break;
        }
        detector.Enrich(second);
        CHECK(Score(second, "30"));
    }
}

void TestWeakIdentityDoesNotAccumulate() {
    const std::vector<std::string> identities = {
        "", "42", "pid:42", "wmi/42", "arbitrary", "{00000000-0000-0000-0000-000000000000}"};
    for (const auto& identity : identities) {
        PrivilegeEscalationDetector detector(true, 10, 8);
        auto first = Signal(EDR_EVT_SERVICE_INSTALL);
        auto second = Signal(EDR_EVT_PRIVILEGE, kBase + kSecond);
        first.processIdentity = second.processIdentity = identity;
        detector.Enrich(first);
        detector.Enrich(second);
        CHECK(Score(first, "35"));
        CHECK(Score(second, "30"));
        CHECK(detector.StateCount() == 0);
    }
}

void TestInvalidScopeDoesNotAccumulate() {
    for (int variation = 0; variation < 4; ++variation) {
        PrivilegeEscalationDetector detector(true, 10, 8);
        auto first = Signal(EDR_EVT_SERVICE_INSTALL);
        switch (variation) {
        case 0: first.source.clear(); break;
        case 1: first.fields[field::kSource] = "etw"; break;
        case 2: first.fields[field::kEndpointId] = "bad endpoint"; break;
        case 3: first.source = std::string(65, 'a'); break;
        }
        auto second = first;
        second.type = EDR_EVT_PRIVILEGE;
        second.ts100ns += kSecond;
        detector.Enrich(first);
        detector.Enrich(second);
        CHECK(Score(second, "30"));
        CHECK(detector.StateCount() == 0);
    }
}

void TestZeroPidIsSingleEventOnly() {
    PrivilegeEscalationDetector detector(true, 10, 8);
    auto first = Signal(EDR_EVT_SERVICE_INSTALL, kBase, 0);
    auto second = Signal(EDR_EVT_PRIVILEGE, kBase + kSecond, 0);
    detector.Enrich(first);
    detector.Enrich(second);
    CHECK(Score(second, "30"));
    CHECK(detector.StateCount() == 0);
}

void TestCreationIdentity() {
    PrivilegeEscalationDetector detector(true, 10, 8);
    auto first = Signal(EDR_EVT_SERVICE_INSTALL);
    first.processIdentity.clear();
    first.processStartTime100ns = kBase - kSecond;
    auto second = first;
    second.type = EDR_EVT_PRIVILEGE;
    second.ts100ns += kSecond;
    detector.Enrich(first);
    detector.Enrich(second);
    CHECK(Score(second, "80"));
}

void TestInvalidTimes() {
    FILETIME now{};
    GetSystemTimePreciseAsFileTime(&now);
    const uint64_t wall = (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    for (int variation = 0; variation < 4; ++variation) {
        PrivilegeEscalationDetector detector(true, 10, 8);
        auto event = Signal(EDR_EVT_SERVICE_INSTALL);
        switch (variation) {
        case 0: event.ts100ns = 0; break;
        case 1: event.ts100ns = wall + 3600 * kSecond; break;
        case 2: event.processStartTime100ns = event.ts100ns + 1; break;
        case 3: event.disposition = EventDisposition::ReportOnly; break;
        }
        detector.Enrich(event);
        CHECK(Unstamped(event));
        CHECK(detector.StateCount() == 0);
    }
}

void TestOutOfOrderDoesNotAddEvidence() {
    PrivilegeEscalationDetector detector(true, 10, 8);
    auto first = Signal(EDR_EVT_PRIVILEGE, kBase + 5 * kSecond);
    detector.Enrich(first);
    auto late = Signal(EDR_EVT_SERVICE_INSTALL, kBase);
    detector.Enrich(late);
    CHECK(Unstamped(late));
    auto current = Signal(EDR_EVT_PRIVILEGE, kBase + 6 * kSecond);
    detector.Enrich(current);
    CHECK(Score(current, "30"));
}

void TestSignalsExpireIndividually() {
    PrivilegeEscalationDetector detector(true, 10, 8);
    auto first = Signal(EDR_EVT_SERVICE_INSTALL);
    auto second = Signal(EDR_EVT_PRIVILEGE, kBase + 9 * kSecond);
    auto third = Signal(EDR_EVT_PRIVILEGE, kBase + 11 * kSecond);
    detector.Enrich(first);
    detector.Enrich(second);
    CHECK(Score(second, "80"));
    detector.Enrich(third);
    CHECK(Score(third, "30"));
    CHECK(third.fields.at(field::kPrivEscSignals) == "suspicious_privilege");
}

void TestWindowBoundaryAndZeroWindow() {
    for (uint32_t window : {0u, 10u}) {
        PrivilegeEscalationDetector detector(true, window, 8);
        auto first = Signal(EDR_EVT_SERVICE_INSTALL);
        auto second = Signal(EDR_EVT_PRIVILEGE, kBase + window * kSecond);
        detector.Enrich(first);
        detector.Enrich(second);
        CHECK(Score(second, "30"));
    }
}

void TestCapacityEvictsOldest() {
    PrivilegeEscalationDetector detector(true, 10, 2);
    for (uint32_t pid : {42u, 43u, 44u}) {
        auto event = Signal(EDR_EVT_SERVICE_INSTALL, kBase + (pid - 42) * kSecond, pid);
        detector.Enrich(event);
        CHECK(detector.StateCount() <= 2);
    }
    auto second = Signal(EDR_EVT_PRIVILEGE, kBase + 3 * kSecond, 42);
    detector.Enrich(second);
    CHECK(Score(second, "30"));
    CHECK(detector.StateCount() == 2);
}

void TestInvalidEventDoesNotPurge() {
    PrivilegeEscalationDetector detector(true, 10, 8);
    auto first = Signal(EDR_EVT_SERVICE_INSTALL);
    detector.Enrich(first);
    auto unrelated = Signal(EDR_EVT_IMAGE_LOAD, kBase + 100 * kSecond);
    unrelated.fields[field::kImage] = "C:\\App\\normal.exe";
    detector.Enrich(unrelated);
    auto second = Signal(EDR_EVT_PRIVILEGE, kBase + kSecond);
    detector.Enrich(second);
    CHECK(Score(second, "80"));
}

void TestStrictAccessMask() {
    for (const char* mask : {"40junk", "-40", "40 ", "100000040"}) {
        PrivilegeEscalationDetector detector(true, 10, 8);
        auto event = Signal(EDR_EVT_PROCESS_ACCESS);
        event.fields[field::kAccessMask] = mask;
        detector.Enrich(event);
        CHECK(Unstamped(event));
    }
}

std::wstring ImageLoadXml(const std::wstring& dll, const std::wstring& host) {
    return L"<Event><System><EventID>7</EventID>"
        L"<TimeCreated SystemTime='2026-10-19T03:04:05.1234567Z'/></System>"
        L"<EventData><Data Name='ProcessId'>42</Data>"
        L"<Data Name='ProcessGuid'>{7c2b39e1-14a1-4f0c-a242-8d981aab9853}</Data>"
        L"<Data Name='Image'>" + host + L"</Data><Data Name='ImageLoaded'>" +
        dll + L"</Data></EventData></Event>";
}

void TestRealSysmon7Contract() {
    PrivilegeEscalationDetector detector(true, 300, 8);
    Event event;
    CHECK(ParseSysmonXml(ImageLoadXml(L"C:\\Temp\\test.dll",
                                     L"C:\\Windows\\System32\\svchost.exe"), event));
    CHECK(event.fields.at(field::kImage) == "C:\\Windows\\System32\\svchost.exe");
    CHECK(event.fields.at(field::kTargetImage) == "C:\\Temp\\test.dll");
    detector.Enrich(event);
    CHECK(Score(event, "20"));
    CHECK(event.fields.at(field::kPrivEscSignals) == "dll_sideload");
}

void TestNormalAndEmptyDllPaths() {
    for (const wchar_t* dll : {L"C:\\Windows\\System32\\normal.dll",
                              L"C:/Windows/SysWOW64/normal.dll", L""}) {
        PrivilegeEscalationDetector detector(true, 300, 8);
        Event event;
        if (ParseSysmonXml(ImageLoadXml(dll, L"C:\\Windows\\System32\\svchost.exe"), event))
            detector.Enrich(event);
        CHECK(Unstamped(event));
        CHECK(detector.StateCount() == 0);
    }
    auto event = Signal(EDR_EVT_IMAGE_LOAD);
    event.fields[field::kTargetImage] = "C:\\Windows\\System32\\svchost.exe";
    event.fields.erase(field::kImage);
    PrivilegeEscalationDetector detector(true, 300, 8);
    detector.Enrich(event);
    CHECK(Unstamped(event));
}

void TestNativeAccessAndPrivilegeFields() {
    Event access;
    CHECK(ParseSysmonXml(
        L"<Event><System><EventID>10</EventID>"
        L"<TimeCreated SystemTime='2026-10-19T03:04:05.1234567Z'/></System>"
        L"<EventData><Data Name='SourceProcessId'>42</Data>"
        L"<Data Name='TargetProcessId'>90</Data>"
        L"<Data Name='SourceProcessGUID'>{7c2b39e1-14a1-4f0c-a242-8d981aab9853}</Data>"
        L"<Data Name='TargetProcessGUID'>{7c2b39e1-14a1-4f0c-a242-8d981aab9854}</Data>"
        L"<Data Name='SourceImage'>C:\\Tools\\client.exe</Data>"
        L"<Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data>"
        L"<Data Name='GrantedAccess'>0x40</Data></EventData></Event>", access));
    PrivilegeEscalationDetector detector(true, 300, 8);
    detector.Enrich(access);
    CHECK(Score(access, "40"));
    Event privilege;
    CHECK(ParsePrivilegeLogXml(
        L"<Event><System><EventID>4673</EventID>"
        L"<TimeCreated SystemTime='2026-10-19T03:04:06.1234567Z'/></System>"
        L"<EventData><Data Name='ProcessId'>42</Data>"
        L"<Data Name='ProcessName'>C:\\Tools\\client.exe</Data>"
        L"<Data Name='PrivilegeList'>SeDebugPrivilege</Data></EventData></Event>", privilege));
    detector.Enrich(privilege);
    CHECK(Score(privilege, "30"));
    // Native 4673 supplies no strong process-instance evidence. Its PID
    // cannot merge with Sysmon's access event or acquire that event's score.
    CHECK(detector.StateCount() == 1);
}

void TestPrivilegeNamesAreWholeTokens() {
    PrivilegeEscalationDetector detector(true, 10, 8);
    for (const char* privileges : {"NotSeDebugPrivilege", "SeDebugPrivilegeDisabled"}) {
        auto event = Signal(EDR_EVT_PRIVILEGE);
        event.fields[field::kPrivileges] = privileges;
        detector.Enrich(event);
        CHECK(Unstamped(event));
    }
}

void TestProductionRule(const char* rulesPath) {
    RuleEngine engine;
    engine.LoadFromFile(rulesPath);
    CHECK(engine.RuleCount() > 0);
    PrivilegeEscalationDetector detector(true, 10, 8);
    auto first = Signal(EDR_EVT_SERVICE_INSTALL);
    auto second = Signal(EDR_EVT_PRIVILEGE, kBase + kSecond);
    detector.Enrich(first);
    detector.Enrich(second);
    bool matched = false;
    engine.SetAlertCallback([&](const Alert& alert) {
        if (alert.ruleId == "EDR-319") matched = true;
    });
    engine.OnEvent(second);
    CHECK(matched);
}
} // namespace

int main(int argc, char** argv) {
    using Test = void (*)();
    const Test tests[] = {
        RunPrivilegeEscalationDetectorTests, TestReliableInstance,
        TestInstanceScopeIsolation, TestWeakIdentityDoesNotAccumulate,
        TestInvalidScopeDoesNotAccumulate, TestZeroPidIsSingleEventOnly,
        TestCreationIdentity, TestInvalidTimes, TestOutOfOrderDoesNotAddEvidence,
        TestSignalsExpireIndividually, TestWindowBoundaryAndZeroWindow,
        TestCapacityEvictsOldest, TestInvalidEventDoesNotPurge, TestStrictAccessMask,
        TestRealSysmon7Contract, TestNormalAndEmptyDllPaths,
        TestNativeAccessAndPrivilegeFields, TestPrivilegeNamesAreWholeTokens};
    int failures = 0;
    for (const auto test : tests) {
        try { test(); }
        catch (const std::exception& error) {
            std::fprintf(stderr, "%s\n", error.what());
            ++failures;
        }
    }
    if (argc > 1) {
        try { TestProductionRule(argv[1]); }
        catch (const std::exception& error) {
            std::fprintf(stderr, "%s\n", error.what());
            ++failures;
        }
    }
    std::printf("Privilege escalation contract: %zu groups, %d failed\n",
                sizeof(tests) / sizeof(tests[0]) + (argc > 1 ? 1 : 0), failures);
    return failures == 0 ? 0 : 1;
}
