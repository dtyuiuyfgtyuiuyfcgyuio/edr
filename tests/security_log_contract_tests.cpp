/* Native Security EventData contracts, through production enrichers/rules. */
#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "rule_engine.h"
#include "security_log_parser.h"
#include "service_install_detector.h"
#include "time_change_detector.h"

namespace {

#define CHECK(expression) Check((expression), #expression, __LINE__)
void Check(bool result, const char* expression, int line) {
    if (!result) throw std::runtime_error(std::string(expression) +
        " (line " + std::to_string(line) + ")");
}

std::wstring Data(const wchar_t* name, const std::wstring& value) {
    return std::wstring(L"<Data Name='") + name + L"'>" + value + L"</Data>";
}

// System/Execution identifies the Security provider, not the audited subject.
std::wstring Xml(unsigned id, const std::wstring& data) {
    return L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        L"<System><Provider Name='Microsoft-Windows-Security-Auditing' "
        L"Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
        L"<EventID>" + std::to_wstring(id) + L"</EventID><Version>" +
        (id == 4616 ? L"1" : L"0") + L"</Version>"
        L"<Level>0</Level><Task>0</Task><Opcode>0</Opcode>"
        L"<Keywords>0x8020000000000000</Keywords>"
        L"<TimeCreated SystemTime='2026-10-20T10:00:00.1234567Z'/>"
        L"<EventRecordID>12345</EventRecordID><Correlation/>"
        L"<Execution ProcessID='888' ThreadID='999'/><Channel>Security</Channel>"
        L"<Computer>CONTRACT-HOST</Computer><Security/></System><EventData>" +
        data + L"</EventData></Event>";
}

std::wstring Subject() {
    return Data(L"SubjectUserSid", L"S-1-5-21-100-200-300-1001") +
        Data(L"SubjectUserName", L"native-user") +
        Data(L"SubjectDomainName", L"NATIVE-DOMAIN") +
        Data(L"SubjectLogonId", L"0x123456");
}

edr::Event Parse(unsigned id, const std::wstring& data) {
    edr::Event event;
    CHECK(edr::ParseSecurityLogXml(Xml(id, data), event));
    CHECK(event.source == "security_log");
    CHECK(event.fields.at(edr::field::kSource) == "security_log");
    CHECK(event.fields.at(edr::field::kSecurityEventId) == std::to_string(id));
    CHECK(event.pid == 0);
    CHECK(event.ppid == 0);
    CHECK(event.fields.count(edr::field::kPid) == 0);
    CHECK(event.fields.count(edr::field::kPpid) == 0);
    return event;
}

bool Hits(edr::RuleEngine& engine, const edr::Event& event, const char* ruleId) {
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });
    engine.OnEvent(event);
    engine.SetAlertCallback({});
    return std::find(hits.begin(), hits.end(), ruleId) != hits.end();
}

const wchar_t* kMaliciousService =
    L"C:\\Users\\Public\\powershell.exe -enc aGVsbG8=";
const wchar_t* kBenignService = L"C:\\Windows\\System32\\svchost.exe -k netsvcs";

std::wstring Service(const std::wstring& path) {
    return Subject() + Data(L"ServiceName", L"NativeContractSvc") +
        Data(L"ServiceFileName", path) + Data(L"ServiceType", L"0x10") +
        Data(L"ServiceStartType", L"2") +
        Data(L"ServiceAccount", L"LocalSystem");
}

void NativeServiceReachesRule(edr::RuleEngine& engine) {
    auto event = Parse(4697, Service(kMaliciousService));
    CHECK(event.type == EDR_EVT_SERVICE_INSTALL);
    CHECK(event.fields.at(edr::field::kServiceImagePath) ==
        "C:\\Users\\Public\\powershell.exe -enc aGVsbG8=");
    edr::ServiceInstallDetector detector(true);
    detector.Enrich(event);
    CHECK(event.fields.at(edr::field::kSvcInstallScore) == "85");
    CHECK(Hits(engine, event, "EDR-347"));
}

void NativeServiceWinsConflict(edr::RuleEngine& engine) {
    auto event = Parse(4697, Service(kBenignService) +
        Data(L"ImagePath", kMaliciousService) + Data(L"Source", L"sysmon"));
    CHECK(event.fields.at(edr::field::kServiceImagePath) ==
        "C:\\Windows\\System32\\svchost.exe -k netsvcs");
    edr::ServiceInstallDetector detector(true);
    detector.Enrich(event);
    CHECK(event.fields.count(edr::field::kSvcInstallScore) == 0);
    CHECK(!Hits(engine, event, "EDR-347"));
}

void MissingNativeServiceHasNoAlias(edr::RuleEngine& engine) {
    auto event = Parse(4697, Subject() + Data(L"ImagePath", kMaliciousService));
    CHECK(event.fields.count(edr::field::kServiceImagePath) == 0);
    edr::ServiceInstallDetector detector(true);
    detector.Enrich(event);
    CHECK(!Hits(engine, event, "EDR-347"));
    event = Parse(4697, Service(L"") + Data(L"ImagePath", kMaliciousService));
    detector.Enrich(event);
    CHECK(event.fields.count(edr::field::kServiceImagePath) == 0);
    CHECK(!Hits(engine, event, "EDR-347"));
}

edr::Event Time(const std::wstring& previous, const std::wstring& next) {
    return Parse(4616, Subject() + Data(L"PreviousTime", previous) +
        Data(L"NewTime", next) + Data(L"ProcessId", L"0x1234") +
        Data(L"ProcessName", L"C:\\Windows\\System32\\svchost.exe"));
}

void NativeTimeReachesRule(edr::RuleEngine& engine) {
    auto event = Time(L"2026-10-20T10:00:00.1234567Z",
        L"2026-10-20T09:50:00.1234567Z");
    CHECK(event.fields.at(edr::field::kTimeChangePrev100ns) ==
        "134369640001234567");
    CHECK(event.fields.at(edr::field::kTimeChangeNew100ns) ==
        "134369634001234567");
    edr::TimeChangeDetector detector(true, 600, 8, 2, 3600);
    detector.Enrich(event);
    CHECK(event.fields.at(edr::field::kTimeChangeDeltaSeconds) == "-600");
    CHECK(event.fields.at(edr::field::kTimeChangeScore) == "65");
    CHECK(Hits(engine, event, "EDR-333"));
}

void NineDigitFractionKeeps100ns(edr::RuleEngine& engine) {
    auto event = Time(L"2026-10-20T10:00:00.123456789Z",
        L"2026-10-20T09:50:00.123456799Z");
    CHECK(event.fields.at(edr::field::kTimeChangePrev100ns) ==
        "134369640001234567");
    CHECK(event.fields.at(edr::field::kTimeChangeNew100ns) ==
        "134369634001234567");
    edr::TimeChangeDetector detector(true, 600, 8, 2, 3600);
    detector.Enrich(event);
    CHECK(Hits(engine, event, "EDR-333"));
}

void NativeTimeFractionFormats(edr::RuleEngine&) {
    for (const wchar_t* time : {L"2026-10-20T10:00:00Z",
         L"2026-10-20T10:00:00.0Z", L"2026-10-20T10:00:00.000Z",
         L"2026-10-20T10:00:00.000000000Z"}) {
        const auto event = Time(time, time);
        CHECK(event.fields.at(edr::field::kTimeChangePrev100ns) == "134369640000000000");
    }
    auto event = Time(L"1601-01-01T00:00:00Z", L"1601-01-01T00:00:00.0000001Z");
    CHECK(event.fields.at(edr::field::kTimeChangePrev100ns) == "0");
    CHECK(event.fields.at(edr::field::kTimeChangeNew100ns) == "1");
}

void NativeTimeNtpAndMissingStayQuiet(edr::RuleEngine& engine) {
    auto event = Time(L"2026-10-20T10:00:00.0000000Z",
        L"2026-10-20T10:00:01.0000000Z");
    CHECK(event.fields.count(edr::field::kTimeChangePrev100ns) == 1);
    edr::TimeChangeDetector detector(true, 600, 8, 2, 3600);
    detector.Enrich(event);
    CHECK(event.fields.count(edr::field::kTimeChangeScore) == 0);
    CHECK(!Hits(engine, event, "EDR-333"));
    event = Parse(4616, Subject() +
        Data(L"NewTime", L"2026-10-20T09:50:00.0000000Z"));
    detector.Enrich(event);
    CHECK(event.fields.count(edr::field::kTimeChangeScore) == 0);
    CHECK(!Hits(engine, event, "EDR-333"));
}

void InvalidTimesStayUnstamped(edr::RuleEngine& engine) {
    const wchar_t* invalid[] = {
        L"2026-02-29T10:00:00.0000000Z", L"2024-02-30T10:00:00.0000000Z",
        L"2026-04-31T10:00:00.0000000Z", L"2026-13-01T10:00:00.0000000Z",
        L"2026-00-20T10:00:00.0000000Z", L"2026-10-00T10:00:00.0000000Z",
        L"2026-10-20T24:00:00.0000000Z", L"2026-10-20T10:60:00.0000000Z",
        L"2026-10-20T10:00:60.0000000Z", L"2026-10-20T10:00:00.1234567x",
        L"2026-10-20T10:00:00.1234567Zjunk", L"2026-10-20T10:00:00.1234567+00:00",
        L"2026-10-20T10:00:00.1234567a9Z", L"2026-10-20 10:00:00.1234567Z",
        L"2026-10-20T10:00:00.Z", L"2026-10-20T10:00:00.1234567890Z",
        L"", L"-1", L"18446744073709551616"
    };
    for (const auto* bad : invalid) {
        for (bool previousInvalid : {false, true}) {
            auto event = Time(previousInvalid ? bad : L"2026-10-20T10:00:00.0000000Z",
                previousInvalid ? L"2026-10-20T09:50:00.0000000Z" : bad);
            CHECK(event.fields.count(previousInvalid ? edr::field::kTimeChangePrev100ns :
                edr::field::kTimeChangeNew100ns) == 0);
            edr::TimeChangeDetector detector(true, 600, 8, 2, 3600);
            detector.Enrich(event);
            CHECK(event.fields.count(edr::field::kTimeChangeScore) == 0);
            CHECK(!Hits(engine, event, "EDR-333"));
        }
    }
}

void LeapDayAndNumericCompatibility(edr::RuleEngine& engine) {
    auto event = Time(L"2024-02-29T10:00:00.0000000Z",
        L"2024-02-29T09:50:00.0000000Z");
    CHECK(event.fields.count(edr::field::kTimeChangePrev100ns) == 1);
    edr::TimeChangeDetector leap(true, 600, 8, 2, 3600);
    leap.Enrich(event);
    CHECK(Hits(engine, event, "EDR-333"));
    event = Time(L"134369640000000000", L"134369634000000000");
    edr::TimeChangeDetector decimal(true, 600, 8, 2, 3600);
    decimal.Enrich(event);
    CHECK(event.fields.at(edr::field::kTimeChangeDeltaSeconds) == "-600");
    CHECK(Hits(engine, event, "EDR-333"));
    event = Time(L"0x01DC420A410C1000", L"0x01DC420A1D48CA00");
    CHECK(event.fields.at(edr::field::kTimeChangePrev100ns) == "134054700722688000");
    CHECK(event.fields.at(edr::field::kTimeChangeNew100ns) == "134054700122688000");
    edr::TimeChangeDetector hex(true, 600, 8, 2, 3600);
    hex.Enrich(event);
    CHECK(Hits(engine, event, "EDR-333"));
}

void NativeElevatedSubjectIsAccount(edr::RuleEngine&) {
    auto event = Parse(4672, Subject() +
        Data(L"PrivilegeList", L"SeDebugPrivilege\r\nSeBackupPrivilege"));
    CHECK(event.type == EDR_EVT_LOGON);
    CHECK(event.fields.at(edr::field::kOperationType) == "LOGON_ELEVATED");
    CHECK(event.fields.at(edr::field::kTargetUser) == "native-user");
    CHECK(event.fields.at(edr::field::kTargetDomain) == "NATIVE-DOMAIN");
    CHECK(event.fields.at(edr::field::kTargetUserSid) == "S-1-5-21-100-200-300-1001");
    CHECK(event.fields.at(edr::field::kLogonId) == "0x123456");
    CHECK(event.fields.at(edr::field::kSubjectUserName) == "native-user");
    CHECK(event.fields.at(edr::field::kPrivileges) == "SeDebugPrivilege\r\nSeBackupPrivilege");
}

void ElevatedSubjectWinsConflicts(edr::RuleEngine&) {
    auto event = Parse(4672, Subject() + Data(L"TargetUserName", L"decoy") +
        Data(L"TargetDomainName", L"DECOY") + Data(L"TargetLogonId", L"0x999") +
        Data(L"TargetUserSid", L"S-1-5-18") + Data(L"Source", L"sysmon"));
    CHECK(event.fields.at(edr::field::kTargetUser) == "native-user");
    CHECK(event.fields.at(edr::field::kTargetDomain) == "NATIVE-DOMAIN");
    CHECK(event.fields.at(edr::field::kTargetUserSid) == "S-1-5-21-100-200-300-1001");
    CHECK(event.fields.at(edr::field::kLogonId) == "0x123456");
    event = Parse(4672, Data(L"TargetUserName", L"decoy") +
        Data(L"TargetDomainName", L"DECOY") + Data(L"TargetLogonId", L"0x999"));
    CHECK(event.fields.count(edr::field::kTargetUser) == 0);
    CHECK(event.fields.count(edr::field::kTargetDomain) == 0);
    CHECK(event.fields.count(edr::field::kLogonId) == 0);
}

void Logon4624RetainsTargetSemantics(edr::RuleEngine&) {
    auto event = Parse(4624, Subject() + Data(L"TargetUserName", L"target-user") +
        Data(L"TargetDomainName", L"TARGET") + Data(L"TargetLogonId", L"0x987") +
        Data(L"TargetUserSid", L"S-1-5-21-400-500-600-1002") +
        Data(L"LogonType", L"10"));
    CHECK(event.fields.at(edr::field::kTargetUser) == "target-user");
    CHECK(event.fields.at(edr::field::kTargetDomain) == "TARGET");
    CHECK(event.fields.at(edr::field::kLogonId) == "0x987");
    CHECK(event.fields.at(edr::field::kTargetUserSid) == "S-1-5-21-400-500-600-1002");
    CHECK(event.fields.at(edr::field::kSubjectUserName) == "native-user");
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: edr_security_log_contract_tests <production-rules.json>\n";
        return 2;
    }
    try {
        edr::RuleEngine engine;
        engine.LoadFromFile(argv[1]);
        struct Test { const char* name; void (*run)(edr::RuleEngine&); };
        const Test tests[] = {
            {"native service reaches EDR-347", NativeServiceReachesRule},
            {"native service wins conflicting ImagePath/source", NativeServiceWinsConflict},
            {"missing native service does not use alias", MissingNativeServiceHasNoAlias},
            {"native time reaches EDR-333", NativeTimeReachesRule},
            {"nine-digit fraction retains 100ns precision", NineDigitFractionKeeps100ns},
            {"native UTC fraction formats and epoch", NativeTimeFractionFormats},
            {"NTP and missing native time remain unscored", NativeTimeNtpAndMissingStayQuiet},
            {"invalid dates and formats remain unscored", InvalidTimesStayUnstamped},
            {"leap day and numeric FILETIME compatibility", LeapDayAndNumericCompatibility},
            {"4672 native subject is elevated account", NativeElevatedSubjectIsAccount},
            {"4672 subject wins target/source conflicts", ElevatedSubjectWinsConflicts},
            {"4624 retains target semantics", Logon4624RetainsTargetSemantics}
        };
        size_t failures = 0;
        for (const auto& test : tests) {
            try { test.run(engine); std::cout << "PASS " << test.name << '\n'; }
            catch (const std::exception& error) {
                ++failures;
                std::cerr << "FAIL " << test.name << ": " << error.what() << '\n';
            }
        }
        std::cout << "security native contracts: " << (std::size(tests) - failures)
            << '/' << std::size(tests) << " passed\n";
        return failures ? 1 : 0;
    } catch (const std::exception& error) {
        std::cerr << "setup error: " << error.what() << '\n';
        return 2;
    }
}
