/*
 * privileged_group_detector_tests.cpp - Unit tests for
 * PrivilegedGroupDetector, the 4728/4732/4756 parser cases, and the
 * production rule it feeds (EDR-334).
 */
#include "privileged_group_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "privileged_group_detector.h"
#include "rule_engine.h"
#include "security_log_parser.h"

namespace {

#define PG_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "privileged group detector test failed at line " +
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

constexpr uint64_t kBase = 1000000000ULL;
constexpr uint64_t kSecond = 10000000ULL;

edr::Event GroupAdd(const char* actorUser, const char* group,
                    const char* member, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_ACCOUNT_CHANGE;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "ACCOUNT_CHANGE";
    ev.fields[edr::field::kOperationType] = "GROUP_MEMBER_ADD";
    ev.fields[edr::field::kSubjectUserName] = actorUser;
    ev.fields[edr::field::kSubjectDomainName] = "CORP";
    if (group != nullptr && *group != '\0')
        ev.fields[edr::field::kTargetGroupName] = group;
    if (member != nullptr && *member != '\0')
        ev.fields[edr::field::kTargetUser] = member;
    return ev;
}

std::wstring SecXml4728() {
    return L"<Event><System><EventID>4732</EventID>"
           L"<TimeCreated SystemTime='2026-08-21T10:00:00.1234567Z'/>"
           L"</System><EventData>"
           L"<Data Name='SubjectUserSid'>S-1-5-21-500</Data>"
           L"<Data Name='SubjectUserName'>eviladmin</Data>"
           L"<Data Name='SubjectDomainName'>CORP</Data>"
           L"<Data Name='MemberSid'>S-1-5-21-1000</Data>"
           L"<Data Name='MemberName'>backdoor_svc</Data>"
           L"<Data Name='TargetDomainName'>BUILTIN</Data>"
           L"<Data Name='TargetUserName'>Administrators</Data>"
           L"</EventData></Event>";
}

void TestParserEmitsGroupMemberAdd() {
    edr::Event event;
    PG_CHECK(edr::ParseSecurityLogXml(SecXml4728().c_str(), event));
    PG_CHECK(event.type == EDR_EVT_ACCOUNT_CHANGE);
    PG_CHECK(event.fields.at(edr::field::kOperationType) ==
             "GROUP_MEMBER_ADD");
    PG_CHECK(event.fields.at(edr::field::kTargetGroupName) ==
             "Administrators");
    PG_CHECK(event.fields.at(edr::field::kTargetUser) == "backdoor_svc");
    PG_CHECK(event.fields.at(edr::field::kSubjectUserName) == "eviladmin");
}

void TestSingleSensitiveAddSuspicious() {
    edr::PrivilegedGroupDetector detector(true, 600, 1024);
    edr::Event ev =
        GroupAdd("bob", "Administrators", "backdoor_svc", kBase);
    detector.Enrich(ev);
    PG_CHECK(ev.fields.at(edr::field::kPrivilegedGroupScore) == "60");
    PG_CHECK(ev.fields.at(edr::field::kPrivilegedGroupVerdict) ==
             "SUSPICIOUS");
    PG_CHECK(ev.fields.at(edr::field::kPrivilegedGroupCount) == "1");
    PG_CHECK(ev.fields.at(edr::field::kPrivilegedGroupSensitiveAdds) == "1");
}

void TestTwoSensitiveAddsMalicious() {
    edr::PrivilegedGroupDetector detector(true, 600, 1024);
    detector.Enrich(GroupAdd("bob", "Domain Admins", "a", kBase));
    edr::Event ev =
        GroupAdd("bob", "Backup Operators", "b", kBase + kSecond);
    detector.Enrich(ev);
    /* 60 + 20 (second sensitive add) = 80. */
    PG_CHECK(ev.fields.at(edr::field::kPrivilegedGroupScore) == "80");
    PG_CHECK(ev.fields.at(edr::field::kPrivilegedGroupVerdict) ==
             "MALICIOUS");
    PG_CHECK(ev.fields.at(edr::field::kPrivilegedGroupCount) == "2");
}

void TestNonSensitiveChurnStampedBelowBand() {
    edr::PrivilegedGroupDetector detector(true, 600, 1024);
    for (uint32_t i = 0; i < 2; ++i) {
        edr::Event quiet = GroupAdd("helpdesk", "IT Staff",
                                    ("u" + std::to_string(i)).c_str(),
                                    kBase + i * kSecond);
        detector.Enrich(quiet);
        PG_CHECK(quiet.fields.find(edr::field::kPrivilegedGroupScore) ==
                 quiet.fields.end());
    }
    edr::Event third = GroupAdd("helpdesk", "IT Staff", "u3",
                                kBase + 2 * kSecond);
    detector.Enrich(third);
    PG_CHECK(third.fields.at(edr::field::kPrivilegedGroupScore) == "30");
    PG_CHECK(third.fields.find(edr::field::kPrivilegedGroupVerdict) ==
             third.fields.end());
}

void TestMixedAddsEscalate() {
    edr::PrivilegedGroupDetector detector(true, 600, 1024);
    detector.Enrich(GroupAdd("bob", "IT Staff", "u1", kBase));
    detector.Enrich(GroupAdd("bob", "Remote Desktop Users", "u2",
                             kBase + kSecond));
    detector.Enrich(GroupAdd("bob", "IT Staff", "u3", kBase + 2 * kSecond));
    edr::Event last = GroupAdd("bob", "IT Staff", "u4",
                               kBase + 3 * kSecond);
    detector.Enrich(last);
    /* Sensitive add (60) + churn past 4 total adds (+10) = 70. */
    PG_CHECK(last.fields.at(edr::field::kPrivilegedGroupScore) == "70");
    PG_CHECK(last.fields.at(edr::field::kPrivilegedGroupVerdict) ==
             "SUSPICIOUS");
    PG_CHECK(last.fields.at(edr::field::kPrivilegedGroupCount) == "4");
}

void TestWindowExpiryReset() {
    edr::PrivilegedGroupDetector detector(true, 600, 1024);
    detector.Enrich(GroupAdd("bob", "Administrators", "x", kBase));
    edr::Event later = GroupAdd("bob", "Print Operators", "y",
                                kBase + 700 * kSecond);
    detector.Enrich(later);
    /* Window elapsed: state purged, single non-sensitive add stays silent. */
    PG_CHECK(later.fields.find(edr::field::kPrivilegedGroupScore) ==
             later.fields.end());
}

void TestMissingGroupSkipped() {
    edr::PrivilegedGroupDetector detector(true, 600, 1024);
    edr::Event ev = GroupAdd("bob", nullptr, "ghost", kBase);
    detector.Enrich(ev);
    PG_CHECK(ev.fields.find(edr::field::kPrivilegedGroupScore) ==
             ev.fields.end());
}

void TestWrongOperationIgnored() {
    edr::PrivilegedGroupDetector detector(true, 600, 1024);
    edr::Event ev = GroupAdd("bob", "Administrators", "x", kBase);
    ev.fields[edr::field::kOperationType] = "ACCOUNT_ENABLED";
    detector.Enrich(ev);
    PG_CHECK(ev.fields.find(edr::field::kPrivilegedGroupScore) ==
             ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::PrivilegedGroupDetector detector(false, 600, 1024);
    edr::Event ev =
        GroupAdd("bob", "Administrators", "x", kBase);
    detector.Enrich(ev);
    PG_CHECK(ev.fields.find(edr::field::kPrivilegedGroupScore) ==
             ev.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::PrivilegedGroupDetector detector(true, 600, 1024);
    detector.Enrich(
        GroupAdd("bob", "Administrators", "svc", kBase));
    edr::Event ev = GroupAdd("bob", "Domain Admins", "svc2",
                             kBase + kSecond);
    detector.Enrich(ev);
    engine.OnEvent(ev);
    PG_CHECK(Has(hits, "EDR-334"));
}

} // namespace

void RunPrivilegedGroupDetectorTests() {
    TestParserEmitsGroupMemberAdd();
    TestSingleSensitiveAddSuspicious();
    TestTwoSensitiveAddsMalicious();
    TestNonSensitiveChurnStampedBelowBand();
    TestMixedAddsEscalate();
    TestWindowExpiryReset();
    TestMissingGroupSkipped();
    TestWrongOperationIgnored();
    TestDisabledNoStamp();
    TestProductionRule();
}
