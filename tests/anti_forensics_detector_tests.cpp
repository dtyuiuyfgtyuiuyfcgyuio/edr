/*
 * anti_forensics_detector_tests.cpp - Unit tests for AntiForensicsDetector
 * and the production rule it feeds (EDR-332).
 */
#include "anti_forensics_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "anti_forensics_detector.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"

namespace {

#define AF_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "anti-forensics detector test failed at line " +
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

edr::Event AuditLog(const char* eventId, const char* subjectUser,
                    const char* subjectDomain, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_AUDIT_LOG;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "AUDIT_LOG";
    event.fields[edr::field::kAuditLogEventId] = eventId;
    if (subjectUser != nullptr && *subjectUser != '\0')
        event.fields[edr::field::kSubjectUserName] = subjectUser;
    if (subjectDomain != nullptr && *subjectDomain != '\0')
        event.fields[edr::field::kSubjectDomainName] = subjectDomain;
    return event;
}

constexpr uint64_t kBase = 1000000000ULL;
constexpr uint64_t kSecond = 10000000ULL;

void TestSingleClearSuspicious() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    edr::Event ev =
        AuditLog("1102", "Administrator", "DESKTOP", kBase);
    detector.Enrich(ev);
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsScore) == "55");
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsCount) == "1");
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsMechanisms) ==
             "security_log_cleared");
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsVerdict) ==
             "SUSPICIOUS");
}

void TestAuditStopOnlyNoVerdict() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    edr::Event ev = AuditLog("1100", "SYSTEM", "NT AUTHORITY", kBase);
    detector.Enrich(ev);
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsScore) == "20");
    AF_CHECK(ev.fields.find(edr::field::kAntiForensicsVerdict) ==
             ev.fields.end());
}

void TestClearPlusStopMalicious() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    detector.Enrich(
        AuditLog("1100", "Administrator", "DESKTOP", kBase));
    edr::Event ev = AuditLog("1102", "Administrator", "DESKTOP",
                             kBase + kSecond);
    detector.Enrich(ev);
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsScore) == "75");
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsVerdict) ==
             "MALICIOUS");
}

void TestRepeatedClearsEscalate() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    detector.Enrich(AuditLog("1102", "admin", "", kBase));
    edr::Event ev =
        AuditLog("1102", "admin", "", kBase + kSecond);
    detector.Enrich(ev);
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsScore) == "80");
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsVerdict) ==
             "MALICIOUS");
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsCount) == "2");
}

void TestActorsIndependent() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    edr::Event clear = AuditLog("1102", "admin", "", kBase);
    detector.Enrich(clear);
    edr::Event stop =
        AuditLog("1100", "SYSTEM", "NT AUTHORITY", kBase + kSecond);
    detector.Enrich(stop);
    AF_CHECK(clear.fields.at(edr::field::kAntiForensicsScore) == "55");
    AF_CHECK(stop.fields.at(edr::field::kAntiForensicsScore) == "20");
}

void TestWindowExpiryReset() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    detector.Enrich(AuditLog("1102", "admin", "", kBase));
    /* Second clear after the window elapsed: state was purged. */
    edr::Event ev = AuditLog("1102", "admin", "",
                             kBase + 310 * kSecond);
    detector.Enrich(ev);
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsScore) == "55");
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsCount) == "1");
}

void TestUnknownEventIdIgnored() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    edr::Event ev = AuditLog("9999", "admin", "", kBase);
    detector.Enrich(ev);
    AF_CHECK(ev.fields.find(edr::field::kAntiForensicsScore) ==
             ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::AntiForensicsDetector detector(false, 300, 1024);
    edr::Event ev = AuditLog("1102", "admin", "", kBase);
    detector.Enrich(ev);
    AF_CHECK(ev.fields.find(edr::field::kAntiForensicsScore) ==
             ev.fields.end());
}

void TestWrongTypeIgnored() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    edr::Event ev;
    ev.type = EDR_EVT_REG_WRITE;
    ev.ts100ns = kBase;
    ev.fields[edr::field::kType] = "REG_WRITE";
    ev.fields[edr::field::kAuditLogEventId] = "1102";
    detector.Enrich(ev);
    AF_CHECK(ev.fields.find(edr::field::kAntiForensicsScore) ==
             ev.fields.end());
}

void TestAuditPolicyChangeBelowBand() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    edr::Event ev = AuditLog("4719", "admin", "CORP", kBase);
    detector.Enrich(ev);
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsScore) == "30");
    AF_CHECK(ev.fields.find(edr::field::kAntiForensicsVerdict) ==
             ev.fields.end());
}

void TestClearPlusPolicyChangeMalicious() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    edr::Event clear = AuditLog("1102", "admin", "CORP", kBase);
    detector.Enrich(clear);
    edr::Event policy =
        AuditLog("4719", "admin", "CORP", kBase + kSecond);
    detector.Enrich(policy);
    /* Clear (55) + audit policy change (30) = 85. */
    AF_CHECK(policy.fields.at(edr::field::kAntiForensicsScore) == "85");
    AF_CHECK(policy.fields.at(edr::field::kAntiForensicsVerdict) ==
             "MALICIOUS");
}

void TestLogFullLowSignal() {
    edr::AntiForensicsDetector detector(true, 300, 1024);
    edr::Event ev = AuditLog("1104", "", "", kBase);
    detector.Enrich(ev);
    AF_CHECK(ev.fields.at(edr::field::kAntiForensicsScore) == "15");
    AF_CHECK(ev.fields.find(edr::field::kAntiForensicsVerdict) ==
             ev.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::AntiForensicsDetector detector(true, 300, 1024);
    detector.Enrich(AuditLog("1102", "admin", "", kBase));
    edr::Event ev = AuditLog("1102", "admin", "", kBase + kSecond);
    detector.Enrich(ev);
    engine.OnEvent(ev);
    AF_CHECK(Has(hits, "EDR-332"));
}

} // namespace

void RunAntiForensicsDetectorTests() {
    TestSingleClearSuspicious();
    TestAuditStopOnlyNoVerdict();
    TestClearPlusStopMalicious();
    TestRepeatedClearsEscalate();
    TestActorsIndependent();
    TestWindowExpiryReset();
    TestUnknownEventIdIgnored();
    TestDisabledNoStamp();
    TestWrongTypeIgnored();
    TestAuditPolicyChangeBelowBand();
    TestClearPlusPolicyChangeMalicious();
    TestLogFullLowSignal();
    TestProductionRule();
}
