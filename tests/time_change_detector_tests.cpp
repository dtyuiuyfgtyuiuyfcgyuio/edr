/*
 * time_change_detector_tests.cpp - Unit tests for the 4616 security log
 * parser case, TimeChangeDetector, and the production rule it feeds
 * (EDR-333).
 */
#include "time_change_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"
#include "security_log_parser.h"
#include "time_change_detector.h"

namespace {

#define TC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "time change detector test failed at line " +
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

constexpr uint64_t kBase = 134000000000000000ULL;
constexpr uint64_t kSecond = 10000000ULL;

edr::Event TimeChange(uint64_t prevTicks, uint64_t newTicks,
                      uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_SYSTEM_TIME_CHANGE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "SYSTEM_TIME_CHANGE";
    if (prevTicks != 0)
        event.fields[edr::field::kTimeChangePrev100ns] =
            std::to_string(prevTicks);
    if (newTicks != 0)
        event.fields[edr::field::kTimeChangeNew100ns] =
            std::to_string(newTicks);
    return event;
}

std::wstring SecXml4616(const wchar_t* previousTime,
                        const wchar_t* newTime) {
    std::wstring data =
        L"<Data Name='SubjectUserSid'>S-1-5-21-500</Data>"
        L"<Data Name='SubjectUserName'>Administrator</Data>"
        L"<Data Name='SubjectDomainName'>DESKTOP-TEST</Data>";
    if (previousTime != nullptr)
        data += std::wstring(L"<Data Name='PreviousTime'>") + previousTime +
                L"</Data>";
    if (newTime != nullptr)
        data += std::wstring(L"<Data Name='NewTime'>") + newTime +
                L"</Data>";
    return L"<Event><System><EventID>4616</EventID>"
           L"<TimeCreated SystemTime='2026-07-30T10:00:00.1234567Z'/>"
           L"</System><EventData>" + data + L"</EventData></Event>";
}

void TestParserEmitsTimeChangeEvent() {
    edr::Event event;
    TC_CHECK(edr::ParseSecurityLogXml(SecXml4616(
        std::to_wstring(kBase).c_str(),
        std::to_wstring(kBase + kSecond).c_str()).c_str(), event));
    TC_CHECK(event.type == EDR_EVT_SYSTEM_TIME_CHANGE);
    TC_CHECK(event.fields.at(edr::field::kSecurityEventId) == "4616");
    TC_CHECK(event.fields.at(edr::field::kOperationType) == "TIME_CHANGE");
    TC_CHECK(event.fields.at(edr::field::kSubjectUserName) ==
             "Administrator");
    TC_CHECK(event.fields.at(edr::field::kSubjectDomainName) ==
             "DESKTOP-TEST");
    TC_CHECK(event.fields.at(edr::field::kTimeChangePrev100ns) ==
             std::to_string(kBase));
    TC_CHECK(event.fields.at(edr::field::kTimeChangeNew100ns) ==
             std::to_string(kBase + kSecond));
}

void TestParserAcceptsHexFiletime() {
    const uint64_t value = 0x01DC123456789ABCLL;
    edr::Event event;
    wchar_t buf[32];
    swprintf_s(buf, L"0x%llx", static_cast<unsigned long long>(value));
    TC_CHECK(edr::ParseSecurityLogXml(SecXml4616(buf, buf).c_str(),
                                      event));
    TC_CHECK(event.fields.at(edr::field::kTimeChangePrev100ns) ==
             std::to_string(value));
}

void TestParserSkipsGarbageTimeValues() {
    edr::Event event;
    TC_CHECK(edr::ParseSecurityLogXml(SecXml4616(
        L"garbage",
        std::to_wstring(kBase).c_str()).c_str(), event));
    TC_CHECK(event.type == EDR_EVT_SYSTEM_TIME_CHANGE);
    TC_CHECK(event.fields.find(edr::field::kTimeChangePrev100ns) ==
             event.fields.end());
    TC_CHECK(event.fields.at(edr::field::kTimeChangeNew100ns) ==
             std::to_string(kBase));
}

void TestNtpCorrectionIgnored() {
    edr::TimeChangeDetector detector(true, 300, 1024, 5, 86400);
    edr::Event ev = TimeChange(kBase, kBase + 2 * kSecond, kBase);
    detector.Enrich(ev);
    TC_CHECK(ev.fields.find(edr::field::kTimeChangeScore) == ev.fields.end());
}

void TestRollbackSuspicious() {
    edr::TimeChangeDetector detector(true, 300, 1024, 5, 86400);
    edr::Event ev = TimeChange(kBase, kBase - 60 * kSecond, kBase);
    detector.Enrich(ev);
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeScore) == "65");
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeVerdict) == "SUSPICIOUS");
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeMechanisms) ==
             "time_rollback");
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeDeltaSeconds) == "-60");
}

void TestLargeForwardJumpBelowAlert() {
    edr::TimeChangeDetector detector(true, 300, 1024, 5, 86400);
    edr::Event ev = TimeChange(
        kBase, kBase + (86400ULL + 30ULL) * kSecond, kBase);
    detector.Enrich(ev);
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeScore) == "45");
    TC_CHECK(ev.fields.find(edr::field::kTimeChangeVerdict) ==
             ev.fields.end());
}

void TestModerateShiftStampedNoVerdict() {
    edr::TimeChangeDetector detector(true, 300, 1024, 5, 86400);
    edr::Event ev = TimeChange(kBase, kBase + 3600 * kSecond, kBase);
    detector.Enrich(ev);
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeScore) == "30");
    TC_CHECK(ev.fields.find(edr::field::kTimeChangeVerdict) ==
             ev.fields.end());
}

void TestTwoRollbacksMalicious() {
    edr::TimeChangeDetector detector(true, 300, 1024, 5, 86400);
    detector.Enrich(TimeChange(kBase, kBase - 60 * kSecond, kBase));
    edr::Event ev = TimeChange(kBase - 50 * kSecond,
                               kBase - 110 * kSecond, kBase + kSecond);
    detector.Enrich(ev);
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeScore) == "80");
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeVerdict) == "MALICIOUS");
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeCount) == "2");
}

void TestWindowExpiryResets() {
    edr::TimeChangeDetector detector(true, 300, 1024, 5, 86400);
    detector.Enrich(TimeChange(kBase, kBase - 60 * kSecond, kBase));
    edr::Event ev = TimeChange(kBase, kBase - 60 * kSecond,
                               kBase + 310 * kSecond);
    detector.Enrich(ev);
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeScore) == "65");
    TC_CHECK(ev.fields.at(edr::field::kTimeChangeCount) == "1");
}

void TestMissingFieldsIgnored() {
    edr::TimeChangeDetector detector(true, 300, 1024, 5, 86400);
    edr::Event ev = TimeChange(0, 0, kBase); /* builder skips fields */
    detector.Enrich(ev);
    TC_CHECK(ev.fields.find(edr::field::kTimeChangeScore) == ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::TimeChangeDetector detector(false, 300, 1024, 5, 86400);
    edr::Event ev = TimeChange(kBase, kBase - 60 * kSecond, kBase);
    detector.Enrich(ev);
    TC_CHECK(ev.fields.find(edr::field::kTimeChangeScore) == ev.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::TimeChangeDetector detector(true, 300, 1024, 5, 86400);
    detector.Enrich(TimeChange(kBase, kBase - 60 * kSecond, kBase));
    edr::Event ev = TimeChange(kBase - 50 * kSecond,
                               kBase - 110 * kSecond, kBase + kSecond);
    detector.Enrich(ev);
    engine.OnEvent(ev);
    TC_CHECK(Has(hits, "EDR-333"));
}

} // namespace

void RunTimeChangeDetectorTests() {
    TestParserEmitsTimeChangeEvent();
    TestParserAcceptsHexFiletime();
    TestParserSkipsGarbageTimeValues();
    TestNtpCorrectionIgnored();
    TestRollbackSuspicious();
    TestLargeForwardJumpBelowAlert();
    TestModerateShiftStampedNoVerdict();
    TestTwoRollbacksMalicious();
    TestWindowExpiryResets();
    TestMissingFieldsIgnored();
    TestDisabledNoStamp();
    TestProductionRule();
}
