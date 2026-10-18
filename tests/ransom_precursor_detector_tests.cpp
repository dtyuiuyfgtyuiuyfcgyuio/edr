/*
 * ransom_precursor_detector_tests.cpp - Unit tests for
 * ClassifyRansomPrecursor and RansomPrecursorDetector (EDR-257).
 */
#include "ransom_precursor_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "ransom_precursor_detector.h"
#include "rule_engine.h"

namespace {

#define RP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "ransom precursor detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

edr::Event Precursor(const char* image, const char* command, uint64_t ts) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts;
    event.pid = 100;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kCommandLine] = command;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

void TestClassifier() {
    RP_CHECK(edr::ClassifyRansomPrecursor(
                 "C:\\Windows\\System32\\vssadmin.exe",
                 "vssadmin delete shadows /all /quiet") == "shadow_delete");
    RP_CHECK(edr::ClassifyRansomPrecursor(
                 "vssadmin.exe", "vssadmin list shadows").empty());
    RP_CHECK(edr::ClassifyRansomPrecursor(
                 "C:\\Windows\\System32\\bcdedit.exe",
                 "bcdedit /set {default} recoveryenabled no") ==
             "recovery_disable");
    RP_CHECK(edr::ClassifyRansomPrecursor(
                 "wevtutil.exe", "wevtutil cl Security") == "log_clear");
    RP_CHECK(edr::ClassifyRansomPrecursor(
                 "wevtutil.exe", "wevtutil collect Security").empty());
    RP_CHECK(edr::ClassifyRansomPrecursor(
                 "fsutil.exe", "fsutil usn deletejournal /d C:") ==
             "usn_delete");
    RP_CHECK(edr::ClassifyRansomPrecursor(
                 "cipher.exe", "cipher /w:C:\\temp") == "free_space_wipe");
    RP_CHECK(edr::ClassifyRansomPrecursor(
                 "wbadmin.exe", "wbadmin delete catalog -quiet") ==
             "backup_delete");
}

void TestSingleTechniqueNoStamp() {
    edr::RansomPrecursorDetector detector(true, 180, 256, 2, 300);
    edr::Event event = Precursor("C:\\Windows\\System32\\vssadmin.exe",
                                 "vssadmin delete shadows /all /quiet",
                                 100000000000ULL);
    detector.Enrich(event);
    RP_CHECK(!HasField(event, edr::field::kRansomPrecursorScore));
    RP_CHECK(detector.StateCount() == 1);
}

void TestTwoTechniquesStamp() {
    edr::RansomPrecursorDetector detector(true, 180, 256, 2, 300);
    const uint64_t base = 200000000000ULL;
    edr::Event first = Precursor("C:\\Windows\\System32\\vssadmin.exe",
                                 "vssadmin delete shadows /all /quiet",
                                 base);
    detector.Enrich(first);
    edr::Event second = Precursor("C:\\Windows\\System32\\bcdedit.exe",
                                  "bcdedit /set {default} recoveryenabled no",
                                  base + 10000000ULL);
    detector.Enrich(second);
    RP_CHECK(HasField(second, edr::field::kRansomPrecursorScore));
    RP_CHECK(second.fields.at(edr::field::kRansomPrecursorCount) == "2");
    RP_CHECK(second.fields.at(edr::field::kRansomPrecursorScore) == "70");
    RP_CHECK(second.fields.at(edr::field::kRansomPrecursorTechniques)
                 .find("recovery_disable") != std::string::npos);
    RP_CHECK(second.fields.at(edr::field::kRansomPrecursorTechniques)
                 .find("shadow_delete") != std::string::npos);
}

void TestTimeRollbackRejected() {
    edr::RansomPrecursorDetector detector(true, 180, 256, 2, 300);
    const uint64_t base = 300000000000ULL;
    edr::Event first = Precursor("C:\\Windows\\System32\\vssadmin.exe",
                                 "vssadmin delete shadows /all /quiet",
                                 base);
    detector.Enrich(first);
    edr::Event late = Precursor("C:\\Windows\\System32\\bcdedit.exe",
                                "bcdedit /set {default} recoveryenabled no",
                                base - 1000ULL);
    detector.Enrich(late);
    RP_CHECK(!HasField(late, edr::field::kRansomPrecursorScore));
}

void TestWindowExpiry() {
    edr::RansomPrecursorDetector detector(true, 60, 256, 2, 0);
    const uint64_t base = 400000000000ULL;
    const uint64_t later = base + 61ULL * 10000000ULL;
    edr::Event first = Precursor("C:\\Windows\\System32\\vssadmin.exe",
                                 "vssadmin delete shadows /all /quiet",
                                 base);
    detector.Enrich(first);
    edr::Event second = Precursor("C:\\Windows\\System32\\bcdedit.exe",
                                  "bcdedit /set {default} recoveryenabled no",
                                  later);
    detector.Enrich(second);
    RP_CHECK(!HasField(second, edr::field::kRansomPrecursorScore));
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });
    edr::RansomPrecursorDetector detector(true, 180, 256, 2, 300);
    const uint64_t base = 500000000000ULL;
    edr::Event first = Precursor("C:\\Windows\\System32\\vssadmin.exe",
                                 "vssadmin delete shadows /all /quiet",
                                 base);
    detector.Enrich(first);
    engine.OnEvent(first);
    edr::Event second = Precursor("C:\\Windows\\System32\\wevtutil.exe",
                                  "wevtutil cl Security",
                                  base + 10000000ULL);
    detector.Enrich(second);
    engine.OnEvent(second);
    RP_CHECK(std::find(hits.begin(), hits.end(), "EDR-257") != hits.end());
}

} // namespace

void RunRansomPrecursorDetectorTests() {
    TestClassifier();
    TestSingleTechniqueNoStamp();
    TestTwoTechniquesStamp();
    TestTimeRollbackRejected();
    TestWindowExpiry();
    TestProductionRule();
}
