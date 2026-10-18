/*
 * surveillance_detector_tests.cpp - Unit tests for SurveillanceDetector and
 * the production rule it feeds (EDR-328).
 */
#include "surveillance_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"
#include "surveillance_detector.h"

namespace {

#define SV_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "surveillance detector test failed at line " +
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

edr::Event SurveillanceEvent(uint16_t type, const char* typeName,
                             uint32_t pid, const std::string& image,
                             uint64_t ts100ns) {
    edr::Event event;
    event.type = type;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = typeName;
    if (!image.empty()) event.fields[edr::field::kImage] = image;
    return event;
}

edr::Event Clipboard(uint32_t pid, uint64_t ts100ns,
                     const std::string& image = "") {
    return SurveillanceEvent(EDR_EVT_CLIPBOARD_ACCESS, "CLIPBOARD_ACCESS",
                             pid, image, ts100ns);
}

edr::Event Keylogger(uint32_t pid, uint64_t ts100ns,
                     const std::string& image = "") {
    return SurveillanceEvent(EDR_EVT_KEYLOGGER, "KEYLOGGER", pid, image,
                             ts100ns);
}

edr::Event Wallpaper(uint32_t pid, uint64_t ts100ns,
                     const std::string& image = "") {
    return SurveillanceEvent(EDR_EVT_WALLPAPER_CHANGE, "WALLPAPER_CHANGE",
                             pid, image, ts100ns);
}

void TestTwoSignalsSuspicious() {
    edr::SurveillanceDetector detector(true, 600, 1024, 2);
    const uint64_t base = 1000000000ULL;
    detector.Enrich(Clipboard(100, base));
    edr::Event second = Keylogger(100, base + 10000000ULL);
    detector.Enrich(second);
    SV_CHECK(second.fields.at(edr::field::kSurveillanceScore) == "70");
    SV_CHECK(second.fields.at(edr::field::kSurveillanceCount) == "2");
    SV_CHECK(second.fields.at(edr::field::kSurveillanceSignals).find(
                 "clipboard_access") != std::string::npos);
    SV_CHECK(second.fields.at(edr::field::kSurveillanceSignals).find(
                 "keylogger") != std::string::npos);
    SV_CHECK(second.fields.at(edr::field::kSurveillanceVerdict) ==
             "SUSPICIOUS");
}

void TestThreeSignalsMalicious() {
    edr::SurveillanceDetector detector(true, 600, 1024, 2);
    const uint64_t base = 2000000000ULL;
    detector.Enrich(Clipboard(200, base));
    detector.Enrich(Keylogger(200, base + 10000000ULL));
    edr::Event third = Wallpaper(200, base + 20000000ULL);
    detector.Enrich(third);
    SV_CHECK(third.fields.at(edr::field::kSurveillanceScore) == "100");
    SV_CHECK(third.fields.at(edr::field::kSurveillanceVerdict) ==
             "MALICIOUS");
}

void TestSingleSignalNoStamp() {
    edr::SurveillanceDetector detector(true, 600, 1024, 2);
    const uint64_t base = 3000000000ULL;
    edr::Event event = Clipboard(300, base);
    detector.Enrich(event);
    SV_CHECK(event.fields.find(edr::field::kSurveillanceScore) ==
             event.fields.end());
}

void TestKnownToolMalicious() {
    edr::SurveillanceDetector detector(true, 600, 1024, 2);
    const uint64_t base = 4000000000ULL;
    edr::Event event =
        Clipboard(400, base, "C:\\Tools\\spyrix.exe");
    detector.Enrich(event);
    SV_CHECK(event.fields.at(edr::field::kSurveillanceScore) == "80");
    SV_CHECK(event.fields.at(edr::field::kSurveillanceVerdict) ==
             "MALICIOUS");
    SV_CHECK(event.fields.at(edr::field::kSurveillanceSignals).find(
                 "known_tool:spyrix") != std::string::npos);
}

void TestWindowExpiryResets() {
    edr::SurveillanceDetector detector(true, 1, 1024, 2);
    const uint64_t base = 5000000000ULL;
    detector.Enrich(Clipboard(500, base));
    edr::Event second = Keylogger(500, base + 11000000ULL);
    detector.Enrich(second);
    SV_CHECK(second.fields.find(edr::field::kSurveillanceScore) ==
             second.fields.end());
}

void TestDifferentPidsDoNotCorrelate() {
    edr::SurveillanceDetector detector(true, 600, 1024, 2);
    const uint64_t base = 6000000000ULL;
    edr::Event first = Clipboard(600, base);
    detector.Enrich(first);
    edr::Event second = Keylogger(601, base + 10000000ULL);
    detector.Enrich(second);
    SV_CHECK(first.fields.find(edr::field::kSurveillanceScore) ==
             first.fields.end());
    SV_CHECK(second.fields.find(edr::field::kSurveillanceScore) ==
             second.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::SurveillanceDetector detector(true, 600, 1024, 2);
    const uint64_t base = 7000000000ULL;
    detector.Enrich(Clipboard(700, base));
    edr::Event second = Keylogger(700, base + 10000000ULL);
    detector.Enrich(second);
    engine.OnEvent(second);
    SV_CHECK(Has(hits, "EDR-328"));
}

} // namespace

void RunSurveillanceDetectorTests() {
    TestTwoSignalsSuspicious();
    TestThreeSignalsMalicious();
    TestSingleSignalNoStamp();
    TestKnownToolMalicious();
    TestWindowExpiryResets();
    TestDifferentPidsDoNotCorrelate();
    TestProductionRule();
}
