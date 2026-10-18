/*
 * webshell_detector_tests.cpp - Unit tests for WebshellDetector and the
 * production rule it feeds (EDR-329).
 */
#include "webshell_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"
#include "webshell_detector.h"

namespace {

#define WS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "webshell detector test failed at line " +
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

edr::Event FileCreate(const std::string& path, const std::string& image,
                      uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kFilePath] = path;
    if (!image.empty()) event.fields[edr::field::kImage] = image;
    return event;
}

void TestSuspiciousNameMalicious() {
    edr::WebshellDetector detector(true, 1024, 300);
    const uint64_t base = 1000000000ULL;
    edr::Event event = FileCreate("C:\\inetpub\\wwwroot\\cmd.php", "", base);
    detector.Enrich(event);
    WS_CHECK(event.fields.at(edr::field::kWebshellScore) == "85");
    WS_CHECK(event.fields.at(edr::field::kWebshellVerdict) == "MALICIOUS");
    WS_CHECK(event.fields.at(edr::field::kWebshellExtension) == "php");
    WS_CHECK(event.fields.at(edr::field::kWebshellReasons).find(
                 "suspicious_name") != std::string::npos);
    WS_CHECK(event.fields.at(edr::field::kWebshellPath) ==
             "C:\\inetpub\\wwwroot\\cmd.php");
}

void TestNonWebServerWriterSuspicious() {
    edr::WebshellDetector detector(true, 1024, 300);
    const uint64_t base = 2000000000ULL;
    edr::Event event = FileCreate("C:\\inetpub\\wwwroot\\photo.aspx",
                                  "C:\\Windows\\System32\\cmd.exe", base);
    detector.Enrich(event);
    WS_CHECK(event.fields.at(edr::field::kWebshellScore) == "65");
    WS_CHECK(event.fields.at(edr::field::kWebshellVerdict) == "SUSPICIOUS");
    WS_CHECK(event.fields.at(edr::field::kWebshellReasons).find(
                 "non_webserver_writer") != std::string::npos);
}

void TestWebServerWriterNoStamp() {
    edr::WebshellDetector detector(true, 1024, 300);
    const uint64_t base = 3000000000ULL;
    edr::Event event = FileCreate("C:\\inetpub\\wwwroot\\photo.aspx",
                                  "C:\\Windows\\System32\\w3wp.exe", base);
    detector.Enrich(event);
    WS_CHECK(event.fields.find(edr::field::kWebshellScore) ==
             event.fields.end());
}

void TestNotWebRootNoStamp() {
    edr::WebshellDetector detector(true, 1024, 300);
    const uint64_t base = 4000000000ULL;
    edr::Event event = FileCreate("C:\\Windows\\System32\\cmd.php", "", base);
    detector.Enrich(event);
    WS_CHECK(event.fields.find(edr::field::kWebshellScore) ==
             event.fields.end());
}

void TestNotScriptNoStamp() {
    edr::WebshellDetector detector(true, 1024, 300);
    const uint64_t base = 5000000000ULL;
    edr::Event event =
        FileCreate("C:\\inetpub\\wwwroot\\readme.txt", "", base);
    detector.Enrich(event);
    WS_CHECK(event.fields.find(edr::field::kWebshellScore) ==
             event.fields.end());
}

void TestDedupSuppressesRepeat() {
    edr::WebshellDetector detector(true, 1024, 600);
    const uint64_t base = 6000000000ULL;
    edr::Event first = FileCreate("C:\\inetpub\\wwwroot\\cmd.php", "", base);
    detector.Enrich(first);
    WS_CHECK(first.fields.count(edr::field::kWebshellScore) == 1);
    edr::Event second =
        FileCreate("C:\\inetpub\\wwwroot\\cmd.php", "", base + 10000000ULL);
    detector.Enrich(second);
    WS_CHECK(second.fields.find(edr::field::kWebshellScore) ==
             second.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::WebshellDetector detector(true, 1024, 300);
    const uint64_t base = 7000000000ULL;
    edr::Event event = FileCreate("C:\\inetpub\\wwwroot\\shell.php", "", base);
    detector.Enrich(event);
    engine.OnEvent(event);
    WS_CHECK(Has(hits, "EDR-329"));
}

} // namespace

void RunWebshellDetectorTests() {
    TestSuspiciousNameMalicious();
    TestNonWebServerWriterSuspicious();
    TestWebServerWriterNoStamp();
    TestNotWebRootNoStamp();
    TestNotScriptNoStamp();
    TestDedupSuppressesRepeat();
    TestProductionRule();
}
