/*
 * behavior_baseline_detector_tests.cpp - Unit, config, and production-rule
 * coverage for the learned behavior baseline detector.
 */
#include "behavior_baseline_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "behavior_baseline_detector.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"

namespace {

#define BB_CHECK(condition) Check((condition), #condition, __LINE__)

constexpr uint64_t kTicksPerSecond = 10000000ULL;

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "behavior baseline test failed at line " +
            std::to_string(line) + ": " + expression);
}

std::string TestPath(const char* suffix) {
    return std::string("edr-native-behavior-baseline-") +
           std::to_string(GetCurrentProcessId()) + "-" + suffix;
}

const char* ProductionRulesPath(const char* supplied) {
    if (supplied && *supplied) return supplied;
    if (GetFileAttributesA("..\\rules\\rules.json") !=
        INVALID_FILE_ATTRIBUTES)
        return "..\\rules\\rules.json";
    return "rules\\rules.json";
}

edr::BehaviorBaselineDetector::Options Options(
    uint32_t trainingSeconds = 10, uint32_t windowSeconds = 3600,
    uint32_t dedupSeconds = 0) {
    edr::BehaviorBaselineDetector::Options options;
    options.enabled = true;
    options.trainingSeconds = trainingSeconds;
    options.windowSeconds = windowSeconds;
    options.dedupSeconds = dedupSeconds;
    return options;
}

edr::Event ProcessStart(const char* parent, const char* image,
                        uint64_t ts100ns, const char* chainScore = nullptr) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kParentImage] = parent;
    event.fields[edr::field::kImage] = image;
    if (chainScore)
        event.fields[edr::field::kChainScore] = chainScore;
    return event;
}

edr::Event FileCreate(const char* image, const char* path,
                      uint64_t ts100ns, bool useFallback = false) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kImage] = image;
    event.fields[useFallback ? edr::field::kFilePath
                             : edr::field::kTargetPath] = path;
    return event;
}

edr::Event NetConnect(const char* image, const char* ip, const char* port,
                      uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_NET_CONNECT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "NET_CONNECT";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kDstIp] = ip;
    if (port) event.fields[edr::field::kDstPort] = port;
    return event;
}

/* Materialize the event before passing the mutable reference required by
 * Enrich; strict C++17 rejects binding a temporary to that reference. */
void Feed(edr::BehaviorBaselineDetector& detector, edr::Event event) {
    detector.Enrich(event);
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

uint64_t BaseTime() {
    FILETIME fileTime = {};
    GetSystemTimePreciseAsFileTime(&fileTime);
    return (static_cast<uint64_t>(fileTime.dwHighDateTime) << 32) |
           fileTime.dwLowDateTime;
}

void Train(edr::BehaviorBaselineDetector& detector, uint64_t base) {
    Feed(detector, ProcessStart("C:\\Apps\\agent.exe",
                                "C:\\Tools\\known-one.exe", base));
    Feed(detector, ProcessStart("C:\\Apps\\agent.exe",
                                "C:\\Tools\\known-two.exe",
                                base + kTicksPerSecond));
    Feed(detector, FileCreate("C:\\Apps\\agent.exe",
                              "C:\\Data\\known\\one.txt",
                              base + 2 * kTicksPerSecond));
    Feed(detector, NetConnect("C:\\Apps\\agent.exe", "192.0.2.10", "443",
                              base + 3 * kTicksPerSecond));
}

void TestDisabledAndInspects() {
    BB_CHECK(edr::BehaviorBaselineDetector::Inspects(EDR_EVT_PROCESS_START));
    BB_CHECK(edr::BehaviorBaselineDetector::Inspects(EDR_EVT_FILE_CREATE));
    BB_CHECK(edr::BehaviorBaselineDetector::Inspects(EDR_EVT_NET_CONNECT));
    BB_CHECK(!edr::BehaviorBaselineDetector::Inspects(EDR_EVT_PROCESS_STOP));

    const std::string path = TestPath("disabled.json");
    {
        std::ofstream out(path, std::ios::binary);
        out << "preserve-this-file";
    }
    edr::BehaviorBaselineDetector::Options options = Options();
    options.enabled = false;
    options.baselinePath = path;
    edr::BehaviorBaselineDetector detector(options);
    edr::Event event = ProcessStart("C:\\Apps\\agent.exe",
                                    "C:\\Tools\\child.exe", BaseTime());
    detector.Enrich(event);
    BB_CHECK(!HasField(event, edr::field::kBehaviorBaselineScore));
    BB_CHECK(detector.StateCount() == 0);
    BB_CHECK(detector.LoadedEntries() == 0);
    BB_CHECK(detector.LastError().empty());
    std::ifstream in(path, std::ios::binary);
    std::string contents((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
    BB_CHECK(contents == "preserve-this-file");
    DeleteFileA(path.c_str());
}

void TestTrainingAndSingleCategoryScores() {
    edr::BehaviorBaselineDetector detector(Options(10));
    const uint64_t base = BaseTime();
    Train(detector, base);
    const uint64_t trainedAt = base + 10 * kTicksPerSecond;

    /* The same child, write directory, and endpoint remain known after the
     * training clock closes. */
    edr::Event knownChild = ProcessStart(
        "C:\\Apps\\agent.exe", "C:\\Other\\KNOWN-ONE.EXE", trainedAt);
    detector.Enrich(knownChild);
    BB_CHECK(!HasField(knownChild, edr::field::kBehaviorBaselineScore));
    edr::Event knownDir = FileCreate(
        "C:\\Apps\\agent.exe", "C:\\Data\\KNOWN\\two.txt",
        trainedAt + 1);
    detector.Enrich(knownDir);
    BB_CHECK(!HasField(knownDir, edr::field::kBehaviorBaselineScore));
    edr::Event knownEndpoint = NetConnect(
        "C:\\Apps\\agent.exe", "192.0.2.10", "443", trainedAt + 2);
    detector.Enrich(knownEndpoint);
    BB_CHECK(!HasField(knownEndpoint, edr::field::kBehaviorBaselineScore));

    edr::BehaviorBaselineDetector childOnly(Options(10));
    Train(childOnly, base + 20 * kTicksPerSecond);
    edr::Event child = ProcessStart(
        "C:\\Apps\\agent.exe", "C:\\Tools\\new.exe",
        base + 30 * kTicksPerSecond);
    childOnly.Enrich(child);
    BB_CHECK(!HasField(child, edr::field::kBehaviorBaselineScore));

    edr::BehaviorBaselineDetector dirOnly(Options(10));
    Train(dirOnly, base + 40 * kTicksPerSecond);
    edr::Event dir = FileCreate("C:\\Apps\\agent.exe",
                                "C:\\Data\\new\\file.txt",
                                base + 50 * kTicksPerSecond, true);
    dirOnly.Enrich(dir);
    BB_CHECK(!HasField(dir, edr::field::kBehaviorBaselineScore));

    edr::BehaviorBaselineDetector endpointOnly(Options(10));
    Train(endpointOnly, base + 60 * kTicksPerSecond);
    edr::Event endpoint = NetConnect("C:\\Apps\\agent.exe", "198.51.100.5",
                                     "8443", base + 70 * kTicksPerSecond);
    endpointOnly.Enrich(endpoint);
    BB_CHECK(!HasField(endpoint, edr::field::kBehaviorBaselineScore));
}

void TestCategoryAggregationAndProductionRules(const char* rulesPath) {
    /* Keep the production default dedup interval: a 70-point log must not
     * suppress a higher-severity 100-point alert from the same burst. */
    edr::BehaviorBaselineDetector detector(Options(10, 3600, 600));
    const uint64_t base = BaseTime();
    Train(detector, base);
    const uint64_t trainedAt = base + 10 * kTicksPerSecond;

    edr::Event child = ProcessStart("C:\\Apps\\agent.exe",
                                    "C:\\Tools\\new.exe", trainedAt);
    detector.Enrich(child);
    BB_CHECK(!HasField(child, edr::field::kBehaviorBaselineScore));

    edr::Event twoCategories = FileCreate(
        "C:\\Apps\\agent.exe", "C:\\Data\\new\\file.txt",
        trainedAt + kTicksPerSecond);
    detector.Enrich(twoCategories);
    BB_CHECK(twoCategories.fields.at(edr::field::kBehaviorBaselineScore) ==
             "70");
    BB_CHECK(twoCategories.fields.at(edr::field::kBehaviorBaselineSignals) ==
             "new_child,new_dir");
    BB_CHECK(twoCategories.fields.at(edr::field::kBehaviorBaselineNewDir) ==
             "c:\\data\\new");

    edr::Event threeCategories = NetConnect(
        "C:\\Apps\\agent.exe", "198.51.100.5", "8443",
        trainedAt + 2 * kTicksPerSecond);
    detector.Enrich(threeCategories);
    BB_CHECK(threeCategories.fields.at(edr::field::kBehaviorBaselineScore) ==
             "100");
    BB_CHECK(threeCategories.fields.at(edr::field::kBehaviorBaselineSignals) ==
             "new_child,new_dir,new_endpoint");
    BB_CHECK(threeCategories.fields.at(
                 edr::field::kBehaviorBaselineNewEndpoint) ==
             "198.51.100.5:8443");

    struct Hit {
        std::string id;
        std::string action;
    };
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath(rulesPath));
    std::vector<Hit> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back({alert.ruleId, alert.action});
    });
    engine.OnEvent(twoCategories);
    BB_CHECK(hits.size() == 1);
    BB_CHECK(hits[0].id == "EDR-515");
    BB_CHECK(hits[0].action == "log");
    hits.clear();
    engine.OnEvent(threeCategories);
    BB_CHECK(hits.size() == 1);
    BB_CHECK(hits[0].id == "EDR-516");
    BB_CHECK(hits[0].action == "alert");

    edr::Event duplicateEndpoint = NetConnect(
        "C:\\Apps\\agent.exe", "198.51.100.5", "8443",
        trainedAt + 3 * kTicksPerSecond);
    detector.Enrich(duplicateEndpoint);
    BB_CHECK(!HasField(duplicateEndpoint, edr::field::kBehaviorBaselineScore));

    /* Exercise the rule boundary inclusively and the intentional 50-54 gap. */
    for (const auto& sample : std::vector<std::pair<int, const char*>>{
             {50, ""}, {54, ""}, {55, "EDR-515"},
             {74, "EDR-515"}, {75, "EDR-516"}, {100, "EDR-516"}}) {
        edr::Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[edr::field::kType] = "PROCESS_START";
        event.fields[edr::field::kBehaviorBaselineScore] =
            std::to_string(sample.first);
        hits.clear();
        engine.OnEvent(event);
        if (*sample.second == '\0') {
            BB_CHECK(hits.empty());
        } else {
            BB_CHECK(hits.size() == 1);
            BB_CHECK(hits[0].id == sample.second);
            BB_CHECK(hits[0].action ==
                     (sample.first <= 74 ? "log" : "alert"));
            BB_CHECK(hits[0].action != "terminate");
            BB_CHECK(hits[0].action != "kill");
            BB_CHECK(hits[0].action != "delete_file");
            BB_CHECK(hits[0].action != "isolate");
            BB_CHECK(hits[0].action != "quarantine");
        }
    }
}

void TestWindowAndDedupBoundaries() {
    const uint64_t base = BaseTime();
    edr::BehaviorBaselineDetector windowed(Options(10, 5, 0));
    Train(windowed, base);
    const uint64_t trainedAt = base + 10 * kTicksPerSecond;
    edr::Event child = ProcessStart("C:\\Apps\\agent.exe",
                                    "C:\\Tools\\new.exe", trainedAt);
    windowed.Enrich(child);
    edr::Event dir = FileCreate("C:\\Apps\\agent.exe",
                                "C:\\Data\\new\\one.txt",
                                trainedAt + kTicksPerSecond);
    windowed.Enrich(dir);
    BB_CHECK(dir.fields.at(edr::field::kBehaviorBaselineScore) == "70");

    /* Both earlier marks are outside the inclusive 5-second window here. */
    edr::Event endpoint = NetConnect(
        "C:\\Apps\\agent.exe", "198.51.100.8", "443",
        trainedAt + 7 * kTicksPerSecond);
    windowed.Enrich(endpoint);
    BB_CHECK(!HasField(endpoint, edr::field::kBehaviorBaselineScore));
    edr::Event childAgain = ProcessStart(
        "C:\\Apps\\agent.exe", "C:\\Tools\\new-two.exe",
        trainedAt + 8 * kTicksPerSecond);
    windowed.Enrich(childAgain);
    BB_CHECK(childAgain.fields.at(edr::field::kBehaviorBaselineScore) == "70");

    edr::BehaviorBaselineDetector deduped(Options(10, 30, 5));
    const uint64_t dedupBase = base + 20 * kTicksPerSecond;
    Train(deduped, dedupBase);
    const uint64_t t = dedupBase + 10 * kTicksPerSecond;
    edr::Event firstChild = ProcessStart(
        "C:\\Apps\\agent.exe", "C:\\Tools\\new.exe", t);
    deduped.Enrich(firstChild);
    edr::Event firstDir = FileCreate("C:\\Apps\\agent.exe",
                                     "C:\\Data\\new\\one.txt",
                                     t + kTicksPerSecond);
    deduped.Enrich(firstDir);
    BB_CHECK(firstDir.fields.at(edr::field::kBehaviorBaselineScore) == "70");
    edr::Event suppressed = FileCreate(
        "C:\\Apps\\agent.exe", "C:\\Data\\newer\\one.txt",
        t + 2 * kTicksPerSecond);
    deduped.Enrich(suppressed);
    BB_CHECK(!HasField(suppressed, edr::field::kBehaviorBaselineScore));
    edr::Event afterDedup = NetConnect(
        "C:\\Apps\\agent.exe", "198.51.100.9", "443",
        t + 7 * kTicksPerSecond);
    deduped.Enrich(afterDedup);
    BB_CHECK(afterDedup.fields.at(edr::field::kBehaviorBaselineScore) == "100");
}

void TestDetectorThresholdBoundary() {
    const uint64_t base = BaseTime();
    edr::BehaviorBaselineDetector::Options exactOptions = Options(10);
    exactOptions.minScore = 70;
    edr::BehaviorBaselineDetector exact(exactOptions);
    Train(exact, base);
    const uint64_t t = base + 10 * kTicksPerSecond;
    edr::Event child = ProcessStart("C:\\Apps\\agent.exe",
                                    "C:\\Tools\\new.exe", t);
    exact.Enrich(child);
    edr::Event dir = FileCreate("C:\\Apps\\agent.exe",
                                "C:\\Data\\new\\file.txt",
                                t + kTicksPerSecond);
    exact.Enrich(dir);
    BB_CHECK(dir.fields.at(edr::field::kBehaviorBaselineScore) == "70");

    edr::BehaviorBaselineDetector::Options aboveOptions = Options(10);
    aboveOptions.minScore = 71;
    edr::BehaviorBaselineDetector above(aboveOptions);
    const uint64_t otherBase = base + 20 * kTicksPerSecond;
    Train(above, otherBase);
    const uint64_t otherT = otherBase + 10 * kTicksPerSecond;
    edr::Event childAbove = ProcessStart(
        "C:\\Apps\\agent.exe", "C:\\Tools\\new.exe", otherT);
    above.Enrich(childAbove);
    edr::Event dirAbove = FileCreate("C:\\Apps\\agent.exe",
                                     "C:\\Data\\new\\file.txt",
                                     otherT + kTicksPerSecond);
    above.Enrich(dirAbove);
    BB_CHECK(!HasField(dirAbove, edr::field::kBehaviorBaselineScore));
}

void TestStateAndObservationCapacity() {
    edr::BehaviorBaselineDetector::Options stateOptions = Options(1000);
    stateOptions.stateCapacity = 2;
    edr::BehaviorBaselineDetector states(stateOptions);
    const uint64_t base = BaseTime();
    Feed(states, ProcessStart("C:\\Parents\\one.exe", "one-child.exe", base));
    Feed(states, ProcessStart("C:\\Parents\\two.exe", "two-child.exe",
                              base + kTicksPerSecond));
    Feed(states, ProcessStart("C:\\Parents\\three.exe", "three-child.exe",
                              base + 2 * kTicksPerSecond));
    BB_CHECK(states.StateCount() == 2);

    edr::BehaviorBaselineDetector::Options observationOptions = Options(5);
    observationOptions.maxObservations = 1;
    edr::BehaviorBaselineDetector observations(observationOptions);
    Feed(observations, ProcessStart("C:\\Apps\\agent.exe",
                                    "C:\\Tools\\one.exe", base));
    Feed(observations, ProcessStart("C:\\Apps\\agent.exe",
                                    "C:\\Tools\\two.exe",
                                    base + kTicksPerSecond));
    edr::Event overLimit = ProcessStart(
        "C:\\Apps\\agent.exe", "C:\\Tools\\two.exe",
        base + 5 * kTicksPerSecond);
    observations.Enrich(overLimit);
    BB_CHECK(!HasField(overLimit, edr::field::kBehaviorBaselineScore));
    edr::Event secondCategory = FileCreate(
        "C:\\Apps\\agent.exe", "C:\\Data\\novel\\one.txt",
        base + 6 * kTicksPerSecond);
    observations.Enrich(secondCategory);
    BB_CHECK(secondCategory.fields.at(edr::field::kBehaviorBaselineScore) ==
             "70");
}

void TestPollutionBlocksTraining() {
    edr::BehaviorBaselineDetector detector(Options(5));
    const uint64_t base = BaseTime();
    Feed(detector, ProcessStart("C:\\Apps\\agent.exe",
                                "C:\\Tools\\one.exe", base, "75"));
    Feed(detector, ProcessStart("C:\\Apps\\agent.exe",
                                "C:\\Tools\\two.exe",
                                base + kTicksPerSecond));
    edr::Event child = ProcessStart("C:\\Apps\\agent.exe",
                                    "C:\\Tools\\two.exe",
                                    base + 5 * kTicksPerSecond);
    detector.Enrich(child);
    BB_CHECK(!HasField(child, edr::field::kBehaviorBaselineScore));
    edr::Event dir = FileCreate("C:\\Apps\\agent.exe",
                                "C:\\Data\\new\\file.txt",
                                base + 6 * kTicksPerSecond);
    detector.Enrich(dir);
    BB_CHECK(dir.fields.at(edr::field::kBehaviorBaselineScore) == "70");
}

void WriteText(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("could not create test file: " + path);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) throw std::runtime_error("could not write test file: " + path);
}

void SetConfigSentinels(edr::Config& config) {
    config.behaviorBaselineEnable = false;
    config.behaviorBaselineTrainingSeconds = 123;
    config.behaviorBaselineWindowSeconds = 234;
    config.behaviorBaselineDedupSeconds = 345;
    config.behaviorBaselineStateCapacity = 456;
    config.behaviorBaselineMinScore = 67;
    config.behaviorBaselinePollutionScore = 78;
    config.behaviorBaselinePath = "keep-this-path";
    config.behaviorBaselineMaxAgeDays = 89;
    config.behaviorBaselineMaxObservations = 90;
}

void CheckConfigSentinels(const edr::Config& config) {
    BB_CHECK(!config.behaviorBaselineEnable);
    BB_CHECK(config.behaviorBaselineTrainingSeconds == 123);
    BB_CHECK(config.behaviorBaselineWindowSeconds == 234);
    BB_CHECK(config.behaviorBaselineDedupSeconds == 345);
    BB_CHECK(config.behaviorBaselineStateCapacity == 456);
    BB_CHECK(config.behaviorBaselineMinScore == 67);
    BB_CHECK(config.behaviorBaselinePollutionScore == 78);
    BB_CHECK(config.behaviorBaselinePath == "keep-this-path");
    BB_CHECK(config.behaviorBaselineMaxAgeDays == 89);
    BB_CHECK(config.behaviorBaselineMaxObservations == 90);
}

void TestConfigDefaultsValidAndStrictAtomic() {
    edr::Config defaults;
    BB_CHECK(!defaults.behaviorBaselineEnable);
    BB_CHECK(defaults.behaviorBaselineTrainingSeconds == 86400);
    BB_CHECK(defaults.behaviorBaselineWindowSeconds == 3600);
    BB_CHECK(defaults.behaviorBaselineDedupSeconds == 600);
    BB_CHECK(defaults.behaviorBaselineStateCapacity == 4096);
    BB_CHECK(defaults.behaviorBaselineMinScore == 55);
    BB_CHECK(defaults.behaviorBaselinePollutionScore == 75);
    BB_CHECK(defaults.behaviorBaselinePath.empty());
    BB_CHECK(defaults.behaviorBaselineMaxAgeDays == 30);
    BB_CHECK(defaults.behaviorBaselineMaxObservations == 64);

    const std::string path = TestPath("config.json");
    const std::string valid =
        R"({"behavior_baseline":{"enable":true,"training_seconds":31536000,"window_seconds":1,"dedup_seconds":86400,"state_capacity":65536,"min_score":10,"pollution_score":100,"baseline_path":"baseline.json","max_age_days":3650,"max_observations":4096}})";
    WriteText(path, valid);
    edr::Config config;
    std::string error;
    BB_CHECK(edr::LoadConfigFile(path, config, error));
    BB_CHECK(config.behaviorBaselineEnable);
    BB_CHECK(config.behaviorBaselineTrainingSeconds == 31536000);
    BB_CHECK(config.behaviorBaselineWindowSeconds == 1);
    BB_CHECK(config.behaviorBaselineDedupSeconds == 86400);
    BB_CHECK(config.behaviorBaselineStateCapacity == 65536);
    BB_CHECK(config.behaviorBaselineMinScore == 10);
    BB_CHECK(config.behaviorBaselinePollutionScore == 100);
    BB_CHECK(config.behaviorBaselinePath == "baseline.json");
    BB_CHECK(config.behaviorBaselineMaxAgeDays == 3650);
    BB_CHECK(config.behaviorBaselineMaxObservations == 4096);

    std::vector<std::string> invalid = {
        R"({"behavior_baseline":true})",
        R"({"behavior_baseline":{"unknown":1}})",
        R"({"behavior_baseline":{"enable":"true"}})",
        R"({"behavior_baseline":{"training_seconds":-1}})",
        R"({"behavior_baseline":{"training_seconds":31536001}})",
        R"({"behavior_baseline":{"training_seconds":1.5}})",
        R"({"behavior_baseline":{"training_seconds":4294967296}})",
        R"({"behavior_baseline":{"window_seconds":0}})",
        R"({"behavior_baseline":{"window_seconds":86401}})",
        R"({"behavior_baseline":{"window_seconds":1.5}})",
        R"({"behavior_baseline":{"dedup_seconds":-1}})",
        R"({"behavior_baseline":{"dedup_seconds":86401}})",
        R"({"behavior_baseline":{"dedup_seconds":2.5}})",
        R"({"behavior_baseline":{"state_capacity":0}})",
        R"({"behavior_baseline":{"state_capacity":65537}})",
        R"({"behavior_baseline":{"state_capacity":2.5}})",
        R"({"behavior_baseline":{"min_score":9}})",
        R"({"behavior_baseline":{"min_score":101}})",
        R"({"behavior_baseline":{"min_score":55.5}})",
        R"({"behavior_baseline":{"pollution_score":0}})",
        R"({"behavior_baseline":{"pollution_score":101}})",
        R"({"behavior_baseline":{"pollution_score":"75"}})",
        R"({"behavior_baseline":{"baseline_path":7}})",
        R"({"behavior_baseline":{"baseline_path":"bad\u0000path"}})",
        R"({"behavior_baseline":{"max_age_days":0}})",
        R"({"behavior_baseline":{"max_age_days":3651}})",
        R"({"behavior_baseline":{"max_age_days":2.5}})",
        R"({"behavior_baseline":{"max_observations":0}})",
        R"({"behavior_baseline":{"max_observations":4097}})",
        R"({"behavior_baseline":{"max_observations":2.5}})"};

    /* Earlier valid assignments in this same block must not leak when the
     * final field fails validation. */
    invalid.push_back(
        R"({"behavior_baseline":{"enable":true,"training_seconds":1,"window_seconds":2,"dedup_seconds":3,"state_capacity":100,"min_score":40,"pollution_score":50,"baseline_path":"changed.json","max_age_days":60,"max_observations":0}})");

    for (const std::string& text : invalid) {
        WriteText(path, text);
        edr::Config unchanged;
        SetConfigSentinels(unchanged);
        error.clear();
        BB_CHECK(!edr::LoadConfigFile(path, unchanged, error));
        BB_CHECK(!error.empty());
        CheckConfigSentinels(unchanged);
    }
    DeleteFileA(path.c_str());
}

} // namespace

void RunBehaviorBaselineTests(const char* rulesPath) {
    TestDisabledAndInspects();
    TestTrainingAndSingleCategoryScores();
    TestCategoryAggregationAndProductionRules(rulesPath);
    TestWindowAndDedupBoundaries();
    TestDetectorThresholdBoundary();
    TestStateAndObservationCapacity();
    TestPollutionBlocksTraining();
    TestConfigDefaultsValidAndStrictAtomic();
}
