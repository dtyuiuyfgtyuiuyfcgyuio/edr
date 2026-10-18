/*
 * discovery_recon_detector_tests.cpp - Unit tests for DiscoveryReconDetector.
 */
#include "discovery_recon_detector_tests.h"

#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>

#include "config.h"
#include "discovery_recon_detector.h"
#include "edr_event.h"
#include "event_bus.h"

using namespace edr;

namespace {

#define DR_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "discovery recon detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(const std::string& image,
                        const std::string& commandLine,
                        uint64_t ts100ns, uint32_t pid = 100) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

void TestClassifier() {
    DR_CHECK(ClassifyDiscoveryTechnique(
        "C:\\Windows\\System32\\whoami.exe", "whoami /all") ==
        "account_discovery");
    DR_CHECK(ClassifyDiscoveryTechnique(
        "C:\\Windows\\System32\\nltest.exe", "nltest /dclist:lab") ==
        "domain_discovery");
    DR_CHECK(ClassifyDiscoveryTechnique(
        "C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all") ==
        "network_discovery");
    DR_CHECK(ClassifyDiscoveryTechnique(
        "C:\\Windows\\System32\\tasklist.exe", "tasklist /v") ==
        "process_discovery");
    DR_CHECK(ClassifyDiscoveryTechnique(
        "C:\\Windows\\System32\\notepad.exe",
        "notepad C:\\temp\\x.txt").empty());
}

void TestCorrelation() {
    edr::DiscoveryReconDetector detector(true, 300, 2048, 3, 600);
    const uint64_t base = 200000000000ULL;

    edr::Event first = ProcessStart(
        "C:\\Windows\\System32\\whoami.exe", "whoami /all",
        base + 10000000ULL);
    detector.Enrich(first);
    DR_CHECK(!HasField(first, edr::field::kDiscoveryScore));

    edr::Event second = ProcessStart(
        "C:\\Windows\\System32\\nltest.exe", "nltest /dclist:lab",
        base + 20000000ULL);
    detector.Enrich(second);
    DR_CHECK(!HasField(second, edr::field::kDiscoveryScore));

    edr::Event third = ProcessStart(
        "C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all",
        base + 30000000ULL);
    detector.Enrich(third);
    DR_CHECK(HasField(third, edr::field::kDiscoveryScore));
    DR_CHECK(third.fields.at(edr::field::kDiscoveryCount) == "3");
    DR_CHECK(third.fields.at(edr::field::kDiscoveryVerdict) ==
             "multi_stage_reconnaissance");

    edr::Event duplicate = ProcessStart(
        "C:\\Windows\\System32\\tasklist.exe", "tasklist /v",
        base + 40000000ULL);
    detector.Enrich(duplicate);
    DR_CHECK(HasField(duplicate, edr::field::kDiscoveryScore));
    DR_CHECK(duplicate.fields.at(edr::field::kDiscoveryCount) == "4");
}

void TestInspectionsAndDisabled() {
    DR_CHECK(edr::DiscoveryReconDetector::Inspects(EDR_EVT_PROCESS_START));
    DR_CHECK(!edr::DiscoveryReconDetector::Inspects(EDR_EVT_FILE_CREATE));

    edr::DiscoveryReconDetector disabled(false, 300, 2048, 3, 600);
    edr::Event event = ProcessStart(
        "C:\\Windows\\System32\\whoami.exe", "whoami /all", 1000);
    disabled.Enrich(event);
    DR_CHECK(!HasField(event, edr::field::kDiscoveryScore));
    DR_CHECK(disabled.StateCount() == 0);
}

void TestConfigStrictAtomic() {
    const char* path = "edr-native-discovery-recon-config.json";
    std::ofstream out(path, std::ios::binary);
    out << R"({"discovery_recon":{"enable":true,"window_seconds":240,"state_capacity":1024,"min_techniques":4,"dedup_seconds":180}})";
    out.close();

    std::string error;
    edr::Config config;
    DR_CHECK(edr::LoadConfigFile(path, config, error));
    DR_CHECK(config.discoveryReconEnable);
    DR_CHECK(config.discoveryReconWindowSeconds == 240);
    DR_CHECK(config.discoveryReconStateCapacity == 1024);
    DR_CHECK(config.discoveryReconMinTechniques == 4);
    DR_CHECK(config.discoveryReconDedupSeconds == 180);

    std::ofstream bad(path, std::ios::binary);
    bad << R"({"discovery_recon":{"enable":true,"bogus":1}})";
    bad.close();
    edr::Config unchanged;
    DR_CHECK(!edr::LoadConfigFile(path, unchanged, error));
    DR_CHECK(!unchanged.discoveryReconEnable);

    std::remove(path);
}

} // namespace

void RunDiscoveryReconDetectorTests() {
    TestClassifier();
    TestCorrelation();
    TestInspectionsAndDisabled();
    TestConfigStrictAtomic();
}
