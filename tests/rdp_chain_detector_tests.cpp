/*
 * rdp_chain_detector_tests.cpp - Unit tests for RdpChainDetector and the
 * production rule it feeds.
 */
#include "rdp_chain_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "rdp_chain_detector.h"
#include "rule_engine.h"

namespace {

#define RC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "rdp chain detector test failed at line " +
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

edr::Event RdpSession(const std::string& action, const std::string& user,
                      const std::string& domain, const std::string& sourceIp,
                      uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_RDP_SESSION;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "RDP_SESSION";
    event.fields[edr::field::kRdpAction] = action;
    event.fields[edr::field::kRdpUser] = user;
    event.fields[edr::field::kRdpDomain] = domain;
    event.fields[edr::field::kRdpSourceIp] = sourceIp;
    return event;
}

void TestThresholdAndVerdict() {
    edr::RdpChainDetector detector(true, 600, 4096, 1);
    const uint64_t base = 1000000000ULL;
    const std::string user = "alice";

    edr::Event first = RdpSession("logon", user, "CORP", "192.0.2.10", base);
    detector.Enrich(first);
    RC_CHECK(first.fields.at(edr::field::kRdpChainCount) == "1");
    RC_CHECK(first.fields.at(edr::field::kRdpChainScore) == "35");
    RC_CHECK(first.fields.find(edr::field::kRdpChainVerdict) ==
             first.fields.end());

    edr::Event second = RdpSession("reconnect", user, "CORP", "192.0.2.10", base + 10000000ULL);
    detector.Enrich(second);
    RC_CHECK(second.fields.find(edr::field::kRdpChainScore) == second.fields.end());

    edr::Event third = RdpSession("auth_success", user, "CORP", "192.0.2.10", base + 20000000ULL);
    detector.Enrich(third);
    RC_CHECK(third.fields.find(edr::field::kRdpChainScore) ==
             third.fields.end());
}

void TestMultipleSourcesTrigger() {
    edr::RdpChainDetector detector(true, 600, 4096, 2);
    const uint64_t base = 2000000000ULL;
    const std::string user = "bob";

    edr::Event first = RdpSession("logon", user, "CORP", "192.0.2.10", base);
    detector.Enrich(first);
    edr::Event second = RdpSession("logon", user, "CORP", "192.0.2.11", base + 10000000ULL);
    detector.Enrich(second);
    RC_CHECK(second.fields.at(edr::field::kRdpChainCount) == "2");
    RC_CHECK(second.fields.at(edr::field::kRdpChainSources).find("192.0.2.10") != std::string::npos);
    RC_CHECK(second.fields.at(edr::field::kRdpChainSources).find("192.0.2.11") != std::string::npos);
}

void TestWindowExpiryResets() {
    edr::RdpChainDetector detector(true, 1, 4096, 2);
    const uint64_t base = 3000000000ULL;
    edr::Event first = RdpSession("logon", "carol", "CORP", "192.0.2.10", base);
    detector.Enrich(first);
    edr::Event second = RdpSession("reconnect", "carol", "CORP", "192.0.2.11", base + 1000000ULL);
    detector.Enrich(second);
    RC_CHECK(second.fields.at(edr::field::kRdpChainCount) == "2");

    edr::Event later = RdpSession("logon", "carol", "CORP", "192.0.2.12", base + 11000000ULL);
    detector.Enrich(later);
    RC_CHECK(later.fields.find(edr::field::kRdpChainScore) == later.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::RdpChainDetector detector(true, 600, 4096, 2);
    const uint64_t base = 4000000000ULL;
    edr::Event first = RdpSession("logon", "dave", "CORP", "192.0.2.10", base);
    detector.Enrich(first);
    engine.OnEvent(first);
    RC_CHECK(!Has(hits, "EDR-301"));

    edr::Event second = RdpSession("logon", "dave", "CORP", "192.0.2.11", base + 10000000ULL);
    detector.Enrich(second);
    engine.OnEvent(second);
    RC_CHECK(Has(hits, "EDR-301"));
}

} // namespace

void RunRdpChainDetectorTests() {
    TestThresholdAndVerdict();
    TestMultipleSourcesTrigger();
    TestWindowExpiryResets();
    TestProductionRule();
}
