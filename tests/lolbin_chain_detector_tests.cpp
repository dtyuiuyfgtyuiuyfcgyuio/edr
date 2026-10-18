/*
 * lolbin_chain_detector_tests.cpp - Unit tests for LolbinChainDetector and
 * the production rule it feeds.
 */
#include "lolbin_chain_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "lolbin_chain_detector.h"
#include "rule_engine.h"

namespace {

#define LC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "lolbin chain detector test failed at line " +
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

void Dispatch(edr::LolbinChainDetector& detector, edr::Event& event) {
    if (detector.Inspects(event.type)) detector.Enrich(event);
}

edr::Event ProcessStart(uint32_t pid, uint32_t ppid,
                        const std::string& image,
                        const std::string& parent, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.ppid = ppid;
    event.source = "sysmon";
    event.parentProcessIdentity = "{parent-" + std::to_string(ppid) + "}";
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (!parent.empty()) event.fields[edr::field::kParentImage] = parent;
    return event;
}

void TestConfigDefault() {
    edr::LolbinChainDetector detector(true, 600, 4096, 3);
    LC_CHECK(detector.StateCount() == 0);
}

void TestThresholdAndVerdict() {
    edr::LolbinChainDetector detector(true, 600, 4096, 3);
    const uint64_t base = 1000000000ULL;
    const std::string parent = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";

    edr::Event first = ProcessStart(1001, 500,
        "C:\\Windows\\System32\\powershell.exe", parent, base);
    Dispatch(detector, first);
    LC_CHECK(first.fields.find(edr::field::kLolbinChainScore) == first.fields.end());

    edr::Event second = ProcessStart(1002, 500,
        "C:\\Windows\\System32\\mshta.exe", parent, base + 10000000ULL);
    Dispatch(detector, second);
    LC_CHECK(second.fields.find(edr::field::kLolbinChainScore) == second.fields.end());

    edr::Event third = ProcessStart(1003, 500,
        "C:\\Windows\\System32\\rundll32.exe", parent, base + 20000000ULL);
    Dispatch(detector, third);
    LC_CHECK(third.fields.count(edr::field::kLolbinChainCount) == 1);
    LC_CHECK(third.fields.at(edr::field::kLolbinChainCount) == "3");
    LC_CHECK(third.fields.at(edr::field::kLolbinChainWindowSeconds) == "600");
    LC_CHECK(third.fields.at(edr::field::kLolbinChainScore) == "75");
    LC_CHECK(third.fields.at(edr::field::kLolbinChainVerdict) == "MALICIOUS");
}

void TestWindowExpiryResets() {
    edr::LolbinChainDetector detector(true, 1, 4096, 2);
    const uint64_t base = 2000000000ULL;
    const std::string parent = "C:\\Users\\alice\\AppData\\Local\\Temp\\builder.exe";

    edr::Event first = ProcessStart(2001, 500,
        "C:\\Windows\\System32\\cmd.exe", parent, base);
    Dispatch(detector, first);
    edr::Event second = ProcessStart(2002, 500,
        "C:\\Windows\\System32\\powershell.exe", parent, base + 1000000ULL);
    Dispatch(detector, second);
    LC_CHECK(second.fields.at(edr::field::kLolbinChainCount) == "2");

    edr::Event later = ProcessStart(2003, 500,
        "C:\\Windows\\System32\\wscript.exe", parent, base + 11000000ULL);
    Dispatch(detector, later);
    /* Parent-identity rework: expiry decays lastFlaggedCount (2 -> 1, the
     * powershell child sits exactly at the window boundary and survives the
     * strict-greater purge), so the wscript arrival re-crosses the threshold
     * and re-flags with a fresh score instead of staying cooldown-silent. */
    LC_CHECK(later.fields.at(edr::field::kLolbinChainCount) == "2");
    LC_CHECK(later.fields.at(edr::field::kLolbinChainScore) == "55");
}

void TestRulePipeline() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::LolbinChainDetector detector(true, 600, 4096, 3);
    const uint64_t base = 3000000000ULL;
    const std::string parent = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";

    edr::Event first = ProcessStart(3001, 100,
        "C:\\Windows\\System32\\powershell.exe", parent, base);
    Dispatch(detector, first);
    engine.OnEvent(first);
    LC_CHECK(!Has(hits, "EDR-299"));

    edr::Event second = ProcessStart(3002, 100,
        "C:\\Windows\\System32\\mshta.exe", parent, base + 10000000ULL);
    Dispatch(detector, second);
    engine.OnEvent(second);
    LC_CHECK(!Has(hits, "EDR-299"));

    edr::Event third = ProcessStart(3003, 100,
        "C:\\Windows\\System32\\rundll32.exe", parent, base + 20000000ULL);
    Dispatch(detector, third);
    engine.OnEvent(third);
    LC_CHECK(Has(hits, "EDR-299"));
}

void TestParentInstanceIsolation() {
    for (int scenario = 0; scenario < 9; ++scenario) {
        edr::LolbinChainDetector detector(true, 600, 8, 2);
        auto first = ProcessStart(4001, 500, "powershell.exe", "winword.exe", 1000000000);
        auto second = ProcessStart(4001, 500, "mshta.exe", "winword.exe", 1010000000);
        switch (scenario) {
        case 0: second.parentProcessIdentity = "{replacement-parent}"; break;
        case 1: first.parentProcessIdentity.clear(); second.parentProcessIdentity.clear(); break;
        case 2: second.ppid = 501; second.parentProcessIdentity = "{other-parent}"; break;
        case 3: first.fields[edr::field::kEndpointId] = "A";
                second.fields[edr::field::kEndpointId] = "B"; break;
        case 4: second.source = "etw"; break;
        case 5: first.parentProcessIdentity = second.parentProcessIdentity = "pid:500"; break;
        case 6: first.parentProcessIdentity = second.parentProcessIdentity = "500"; break;
        case 7: first.parentProcessIdentity = second.parentProcessIdentity = "wmi/500"; break;
        case 8: first.source.clear(); second.source.clear(); break;
        }
        Dispatch(detector, first);
        Dispatch(detector, second);
        LC_CHECK(second.fields.count(edr::field::kLolbinChainScore) == 0);
    }
}

void TestExactParentIdentityAndDuplicateChild() {
    edr::LolbinChainDetector detector(true, 600, 8, 2);
    auto first = ProcessStart(4101, 500, "powershell.exe", "winword.exe", 1000000000);
    first.parentProcessIdentity = "500@123456";
    Dispatch(detector, first);
    auto duplicate = first;
    duplicate.pid = 4102;
    duplicate.ts100ns += 1000000;
    Dispatch(detector, duplicate);
    LC_CHECK(duplicate.fields.count(edr::field::kLolbinChainScore) == 0);
    auto second = ProcessStart(4103, 500, "mshta.exe", "winword.exe", 1010000000);
    second.parentProcessIdentity = first.parentProcessIdentity;
    second.source = "etw"; // Exact PID+creation identity is provider-neutral.
    Dispatch(detector, second);
    LC_CHECK(second.fields.at(edr::field::kLolbinChainCount) == "2");
    auto reused = ProcessStart(4104, 500, "cmd.exe", "winword.exe", 1020000000);
    reused.parentProcessIdentity = "500@123457";
    Dispatch(detector, reused);
    LC_CHECK(reused.fields.count(edr::field::kLolbinChainScore) == 0);
}

void TestWindowRecrossAndCapacity() {
    edr::LolbinChainDetector detector(true, 1, 2, 2);
    auto first = ProcessStart(4201, 500, "powershell.exe", "winword.exe", 1000000000);
    auto second = ProcessStart(4202, 500, "mshta.exe", "winword.exe", 1005000000);
    Dispatch(detector, first);
    Dispatch(detector, second);
    LC_CHECK(second.fields.count(edr::field::kLolbinChainScore) == 1);
    auto third = ProcessStart(4203, 500, "cmd.exe", "winword.exe", 1011000000);
    Dispatch(detector, third); // First child expired; a fresh pair must report again.
    LC_CHECK(third.fields.at(edr::field::kLolbinChainCount) == "2");
    for (uint32_t parent = 501; parent < 507; ++parent) {
        auto ev = ProcessStart(4300 + parent, parent, "cmd.exe", "winword.exe", 1012000000 + parent);
        Dispatch(detector, ev);
        LC_CHECK(detector.StateCount() <= 2);
    }
    auto oldParent = ProcessStart(4500, 500, "wscript.exe", "winword.exe", 1013000000);
    Dispatch(detector, oldParent);
    LC_CHECK(oldParent.fields.count(edr::field::kLolbinChainScore) == 0);
    auto unrelated = ProcessStart(4501, 500, "rundll32.exe", "winword.exe", 1014000000);
    unrelated.type = EDR_EVT_NET_CONNECT;
    Dispatch(detector, unrelated);
    LC_CHECK(unrelated.fields.count(edr::field::kLolbinChainScore) == 0);
}

void TestLateEvidenceCannotRecreateExpiredChildren() {
    edr::LolbinChainDetector detector(true, 1, 8, 2);
    const uint64_t base = 1000000000;
    auto first = ProcessStart(4601, 500, "powershell.exe", "winword.exe", base);
    Dispatch(detector, first);
    auto tooLate = ProcessStart(4602, 500, "mshta.exe", "winword.exe", base - 20000000);
    Dispatch(detector, tooLate);
    LC_CHECK(tooLate.fields.count(edr::field::kLolbinChainScore) == 0);
    auto recent = ProcessStart(4603, 500, "cmd.exe", "winword.exe", base + 9000000);
    Dispatch(detector, recent);
    LC_CHECK(recent.fields.at(edr::field::kLolbinChainCount) == "2");
}

} // namespace

void RunLolbinChainDetectorTests() {
    TestConfigDefault();
    TestThresholdAndVerdict();
    TestWindowExpiryResets();
    TestRulePipeline();
    TestParentInstanceIsolation();
    TestExactParentIdentityAndDuplicateChild();
    TestWindowRecrossAndCapacity();
    TestLateEvidenceCannotRecreateExpiredChildren();
}
