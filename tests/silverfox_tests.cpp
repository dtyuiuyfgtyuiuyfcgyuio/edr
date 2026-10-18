#include "silverfox_tests.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"
#include "silverfox_detector.h"

namespace {

#define SF_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "SilverFox test failed at line " + std::to_string(line) +
            ": " + expression);
}

void WriteFile(const char* path, const std::string& text) {
    std::ofstream output(path, std::ios::binary);
    SF_CHECK(output.good());
    output << text;
    SF_CHECK(output.good());
}

bool HasRule(const std::vector<std::string>& hits, const char* id) {
    return std::find(hits.begin(), hits.end(), id) != hits.end();
}

void TestSilverFoxConfig() {
    edr::Config defaults;
    SF_CHECK(defaults.enableSilverFox);
    SF_CHECK(!defaults.ratAnalyzerEnable);
    SF_CHECK(defaults.ratAnalyzerScanIntervalSeconds == 15);
    SF_CHECK(defaults.ratAnalyzerMinScore == 15);
    SF_CHECK(defaults.ratAnalyzerDedupWindowSeconds == 300);
    SF_CHECK(!defaults.persistChainEnable);
    SF_CHECK(defaults.persistChainWindowSeconds == 600);
    SF_CHECK(defaults.persistChainMinMechanisms == 3);
    SF_CHECK(defaults.silverFoxIocPath ==
             "rules\\silverfox_ioc.v2.json");
    SF_CHECK(defaults.silverFoxCorrelationWindowSeconds == 600);
    SF_CHECK(defaults.silverFoxStateCapacity == 4096);

    const char* path = "edr-native-silverfox-config.json";
    WriteFile(path,
        R"({"enable_rat_analyzer":true,"rat_analyzer_scan_interval_seconds":30,"rat_analyzer_min_score":20,"rat_analyzer_dedup_window_seconds":600,"rat_analyzer_state_capacity":512,"silverfox":{"enable":true,"ioc_path":"rules\\test-ioc.json","correlation_window_seconds":30,"state_capacity":128}})");
    edr::Config valid;
    std::string error;
    SF_CHECK(edr::LoadConfigFile(path, valid, error));
    SF_CHECK(valid.enableSilverFox);
    SF_CHECK(valid.ratAnalyzerEnable);
    SF_CHECK(valid.ratAnalyzerScanIntervalSeconds == 30);
    SF_CHECK(valid.ratAnalyzerMinScore == 20);
    SF_CHECK(valid.ratAnalyzerDedupWindowSeconds == 600);
    SF_CHECK(valid.ratAnalyzerStateCapacity == 512);
    SF_CHECK(!valid.persistChainEnable);
    SF_CHECK(valid.silverFoxIocPath == "rules\\test-ioc.json");
    SF_CHECK(valid.silverFoxCorrelationWindowSeconds == 30);
    SF_CHECK(valid.silverFoxStateCapacity == 128);

    for (const char* invalid : {
        R"({"silverfox":true})",
        R"({"silverfox":{"unknown":1}})",
        R"({"silverfox":{"enable":"true"}})",
        R"({"silverfox":{"ioc_path":""}})",
        R"({"silverfox":{"correlation_window_seconds":29}})",
        R"({"silverfox":{"correlation_window_seconds":3601}})",
        R"({"silverfox":{"correlation_window_seconds":30.5}})",
        R"({"silverfox":{"state_capacity":127}})",
        R"({"silverfox":{"state_capacity":65537}})"}) {
        WriteFile(path, invalid);
        edr::Config unchanged;
        unchanged.silverFoxStateCapacity = 777;
        SF_CHECK(!edr::LoadConfigFile(path, unchanged, error));
        SF_CHECK(unchanged.silverFoxStateCapacity == 777);
        SF_CHECK(unchanged.silverFoxCorrelationWindowSeconds == 600);
    }
    DeleteFileA(path);
}
std::string TestIocJson() {
    const std::string hash(64, 'a');
    const std::string certificate(64, 'b');
    return std::string(
        R"({"schema_version":2,"family":"SilverFox","indicators":[)") +
        R"({"id":"TEST-HASH","type":"sha256","value":")" + hash +
        R"(","confidence":"high","status":"active","source_url":"https://bbs.kafan.cn/thread-test","observed_at":"2026-08-02"},)" +
        R"({"id":"TEST-CERT","type":"certificate_sha256","value":")" +
        certificate +
        R"(","confidence":"high","status":"active","source_url":"https://bbs.kafan.cn/thread-test","observed_at":"2026-08-02"},)" +
        R"({"id":"TEST-DOMAIN","type":"domain","value":"sample.invalid","confidence":"medium","status":"active","source_url":"https://bbs.kafan.cn/thread-test","observed_at":"2026-08-02"},)" +
        R"({"id":"TEST-IP","type":"ipv4","value":"203.0.113.42","confidence":"medium","status":"active","source_url":"https://bbs.kafan.cn/thread-test","observed_at":"2026-08-02"},)" +
        R"({"id":"TEST-CANDIDATE","type":"domain","value":"ignored.invalid","confidence":"low","status":"candidate","source_url":"https://bbs.kafan.cn/thread-test","observed_at":"2026-08-02"}]})";
}

void TestSilverFoxIocs() {
    const char* path = "edr-native-silverfox-ioc.json";
    WriteFile(path, TestIocJson());
    edr::SilverFoxDetector detector(true, 600, 128);
    std::string error;
    SF_CHECK(detector.LoadIndicators(path, error));
    SF_CHECK(error.empty());
    SF_CHECK(detector.IndicatorCount() == 4);

    edr::Event hash;
    hash.type = EDR_EVT_FILE_CREATE;
    hash.ts100ns = 1000;
    hash.fields[edr::field::kSha256] = std::string(64, 'A');
    detector.Enrich(hash);
    SF_CHECK(hash.fields.at(edr::field::kSilverFoxFamily) ==
             "SilverFox");
    SF_CHECK(hash.fields.at(edr::field::kSilverFoxSignals).find(
                 "VERIFIED_HASH_IOC") != std::string::npos);
    SF_CHECK(hash.fields.at(edr::field::kSilverFoxIocIds) ==
             "TEST-HASH");
    SF_CHECK(hash.fields.at(edr::field::kSilverFoxIocSources).find(
                 "https://bbs.kafan.cn/") == 0);

    edr::Event certificate;
    certificate.type = EDR_EVT_FILE_CREATE;
    certificate.ts100ns = 2000;
    certificate.fields[edr::field::kSignerCertificateSha256] =
        std::string(64, 'B');
    detector.Enrich(certificate);
    SF_CHECK(certificate.fields.at(
        edr::field::kSilverFoxIocIds) == "TEST-CERT");

    edr::Event domain;
    domain.type = EDR_EVT_DNS_QUERY;
    domain.ts100ns = 3000;
    domain.fields[edr::field::kTargetHost] =
        "cdn.sample.invalid.";
    detector.Enrich(domain);
    SF_CHECK(domain.fields.at(
        edr::field::kSilverFoxIocIds) == "TEST-DOMAIN");

    edr::Event ip;
    ip.type = EDR_EVT_NET_CONNECT;
    ip.ts100ns = 4000;
    ip.fields[edr::field::kDstIp] = "203.0.113.42";
    detector.Enrich(ip);
    SF_CHECK(ip.fields.at(
        edr::field::kSilverFoxIocIds) == "TEST-IP");

    WriteFile(path,
        R"({"schema_version":2,"family":"SilverFox","indicators":[{"id":"BAD","type":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","confidence":"high","status":"active","observed_at":"2026-08-02"}]})");
    SF_CHECK(!detector.LoadIndicators(path, error));
    SF_CHECK(!error.empty());
    SF_CHECK(detector.IndicatorCount() == 4);

    edr::SilverFoxDetector disabled(false, 600, 128);
    SF_CHECK(disabled.LoadIndicators(path, error) == false);
    edr::Event disabledEvent = hash;
    disabledEvent.fields.clear();
    disabledEvent.fields[edr::field::kSha256] =
        std::string(64, 'a');
    disabled.Enrich(disabledEvent);
    SF_CHECK(disabledEvent.fields.find(
        edr::field::kSilverFoxFamily) ==
        disabledEvent.fields.end());

    const char* productionPath =
        GetFileAttributesA("..\\rules\\silverfox_ioc.v2.json") !=
                INVALID_FILE_ATTRIBUTES
            ? "..\\rules\\silverfox_ioc.v2.json"
            : "rules\\silverfox_ioc.v2.json";
    edr::SilverFoxDetector production(true, 600, 128);
    SF_CHECK(production.LoadIndicators(productionPath, error));
    SF_CHECK(production.IndicatorCount() == 0);
    DeleteFileA(path);
}
edr::Event ProcessEvent(uint32_t pid, uint32_t ppid,
                        const std::string& image,
                        const std::string& parent,
                        const std::string& commandLine,
                        const char* signature = "trusted") {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns =
        100000000ULL + static_cast<uint64_t>(pid) * 10000000ULL;
    event.pid = pid;
    event.ppid = ppid;
    event.processIdentity = "test-process-" + std::to_string(pid);
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kPid] = std::to_string(pid);
    event.fields[edr::field::kPpid] = std::to_string(ppid);
    event.fields[edr::field::kImage] = image;
    if (!parent.empty())
        event.fields[edr::field::kParentImage] = parent;
    if (!commandLine.empty())
        event.fields[edr::field::kCommandLine] = commandLine;
    event.fields[edr::field::kSignatureStatus] = signature;
    return event;
}

edr::Event FakeInstallerEvent(uint32_t pid) {
    const std::string systemLoader =
        std::string("C:\\Windows\\System32\\run") + "dll32.exe";
    const std::string command =
        std::string("run") + "dll32.exe C:\\Users\\alice\\AppData\\"
        "Local\\Temp\\Rar" + "$EX00\\payload.dat,Start";
    return ProcessEvent(
        pid, 10, systemLoader,
        "C:\\Users\\alice\\Downloads\\setup.exe", command);
}
void TestSilverFoxBehaviorSignals() {
    edr::SilverFoxDetector detector(true, 600, 128);

    const std::string analysisName =
        std::string("Process") + "Hacker.exe";
    edr::Event analysisTool = ProcessEvent(
        10, 1, "C:\\Tools\\" + analysisName,
        "C:\\Windows\\explorer.exe", "C:\\Tools\\" + analysisName);
    detector.Enrich(analysisTool);
    SF_CHECK(analysisTool.fields.find(
        edr::field::kSilverFoxFamily) == analysisTool.fields.end());

    const std::string loader =
        std::string("C:\\Windows\\System32\\run") + "dll32.exe";
    const std::string benignCommand =
        std::string("run") +
        "dll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL";
    edr::Event benignLoader = ProcessEvent(
        11, 1, loader, "C:\\Program Files\\Vendor\\setup.exe",
        benignCommand);
    detector.Enrich(benignLoader);
    SF_CHECK(benignLoader.fields.find(
        edr::field::kSilverFoxFamily) == benignLoader.fields.end());

    edr::Event userApp = ProcessEvent(
        20, 1, "C:\\Users\\alice\\AppData\\Local\\Vendor\\app.exe",
        "C:\\Windows\\explorer.exe", "", "trusted");
    detector.Enrich(userApp);
    SF_CHECK(userApp.fields.find(
        edr::field::kSilverFoxFamily) == userApp.fields.end());

    edr::Event fake = FakeInstallerEvent(30);
    detector.Enrich(fake);
    SF_CHECK(fake.fields.at(edr::field::kSilverFoxConfidence) ==
             "high");
    SF_CHECK(fake.fields.at(edr::field::kSilverFoxSignals).find(
                 "FAKE_INSTALLER_CHAIN") != std::string::npos);

    edr::Event medium = ProcessEvent(
        31, 1, "C:\\Vendor\\svchost.exe",
        "C:\\Windows\\explorer.exe", "", "trusted");
    detector.Enrich(medium);
    SF_CHECK(medium.fields.at(edr::field::kSilverFoxConfidence) ==
             "medium");
    SF_CHECK(medium.fields.at(edr::field::kSilverFoxSignals).find(
                 "MASQUERADED_SYSTEM_BINARY") != std::string::npos);
}

void TestSilverFoxSideLoad() {
    edr::SilverFoxDetector detector(true, 600, 128);
    edr::Event process = ProcessEvent(
        40, 1, "C:\\Users\\alice\\AppData\\Local\\Vendor\\app.exe",
        "C:\\Windows\\explorer.exe", "", "trusted");
    detector.Enrich(process);

    edr::Event imageLoad;
    imageLoad.type = EDR_EVT_IMAGE_LOAD;
    imageLoad.ts100ns = process.ts100ns + 1000;
    imageLoad.pid = process.pid;
    imageLoad.processIdentity = process.processIdentity;
    imageLoad.fields[edr::field::kType] = "IMAGE_LOAD";
    imageLoad.fields[edr::field::kImage] =
        "C:\\Users\\alice\\AppData\\Local\\Vendor\\app.exe";
    imageLoad.fields[edr::field::kTargetImage] =
        "C:\\Users\\alice\\AppData\\Local\\Vendor\\version.dll";
    imageLoad.fields[edr::field::kSignatureStatus] =
        "unsigned_embedded";
    detector.Enrich(imageLoad);

    SF_CHECK(imageLoad.fields.at(
        edr::field::kSilverFoxConfidence) == "high");
    SF_CHECK(imageLoad.fields.at(
        edr::field::kSilverFoxSignals).find(
            "USER_WRITABLE_SIDELOAD") != std::string::npos);
}

void TestSilverFoxCorrelation() {
    edr::SilverFoxDetector detector(true, 600, 128);
    edr::Event process = ProcessEvent(
        50, 1, "C:\\Users\\alice\\AppData\\Local\\Cache\\helper.exe",
        "C:\\Windows\\explorer.exe", "", "unsigned_embedded");
    detector.Enrich(process);

    edr::Event script;
    script.type = EDR_EVT_POWERSHELL_SCRIPT;
    script.ts100ns = process.ts100ns + 1000;
    script.pid = process.pid;
    script.processIdentity = process.processIdentity;
    script.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    script.fields[edr::field::kScriptBlockText] =
        std::string("Add-") + "MpPreference -Exclusion" +
        "Path C:\\Users\\alice\\AppData\\Local\\Cache";
    detector.Enrich(script);
    SF_CHECK(script.fields.at(
        edr::field::kSilverFoxSignals).find(
            "CORRELATED_DEFENDER_TAMPER") != std::string::npos);

    edr::Event persistence;
    persistence.type = EDR_EVT_REG_WRITE;
    persistence.ts100ns = script.ts100ns + 1000;
    persistence.pid = process.pid;
    persistence.processIdentity = process.processIdentity;
    persistence.fields[edr::field::kType] = "REG_WRITE";
    persistence.fields[edr::field::kRegKey] =
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater";
    persistence.fields[edr::field::kRegValue] =
        "C:\\Users\\alice\\AppData\\Local\\Cache\\helper.exe";
    detector.Enrich(persistence);
    SF_CHECK(persistence.fields.at(
        edr::field::kSilverFoxSignals).find(
            "CORRELATED_RUNKEY_PERSISTENCE") != std::string::npos);
}

edr::Event InjectionNetworkEvent(edr::SilverFoxDetector& detector,
                                 uint32_t pid) {
    edr::Event process = ProcessEvent(
        pid, 1, "C:\\Users\\alice\\AppData\\Local\\Cache\\client.exe",
        "C:\\Windows\\explorer.exe", "", "trusted");
    detector.Enrich(process);

    edr::Event access;
    access.type = EDR_EVT_PROCESS_ACCESS;
    access.ts100ns = process.ts100ns + 1000;
    access.pid = process.pid;
    access.processIdentity = process.processIdentity;
    access.fields[edr::field::kType] = "PROCESS_ACCESS";
    access.fields[edr::field::kImage] =
        "C:\\Users\\alice\\AppData\\Local\\Cache\\client.exe";
    access.fields[edr::field::kCrossProcess] = "true";
    access.fields[edr::field::kAccessCreateThread] = "true";
    access.fields[edr::field::kAccessVmOperation] = "true";
    access.fields[edr::field::kAccessVmWrite] = "true";
    detector.Enrich(access);
    SF_CHECK(access.fields.at(
        edr::field::kSilverFoxSignals).find(
            "CORRELATED_PROCESS_INJECTION") != std::string::npos);

    edr::Event network;
    network.type = EDR_EVT_NET_CONNECT;
    network.ts100ns = access.ts100ns + 1000;
    network.pid = process.pid;
    network.processIdentity = process.processIdentity;
    network.fields[edr::field::kType] = "NET_CONNECT";
    network.fields[edr::field::kDstIp] = "198.51.100.20";
    network.fields[edr::field::kDstPort] = "443";
    detector.Enrich(network);
    return network;
}

void TestSilverFoxInjectionNetwork() {
    edr::SilverFoxDetector detector(true, 600, 128);
    edr::Event network = InjectionNetworkEvent(detector, 60);
    SF_CHECK(network.fields.at(
        edr::field::kSilverFoxSignals).find(
            "POST_INJECTION_NETWORK") != std::string::npos);
    SF_CHECK(network.fields.at(
        edr::field::kSilverFoxConfidence) == "high");

    edr::SilverFoxDetector expiring(true, 30, 128);
    edr::Event fake = FakeInstallerEvent(70);
    expiring.Enrich(fake);
    edr::Event lateNetwork;
    lateNetwork.type = EDR_EVT_NET_CONNECT;
    lateNetwork.ts100ns = fake.ts100ns + 31ULL * 10000000ULL;
    lateNetwork.pid = fake.pid;
    lateNetwork.processIdentity = fake.processIdentity;
    lateNetwork.fields[edr::field::kType] = "NET_CONNECT";
    lateNetwork.fields[edr::field::kDstIp] = "198.51.100.21";
    expiring.Enrich(lateNetwork);
    SF_CHECK(lateNetwork.fields.find(
        edr::field::kSilverFoxFamily) == lateNetwork.fields.end());
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

void Evaluate(edr::RuleEngine& engine, edr::Event& event,
              std::vector<std::string>& hits) {
    hits.clear();
    engine.OnEvent(event);
}
void TestSilverFoxProductionRules() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) {
            hits.push_back(alert.ruleId);
        });
    edr::SilverFoxDetector detector(true, 600, 128);

    edr::Event fake = FakeInstallerEvent(80);
    detector.Enrich(fake);
    Evaluate(engine, fake, hits);
    SF_CHECK(HasRule(hits, "SF-001"));
    SF_CHECK(HasRule(hits, "SF-003"));
    SF_CHECK(HasRule(hits, "SF-010"));
    SF_CHECK(!HasRule(hits, "SF-004"));

    edr::Event medium = ProcessEvent(
        81, 1, "C:\\Vendor\\svchost.exe",
        "C:\\Windows\\explorer.exe", "", "trusted");
    detector.Enrich(medium);
    Evaluate(engine, medium, hits);
    SF_CHECK(!HasRule(hits, "SF-002"));
    SF_CHECK(HasRule(hits, "SF-009"));
    SF_CHECK(!HasRule(hits, "SF-001"));
    edr::Event mediumNetwork;
    mediumNetwork.type = EDR_EVT_NET_CONNECT;
    mediumNetwork.ts100ns = medium.ts100ns + 1000;
    mediumNetwork.pid = medium.pid;
    mediumNetwork.processIdentity = medium.processIdentity;
    mediumNetwork.fields[edr::field::kType] = "NET_CONNECT";
    mediumNetwork.fields[edr::field::kDstIp] = "198.51.100.30";
    mediumNetwork.fields[edr::field::kDstPort] = "443";
    detector.Enrich(mediumNetwork);
    Evaluate(engine, mediumNetwork, hits);
    SF_CHECK(HasRule(hits, "SF-002"));
    SF_CHECK(!HasRule(hits, "SF-001"));

    const std::string tool =
        std::string("C:\\Tools\\Process") + "Hacker.exe";
    edr::Event benign = ProcessEvent(
        82, 1, tool, "C:\\Windows\\explorer.exe", tool);
    detector.Enrich(benign);
    Evaluate(engine, benign, hits);
    for (const std::string& id : hits)
        SF_CHECK(id.rfind("SF-", 0) != 0);

    edr::Event process = ProcessEvent(
        83, 1, "C:\\Users\\alice\\AppData\\Local\\Vendor\\app.exe",
        "C:\\Windows\\explorer.exe", "", "trusted");
    detector.Enrich(process);
    edr::Event imageLoad;
    imageLoad.type = EDR_EVT_IMAGE_LOAD;
    imageLoad.ts100ns = process.ts100ns + 1000;
    imageLoad.pid = process.pid;
    imageLoad.processIdentity = process.processIdentity;
    imageLoad.fields[edr::field::kType] = "IMAGE_LOAD";
    imageLoad.fields[edr::field::kImage] =
        "C:\\Users\\alice\\AppData\\Local\\Vendor\\app.exe";
    imageLoad.fields[edr::field::kTargetImage] =
        "C:\\Users\\alice\\AppData\\Local\\Vendor\\version.dll";
    imageLoad.fields[edr::field::kSignatureStatus] =
        "unsigned_embedded";
    detector.Enrich(imageLoad);
    Evaluate(engine, imageLoad, hits);
    SF_CHECK(HasRule(hits, "SF-005"));
}

void TestSilverFoxCorrelatedRules() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) {
            hits.push_back(alert.ruleId);
        });
    edr::SilverFoxDetector detector(true, 600, 128);

    edr::Event process = ProcessEvent(
        90, 1, "C:\\Users\\alice\\AppData\\Local\\Cache\\helper.exe",
        "C:\\Windows\\explorer.exe", "", "unsigned_embedded");
    detector.Enrich(process);
    edr::Event script;
    script.type = EDR_EVT_POWERSHELL_SCRIPT;
    script.ts100ns = process.ts100ns + 1000;
    script.pid = process.pid;
    script.processIdentity = process.processIdentity;
    script.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    script.fields[edr::field::kScriptBlockText] =
        std::string("Add-") + "MpPreference -Exclusion" +
        "Path C:\\Users\\alice\\AppData\\Local\\Cache";
    detector.Enrich(script);
    Evaluate(engine, script, hits);
    SF_CHECK(HasRule(hits, "SF-006"));

    edr::Event persistence;
    persistence.type = EDR_EVT_REG_WRITE;
    persistence.ts100ns = script.ts100ns + 1000;
    persistence.pid = process.pid;
    persistence.processIdentity = process.processIdentity;
    persistence.fields[edr::field::kType] = "REG_WRITE";
    persistence.fields[edr::field::kRegKey] =
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater";
    persistence.fields[edr::field::kRegValue] =
        "C:\\Users\\alice\\AppData\\Local\\Cache\\helper.exe";
    detector.Enrich(persistence);
    Evaluate(engine, persistence, hits);
    SF_CHECK(HasRule(hits, "SF-007"));

    edr::Event network = InjectionNetworkEvent(detector, 91);
    Evaluate(engine, network, hits);
    SF_CHECK(HasRule(hits, "SF-008"));
}

void TestSilverFoxIocRule() {
    const char* path = "edr-native-silverfox-rule-ioc.json";
    WriteFile(path, TestIocJson());
    edr::SilverFoxDetector detector(true, 600, 128);
    std::string error;
    SF_CHECK(detector.LoadIndicators(path, error));

    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.ts100ns = 9000000000ULL;
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kSha256] = std::string(64, 'a');
    detector.Enrich(event);

    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) {
            hits.push_back(alert.ruleId);
        });
    Evaluate(engine, event, hits);
    SF_CHECK(HasRule(hits, "SF-001"));
    SF_CHECK(HasRule(hits, "SF-004"));
    SF_CHECK(!HasRule(hits, "SF-010"));
    DeleteFileA(path);
}

void TestSilverFoxByovdSignals() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) {
            hits.push_back(alert.ruleId);
        });
    edr::SilverFoxDetector detector(true, 600, 128);

    /* BYOVD: a suspicious-context process stages a known-abused
     * vulnerable driver. USER_WRITABLE_EXECUTION (15) +
     * UNTRUSTED_EXECUTABLE (15) + BYOVD_DRIVER_ARTIFACT (60) +
     * CORRELATED_BYOVD_DRIVER_ARTIFACT (25) = high confidence. */
    edr::Event process = ProcessEvent(
        95, 1,
        std::string("C:\\Users\\bob\\AppData\\Local\\Temp\\") +
            "dropper.exe",
        "C:\\Windows\\explorer.exe", "", "unsigned_embedded");
    detector.Enrich(process);

    edr::Event driverFile;
    driverFile.type = EDR_EVT_FILE_CREATE;
    driverFile.ts100ns = process.ts100ns + 1000;
    driverFile.pid = process.pid;
    driverFile.processIdentity = process.processIdentity;
    driverFile.fields[edr::field::kType] = "FILE_CREATE";
    driverFile.fields[edr::field::kFilePath] =
        "C:\\Users\\bob\\AppData\\Local\\Temp\\rtcore64.sys";
    detector.Enrich(driverFile);
    Evaluate(engine, driverFile, hits);
    SF_CHECK(HasRule(hits, "SF-011"));

    /* Security-software tamper access from the same process. */
    edr::Event tamperAccess;
    tamperAccess.type = EDR_EVT_PROCESS_ACCESS;
    tamperAccess.ts100ns = process.ts100ns + 2000;
    tamperAccess.pid = process.pid;
    tamperAccess.processIdentity = process.processIdentity;
    tamperAccess.fields[edr::field::kType] = "PROCESS_ACCESS";
    tamperAccess.fields[edr::field::kImage] =
        "C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe";
    tamperAccess.fields[edr::field::kTargetImage] =
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
        "4.18.24040.4-0\\MsMpEng.exe";
    tamperAccess.fields[edr::field::kCrossProcess] = "true";
    tamperAccess.fields[edr::field::kAccessVmRead] = "true";
    detector.Enrich(tamperAccess);
    Evaluate(engine, tamperAccess, hits);
    SF_CHECK(HasRule(hits, "SF-012"));
}

void TestSilverFoxMasqueradeExtension() {
    edr::SilverFoxDetector detector(true, 600, 128);

    /* wudfhost.exe outside the system directories is now a masquerade
     * signal, matching public SilverFox reporting. Combined score:
     * MASQUERADED_SYSTEM_BINARY (55) + USER_WRITABLE_EXECUTION (15) =
     * 70 -> medium confidence. */
    edr::Event wudf = ProcessEvent(
        96, 1, "C:\\Users\\carol\\AppData\\Roaming\\wudfhost.exe",
        "C:\\Windows\\explorer.exe", "");
    detector.Enrich(wudf);
    auto scoreIt = wudf.fields.find(edr::field::kSilverFoxScore);
    SF_CHECK(scoreIt != wudf.fields.end());
    SF_CHECK(scoreIt->second == "70");

    auto signalsIt = wudf.fields.find(edr::field::kSilverFoxSignals);
    SF_CHECK(signalsIt != wudf.fields.end());
    SF_CHECK(signalsIt->second.find("MASQUERADED_SYSTEM_BINARY") !=
             std::string::npos);

    /* A service install referencing an abused .sys name fires the BYOVD
     * signal on its own (name-token match is intentional: driver staging
     * by any context is worth surfacing). */
    edr::Event byovdStaging;
    byovdStaging.type = EDR_EVT_SERVICE_INSTALL;
    byovdStaging.ts100ns = 100000000ULL + 97ULL * 10000000ULL;
    byovdStaging.pid = 97;
    byovdStaging.processIdentity = "test-process-97";
    byovdStaging.fields[edr::field::kType] = "SERVICE_INSTALL";
    byovdStaging.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\sc.exe";
    byovdStaging.fields[edr::field::kCommandLine] =
        "sc create drv binPath= C:\\Temp\\gmer.sys type= kernel";
    detector.Enrich(byovdStaging);
    auto byovdScore = byovdStaging.fields.find(
        edr::field::kSilverFoxScore);
    SF_CHECK(byovdScore != byovdStaging.fields.end());
}

} // namespace

void RunSilverFoxTests() {
    TestSilverFoxConfig();
    TestSilverFoxIocs();
    TestSilverFoxBehaviorSignals();
    TestSilverFoxSideLoad();
    TestSilverFoxCorrelation();
    TestSilverFoxInjectionNetwork();
    TestSilverFoxProductionRules();
    TestSilverFoxCorrelatedRules();
    TestSilverFoxIocRule();
    TestSilverFoxByovdSignals();
    TestSilverFoxMasqueradeExtension();
}
