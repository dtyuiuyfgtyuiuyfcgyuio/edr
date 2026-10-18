/*
 * cloud_metadata_detector_tests.cpp - Unit tests for CloudMetadataDetector
 * (T1552.005) and the production rules that consume its score field.
 *
 * Detector tiers asserted here (per user/cloud_metadata_detector.cpp):
 *   85 imds_link_local    169.254.169.254 (octet-bounded) and
 *                          fd00:ec2::254, across the command, PowerShell
 *                          (body ONLY in kScriptBlockText) and kImage
 *                          fallback planes.
 *   85 gcp_metadata_host  metadata.google.internal / metadata.goog.
 *   80 cloud_metadata_host metadata.tencentyun.com / metadata.azure.com /
 *                          metadata.oraclecloud.com and the Alibaba IMDS
 *                          address 100.100.100.200 (octet-bounded).
 *   70 imds_token_shape   x-aws-ec2-metadata-token / metadata-flavor /
 *                          /metadata/identity/oauth2/token /
 *                          /metadata/instance?api-version.
 *   Octet-bounded needles keep longer dotted runs (169.254.169.2545,
 *   1169.254.169.254, 100.100.100.2000) silent; ordinary HTTP fetches and
 *   local network commands never score.
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-496  cloud_metadata_score >= 75   high/alert  T1552.005
 *   EDR-497  cloud_metadata_score 55-74   medium/log  T1552.005
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "cloud_metadata_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "cloud_metadata_detector.h"
#include "rule_engine.h"

namespace {

#define CM_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "cloud metadata detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

/* House contract: POWERSHELL_SCRIPT bodies live ONLY in kScriptBlockText
 * (never kCommandLine) and every test event carries an explicit ts100ns. */
edr::Event PsScriptEvent(uint64_t ts, const char* scriptText) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptText;
    return event;
}

edr::Event ProcEvent(uint64_t ts, const char* image, const char* cmdLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (cmdLine != nullptr)
        event.fields[edr::field::kCommandLine] = cmdLine;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kCloudMetadataScore) !=
           event.fields.end();
}

void TestInspects() {
    CM_CHECK(edr::CloudMetadataDetector::Inspects(EDR_EVT_PROCESS_START));
    CM_CHECK(edr::CloudMetadataDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    CM_CHECK(!edr::CloudMetadataDetector::Inspects(EDR_EVT_NET_LISTENER));
    CM_CHECK(!edr::CloudMetadataDetector::Inspects(EDR_EVT_REG_WRITE));
    CM_CHECK(!edr::CloudMetadataDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::CloudMetadataDetector detector(false, 55, 300, 1024);
    edr::Event cmd = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    detector.Enrich(cmd);
    CM_CHECK(!HasScore(cmd));
    edr::Event ps = PsScriptEvent(
        1001 * kSecond,
        "Invoke-RestMethod http://metadata.google.internal/computeMetadata/v1/");
    detector.Enrich(ps);
    CM_CHECK(!HasScore(ps));
}

void TestLinkLocalTier85() {
    edr::CloudMetadataDetector detector(true, 55, 300, 1024);

    /* curl against the AWS/GCP/Azure link-local IMDS. */
    edr::Event curl = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    detector.Enrich(curl);
    CM_CHECK(curl.fields.at(edr::field::kCloudMetadataScore) == "85");
    CM_CHECK(curl.fields.at(edr::field::kCloudMetadataVerdict) == "malicious");
    CM_CHECK(curl.fields.at(edr::field::kCloudMetadataSignals) ==
             "imds_link_local");
    CM_CHECK(curl.fields.at(edr::field::kCloudMetadataIndicator) ==
             "169.254.169.254");

    /* PowerShell plane: body lives ONLY in kScriptBlockText. */
    edr::Event ps = PsScriptEvent(
        1400 * kSecond,
        "Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'");
    detector.Enrich(ps);
    CM_CHECK(ps.fields.at(edr::field::kCloudMetadataScore) == "85");
    CM_CHECK(ps.fields.at(edr::field::kCloudMetadataSignals) ==
             "imds_link_local");

    /* AWS IMDSv2 IPv6 endpoint. */
    edr::Event v6 = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://[fd00:ec2::254]/latest/meta-data/");
    detector.Enrich(v6);
    CM_CHECK(v6.fields.at(edr::field::kCloudMetadataScore) == "85");
    CM_CHECK(v6.fields.at(edr::field::kCloudMetadataIndicator) ==
             "fd00:ec2::254");

    /* kImage fallback: bare image name without a command line. */
    edr::Event image = ProcEvent(
        2200 * kSecond,
        "C:\\Tools\\169.254.169.254\\probe.exe", nullptr);
    detector.Enrich(image);
    CM_CHECK(image.fields.at(edr::field::kCloudMetadataScore) == "85");
}

void TestGcpHostTier85() {
    edr::CloudMetadataDetector detector(true, 55, 300, 1024);

    edr::Event internal = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl -H \"Metadata-Flavor: Google\" "
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token");
    detector.Enrich(internal);
    CM_CHECK(internal.fields.at(edr::field::kCloudMetadataScore) == "85");
    CM_CHECK(internal.fields.at(edr::field::kCloudMetadataVerdict) ==
             "malicious");
    CM_CHECK(internal.fields.at(edr::field::kCloudMetadataSignals) ==
             "gcp_metadata_host");
    CM_CHECK(internal.fields.at(edr::field::kCloudMetadataIndicator) ==
             "metadata.google.internal");

    edr::Event goog = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://metadata.goog/computeMetadata/v1/");
    detector.Enrich(goog);
    CM_CHECK(goog.fields.at(edr::field::kCloudMetadataScore) == "85");
    CM_CHECK(goog.fields.at(edr::field::kCloudMetadataIndicator) ==
             "metadata.goog");
}

void TestOtherProvidersTier80() {
    edr::CloudMetadataDetector detector(true, 55, 300, 1024);

    edr::Event tencent = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/");
    detector.Enrich(tencent);
    CM_CHECK(tencent.fields.at(edr::field::kCloudMetadataScore) == "80");
    CM_CHECK(tencent.fields.at(edr::field::kCloudMetadataVerdict) ==
             "malicious");
    CM_CHECK(tencent.fields.at(edr::field::kCloudMetadataSignals) ==
             "cloud_metadata_host");

    edr::Event azure = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://metadata.azure.com/metadata/instance");
    detector.Enrich(azure);
    CM_CHECK(azure.fields.at(edr::field::kCloudMetadataScore) == "80");
    CM_CHECK(azure.fields.at(edr::field::kCloudMetadataIndicator) ==
             "metadata.azure.com");

    edr::Event oracle = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://metadata.oraclecloud.com/opc/v2/instance/");
    detector.Enrich(oracle);
    CM_CHECK(oracle.fields.at(edr::field::kCloudMetadataScore) == "80");

    /* Alibaba Cloud IMDS CGNAT address. */
    edr::Event aliyun = ProcEvent(
        2200 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://100.100.100.200/latest/meta-data/");
    detector.Enrich(aliyun);
    CM_CHECK(aliyun.fields.at(edr::field::kCloudMetadataScore) == "80");
    CM_CHECK(aliyun.fields.at(edr::field::kCloudMetadataIndicator) ==
             "100.100.100.200");
}

void TestTokenShapeTier70() {
    edr::CloudMetadataDetector detector(true, 55, 300, 1024);

    /* AWS IMDSv2 header without the endpoint in the text. */
    edr::Event aws = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl -H \"X-aws-ec2-metadata-token: $TOKEN\" http://metadata/");
    detector.Enrich(aws);
    CM_CHECK(aws.fields.at(edr::field::kCloudMetadataScore) == "70");
    CM_CHECK(aws.fields.at(edr::field::kCloudMetadataVerdict) ==
             "suspicious");
    CM_CHECK(aws.fields.at(edr::field::kCloudMetadataSignals) ==
             "imds_token_shape");
    CM_CHECK(aws.fields.at(edr::field::kCloudMetadataIndicator) ==
             "x-aws-ec2-metadata-token");

    edr::Event gcp = PsScriptEvent(
        1400 * kSecond,
        "Invoke-WebRequest -Headers @{\"Metadata-Flavor\"=\"Google\"} "
        "-Uri http://metadata/computeMetadata/v1/");
    detector.Enrich(gcp);
    CM_CHECK(gcp.fields.at(edr::field::kCloudMetadataScore) == "70");

    edr::Event azurePath = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl -H \"Metadata:true\" http://host/metadata/identity/oauth2/token?resource=x");
    detector.Enrich(azurePath);
    CM_CHECK(azurePath.fields.at(edr::field::kCloudMetadataScore) == "70");
    CM_CHECK(azurePath.fields.at(edr::field::kCloudMetadataIndicator) ==
             "/metadata/identity/oauth2/token");

    edr::Event azureInstance = ProcEvent(
        2200 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://host/metadata/instance?api-version=2021-02-01");
    detector.Enrich(azureInstance);
    CM_CHECK(azureInstance.fields.at(edr::field::kCloudMetadataScore) == "70");
}

void TestOctetBoundaryNegatives() {
    edr::CloudMetadataDetector detector(true, 55, 300, 1024);

    const char* const kLookalikes[] = {
        "curl http://169.254.169.2545/latest/meta-data/",
        "curl http://1169.254.169.254/latest/meta-data/",
        "curl http://100.100.100.2000/latest/meta-data/",
    };
    for (int i = 0; i < 3; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\curl.exe", kLookalikes[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[cloud_metadata] lookalike scored: %s\n",
                         kLookalikes[i]);
        CM_CHECK(!HasScore(ev));
    }
}

void TestNormalOpsSilent() {
    edr::CloudMetadataDetector detector(true, 55, 300, 1024);

    const char* const kNormalOps[] = {
        "curl https://example.com/",
        "curl https://169.254.169.254.example.com/",  /* host suffix, not IMDS */
        "ipconfig /all",
        "curl http://192.168.1.1/",
        "netstat -ano",
    };
    for (int i = 0; i < 5; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\cmd.exe", kNormalOps[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[cloud_metadata] op scored: %s\n",
                         kNormalOps[i]);
        CM_CHECK(!HasScore(ev));
    }
    CM_CHECK(detector.StateCount() == 0);
}

void TestMinScoreGating() {
    /* min_score 85: the 80 and 70 tiers are filtered and, because the gate
     * runs before dedup bookkeeping, no key is inserted for them. */
    {
        edr::CloudMetadataDetector detector(true, 85, 300, 1024);
        edr::Event tier80 = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\curl.exe",
            "curl http://metadata.tencentyun.com/latest/meta-data/");
        detector.Enrich(tier80);
        CM_CHECK(!HasScore(tier80));
        edr::Event tier70 = ProcEvent(
            1100 * kSecond, "C:\\Windows\\System32\\curl.exe",
            "curl -H \"Metadata-Flavor: Google\" http://host/");
        detector.Enrich(tier70);
        CM_CHECK(!HasScore(tier70));
        CM_CHECK(detector.StateCount() == 0);

        edr::Event tier85 = ProcEvent(
            1200 * kSecond, "C:\\Windows\\System32\\curl.exe",
            "curl http://169.254.169.254/latest/meta-data/");
        detector.Enrich(tier85);
        CM_CHECK(tier85.fields.at(edr::field::kCloudMetadataScore) == "85");
        CM_CHECK(detector.StateCount() == 1);
    }
    /* min_score 55 (default): the 70 tier survives. */
    {
        edr::CloudMetadataDetector detector(true, 55, 300, 1024);
        edr::Event tier70 = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\curl.exe",
            "curl -H \"Metadata-Flavor: Google\" http://host/");
        detector.Enrich(tier70);
        CM_CHECK(tier70.fields.at(edr::field::kCloudMetadataScore) == "70");
    }
}

void TestDedupPerTier() {
    edr::CloudMetadataDetector detector(true, 55, 300, 1024);

    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://169.254.169.254/latest/meta-data/");
    detector.Enrich(first);
    CM_CHECK(HasScore(first));
    CM_CHECK(detector.StateCount() == 1);

    /* Same tier inside the window is suppressed. */
    edr::Event repeat = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://169.254.169.254/latest/meta-data/");
    detector.Enrich(repeat);
    CM_CHECK(!HasScore(repeat));

    /* A different tier is a different key and passes. */
    edr::Event otherTier = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://metadata.tencentyun.com/latest/meta-data/");
    detector.Enrich(otherTier);
    CM_CHECK(HasScore(otherTier));
    CM_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the first tier. */
    edr::Event late = ProcEvent(
        1000 * kSecond + 301 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://169.254.169.254/latest/meta-data/");
    detector.Enrich(late);
    CM_CHECK(HasScore(late));
    CM_CHECK(detector.StateCount() == 2);
}

void TestStateCapacityReset() {
    edr::CloudMetadataDetector detector(true, 55, 300, 1);
    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://169.254.169.254/latest/meta-data/");
    detector.Enrich(first);
    CM_CHECK(HasScore(first));
    CM_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event second = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://metadata.tencentyun.com/latest/meta-data/");
    detector.Enrich(second);
    CM_CHECK(HasScore(second));
    CM_CHECK(detector.StateCount() == 1);

    /* The reset re-arms the first tier (its key was cleared). */
    edr::Event again = ProcEvent(
        1200 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl http://169.254.169.254/latest/meta-data/");
    detector.Enrich(again);
    CM_CHECK(HasScore(again));
    CM_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::CloudMetadataDetector detector(true, 55, 300, 1024);

    /* Uninspected event type carrying IMDS text in an unrelated field. */
    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 1000 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] = "http://169.254.169.254/";
    detector.Enrich(reg);
    CM_CHECK(!HasScore(reg));

    /* POWERSHELL_SCRIPT without a script body. */
    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1001 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    CM_CHECK(!HasScore(ps));

    /* PROCESS_START without a command line or IMDS image. */
    edr::Event proc = ProcEvent(1002 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe", nullptr);
    detector.Enrich(proc);
    CM_CHECK(!HasScore(proc));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set cloud_metadata_score field (the RuleEngine never
 * calls the detector itself). */
struct AlertRecord {
    std::string ruleId;
    std::string severity;
    std::string action;
    std::vector<std::string> mitre;
};

std::vector<AlertRecord> g_alerts;

bool HasAlert(const char* id) {
    for (const AlertRecord& a : g_alerts)
        if (a.ruleId == id) return true;
    return false;
}

const AlertRecord* FindAlert(const char* id) {
    for (const AlertRecord& a : g_alerts)
        if (a.ruleId == id) return &a;
    return nullptr;
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

std::string ReadAllText(const char* path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

void FeedScore(edr::RuleEngine* engine, const char* score) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.ts100ns = 1000 * kSecond;
    ev.fields[edr::field::kType] = "PROCESS_START";
    if (score != nullptr)
        ev.fields[edr::field::kCloudMetadataScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-496 (cloud_metadata_score >= 75, high/alert, T1552.005) and
     * EDR-497 (55-74, medium/log, T1552.005) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[cloud_metadata] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-496") == std::string::npos ||
        rulesText.find("EDR-497") == std::string::npos) {
        std::fprintf(stderr,
                     "[cloud_metadata] EDR-496/EDR-497 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* High band: 85/80/75 all land in >=75, so they hit EDR-496 only. */
    FeedScore(&engine, "100");
    CM_CHECK(HasAlert("EDR-496"));
    CM_CHECK(!HasAlert("EDR-497"));
    const AlertRecord* high = FindAlert("EDR-496");
    CM_CHECK(high != nullptr);
    CM_CHECK(high->severity == "high");
    CM_CHECK(high->action == "alert");
    CM_CHECK(std::find(high->mitre.begin(), high->mitre.end(),
                       "T1552.005") != high->mitre.end());

    FeedScore(&engine, "85");
    CM_CHECK(HasAlert("EDR-496"));
    CM_CHECK(!HasAlert("EDR-497"));
    FeedScore(&engine, "80");
    CM_CHECK(HasAlert("EDR-496"));
    CM_CHECK(!HasAlert("EDR-497"));
    FeedScore(&engine, "75");
    CM_CHECK(HasAlert("EDR-496"));
    CM_CHECK(!HasAlert("EDR-497"));

    /* Mid band: 74 must NOT hit the >=75 rule; 70/55 hit EDR-497 only. */
    FeedScore(&engine, "74");
    CM_CHECK(HasAlert("EDR-497"));
    CM_CHECK(!HasAlert("EDR-496"));
    const AlertRecord* mid = FindAlert("EDR-497");
    CM_CHECK(mid != nullptr);
    CM_CHECK(mid->severity == "medium");
    CM_CHECK(mid->action == "log");
    CM_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(),
                       "T1552.005") != mid->mitre.end());
    FeedScore(&engine, "70");
    CM_CHECK(HasAlert("EDR-497"));
    CM_CHECK(!HasAlert("EDR-496"));
    FeedScore(&engine, "55");
    CM_CHECK(HasAlert("EDR-497"));
    CM_CHECK(!HasAlert("EDR-496"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    CM_CHECK(!HasAlert("EDR-496"));
    CM_CHECK(!HasAlert("EDR-497"));
    FeedScore(&engine, "50");
    CM_CHECK(!HasAlert("EDR-496"));
    CM_CHECK(!HasAlert("EDR-497"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    CM_CHECK(!HasAlert("EDR-496"));
    CM_CHECK(!HasAlert("EDR-497"));
}

} // namespace

void RunCloudMetadataDetectorTests() {
    std::fprintf(stderr, "[cloud_metadata] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[cloud_metadata] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[cloud_metadata] TestLinkLocalTier85\n");
    TestLinkLocalTier85();
    std::fprintf(stderr, "[cloud_metadata] TestGcpHostTier85\n");
    TestGcpHostTier85();
    std::fprintf(stderr, "[cloud_metadata] TestOtherProvidersTier80\n");
    TestOtherProvidersTier80();
    std::fprintf(stderr, "[cloud_metadata] TestTokenShapeTier70\n");
    TestTokenShapeTier70();
    std::fprintf(stderr, "[cloud_metadata] TestOctetBoundaryNegatives\n");
    TestOctetBoundaryNegatives();
    std::fprintf(stderr, "[cloud_metadata] TestNormalOpsSilent\n");
    TestNormalOpsSilent();
    std::fprintf(stderr, "[cloud_metadata] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[cloud_metadata] TestDedupPerTier\n");
    TestDedupPerTier();
    std::fprintf(stderr, "[cloud_metadata] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[cloud_metadata] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[cloud_metadata] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[cloud_metadata] all passed\n");
}
