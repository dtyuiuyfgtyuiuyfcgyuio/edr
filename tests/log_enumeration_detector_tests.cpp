/*
 * log_enumeration_detector_tests.cpp - Unit tests for
 * LogEnumerationDetector (T1654) and the production rules that consume
 * its score field.
 *
 * Detector tiers asserted here (per user/log_enumeration_detector.cpp):
 *   75 security_log_targeting  inventory enumeration or log-config query
 *                              naming a defensive channel (Security,
 *                              Sysmon, Defender, ...).
 *   65 event_log_enumeration   bulk inventory enumeration (wevtutil el /
 *                              Get-WinEvent -ListLog / Get-EventLog -List).
 *   60 log_config_query        per-log configuration read (wevtutil gl /
 *                              Get-WinEvent -ListProvider).
 *   Deliberate silences: wevtutil clear-log / cl / sl (tamper, owned by
 *   eventlog_tamper / defense_evasion) and wevtutil qe (content reading).
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-510  log_enumeration_score >= 75   high/alert  T1654
 *   EDR-511  log_enumeration_score 55-74   medium/log  T1654
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "log_enumeration_detector_tests.h"

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
#include "log_enumeration_detector.h"
#include "rule_engine.h"

namespace {

#define LE_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "log enumeration test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

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
    return event.fields.find(edr::field::kLogEnumerationScore) !=
           event.fields.end();
}

void TestInspects() {
    LE_CHECK(edr::LogEnumerationDetector::Inspects(EDR_EVT_PROCESS_START));
    LE_CHECK(edr::LogEnumerationDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    LE_CHECK(!edr::LogEnumerationDetector::Inspects(EDR_EVT_NET_LISTENER));
    LE_CHECK(!edr::LogEnumerationDetector::Inspects(EDR_EVT_REG_WRITE));
    LE_CHECK(!edr::LogEnumerationDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::LogEnumerationDetector detector(false, 55, 300, 1024);
    edr::Event el = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil el");
    detector.Enrich(el);
    LE_CHECK(!HasScore(el));
    edr::Event security = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil gl security");
    detector.Enrich(security);
    LE_CHECK(!HasScore(security));
}

void TestSecurityLogTargetingTier75() {
    edr::LogEnumerationDetector detector(true, 55, 300, 1024);

    /* All of these share the "security_log_targeting" dedup key, so the
     * events must be spaced past the default 300s window. */
    edr::Event config = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil gl security");
    detector.Enrich(config);
    LE_CHECK(config.fields.at(edr::field::kLogEnumerationScore) == "75");
    LE_CHECK(config.fields.at(edr::field::kLogEnumerationVerdict) ==
             "malicious");
    LE_CHECK(config.fields.at(edr::field::kLogEnumerationSignals) ==
             "security_log_targeting");
    LE_CHECK(config.fields.at(edr::field::kLogEnumerationChannels) ==
             "security");
    LE_CHECK(config.fields.at(edr::field::kLogEnumerationTools) ==
             "wevtutil gl");

    edr::Event sysmon = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil gl Microsoft-Windows-Sysmon/Operational");
    detector.Enrich(sysmon);
    LE_CHECK(sysmon.fields.at(edr::field::kLogEnumerationScore) == "75");
    LE_CHECK(sysmon.fields.at(edr::field::kLogEnumerationChannels) ==
             "sysmon");

    /* PowerShell plane: body lives ONLY in kScriptBlockText. */
    edr::Event ps = PsScriptEvent(
        1800 * kSecond, "Get-WinEvent -ListLog Security -ErrorAction Stop");
    detector.Enrich(ps);
    LE_CHECK(ps.fields.at(edr::field::kLogEnumerationScore) == "75");
    LE_CHECK(ps.fields.at(edr::field::kLogEnumerationSignals) ==
             "security_log_targeting");
}

void TestBulkEnumerationTier65() {
    edr::LogEnumerationDetector detector(true, 55, 300, 1024);

    edr::Event el = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil el");
    detector.Enrich(el);
    LE_CHECK(el.fields.at(edr::field::kLogEnumerationScore) == "65");
    LE_CHECK(el.fields.at(edr::field::kLogEnumerationVerdict) ==
             "suspicious");
    LE_CHECK(el.fields.at(edr::field::kLogEnumerationSignals) ==
             "event_log_enumeration");

    edr::Event ps = PsScriptEvent(
        1400 * kSecond, "Get-WinEvent -ListLog * | Select-Object LogName");
    detector.Enrich(ps);
    LE_CHECK(ps.fields.at(edr::field::kLogEnumerationScore) == "65");

    edr::Event legacy = PsScriptEvent(1800 * kSecond, "Get-EventLog -List");
    detector.Enrich(legacy);
    LE_CHECK(legacy.fields.at(edr::field::kLogEnumerationScore) == "65");
}

void TestLogConfigTier60() {
    edr::LogEnumerationDetector detector(true, 55, 300, 1024);

    edr::Event gl = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil gl Application");
    detector.Enrich(gl);
    LE_CHECK(gl.fields.at(edr::field::kLogEnumerationScore) == "60");
    LE_CHECK(gl.fields.at(edr::field::kLogEnumerationSignals) ==
             "log_config_query");
    LE_CHECK(gl.fields.find(edr::field::kLogEnumerationChannels) ==
             gl.fields.end());

    edr::Event providers = PsScriptEvent(
        1400 * kSecond, "Get-WinEvent -ListProvider *");
    detector.Enrich(providers);
    LE_CHECK(providers.fields.at(edr::field::kLogEnumerationScore) == "60");
}

void TestTamperSilent() {
    edr::LogEnumerationDetector detector(true, 55, 300, 1024);

    /* Clearing, disabling and reconfiguring logs is tamper, owned by
     * eventlog_tamper / defense_evasion - not this discovery detector. */
    const char* const kTamper[] = {
        "wevtutil clear-log Security",
        "wevtutil cl Security",
        "wevtutil sl Security /e:false",
        "wevtutil set-log Security /enabled:false",
    };
    for (int i = 0; i < 4; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\wevtutil.exe", kTamper[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[log_enum] tamper scored: %s\n",
                         kTamper[i]);
        LE_CHECK(!HasScore(ev));
    }

    /* wevtutil qe reads recorded events (content), not the inventory. */
    edr::Event qe = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil qe Security /c:5 /rd:true /f:text");
    detector.Enrich(qe);
    LE_CHECK(!HasScore(qe));

    /* Get-WinEvent -LogName reads content, not the inventory. */
    edr::Event content = PsScriptEvent(
        1101 * kSecond, "Get-WinEvent -LogName Security -MaxEvents 20");
    detector.Enrich(content);
    LE_CHECK(!HasScore(content));

    LE_CHECK(detector.StateCount() == 0);
}

void TestNormalOpsSilent() {
    edr::LogEnumerationDetector detector(true, 55, 300, 1024);

    const char* const kNormalOps[] = {
        "eventvwr.msc",
        "Get-WinEvent -FilterHashtable @{LogName='System'} -MaxEvents 10",
        "sc query eventlog",
    };
    for (int i = 0; i < 3; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\cmd.exe", kNormalOps[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[log_enum] op scored: %s\n",
                         kNormalOps[i]);
        LE_CHECK(!HasScore(ev));
    }
    LE_CHECK(detector.StateCount() == 0);
}

void TestMinScoreGating() {
    /* min_score 75: the 65/60 tiers are filtered and, because the gate
     * runs before dedup bookkeeping, no key is inserted. */
    {
        edr::LogEnumerationDetector detector(true, 75, 300, 1024);
        edr::Event el = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
            "wevtutil el");
        detector.Enrich(el);
        LE_CHECK(!HasScore(el));
        edr::Event gl = ProcEvent(
            1100 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
            "wevtutil gl Application");
        detector.Enrich(gl);
        LE_CHECK(!HasScore(gl));
        LE_CHECK(detector.StateCount() == 0);

        edr::Event targeted = ProcEvent(
            1200 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
            "wevtutil gl security");
        detector.Enrich(targeted);
        LE_CHECK(targeted.fields.at(edr::field::kLogEnumerationScore) == "75");
        LE_CHECK(detector.StateCount() == 1);
    }
    /* min_score 55 (default): the 60 tier survives. */
    {
        edr::LogEnumerationDetector detector(true, 55, 300, 1024);
        edr::Event gl = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
            "wevtutil gl Application");
        detector.Enrich(gl);
        LE_CHECK(gl.fields.at(edr::field::kLogEnumerationScore) == "60");
    }
}

void TestDedupPerTier() {
    edr::LogEnumerationDetector detector(true, 55, 300, 1024);

    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil el");
    detector.Enrich(first);
    LE_CHECK(HasScore(first));
    LE_CHECK(detector.StateCount() == 1);

    /* Same tier inside the window is suppressed. */
    edr::Event repeat = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil el");
    detector.Enrich(repeat);
    LE_CHECK(!HasScore(repeat));

    /* A different tier is a different key and passes. */
    edr::Event otherTier = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil gl security");
    detector.Enrich(otherTier);
    LE_CHECK(HasScore(otherTier));
    LE_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the first tier. */
    edr::Event late = ProcEvent(
        1000 * kSecond + 301 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil el");
    detector.Enrich(late);
    LE_CHECK(HasScore(late));
    LE_CHECK(detector.StateCount() == 2);
}

void TestStateCapacityReset() {
    edr::LogEnumerationDetector detector(true, 55, 300, 1);
    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil el");
    detector.Enrich(first);
    LE_CHECK(HasScore(first));
    LE_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event second = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil gl security");
    detector.Enrich(second);
    LE_CHECK(HasScore(second));
    LE_CHECK(detector.StateCount() == 1);

    /* The reset re-arms the first tier (its key was cleared). */
    edr::Event again = ProcEvent(
        1200 * kSecond, "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil el");
    detector.Enrich(again);
    LE_CHECK(HasScore(again));
    LE_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::LogEnumerationDetector detector(true, 55, 300, 1024);

    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 1000 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] = "wevtutil el";
    detector.Enrich(reg);
    LE_CHECK(!HasScore(reg));

    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1001 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    LE_CHECK(!HasScore(ps));

    edr::Event proc = ProcEvent(1002 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe", nullptr);
    detector.Enrich(proc);
    LE_CHECK(!HasScore(proc));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set log_enumeration_score field (the RuleEngine never
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
        ev.fields[edr::field::kLogEnumerationScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-510 (log_enumeration_score >= 75, high/alert, T1654) and
     * EDR-511 (55-74, medium/log, T1654) are written to rules/rules.json
     * by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[log_enum] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-510") == std::string::npos ||
        rulesText.find("EDR-511") == std::string::npos) {
        std::fprintf(stderr,
                     "[log_enum] EDR-510/EDR-511 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* High band: 100/75 land in >=75, so they hit EDR-510 only. */
    FeedScore(&engine, "100");
    LE_CHECK(HasAlert("EDR-510"));
    LE_CHECK(!HasAlert("EDR-511"));
    const AlertRecord* high = FindAlert("EDR-510");
    LE_CHECK(high != nullptr);
    LE_CHECK(high->severity == "high");
    LE_CHECK(high->action == "alert");
    LE_CHECK(std::find(high->mitre.begin(), high->mitre.end(), "T1654") !=
             high->mitre.end());

    FeedScore(&engine, "75");
    LE_CHECK(HasAlert("EDR-510"));
    LE_CHECK(!HasAlert("EDR-511"));

    /* Mid band: 74 must NOT hit the >=75 rule; 65/60/55 hit EDR-511 only. */
    FeedScore(&engine, "74");
    LE_CHECK(HasAlert("EDR-511"));
    LE_CHECK(!HasAlert("EDR-510"));
    const AlertRecord* mid = FindAlert("EDR-511");
    LE_CHECK(mid != nullptr);
    LE_CHECK(mid->severity == "medium");
    LE_CHECK(mid->action == "log");
    LE_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(), "T1654") !=
             mid->mitre.end());
    FeedScore(&engine, "65");
    LE_CHECK(HasAlert("EDR-511"));
    LE_CHECK(!HasAlert("EDR-510"));
    FeedScore(&engine, "60");
    LE_CHECK(HasAlert("EDR-511"));
    LE_CHECK(!HasAlert("EDR-510"));
    FeedScore(&engine, "55");
    LE_CHECK(HasAlert("EDR-511"));
    LE_CHECK(!HasAlert("EDR-510"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    LE_CHECK(!HasAlert("EDR-510"));
    LE_CHECK(!HasAlert("EDR-511"));
    FeedScore(&engine, "50");
    LE_CHECK(!HasAlert("EDR-510"));
    LE_CHECK(!HasAlert("EDR-511"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    LE_CHECK(!HasAlert("EDR-510"));
    LE_CHECK(!HasAlert("EDR-511"));
}

} // namespace

void RunLogEnumerationDetectorTests() {
    std::fprintf(stderr, "[log_enum] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[log_enum] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[log_enum] TestSecurityLogTargetingTier75\n");
    TestSecurityLogTargetingTier75();
    std::fprintf(stderr, "[log_enum] TestBulkEnumerationTier65\n");
    TestBulkEnumerationTier65();
    std::fprintf(stderr, "[log_enum] TestLogConfigTier60\n");
    TestLogConfigTier60();
    std::fprintf(stderr, "[log_enum] TestTamperSilent\n");
    TestTamperSilent();
    std::fprintf(stderr, "[log_enum] TestNormalOpsSilent\n");
    TestNormalOpsSilent();
    std::fprintf(stderr, "[log_enum] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[log_enum] TestDedupPerTier\n");
    TestDedupPerTier();
    std::fprintf(stderr, "[log_enum] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[log_enum] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[log_enum] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[log_enum] all passed\n");
}
