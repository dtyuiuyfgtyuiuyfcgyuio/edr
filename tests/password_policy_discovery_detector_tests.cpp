/*
 * password_policy_discovery_detector_tests.cpp - Unit tests for
 * PasswordPolicyDiscoveryDetector (T1201) and the production rules that
 * consume its score field.
 *
 * Detector tiers asserted here (per
 * user/password_policy_discovery_detector.cpp):
 *   75 domain_password_policy_query Get-ADDefaultDomainPasswordPolicy /
 *                                   Get-ADFineGrainedPasswordPolicy /
 *                                   Get-ADUserResultantPasswordPolicy /
 *                                   Get-DomainPolicy, on the command and
 *                                   PowerShell planes.
 *   70 net_accounts_domain_read      `net accounts /domain`.
 *   65 net_accounts_read             bare `net accounts`.
 *   65 secedit_policy_export         `secedit /export`.
 *   Deliberate silences: any `net accounts` carrying a setter flag
 *   (/minpwlen, /maxpwage, /minpwage, /uniquepw, /lockoutthreshold,
 *   /lockoutduration, /lockoutwindow, /forcelogoff) - that is a policy
 *   modification owned by account_op; `secedit /configure`; unrelated
 *   account commands.
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-506  password_policy_score >= 75   high/alert  T1201
 *   EDR-507  password_policy_score 55-74   medium/log  T1201
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "password_policy_discovery_detector_tests.h"

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
#include "password_policy_discovery_detector.h"
#include "rule_engine.h"

namespace {

#define PP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "password policy discovery test failed at line " +
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
    return event.fields.find(edr::field::kPasswordPolicyScore) !=
           event.fields.end();
}

void TestInspects() {
    PP_CHECK(edr::PasswordPolicyDiscoveryDetector::Inspects(
        EDR_EVT_PROCESS_START));
    PP_CHECK(edr::PasswordPolicyDiscoveryDetector::Inspects(
        EDR_EVT_POWERSHELL_SCRIPT));
    PP_CHECK(!edr::PasswordPolicyDiscoveryDetector::Inspects(
        EDR_EVT_NET_LISTENER));
    PP_CHECK(!edr::PasswordPolicyDiscoveryDetector::Inspects(
        EDR_EVT_REG_WRITE));
    PP_CHECK(!edr::PasswordPolicyDiscoveryDetector::Inspects(
        EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::PasswordPolicyDiscoveryDetector detector(false, 55, 300, 1024);
    edr::Event ps = PsScriptEvent(
        1000 * kSecond, "Get-ADDefaultDomainPasswordPolicy");
    detector.Enrich(ps);
    PP_CHECK(!HasScore(ps));
    edr::Event proc = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net accounts /domain");
    detector.Enrich(proc);
    PP_CHECK(!HasScore(proc));
}

void TestAdPolicyCmdletsTier75() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);

    const char* const kCmdlets[] = {
        "Get-ADDefaultDomainPasswordPolicy",
        "Get-ADFineGrainedPasswordPolicy -Filter *",
        "Get-ADUserResultantPasswordPolicy -Identity admin",
        "Get-DomainPolicy",
    };
    /* All four share the "domain_password_policy_query" dedup key, so the
     * events must be spaced past the default 300s window. */
    for (int i = 0; i < 4; ++i) {
        edr::Event ps = PsScriptEvent(
            (1000 + static_cast<uint64_t>(i) * 400) * kSecond, kCmdlets[i]);
        detector.Enrich(ps);
        PP_CHECK(ps.fields.at(edr::field::kPasswordPolicyScore) == "75");
        PP_CHECK(ps.fields.at(edr::field::kPasswordPolicyVerdict) ==
                 "malicious");
        PP_CHECK(ps.fields.at(edr::field::kPasswordPolicySignals) ==
                 "domain_password_policy_query");
    }

    /* Command plane shape. */
    edr::Event cmd = ProcEvent(
        4000 * kSecond, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
                        "powershell.exe",
        "powershell -c \"Get-ADDefaultDomainPasswordPolicy\"");
    detector.Enrich(cmd);
    PP_CHECK(cmd.fields.at(edr::field::kPasswordPolicyScore) == "75");
    PP_CHECK(cmd.fields.at(edr::field::kPasswordPolicyTools) ==
             "get-addefaultdomainpasswordpolicy");
}

void TestNetAccountsDomainTier70() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);

    edr::Event domain = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net accounts /domain");
    detector.Enrich(domain);
    PP_CHECK(domain.fields.at(edr::field::kPasswordPolicyScore) == "70");
    PP_CHECK(domain.fields.at(edr::field::kPasswordPolicyVerdict) ==
             "suspicious");
    PP_CHECK(domain.fields.at(edr::field::kPasswordPolicySignals) ==
             "net_accounts_domain_read");
    PP_CHECK(domain.fields.at(edr::field::kPasswordPolicyTools) ==
             "net accounts");

    /* Full-path binary name shape. */
    edr::Event exeForm = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net.exe accounts /domain");
    detector.Enrich(exeForm);
    PP_CHECK(exeForm.fields.at(edr::field::kPasswordPolicyScore) == "70");
}

void TestNetAccountsLocalTier65() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);

    edr::Event local = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\net.exe", "net accounts");
    detector.Enrich(local);
    PP_CHECK(local.fields.at(edr::field::kPasswordPolicyScore) == "65");
    PP_CHECK(local.fields.at(edr::field::kPasswordPolicySignals) ==
             "net_accounts_read");
}

void TestSeceditExportTier65() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);

    edr::Event exported = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\secedit.exe",
        "secedit /export /cfg C:\\Users\\Public\\secpol.inf");
    detector.Enrich(exported);
    PP_CHECK(exported.fields.at(edr::field::kPasswordPolicyScore) == "65");
    PP_CHECK(exported.fields.at(edr::field::kPasswordPolicySignals) ==
             "secedit_policy_export");
    PP_CHECK(exported.fields.at(edr::field::kPasswordPolicyTools) ==
             "secedit");
}

void TestSetterFlagsSilent() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);

    /* Any `net accounts` that MODIFIES the policy belongs to account_op,
     * not to this discovery detector. */
    const char* const kSetters[] = {
        "net accounts /minpwlen:0",
        "net accounts /maxpwage:unlimited",
        "net accounts /minpwage:0",
        "net accounts /uniquepw:0",
        "net accounts /lockoutthreshold:0",
        "net accounts /lockoutduration:0 /lockoutwindow:0",
        "net accounts /forcelogoff:no",
        "net accounts /domain /minpwlen:4",
    };
    for (int i = 0; i < 8; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\net.exe", kSetters[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[password_policy] setter scored: %s\n",
                         kSetters[i]);
        PP_CHECK(!HasScore(ev));
    }

    /* secedit without /export is a policy write. */
    edr::Event configure = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\secedit.exe",
        "secedit /configure /db secedit.sdb /cfg secpol.inf");
    detector.Enrich(configure);
    PP_CHECK(!HasScore(configure));

    PP_CHECK(detector.StateCount() == 0);
}

void TestNormalOpsSilent() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);

    const char* const kNormalOps[] = {
        "net user backdoor P@ssw0rd! /add",
        "net view",
        "net localgroup administrators",
        "Get-ADUser -Filter * -Properties PasswordLastSet",
        "net use \\\\fileserver\\share",
    };
    for (int i = 0; i < 5; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\net.exe", kNormalOps[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[password_policy] op scored: %s\n",
                         kNormalOps[i]);
        PP_CHECK(!HasScore(ev));
    }
    PP_CHECK(detector.StateCount() == 0);
}

void TestTokenTailBoundaryNegatives() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);

    /* Letter suffix glued onto the "net accounts" stem: "net accountsx"
     * is a different token, the tail edge must reject it. */
    edr::Event accountsx = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net accountsx /domain");
    detector.Enrich(accountsx);
    PP_CHECK(!HasScore(accountsx));

    /* Same tail family on the net.exe command shape. */
    edr::Event exeForm = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net.exe accountsdomain");
    detector.Enrich(exeForm);
    PP_CHECK(!HasScore(exeForm));

    /* Underscore continuation: identifier-style names glue onto the
     * stem ("net1 accounts_audit"), the tail edge must reject it. */
    edr::Event audit = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net1 accounts_audit");
    detector.Enrich(audit);
    PP_CHECK(!HasScore(audit));

    PP_CHECK(detector.StateCount() == 0);
}

void TestMinScoreGating() {
    /* min_score 75: the 70/65 tiers are filtered and, because the gate
     * runs before dedup bookkeeping, no key is inserted. */
    {
        edr::PasswordPolicyDiscoveryDetector detector(true, 75, 300, 1024);
        edr::Event local = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\net.exe", "net accounts");
        detector.Enrich(local);
        PP_CHECK(!HasScore(local));
        edr::Event domain = ProcEvent(
            1100 * kSecond, "C:\\Windows\\System32\\net.exe",
            "net accounts /domain");
        detector.Enrich(domain);
        PP_CHECK(!HasScore(domain));
        PP_CHECK(detector.StateCount() == 0);

        edr::Event cmdlet = PsScriptEvent(
            1200 * kSecond, "Get-ADDefaultDomainPasswordPolicy");
        detector.Enrich(cmdlet);
        PP_CHECK(cmdlet.fields.at(edr::field::kPasswordPolicyScore) == "75");
        PP_CHECK(detector.StateCount() == 1);
    }
    /* min_score 55 (default): the 65 tier survives. */
    {
        edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);
        edr::Event local = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\net.exe", "net accounts");
        detector.Enrich(local);
        PP_CHECK(local.fields.at(edr::field::kPasswordPolicyScore) == "65");
    }
}

void TestDedupPerTier() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);

    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net accounts /domain");
    detector.Enrich(first);
    PP_CHECK(HasScore(first));
    PP_CHECK(detector.StateCount() == 1);

    /* Same tier inside the window is suppressed. */
    edr::Event repeat = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net accounts /domain");
    detector.Enrich(repeat);
    PP_CHECK(!HasScore(repeat));

    /* A different tier is a different key and passes. */
    edr::Event otherTier = PsScriptEvent(
        1100 * kSecond, "Get-ADDefaultDomainPasswordPolicy");
    detector.Enrich(otherTier);
    PP_CHECK(HasScore(otherTier));
    PP_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the first tier. */
    edr::Event late = ProcEvent(
        1000 * kSecond + 301 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net accounts /domain");
    detector.Enrich(late);
    PP_CHECK(HasScore(late));
    PP_CHECK(detector.StateCount() == 2);
}

void TestStateCapacityReset() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1);
    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net accounts /domain");
    detector.Enrich(first);
    PP_CHECK(HasScore(first));
    PP_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event second = PsScriptEvent(
        1100 * kSecond, "Get-ADDefaultDomainPasswordPolicy");
    detector.Enrich(second);
    PP_CHECK(HasScore(second));
    PP_CHECK(detector.StateCount() == 1);

    /* The reset re-arms the first tier (its key was cleared). */
    edr::Event again = ProcEvent(
        1200 * kSecond, "C:\\Windows\\System32\\net.exe",
        "net accounts /domain");
    detector.Enrich(again);
    PP_CHECK(HasScore(again));
    PP_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::PasswordPolicyDiscoveryDetector detector(true, 55, 300, 1024);

    /* Uninspected event type carrying the cmdlet text in an unrelated
     * field. */
    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 1000 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] = "Get-ADDefaultDomainPasswordPolicy";
    detector.Enrich(reg);
    PP_CHECK(!HasScore(reg));

    /* POWERSHELL_SCRIPT without a script body. */
    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1001 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    PP_CHECK(!HasScore(ps));

    /* PROCESS_START without a command line. */
    edr::Event proc = ProcEvent(1002 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe", nullptr);
    detector.Enrich(proc);
    PP_CHECK(!HasScore(proc));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set password_policy_score field (the RuleEngine never
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
        ev.fields[edr::field::kPasswordPolicyScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-506 (password_policy_score >= 75, high/alert, T1201) and
     * EDR-507 (55-74, medium/log, T1201) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[password_policy] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-506") == std::string::npos ||
        rulesText.find("EDR-507") == std::string::npos) {
        std::fprintf(stderr,
                     "[password_policy] EDR-506/EDR-507 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* High band: 100/75 land in >=75, so they hit EDR-506 only. */
    FeedScore(&engine, "100");
    PP_CHECK(HasAlert("EDR-506"));
    PP_CHECK(!HasAlert("EDR-507"));
    const AlertRecord* high = FindAlert("EDR-506");
    PP_CHECK(high != nullptr);
    PP_CHECK(high->severity == "high");
    PP_CHECK(high->action == "alert");
    PP_CHECK(std::find(high->mitre.begin(), high->mitre.end(), "T1201") !=
             high->mitre.end());

    FeedScore(&engine, "75");
    PP_CHECK(HasAlert("EDR-506"));
    PP_CHECK(!HasAlert("EDR-507"));

    /* Mid band: 74 must NOT hit the >=75 rule; 70/65/55 hit EDR-507 only. */
    FeedScore(&engine, "74");
    PP_CHECK(HasAlert("EDR-507"));
    PP_CHECK(!HasAlert("EDR-506"));
    const AlertRecord* mid = FindAlert("EDR-507");
    PP_CHECK(mid != nullptr);
    PP_CHECK(mid->severity == "medium");
    PP_CHECK(mid->action == "log");
    PP_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(), "T1201") !=
             mid->mitre.end());
    FeedScore(&engine, "70");
    PP_CHECK(HasAlert("EDR-507"));
    PP_CHECK(!HasAlert("EDR-506"));
    FeedScore(&engine, "65");
    PP_CHECK(HasAlert("EDR-507"));
    PP_CHECK(!HasAlert("EDR-506"));
    FeedScore(&engine, "55");
    PP_CHECK(HasAlert("EDR-507"));
    PP_CHECK(!HasAlert("EDR-506"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    PP_CHECK(!HasAlert("EDR-506"));
    PP_CHECK(!HasAlert("EDR-507"));
    FeedScore(&engine, "50");
    PP_CHECK(!HasAlert("EDR-506"));
    PP_CHECK(!HasAlert("EDR-507"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    PP_CHECK(!HasAlert("EDR-506"));
    PP_CHECK(!HasAlert("EDR-507"));
}

} // namespace

void RunPasswordPolicyDiscoveryDetectorTests() {
    std::fprintf(stderr, "[password_policy] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[password_policy] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[password_policy] TestAdPolicyCmdletsTier75\n");
    TestAdPolicyCmdletsTier75();
    std::fprintf(stderr, "[password_policy] TestNetAccountsDomainTier70\n");
    TestNetAccountsDomainTier70();
    std::fprintf(stderr, "[password_policy] TestNetAccountsLocalTier65\n");
    TestNetAccountsLocalTier65();
    std::fprintf(stderr, "[password_policy] TestSeceditExportTier65\n");
    TestSeceditExportTier65();
    std::fprintf(stderr, "[password_policy] TestSetterFlagsSilent\n");
    TestSetterFlagsSilent();
    std::fprintf(stderr, "[password_policy] TestNormalOpsSilent\n");
    TestNormalOpsSilent();
    std::fprintf(stderr,
                 "[password_policy] TestTokenTailBoundaryNegatives\n");
    TestTokenTailBoundaryNegatives();
    std::fprintf(stderr, "[password_policy] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[password_policy] TestDedupPerTier\n");
    TestDedupPerTier();
    std::fprintf(stderr, "[password_policy] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[password_policy] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[password_policy] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[password_policy] all passed\n");
}
