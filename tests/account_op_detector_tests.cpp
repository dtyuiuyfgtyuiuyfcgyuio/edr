#include "account_op_detector_tests.h"

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
#include "account_op_detector.h"
#include "rule_engine.h"

namespace {

#define AOP_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "account op test failed at line " + std::to_string(line) +
            ": " + expr);
}

edr::Event ProcStart(const std::string& image, const std::string& cmdLine,
                     uint32_t pid) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.pid = pid;
    ev.fields[edr::field::kImage] = image;
    ev.fields[edr::field::kCommandLine] = cmdLine;
    return ev;
}

void TestLocalAccountCreate() {
    std::fprintf(stderr, "[account_op] TestLocalAccountCreate\n");
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net user backdoor P@ssw0rd! /add", 2001);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.count(edr::field::kAccountOpScore) > 0);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpScore) == "55");
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpSignals)
                  .find("account_create") != std::string::npos);
    /* 55 is exactly the SUSPICIOUS floor of the house verdict band. */
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpVerdict) == "SUSPICIOUS");
}

void TestAdminGroupAdd() {
    std::fprintf(stderr, "[account_op] TestAdminGroupAdd\n");
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net localgroup administrators backdoor /add",
                              2002);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpScore) == "80");
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpSignals)
                  .find("admin_group_add") != std::string::npos);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpVerdict) == "MALICIOUS");
}

void TestDomainGroupAdd() {
    std::fprintf(stderr, "[account_op] TestDomainGroupAdd\n");
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net group \"Domain Admins\" backdoor /add /domain",
                              2003);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpScore) == "75");
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpSignals)
                  .find("domain_group_add") != std::string::npos);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpVerdict) == "MALICIOUS");
}

void TestAccountEnable() {
    std::fprintf(stderr, "[account_op] TestAccountEnable\n");
    /* account_enable is 50: below the 55 alert band the event is stamped
     * with NOTHING (no score/signals/commands/verdict). The gate is on
     * the FINAL aggregated score in Enrich (`signal.verdict.empty()`
     * early exit), not per signal, because no rule consumes the 50-54
     * dead band (house regex ^(?:5[5-9]|...)$) - a stamped sub-55 score
     * would be a dead letter. The classification itself stays observable
     * through the pure helper (see the short-flag regression test). */
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net user guest /active:yes", 2004);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpScore) == ev.fields.end());
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpSignals) ==
              ev.fields.end());
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpCommands) ==
              ev.fields.end());
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpVerdict) ==
              ev.fields.end());
}

void TestAccountEnableShortFlagRegression() {
    std::fprintf(stderr,
                 "[account_op] TestAccountEnableShortFlagRegression\n");
    /* Regression guard: the short /active:y form keeps the existing
     * enable signal and is not shadowed by the delete/disable branches.
     * The 50-point signal no longer stamps the event (sub-55 dead-band
     * gate on the final aggregated score in Enrich), so the branch is
     * asserted through the pure classification helper: recognized,
     * scored 50, verdict empty per the house band. */
    edr::AccountOpSignal signal = edr::ClassifyAccountOperation(
        "C:\\Windows\\System32\\net.exe", "net user bob /active:y");
    AOP_CHECK(signal.suspicious);
    AOP_CHECK(signal.score == 50);
    AOP_CHECK(signal.signals.find("account_enable") != std::string::npos);
    AOP_CHECK(signal.verdict.empty());
    /* And the event path stays unstamped. */
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net user bob /active:y", 2010);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpScore) == ev.fields.end());
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpVerdict) ==
              ev.fields.end());
}

void TestAccountPolicyChangeSubBandSilent() {
    std::fprintf(stderr,
                 "[account_op] TestAccountPolicyChangeSubBandSilent\n");
    /* account_policy_change is 35: single sub-55 signal, event not
     * stamped at all (same final-score gate as the 40/50 signals). */
    edr::AccountOpSignal signal = edr::ClassifyAccountOperation(
        "C:\\Windows\\System32\\net.exe",
        "net accounts /lockoutthreshold:never /minpwlen:0");
    AOP_CHECK(signal.suspicious);
    AOP_CHECK(signal.score == 35);
    AOP_CHECK(signal.signals.find("account_policy_change") !=
              std::string::npos);
    AOP_CHECK(signal.verdict.empty());
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\net.exe",
        "net accounts /lockoutthreshold:never /minpwlen:0", 2017);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpScore) == ev.fields.end());
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpVerdict) ==
              ev.fields.end());
}

void TestAccountDisable() {
    std::fprintf(stderr, "[account_op] TestAccountDisable\n");
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net user bob /active:no", 2011);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpScore) == "60");
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpSignals)
                  .find("account_disable") != std::string::npos);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpVerdict) == "SUSPICIOUS");
}

void TestAccountDisableSpacedFlag() {
    std::fprintf(stderr, "[account_op] TestAccountDisableSpacedFlag\n");
    /* Spaced form, same shape as the "/active: yes" enable twin. */
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net user bob /active: no", 2012);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpScore) == "60");
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpSignals)
                  .find("account_disable") != std::string::npos);
}

void TestAccountDelete() {
    std::fprintf(stderr, "[account_op] TestAccountDelete\n");
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net user bob /delete", 2013);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpScore) == "70");
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpSignals)
                  .find("account_delete") != std::string::npos);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpVerdict) == "SUSPICIOUS");
}

void TestAccountDeleteNet1() {
    std::fprintf(stderr, "[account_op] TestAccountDeleteNet1\n");
    /* net1.exe rides the same mirror gate as net.exe. */
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net1.exe",
                              "net1 user bob /delete", 2014);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpScore) == "70");
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpSignals)
                  .find("account_delete") != std::string::npos);
}

void TestNetUseDeleteNotAccountDelete() {
    std::fprintf(stderr, "[account_op] TestNetUseDeleteNotAccountDelete\n");
    /* "net use ... /delete" tears down a connection, not an account:
     * the space-delimited " user " needle cannot match " use " and the
     * existing "user " branch does not match either, so nothing is
     * stamped. */
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net use \\\\srv\\ipc$ /delete", 2015);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpScore) ==
              ev.fields.end());
}

void TestLocalGroupDeleteNotAccountDelete() {
    std::fprintf(stderr,
                 "[account_op] TestLocalGroupDeleteNotAccountDelete\n");
    /* Group deletion is not an account signal: the localgroup branch
     * requires /add, and the space-delimited " user " needle does not
     * match "localgroup ...", so account_delete cannot fire. Current
     * behavior is silent (no signal consumes group deletion yet). */
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net localgroup administrators bob /delete",
                              2016);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpScore) ==
              ev.fields.end());
}

void TestPasswordChange() {
    std::fprintf(stderr, "[account_op] TestPasswordChange\n");
    /* password_change is 40: another sub-55 signal - the event is not
     * stamped at all; the branch stays observable via the pure helper. */
    edr::AccountOpSignal signal = edr::ClassifyAccountOperation(
        "C:\\Windows\\System32\\net.exe", "net user alice NewPass123");
    AOP_CHECK(signal.suspicious);
    AOP_CHECK(signal.score == 40);
    AOP_CHECK(signal.signals.find("password_change") != std::string::npos);
    AOP_CHECK(signal.verdict.empty());
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net user alice NewPass123", 2005);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpScore) == ev.fields.end());
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpVerdict) ==
              ev.fields.end());
}

void TestDsaddUser() {
    std::fprintf(stderr, "[account_op] TestDsaddUser\n");
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\dsadd.exe",
        "dsadd user \"CN=svc-backup,CN=Users,DC=corp,DC=local\" -pwd P@ss",
        2006);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpScore) == "55");
    AOP_CHECK(ev.fields.at(edr::field::kAccountOpSignals)
                  .find("account_create") != std::string::npos);
}

void TestBenignNetViewNoStamp() {
    std::fprintf(stderr, "[account_op] TestBenignNetViewNoStamp\n");
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net view \\\\fileserver", 2007);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpScore) ==
              ev.fields.end());
}

void TestNonAccountToolNoStamp() {
    std::fprintf(stderr, "[account_op] TestNonAccountToolNoStamp\n");
    edr::AccountOpDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\whoami.exe",
                              "whoami /all", 2008);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpScore) ==
              ev.fields.end());
}

void TestDisabledNoStamp() {
    std::fprintf(stderr, "[account_op] TestDisabledNoStamp\n");
    edr::AccountOpDetector det(false);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\net.exe",
                              "net user backdoor P@ssw0rd! /add", 2009);
    det.Enrich(ev);
    AOP_CHECK(ev.fields.find(edr::field::kAccountOpScore) ==
              ev.fields.end());
}

/* ---- production rules (EDR-495) -------------------------------------- */

struct AlertRecord {
    std::string ruleId;
    std::string severity;
    std::string action;
    std::vector<std::string> mitre;
};

std::vector<AlertRecord> g_alerts;

bool HasAlert(const char* id) {
    return std::find_if(g_alerts.begin(), g_alerts.end(),
                        [&](const AlertRecord& a) { return a.ruleId == id; })
           != g_alerts.end();
}

const AlertRecord* FindAlert(const char* id) {
    auto it = std::find_if(g_alerts.begin(), g_alerts.end(),
                           [&](const AlertRecord& a) {
                               return a.ruleId == id;
                           });
    return it == g_alerts.end() ? nullptr : &*it;
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

constexpr uint64_t kSecond = 10000000ULL;

void FeedAccountOp(edr::RuleEngine* engine, const char* score,
                   const char* signals) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.ts100ns = 1000 * kSecond;
    ev.fields[edr::field::kType] = "PROCESS_START";
    ev.fields[edr::field::kImage] = "C:\\Windows\\System32\\net.exe";
    if (score != nullptr)
        ev.fields[edr::field::kAccountOpScore] = score;
    if (signals != nullptr)
        ev.fields[edr::field::kAccountOpSignals] = signals;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    std::fprintf(stderr, "[account_op] TestProductionRules\n");
    /* EDR-495 (account_op_score 55-74 AND account_op_signals carrying the
     * whole token account_delete or account_disable; medium/log, T1531)
     * is written to rules/rules.json by the wiring agent. Until then skip
     * the block (same policy as the other production-rule suites).
     *
     * Division of labor with the existing consumer: EDR-326 owns the >=75
     * band (any signal). No rule consumed the 55-74 band before EDR-495,
     * so the other 55-74 signals (account_create 55, domain_account_create
     * 70, local_group_add 60) stay unrouted; the second match field (the
     * signals token regex) is what keeps EDR-495 away from them. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[account_op] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-495") == std::string::npos) {
        std::fprintf(stderr,
                     "[account_op] EDR-495 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* 70 account_delete -> EDR-495, medium/log, T1531. */
    FeedAccountOp(&engine, "70", "account_delete");
    AOP_CHECK(HasAlert("EDR-495"));
    AOP_CHECK(!HasAlert("EDR-326"));
    const AlertRecord* del = FindAlert("EDR-495");
    AOP_CHECK(del != nullptr);
    AOP_CHECK(del->severity == "medium");
    AOP_CHECK(del->action == "log");
    AOP_CHECK(std::find(del->mitre.begin(), del->mitre.end(), "T1531") !=
              del->mitre.end());

    /* 60 account_disable -> EDR-495. */
    FeedAccountOp(&engine, "60", "account_disable");
    AOP_CHECK(HasAlert("EDR-495"));
    AOP_CHECK(!HasAlert("EDR-326"));

    /* Delete token embedded in a comma list still matches whole tokens. */
    FeedAccountOp(&engine, "70", "password_change,account_delete");
    AOP_CHECK(HasAlert("EDR-495"));

    /* Other 55-74 signals must not hit EDR-495: the signals regex is the
     * differentiator (these stay unrouted; EDR-326 only takes >=75). */
    FeedAccountOp(&engine, "55", "account_create");
    AOP_CHECK(!HasAlert("EDR-495"));
    FeedAccountOp(&engine, "70", "domain_account_create");
    AOP_CHECK(!HasAlert("EDR-495"));
    FeedAccountOp(&engine, "60", "local_group_add");
    AOP_CHECK(!HasAlert("EDR-495"));

    /* Token boundary: a superstring of account_delete is not a match. */
    FeedAccountOp(&engine, "70", "account_deleted");
    AOP_CHECK(!HasAlert("EDR-495"));

    /* >=75 never enters this rule (EDR-326's band). */
    FeedAccountOp(&engine, "75", "account_delete");
    AOP_CHECK(!HasAlert("EDR-495"));
    FeedAccountOp(&engine, "80", "admin_group_add");
    AOP_CHECK(!HasAlert("EDR-495"));

    /* Dead band 50-54 and below. */
    FeedAccountOp(&engine, "54", "account_delete");
    AOP_CHECK(!HasAlert("EDR-495"));
    FeedAccountOp(&engine, "50", "account_enable");
    AOP_CHECK(!HasAlert("EDR-495"));
    FeedAccountOp(&engine, "40", "password_change");
    AOP_CHECK(!HasAlert("EDR-495"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedAccountOp(&engine, nullptr, nullptr);
    AOP_CHECK(!HasAlert("EDR-495"));
}

} // namespace

void RunAccountOpDetectorTests() {
    TestLocalAccountCreate();
    TestAdminGroupAdd();
    TestDomainGroupAdd();
    TestAccountEnable();
    TestAccountEnableShortFlagRegression();
    TestAccountPolicyChangeSubBandSilent();
    TestAccountDisable();
    TestAccountDisableSpacedFlag();
    TestAccountDelete();
    TestAccountDeleteNet1();
    TestNetUseDeleteNotAccountDelete();
    TestLocalGroupDeleteNotAccountDelete();
    TestPasswordChange();
    TestDsaddUser();
    TestBenignNetViewNoStamp();
    TestNonAccountToolNoStamp();
    TestDisabledNoStamp();
    TestProductionRules();
    std::fprintf(stderr, "[account_op] all passed\n");
}
