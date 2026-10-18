/*
 * mailbox_delegate_detector_tests.cpp - Unit tests for
 * MailboxDelegateDetector (T1098.002) and the production rules that
 * consume its score field.
 *
 * Detector tiers asserted here (per user/mailbox_delegate_detector.cpp):
 *   85 delegate_full_access_grant     (Add-MailboxPermission /
 *                                      Add-ADPermission + -AccessRights
 *                                      FullAccess, space / colon / quoted
 *                                      forms, -User/-Identity any order,
 *                                      PS plane or command plane)
 *   80 delegate_send_as_grant         (Add-RecipientPermission
 *                                      -AccessRights SendAs, Set-Mailbox
 *                                      -GrantSendOnBehalfTo, merged with
 *                                      Add-ADPermission -ExtendedRights
 *                                      Send-as / "Send As")
 *   65 delegate_folder_permission_grant (Add-MailboxFolderPermission,
 *                                      regardless of sub-parameters)
 *   silent: Get-* queries, Remove-* remediation (even with -AccessRights
 *   FullAccess/SendAs in the text), non-grant -AccessRights values
 *   (ReadPermission / ChangeOwner / CreateItems), bare Set-Mailbox,
 *   Set-MailboxFolderPermission, cmdlet-name noise.
 *
 * Flag-value matching is bound to the owning grant cmdlet's span (the
 * region between the grant cmdlet occurrence and the next
 * mailbox-delegation cmdlet token, across "\n" / ";" / "|" statement
 * separators): values carried by a foreign statement never endorse a
 * grant cmdlet elsewhere in the block, while the mirror shape
 * (Remove-* first, grant second) still scores. PowerShell backtick line
 * continuations inside a flag value are soft whitespace.
 *
 * Dedup key is signal|target with the target from the full "-identity"
 * needle; events that share a key are spaced beyond the 300s window or
 * given distinct identities inside these tests.
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-491  mailbox_delegate_score >= 75   high/alert  T1098.002
 *   EDR-492  mailbox_delegate_score 55-74   medium/log  T1098.002
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "mailbox_delegate_detector_tests.h"

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
#include "mailbox_delegate_detector.h"
#include "rule_engine.h"

namespace {

#define MB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "mailbox delegate detector test failed at line " +
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
    if (scriptText != nullptr)
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
    return event.fields.find(edr::field::kMailboxDelegateScore) !=
           event.fields.end();
}

void TestInspects() {
    MB_CHECK(edr::MailboxDelegateDetector::Inspects(EDR_EVT_PROCESS_START));
    MB_CHECK(
        edr::MailboxDelegateDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    MB_CHECK(!edr::MailboxDelegateDetector::Inspects(EDR_EVT_NET_LISTENER));
    MB_CHECK(!edr::MailboxDelegateDetector::Inspects(EDR_EVT_REG_WRITE));
    MB_CHECK(!edr::MailboxDelegateDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::MailboxDelegateDetector detector(false, 55, 300, 1024);
    edr::Event ps = PsScriptEvent(
        1000 * kSecond,
        "Add-MailboxPermission -Identity jdoe -User eve "
        "-AccessRights FullAccess");
    detector.Enrich(ps);
    MB_CHECK(!HasScore(ps));
    edr::Event proc = ProcEvent(
        1001 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command Set-Mailbox -GrantSendOnBehalfTo eve");
    detector.Enrich(proc);
    MB_CHECK(!HasScore(proc));
}

/* The 85 tier: -AccessRights FullAccess in the space / colon / quoted
 * forms, on both cmdlets, with -User and -Identity in any order, on both
 * planes. Every case uses a distinct -Identity, so every event is a fresh
 * dedup key (delegate_full_access_grant|<identity>) despite the 1s
 * spacing. */
void TestFullAccessGrantTier85() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);

    edr::Event ps = PsScriptEvent(
        1000 * kSecond,
        "Add-MailboxPermission -Identity jdoe -User eve@evil.example "
        "-AccessRights FullAccess -AutoMapping $false");
    detector.Enrich(ps);
    MB_CHECK(ps.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(ps.fields.at(edr::field::kMailboxDelegateVerdict) ==
             "malicious");
    MB_CHECK(ps.fields.at(edr::field::kMailboxDelegateSignals) ==
             "delegate_full_access_grant");
    MB_CHECK(ps.fields.at(edr::field::kMailboxDelegateCmdlets) ==
             "add-mailboxpermission/add-adpermission");
    MB_CHECK(ps.fields.at(edr::field::kMailboxDelegateTargets) == "jdoe");

    edr::Event colon = PsScriptEvent(
        1001 * kSecond,
        "Add-MailboxPermission -Identity:alice -AccessRights:FullAccess");
    detector.Enrich(colon);
    MB_CHECK(colon.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(colon.fields.at(edr::field::kMailboxDelegateTargets) ==
             "alice");

    edr::Event quoted = PsScriptEvent(
        1002 * kSecond,
        "Add-MailboxPermission -Identity 'bob' -AccessRights \"FullAccess\"");
    detector.Enrich(quoted);
    MB_CHECK(quoted.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(quoted.fields.at(edr::field::kMailboxDelegateTargets) == "bob");

    edr::Event ad = PsScriptEvent(
        1003 * kSecond,
        "Add-ADPermission -Identity salesmbx -User svc_backup "
        "-AccessRights FullAccess");
    detector.Enrich(ad);
    MB_CHECK(ad.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(ad.fields.at(edr::field::kMailboxDelegateSignals) ==
             "delegate_full_access_grant");
    MB_CHECK(ad.fields.at(edr::field::kMailboxDelegateTargets) ==
             "salesmbx");

    /* Parameter order is irrelevant: -AccessRights before -Identity. */
    edr::Event reordered = PsScriptEvent(
        1004 * kSecond,
        "Add-MailboxPermission -AccessRights FullAccess -Identity eveinbox "
        "-User eve");
    detector.Enrich(reordered);
    MB_CHECK(reordered.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(reordered.fields.at(edr::field::kMailboxDelegateTargets) ==
             "eveinbox");

    /* The -Accessright (no trailing s) spelling is accepted too. */
    edr::Event singular = PsScriptEvent(
        1005 * kSecond,
        "Add-MailboxPermission -Identity onembx -Accessright FullAccess");
    detector.Enrich(singular);
    MB_CHECK(singular.fields.at(edr::field::kMailboxDelegateScore) == "85");

    /* Quoted multi-value list keeps FullAccess inside the span. */
    edr::Event list = PsScriptEvent(
        1006 * kSecond,
        "Add-MailboxPermission -Identity listmbx -User eve "
        "-AccessRights \"FullAccess\", \"ExternalSharing\"");
    detector.Enrich(list);
    MB_CHECK(list.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(list.fields.at(edr::field::kMailboxDelegateTargets) ==
             "listmbx");

    /* Command plane: the cmdlet rides on powershell.exe -Command. */
    edr::Event cmd = ProcEvent(
        1007 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command \"Add-MailboxPermission -Identity winmbx "
        "-User eve -AccessRights FullAccess\"");
    detector.Enrich(cmd);
    MB_CHECK(cmd.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(cmd.fields.at(edr::field::kMailboxDelegateVerdict) ==
             "malicious");
    MB_CHECK(cmd.fields.at(edr::field::kMailboxDelegateTargets) == "winmbx");

    MB_CHECK(detector.StateCount() == 8);
}

/* The 80 tier in all three merged shapes. Distinct identities per case ->
 * distinct dedup keys despite 1s spacing. */
void TestSendAsGrantTier80() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);

    edr::Event sendAs = PsScriptEvent(
        2000 * kSecond,
        "Add-RecipientPermission -Identity hrmbx -Trustee eve@evil.example "
        "-AccessRights SendAs");
    detector.Enrich(sendAs);
    MB_CHECK(sendAs.fields.at(edr::field::kMailboxDelegateScore) == "80");
    MB_CHECK(sendAs.fields.at(edr::field::kMailboxDelegateVerdict) ==
             "malicious");
    MB_CHECK(sendAs.fields.at(edr::field::kMailboxDelegateSignals) ==
             "delegate_send_as_grant");
    MB_CHECK(sendAs.fields.at(edr::field::kMailboxDelegateCmdlets) ==
             "add-recipientpermission/set-mailbox/add-adpermission");
    MB_CHECK(sendAs.fields.at(edr::field::kMailboxDelegateTargets) ==
             "hrmbx");

    edr::Event colon = PsScriptEvent(
        2001 * kSecond,
        "Add-RecipientPermission -Identity finmbx -AccessRights:SendAs");
    detector.Enrich(colon);
    MB_CHECK(colon.fields.at(edr::field::kMailboxDelegateScore) == "80");
    MB_CHECK(colon.fields.at(edr::field::kMailboxDelegateTargets) ==
             "finmbx");

    edr::Event quoted = PsScriptEvent(
        2002 * kSecond,
        "Add-RecipientPermission -Identity opsmbx -AccessRights \"SendAs\"");
    detector.Enrich(quoted);
    MB_CHECK(quoted.fields.at(edr::field::kMailboxDelegateScore) == "80");
    MB_CHECK(quoted.fields.at(edr::field::kMailboxDelegateTargets) ==
             "opsmbx");

    edr::Event onBehalf = PsScriptEvent(
        2003 * kSecond,
        "Set-Mailbox -Identity ceombx -GrantSendOnBehalfTo "
        "eve@evil.example");
    detector.Enrich(onBehalf);
    MB_CHECK(onBehalf.fields.at(edr::field::kMailboxDelegateScore) == "80");
    MB_CHECK(onBehalf.fields.at(edr::field::kMailboxDelegateSignals) ==
             "delegate_send_as_grant");
    MB_CHECK(onBehalf.fields.at(edr::field::kMailboxDelegateTargets) ==
             "ceombx");

    /* Add-ADPermission -ExtendedRights "Send-as" is merged into the same
     * 80 signal. */
    edr::Event extended = PsScriptEvent(
        2004 * kSecond,
        "Add-ADPermission -Identity legacydb -User eve -ExtendedRights "
        "\"Send-as\"");
    detector.Enrich(extended);
    MB_CHECK(extended.fields.at(edr::field::kMailboxDelegateScore) == "80");
    MB_CHECK(extended.fields.at(edr::field::kMailboxDelegateSignals) ==
             "delegate_send_as_grant");
    MB_CHECK(extended.fields.at(edr::field::kMailboxDelegateTargets) ==
             "legacydb");

    edr::Event extendedSpaced = PsScriptEvent(
        2005 * kSecond,
        "Add-ADPermission -Identity db2 -User eve -ExtendedRights "
        "\"Send As\"");
    detector.Enrich(extendedSpaced);
    MB_CHECK(extendedSpaced.fields.at(edr::field::kMailboxDelegateScore) ==
             "80");
    MB_CHECK(extendedSpaced.fields.at(edr::field::kMailboxDelegateTargets) ==
             "db2");

    /* Command plane Set-Mailbox -GrantSendOnBehalfTo. */
    edr::Event cmd = ProcEvent(
        2006 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command \"Set-Mailbox -Identity cmdmbx "
        "-GrantSendOnBehalfTo attacker@evil.example\"");
    detector.Enrich(cmd);
    MB_CHECK(cmd.fields.at(edr::field::kMailboxDelegateScore) == "80");
    MB_CHECK(cmd.fields.at(edr::field::kMailboxDelegateTargets) == "cmdmbx");

    MB_CHECK(detector.StateCount() == 7);
}

/* The 65 tier fires for Add-MailboxFolderPermission regardless of
 * sub-parameters. */
void TestFolderPermissionTier65() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);

    edr::Event folder = PsScriptEvent(
        3000 * kSecond,
        "Add-MailboxFolderPermission -Identity jdoe:\\Calendar "
        "-User eve@evil.example -AccessRights Editor");
    detector.Enrich(folder);
    MB_CHECK(folder.fields.at(edr::field::kMailboxDelegateScore) == "65");
    MB_CHECK(folder.fields.at(edr::field::kMailboxDelegateVerdict) ==
             "suspicious");
    MB_CHECK(folder.fields.at(edr::field::kMailboxDelegateSignals) ==
             "delegate_folder_permission_grant");
    MB_CHECK(folder.fields.at(edr::field::kMailboxDelegateCmdlets) ==
             "add-mailboxfolderpermission");
    MB_CHECK(folder.fields.at(edr::field::kMailboxDelegateTargets) ==
             "jdoe:\\calendar");

    edr::Event bare = PsScriptEvent(
        3001 * kSecond, "Add-MailboxFolderPermission -Identity inbox2");
    detector.Enrich(bare);
    MB_CHECK(bare.fields.at(edr::field::kMailboxDelegateScore) == "65");
    MB_CHECK(bare.fields.at(edr::field::kMailboxDelegateTargets) ==
             "inbox2");

    MB_CHECK(detector.StateCount() == 2);
}

/* Governance and non-grant shapes stay silent: queries, removals,
 * non-grant -AccessRights values, bare Set-Mailbox, Set-* (not Add-*)
 * folder permissions, cmdlet-name noise. */
void TestSilentNonGrantShapes() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);

    struct Case {
        uint64_t ts;
        const char* text;
    };
    const Case cases[] = {
        {4000, "Get-MailboxPermission -Identity jdoe"},
        {4001, "Get-RecipientPermission -Identity jdoe"},
        {4002, "Get-MailboxFolderPermission -Identity jdoe:\\Inbox"},
        {4003, "Get-ADPermission -Identity jdoe"},
        /* Removing a delegate is remediation even when the text carries
         * grant values. */
        {4004, "Remove-MailboxPermission -Identity jdoe -User eve "
               "-AccessRights FullAccess"},
        {4005, "Remove-RecipientPermission -Identity jdoe -Trustee eve "
               "-AccessRights SendAs"},
        /* Non-grant -AccessRights values never score. */
        {4006, "Add-MailboxPermission -Identity jdoe -User eve "
               "-AccessRights ReadPermission"},
        {4007, "Add-MailboxPermission -Identity jdoe -User eve "
               "-AccessRights ChangeOwner"},
        {4008, "Add-RecipientPermission -Identity jdoe -Trustee eve "
               "-AccessRights CreateItems"},
        /* Bare Set-Mailbox is routine mailbox maintenance. */
        {4009, "Set-Mailbox -Identity jdoe -MaxSendSize 50MB"},
        /* Set-* folder permission is not an Add-* grant; the set-mailbox
         * needle must not swallow set-mailboxfolderpermission. */
        {4010, "Set-MailboxFolderPermission -Identity jdoe:\\Calendar "
               "-User eve -AccessRights Editor"},
        /* Cmdlet-name noise fails the word-boundary check. */
        {4011, "Add-MailboxPermissionFake -Identity x -User eve "
               "-AccessRights FullAccess"},
        {4012, "Unrelated-Commandlet -Identity jdoe -AccessRights "
               "FullAccess"},
    };
    for (const Case& c : cases) {
        edr::Event ps = PsScriptEvent(c.ts * kSecond, c.text);
        detector.Enrich(ps);
        MB_CHECK(!HasScore(ps));
    }
    MB_CHECK(detector.StateCount() == 0);
}

/* min_score gating with isolated instances: a low-threshold instance lets
 * the 65 tier stamp, high-threshold instances keep it silent while 85
 * still passes. */
void TestMinScoreGating() {
    {
        /* Low threshold admits the 65 tier. */
        edr::MailboxDelegateDetector detector(true, 55, 300, 1024);
        edr::Event low = PsScriptEvent(
            5000 * kSecond,
            "Add-MailboxFolderPermission -Identity lowmbx -User eve");
        detector.Enrich(low);
        MB_CHECK(low.fields.at(edr::field::kMailboxDelegateScore) == "65");
        MB_CHECK(low.fields.at(edr::field::kMailboxDelegateVerdict) ==
                 "suspicious");
    }
    {
        /* min_score 75: 65 silent, 85 survives. */
        edr::MailboxDelegateDetector detector(true, 75, 300, 1024);
        edr::Event folder = PsScriptEvent(
            5001 * kSecond,
            "Add-MailboxFolderPermission -Identity quietmbx -User eve");
        detector.Enrich(folder);
        MB_CHECK(!HasScore(folder));
        edr::Event full = PsScriptEvent(
            5002 * kSecond,
            "Add-MailboxPermission -Identity highmbx -User eve "
            "-AccessRights FullAccess");
        detector.Enrich(full);
        MB_CHECK(full.fields.at(edr::field::kMailboxDelegateScore) == "85");
    }
    {
        /* min_score 85: 80 silent, 85 survives. */
        edr::MailboxDelegateDetector detector(true, 85, 300, 1024);
        edr::Event sendAs = PsScriptEvent(
            5003 * kSecond,
            "Add-RecipientPermission -Identity strictmbx -Trustee eve "
            "-AccessRights SendAs");
        detector.Enrich(sendAs);
        MB_CHECK(!HasScore(sendAs));
        edr::Event full = PsScriptEvent(
            5004 * kSecond,
            "Add-MailboxPermission -Identity topmbx -User eve "
            "-AccessRights FullAccess");
        detector.Enrich(full);
        MB_CHECK(full.fields.at(edr::field::kMailboxDelegateScore) == "85");
    }
}

/* Dedup per signal|identity key: same identity inside the window is
 * suppressed, a different identity re-arms, the 301st second re-arms, and
 * identity-free commands share the empty-target key. */
void TestDedupWindow() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);

    edr::Event first = PsScriptEvent(
        6000 * kSecond,
        "Add-MailboxPermission -Identity jdoe -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(first);
    MB_CHECK(HasScore(first));

    /* Same signal+identity inside the window is suppressed. */
    edr::Event repeat = PsScriptEvent(
        6100 * kSecond,
        "Add-MailboxPermission -Identity jdoe -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(repeat);
    MB_CHECK(!HasScore(repeat));

    /* A different delegated mailbox is a different key and re-arms. */
    edr::Event other = PsScriptEvent(
        6100 * kSecond,
        "Add-MailboxPermission -Identity alice -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(other);
    MB_CHECK(HasScore(other));
    MB_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the original key. */
    edr::Event late = PsScriptEvent(
        6301 * kSecond,
        "Add-MailboxPermission -Identity jdoe -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(late);
    MB_CHECK(HasScore(late));
    MB_CHECK(detector.StateCount() == 2);

    /* Identity-free grants dedup on the shared empty target. */
    edr::Event noId1 = PsScriptEvent(
        7000 * kSecond,
        "Add-MailboxPermission -User eve -AccessRights FullAccess");
    detector.Enrich(noId1);
    MB_CHECK(HasScore(noId1));
    MB_CHECK(noId1.fields.find(edr::field::kMailboxDelegateTargets) ==
             noId1.fields.end());
    MB_CHECK(detector.StateCount() == 3);

    edr::Event noId2 = PsScriptEvent(
        7100 * kSecond,
        "Add-MailboxPermission -User eve -AccessRights FullAccess");
    detector.Enrich(noId2);
    MB_CHECK(!HasScore(noId2));

    /* 400s later: beyond the window, re-armed. */
    edr::Event noId3 = PsScriptEvent(
        7400 * kSecond,
        "Add-MailboxPermission -User eve -AccessRights FullAccess");
    detector.Enrich(noId3);
    MB_CHECK(HasScore(noId3));
    MB_CHECK(detector.StateCount() == 3);
}

void TestDedupDisabledWithZeroWindow() {
    edr::MailboxDelegateDetector detector(true, 55, 0, 1024);
    edr::Event first = PsScriptEvent(
        8000 * kSecond,
        "Add-MailboxPermission -Identity jdoe -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(first);
    MB_CHECK(HasScore(first));
    edr::Event second = PsScriptEvent(
        8100 * kSecond,
        "Add-MailboxPermission -Identity jdoe -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(second);
    MB_CHECK(HasScore(second)); /* window 0 disables dedup */
    MB_CHECK(detector.StateCount() == 1);
}

void TestStateCapacityReset() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1);
    edr::Event a = PsScriptEvent(
        9000 * kSecond,
        "Add-MailboxPermission -Identity a -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(a);
    MB_CHECK(HasScore(a));
    MB_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event b = PsScriptEvent(
        9100 * kSecond,
        "Add-MailboxPermission -Identity b -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(b);
    MB_CHECK(HasScore(b));
    MB_CHECK(detector.StateCount() == 1);

    edr::Event c = PsScriptEvent(
        9200 * kSecond,
        "Add-MailboxPermission -Identity a -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(c);
    MB_CHECK(HasScore(c));
    MB_CHECK(detector.StateCount() == 1);

    edr::Event d = PsScriptEvent(
        9300 * kSecond,
        "Add-MailboxPermission -Identity c -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(d);
    MB_CHECK(HasScore(d));
    MB_CHECK(detector.StateCount() == 1);
}

/* Plane coverage and the kScriptBlockText-only body contract. */
void TestPlaneCoverage() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);

    /* PS plane: body in kScriptBlockText is scored. */
    edr::Event ps = PsScriptEvent(
        10000 * kSecond,
        "Add-MailboxPermission -Identity psmbx -User eve -AccessRights "
        "FullAccess");
    detector.Enrich(ps);
    MB_CHECK(ps.fields.at(edr::field::kMailboxDelegateScore) == "85");

    /* PS_SCRIPT without a script body is silent. */
    edr::Event psNoBody = PsScriptEvent(10001 * kSecond, nullptr);
    detector.Enrich(psNoBody);
    MB_CHECK(!HasScore(psNoBody));

    /* Command plane: the cmdlet rides on kCommandLine. */
    edr::Event cmd = ProcEvent(
        10002 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command \"Add-MailboxPermission -Identity "
        "cmdmbx2 -User eve -AccessRights FullAccess\"");
    detector.Enrich(cmd);
    MB_CHECK(cmd.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(detector.StateCount() == 2);

    /* PROCESS_START without a command line and without a matching image. */
    edr::Event procNoCmd = ProcEvent(
        10003 * kSecond,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        nullptr);
    detector.Enrich(procNoCmd);
    MB_CHECK(!HasScore(procNoCmd));

    /* Uninspected event type: silent even with grant text. */
    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 10004 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] =
        "Add-MailboxPermission -Identity jdoe -User eve -AccessRights "
        "FullAccess";
    detector.Enrich(reg);
    MB_CHECK(!HasScore(reg));

    MB_CHECK(detector.StateCount() == 2);
}

/* Identity extraction guards: the full "-identity" needle keeps a
 * neighbouring "-Id <n>" parameter from becoming the dedup target; colon
 * and quoted forms bind correctly. */
void TestIdentityExtractionGuards() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);

    edr::Event withId = PsScriptEvent(
        11000 * kSecond,
        "Add-MailboxPermission -Id 42 -Identity realmbx -User eve "
        "-AccessRights FullAccess");
    detector.Enrich(withId);
    MB_CHECK(withId.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(withId.fields.at(edr::field::kMailboxDelegateTargets) ==
             "realmbx");

    edr::Event colon = PsScriptEvent(
        11001 * kSecond,
        "Add-MailboxPermission -Identity:colonmbx -User eve "
        "-AccessRights FullAccess");
    detector.Enrich(colon);
    MB_CHECK(colon.fields.at(edr::field::kMailboxDelegateTargets) ==
             "colonmbx");

    edr::Event quoted = PsScriptEvent(
        11002 * kSecond,
        "Add-MailboxPermission -Identity \"quotedmbx\" -User eve "
        "-AccessRights FullAccess");
    detector.Enrich(quoted);
    MB_CHECK(quoted.fields.at(edr::field::kMailboxDelegateTargets) ==
             "quotedmbx");

    /* No -Identity anywhere: no targets field, empty dedup target. */
    edr::Event noIdentity = PsScriptEvent(
        11003 * kSecond,
        "Add-MailboxPermission -User eve -AccessRights FullAccess");
    detector.Enrich(noIdentity);
    MB_CHECK(HasScore(noIdentity));
    MB_CHECK(noIdentity.fields.find(edr::field::kMailboxDelegateTargets) ==
             noIdentity.fields.end());

    MB_CHECK(detector.StateCount() == 4);
}

/* P2-1 regression (false positive): in a mixed Add+Remove block the
 * Remove statement's -AccessRights value must not endorse the earlier
 * Add-*. Values are never taken across statement boundaries, so the
 * block stays silent. */
void TestMixedStatementsRemoveNotEndorsement() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);
    edr::Event mixed = PsScriptEvent(
        12000 * kSecond,
        "Add-MailboxPermission -Identity jdoe -User auditor -AccessRights "
        "ReadPermission\nRemove-MailboxPermission -Identity jdoe -User "
        "contractor -AccessRights FullAccess");
    detector.Enrich(mixed);
    MB_CHECK(!HasScore(mixed));
    MB_CHECK(detector.StateCount() == 0);
}

/* Mirror shape of the mixed block: the Remove statement first, the
 * grant second. The Add region owns its own FullAccess value, so the
 * block still scores 85 (the region binding must not over-tighten). */
void TestRemoveThenAddStillHits() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);
    edr::Event mirror = PsScriptEvent(
        12100 * kSecond,
        "Remove-MailboxPermission -Identity jdoe -User contractor "
        "-AccessRights FullAccess ; Add-MailboxPermission -Identity jdoe "
        "-User auditor -AccessRights FullAccess");
    detector.Enrich(mirror);
    MB_CHECK(mirror.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(mirror.fields.at(edr::field::kMailboxDelegateSignals) ==
             "delegate_full_access_grant");
    MB_CHECK(mirror.fields.at(edr::field::kMailboxDelegateTargets) ==
             "jdoe");
}

/* Pipeline boundary: the value sits before the pipe, so it belongs to
 * the Add region even though the piped Remove-* opens a new statement
 * (its cmdlet token is still a region boundary). */
void TestPipelineBoundary() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);
    edr::Event pipe = PsScriptEvent(
        12200 * kSecond,
        "Add-MailboxPermission -Identity pipejdoe -User auditor "
        "-AccessRights FullAccess | Remove-MailboxPermission -Identity "
        "pipejdoe -User contractor");
    detector.Enrich(pipe);
    MB_CHECK(pipe.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(pipe.fields.at(edr::field::kMailboxDelegateSignals) ==
             "delegate_full_access_grant");
    MB_CHECK(pipe.fields.at(edr::field::kMailboxDelegateTargets) ==
             "pipejdoe");
}

/* P2-2 regression (false negative): a backtick line continuation inside
 * the -AccessRights value is soft whitespace, so the grant still scores
 * 85 and the identity binds from the first line. */
void TestBacktickContinuation() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);
    edr::Event backtick = PsScriptEvent(
        12300 * kSecond,
        "Add-MailboxPermission -Identity a -User b -AccessRights `\n"
        "    FullAccess");
    detector.Enrich(backtick);
    MB_CHECK(backtick.fields.at(edr::field::kMailboxDelegateScore) == "85");
    MB_CHECK(backtick.fields.at(edr::field::kMailboxDelegateVerdict) ==
             "malicious");
    MB_CHECK(backtick.fields.at(edr::field::kMailboxDelegateTargets) ==
             "a");
}

/* Combined negative: a fake Add cmdlet never anchors a region, so the
 * FullAccess values riding on the fake statement and on the following
 * Remove-* cannot produce a grant even after the span binding. */
void TestFakeCmdletWithRemoveFullAccess() {
    edr::MailboxDelegateDetector detector(true, 55, 300, 1024);
    edr::Event fake = PsScriptEvent(
        12400 * kSecond,
        "Add-MailboxPermissionFake -Identity x -User eve -AccessRights "
        "FullAccess\nRemove-MailboxPermission -Identity y -User eve "
        "-AccessRights FullAccess");
    detector.Enrich(fake);
    MB_CHECK(!HasScore(fake));
    MB_CHECK(detector.StateCount() == 0);
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set mailbox_delegate_score field (the RuleEngine never
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
        ev.fields[edr::field::kMailboxDelegateScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-491 (mailbox_delegate_score >= 75, high/alert, T1098.002) and
     * EDR-492 (55-74, medium/log, T1098.002) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[mailbox_delegate] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-491") == std::string::npos ||
        rulesText.find("EDR-492") == std::string::npos) {
        std::fprintf(stderr,
                     "[mailbox_delegate] EDR-491/EDR-492 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* Positive >=75 band: detector tiers 85 and 80 hit EDR-491 only. */
    FeedScore(&engine, "85");
    MB_CHECK(HasAlert("EDR-491"));
    MB_CHECK(!HasAlert("EDR-492"));
    const AlertRecord* high = FindAlert("EDR-491");
    MB_CHECK(high != nullptr);
    MB_CHECK(high->severity == "high");
    MB_CHECK(high->action == "alert");
    MB_CHECK(std::find(high->mitre.begin(), high->mitre.end(),
                       "T1098.002") != high->mitre.end());

    FeedScore(&engine, "80");
    MB_CHECK(HasAlert("EDR-491"));
    MB_CHECK(!HasAlert("EDR-492"));

    /* Band edges: 75 is the lower edge of the high band, 100 the top. */
    FeedScore(&engine, "75");
    MB_CHECK(HasAlert("EDR-491"));
    MB_CHECK(!HasAlert("EDR-492"));
    FeedScore(&engine, "100");
    MB_CHECK(HasAlert("EDR-491"));
    MB_CHECK(!HasAlert("EDR-492"));

    /* Mid band: 74 must NOT hit the >=75 rule; 65 and 55 hit EDR-492
     * only. */
    FeedScore(&engine, "74");
    MB_CHECK(HasAlert("EDR-492"));
    MB_CHECK(!HasAlert("EDR-491"));
    FeedScore(&engine, "65");
    MB_CHECK(HasAlert("EDR-492"));
    MB_CHECK(!HasAlert("EDR-491"));
    const AlertRecord* mid = FindAlert("EDR-492");
    MB_CHECK(mid != nullptr);
    MB_CHECK(mid->severity == "medium");
    MB_CHECK(mid->action == "log");
    MB_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(),
                       "T1098.002") != mid->mitre.end());
    FeedScore(&engine, "55");
    MB_CHECK(HasAlert("EDR-492"));
    MB_CHECK(!HasAlert("EDR-491"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    MB_CHECK(!HasAlert("EDR-491"));
    MB_CHECK(!HasAlert("EDR-492"));
    FeedScore(&engine, "52");
    MB_CHECK(!HasAlert("EDR-491"));
    MB_CHECK(!HasAlert("EDR-492"));
    FeedScore(&engine, "50");
    MB_CHECK(!HasAlert("EDR-491"));
    MB_CHECK(!HasAlert("EDR-492"));
    FeedScore(&engine, "40");
    MB_CHECK(!HasAlert("EDR-491"));
    MB_CHECK(!HasAlert("EDR-492"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    MB_CHECK(!HasAlert("EDR-491"));
    MB_CHECK(!HasAlert("EDR-492"));
}

} // namespace

void RunMailboxDelegateDetectorTests() {
    std::fprintf(stderr, "[mailbox_delegate] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[mailbox_delegate] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[mailbox_delegate] TestFullAccessGrantTier85\n");
    TestFullAccessGrantTier85();
    std::fprintf(stderr, "[mailbox_delegate] TestSendAsGrantTier80\n");
    TestSendAsGrantTier80();
    std::fprintf(stderr, "[mailbox_delegate] TestFolderPermissionTier65\n");
    TestFolderPermissionTier65();
    std::fprintf(stderr, "[mailbox_delegate] TestSilentNonGrantShapes\n");
    TestSilentNonGrantShapes();
    std::fprintf(stderr, "[mailbox_delegate] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[mailbox_delegate] TestDedupWindow\n");
    TestDedupWindow();
    std::fprintf(stderr,
                 "[mailbox_delegate] TestDedupDisabledWithZeroWindow\n");
    TestDedupDisabledWithZeroWindow();
    std::fprintf(stderr, "[mailbox_delegate] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[mailbox_delegate] TestPlaneCoverage\n");
    TestPlaneCoverage();
    std::fprintf(stderr,
                 "[mailbox_delegate] TestIdentityExtractionGuards\n");
    TestIdentityExtractionGuards();
    std::fprintf(
        stderr, "[mailbox_delegate] TestMixedStatementsRemoveNotEndorsement\n");
    TestMixedStatementsRemoveNotEndorsement();
    std::fprintf(stderr, "[mailbox_delegate] TestRemoveThenAddStillHits\n");
    TestRemoveThenAddStillHits();
    std::fprintf(stderr, "[mailbox_delegate] TestPipelineBoundary\n");
    TestPipelineBoundary();
    std::fprintf(stderr, "[mailbox_delegate] TestBacktickContinuation\n");
    TestBacktickContinuation();
    std::fprintf(stderr,
                 "[mailbox_delegate] TestFakeCmdletWithRemoveFullAccess\n");
    TestFakeCmdletWithRemoveFullAccess();
    std::fprintf(stderr, "[mailbox_delegate] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[mailbox_delegate] all passed\n");
}
