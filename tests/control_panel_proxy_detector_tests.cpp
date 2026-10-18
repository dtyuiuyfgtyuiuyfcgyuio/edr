/*
 * control_panel_proxy_detector_tests.cpp - Unit tests for
 * ControlPanelProxyDetector (T1218.002) and the production rules that
 * consume its score field.
 *
 * Detector tiers asserted here (per user/control_panel_proxy_detector.cpp):
 *   85 control_inf_exec    control.exe plus a `.inf` argument (INF
 *                          Install section execution), command and
 *                          PowerShell planes.
 *   80 control_cpl_payload control.exe plus a `.cpl` argument that
 *                          resolves into a user-writable or remote
 *                          location (UNC / \Users\Public\ / \AppData\ ...).
 *   70 control_rundll_cpl  Control_RunDLL plus `.cpl` resolving into a
 *                          user-writable / remote location, when
 *                          control.exe is not named.
 *   Deliberate silences: `control.exe main.cpl`,
 *   `control.exe C:\Windows\System32\main.cpl`,
 *   `rundll32 shell32.dll,Control_RunDLL main.cpl`,
 *   `control.exe /name Microsoft.X`, bare `control.exe`, and vendor
 *   binaries whose name ends in "control.exe" (connectwisecontrol.exe /
 *   mycontrol.exe) - the start edge of the token-bounded needles keeps
 *   the stem from matching inside a longer token, the tail edge rejects
 *   glued lookalikes ("control.exed", "Control_RunDLL2",
 *   "Control_RunDLL_Legacy"), and the real shell32 exports
 *   Control_RunDLLA / Control_RunDLLW stay covered as explicit needles.
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-502  control_panel_score >= 75   high/alert  T1218.002
 *   EDR-503  control_panel_score 55-74   medium/log  T1218.002
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "control_panel_proxy_detector_tests.h"

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
#include "control_panel_proxy_detector.h"
#include "rule_engine.h"

namespace {

#define CP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "control panel proxy detector test failed at line " +
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
    return event.fields.find(edr::field::kControlPanelScore) !=
           event.fields.end();
}

void TestInspects() {
    CP_CHECK(edr::ControlPanelProxyDetector::Inspects(EDR_EVT_PROCESS_START));
    CP_CHECK(edr::ControlPanelProxyDetector::Inspects(
        EDR_EVT_POWERSHELL_SCRIPT));
    CP_CHECK(!edr::ControlPanelProxyDetector::Inspects(EDR_EVT_NET_LISTENER));
    CP_CHECK(!edr::ControlPanelProxyDetector::Inspects(EDR_EVT_REG_WRITE));
    CP_CHECK(!edr::ControlPanelProxyDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::ControlPanelProxyDetector detector(false, 55, 300, 1024);
    edr::Event inf = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.inf");
    detector.Enrich(inf);
    CP_CHECK(!HasScore(inf));
    edr::Event cpl = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.cpl");
    detector.Enrich(cpl);
    CP_CHECK(!HasScore(cpl));
}

void TestInfExecTier85() {
    edr::ControlPanelProxyDetector detector(true, 55, 300, 1024);

    /* Full-path command shape. */
    edr::Event proc = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.inf");
    detector.Enrich(proc);
    CP_CHECK(proc.fields.at(edr::field::kControlPanelScore) == "85");
    CP_CHECK(proc.fields.at(edr::field::kControlPanelVerdict) ==
             "malicious");
    CP_CHECK(proc.fields.at(edr::field::kControlPanelSignals) ==
             "control_inf_exec");
    CP_CHECK(proc.fields.at(edr::field::kControlPanelFiles) == ".inf");

    /* Bare binary name shape. */
    edr::Event bare = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "control.exe C:\\Temp\\payload.inf");
    detector.Enrich(bare);
    CP_CHECK(bare.fields.at(edr::field::kControlPanelScore) == "85");

    /* PowerShell plane: body lives ONLY in kScriptBlockText. */
    edr::Event ps = PsScriptEvent(
        1800 * kSecond,
        "Start-Process control.exe -ArgumentList \"C:\\Temp\\payload.inf\"");
    detector.Enrich(ps);
    CP_CHECK(ps.fields.at(edr::field::kControlPanelScore) == "85");
    CP_CHECK(ps.fields.at(edr::field::kControlPanelSignals) ==
             "control_inf_exec");
}

void TestCplPayloadTier80() {
    edr::ControlPanelProxyDetector detector(true, 55, 300, 1024);

    /* User-writable path. */
    edr::Event publicDir = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.cpl");
    detector.Enrich(publicDir);
    CP_CHECK(publicDir.fields.at(edr::field::kControlPanelScore) == "80");
    CP_CHECK(publicDir.fields.at(edr::field::kControlPanelVerdict) ==
             "malicious");
    CP_CHECK(publicDir.fields.at(edr::field::kControlPanelSignals) ==
             "control_cpl_payload");
    CP_CHECK(publicDir.fields.at(edr::field::kControlPanelFiles) == ".cpl");

    /* UNC share. */
    edr::Event unc = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "control.exe \\\\fileserver\\share\\payload.cpl");
    detector.Enrich(unc);
    CP_CHECK(unc.fields.at(edr::field::kControlPanelScore) == "80");

    /* AppData staging. */
    edr::Event appdata = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "control.exe C:\\Users\\admin\\AppData\\Local\\Temp\\evil.cpl");
    detector.Enrich(appdata);
    CP_CHECK(appdata.fields.at(edr::field::kControlPanelScore) == "80");
}

void TestRundllCplTier70() {
    edr::ControlPanelProxyDetector detector(true, 55, 300, 1024);

    edr::Event rundll = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe shell32.dll,Control_RunDLL C:\\Users\\Public\\evil.cpl");
    detector.Enrich(rundll);
    CP_CHECK(rundll.fields.at(edr::field::kControlPanelScore) == "70");
    CP_CHECK(rundll.fields.at(edr::field::kControlPanelVerdict) ==
             "suspicious");
    CP_CHECK(rundll.fields.at(edr::field::kControlPanelSignals) ==
             "control_rundll_cpl");
    CP_CHECK(rundll.fields.at(edr::field::kControlPanelFiles) == ".cpl");

    /* PowerShell plane. */
    edr::Event ps = PsScriptEvent(
        1400 * kSecond,
        "Start-Process rundll32.exe -ArgumentList "
        "\"shell32.dll,Control_RunDLL\",\"C:\\Temp\\evil.cpl\"");
    detector.Enrich(ps);
    CP_CHECK(ps.fields.at(edr::field::kControlPanelScore) == "70");
}

void TestSystemAppletSilent() {
    edr::ControlPanelProxyDetector detector(true, 55, 300, 1024);

    const char* const kNormalOps[] = {
        "control.exe main.cpl",                        /* bare applet name */
        "control.exe C:\\Windows\\System32\\main.cpl",  /* system applet */
        "control.exe /name Microsoft.WindowsUpdate",
        "control.exe",
        "control.exe desk.cpl,,1",
    };
    for (int i = 0; i < 5; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\control.exe", kNormalOps[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[control_panel] op scored: %s\n",
                         kNormalOps[i]);
        CP_CHECK(!HasScore(ev));
    }
    CP_CHECK(detector.StateCount() == 0);
}

void TestWordBoundaryNegatives() {
    edr::ControlPanelProxyDetector detector(true, 55, 300, 1024);

    /* Vendor remote-access tool whose name ends in "control.exe": the
     * word-start guard keeps the "control.exe" stem from matching. */
    edr::Event vendor = ProcEvent(
        1000 * kSecond, "C:\\Program Files\\ConnectWise\\connectwisecontrol.exe",
        "connectwisecontrol.exe C:\\Users\\Public\\payload.cpl");
    detector.Enrich(vendor);
    CP_CHECK(!HasScore(vendor));

    edr::Event mycontrol = ProcEvent(
        1001 * kSecond, "C:\\Tools\\mycontrol.exe",
        "mycontrol.exe C:\\Users\\Public\\evil.inf");
    detector.Enrich(mycontrol);
    CP_CHECK(!HasScore(mycontrol));

    /* Control_RunDLL on a System32 applet is a normal applet open: the
     * payload-location rule keeps the 70 tier silent. */
    edr::Event rundllApplet = ProcEvent(
        1002 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe shell32.dll,Control_RunDLL "
        "C:\\Windows\\System32\\main.cpl");
    detector.Enrich(rundllApplet);
    CP_CHECK(!HasScore(rundllApplet));

    /* Control_RunDLL on a dropped payload does score (70). */
    edr::Event rundllPayload = ProcEvent(
        1003 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe shell32.dll,Control_RunDLL C:\\Temp\\evil.cpl");
    detector.Enrich(rundllPayload);
    CP_CHECK(rundllPayload.fields.at(edr::field::kControlPanelScore) == "70");

    /* An .inf under a non-Control-Panel signed host stays silent here
     * (that is the generic rundll32 / T1218.011 face). */
    edr::Event otherHost = ProcEvent(
        1004 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 0 "
        "C:\\Users\\Public\\evil.inf");
    detector.Enrich(otherHost);
    CP_CHECK(!HasScore(otherHost));
}

void TestTokenTailBoundaryNegatives() {
    edr::ControlPanelProxyDetector detector(true, 55, 300, 1024);

    /* Letter suffix glued onto the "control.exe" stem: "control.exed"
     * is a different token, the tail edge must reject it even when a
     * payload .cpl and a payload location are present. */
    edr::Event controlExed = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "control.exed C:\\Users\\Public\\payload.cpl");
    detector.Enrich(controlExed);
    CP_CHECK(!HasScore(controlExed));

    /* Digit/underscore glue on the Control_RunDLL export stem: neither
     * is a real shell32 export, the tail edge must reject them (the old
     * word-start-only helper fired the 70 tier on both). */
    edr::Event rundll2 = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe shell32.dll,Control_RunDLL2 C:\\Temp\\evil.cpl");
    detector.Enrich(rundll2);
    CP_CHECK(!HasScore(rundll2));

    edr::Event rundllLegacy = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe shell32.dll,Control_RunDLL_Legacy C:\\Temp\\evil.cpl");
    detector.Enrich(rundllLegacy);
    CP_CHECK(!HasScore(rundllLegacy));

    /* Non-negative guard: the real shell32 exports Control_RunDLLA /
     * Control_RunDLLW are genuine export names the old word-start-only
     * helper matched by accident; the explicit A/W needles keep that
     * coverage under the new tail edge (Control_RunDLLW scores 70). */
    edr::Event rundllW = ProcEvent(
        2200 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe shell32.dll,Control_RunDLLW C:\\Temp\\evil.cpl");
    detector.Enrich(rundllW);
    CP_CHECK(rundllW.fields.at(edr::field::kControlPanelScore) == "70");

    CP_CHECK(detector.StateCount() == 1);
}

void TestMinScoreGating() {
    /* min_score 85: the 80 and 70 tiers are filtered and, because the
     * gate runs before dedup bookkeeping, no key is inserted. */
    {
        edr::ControlPanelProxyDetector detector(true, 85, 300, 1024);
        edr::Event tier80 = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\control.exe",
            "control.exe C:\\Users\\Public\\evil.cpl");
        detector.Enrich(tier80);
        CP_CHECK(!HasScore(tier80));
        edr::Event tier70 = ProcEvent(
            1100 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe shell32.dll,Control_RunDLL C:\\Temp\\evil.cpl");
        detector.Enrich(tier70);
        CP_CHECK(!HasScore(tier70));
        CP_CHECK(detector.StateCount() == 0);

        edr::Event tier85 = ProcEvent(
            1200 * kSecond, "C:\\Windows\\System32\\control.exe",
            "control.exe C:\\Users\\Public\\evil.inf");
        detector.Enrich(tier85);
        CP_CHECK(tier85.fields.at(edr::field::kControlPanelScore) == "85");
        CP_CHECK(detector.StateCount() == 1);
    }
    /* min_score 55 (default): the 70 tier survives. */
    {
        edr::ControlPanelProxyDetector detector(true, 55, 300, 1024);
        edr::Event tier70 = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe shell32.dll,Control_RunDLL C:\\Temp\\evil.cpl");
        detector.Enrich(tier70);
        CP_CHECK(tier70.fields.at(edr::field::kControlPanelScore) == "70");
    }
}

void TestDedupPerTier() {
    edr::ControlPanelProxyDetector detector(true, 55, 300, 1024);

    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.inf");
    detector.Enrich(first);
    CP_CHECK(HasScore(first));
    CP_CHECK(detector.StateCount() == 1);

    /* Same tier inside the window is suppressed. */
    edr::Event repeat = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Temp\\payload.inf");
    detector.Enrich(repeat);
    CP_CHECK(!HasScore(repeat));

    /* A different tier is a different key and passes. */
    edr::Event otherTier = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.cpl");
    detector.Enrich(otherTier);
    CP_CHECK(HasScore(otherTier));
    CP_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the first tier. */
    edr::Event late = ProcEvent(
        1000 * kSecond + 301 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.inf");
    detector.Enrich(late);
    CP_CHECK(HasScore(late));
    CP_CHECK(detector.StateCount() == 2);
}

void TestStateCapacityReset() {
    edr::ControlPanelProxyDetector detector(true, 55, 300, 1);
    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.inf");
    detector.Enrich(first);
    CP_CHECK(HasScore(first));
    CP_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event second = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.cpl");
    detector.Enrich(second);
    CP_CHECK(HasScore(second));
    CP_CHECK(detector.StateCount() == 1);

    /* The reset re-arms the first tier (its key was cleared). */
    edr::Event again = ProcEvent(
        1200 * kSecond, "C:\\Windows\\System32\\control.exe",
        "control.exe C:\\Users\\Public\\evil.inf");
    detector.Enrich(again);
    CP_CHECK(HasScore(again));
    CP_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::ControlPanelProxyDetector detector(true, 55, 300, 1024);

    /* Uninspected event type carrying the proxy text in an unrelated
     * field. */
    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 1000 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] = "control.exe C:\\evil.inf";
    detector.Enrich(reg);
    CP_CHECK(!HasScore(reg));

    /* POWERSHELL_SCRIPT without a script body. */
    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1001 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    CP_CHECK(!HasScore(ps));

    /* PROCESS_START without a command line or proxy image. */
    edr::Event proc = ProcEvent(1002 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe", nullptr);
    detector.Enrich(proc);
    CP_CHECK(!HasScore(proc));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set control_panel_score field (the RuleEngine never
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
        ev.fields[edr::field::kControlPanelScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-502 (control_panel_score >= 75, high/alert, T1218.002) and
     * EDR-503 (55-74, medium/log, T1218.002) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[control_panel] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-502") == std::string::npos ||
        rulesText.find("EDR-503") == std::string::npos) {
        std::fprintf(stderr,
                     "[control_panel] EDR-502/EDR-503 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* High band: 85/80/75 all land in >=75, so they hit EDR-502 only. */
    FeedScore(&engine, "100");
    CP_CHECK(HasAlert("EDR-502"));
    CP_CHECK(!HasAlert("EDR-503"));
    const AlertRecord* high = FindAlert("EDR-502");
    CP_CHECK(high != nullptr);
    CP_CHECK(high->severity == "high");
    CP_CHECK(high->action == "alert");
    CP_CHECK(std::find(high->mitre.begin(), high->mitre.end(),
                       "T1218.002") != high->mitre.end());

    FeedScore(&engine, "85");
    CP_CHECK(HasAlert("EDR-502"));
    CP_CHECK(!HasAlert("EDR-503"));
    FeedScore(&engine, "80");
    CP_CHECK(HasAlert("EDR-502"));
    CP_CHECK(!HasAlert("EDR-503"));
    FeedScore(&engine, "75");
    CP_CHECK(HasAlert("EDR-502"));
    CP_CHECK(!HasAlert("EDR-503"));

    /* Mid band: 74 must NOT hit the >=75 rule; 70/55 hit EDR-503 only. */
    FeedScore(&engine, "74");
    CP_CHECK(HasAlert("EDR-503"));
    CP_CHECK(!HasAlert("EDR-502"));
    const AlertRecord* mid = FindAlert("EDR-503");
    CP_CHECK(mid != nullptr);
    CP_CHECK(mid->severity == "medium");
    CP_CHECK(mid->action == "log");
    CP_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(),
                       "T1218.002") != mid->mitre.end());
    FeedScore(&engine, "70");
    CP_CHECK(HasAlert("EDR-503"));
    CP_CHECK(!HasAlert("EDR-502"));
    FeedScore(&engine, "55");
    CP_CHECK(HasAlert("EDR-503"));
    CP_CHECK(!HasAlert("EDR-502"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    CP_CHECK(!HasAlert("EDR-502"));
    CP_CHECK(!HasAlert("EDR-503"));
    FeedScore(&engine, "50");
    CP_CHECK(!HasAlert("EDR-502"));
    CP_CHECK(!HasAlert("EDR-503"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    CP_CHECK(!HasAlert("EDR-502"));
    CP_CHECK(!HasAlert("EDR-503"));
}

} // namespace

void RunControlPanelProxyDetectorTests() {
    std::fprintf(stderr, "[control_panel] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[control_panel] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[control_panel] TestInfExecTier85\n");
    TestInfExecTier85();
    std::fprintf(stderr, "[control_panel] TestCplPayloadTier80\n");
    TestCplPayloadTier80();
    std::fprintf(stderr, "[control_panel] TestRundllCplTier70\n");
    TestRundllCplTier70();
    std::fprintf(stderr, "[control_panel] TestSystemAppletSilent\n");
    TestSystemAppletSilent();
    std::fprintf(stderr, "[control_panel] TestWordBoundaryNegatives\n");
    TestWordBoundaryNegatives();
    std::fprintf(stderr,
                 "[control_panel] TestTokenTailBoundaryNegatives\n");
    TestTokenTailBoundaryNegatives();
    std::fprintf(stderr, "[control_panel] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[control_panel] TestDedupPerTier\n");
    TestDedupPerTier();
    std::fprintf(stderr, "[control_panel] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[control_panel] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[control_panel] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[control_panel] all passed\n");
}
