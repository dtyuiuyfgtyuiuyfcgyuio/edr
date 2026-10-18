/*
 * gpp_password_detector_tests.cpp - Unit tests for GppPasswordDetector
 * (T1552.006) and the production rules that consume its score field.
 *
 * Detector tiers asserted here (per user/gpp_password_detector.cpp):
 *   90 gpp_password_tool   Get-GPPPassword / Get-GPPAutologon /
 *                          Get-GPPDomainPassword / Get-CachedGPPPassword.
 *   85 gpp_decrypt_tool    gpp-decrypt / gpprefdecrypt.
 *   80 cpassword_search    a `cpassword` token plus a search verb
 *                          (findstr / Select-String / grep / find / type).
 *   75 gpp_xml_access      a SYSVOL path plus a GPP XML name.
 *   65 cpassword_reference a bare `cpassword` token.
 *   Token-bounded needles (both edges) keep "encpassword" silent via
 *   the start edge and "cpassworded" / "cpassword_dump" silent via the
 *   tail edge; normal read-only policy commands (gpresult / Get-GPO /
 *   gpupdate) and plain file reads never score.
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-500  gpp_password_score >= 75   high/alert  T1552.006
 *   EDR-501  gpp_password_score 55-74   medium/log  T1552.006
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "gpp_password_detector_tests.h"

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
#include "gpp_password_detector.h"
#include "rule_engine.h"

namespace {

#define GP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "gpp password detector test failed at line " +
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
    return event.fields.find(edr::field::kGppPasswordScore) !=
           event.fields.end();
}

void TestInspects() {
    GP_CHECK(edr::GppPasswordDetector::Inspects(EDR_EVT_PROCESS_START));
    GP_CHECK(edr::GppPasswordDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    GP_CHECK(!edr::GppPasswordDetector::Inspects(EDR_EVT_NET_LISTENER));
    GP_CHECK(!edr::GppPasswordDetector::Inspects(EDR_EVT_REG_WRITE));
    GP_CHECK(!edr::GppPasswordDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::GppPasswordDetector detector(false, 55, 300, 1024);
    edr::Event ps = PsScriptEvent(
        1000 * kSecond, "Import-Module .\\Get-GPPPassword.ps1; Get-GPPPassword");
    detector.Enrich(ps);
    GP_CHECK(!HasScore(ps));
    edr::Event proc = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\findstr.exe",
        "findstr /s /i cpassword \\\\dc\\sysvol\\corp.local\\Policies\\*.xml");
    detector.Enrich(proc);
    GP_CHECK(!HasScore(proc));
}

void TestGppToolTier90() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    const char* const kTools[] = {
        "Get-GPPPassword",
        "Get-GPPAutologon",
        "Get-GPPDomainPassword",
        "Get-CachedGPPPassword",
    };
    /* All four tools share the "gpp_password_tool" dedup key, so the
     * events must be spaced past the default 300s window. */
    for (int i = 0; i < 4; ++i) {
        edr::Event ps = PsScriptEvent(
            (1000 + static_cast<uint64_t>(i) * 400) * kSecond,
            (std::string("Import-Module .\\PowerSploit.ps1; ") +
             kTools[i]).c_str());
        detector.Enrich(ps);
        GP_CHECK(ps.fields.at(edr::field::kGppPasswordScore) == "90");
        GP_CHECK(ps.fields.at(edr::field::kGppPasswordVerdict) ==
                 "malicious");
        GP_CHECK(ps.fields.at(edr::field::kGppPasswordSignals) ==
                 "gpp_password_tool");
    }
}

void TestDecryptToolTier85() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    edr::Event gpp = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw");
    detector.Enrich(gpp);
    GP_CHECK(gpp.fields.at(edr::field::kGppPasswordScore) == "85");
    GP_CHECK(gpp.fields.at(edr::field::kGppPasswordVerdict) == "malicious");
    GP_CHECK(gpp.fields.at(edr::field::kGppPasswordSignals) ==
             "gpp_decrypt_tool");
    GP_CHECK(gpp.fields.at(edr::field::kGppPasswordTools) == "gpp-decrypt");

    edr::Event py = ProcEvent(
        1400 * kSecond, "C:\\Python39\\python.exe",
        "python gpprefdecrypt.py j1Uyj3Vx8TY9LtLZil2uAuZkFQA");
    detector.Enrich(py);
    GP_CHECK(py.fields.at(edr::field::kGppPasswordScore) == "85");
    GP_CHECK(py.fields.at(edr::field::kGppPasswordTools) == "gpprefdecrypt");
}

void TestCpasswordSearchTier80() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    edr::Event findstr = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\findstr.exe",
        "findstr /s /i cpassword \\\\dc01\\sysvol\\corp.local\\Policies\\*.xml");
    detector.Enrich(findstr);
    GP_CHECK(findstr.fields.at(edr::field::kGppPasswordScore) == "80");
    GP_CHECK(findstr.fields.at(edr::field::kGppPasswordVerdict) ==
             "malicious");
    GP_CHECK(findstr.fields.at(edr::field::kGppPasswordSignals) ==
             "cpassword_search");

    edr::Event selectString = PsScriptEvent(
        1400 * kSecond,
        "Get-ChildItem \\\\dc01\\sysvol -Recurse -Filter *.xml | "
        "Select-String -Pattern cpassword");
    detector.Enrich(selectString);
    GP_CHECK(selectString.fields.at(edr::field::kGppPasswordScore) == "80");
    GP_CHECK(selectString.fields.at(edr::field::kGppPasswordSignals) ==
             "cpassword_search");
}

void TestSysvolXmlAccessTier75() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    edr::Event groups = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "copy \\\\dc01\\sysvol\\corp.local\\Policies\\{31B2F340}\\Machine\\"
        "Preferences\\Groups\\Groups.xml C:\\Users\\Public\\g.xml");
    detector.Enrich(groups);
    GP_CHECK(groups.fields.at(edr::field::kGppPasswordScore) == "75");
    GP_CHECK(groups.fields.at(edr::field::kGppPasswordVerdict) ==
             "malicious");
    GP_CHECK(groups.fields.at(edr::field::kGppPasswordSignals) ==
             "gpp_xml_access");
    GP_CHECK(groups.fields.at(edr::field::kGppPasswordTools) == "groups.xml");

    edr::Event services = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "type \\\\dc01\\sysvol\\corp.local\\Policies\\{31B2F340}\\Machine\\"
        "Preferences\\Services\\Services.xml");
    detector.Enrich(services);
    GP_CHECK(services.fields.at(edr::field::kGppPasswordScore) == "75");
    GP_CHECK(services.fields.at(edr::field::kGppPasswordTools) ==
             "services.xml");
}

void TestCpasswordReferenceTier65() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    /* A parser that never names a tool and never says SYSVOL: the bare
     * token only. No search verb, so the 80 tier stays silent. */
    edr::Event ps = PsScriptEvent(
        1000 * kSecond,
        "$xml = [xml](Get-Content .\\Groups.xml); "
        "$c = $xml.Groups.User.Properties.cpassword; Write-Host $c");
    detector.Enrich(ps);
    GP_CHECK(ps.fields.at(edr::field::kGppPasswordScore) == "65");
    GP_CHECK(ps.fields.at(edr::field::kGppPasswordVerdict) == "suspicious");
    GP_CHECK(ps.fields.at(edr::field::kGppPasswordSignals) ==
             "cpassword_reference");
}

void TestWordBoundaryNegatives() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    /* "encpassword" carries the cpassword stem after a letter: the
     * word-start guard keeps every tier silent. */
    edr::Event enc = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "findstr /s encpassword C:\\Users\\admin\\notes.txt");
    detector.Enrich(enc);
    GP_CHECK(!HasScore(enc));

    /* "reencpassword" likewise. */
    edr::Event reenc = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "type C:\\Users\\admin\\reencpassword.log");
    detector.Enrich(reenc);
    GP_CHECK(!HasScore(reenc));
}

void TestTokenTailBoundaryNegatives() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    /* Letter suffix glued onto the "cpassword" stem: "cpassworded" is a
     * different word, the tail edge must reject it (the old
     * word-start-only helper fired the 80 tier on it via the findstr
     * verb). */
    edr::Event cpassworded = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\findstr.exe",
        "findstr /s /i cpassworded C:\\Users\\admin\\notes.txt");
    detector.Enrich(cpassworded);
    GP_CHECK(!HasScore(cpassworded));

    /* Underscore continuation: property/identifier-style names glue
     * onto the stem, so "cpassword_dump" must not fire the bare-token
     * 65 tier. */
    edr::Event dump = PsScriptEvent(
        1400 * kSecond,
        "$d = $xml.Groups.User.Properties.cpassword_dump; Write-Host $d");
    detector.Enrich(dump);
    GP_CHECK(!HasScore(dump));

    /* Same tail family with a different search verb. */
    edr::Event typed = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "type C:\\Users\\admin\\cpassworded.log");
    detector.Enrich(typed);
    GP_CHECK(!HasScore(typed));

    GP_CHECK(detector.StateCount() == 0);
}

void TestNormalOpsSilent() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    const char* const kNormalOps[] = {
        "gpresult /r",
        "gpupdate /force",
        "type C:\\Users\\admin\\readme.txt",
        "findstr /s password \\\\dc01\\sysvol\\corp.local\\Policies\\*.xml",
        "Get-GPO -All",
    };
    for (int i = 0; i < 5; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\cmd.exe", kNormalOps[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[gpp_password] op scored: %s\n",
                         kNormalOps[i]);
        GP_CHECK(!HasScore(ev));
    }
    GP_CHECK(detector.StateCount() == 0);
}

void TestMinScoreGating() {
    /* min_score 90: the 85/80/75/65 tiers are filtered and, because the
     * gate runs before dedup bookkeeping, no key is inserted. */
    {
        edr::GppPasswordDetector detector(true, 90, 300, 1024);
        edr::Event tier80 = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\findstr.exe",
            "findstr /s /i cpassword \\\\dc\\sysvol\\*.xml");
        detector.Enrich(tier80);
        GP_CHECK(!HasScore(tier80));
        GP_CHECK(detector.StateCount() == 0);

        edr::Event tier90 = PsScriptEvent(
            1100 * kSecond, "Get-GPPPassword");
        detector.Enrich(tier90);
        GP_CHECK(tier90.fields.at(edr::field::kGppPasswordScore) == "90");
        GP_CHECK(detector.StateCount() == 1);
    }
    /* min_score 55 (default): the 65 tier survives. */
    {
        edr::GppPasswordDetector detector(true, 55, 300, 1024);
        edr::Event tier65 = PsScriptEvent(
            1000 * kSecond, "$x = $props.cpassword; Use($x)");
        detector.Enrich(tier65);
        GP_CHECK(tier65.fields.at(edr::field::kGppPasswordScore) == "65");
    }
}

void TestDedupPerTier() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    edr::Event first = PsScriptEvent(1000 * kSecond, "Get-GPPPassword");
    detector.Enrich(first);
    GP_CHECK(HasScore(first));
    GP_CHECK(detector.StateCount() == 1);

    /* Same tier inside the window is suppressed. */
    edr::Event repeat = PsScriptEvent(1100 * kSecond, "Get-GPPAutologon");
    detector.Enrich(repeat);
    GP_CHECK(!HasScore(repeat));

    /* A different tier is a different key and passes. */
    edr::Event otherTier = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA");
    detector.Enrich(otherTier);
    GP_CHECK(HasScore(otherTier));
    GP_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the first tier. */
    edr::Event late = PsScriptEvent(
        1000 * kSecond + 301 * kSecond, "Get-GPPPassword");
    detector.Enrich(late);
    GP_CHECK(HasScore(late));
    GP_CHECK(detector.StateCount() == 2);
}

void TestStateCapacityReset() {
    edr::GppPasswordDetector detector(true, 55, 300, 1);
    edr::Event first = PsScriptEvent(1000 * kSecond, "Get-GPPPassword");
    detector.Enrich(first);
    GP_CHECK(HasScore(first));
    GP_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event second = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA");
    detector.Enrich(second);
    GP_CHECK(HasScore(second));
    GP_CHECK(detector.StateCount() == 1);

    /* The reset re-arms the first tier (its key was cleared). */
    edr::Event again = PsScriptEvent(1200 * kSecond, "Get-GPPPassword");
    detector.Enrich(again);
    GP_CHECK(HasScore(again));
    GP_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::GppPasswordDetector detector(true, 55, 300, 1024);

    /* Uninspected event type carrying GPP text in an unrelated field. */
    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 1000 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] = "Get-GPPPassword";
    detector.Enrich(reg);
    GP_CHECK(!HasScore(reg));

    /* POWERSHELL_SCRIPT without a script body. */
    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1001 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    GP_CHECK(!HasScore(ps));

    /* PROCESS_START without a command line or GPP image. */
    edr::Event proc = ProcEvent(1002 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe", nullptr);
    detector.Enrich(proc);
    GP_CHECK(!HasScore(proc));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set gpp_password_score field (the RuleEngine never calls
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
        ev.fields[edr::field::kGppPasswordScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-500 (gpp_password_score >= 75, high/alert, T1552.006) and
     * EDR-501 (55-74, medium/log, T1552.006) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[gpp_password] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-500") == std::string::npos ||
        rulesText.find("EDR-501") == std::string::npos) {
        std::fprintf(stderr,
                     "[gpp_password] EDR-500/EDR-501 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* High band: 90/85/80/75 all land in >=75, so they hit EDR-500 only. */
    FeedScore(&engine, "90");
    GP_CHECK(HasAlert("EDR-500"));
    GP_CHECK(!HasAlert("EDR-501"));
    const AlertRecord* high = FindAlert("EDR-500");
    GP_CHECK(high != nullptr);
    GP_CHECK(high->severity == "high");
    GP_CHECK(high->action == "alert");
    GP_CHECK(std::find(high->mitre.begin(), high->mitre.end(),
                       "T1552.006") != high->mitre.end());

    FeedScore(&engine, "85");
    GP_CHECK(HasAlert("EDR-500"));
    GP_CHECK(!HasAlert("EDR-501"));
    FeedScore(&engine, "80");
    GP_CHECK(HasAlert("EDR-500"));
    GP_CHECK(!HasAlert("EDR-501"));
    FeedScore(&engine, "75");
    GP_CHECK(HasAlert("EDR-500"));
    GP_CHECK(!HasAlert("EDR-501"));

    /* Mid band: 74 must NOT hit the >=75 rule; 65/55 hit EDR-501 only. */
    FeedScore(&engine, "74");
    GP_CHECK(HasAlert("EDR-501"));
    GP_CHECK(!HasAlert("EDR-500"));
    const AlertRecord* mid = FindAlert("EDR-501");
    GP_CHECK(mid != nullptr);
    GP_CHECK(mid->severity == "medium");
    GP_CHECK(mid->action == "log");
    GP_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(),
                       "T1552.006") != mid->mitre.end());
    FeedScore(&engine, "65");
    GP_CHECK(HasAlert("EDR-501"));
    GP_CHECK(!HasAlert("EDR-500"));
    FeedScore(&engine, "55");
    GP_CHECK(HasAlert("EDR-501"));
    GP_CHECK(!HasAlert("EDR-500"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    GP_CHECK(!HasAlert("EDR-500"));
    GP_CHECK(!HasAlert("EDR-501"));
    FeedScore(&engine, "50");
    GP_CHECK(!HasAlert("EDR-500"));
    GP_CHECK(!HasAlert("EDR-501"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    GP_CHECK(!HasAlert("EDR-500"));
    GP_CHECK(!HasAlert("EDR-501"));
}

} // namespace

void RunGppPasswordDetectorTests() {
    std::fprintf(stderr, "[gpp_password] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[gpp_password] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[gpp_password] TestGppToolTier90\n");
    TestGppToolTier90();
    std::fprintf(stderr, "[gpp_password] TestDecryptToolTier85\n");
    TestDecryptToolTier85();
    std::fprintf(stderr, "[gpp_password] TestCpasswordSearchTier80\n");
    TestCpasswordSearchTier80();
    std::fprintf(stderr, "[gpp_password] TestSysvolXmlAccessTier75\n");
    TestSysvolXmlAccessTier75();
    std::fprintf(stderr, "[gpp_password] TestCpasswordReferenceTier65\n");
    TestCpasswordReferenceTier65();
    std::fprintf(stderr, "[gpp_password] TestWordBoundaryNegatives\n");
    TestWordBoundaryNegatives();
    std::fprintf(stderr, "[gpp_password] TestTokenTailBoundaryNegatives\n");
    TestTokenTailBoundaryNegatives();
    std::fprintf(stderr, "[gpp_password] TestNormalOpsSilent\n");
    TestNormalOpsSilent();
    std::fprintf(stderr, "[gpp_password] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[gpp_password] TestDedupPerTier\n");
    TestDedupPerTier();
    std::fprintf(stderr, "[gpp_password] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[gpp_password] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[gpp_password] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[gpp_password] all passed\n");
}
