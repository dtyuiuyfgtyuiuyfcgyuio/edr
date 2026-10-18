/*
 * hidden_user_account_detector_tests.cpp - Unit tests for
 * HiddenUserAccountDetector (T1564.002) and the production rules that
 * consume its score field.
 *
 * Detector tiers asserted here (per user/hidden_user_account_detector.cpp):
 *   85 hidden_user_account   UserList value written with data 0, in the
 *                            snapshot REG_WRITE shape (full path ending in
 *                            the account, kRegValue = data) and on the
 *                            command plane with an explicit zero shape
 *                            (/d 0, -Value 0).
 *   75 hidden_user_write     driver-shape REG_WRITE (key ends at UserList,
 *                            kRegValue = account name, no data).
 *   70 hidden_user_visible   UserList value written with non-zero data.
 *   65 hidden_user_cmd_write command plane without a zero shape.
 *   Deliberate silences: other SpecialAccounts subkeys, `reg query` (read),
 *   `reg delete` (un-hide), and paths that merely contain "userlist".
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-504  hidden_user_score >= 75   high/alert  T1564.002
 *   EDR-505  hidden_user_score 55-74   medium/log  T1564.002
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "hidden_user_account_detector_tests.h"

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
#include "hidden_user_account_detector.h"
#include "rule_engine.h"

namespace {

#define HU_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "hidden user account test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

const char* const kUserListKey =
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
    "SpecialAccounts\\UserList";

edr::Event RegEvent(uint64_t ts, const char* key, const char* value) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    if (value != nullptr) event.fields[edr::field::kRegValue] = value;
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

edr::Event PsScriptEvent(uint64_t ts, const char* scriptText) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptText;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kHiddenUserScore) !=
           event.fields.end();
}

void TestInspects() {
    HU_CHECK(edr::HiddenUserAccountDetector::Inspects(EDR_EVT_REG_WRITE));
    HU_CHECK(edr::HiddenUserAccountDetector::Inspects(EDR_EVT_PROCESS_START));
    HU_CHECK(edr::HiddenUserAccountDetector::Inspects(
        EDR_EVT_POWERSHELL_SCRIPT));
    HU_CHECK(!edr::HiddenUserAccountDetector::Inspects(EDR_EVT_NET_LISTENER));
    HU_CHECK(!edr::HiddenUserAccountDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::HiddenUserAccountDetector detector(false, 55, 300, 1024);
    edr::Event reg = RegEvent(
        1000 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\backdoor",
        "0");
    detector.Enrich(reg);
    HU_CHECK(!HasScore(reg));
    edr::Event cmd = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\reg.exe",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Winlogon\\SpecialAccounts\\UserList\" /v backdoor /t REG_DWORD /d 0");
    detector.Enrich(cmd);
    HU_CHECK(!HasScore(cmd));
}

void TestSnapshotHiddenTier85() {
    edr::HiddenUserAccountDetector detector(true, 55, 300, 1024);

    /* Snapshot shape: full path ending in the account, kRegValue = data. */
    edr::Event reg = RegEvent(
        1000 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\backdoor",
        "0");
    detector.Enrich(reg);
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserScore) == "85");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserVerdict) == "malicious");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserSignals) ==
             "hidden_user_account");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserAccounts) == "backdoor");

    /* Hive-agnostic prefix spelling must not matter. */
    edr::Event machine = RegEvent(
        1400 * kSecond,
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\"
        "CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\\svc_backup",
        "0");
    detector.Enrich(machine);
    HU_CHECK(machine.fields.at(edr::field::kHiddenUserScore) == "85");
    HU_CHECK(machine.fields.at(edr::field::kHiddenUserAccounts) ==
             "svc_backup");
}

void TestSnapshotVisibleTier70() {
    edr::HiddenUserAccountDetector detector(true, 55, 300, 1024);

    edr::Event reg = RegEvent(
        1000 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\backdoor",
        "1");
    detector.Enrich(reg);
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserScore) == "70");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserVerdict) == "suspicious");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserSignals) ==
             "hidden_user_visible");
}

void TestDriverShapeTier75() {
    edr::HiddenUserAccountDetector detector(true, 55, 300, 1024);

    /* Driver shape: key ends at UserList, kRegValue is the value NAME
     * (the account); no data is available. */
    edr::Event reg = RegEvent(
        1000 * kSecond,
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\"
        "CurrentVersion\\Winlogon\\SpecialAccounts\\UserList",
        "backdoor");
    detector.Enrich(reg);
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserScore) == "75");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserVerdict) == "malicious");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserSignals) ==
             "hidden_user_write");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserAccounts) == "backdoor");
}

void TestCommandPlaneTier85() {
    edr::HiddenUserAccountDetector detector(true, 55, 300, 1024);

    /* reg add with an explicit zero data. */
    edr::Event reg = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\reg.exe",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Winlogon\\SpecialAccounts\\UserList\" /v backdoor "
        "/t REG_DWORD /d 0");
    detector.Enrich(reg);
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserScore) == "85");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserSignals) ==
             "hidden_user_account");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserAccounts) == "backdoor");

    /* PowerShell plane: Set-ItemProperty -Value 0 (body only in
     * kScriptBlockText). */
    edr::Event ps = PsScriptEvent(
        1400 * kSecond,
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\"
        "CurrentVersion\\Winlogon\\SpecialAccounts\\UserList' "
        "-Name svc_backup -Value 0");
    detector.Enrich(ps);
    HU_CHECK(ps.fields.at(edr::field::kHiddenUserScore) == "85");
    HU_CHECK(ps.fields.at(edr::field::kHiddenUserAccounts) == "svc_backup");
}

void TestCommandPlaneTier65() {
    edr::HiddenUserAccountDetector detector(true, 55, 300, 1024);

    /* A UserList write without a recognizable zero shape. */
    edr::Event reg = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\reg.exe",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Winlogon\\SpecialAccounts\\UserList\" /v backdoor "
        "/t REG_DWORD");
    detector.Enrich(reg);
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserScore) == "65");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserVerdict) == "suspicious");
    HU_CHECK(reg.fields.at(edr::field::kHiddenUserSignals) ==
             "hidden_user_cmd_write");
}

void TestNormalOpsSilent() {
    edr::HiddenUserAccountDetector detector(true, 55, 300, 1024);

    /* Other SpecialAccounts subkeys are unrelated. */
    edr::Event notes = RegEvent(
        1000 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\Notes\\x",
        "0");
    detector.Enrich(notes);
    HU_CHECK(!HasScore(notes));

    /* A path that merely mentions userlist without the SpecialAccounts
     * parent pair. */
    edr::Event unrelated = RegEvent(
        1001 * kSecond,
        "HKLM\\SOFTWARE\\Vendor\\App\\UserList\\item",
        "0");
    detector.Enrich(unrelated);
    HU_CHECK(!HasScore(unrelated));

    /* reg query is a read, not a concealment write. */
    edr::Event query = ProcEvent(
        1002 * kSecond, "C:\\Windows\\System32\\reg.exe",
        "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Winlogon\\SpecialAccounts\\UserList\"");
    detector.Enrich(query);
    HU_CHECK(!HasScore(query));

    /* reg delete un-hides the account. */
    edr::Event del = ProcEvent(
        1003 * kSecond, "C:\\Windows\\System32\\reg.exe",
        "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Winlogon\\SpecialAccounts\\UserList\" /v backdoor /f");
    detector.Enrich(del);
    HU_CHECK(!HasScore(del));

    /* Unrelated registry write. */
    edr::Event other = RegEvent(
        1004 * kSecond, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                        "Run\\updater",
        "C:\\Program Files\\App\\updater.exe");
    detector.Enrich(other);
    HU_CHECK(!HasScore(other));

    HU_CHECK(detector.StateCount() == 0);
}

void TestMinScoreGating() {
    /* min_score 85: the 75/70/65 tiers are filtered and, because the gate
     * runs before dedup bookkeeping, no key is inserted. */
    {
        edr::HiddenUserAccountDetector detector(true, 85, 300, 1024);
        edr::Event driver = RegEvent(
            1000 * kSecond,
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\Winlogon\\SpecialAccounts\\UserList",
            "backdoor");
        detector.Enrich(driver);
        HU_CHECK(!HasScore(driver));
        HU_CHECK(detector.StateCount() == 0);

        edr::Event hidden = RegEvent(
            1100 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            "Winlogon\\SpecialAccounts\\UserList\\backdoor",
            "0");
        detector.Enrich(hidden);
        HU_CHECK(hidden.fields.at(edr::field::kHiddenUserScore) == "85");
        HU_CHECK(detector.StateCount() == 1);
    }
    /* min_score 55 (default): the 65 tier survives. */
    {
        edr::HiddenUserAccountDetector detector(true, 55, 300, 1024);
        edr::Event cmd = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" "
            "/v backdoor /t REG_DWORD");
        detector.Enrich(cmd);
        HU_CHECK(cmd.fields.at(edr::field::kHiddenUserScore) == "65");
    }
}

void TestDedupPerAccount() {
    edr::HiddenUserAccountDetector detector(true, 55, 300, 1024);

    edr::Event first = RegEvent(
        1000 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\backdoor",
        "0");
    detector.Enrich(first);
    HU_CHECK(HasScore(first));
    HU_CHECK(detector.StateCount() == 1);

    /* Same account inside the window is suppressed. */
    edr::Event repeat = RegEvent(
        1100 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\backdoor",
        "0");
    detector.Enrich(repeat);
    HU_CHECK(!HasScore(repeat));

    /* A different account is a different key and passes. */
    edr::Event other = RegEvent(
        1100 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\svc_backup",
        "0");
    detector.Enrich(other);
    HU_CHECK(HasScore(other));
    HU_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the first account. */
    edr::Event late = RegEvent(
        1000 * kSecond + 301 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\backdoor",
        "0");
    detector.Enrich(late);
    HU_CHECK(HasScore(late));
    HU_CHECK(detector.StateCount() == 2);
}

void TestStateCapacityReset() {
    edr::HiddenUserAccountDetector detector(true, 55, 300, 1);
    edr::Event first = RegEvent(
        1000 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\backdoor",
        "0");
    detector.Enrich(first);
    HU_CHECK(HasScore(first));
    HU_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event second = RegEvent(
        1100 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\svc_backup",
        "0");
    detector.Enrich(second);
    HU_CHECK(HasScore(second));
    HU_CHECK(detector.StateCount() == 1);

    /* The reset re-arms the first account (its key was cleared). */
    edr::Event again = RegEvent(
        1200 * kSecond,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
        "SpecialAccounts\\UserList\\backdoor",
        "0");
    detector.Enrich(again);
    HU_CHECK(HasScore(again));
    HU_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::HiddenUserAccountDetector detector(true, 55, 300, 1024);

    /* Uninspected event type carrying the key text in an unrelated field. */
    edr::Event file;
    file.type = EDR_EVT_FILE_CREATE;
    file.ts100ns = 1000 * kSecond;
    file.fields[edr::field::kType] = "FILE_CREATE";
    file.fields[edr::field::kImage] = kUserListKey;
    detector.Enrich(file);
    HU_CHECK(!HasScore(file));

    /* POWERSHELL_SCRIPT without a script body. */
    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1001 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    HU_CHECK(!HasScore(ps));

    /* REG_WRITE without a key. */
    edr::Event empty;
    empty.type = EDR_EVT_REG_WRITE;
    empty.ts100ns = 1002 * kSecond;
    empty.fields[edr::field::kType] = "REG_WRITE";
    detector.Enrich(empty);
    HU_CHECK(!HasScore(empty));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set hidden_user_score field (the RuleEngine never calls
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
    ev.type = EDR_EVT_REG_WRITE;
    ev.ts100ns = 1000 * kSecond;
    ev.fields[edr::field::kType] = "REG_WRITE";
    if (score != nullptr)
        ev.fields[edr::field::kHiddenUserScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-504 (hidden_user_score >= 75, high/alert, T1564.002) and
     * EDR-505 (55-74, medium/log, T1564.002) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[hidden_user] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-504") == std::string::npos ||
        rulesText.find("EDR-505") == std::string::npos) {
        std::fprintf(stderr,
                     "[hidden_user] EDR-504/EDR-505 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* High band: 85/75 both land in >=75, so they hit EDR-504 only. */
    FeedScore(&engine, "100");
    HU_CHECK(HasAlert("EDR-504"));
    HU_CHECK(!HasAlert("EDR-505"));
    const AlertRecord* high = FindAlert("EDR-504");
    HU_CHECK(high != nullptr);
    HU_CHECK(high->severity == "high");
    HU_CHECK(high->action == "alert");
    HU_CHECK(std::find(high->mitre.begin(), high->mitre.end(),
                       "T1564.002") != high->mitre.end());

    FeedScore(&engine, "85");
    HU_CHECK(HasAlert("EDR-504"));
    HU_CHECK(!HasAlert("EDR-505"));
    FeedScore(&engine, "75");
    HU_CHECK(HasAlert("EDR-504"));
    HU_CHECK(!HasAlert("EDR-505"));

    /* Mid band: 74 must NOT hit the >=75 rule; 70/65/55 hit EDR-505 only. */
    FeedScore(&engine, "74");
    HU_CHECK(HasAlert("EDR-505"));
    HU_CHECK(!HasAlert("EDR-504"));
    const AlertRecord* mid = FindAlert("EDR-505");
    HU_CHECK(mid != nullptr);
    HU_CHECK(mid->severity == "medium");
    HU_CHECK(mid->action == "log");
    HU_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(),
                       "T1564.002") != mid->mitre.end());
    FeedScore(&engine, "70");
    HU_CHECK(HasAlert("EDR-505"));
    HU_CHECK(!HasAlert("EDR-504"));
    FeedScore(&engine, "65");
    HU_CHECK(HasAlert("EDR-505"));
    HU_CHECK(!HasAlert("EDR-504"));
    FeedScore(&engine, "55");
    HU_CHECK(HasAlert("EDR-505"));
    HU_CHECK(!HasAlert("EDR-504"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    HU_CHECK(!HasAlert("EDR-504"));
    HU_CHECK(!HasAlert("EDR-505"));
    FeedScore(&engine, "50");
    HU_CHECK(!HasAlert("EDR-504"));
    HU_CHECK(!HasAlert("EDR-505"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    HU_CHECK(!HasAlert("EDR-504"));
    HU_CHECK(!HasAlert("EDR-505"));
}

} // namespace

void RunHiddenUserAccountDetectorTests() {
    std::fprintf(stderr, "[hidden_user] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[hidden_user] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[hidden_user] TestSnapshotHiddenTier85\n");
    TestSnapshotHiddenTier85();
    std::fprintf(stderr, "[hidden_user] TestSnapshotVisibleTier70\n");
    TestSnapshotVisibleTier70();
    std::fprintf(stderr, "[hidden_user] TestDriverShapeTier75\n");
    TestDriverShapeTier75();
    std::fprintf(stderr, "[hidden_user] TestCommandPlaneTier85\n");
    TestCommandPlaneTier85();
    std::fprintf(stderr, "[hidden_user] TestCommandPlaneTier65\n");
    TestCommandPlaneTier65();
    std::fprintf(stderr, "[hidden_user] TestNormalOpsSilent\n");
    TestNormalOpsSilent();
    std::fprintf(stderr, "[hidden_user] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[hidden_user] TestDedupPerAccount\n");
    TestDedupPerAccount();
    std::fprintf(stderr, "[hidden_user] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[hidden_user] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[hidden_user] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[hidden_user] all passed\n");
}
