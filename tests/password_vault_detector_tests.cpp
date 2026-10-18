/*
 * password_vault_detector_tests.cpp - Unit tests for
 * PasswordVaultDetector (T1555.005) and the production rules it feeds
 * (EDR-489/EDR-490).
 *
 * Text placement follows the house contract: command-surface text goes in
 * kCommandLine; a POWERSHELL_SCRIPT body goes ONLY in kScriptBlockText
 * (never kCommandLine/kImage).
 */
#include "password_vault_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "password_vault_detector.h"
#include "rule_engine.h"

namespace {

#define PV_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "password vault detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

/* POWERSHELL_SCRIPT carries its body only in kScriptBlockText. */
edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptBody) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptBody;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kPasswordVaultScore);
    return it == event.fields.end() ? "" : it->second;
}

struct RuleHit {
    std::string ruleId;
    std::string severity;
    std::vector<std::string> mitre;
};

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

bool Has(const std::vector<RuleHit>& hits, const char* id) {
    for (const RuleHit& hit : hits) {
        if (hit.ruleId == id) return true;
    }
    return false;
}

const RuleHit* Find(const std::vector<RuleHit>& hits, const char* id) {
    for (const RuleHit& hit : hits) {
        if (hit.ruleId == id) return &hit;
    }
    return nullptr;
}

bool HasMitre(const RuleHit& hit, const char* technique) {
    return std::find(hit.mitre.begin(), hit.mitre.end(), technique) !=
           hit.mitre.end();
}

bool RulesTextContains(const char* path, const char* needle) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    return text.find(needle) != std::string::npos;
}

void TestInspectsAndDisabled() {
    PV_CHECK(edr::PasswordVaultDetector::Inspects(EDR_EVT_PROCESS_START));
    PV_CHECK(
        edr::PasswordVaultDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    PV_CHECK(!edr::PasswordVaultDetector::Inspects(EDR_EVT_REG_WRITE));

    edr::PasswordVaultDetector detector(false, 55, 300, 1024);
    edr::Event event = ProcEvent(1000 * kSecond, "C:\\Tools\\keepass2john.exe",
                                 "keepass2john.exe C:\\v\\vault.kdbx");
    detector.Enrich(event);
    PV_CHECK(Score(event).empty());
    PV_CHECK(event.fields.find(edr::field::kPasswordVaultVerdict) ==
             event.fields.end());
}

void TestKeepass2JohnHashExtraction() {
    edr::PasswordVaultDetector detector(true, 55, 300, 1024);
    edr::Event event = ProcEvent(
        1000 * kSecond, "C:\\Tools\\keepass2john.exe",
        "keepass2john.exe C:\\Users\\bob\\Documents\\vault.kdbx > hash.txt");
    detector.Enrich(event);
    PV_CHECK(Score(event) == "90");
    PV_CHECK(event.fields.at(edr::field::kPasswordVaultVerdict) ==
             "malicious");
    PV_CHECK(event.fields.at(edr::field::kPasswordVaultSignals) ==
             "keepass2john_hash_extraction");
    PV_CHECK(event.fields.at(edr::field::kPasswordVaultTools) ==
             "keepass2john");
    PV_CHECK(detector.StateCount() == 1);
}

void TestBitwardenCliExport() {
    edr::PasswordVaultDetector detector(true, 55, 300, 1024);
    edr::Event event = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "bw export --format json --output C:\\Temp\\bitwarden.json");
    detector.Enrich(event);
    PV_CHECK(Score(event) == "85");
    PV_CHECK(event.fields.at(edr::field::kPasswordVaultVerdict) ==
             "malicious");
    PV_CHECK(event.fields.at(edr::field::kPasswordVaultSignals) ==
             "bitwarden_cli_export");
    PV_CHECK(event.fields.at(edr::field::kPasswordVaultTools) == "bitwarden");

    /* bw.exe image with the export subcommand; the needle is
     * "bw.exe export" at a command boundary. Separate instance: the
     * per-signal dedup window would mask the same signal otherwise. */
    edr::PasswordVaultDetector exeDetector(true, 55, 300, 1024);
    edr::Event exeForm = ProcEvent(
        1010 * kSecond, "C:\\Program Files\\Bitwarden CLI\\bw.exe",
        "bw.exe export --raw");
    exeDetector.Enrich(exeForm);
    PV_CHECK(Score(exeForm) == "85");
    PV_CHECK(exeForm.fields.at(edr::field::kPasswordVaultSignals) ==
             "bitwarden_cli_export");
}

/* .kdb/.kdbx referenced with an export/copy/archive verb on both
 * surfaces. */
void TestKeepassDatabaseStaging() {
    edr::PasswordVaultDetector detector(true, 55, 300, 1024);
    edr::Event ps = ScriptEvent(
        1000 * kSecond,
        "Copy-Item C:\\Users\\bob\\Documents\\vault.kdbx \\\\srv\\loot\\");
    detector.Enrich(ps);
    PV_CHECK(Score(ps) == "80");
    PV_CHECK(ps.fields.at(edr::field::kPasswordVaultSignals) ==
             "keepass_database_staging");
    PV_CHECK(ps.fields.at(edr::field::kPasswordVaultVerdict) == "malicious");
    PV_CHECK(ps.fields.find(edr::field::kCommandLine) == ps.fields.end());
    PV_CHECK(ps.fields.find(edr::field::kImage) == ps.fields.end());

    /* Command surface: cmd copy of the database. Separate instance - the
     * per-signal dedup window would mask the same signal otherwise. */
    edr::PasswordVaultDetector cmdDetector(true, 55, 300, 1024);
    edr::Event cmd = ProcEvent(
        1010 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "copy C:\\Vault\\db.kdb \\\\srv\\share\\db.kdb");
    cmdDetector.Enrich(cmd);
    PV_CHECK(Score(cmd) == "80");
    PV_CHECK(cmd.fields.at(edr::field::kPasswordVaultSignals) ==
             "keepass_database_staging");
}

/* Low-band positives use a 55-threshold instance (min_score isolation). */
void TestKeepassxCliTiers() {
    edr::PasswordVaultDetector detector(true, 55, 300, 1024);
    edr::Event exportUse = ProcEvent(
        1000 * kSecond, "C:\\Program Files\\KeePassXC\\keepassxc-cli.exe",
        "keepassxc-cli export C:\\v\\db.kdbx");
    detector.Enrich(exportUse);
    PV_CHECK(Score(exportUse) == "70");
    PV_CHECK(exportUse.fields.at(edr::field::kPasswordVaultVerdict) ==
             "suspicious");
    PV_CHECK(exportUse.fields.at(edr::field::kPasswordVaultSignals) ==
             "keepassxc_cli_export");
    PV_CHECK(exportUse.fields.at(edr::field::kPasswordVaultTools) ==
             "keepassxc-cli");

    edr::Event showUse = ProcEvent(
        1010 * kSecond, "C:\\Program Files\\KeePassXC\\keepassxc-cli.exe",
        "keepassxc-cli show -a Password C:\\v\\db.kdbx");
    detector.Enrich(showUse);
    PV_CHECK(Score(showUse) == "60");
    PV_CHECK(showUse.fields.at(edr::field::kPasswordVaultVerdict) ==
             "suspicious");
    PV_CHECK(showUse.fields.at(edr::field::kPasswordVaultSignals) ==
             "keepassxc_cli_noninteractive_use");
}

/* keepassxc-cli export is judged at subcommand level (contract in
 * password_vault_detector.h): only an export token directly bound to a
 * keepassxc executable token - or a hyphenated export compound after it
 * (piped "export-csv", deliberately retained) - upgrades to 70; prose
 * "export" words stay in the 60 automation tier. One fresh detector
 * instance per case so per-signal dedup slots stay independent. */
void TestKeepassxCliExportSubcommandBoundary() {
    struct Case {
        const char* image;
        const char* commandLine;
        const char* expectedScore;
        const char* expectedSignal;
    };

    /* 60 negatives: an "export" word that is not the subcommand. */
    const Case negatives[] = {
        {"C:\\Program Files\\KeePassXC\\keepassxc-cli.exe",
         "keepassxc-cli show db", "60",
         "keepassxc_cli_noninteractive_use"},
        {"C:\\Program Files\\KeePassXC\\keepassxc-cli.exe",
         "keepassxc-cli show db.kdbx  # see export docs", "60",
         "keepassxc_cli_noninteractive_use"},
        {"C:\\Program Files\\KeePassXC\\keepassxc-cli.exe",
         "keepassxc-cli show -a Password C:\\v\\db.kdbx  # export notes",
         "60", "keepassxc_cli_noninteractive_use"},
        {"C:\\Program Files\\KeePassXC\\keepassxc-cli.exe",
         "keepassxc-cli # export docs", "60",
         "keepassxc_cli_noninteractive_use"},
        {"C:\\Program Files\\KeePassXC\\keepassxc-cli.exe",
         "keepassxc-cli show db # pipe to export-csv next", "60",
         "keepassxc_cli_noninteractive_use"},
    };
    for (const Case& c : negatives) {
        edr::PasswordVaultDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(1000 * kSecond, c.image, c.commandLine);
        detector.Enrich(event);
        PV_CHECK(Score(event) == c.expectedScore);
        PV_CHECK(event.fields.at(edr::field::kPasswordVaultSignals) ==
                 c.expectedSignal);
    }

    /* 70 positives: export bound to a keepassxc executable token. */
    const Case positives[] = {
        {"C:\\Windows\\System32\\cmd.exe",
         "keepassxc-cli export C:\\v\\db.kdbx out.csv", "70",
         "keepassxc_cli_export"},
        {"C:\\Windows\\System32\\cmd.exe",
         "keepassxc-cli -q export C:\\v\\db.kdbx", "70",
         "keepassxc_cli_export"},
        {"C:\\Windows\\System32\\cmd.exe",
         "keepassxc-cli -k C:\\Keys\\k.key export C:\\v\\db.kdbx", "70",
         "keepassxc_cli_export"},
        {"C:\\Windows\\System32\\cmd.exe",
         "keepassxc export C:\\v\\db.kdbx out.csv", "70",
         "keepassxc_cli_export"},
        {"C:\\Program Files\\KeePassXC\\keepassxc-cli.exe",
         "keepassxc-cli.exe export C:\\v\\db.kdbx", "70",
         "keepassxc_cli_export"},
        {"C:\\Program Files\\KeePassXC\\keepassxc-cli.exe",
         "keepassxc-cli show db | export-csv out", "70",
         "keepassxc_cli_export"},
    };
    for (const Case& c : positives) {
        edr::PasswordVaultDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(1000 * kSecond, c.image, c.commandLine);
        detector.Enrich(event);
        PV_CHECK(Score(event) == c.expectedScore);
        PV_CHECK(event.fields.at(edr::field::kPasswordVaultVerdict) ==
                 "suspicious");
        PV_CHECK(event.fields.at(edr::field::kPasswordVaultSignals) ==
                 c.expectedSignal);
        PV_CHECK(event.fields.at(edr::field::kPasswordVaultTools) ==
                 "keepassxc-cli");
    }
}

/* 1Password CLI bulk reads; each phrase on its own low-threshold
 * instance so the per-signal dedup window cannot mask it. */
void TestOnePasswordCliBulkRead() {
    edr::PasswordVaultDetector detector(true, 55, 300, 1024);
    edr::Event opRead = ProcEvent(
        1000 * kSecond, "C:\\Program Files\\1Password CLI\\op.exe",
        "op read \"op://Private/server/password\"");
    detector.Enrich(opRead);
    PV_CHECK(Score(opRead) == "60");
    PV_CHECK(opRead.fields.at(edr::field::kPasswordVaultVerdict) ==
             "suspicious");
    PV_CHECK(opRead.fields.at(edr::field::kPasswordVaultSignals) ==
             "onepassword_cli_bulk_read");
    PV_CHECK(opRead.fields.at(edr::field::kPasswordVaultTools) == "1password");

    edr::PasswordVaultDetector listDetector(true, 55, 300, 1024);
    edr::Event opList = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "op item list --account my.1password.com");
    listDetector.Enrich(opList);
    PV_CHECK(Score(opList) == "60");

    /* Word-bounded matching: "desktop readme" must not match "op read"
     * and "op.exe item list" exercises the image-name subcommand route. */
    edr::PasswordVaultDetector boundaryDetector(true, 55, 300, 1024);
    edr::Event boundary = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "dir desktop readme.txt");
    boundaryDetector.Enrich(boundary);
    PV_CHECK(Score(boundary).empty());

    edr::PasswordVaultDetector exeDetector(true, 55, 300, 1024);
    edr::Event exeRoute = ProcEvent(
        1000 * kSecond, "C:\\Program Files\\1Password CLI\\op.exe",
        "op.exe item list");
    exeDetector.Enrich(exeRoute);
    PV_CHECK(Score(exeRoute) == "60");
}

/* Anti-false-positive negative: bare keepass mentions, the GUI binary,
 * and plain .kdbx references without a staging verb stay silent. */
void TestBareKeepassMentionsSilent() {
    edr::PasswordVaultDetector detector(true, 55, 300, 1024);
    edr::Event gui = ProcEvent(
        1000 * kSecond, "C:\\Program Files\\KeePassXC\\keepassxc.exe",
        "keepassxc.exe");
    detector.Enrich(gui);
    PV_CHECK(Score(gui).empty());

    edr::Event mention = ProcEvent(
        1010 * kSecond, "C:\\Windows\\System32\\notepad.exe",
        "notepad.exe C:\\Notes\\keepass-setup.txt");
    detector.Enrich(mention);
    PV_CHECK(Score(mention).empty());

    edr::Event plainRef = ProcEvent(
        1020 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "dir C:\\Users\\bob\\Documents\\vault.kdbx");
    detector.Enrich(plainRef);
    PV_CHECK(Score(plainRef).empty());
    PV_CHECK(plainRef.fields.find(edr::field::kPasswordVaultVerdict) ==
             plainRef.fields.end());
    PV_CHECK(detector.StateCount() == 0);
}

/* POWERSHELL_SCRIPT body resolves through kScriptBlockText only. */
void TestScriptBlockOnlyBody() {
    edr::PasswordVaultDetector detector(true, 55, 300, 1024);
    edr::Event event = ScriptEvent(
        1000 * kSecond,
        "keepass2john.exe C:\\Users\\bob\\vault.kdbx | Out-File "
        "C:\\Temp\\hash.txt");
    detector.Enrich(event);
    PV_CHECK(Score(event) == "90");
    PV_CHECK(event.fields.at(edr::field::kPasswordVaultSignals) ==
             "keepass2john_hash_extraction");
    PV_CHECK(event.fields.find(edr::field::kCommandLine) ==
             event.fields.end());
    PV_CHECK(event.fields.find(edr::field::kImage) == event.fields.end());
}

/* PROCESS_START with no command line captured falls back to kImage. */
void TestImageFallback() {
    edr::PasswordVaultDetector detector(true, 55, 300, 1024);
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = 1000 * kSecond;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = "C:\\Tools\\keepass2john.exe";
    detector.Enrich(event);
    PV_CHECK(Score(event) == "90");
}

/* min_score isolation: an independent 90-threshold instance suppresses
 * the 85 band while the 90 tier still stamps. */
void TestMinScoreGate() {
    edr::PasswordVaultDetector strict(true, 90, 300, 1024);
    edr::Event below = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "bw export --format json --output C:\\Temp\\bw.json");
    strict.Enrich(below);
    PV_CHECK(Score(below).empty());
    PV_CHECK(strict.StateCount() == 0);

    edr::Event top = ProcEvent(1010 * kSecond, "C:\\Tools\\keepass2john.exe",
                               "keepass2john.exe C:\\v\\vault.kdbx");
    strict.Enrich(top);
    PV_CHECK(Score(top) == "90");
}

/* Dedup is per signal inside the window: different command text with the
 * same signal is suppressed, the window expiry re-arms, and another
 * signal keeps its own slot. */
void TestDedupWindow() {
    edr::PasswordVaultDetector detector(true, 55, 60, 1024);
    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Tools\\keepass2john.exe",
        "keepass2john.exe C:\\v\\a.kdbx");
    detector.Enrich(first);
    PV_CHECK(!Score(first).empty());
    PV_CHECK(detector.StateCount() == 1);

    edr::Event second = ProcEvent(
        1030 * kSecond, "C:\\Tools\\keepass2john.exe",
        "keepass2john.exe C:\\v\\b.kdbx");
    detector.Enrich(second);
    PV_CHECK(Score(second).empty());
    PV_CHECK(detector.StateCount() == 1);

    edr::Event third = ProcEvent(
        1120 * kSecond, "C:\\Tools\\keepass2john.exe",
        "keepass2john.exe C:\\v\\a.kdbx");
    detector.Enrich(third);
    PV_CHECK(!Score(third).empty());
    PV_CHECK(detector.StateCount() == 1);

    edr::Event bitwarden = ProcEvent(
        1130 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "bw export --format json --output C:\\Temp\\bw.json");
    detector.Enrich(bitwarden);
    PV_CHECK(Score(bitwarden) == "85");
    PV_CHECK(detector.StateCount() == 2);
}

/* EDR-489 (>=75, high/alert) and EDR-490 (55-74, medium/log), both
 * T1555.005. The production-rule section presets the score field manually
 * and feeds the RuleEngine - the detector itself is covered above. */
void TestPasswordVaultProductionRules() {
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[password_vault] skipping production rules: rules "
                     "file not found (%s)\n",
                     path);
        return;
    }
    if (!RulesTextContains(path, "\"EDR-489\"") ||
        !RulesTextContains(path, "\"EDR-490\"")) {
        std::fprintf(stderr,
                     "[password_vault] skipping production rules: EDR-489/"
                     "EDR-490 not wired into rules.json yet\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    std::vector<RuleHit> hits;
    engine.SetAlertCallback([&hits](const edr::Alert& alert) {
        RuleHit hit;
        hit.ruleId = alert.ruleId;
        hit.severity = alert.severity;
        hit.mitre = alert.mitreAttack;
        hits.push_back(hit);
    });

    const uint64_t ts = 1000 * kSecond;
    auto scored = [&](const char* scoreText) {
        edr::Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.ts100ns = ts;
        event.fields[edr::field::kType] = "PROCESS_START";
        event.fields[edr::field::kPasswordVaultScore] = scoreText;
        return event;
    };
    auto expectsHigh = [&](const char* scoreText) {
        hits.clear();
        edr::Event event = scored(scoreText);
        engine.OnEvent(event);
        const RuleHit* hit = Find(hits, "EDR-489");
        PV_CHECK(hit != nullptr);
        PV_CHECK(hit->severity == "high");
        PV_CHECK(HasMitre(*hit, "T1555.005"));
        PV_CHECK(!Has(hits, "EDR-490")); /* bands are disjoint */
    };
    auto expectsMedium = [&](const char* scoreText) {
        hits.clear();
        edr::Event event = scored(scoreText);
        engine.OnEvent(event);
        const RuleHit* hit = Find(hits, "EDR-490");
        PV_CHECK(hit != nullptr);
        PV_CHECK(hit->severity == "medium");
        PV_CHECK(HasMitre(*hit, "T1555.005"));
        PV_CHECK(!Has(hits, "EDR-489"));
    };

    /* 80/85/90 -> EDR-489 only. */
    expectsHigh("80");
    expectsHigh("85");
    expectsHigh("90");

    /* 60/70 (plus the 55 floor and the 74 top edge) -> EDR-490 only. */
    expectsMedium("55");
    expectsMedium("60");
    expectsMedium("70");
    expectsMedium("74");

    /* Dead band: 50-54 (and anything <55) never hits any new rule. */
    for (const char* score : {"54", "50"}) {
        hits.clear();
        edr::Event dead = scored(score);
        engine.OnEvent(dead);
        PV_CHECK(!Has(hits, "EDR-488"));
        PV_CHECK(!Has(hits, "EDR-489"));
        PV_CHECK(!Has(hits, "EDR-490"));
    }

    /* A PROCESS_START without a score field never fires the band rules. */
    hits.clear();
    edr::Event clean;
    clean.type = EDR_EVT_PROCESS_START;
    clean.ts100ns = ts;
    clean.fields[edr::field::kType] = "PROCESS_START";
    engine.OnEvent(clean);
    PV_CHECK(!Has(hits, "EDR-489"));
    PV_CHECK(!Has(hits, "EDR-490"));
}

} // namespace

void RunPasswordVaultDetectorTests() {
    std::fprintf(stderr, "[password_vault] TestInspectsAndDisabled\n");
    TestInspectsAndDisabled();
    std::fprintf(stderr, "[password_vault] TestKeepass2JohnHashExtraction\n");
    TestKeepass2JohnHashExtraction();
    std::fprintf(stderr, "[password_vault] TestBitwardenCliExport\n");
    TestBitwardenCliExport();
    std::fprintf(stderr, "[password_vault] TestKeepassDatabaseStaging\n");
    TestKeepassDatabaseStaging();
    std::fprintf(stderr, "[password_vault] TestKeepassxCliTiers\n");
    TestKeepassxCliTiers();
    std::fprintf(stderr,
                 "[password_vault] "
                 "TestKeepassxCliExportSubcommandBoundary\n");
    TestKeepassxCliExportSubcommandBoundary();
    std::fprintf(stderr, "[password_vault] TestOnePasswordCliBulkRead\n");
    TestOnePasswordCliBulkRead();
    std::fprintf(stderr, "[password_vault] TestBareKeepassMentionsSilent\n");
    TestBareKeepassMentionsSilent();
    std::fprintf(stderr, "[password_vault] TestScriptBlockOnlyBody\n");
    TestScriptBlockOnlyBody();
    std::fprintf(stderr, "[password_vault] TestImageFallback\n");
    TestImageFallback();
    std::fprintf(stderr, "[password_vault] TestMinScoreGate\n");
    TestMinScoreGate();
    std::fprintf(stderr, "[password_vault] TestDedupWindow\n");
    TestDedupWindow();
    std::fprintf(stderr,
                 "[password_vault] TestPasswordVaultProductionRules\n");
    TestPasswordVaultProductionRules();
    std::fprintf(stderr, "[password_vault] all passed\n");
}
