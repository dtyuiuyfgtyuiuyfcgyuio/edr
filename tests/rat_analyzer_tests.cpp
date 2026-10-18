/*
 * rat_analyzer_tests.cpp - Unit tests for the RAT analyzer collector's pure
 * scoring helpers and the production rules they feed (EDR-247 through
 * EDR-250). The helpers require no live process state; the rule checks load
 * the production rules file and verify each rat_verdict band alerts.
 */
#include <windows.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "collector_rat_analyzer.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"

namespace {

#define RA_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "rat analyzer test failed at line " + std::to_string(line) +
            ": " + expression);
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

bool Has(const std::vector<std::string>& hits, const char* id) {
    return std::find(hits.begin(), hits.end(), id) != hits.end();
}

bool HasFlag(const edr::RatScoreResult& result, const char* flag) {
    return std::find(result.flags.begin(), result.flags.end(), flag) !=
           result.flags.end();
}

void TestBenignProcesses() {
    /* svchost.exe parented by services.exe is the ordinary shape. */
    edr::RatScoreResult svchost = edr::RatAnalyzerScoreProcess(
        "svchost.exe", "services.exe",
        "c:\\windows\\system32\\svchost.exe");
    RA_CHECK(svchost.score == 0);
    RA_CHECK(svchost.flags.empty());

    /* explorer.exe is not a protected name or tool. */
    edr::RatScoreResult explorer = edr::RatAnalyzerScoreProcess(
        "explorer.exe", "userinit.exe",
        "c:\\windows\\explorer.exe");
    RA_CHECK(explorer.score == 0);

    /* conhost.exe with a console-app parent (cmd.exe) is benign. */
    edr::RatScoreResult conhost = edr::RatAnalyzerScoreProcess(
        "conhost.exe", "cmd.exe", "c:\\windows\\system32\\conhost.exe");
    RA_CHECK(conhost.score == 0);
}

void TestLoaderFlags() {
    /* svchost.exe NOT parented by services.exe. */
    edr::RatScoreResult svchost = edr::RatAnalyzerScoreProcess(
        "svchost.exe", "explorer.exe",
        "c:\\windows\\system32\\svchost.exe");
    RA_CHECK(svchost.score >= 30);
    RA_CHECK(HasFlag(svchost, "RAT_LOADER_SVCHOST_ABNORMAL_PARENT"));

    /* conhost.exe spawned by services.exe (hidden console). */
    edr::RatScoreResult conhost = edr::RatAnalyzerScoreProcess(
        "conhost.exe", "services.exe",
        "c:\\windows\\system32\\conhost.exe");
    RA_CHECK(conhost.score >= 20);
    RA_CHECK(HasFlag(conhost, "RAT_LOADER_CONHOST_SERVICE_PARENT"));

    /* rundll32.exe with a script host parent (unusual). */
    edr::RatScoreResult rundll = edr::RatAnalyzerScoreProcess(
        "rundll32.exe", "winword.exe",
        "c:\\windows\\system32\\rundll32.exe");
    RA_CHECK(rundll.score >= 15);
    RA_CHECK(HasFlag(rundll, "RAT_LOADER_RUNDLL_ABNORMAL_PARENT"));

    /* rundll32.exe with an ordinary parent stays quiet. */
    edr::RatScoreResult ordinary = edr::RatAnalyzerScoreProcess(
        "rundll32.exe", "explorer.exe",
        "c:\\windows\\system32\\rundll32.exe");
    RA_CHECK(ordinary.score == 0);
}

void TestAnalysisTools() {
    edr::RatScoreResult taskmgr3g = edr::RatAnalyzerScoreProcess(
        "Taskmgr3G.exe", "explorer.exe", "");
    RA_CHECK(taskmgr3g.score >= 20);
    RA_CHECK(HasFlag(taskmgr3g, "RAT_EVASION_taskmgr3g.exe"));

    edr::RatScoreResult ida = edr::RatAnalyzerScoreProcess(
        "ida64.exe", "explorer.exe", "");
    RA_CHECK(ida.score >= 15);
    RA_CHECK(HasFlag(ida, "RAT_EVASION_ida64.exe"));

    /* Unknown tool names do not score. */
    edr::RatScoreResult unknown = edr::RatAnalyzerScoreProcess(
        "notepad.exe", "explorer.exe", "");
    RA_CHECK(unknown.score == 0);
}

void TestMasqueradeAndUserWritable() {
    /* Protected system name running from a user-writable path: both the
     * masquerade and the user-writable booster fire. */
    edr::RatScoreResult evil = edr::RatAnalyzerScoreProcess(
        "svchost.exe", "services.exe",
        "c:\\users\\victim\\appdata\\local\\temp\\svchost.exe");
    RA_CHECK(evil.score >= 35);
    RA_CHECK(HasFlag(evil, "RAT_MASQUERADE_PATH"));
    RA_CHECK(HasFlag(evil, "RAT_USER_WRITABLE_PATH"));

    /* A benign image in a user-writable path alone does not score (the
     * booster never triggers standalone). */
    edr::RatScoreResult benign = edr::RatAnalyzerScoreProcess(
        "notepad.exe", "explorer.exe",
        "c:\\users\\victim\\appdata\\local\\temp\\notepad.exe");
    RA_CHECK(benign.score == 0);

    /* Protected name in System32 is not a masquerade. */
    edr::RatScoreResult system32 = edr::RatAnalyzerScoreProcess(
        "lsass.exe", "wininit.exe", "c:\\windows\\system32\\lsass.exe");
    RA_CHECK(system32.score == 0);
}

void TestVerdicts() {
    RA_CHECK(std::string(edr::RatAnalyzerVerdict(0)) == "MONITOR");
    RA_CHECK(std::string(edr::RatAnalyzerVerdict(29)) == "MONITOR");
    RA_CHECK(std::string(edr::RatAnalyzerVerdict(30)) == "SUSPICIOUS");
    RA_CHECK(std::string(edr::RatAnalyzerVerdict(54)) == "SUSPICIOUS");
    RA_CHECK(std::string(edr::RatAnalyzerVerdict(55)) == "MALICIOUS");
    RA_CHECK(std::string(edr::RatAnalyzerVerdict(100)) == "MALICIOUS");
}

/* RuleEngine hit collector. */
std::vector<std::string> g_hits;

void OnAlert(const edr::Alert& alert) { g_hits.push_back(alert.ruleId); }

void TestRulesMatchRatAnalyzer() {
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::printf("skipping rule checks: rules file not found (%s)\n", path);
        return;
    }
    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback(OnAlert);

    struct Case {
        const char* verdict;
        const char* flags;
        const char* expectedRule;
    };
    const Case cases[] = {
        {"MALICIOUS", "RAT_LOADER_SVCHOST_ABNORMAL_PARENT,RAT_EVASION_ida64.exe", "EDR-247"},
        {"SUSPICIOUS", "RAT_LOADER_CONHOST_SERVICE_PARENT", "EDR-248"},
        {"MONITOR", "RAT_EVASION_procexp.exe", "EDR-249"},
    };
    for (const Case& c : cases) {
        g_hits.clear();
        edr::Event ev;
        ev.type = EDR_EVT_RAT_ANALYZER;
        ev.pid = 4242;
        ev.fields[edr::field::kType] = "RAT_ANALYZER";
        ev.fields[edr::field::kImage] = "svchost.exe";
        ev.fields[edr::field::kRatVerdict] = c.verdict;
        ev.fields[edr::field::kRatFlags] = c.flags;
        ev.fields[edr::field::kRatScore] = "45";
        engine.OnEvent(ev);
        RA_CHECK(Has(g_hits, c.expectedRule));
    }

    /* An unrelated event must not hit any RAT rule. */
    g_hits.clear();
    edr::Event other;
    other.type = EDR_EVT_PROCESS_START;
    other.pid = 4242;
    other.fields[edr::field::kType] = "PROCESS_START";
    other.fields[edr::field::kImage] = "svchost.exe";
    engine.OnEvent(other);
    RA_CHECK(!Has(g_hits, "EDR-247"));
    RA_CHECK(!Has(g_hits, "EDR-248"));
    RA_CHECK(!Has(g_hits, "EDR-249"));
}

} // namespace

int main() {
    try {
        TestBenignProcesses();
        TestLoaderFlags();
        TestAnalysisTools();
        TestMasqueradeAndUserWritable();
        TestVerdicts();
        TestRulesMatchRatAnalyzer();
        std::printf("rat analyzer tests passed\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "rat analyzer test failed: %s\n", e.what());
        return 1;
    }
}
