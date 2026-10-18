/*
 * rule_lint_tests.cpp - Unit tests for the WS-C rule static validator.
 *
 * All cases use self-contained inline JSON so they do not depend on the
 * contents of rules/rules.json (which other workstreams may edit).
 */
#include "rule_lint_tests.h"

#include <cstddef>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "rule_lint.h"

namespace {

#define LINT_CHECK(c) LintCheck((c), #c, __LINE__)

void LintCheck(bool c, const char* expr, int line) {
    if (!c) {
        throw std::runtime_error(std::string("lint CHECK failed at line ") +
                                 std::to_string(line) + ": " + expr);
    }
}

edr::RuleLintReport Lint(const std::string& json, bool* ok,
                         std::string* fatal) {
    edr::RuleLintReport report;
    std::string localFatal;
    const bool parsed = edr::LintRulesJson(
        json, &report, fatal != nullptr ? fatal : &localFatal);
    if (ok != nullptr) *ok = parsed;
    return report;
}

size_t CountCode(const edr::RuleLintReport& r, const std::string& code) {
    size_t n = 0;
    for (const edr::RuleLintIssue& issue : r.issues) {
        if (issue.code == code) ++n;
    }
    return n;
}

const edr::RuleLintIssue* FindCode(const edr::RuleLintReport& r,
                                   const std::string& code) {
    for (const edr::RuleLintIssue& issue : r.issues) {
        if (issue.code == code) return &issue;
    }
    return nullptr;
}

/* A minimal well-formed rule with a harmless regex and full MITRE mapping. */
const char* const kCleanRule =
    R"j({"id":"EDR-001","severity":"high","action":"alert","condition":"all",)j"
    R"j("mitre_attack":["T1059.001"],"mitre_tactic":["Execution"],)j"
    R"j("match":{"image":{"regex":"(?i)powershell(\\.exe)?$"}}})j";

std::string Document(const std::string& rules) {
    return std::string("{\"rules\":[") + rules + "]}";
}

} // namespace

void RunRuleLintTests() {
    std::fprintf(stderr, "[lint] TestValidRuleClean\n");
    {
        bool ok = false;
        const auto rep = Lint(Document(kCleanRule), &ok, nullptr);
        LINT_CHECK(ok);
        LINT_CHECK(rep.ruleCount == 1u);
        LINT_CHECK(rep.errorCount == 0u);
        LINT_CHECK(rep.warningCount == 0u);
        LINT_CHECK(rep.issues.empty());
    }

    std::fprintf(stderr, "[lint] TestDupId\n");
    {
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-050","severity":"high","action":"alert",)j"
                R"j("mitre_attack":["T1059"],"mitre_tactic":["Execution"],)j"
                R"j("match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"EDR-050","severity":"low","action":"log",)j"
                R"j("mitre_attack":["T1059"],"mitre_tactic":["Execution"],)j"
                R"j("match":{"b":{"eq":"2"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "dup_id") == 1u);
        const edr::RuleLintIssue* issue = FindCode(rep, "dup_id");
        LINT_CHECK(issue != nullptr && issue->severity == "error");
        LINT_CHECK(issue != nullptr && issue->ruleId == "EDR-050");
    }

    std::fprintf(stderr, "[lint] TestBadId\n");
    {
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-12","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"EDR-1234","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"EDR-003-KILL","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"SF-1","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"XYZ-001","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"EDR-999","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"SF-001","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"eq":"1"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "bad_id") == 4u);
        LINT_CHECK(CountCode(rep, "legacy_id") == 1u);
        LINT_CHECK(rep.ruleCount == 7u);
    }

    std::fprintf(stderr, "[lint] TestRuleIdCompatibility\n");
    {
        std::string rules;
        for (const char* id : {"EDR-003-KILL", "EDR-314B", "EDR-003-KILL",
                               "EDR-003-OTHER", "EDR-314C", "SF-001"}) {
            if (!rules.empty()) rules += ',';
            rules += std::string("{\"id\":\"") + id +
                "\",\"severity\":\"high\",\"action\":\"alert\","
                "\"match\":{\"a\":{\"eq\":\"1\"}}}";
        }
        const auto rep = Lint(Document(rules), nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "bad_id") == 2u);
        LINT_CHECK(CountCode(rep, "legacy_id") == 3u);
        LINT_CHECK(CountCode(rep, "dup_id") == 1u);
        LINT_CHECK(FindCode(rep, "legacy_id")->severity == "warning");
    }

    std::fprintf(stderr, "[lint] TestBadEnum\n");
    {
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-101","severity":"severe","action":"alert",)j"
                R"j("match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"EDR-102","severity":"high","action":"block",)j"
                R"j("match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"EDR-103","severity":"high","action":"alert",)j"
                R"j("condition":"some","match":{"a":{"eq":"1"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "bad_enum") == 3u);
        LINT_CHECK(FindCode(rep, "bad_enum")->severity == "error");
    }

    std::fprintf(stderr, "[lint] TestEmptyMatch\n");
    {
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-111","severity":"high","action":"alert"},)j"
                R"j({"id":"EDR-112","severity":"high","action":"alert",)j"
                R"j("match":{}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "empty_match") == 2u);
    }

    std::fprintf(stderr, "[lint] TestBadRegexIsolatedPerPredicate\n");
    {
        /* Both predicates carry a broken regex: the second must still be
         * reported (a single bad assertion must not skip the whole rule). */
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-121","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"regex":"("},"b":{"not_regex":"("}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "bad_regex") == 2u);
        LINT_CHECK(FindCode(rep, "bad_regex")->severity == "error");
    }
    {
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-122","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"regex":"^ab+c$"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "bad_regex") == 0u);
    }

    std::fprintf(stderr, "[lint] TestBandLeakOldWritingReported\n");
    {
        /* Regression guard: `[5-9][0-9]` wrongly admits 50..54. */
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-131","severity":"medium","action":"alert",)j"
                R"j("mitre_attack":["T1059"],"mitre_tactic":["Execution"],)j"
                R"j("match":{"x_score":{"regex":"^(?:[5-9][0-9]|100)$"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "band_leak") == 1u);
        const edr::RuleLintIssue* issue = FindCode(rep, "band_leak");
        LINT_CHECK(issue != nullptr && issue->severity == "warning");
        LINT_CHECK(issue != nullptr &&
                   issue->message.find("50") != std::string::npos);
    }

    std::fprintf(stderr, "[lint] TestBandLeakCorrectWritingSilent\n");
    {
        /* The canonical house band starts at 55 and must stay silent. */
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-132","severity":"medium","action":"alert",)j"
                R"j("mitre_attack":["T1059"],"mitre_tactic":["Execution"],)j"
                R"j("match":{"x_score":{"regex":"^(?:5[5-9]|[6-9][0-9]|100)$"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "band_leak") == 0u);
        LINT_CHECK(rep.errorCount == 0u);
    }

    std::fprintf(stderr, "[lint] TestBandLeakUsesEngineRegexSearchSemantics\n");
    {
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-134","severity":"medium","action":"alert",)j"
                R"j("mitre_attack":["T1059"],"mitre_tactic":["Execution"],)j"
                R"j("match":{"x_score":{"regex":"5"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "band_leak") == 1u);
    }

    std::fprintf(stderr, "[lint] TestBandLeakDocumented50Exempt\n");
    {
        /* An intentional 50+ floor is documented in comments and accepted. */
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-133","severity":"high","action":"alert",)j"
                R"j("comments":"deliberately 50+ floor, not the 55+ house band",)j"
                R"j("mitre_attack":["T1059"],"mitre_tactic":["Execution"],)j"
                R"j("match":{"x_score":{"regex":"^(?:[5-9][0-9]|100)$"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "band_leak") == 0u);
    }

    std::fprintf(stderr, "[lint] TestOverMatchAnyTypeEq\n");
    {
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-141","severity":"high","action":"alert",)j"
                R"j("condition":"any","mitre_attack":["T1059"],)j"
                R"j("mitre_tactic":["Execution"],)j"
                R"j("match":{"type":{"eq":"PROCESS_START"},)j"
                R"j("image":{"regex":"evil"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "over_match") == 1u);
        LINT_CHECK(FindCode(rep, "over_match")->severity == "warning");
    }
    {
        /* condition "all" with a type eq is fine. */
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-142","severity":"high","action":"alert",)j"
                R"j("condition":"all","mitre_attack":["T1059"],)j"
                R"j("mitre_tactic":["Execution"],)j"
                R"j("match":{"type":{"eq":"PROCESS_START"},)j"
                R"j("image":{"regex":"evil"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "over_match") == 0u);
    }
    {
        /* condition "any" without a type eq is fine. */
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-143","severity":"high","action":"alert",)j"
                R"j("condition":"any","mitre_attack":["T1059"],)j"
                R"j("mitre_tactic":["Execution"],)j"
                R"j("match":{"image":{"regex":"evil"},)j"
                R"j("parent_image":{"regex":"bad"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "over_match") == 0u);
    }

    std::fprintf(stderr, "[lint] TestBadMitre\n");
    {
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-151","severity":"high","action":"alert",)j"
                R"j("mitre_attack":["T123","T1059.001","bad"],)j"
                R"j("mitre_tactic":["Execution"],"match":{"a":{"eq":"1"}}},)j"
                R"j({"id":"EDR-152","severity":"high","action":"alert",)j"
                R"j("mitre_attack":["T1059"],"mitre_tactic":[],)j"
                R"j("match":{"a":{"eq":"1"}}})j"),
            nullptr, nullptr);
        /* 2 malformed technique ids + 1 empty tactic array. */
        LINT_CHECK(CountCode(rep, "bad_mitre") == 3u);
        LINT_CHECK(FindCode(rep, "bad_mitre")->severity == "warning");
    }
    {
        /* A rule without any mitre_tactic field is flagged (missing tactic). */
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-153","severity":"high","action":"alert",)j"
                R"j("mitre_attack":["T1059"],"match":{"a":{"eq":"1"}}})j"),
            nullptr, nullptr);
        LINT_CHECK(CountCode(rep, "bad_mitre") == 1u);
    }

    std::fprintf(stderr, "[lint] TestFatalPaths\n");
    {
        std::string fatal;
        bool ok = true;
        const auto rep = Lint(R"j({"rules":[ {"id": )j", &ok, &fatal);
        LINT_CHECK(!ok);
        LINT_CHECK(!fatal.empty());
        LINT_CHECK(rep.errorCount >= 1u);
        LINT_CHECK(CountCode(rep, "fatal") == 1u);
    }
    {
        bool ok = true;
        const auto rep =
            Lint(R"j({"comment":"no rules array here"})j", &ok, nullptr);
        LINT_CHECK(!ok);
        LINT_CHECK(CountCode(rep, "fatal") == 1u);
    }
    {
        /* A bare top-level array is accepted as the rule list. */
        bool ok = false;
        const auto rep = Lint(std::string("[") + kCleanRule + "]", &ok, nullptr);
        LINT_CHECK(ok);
        LINT_CHECK(rep.ruleCount == 1u);
        LINT_CHECK(rep.errorCount == 0u);
    }

    std::fprintf(stderr, "[lint] TestIssuesSortedByRuleIdThenCode\n");
    {
        const auto rep = Lint(
            Document(
                R"j({"id":"EDR-202","severity":"bogus","action":"alert",)j"
                R"j("match":{}},)j"
                R"j({"id":"EDR-201","severity":"high","action":"alert",)j"
                R"j("match":{"a":{"regex":"("}}})j"),
            nullptr, nullptr);
        LINT_CHECK(rep.issues.size() >= 3u);
        for (size_t i = 1; i < rep.issues.size(); ++i) {
            const edr::RuleLintIssue& prev = rep.issues[i - 1];
            const edr::RuleLintIssue& cur = rep.issues[i];
            const bool ordered =
                (prev.ruleId < cur.ruleId) ||
                (prev.ruleId == cur.ruleId && prev.code <= cur.code);
            LINT_CHECK(ordered);
        }
    }

    std::fprintf(stderr, "[lint] TestDeterministicFormatting\n");
    {
        const std::string doc = Document(
            R"j({"id":"EDR-301","severity":"severe","action":"alert",)j"
            R"j("match":{"x_score":{"regex":"^(?:[5-9][0-9]|100)$"}}})j");
        const auto first = Lint(doc, nullptr, nullptr);
        const auto second = Lint(doc, nullptr, nullptr);
        const std::string text1 = edr::FormatRuleLintReport(first, false);
        const std::string text2 = edr::FormatRuleLintReport(second, false);
        const std::string json1 = edr::FormatRuleLintReport(first, true);
        const std::string json2 = edr::FormatRuleLintReport(second, true);
        LINT_CHECK(text1 == text2);
        LINT_CHECK(json1 == json2);
        LINT_CHECK(text1.find("rule-lint:") != std::string::npos);
        LINT_CHECK(json1.find("\"ruleCount\"") != std::string::npos);
        LINT_CHECK(json1.find("\"errorCount\"") != std::string::npos);
        LINT_CHECK(json1.find("\"warningCount\"") != std::string::npos);
        LINT_CHECK(json1.find("\"issues\"") != std::string::npos);
        LINT_CHECK(text1.find("band_leak") != std::string::npos);
        LINT_CHECK(text1.find("bad_enum") != std::string::npos);
    }

    std::fprintf(stderr, "[lint] all passed\n");
}
