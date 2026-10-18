/*
 * rule_lint.h - Static validator for the custom JSON rule subset
 * (rules/rules.json). Read-only: it never mutates the rule file and never
 * performs I/O beyond reading the given path.
 *
 * The checks mirror defects that actually shipped in this repository
 * (see CLAUDE.md "安全日志检测器族约定 (2026-08-21)"):
 *   - the score-band leak `^(?:[5-9][0-9]|100)$` admitting 50..54 while the
 *     rule comments claimed "55+ alerted" (fixed 2026-08-27);
 *   - `condition:"any"` combined with an `eq` on `type`, which makes the rule
 *     fire on every event of that type (EDR-103/105, 2026-08-06).
 */
#ifndef EDR_RULE_LINT_H
#define EDR_RULE_LINT_H

#include <cstddef>
#include <string>
#include <vector>

namespace edr {

/* One finding. severity is "error" or "warning"; code is one of the stable
 * identifiers documented in the WS-C contract (dup_id, bad_id, bad_enum,
 * empty_match, bad_regex, band_leak, over_match, bad_mitre, plus "fatal" for
 * an unreadable file / unparsable JSON). */
struct RuleLintIssue {
    std::string severity;
    std::string code;
    std::string ruleId;
    std::string message;
};

struct RuleLintReport {
    size_t ruleCount = 0;
    size_t errorCount = 0;
    size_t warningCount = 0;
    std::vector<RuleLintIssue> issues;
};

/* Load and validate the rule file at `path`.
 *
 * Returns false only when the file cannot be read or the JSON is invalid; in
 * that case an error-severity issue (code "fatal") is appended and *fatal
 * carries the human-readable reason. Detection findings alone do NOT make the
 * return value false - inspect errorCount instead.
 *
 * `out` must be non-null; `fatal` may be null. */
bool LintRulesFile(const std::string& path, RuleLintReport* out,
                   std::string* fatal);

/* Same validation over an in-memory JSON document. Exposed so the unit tests
 * can exercise the checks against self-contained snippets rather than the
 * repository rule file (whose contents may change independently). */
bool LintRulesJson(const std::string& json, RuleLintReport* out,
                   std::string* fatal);

/* Human-readable rendering (json == false) or a stable JSON document
 * (json == true). Output is deterministic for identical input. */
std::string FormatRuleLintReport(const RuleLintReport& r, bool json);

} // namespace edr

#endif /* EDR_RULE_LINT_H */
