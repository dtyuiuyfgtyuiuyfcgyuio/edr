/*
 * rule_lint.cpp - Static validator for rules/rules.json (read-only).
 *
 * Design notes
 * ------------
 * - Reuses the repository's own JSON parser (user/json_lite.h); no third-party
 *   dependency is introduced.
 * - Never throws: std::regex_error is caught at the point of construction and
 *   surfaced as a "bad_regex" issue. Callers get failures through the return
 *   value and the `fatal` out-parameter.
 * - Idempotent and deterministic: identical input yields byte-identical output
 *   (issues are stable-sorted by ruleId, then by code).
 * - Each candidate regex is compiled exactly once per predicate and then
 *   reused for the whole 0..100 score sweep.
 */
#include "rule_lint.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <utility>

#include "json_lite.h"

namespace edr {
namespace {

const char* const kSeverities[] = {"critical", "high", "medium", "low"};
const char* const kActions[] = {"alert", "terminate", "log", "kill",
                                "delete_file"};
const char* const kConditions[] = {"all", "any"};

template <size_t N>
bool ContainsOneOf(const char* const (&values)[N], const std::string& v) {
    for (size_t i = 0; i < N; ++i) {
        if (v == values[i]) return true;
    }
    return false;
}

void AddIssue(RuleLintReport* out, const char* severity, const char* code,
              const std::string& ruleId, const std::string& message) {
    RuleLintIssue issue;
    issue.severity = severity;
    issue.code = code;
    issue.ruleId = ruleId;
    issue.message = message;
    out->issues.push_back(std::move(issue));
}

/* Stable-sort issues by (ruleId, code) and recount severities. */
void Finalize(RuleLintReport* out) {
    std::stable_sort(out->issues.begin(), out->issues.end(),
                     [](const RuleLintIssue& a, const RuleLintIssue& b) {
                         if (a.ruleId != b.ruleId) return a.ruleId < b.ruleId;
                         return a.code < b.code;
                     });
    out->errorCount = 0;
    out->warningCount = 0;
    for (const RuleLintIssue& issue : out->issues) {
        if (issue.severity == "error") {
            ++out->errorCount;
        } else if (issue.severity == "warning") {
            ++out->warningCount;
        }
    }
}

/* Compile a rule regex the same way rule_engine.cpp does: a leading "(?i)"
 * selects case-insensitive matching and is stripped before compilation.
 * Returns false (and fills *err) instead of throwing. */
bool CompileLintRegex(const std::string& pattern, std::regex* out,
                      std::string* err) {
    std::string p = pattern;
    auto flags = std::regex_constants::ECMAScript;
    if (p.rfind("(?i)", 0) == 0) {
        p = p.substr(4);
        flags |= std::regex_constants::icase;
    }
    try {
        *out = std::regex(p, flags);
        return true;
    } catch (const std::regex_error& e) {
        if (err != nullptr) *err = e.what();
        return false;
    }
}

struct BandProbe {
    bool anyHit = false;
    bool hitLeak = false; /* accepted set intersects 50..54 */
    int lowest = -1;      /* lowest accepted value in 0..100 */
};

/* RuleEngine ANDs all operators on a field: eq compares the full string,
 * contains searches a substring, regex requires a search hit, and not_regex
 * requires no search hit. Probe that combined accepted set. */
BandProbe ProbeScoreBand(const std::regex* regex,
                         const std::regex* notRegex,
                         const std::string* equality,
                         const std::string* contains) {
    BandProbe probe;
    for (int score = 0; score <= 100; ++score) {
        const std::string value = std::to_string(score);
        if (equality != nullptr && value != *equality) continue;
        if (contains != nullptr && value.find(*contains) == std::string::npos)
            continue;
        if (regex != nullptr && !std::regex_search(value, *regex)) continue;
        if (notRegex != nullptr && std::regex_search(value, *notRegex))
            continue;
        if (!probe.anyHit || score < probe.lowest) probe.lowest = score;
        probe.anyHit = true;
        if (score >= 50 && score <= 54) probe.hitLeak = true;
    }
    return probe;
}

bool IsScoreField(const std::string& field) {
    static const std::string kSuffix = "_score";
    return field == "score" ||
           (field.size() >= kSuffix.size() &&
            field.compare(field.size() - kSuffix.size(), kSuffix.size(),
                          kSuffix) == 0);
}

/* A 50+ floor is only honoured when the author documented it in the rule's
 * comments. The matched-set lower bound cannot be used as the signal on its
 * own: the buggy `^(?:[5-9][0-9]|100)$` also has a lower bound of exactly 50,
 * so treating "lowest == 50" as intentional would wave the defect through. */
bool Documents50Floor(const jsonlite::Value& rule) {
    static const char* const kCommentKeys[] = {"comments", "comment"};
    for (const char* key : kCommentKeys) {
        const jsonlite::Value* v = rule.find(key);
        if (v != nullptr && v->type == jsonlite::Type::String &&
            v->str.find("50") != std::string::npos) {
            return true;
        }
    }
    return false;
}

const jsonlite::Value* FindRulesArray(const jsonlite::Value& root) {
    if (root.type == jsonlite::Type::Array) return &root;
    if (root.type == jsonlite::Type::Object) {
        const jsonlite::Value* rules = root.find("rules");
        if (rules != nullptr && rules->type == jsonlite::Type::Array) {
            return rules;
        }
    }
    return nullptr;
}

} // namespace

bool LintRulesJson(const std::string& json, RuleLintReport* out,
                   std::string* fatal) {
    if (out == nullptr) {
        if (fatal != nullptr) *fatal = "null lint report";
        return false;
    }
    *out = RuleLintReport();

    jsonlite::Value root;
    try {
        root = jsonlite::parse(json);
    } catch (const jsonlite::ParseError& e) {
        const std::string msg = std::string("rules JSON parse: ") + e.what();
        if (fatal != nullptr) *fatal = msg;
        AddIssue(out, "error", "fatal", "", msg);
        Finalize(out);
        return false;
    } catch (const std::exception& e) {
        const std::string msg = std::string("rules JSON parse: ") + e.what();
        if (fatal != nullptr) *fatal = msg;
        AddIssue(out, "error", "fatal", "", msg);
        Finalize(out);
        return false;
    }

    const jsonlite::Value* rules = FindRulesArray(root);
    if (rules == nullptr) {
        const std::string msg =
            "rules file must contain a 'rules' array (or be a top-level array)";
        if (fatal != nullptr) *fatal = msg;
        AddIssue(out, "error", "fatal", "", msg);
        Finalize(out);
        return false;
    }

    /* Compiled once for the whole document. */
    std::regex idRe;
    std::regex mitreRe;
    std::string compileErr;
    CompileLintRegex("^(?:EDR|SF)-\\d{3}$", &idRe, &compileErr);
    CompileLintRegex("^T\\d{4}(\\.\\d{3})?$", &mitreRe, &compileErr);

    out->ruleCount = rules->array.size();
    std::map<std::string, size_t> seenIds; /* id -> first 1-based index */
    size_t index = 0;

    for (const jsonlite::Value& rule : rules->array) {
        ++index;
        if (rule.type != jsonlite::Type::Object) {
            AddIssue(out, "error", "bad_id",
                     "rule #" + std::to_string(index),
                     "rule entry is not a JSON object");
            continue;
        }

        const jsonlite::Value* idValue = rule.find("id");
        const std::string ruleId =
            idValue != nullptr ? idValue->asString() : std::string();

        /* --- id: format + uniqueness ------------------------------------- */
        if (ruleId == "EDR-003-KILL" || ruleId == "EDR-314B") {
            AddIssue(out, "warning", "legacy_id", ruleId,
                     "historical rule id retained for compatibility");
        } else if (!std::regex_match(ruleId, idRe)) {
            AddIssue(out, "error", "bad_id", ruleId,
                     "id must match ^EDR-\\d{3}$ or ^SF-\\d{3}$");
        }
        if (!ruleId.empty()) {
            auto inserted = seenIds.emplace(ruleId, index);
            if (!inserted.second) {
                AddIssue(out, "error", "dup_id", ruleId,
                         "duplicate id, first defined at rule index " +
                             std::to_string(inserted.first->second));
            }
        }

        /* --- enums -------------------------------------------------------- */
        const std::string severity =
            rule.find("severity") ? rule.find("severity")->asString("low")
                                  : "low"; /* engine default */
        if (!ContainsOneOf(kSeverities, severity)) {
            AddIssue(out, "error", "bad_enum", ruleId,
                     "severity '" + severity +
                         "' not in {critical,high,medium,low}");
        }
        const std::string action =
            rule.find("action") ? rule.find("action")->asString("log") : "log";
        if (!ContainsOneOf(kActions, action)) {
            AddIssue(out, "error", "bad_enum", ruleId,
                     "action '" + action + "' not in {alert,terminate,log," +
                         "kill,delete_file}");
        }
        const std::string condition = rule.find("condition")
                                          ? rule.find("condition")->asString("all")
                                          : "all";
        if (!ContainsOneOf(kConditions, condition)) {
            AddIssue(out, "error", "bad_enum", ruleId,
                     "condition '" + condition + "' not in {all,any}");
        }
        const bool anyCondition = (condition == "any");

        /* --- match object + per-predicate checks -------------------------- */
        const jsonlite::Value* match = rule.find("match");
        const bool matchOk = (match != nullptr &&
                              match->type == jsonlite::Type::Object &&
                              !match->object.empty());
        if (!matchOk) {
            AddIssue(out, "error", "empty_match", ruleId,
                     "'match' is missing or an empty object");
        } else {
            const bool exempt50 = Documents50Floor(rule);
            for (const auto& kv : match->object) {
                const std::string& field = kv.first;
                const jsonlite::Value& pred = kv.second;
                if (pred.type != jsonlite::Type::Object) {
                    /* The engine rejects this shape; not part of the WS-C
                     * code set, so it is left to the loader. */
                    continue;
                }

                if (anyCondition && field == "type" &&
                    pred.find("eq") != nullptr) {
                    AddIssue(out, "warning", "over_match", ruleId,
                             "condition 'any' with an 'eq' on 'type' matches "
                             "every event of that type");
                }

                std::regex compiledRegex;
                std::regex compiledNotRegex;
                bool hasRegex = false;
                bool hasNotRegex = false;
                bool regexError = false;
                std::string equality;
                std::string contains;
                bool hasEquality = false;
                bool hasContains = false;
                if (const jsonlite::Value* eq = pred.find("eq")) {
                    if (eq->type == jsonlite::Type::String) {
                        equality = eq->str;
                        hasEquality = true;
                    } else if (eq->type == jsonlite::Type::Number &&
                               std::isfinite(eq->number) &&
                               std::floor(eq->number) == eq->number &&
                               eq->number >= -9007199254740991.0 &&
                               eq->number <= 9007199254740991.0) {
                        equality = std::to_string(
                            static_cast<long long>(eq->number));
                        hasEquality = true;
                    }
                }
                if (const jsonlite::Value* value = pred.find("contains")) {
                    if (value->type == jsonlite::Type::String &&
                        !value->str.empty()) {
                        contains = value->str;
                        hasContains = true;
                    }
                }
                for (const char* op : {"regex", "not_regex"}) {
                    const jsonlite::Value* v = pred.find(op);
                    if (v == nullptr) continue;
                    const std::string opName = op;
                    if (v->type != jsonlite::Type::String || v->str.empty()) {
                        AddIssue(out, "error", "bad_regex", ruleId,
                                 "'" + opName + "' on field '" + field +
                                     "' must be a non-empty string");
                        regexError = true;
                        continue; /* one bad predicate must not abort the rule */
                    }
                    std::string regexErr;
                    std::regex& compiled = opName == "regex"
                        ? compiledRegex : compiledNotRegex;
                    if (!CompileLintRegex(v->str, &compiled, &regexErr)) {
                        AddIssue(out, "error", "bad_regex", ruleId,
                                 "'" + opName + "' on field '" + field +
                                     "' does not compile: " + regexErr);
                        regexError = true;
                        continue;
                    }
                    if (opName == "regex") hasRegex = true;
                    else hasNotRegex = true;
                }
                /* Non-score fields retain regex type/compile validation, but
                 * the numeric score-domain policy does not apply to them. */
                if (IsScoreField(field) && !regexError &&
                    (hasRegex || hasNotRegex)) {
                    const BandProbe probe = ProbeScoreBand(
                        hasRegex ? &compiledRegex : nullptr,
                        hasNotRegex ? &compiledNotRegex : nullptr,
                        hasEquality ? &equality : nullptr,
                        hasContains ? &contains : nullptr);
                    if (probe.hitLeak && !exempt50) {
                        AddIssue(out, "warning", "band_leak", ruleId,
                                 "regex predicates on field '" + field +
                                     "' accept scores 50..54 (lowest accepted " +
                                     std::to_string(probe.lowest) +
                                     "); expected ^(?:5[5-9]|[6-9][0-9]|100)$ "
                                     "unless a documented 50+ floor is "
                                     "intended");
                    }
                }
            }
        }

        /* --- MITRE ATT&CK mapping ---------------------------------------- */
        if (const jsonlite::Value* attack = rule.find("mitre_attack")) {
            if (attack->type != jsonlite::Type::Array) {
                AddIssue(out, "warning", "bad_mitre", ruleId,
                         "'mitre_attack' must be an array");
            } else {
                for (const jsonlite::Value& item : attack->array) {
                    const std::string tech =
                        item.type == jsonlite::Type::String ? item.str
                                                            : std::string();
                    if (item.type != jsonlite::Type::String ||
                        !std::regex_match(tech, mitreRe)) {
                        AddIssue(out, "warning", "bad_mitre", ruleId,
                                 "mitre_attack entry '" +
                                     (item.type == jsonlite::Type::String
                                          ? tech
                                          : std::string("<non-string>")) +
                                     "' does not match ^T\\d{4}(\\.\\d{3})?$");
                    }
                }
            }
        }
        const jsonlite::Value* tactic = rule.find("mitre_tactic");
        if (tactic == nullptr || tactic->type != jsonlite::Type::Array ||
            tactic->array.empty()) {
            AddIssue(out, "warning", "bad_mitre", ruleId,
                     "'mitre_tactic' is missing or an empty array");
        }
    }

    Finalize(out);
    return true;
}

bool LintRulesFile(const std::string& path, RuleLintReport* out,
                   std::string* fatal) {
    if (out == nullptr) {
        if (fatal != nullptr) *fatal = "null lint report";
        return false;
    }
    *out = RuleLintReport();

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        const std::string msg = "cannot open rules file: " + path;
        if (fatal != nullptr) *fatal = msg;
        AddIssue(out, "error", "fatal", "", msg);
        Finalize(out);
        return false;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return LintRulesJson(buffer.str(), out, fatal);
}

std::string FormatRuleLintReport(const RuleLintReport& r, bool json) {
    std::ostringstream out;
    if (json) {
        out << "{\n";
        out << "  \"ruleCount\": " << r.ruleCount << ",\n";
        out << "  \"errorCount\": " << r.errorCount << ",\n";
        out << "  \"warningCount\": " << r.warningCount << ",\n";
        out << "  \"issues\": [";
        for (size_t i = 0; i < r.issues.size(); ++i) {
            const RuleLintIssue& issue = r.issues[i];
            out << (i == 0 ? "\n" : ",\n");
            out << "    {\"severity\": \"" << jsonlite::escape(issue.severity)
                << "\", \"code\": \"" << jsonlite::escape(issue.code)
                << "\", \"ruleId\": \"" << jsonlite::escape(issue.ruleId)
                << "\", \"message\": \"" << jsonlite::escape(issue.message)
                << "\"}";
        }
        if (!r.issues.empty()) out << "\n  ";
        out << "]\n}\n";
        return out.str();
    }

    out << "rule-lint: " << r.ruleCount << " rule(s), " << r.errorCount
        << " error(s), " << r.warningCount << " warning(s)\n";
    for (const RuleLintIssue& issue : r.issues) {
        out << (issue.severity == "error" ? "ERROR  " : "WARN   ");
        out << issue.code;
        if (!issue.ruleId.empty()) out << " [" << issue.ruleId << "]";
        out << ": " << issue.message << "\n";
    }
    return out.str();
}

} // namespace edr
