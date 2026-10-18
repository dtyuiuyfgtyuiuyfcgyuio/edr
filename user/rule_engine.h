/*
 * rule_engine.h - Custom JSON rule subset (NOT Sigma-compatible).
 *
 * Rule schema:
 *   {
 *     "id": "EDR-001",
 *     "severity": "high",
 *     "action": "alert",            // "log" | "alert" | "terminate"; "block" is an error
 *     "condition": "all",           // "all" (default) | "any"
 *     "mitre_attack": ["T1059.001"], // optional ATT&CK technique IDs
 *     "mitre_tactic": ["Execution"], // optional ATT&CK tactic names
 *     "match": {
 *       "image":        { "regex": "(?i)powershell(\\.exe)?$" },
 *       "command_line": { "contains": "-enc" },
 *       "type":         { "eq": "REG_WRITE" },
 *       "dst_port":     { "not_regex": "^(1|2)$" }
 *     }
 *   }
 *
 * Predicate operators per field: eq | contains | regex | not_regex.
 * Multiple operators on one field are ANDed. Fields are combined per
 * "condition". A leading "(?i)" in a regex is translated to
 * std::regex_constants::icase.
 *
 * Missing-field semantics (M3): if the event lacks a field referenced by a
 * rule, ALL predicates for that field evaluate to false. Under
 * condition=all the rule therefore cannot match.
 */
#ifndef EDR_RULE_ENGINE_H
#define EDR_RULE_ENGINE_H

#include <functional>
#include <regex>
#include <shared_mutex>
#include <string>
#include <vector>

#include "event_bus.h"

namespace edr {

struct Alert {
    std::string ruleId;
    std::string severity;
    std::string action; /* "log", "alert", "terminate", "kill" or "delete_file" */
    const Event* event; /* valid only during dispatch */
    std::vector<std::string> mitreAttack;
    std::vector<std::string> mitreTactic;
};

class RuleEngine : public ISink {
public:
    using AlertCallback = std::function<void(const Alert&)>;

    /* Throws std::runtime_error on a lint error or parse failure (bad JSON,
     * unknown action, bad regex, ...). Runtime preserves non-empty custom IDs
     * by reporting lint bad_id as a warning. */
    void LoadFromFile(const std::string& path);

    /* Hot reload: stats the rules file and reloads it when the mtime, size,
     * or content fingerprint changed since the last processed load. A lint or
     * parse failure keeps the previous rule set and is retried only after the
     * file changes again. Thread-safe: may be called from a maintenance
     * thread while OnEvent runs on the consumer thread. Returns true when
     * rules were swapped. */
    bool MaybeReload();

    void SetAlertCallback(AlertCallback cb) { m_callback = std::move(cb); }

    /* ISink: evaluate an event against all rules. Target < 1ms per event. */
    void OnEvent(const Event& ev) override;

    size_t RuleCount() const;
    size_t ReloadCount() const;

private:
    struct FieldPredicate {
        std::string field;
        bool hasEq = false;
        std::string eq;
        bool hasContains = false;
        std::string contains;
        bool hasRegex = false;
        std::regex re;
        bool hasNotRegex = false;
        std::regex notRe;
    };
    struct Rule {
        std::string id;
        std::string severity;
        std::string action;
        bool matchAll = true; /* condition "all" vs "any" */
        std::vector<std::string> mitreAttack;
        std::vector<std::string> mitreTactic;
        std::vector<FieldPredicate> predicates;
    };

    /* Parses and compiles the rules file; throws std::runtime_error. */
    static std::vector<Rule> ParseRulesSnapshot(const std::string& contents);
    static bool ReadRulesSnapshot(const std::string& path,
                                  std::string* contents);
    static bool StatRulesFile(const std::string& path,
                              uint64_t* writeTime100ns, uint64_t* size);
    static bool FingerprintRulesContents(const std::string& contents,
                                         std::string* fingerprint);
    static bool EvalPredicate(const FieldPredicate& pred, const Event& ev);

    mutable std::shared_mutex m_mutex;
    std::vector<Rule> m_rules;
    AlertCallback m_callback;
    /* Hot-reload bookkeeping (guarded by m_mutex). */
    std::string m_rulesPath;
    bool m_haveSeenStat = false;
    uint64_t m_seenWriteTime100ns = 0;
    uint64_t m_seenSize = 0;
    bool m_haveSeenFingerprint = false;
    std::string m_seenFingerprint;
    size_t m_reloadCount = 0;
};

} // namespace edr

#endif /* EDR_RULE_ENGINE_H */
