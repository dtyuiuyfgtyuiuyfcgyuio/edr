#include "rule_engine.h"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <limits>
#include <unordered_set>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "json_lite.h"
#include "rule_lint.h"

namespace edr {

static std::regex CompileRuleRegex(const std::string& pattern,
                                   const std::string& ruleId) {
    std::string p = pattern;
    auto flags = std::regex_constants::ECMAScript;
    if (p.rfind("(?i)", 0) == 0) {
        p = p.substr(4);
        flags |= std::regex_constants::icase;
    }
    try {
        return std::regex(p, flags);
    } catch (const std::regex_error& e) {
        throw std::runtime_error("rule " + ruleId + ": bad regex '" +
                                 pattern + "': " + e.what());
    }
}

static std::string HexEncode(const unsigned char* bytes, size_t length) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        result.push_back(kHex[(bytes[i] >> 4) & 0x0f]);
        result.push_back(kHex[bytes[i] & 0x0f]);
    }
    return result;
}

bool RuleEngine::FingerprintRulesContents(const std::string& contents,
                                          std::string* fingerprint) {
    if (fingerprint == nullptr) return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<unsigned char> hashObject;
    std::array<unsigned char, 32> digest{};
    DWORD objectBytes = 0;
    DWORD hashBytes = 0;
    DWORD received = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0) {
        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&objectBytes),
                                   sizeof(objectBytes), &received, 0);
    }
    if (status >= 0) {
        status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                                   reinterpret_cast<PUCHAR>(&hashBytes),
                                   sizeof(hashBytes), &received, 0);
    }
    if (status >= 0 && hashBytes != digest.size()) status = STATUS_INVALID_PARAMETER;
    if (status >= 0 && objectBytes != 0) hashObject.resize(objectBytes);
    if (status >= 0) {
        status = BCryptCreateHash(algorithm, &hash, hashObject.data(),
                                  static_cast<ULONG>(hashObject.size()),
                                  nullptr, 0, 0);
    }
    for (size_t offset = 0; status >= 0 && offset < contents.size();) {
        const size_t remaining = contents.size() - offset;
        const size_t chunk = remaining > 64 * 1024
                                 ? static_cast<size_t>(64 * 1024)
                                 : remaining;
        status = BCryptHashData(
            hash, reinterpret_cast<PUCHAR>(
                      const_cast<char*>(contents.data() + offset)),
            static_cast<ULONG>(chunk), 0);
        offset += chunk;
    }
    if (status >= 0) {
        status = BCryptFinishHash(hash, digest.data(),
                                  static_cast<ULONG>(digest.size()), 0);
    }
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) return false;
    *fingerprint = HexEncode(digest.data(), digest.size());
    return true;
}

bool RuleEngine::EvalPredicate(const FieldPredicate& pred, const Event& ev) {
    auto it = ev.fields.find(pred.field);
    if (it == ev.fields.end()) {
        /* M3: missing field => every predicate on it is false. */
        return false;
    }
    const std::string& value = it->second;

    if (pred.hasEq && value != pred.eq) {
        return false;
    }
    if (pred.hasContains &&
        value.find(pred.contains) == std::string::npos) {
        return false;
    }
    if (pred.hasRegex && !std::regex_search(value, pred.re)) {
        return false;
    }
    if (pred.hasNotRegex && std::regex_search(value, pred.notRe)) {
        return false;
    }
    return true;
}

void RuleEngine::LoadFromFile(const std::string& path) {
    std::string contents;
    if (!ReadRulesSnapshot(path, &contents))
        throw std::runtime_error("cannot open rules file: " + path);
    std::vector<Rule> loaded = ParseRulesSnapshot(contents);
    uint64_t writeTime100ns = 0, size = 0;
    const bool haveStat = StatRulesFile(path, &writeTime100ns, &size);
    std::string fingerprint;
    const bool haveFingerprint =
        FingerprintRulesContents(contents, &fingerprint);
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_rules = std::move(loaded);
    m_rulesPath = path;
    m_haveSeenStat = haveStat;
    m_seenWriteTime100ns = writeTime100ns;
    m_seenSize = size;
    m_haveSeenFingerprint = haveFingerprint;
    m_seenFingerprint = haveFingerprint ? std::move(fingerprint) : std::string();
    m_reloadCount = 0;
}

bool RuleEngine::ReadRulesSnapshot(const std::string& path,
                                   std::string* contents) {
    if (contents == nullptr) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    if (in.bad()) return false;
    *contents = ss.str();
    return true;
}

std::vector<RuleEngine::Rule> RuleEngine::ParseRulesSnapshot(
        const std::string& contents) {
    RuleLintReport lint;
    std::string lintFatal;
    const bool lintParsed = LintRulesJson(contents, &lint, &lintFatal);
    if (lintParsed) {
        /* The standalone lint CLI treats non-house IDs as errors. RuleEngine
         * keeps its historical support for caller-defined non-empty IDs, so
         * runtime loading downgrades only this one policy finding. */
        for (RuleLintIssue& issue : lint.issues) {
            if (issue.code == "bad_id" && issue.severity == "error") {
                issue.severity = "warning";
                --lint.errorCount;
                ++lint.warningCount;
            }
        }
    }
    if (!lintParsed || lint.errorCount != 0) {
        throw std::runtime_error("rule lint rejected candidate:\n" +
                                 FormatRuleLintReport(lint, false));
    }
    for (const RuleLintIssue& issue : lint.issues) {
        if (issue.severity == "warning") {
            if (issue.ruleId.empty()) {
                std::fprintf(stderr, "[edr-rules] lint warning %s: %s\n",
                             issue.code.c_str(), issue.message.c_str());
            } else {
                std::fprintf(stderr,
                             "[edr-rules] lint warning %s [%s]: %s\n",
                             issue.code.c_str(), issue.ruleId.c_str(),
                             issue.message.c_str());
            }
        }
    }
    jsonlite::Value root;
    try {
        root = jsonlite::parse(contents);
    } catch (const jsonlite::ParseError& e) {
        throw std::runtime_error(std::string("rules JSON parse: ") + e.what());
    }

    const jsonlite::Value* rules = root.find("rules");
    if (rules == nullptr || rules->type != jsonlite::Type::Array) {
        throw std::runtime_error("rules file must contain a 'rules' array");
    }

    std::vector<Rule> loaded;
    std::unordered_set<std::string> seenIds;
    for (const jsonlite::Value& rv : rules->array) {
        if (rv.type != jsonlite::Type::Object) {
            throw std::runtime_error("rule entry is not an object");
        }
        Rule rule;
        rule.id = rv.find("id") ? rv.find("id")->asString() : "";
        rule.severity = rv.find("severity") ? rv.find("severity")->asString("low") : "low";
        rule.action = rv.find("action") ? rv.find("action")->asString("log") : "log";
        if (rule.id.empty()) {
            throw std::runtime_error("rule without id");
        }
        if (!seenIds.insert(rule.id).second) {
            throw std::runtime_error("duplicate rule id: " + rule.id);
        }
        if (rule.action == "block") {
            throw std::runtime_error("rule " + rule.id +
                ": action 'block' is not supported (log|alert|terminate|kill|delete_file only)");
        }
        if (rule.action != "log" && rule.action != "alert" &&
            rule.action != "terminate" && rule.action != "kill" &&
            rule.action != "delete_file") {
            throw std::runtime_error("rule " + rule.id +
                ": unknown action '" + rule.action + "'");
        }
        std::string cond = rv.find("condition")
            ? rv.find("condition")->asString("all") : "all";
        if (cond == "all") {
            rule.matchAll = true;
        } else if (cond == "any") {
            rule.matchAll = false;
        } else {
            throw std::runtime_error("rule " + rule.id +
                ": unknown condition '" + cond + "'");
        }

        const jsonlite::Value* match = rv.find("match");
        if (match == nullptr || match->type != jsonlite::Type::Object) {
            throw std::runtime_error("rule " + rule.id + ": missing 'match' object");
        }
        if (match->object.empty())
            throw std::runtime_error("rule " + rule.id + ": empty 'match' object");
        for (const auto& kv : match->object) {
            if (kv.second.type != jsonlite::Type::Object) {
                throw std::runtime_error("rule " + rule.id +
                    ": predicate for field '" + kv.first + "' must be an object");
            }
            FieldPredicate pred;
            pred.field = kv.first;
            bool any = false;
            if (const jsonlite::Value* v = kv.second.find("eq")) {
                pred.hasEq = true;
                constexpr double kMaxExactInteger = 9007199254740991.0;
                if (v->type == jsonlite::Type::Number && std::isfinite(v->number) &&
                    std::floor(v->number) == v->number &&
                    v->number >= -kMaxExactInteger && v->number <= kMaxExactInteger) {
                    pred.eq = std::to_string(static_cast<long long>(v->number));
                } else if (v->type == jsonlite::Type::String) {
                    pred.eq = v->str;
                } else {
                    throw std::runtime_error("rule " + rule.id +
                        ": 'eq' for field '" + kv.first +
                        "' must be a string or integer");
                }
                any = true;
            }
            if (const jsonlite::Value* v = kv.second.find("contains")) {
                if (v->type != jsonlite::Type::String || v->str.empty())
                    throw std::runtime_error("rule " + rule.id +
                        ": 'contains' for field '" + kv.first +
                        "' must be a non-empty string");
                pred.hasContains = true;
                pred.contains = v->str;
                any = true;
            }
            if (const jsonlite::Value* v = kv.second.find("regex")) {
                if (v->type != jsonlite::Type::String || v->str.empty())
                    throw std::runtime_error("rule " + rule.id +
                        ": 'regex' for field '" + kv.first +
                        "' must be a non-empty string");
                pred.hasRegex = true;
                pred.re = CompileRuleRegex(v->str, rule.id);
                any = true;
            }
            if (const jsonlite::Value* v = kv.second.find("not_regex")) {
                if (v->type != jsonlite::Type::String || v->str.empty())
                    throw std::runtime_error("rule " + rule.id +
                        ": 'not_regex' for field '" + kv.first +
                        "' must be a non-empty string");
                pred.hasNotRegex = true;
                pred.notRe = CompileRuleRegex(v->str, rule.id);
                any = true;
            }
            if (!any) {
                throw std::runtime_error("rule " + rule.id +
                    ": field '" + kv.first + "' has no predicate operator");
            }
            rule.predicates.push_back(std::move(pred));
        }
        if (const jsonlite::Value* v = rv.find("mitre_attack")) {
            if (v->type != jsonlite::Type::Array)
                throw std::runtime_error("rule " + rule.id +
                    ": 'mitre_attack' must be an array");
            for (const auto& item : v->array) {
                if (item.type != jsonlite::Type::String || item.str.empty())
                    throw std::runtime_error("rule " + rule.id +
                        ": 'mitre_attack' entries must be non-empty strings");
                rule.mitreAttack.push_back(item.str);
            }
        }
        if (const jsonlite::Value* v = rv.find("mitre_tactic")) {
            if (v->type != jsonlite::Type::Array)
                throw std::runtime_error("rule " + rule.id +
                    ": 'mitre_tactic' must be an array");
            for (const auto& item : v->array) {
                if (item.type != jsonlite::Type::String || item.str.empty())
                    throw std::runtime_error("rule " + rule.id +
                        ": 'mitre_tactic' entries must be non-empty strings");
                rule.mitreTactic.push_back(item.str);
            }
        }
        loaded.push_back(std::move(rule));
    }

    return loaded;
}

bool RuleEngine::StatRulesFile(const std::string& path,
                               uint64_t* writeTime100ns, uint64_t* size) {
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     path.data(), static_cast<int>(path.size()),
                                     nullptr, 0);
    if (needed <= 0) return false;
    std::wstring wide(static_cast<size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(),
                            static_cast<int>(path.size()), &wide[0],
                            needed) <= 0)
        return false;
    HANDLE handle = CreateFileW(wide.c_str(), FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE |
                                    FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    FILETIME writeTime{};
    LARGE_INTEGER fileSize{};
    BOOL ok = GetFileTime(handle, nullptr, nullptr, &writeTime);
    ok = ok && GetFileSizeEx(handle, &fileSize) != FALSE;
    CloseHandle(handle);
    if (!ok) return false;
    *writeTime100ns = (static_cast<uint64_t>(writeTime.dwHighDateTime) << 32) |
                      writeTime.dwLowDateTime;
    *size = static_cast<uint64_t>(fileSize.QuadPart);
    return true;
}

bool RuleEngine::MaybeReload() {
    std::string path;
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        path = m_rulesPath;
    }
    if (path.empty()) return false;

    uint64_t writeTime100ns = 0, size = 0;
    if (!StatRulesFile(path, &writeTime100ns, &size)) return false;
    std::string contents;
    if (!ReadRulesSnapshot(path, &contents)) return false;
    std::string fingerprint;
    if (!FingerprintRulesContents(contents, &fingerprint)) return false;
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        /* Unchanged since the last processed stat (loaded or failed). */
        if (m_haveSeenStat && m_seenWriteTime100ns == writeTime100ns &&
            m_seenSize == size && m_haveSeenFingerprint &&
            m_seenFingerprint == fingerprint)
            return false;
    }
    try {
        std::vector<Rule> loaded = ParseRulesSnapshot(contents);
        {
            std::unique_lock<std::shared_mutex> lock(m_mutex);
            m_rules = std::move(loaded);
            m_haveSeenStat = true;
            m_seenWriteTime100ns = writeTime100ns;
            m_seenSize = size;
            m_haveSeenFingerprint = true;
            m_seenFingerprint = std::move(fingerprint);
            ++m_reloadCount;
            std::fprintf(stderr, "[edr-rules] hot reload: %zu rules from %s\n",
                         m_rules.size(), path.c_str());
        }
        return true;
    } catch (const std::exception& e) {
        /* Keep serving the previous rule set; retry only after the file
         * changes again (stat bookkeeping below prevents per-poll log
         * spam). */
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_haveSeenStat = true;
        m_seenWriteTime100ns = writeTime100ns;
        m_seenSize = size;
        m_haveSeenFingerprint = true;
        m_seenFingerprint = std::move(fingerprint);
        std::fprintf(stderr,
                     "[edr-rules] hot reload failed, keeping previous "
                     "rules: %s\n",
                     e.what());
        return false;
    }
}

size_t RuleEngine::RuleCount() const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_rules.size();
}

size_t RuleEngine::ReloadCount() const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_reloadCount;
}

void RuleEngine::OnEvent(const Event& ev) {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    for (const Rule& rule : m_rules) {
        bool matched = rule.matchAll ? true : false;
        for (const FieldPredicate& pred : rule.predicates) {
            bool ok = EvalPredicate(pred, ev);
            if (rule.matchAll) {
                if (!ok) {
                    matched = false;
                    break;
                }
            } else if (ok) {
                matched = true;
                break;
            }
        }
        if (matched && m_callback) {
            Alert alert{rule.id, rule.severity, rule.action, &ev};
            alert.mitreAttack = rule.mitreAttack;
            alert.mitreTactic = rule.mitreTactic;
            m_callback(alert);
        }
    }
}

} // namespace edr
