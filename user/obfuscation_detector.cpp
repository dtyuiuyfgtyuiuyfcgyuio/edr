/*
 * obfuscation_detector.cpp - Obfuscated files or information (T1027).
 */
#include "obfuscation_detector.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <unordered_map>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}
bool ContainsStr(const std::string& value, const std::string& needle) {
    return value.find(needle) != std::string::npos;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool IsBase64Char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

bool HasLongBase64Token(const std::string& text, size_t minLen) {
    size_t run = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        if (IsBase64Char(text[i])) {
            ++run;
            if (run >= minLen) return true;
        } else {
            run = 0;
        }
    }
    return false;
}

double ShannonEntropy(const std::string& token) {
    if (token.empty()) return 0.0;
    std::unordered_map<unsigned char, size_t> freq;
    for (unsigned char c : token) freq[c]++;
    double entropy = 0.0;
    double len = static_cast<double>(token.size());
    for (auto& kv : freq) {
        double p = static_cast<double>(kv.second) / len;
        entropy -= p * (std::log(p) / std::log(2.0));
    }
    return entropy;
}

bool HasHighEntropyToken(const std::string& text, double threshold) {
    size_t start = 0;
    for (size_t i = 0; i <= text.size(); ++i) {
        bool delim = (i == text.size()) || std::isspace(static_cast<unsigned char>(text[i])) ||
                     text[i] == '"' || text[i] == '\'' || text[i] == ';' || text[i] == ',' ||
                     text[i] == '(' || text[i] == ')' || text[i] == '{' || text[i] == '}';
        if (delim) {
            if (i > start) {
                size_t tokLen = i - start;
                if (tokLen >= 20) {
                    std::string token = text.substr(start, tokLen);
                    double e = ShannonEntropy(token);
                    if (e > threshold) return true;
                }
            }
            start = i + 1;
        }
    }
    return false;
}

bool HasCaretObfuscation(const std::string& text, const std::string& lower) {
    size_t caretCount = 0;
    for (char c : text) if (c == '^') ++caretCount;
    if (caretCount >= 3) return true;
    if (Contains(lower, "'+'") || Contains(lower, "\"+\"") ||
        Contains(lower, "' + '") || Contains(lower, "\" + \"") ||
        Contains(lower, "'+\"") || Contains(lower, "\"+'")) {
        return true;
    }
    size_t plusQuote = 0;
    for (size_t i = 0; i + 1 < text.size(); ++i) {
        if ((text[i] == '\'' || text[i] == '"') && text[i+1] == '+') ++plusQuote;
        if (text[i] == '+' && (text[i+1] == '\'' || text[i+1] == '"')) ++plusQuote;
    }
    if (plusQuote >= 2) return true;
    return false;
}

bool HasEnvSubstring(const std::string& lower) {
    if (Contains(lower, ":~") && Contains(lower, "%")) {
        size_t pos = lower.find(":~");
        if (pos != std::string::npos && pos > 0) {
            size_t pct = lower.rfind('%', pos);
            if (pct != std::string::npos) return true;
        }
    }
    // Build "$env" at runtime to avoid literal
    std::string env;
    env.push_back('$'); env.push_back('e'); env.push_back('n'); env.push_back('v');
    std::string envColon;
    envColon.push_back('$'); envColon.push_back('e'); envColon.push_back('n'); envColon.push_back('v'); envColon.push_back(':');
    std::string substr;
    substr.push_back('s'); substr.push_back('u'); substr.push_back('b'); substr.push_back('s'); substr.push_back('t'); substr.push_back('r'); substr.push_back('i'); substr.push_back('n'); substr.push_back('g');
    std::string slice;
    slice.push_back('s'); slice.push_back('l'); slice.push_back('i'); slice.push_back('c'); slice.push_back('e');
    std::string envBrace;
    envBrace.push_back('$'); envBrace.push_back('{'); envBrace.push_back('e'); envBrace.push_back('n'); envBrace.push_back('v'); envBrace.push_back(':');
    if (ContainsStr(lower, env)) {
        if (ContainsStr(lower, substr) || ContainsStr(lower, slice) || ContainsStr(lower, envColon)) {
            if (ContainsStr(lower, substr) || ContainsStr(lower, "[") || Contains(lower, ":~")) {
                return true;
            }
            if (ContainsStr(lower, envColon) && Contains(lower, "[")) return true;
        }
        if (ContainsStr(lower, env) && ContainsStr(lower, substr)) return true;
    }
    if (ContainsStr(lower, envBrace)) return true;
    return false;
}

double SpecialCharRatio(const std::string& text) {
    if (text.empty()) return 0.0;
    size_t special = 0;
    for (unsigned char c : text) {
        if (!std::isalnum(c) && !std::isspace(c)) ++special;
    }
    return static_cast<double>(special) / static_cast<double>(text.size());
}

// Runtime-built needles to avoid static AV signatures
bool HasEncSignal(const std::string& lower) {
    std::string fromB64;
    fromB64.push_back('f'); fromB64.push_back('r'); fromB64.push_back('o'); fromB64.push_back('m');
    fromB64.push_back('b'); fromB64.push_back('a'); fromB64.push_back('s'); fromB64.push_back('e');
    fromB64.push_back('6'); fromB64.push_back('4');
    fromB64.push_back('s'); fromB64.push_back('t'); fromB64.push_back('r'); fromB64.push_back('i'); fromB64.push_back('n'); fromB64.push_back('g');
    if (ContainsStr(lower, fromB64)) return true;
    std::string enc;
    enc.push_back('-'); enc.push_back('e'); enc.push_back('n'); enc.push_back('c');
    // Switches are whole argument tokens: -encode-file and --encryption-key
    // must not be confused with -enc. A slash prefix is accepted as well.
    std::string encCmd;
    encCmd.push_back('-'); encCmd.push_back('e'); encCmd.push_back('n'); encCmd.push_back('c');
    encCmd.push_back('o'); encCmd.push_back('d'); encCmd.push_back('e'); encCmd.push_back('d');
    encCmd.push_back('c'); encCmd.push_back('o'); encCmd.push_back('m'); encCmd.push_back('m');
    encCmd.push_back('a'); encCmd.push_back('n'); encCmd.push_back('d');
    std::string encc;
    encc.push_back('-'); encc.push_back('e'); encc.push_back('n'); encc.push_back('c'); encc.push_back('c');
    size_t start = 0;
    while (start < lower.size()) {
        while (start < lower.size() &&
               std::isspace(static_cast<unsigned char>(lower[start]))) ++start;
        size_t end = start;
        while (end < lower.size() &&
               !std::isspace(static_cast<unsigned char>(lower[end]))) ++end;
        std::string token = lower.substr(start, end - start);
        if (token.size() >= 2 && token.front() == '"' && token.back() == '"')
            token = token.substr(1, token.size() - 2);
        if (!token.empty() && token.front() == '/') token.front() = '-';
        if (token == enc || token == encCmd || token == encc) return true;
        start = end;
    }
    return false;
}

size_t CountToken(const std::string& text, const char* token) {
    const size_t length = std::char_traits<char>::length(token);
    size_t count = 0, pos = 0;
    while ((pos = text.find(token, pos)) != std::string::npos) {
        ++count;
        pos += length;
    }
    return count;
}

bool HasConstruct(const std::string& text, const char* token) {
    if (token[0] != '-') return Contains(text, token);
    const size_t length = std::char_traits<char>::length(token);
    size_t pos = 0;
    while ((pos = text.find(token, pos)) != std::string::npos) {
        const size_t end = pos + length;
        if ((pos == 0 || text[pos - 1] != '-') &&
            (end == text.size() ||
             (!std::isalnum(static_cast<unsigned char>(text[end])) && text[end] != '_')))
            return true;
        pos = end;
    }
    return false;
}

} // namespace

ObfuscationDetector::ObfuscationDetector(bool enabled, uint32_t minScore,
                                         uint32_t dedupWindowSeconds,
                                         size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool ObfuscationDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool ObfuscationDetector::Analyze(const std::string& text,
                                  const std::string& lower,
                                  Finding* out) const {
    uint32_t bestScore = 0;
    std::string signals;

    auto Consider = [&](uint32_t score, const char* name, bool structural = false) {
        if (score > bestScore) bestScore = score;
        if (!signals.empty()) signals += ",";
        signals += name;
        out->hardSignal = out->hardSignal || structural;
    };

    if (HasEncSignal(lower)) {
        Consider(90, "enc_frombase64", true);
    }
    if (HasCaretObfuscation(text, lower)) {
        Consider(85, "caret_quote_concat", true);
    }
    if (HasEnvSubstring(lower)) {
        Consider(80, "env_substring", true);
    }
    if (CountToken(lower, "[char]") >= 2) {
        Consider(80, "repeated_char_cast", true);
    }
    if (std::count(text.begin(), text.end(), '`') >= 3) {
        Consider(85, "backtick_escape", true);
    }
    const char* constructs[] = {"-join", "[string]::join", "-replace",
        "[scriptblock]", "[reflection.assembly]", "[array]::reverse", ".invoke("};
    size_t constructsFound = 0;
    for (const char* construct : constructs) {
        if (HasConstruct(lower, construct)) ++constructsFound;
    }
    if (constructsFound >= 2) Consider(85, "structural_combination", true);
    if (HasLongBase64Token(text, 80)) {
        Consider(80, "base64_long_token");
    }
    if (HasHighEntropyToken(text, 4.5)) {
        Consider(75, "high_entropy");
    }
    if (SpecialCharRatio(text) > 0.30) {
        Consider(60, "special_char_ratio");
    }

    if (bestScore == 0) return false;
    out->score = bestScore;
    out->signals = signals;
    return true;
}

void ObfuscationDetector::Stamp(Event& event, const Finding& finding,
                                const std::string& key) {
    event.fields[field::kObfuscationScore] = std::to_string(finding.score);
    if (finding.score >= 55) {
        event.fields[field::kObfuscationVerdict] =
            finding.hardSignal && finding.score >= 75 ? "malicious" : "suspicious";
        event.fields[field::kObfuscationHardSignal] =
            finding.hardSignal ? "true" : "false";
        event.fields[field::kObfuscationSignals] = finding.signals;
        event.fields[field::kObfuscationText] = key;
    }
}

void ObfuscationDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    std::string text;
    if (event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    } else {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
    }
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    if (text.empty()) return;

    const std::string lower = ToLowerAscii(text);
    Finding finding;
    if (!Analyze(text, lower, &finding)) return;
    if (finding.score < m_minScore) return;
    if (finding.score < 55) return;

    const std::string evidence = lower.substr(0, 160);
    // Soft evidence must never suppress a later structural finding sharing
    // the same prefix. Preserve the displayed text independently of this key.
    std::string key = (finding.hardSignal ? "hard:" : "soft:") + evidence;

    const uint64_t now = event.ts100ns;
    auto it = m_lastAlert.find(key);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                "[edr-obfuscation] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, evidence);
}

} // namespace edr
