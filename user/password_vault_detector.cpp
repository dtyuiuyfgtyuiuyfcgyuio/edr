/*
 * password_vault_detector.cpp - See password_vault_detector.h.
 */
#include "password_vault_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 const char* const needles[], size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (Contains(value, needles[i])) return true;
    }
    return false;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* Word-bounded phrase match: the needle must start the text or follow a
 * command/token boundary. "dir desktop readme.txt" must NOT match the
 * "op read" needle (preceded by 'k'), while " op item list" and
 * "\"op read\"" do match. */
bool HasBounded(const std::string& lower, const std::string& needle) {
    for (size_t pos = lower.find(needle); pos != std::string::npos;
         pos = lower.find(needle, pos + 1)) {
        if (pos == 0) return true;
        const char prev = lower[pos - 1];
        if (prev == ' ' || prev == '\t' || prev == '"' || prev == '\'' ||
            prev == '\\' || prev == '/' || prev == '=' || prev == '-')
            return true;
    }
    return false;
}

/* Word-bounded variant of ContainsAny: every needle must respect the
 * token-boundary rule above (plain substring matching here made
 * "dir desktop readme.txt" match the "op read" phrase). */
bool HasAnyBounded(const std::string& lower,
                   const char* const needles[], size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (HasBounded(lower, needles[i])) return true;
    }
    return false;
}

/* Verbs that export / copy / archive / convert a vault database out of
 * place (the "staging" half of the theft chain). The dash form "export-"
 * deliberately avoids the keepassxc-cli "export" subcommand, which owns
 * its own 60-70 tier. */
const char* const kVaultExportVerbs[] = {
    "export-", "copy-item", "copy ", "move-item",
    "compress-archive", "convertto-securestring",
    "convertfrom-securestring",
};

/* 1Password CLI bulk-read shapes (word-bounded so "desktop readme" or
 * "swap items" never match). */
const char* const kOpCliPhrases[] = {
    "op item", "op read", "op export", "op account",
};

/* Subcommand phrases after a word-bounded op.exe image name. */
const char* const kOpExeSubcommands[] = {
    "item list", "item get ", "item export", " read ", " export ",
    "account list",
};

/* --- keepassxc export judgment (subcommand level) ----------------------
 *
 * The old "export appears anywhere in the text" test stamped 70 for
 * prose like "keepassxc-cli show db.kdbx  # see export docs". The 70
 * tier now requires an export token directly bound to a keepassxc
 * executable token (keepassxc / keepassxc-cli / keepassxc.exe /
 * keepassxc-cli.exe, matched as one word-bounded token):
 *
 *   1. Direct subcommand: from a word-bounded "keepassxc" head, skip an
 *      attached ".exe", then whitespace/quotes and '-'-prefixed option
 *      tokens (the "keepassxc-cli [options] <command>" usage shape, so
 *      "-q export" and "-k <keyfile> export" both reach the command
 *      slot). The first two non-option tokens are inspected; either
 *      being exactly "export" wins. The scan stops at '#' (cmd /
 *      PowerShell comment tail - nothing after it executes).
 *   2. Hyphenated compound (deliberate retention): a word-boundary
 *      complete "export" after the first keepassxc token that belongs
 *      to a hyphenated compound - immediately followed by '-' as in
 *      "keepassxc-cli show db | export-csv out" (piped export tool:
 *      real external transfer, intentionally kept at 70) or immediately
 *      preceded by '-' as in "icon-export". Bare prose words
 *      ("export docs", "exported", "exports") do not qualify and stay
 *      in the 60 tier.
 */

constexpr size_t kKeepassxcHeadLen = sizeof("keepassxc") - 1;
constexpr size_t kExportLen = sizeof("export") - 1;

/* Token characters: lowercase letters (text is pre-lowercased), digits
 * and underscore. */
bool IsTokenChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

/* Word-boundary-complete occurrence of a needle of `length` at pos: the
 * characters immediately before and after are not token characters.
 * '-' bounds on both sides, so "export" is complete inside
 * "export-csv" / "icon-export" but not inside "exports" / "my_export". */
bool IsBoundedAt(const std::string& lower, size_t pos, size_t length) {
    if (pos > 0 && IsTokenChar(lower[pos - 1])) return false;
    const size_t end = pos + length;
    if (end < lower.size() && IsTokenChar(lower[end])) return false;
    return true;
}

/* First word-boundary-complete occurrence of needle at or after from
 * (npos when absent). */
size_t FindBoundedFrom(const std::string& lower, const char* needle,
                       size_t length, size_t from) {
    for (size_t pos = lower.find(needle, from); pos != std::string::npos;
         pos = lower.find(needle, pos + 1)) {
        if (IsBoundedAt(lower, pos, length)) return pos;
    }
    return std::string::npos;
}

/* Separators for the subcommand scan: whitespace and quoting. */
bool IsScanSeparator(char c) {
    return c == ' ' || c == '\t' || c == '"' || c == '\'';
}

size_t SkipSeparators(const std::string& lower, size_t pos) {
    while (pos < lower.size() && IsScanSeparator(lower[pos])) ++pos;
    return pos;
}

size_t TokenEnd(const std::string& lower, size_t pos) {
    while (pos < lower.size() && !IsScanSeparator(lower[pos])) ++pos;
    return pos;
}

bool TokenEquals(const std::string& lower, size_t begin, size_t end,
                 const char* word) {
    return lower.compare(begin, end - begin, word) == 0;
}

/* Direct subcommand slot check for one keepassxc executable token (see
 * the block comment above for the exact semantics). */
bool AnchorHasExportSubcommand(const std::string& lower, size_t anchor) {
    size_t pos = anchor + kKeepassxcHeadLen;
    if (lower.compare(pos, 4, ".exe") == 0) pos += 4;

    size_t nonOptionTokens = 0;
    for (;;) {
        pos = SkipSeparators(lower, pos);
        if (pos >= lower.size()) return false;
        if (lower[pos] == '#') return false; /* comment tail */
        if (lower[pos] == '-') {             /* option token */
            pos = TokenEnd(lower, pos);
            continue;
        }
        const size_t end = TokenEnd(lower, pos);
        if (TokenEquals(lower, pos, end, "export")) return true;
        /* One look-ahead token tolerates value-bearing options such as
         * "-k <keyfile> export"; anything further is outside the
         * subcommand slot and cannot upgrade the tier. */
        if (++nonOptionTokens >= 2) return false;
        pos = end;
    }
}

/* Piped/compound retention check: hyphenated export compounds after the
 * first keepassxc token (see the block comment above). */
bool HasHyphenatedExportAfter(const std::string& lower, size_t from) {
    const size_t comment = lower.find('#', from);
    const size_t limit = comment == std::string::npos ? lower.size() : comment;
    for (size_t pos = lower.find("export", from);
         pos != std::string::npos && pos + kExportLen <= limit;
         pos = lower.find("export", pos + 1)) {
        if (!IsBoundedAt(lower, pos, kExportLen)) continue;
        if (pos + kExportLen < lower.size() && lower[pos + kExportLen] == '-')
            return true; /* export-csv: head of a hyphenated compound */
        if (pos > 0 && lower[pos - 1] == '-')
            return true; /* icon-export: tail of a hyphenated compound */
    }
    return false;
}

/* True when an export token is directly bound to a keepassxc executable
 * token: the subcommand in the slot right after it (option and one
 * option-value token tolerated), or a hyphenated export compound after
 * the first token (piped exfil retention). Prose "export" words
 * elsewhere stay out. */
bool HasKeepassxcExportSubcommand(const std::string& lower) {
    const size_t first =
        FindBoundedFrom(lower, "keepassxc", kKeepassxcHeadLen, 0);
    if (first == std::string::npos) return false;
    if (HasHyphenatedExportAfter(lower, first + kKeepassxcHeadLen))
        return true;
    for (size_t pos = first; pos != std::string::npos;
         pos = FindBoundedFrom(lower, "keepassxc", kKeepassxcHeadLen,
                               pos + 1)) {
        if (AnchorHasExportSubcommand(lower, pos)) return true;
    }
    return false;
}

} // namespace

PasswordVaultDetector::PasswordVaultDetector(bool enabled, uint32_t minScore,
                                             uint32_t dedupWindowSeconds,
                                             size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool PasswordVaultDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool PasswordVaultDetector::Analyze(const std::string& lower,
                                    Finding* out) const {
    Finding best;

    /* keepass2john converts the vault into a crackable hash: extraction
     * plus cracking intent in one binary invocation. */
    if (Contains(lower, "keepass2john")) {
        best.score = 90;
        best.signal = "keepass2john_hash_extraction";
        best.tool = "keepass2john";
    }

    /* Bitwarden CLI bulk export is the account-wide credential dump. */
    if (HasBounded(lower, "bw export") ||
        HasBounded(lower, "bw.exe export")) {
        if (85 > best.score) {
            best.score = 85;
            best.signal = "bitwarden_cli_export";
            best.tool = "bitwarden";
        }
    }

    /* A vault database referenced alongside an export/copy/archive verb
     * is bulk staging of the credential store. Plain .kdbx references
     * without a verb are cred_file_hunt_detector's signal, not ours. */
    if (Contains(lower, ".kdb") &&
        ContainsAny(lower, kVaultExportVerbs,
                    sizeof(kVaultExportVerbs) / sizeof(kVaultExportVerbs[0]))) {
        if (80 > best.score) {
            best.score = 80;
            best.signal = "keepass_database_staging";
            best.tool = "keepass";
        }
    }

    /* keepassxc-cli: an explicit export subcommand is the bulk path (70);
     * any other automation-grade CLI use is a quieter 60. The judgment is
     * subcommand level (HasKeepassxcExportSubcommand): prose "export"
     * words in comments or arguments never upgrade the 60 tier, and the
     * bare GUI binary (keepassxc without -cli) stays silent unless an
     * export subcommand directly follows the executable token. */
    const bool keepassxcCliUse = Contains(lower, "keepassxc-cli");
    const bool keepassxcExportSubcommand =
        HasKeepassxcExportSubcommand(lower);
    if (keepassxcCliUse || keepassxcExportSubcommand) {
        const uint32_t score = keepassxcExportSubcommand ? 70 : 60;
        if (score > best.score) {
            best.score = score;
            best.signal = keepassxcExportSubcommand
                              ? "keepassxc_cli_export"
                              : "keepassxc_cli_noninteractive_use";
            best.tool = "keepassxc-cli";
        }
    }

    /* 1Password CLI bulk reads (op item list / op read / op:// refs). */
    if (Contains(lower, "op://") ||
        HasAnyBounded(lower, kOpCliPhrases,
                      sizeof(kOpCliPhrases) / sizeof(kOpCliPhrases[0])) ||
        (HasBounded(lower, "op.exe") &&
         ContainsAny(lower, kOpExeSubcommands,
                     sizeof(kOpExeSubcommands) /
                         sizeof(kOpExeSubcommands[0])))) {
        if (60 > best.score) {
            best.score = 60;
            best.signal = "onepassword_cli_bulk_read";
            best.tool = "1password";
        }
    }

    if (best.score == 0) return false;
    *out = best;
    return true;
}

void PasswordVaultDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kPasswordVaultScore] = std::to_string(finding.score);
    event.fields[field::kPasswordVaultVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kPasswordVaultSignals] = finding.signal;
    event.fields[field::kPasswordVaultTools] = finding.tool;
}

void PasswordVaultDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script blocks carry the body in kScriptBlockText, never
         * kCommandLine/kImage. */
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }

    const std::string lower = ToLowerAscii(text);
    Finding finding;
    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;
    if (finding.score < 55) return; /* sub-verdict: fully silent */

    const std::string key = finding.signal;
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
                "[edr-password-vault] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
