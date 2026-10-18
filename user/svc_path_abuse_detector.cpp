/*
 * svc_path_abuse_detector.cpp - See svc_path_abuse_detector.h
 * (T1574.009 / T1574.010).
 */
#include "svc_path_abuse_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* Principals that must never gain write access to a service binary. */
constexpr const char* kWeakPrincipals[] = {
    "everyone", "users", "authenticated users", "interactive",
    "domain users", "guests", "\\everyone", "builtin\\users",
    "\"users\"", "(f)", "authenticated_users",
};

/* Write-or-better access tokens in icacls / cacls grant syntax. */
constexpr const char* kWriteGrants[] = {
    ":f", ":m", ":w", ":(f)", ":(m)", ":(w)", "fullcontrol", "modify",
    "/g", "grant",
};

/* User-writable locations. */
bool MentionsWritableDir(const std::string& lower) {
    return Contains(lower, "\\temp\\") || Contains(lower, "%temp%") ||
           Contains(lower, "\\appdata\\") || Contains(lower, "%appdata%") ||
           Contains(lower, "\\users\\public") ||
           Contains(lower, "\\programdata\\") ||
           Contains(lower, "\\downloads\\") ||
           Contains(lower, "\\desktop\\");
}

bool ContainsAny(const std::string& value, const char* const needles[],
                 size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (Contains(value, needles[i])) return true;
    }
    return false;
}

/* Looks like a service binary or a directory that holds one. */
bool MentionsServiceBinary(const std::string& lower) {
    return Contains(lower, ".exe") || Contains(lower, "\\services\\") ||
           Contains(lower, "\\program files") ||
           Contains(lower, "service");
}

bool IsReadOnlyQuery(const std::string& lower) {
    const bool reads = Contains(lower, "sc query") ||
                       Contains(lower, "sc qc") ||
                       Contains(lower, "reg query") ||
                       Contains(lower, "get-service") ||
                       Contains(lower, "get-acl");
    if (!reads) return false;
    return !Contains(lower, "sc config") && !Contains(lower, "icacls") &&
           !Contains(lower, "cacls") && !Contains(lower, "set-acl") &&
           !Contains(lower, "reg add");
}

/* Installer / servicing writers whose service-binary writes are expected. */
bool IsTrustedWriter(const std::string& lower) {
    return Contains(lower, "msiexec") || Contains(lower, "trustedinstaller") ||
           Contains(lower, "tiworker") || Contains(lower, "wusa") ||
           Contains(lower, "\\servicing\\") || Contains(lower, "setup.exe");
}

/*
 * Extract the path VALUE assigned by a binPath= / ImagePath command line.
 *
 * Feeding the whole command line to IsExploitableUnquotedPath is wrong: a
 * command line always contains spaces (between the tool, the switches and
 * the service name), so the predicate is unconditionally true and EVERY
 * binPath write alerts -- including correctly quoted ones, unquoted paths
 * with no space, and %SystemRoot% forms. Only the value after the keyword
 * can be judged for quoting.
 *
 * Returns false when no plausible path start follows the keyword.
 */
bool ExtractAssignedPath(const std::string& raw, const std::string& lower,
                         std::string* out) {
    size_t keyword = std::string::npos;
    size_t keywordLen = 0;
    for (const char* candidate : {"binpath", "imagepath"}) {
        const size_t at = lower.rfind(candidate);
        /* npos is SIZE_MAX, so a plain std::max would let a missing
         * keyword win over a present one (the npos poisoning pattern). */
        if (at == std::string::npos) continue;
        if (keyword == std::string::npos || at > keyword) {
            keyword = at;
            keywordLen = std::strlen(candidate);
        }
    }
    if (keyword == std::string::npos) return false;

    /* Scan forward for the first token that can begin a path: an opening
     * quote, a drive letter, a UNC prefix, or an environment variable. */
    for (size_t i = keyword + keywordLen; i < raw.size(); ++i) {
        const char c = raw[i];
        if (c == '"' || c == '%') {
            *out = raw.substr(i);
            return true;
        }
        if (i + 2 < raw.size() &&
            std::isalpha(static_cast<unsigned char>(c)) && raw[i + 1] == ':' &&
            (raw[i + 2] == '\\' || raw[i + 2] == '/')) {
            *out = raw.substr(i);
            return true;
        }
        if (c == '\\' && i + 1 < raw.size() && raw[i + 1] == '\\') {
            *out = raw.substr(i);
            return true;
        }
    }
    return false;
}

} // namespace

SvcPathAbuseDetector::SvcPathAbuseDetector(bool enabled, uint32_t minScore,
                                           uint32_t dedupWindowSeconds,
                                           size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool SvcPathAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE ||
           type == EDR_EVT_SERVICE_CHANGE;
}

/* static */
bool SvcPathAbuseDetector::IsExploitableUnquotedPath(
    const std::string& imagePath) {
    if (imagePath.empty()) return false;

    /* Skip leading whitespace; a quoted path is safe by construction. */
    size_t start = imagePath.find_first_not_of(" \t");
    if (start == std::string::npos) return false;
    if (imagePath[start] == '"') return false;

    /* Only the executable token matters: arguments after it are already
     * separate argv entries and cannot be pre-empted. Find the .exe that
     * terminates the path, then look for a space BEFORE it. */
    const std::string lower = ToLowerAscii(imagePath);
    const size_t exe = lower.find(".exe", start);
    if (exe == std::string::npos) {
        /* No .exe token: fall back to the first whitespace run, which is
         * only exploitable when a path separator precedes it. */
        const size_t space = lower.find_first_of(" \t", start);
        if (space == std::string::npos) return false;
        return lower.find('\\', start) != std::string::npos &&
               lower.find('\\', start) < space;
    }

    /* A space anywhere inside the executable path is the pre-empt hook. */
    const std::string exeToken = lower.substr(start, exe + 4 - start);
    return exeToken.find(' ') != std::string::npos ||
           exeToken.find('\t') != std::string::npos;
}

bool SvcPathAbuseDetector::Analyze(const std::string& lower,
                                   const std::string& raw,
                                   Finding* out) const {
    if (IsReadOnlyQuery(lower)) return false;

    /* ACL weakening on a service binary or its directory. Checked before
     * the path shapes because an icacls line also mentions a path. */
    const bool aclTool = Contains(lower, "icacls") ||
                         Contains(lower, "cacls") ||
                         Contains(lower, "set-acl") ||
                         Contains(lower, "setacl");
    if (aclTool && MentionsServiceBinary(lower) &&
        ContainsAny(lower, kWeakPrincipals,
                    sizeof(kWeakPrincipals) / sizeof(kWeakPrincipals[0])) &&
        ContainsAny(lower, kWriteGrants,
                    sizeof(kWriteGrants) / sizeof(kWriteGrants[0]))) {
        *out = Finding{85, "service binary ACL opened to non-admin"};
        return true;
    }

    /* sc config binPath rewritten into a user-writable location. */
    if ((Contains(lower, "sc config") || Contains(lower, "sc.exe config")) &&
        Contains(lower, "binpath") && MentionsWritableDir(lower)) {
        *out = Finding{80, "service binPath repointed to writable dir"};
        return true;
    }

    /* Unquoted service path with a space: C:\Program.exe pre-empts
     * C:\Program Files\App\svc.exe. Only the ASSIGNED VALUE may be judged
     * -- see ExtractAssignedPath for why the full command line cannot be. */
    std::string assigned;
    if (ExtractAssignedPath(raw, lower, &assigned) &&
        IsExploitableUnquotedPath(assigned)) {
        *out = Finding{85, "unquoted service path with space"};
        return true;
    }

    return false;
}

void SvcPathAbuseDetector::Stamp(Event& event, const Finding& finding,
                                 const std::string& key) {
    event.fields[field::kSvcPathAbuseScore] = std::to_string(finding.score);
    event.fields[field::kSvcPathAbuseVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kSvcPathAbuseSignals] = finding.signal;
    event.fields[field::kSvcPathAbuseText] = key;
}

void SvcPathAbuseDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    std::string rawPath;

    if (event.type == EDR_EVT_SERVICE_CHANGE) {
        auto pathIt = event.fields.find(field::kServiceImagePath);
        if (pathIt == event.fields.end()) return;
        rawPath = pathIt->second;
        if (rawPath.empty()) return;

        /* The service-change plane carries the ImagePath directly, so the
         * unquoted shape is evaluated without needing a binPath keyword. */
        const std::string lowerPath = ToLowerAscii(rawPath);
        Finding finding;
        if (IsExploitableUnquotedPath(rawPath)) {
            finding = Finding{85, "unquoted service path with space"};
        } else if (MentionsWritableDir(lowerPath)) {
            finding = Finding{80, "service image in writable dir"};
        } else {
            return;
        }
        if (finding.score < m_minScore) return;
        Stamp(event, finding, lowerPath.substr(0, 160));
        return;
    }

    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        const std::string lowerKey = ToLowerAscii(keyIt->second);
        /* Only service ImagePath writes are in scope here. */
        if (!Contains(lowerKey, "\\services\\")) return;
        auto valIt = event.fields.find(field::kRegValue);
        if (valIt == event.fields.end()) return;
        rawPath = valIt->second;
        if (rawPath.empty()) return;

        const std::string lowerVal = ToLowerAscii(rawPath);
        Finding finding;
        if (IsExploitableUnquotedPath(rawPath)) {
            finding = Finding{85, "unquoted service ImagePath with space"};
        } else {
            return;
        }
        if (finding.score < m_minScore) return;
        Stamp(event, finding, (lowerKey + " " + lowerVal).substr(0, 160));
        return;
    }

    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) return;

    const std::string lower = ToLowerAscii(text);
    if (IsTrustedWriter(lower)) return;

    Finding finding;
    if (!Analyze(lower, text, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = lower.substr(0, 160);
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
                "[edr-svc-path-abuse] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
