/*
 * private_key_detector.cpp - Private key theft detector (T1552.004).
 * See header for the scoring model.
 */
#include "private_key_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

std::string LowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool Contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string Basename(const std::string& path) {
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool EndsWith(const std::string& text, const char* suffix) {
    const std::string s(suffix);
    return text.size() >= s.size() &&
           text.compare(text.size() - s.size(), s.size(), s) == 0;
}

/* Key-material filename matchers operate on a lowercased full path. */
bool IsKeyBasename(const std::string& base) {
    return base == "id_rsa" || base == "id_dsa" || base == "id_ecdsa" ||
           base == "id_ed25519" || base == "secring.gpg";
}

bool IsKeyMaterialPath(const std::string& lowerPath) {
    const std::string base = Basename(lowerPath);
    if (IsKeyBasename(base)) return true;
    if (EndsWith(base, ".ppk") || EndsWith(base, ".pfx") ||
        EndsWith(base, ".p12"))
        return true;
    if (EndsWith(base, ".pem") || EndsWith(base, ".key"))
        return Contains(lowerPath, "\\.ssh\\") ||
               Contains(lowerPath, "\\.gnupg\\") ||
               Contains(lowerPath, "\\.aws\\");
    return Contains(lowerPath, "\\.aws\\credentials");
}

/* First key-material token visible in a lowercased command line. */
std::string CommandKeyToken(const std::string& lower) {
    static const char* kTokens[] = {
        "id_rsa",   "id_dsa",  "id_ecdsa", "id_ed25519",
        "secring.gpg", ".ppk", ".pfx",     ".p12",
        ".pem",     ".key",    "\\.aws\\credentials"};
    for (const char* t : kTokens) {
        if (Contains(lower, t)) return t;
    }
    return std::string();
}

bool IsWhitelistedKeyConsumer(const std::string& imageBase) {
    return imageBase == "ssh.exe" || imageBase == "sshd.exe" ||
           imageBase == "ssh-keygen.exe" || imageBase == "git.exe" ||
           imageBase == "putty.exe" || imageBase == "pageant.exe";
}

bool IsTransientLocation(const std::string& lowerPath) {
    return Contains(lowerPath, "\\temp\\") || Contains(lowerPath, "\\tmp\\") ||
           Contains(lowerPath, "\\public\\") ||
           Contains(lowerPath, "\\appdata\\local\\temp\\") ||
           lowerPath.rfind("\\\\", 0) == 0 /* UNC share */;
}

bool HasCopyVerb(const std::string& lower) {
    static const char* kVerbs[] = {
        "type ",   "findstr", "copy ",     "xcopy",   "robocopy",
        "copy-item", "move-item", "get-content", "cp ", "cat "};
    for (const char* v : kVerbs) {
        if (Contains(lower, v)) return true;
    }
    return false;
}

} // namespace

PrivateKeyDetector::PrivateKeyDetector(bool enabled, uint32_t minScore,
                                       uint32_t dedupWindowSeconds,
                                       size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool PrivateKeyDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_FILE_READ || type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}


bool PrivateKeyDetector::AnalyzeFile(const Event& event, std::string* target,
                                     Finding* out) const {
    auto pathIt = event.fields.find(field::kFilePath);
    if (pathIt == event.fields.end() || pathIt->second.empty())
        return false;
    const std::string lowerPath = LowerAscii(pathIt->second);
    if (!IsKeyMaterialPath(lowerPath)) return false;
    *target = Basename(lowerPath);

    auto imageIt = event.fields.find(field::kImage);
    const std::string imageBase = LowerAscii(
        imageIt == event.fields.end() ? std::string()
                                      : Basename(imageIt->second));

    if (event.type == EDR_EVT_FILE_READ) {
        /* ssh/git/putty & friends legitimately read their own keys. */
        if (IsWhitelistedKeyConsumer(imageBase)) return false;
        *out = Finding{75u, "private key read by non-standard process"};
        return true;
    }

    /* FILE_CREATE: key material landing on disk. */
    if (IsWhitelistedKeyConsumer(imageBase)) return false; /* keygen */
    if (IsTransientLocation(lowerPath)) {
        *out = Finding{85u, "private key written to transient location"};
        return true;
    }
    *out = Finding{60u, "private key material staged on disk"};
    return true;
}

bool PrivateKeyDetector::AnalyzeCommand(const std::string& lower,
                                        std::string* target,
                                        Finding* out) const {
    if (Contains(lower, "crypto::")) {
        *target = "mimikatz-crypto";
        *out = Finding{90u, "mimikatz crypto module key/cert export"};
        return true;
    }
    if (Contains(lower, "certutil") && Contains(lower, "-exportpfx")) {
        *target = "certutil-exportpfx";
        *out = Finding{90u, "certutil pfx private key export"};
        return true;
    }
    if (Contains(lower, "export-pfxcertificate")) {
        *target = "export-pfxcertificate";
        *out = Finding{80u, "powershell pfx private key export"};
        return true;
    }

    const std::string token = CommandKeyToken(lower);
    if (token.empty()) return false;
    *target = token;
    if (HasCopyVerb(lower)) {
        *out = Finding{70u, "copy/read verb aimed at private key material"};
        return true;
    }
    *out = Finding{55u, "private key material referenced on command line"};
    return true;
}

void PrivateKeyDetector::Stamp(Event& event, const Finding& finding) const {
    event.fields[field::kPrivateKeyScore] = std::to_string(finding.score);
    event.fields[field::kPrivateKeyVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kPrivateKeySignals] = finding.signal;
}

void PrivateKeyDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    std::string target;
    bool hit = false;
    if (event.type == EDR_EVT_FILE_READ ||
        event.type == EDR_EVT_FILE_CREATE) {
        hit = AnalyzeFile(event, &target, &finding);
    } else {
        const std::string text = LowerAscii(
            [&event]() {
                if (event.type == EDR_EVT_POWERSHELL_SCRIPT) {
                    auto it = event.fields.find(field::kScriptBlockText);
                    if (it != event.fields.end()) return it->second;
                    return std::string();
                }
                auto it = event.fields.find(field::kCommandLine);
                if (it != event.fields.end() && !it->second.empty())
                    return it->second;
                it = event.fields.find(field::kImage);
                return it == event.fields.end() ? std::string()
                                                : it->second;
            }());
        if (!text.empty()) hit = AnalyzeCommand(text, &target, &finding);
    }
    if (!hit) return;
    if (finding.score < m_minScore) return;

    auto imageIt = event.fields.find(field::kImage);
    const std::string key =
        LowerAscii(imageIt == event.fields.end()
                       ? std::string()
                       : Basename(imageIt->second)) +
        "\x1F" + target;
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
                "[edr-private-key] state capacity %zu reached; dedup "
                "reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
