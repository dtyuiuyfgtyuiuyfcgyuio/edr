/*
 * cred_file_hunt_detector.cpp - Unsecured credentials in files
 * (T1552.001) command-plane detector.
 */
#include "cred_file_hunt_detector.h"

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

/* Credential tokens that indicate a content search for secrets. */
constexpr const char* kSearchTokens[] = {
    "password", "passwd", "pwd", "secret", "credential", "passphrase",
};

/* File names that conventionally hold plaintext credentials. */
constexpr const char* kCredFileNames[] = {
    "passwords.txt", "password.txt", "pass.txt", "passwd.txt",
    "credentials.txt", "creds.txt", "cred.txt", "secrets.txt",
    "passwords.json", "credentials.json", "secrets.json",
    "login.txt", "tokens.txt", "vault.txt", "hashes.txt", "hash.txt",
};

/* SSH private key file names / extensions. */
constexpr const char* kSshKeyNames[] = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ppk",
};

/* Verbs that read, copy, archive or move a file (exfil/staging). */
constexpr const char* kReadCopyVerbs[] = {
    "copy ", "xcopy", "robocopy", "type ", "cat ", "curl", "wget",
    "certutil", "base64", "tar ", "7z ", "zip ", "rar ", "bitsadmin",
    "nc ", "netcat", "socat", "scp ", "upload",
};

bool HasReadCopyVerb(const std::string& lower) {
    return ContainsAny(lower, kReadCopyVerbs,
                       sizeof(kReadCopyVerbs) / sizeof(kReadCopyVerbs[0]));
}

/* Recursive / wildcard file target, i.e. a whole-tree credential hunt
 * rather than a single-file look. */
bool IsRecursiveHunt(const std::string& lower) {
    return lower.find("*.", 0) != std::string::npos ||
           lower.find("/s ") != std::string::npos ||
           lower.find("/s\"") != std::string::npos ||
           lower.find("-recurse") != std::string::npos ||
           lower.find("-r ") != std::string::npos ||
           lower.find("-R ") != std::string::npos ||
           lower.find("--include") != std::string::npos;
}

} // namespace

CredentialFileHuntDetector::CredentialFileHuntDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool CredentialFileHuntDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool CredentialFileHuntDetector::Analyze(const std::string& lower,
                                         Finding* out) const {
    Finding best;

    const bool hasToken = ContainsAny(
        lower, kSearchTokens, sizeof(kSearchTokens) / sizeof(kSearchTokens[0]));
    if (hasToken) {
        const bool recursive = IsRecursiveHunt(lower);
        if (Contains(lower, "findstr")) {
            best.score = recursive ? 75 : 65;
            best.signal = recursive ? "recursive findstr credential search"
                                    : "findstr credential search";
        }
        if (Contains(lower, "select-string")) {
            const uint32_t score = recursive ? 75 : 70;
            if (score > best.score) {
                best.score = score;
                best.signal = "select-string credential search";
            }
        }
        if (Contains(lower, "grep")) {
            const uint32_t score = recursive ? 75 : 70;
            if (score > best.score) {
                best.score = score;
                best.signal = "grep credential search";
            }
        }
        if (Contains(lower, "ripgrep") || Contains(lower, "rg.exe") ||
            Contains(lower, " rg ")) {
            if (75 > best.score) {
                best.score = 75;
                best.signal = "ripgrep credential search";
            }
        }
    }

    const bool exfil = HasReadCopyVerb(lower);

    if (ContainsAny(lower, kCredFileNames,
                    sizeof(kCredFileNames) / sizeof(kCredFileNames[0]))) {
        best.score = std::max<uint32_t>(best.score, exfil ? 75 : 70);
        best.signal = "credential-bearing file referenced";
    }

    /* SSH private keys: never score genuine ssh/plink client or
     * key-generation usage; score reads/copies of the key material.
     * The client check must look for the tool invocation ("ssh ", "ssh.exe",
     * "ssh-keygen") - a bare "ssh" substring would also match the ".ssh\"
     * directory of the very key path being copied. */
    const bool sshClientContext =
        Contains(lower, "ssh ") || Contains(lower, "ssh.exe") ||
        Contains(lower, "ssh-keygen") || Contains(lower, "ssh-keygen.exe") ||
        Contains(lower, "plink");
    if (!sshClientContext &&
        ContainsAny(lower, kSshKeyNames,
                    sizeof(kSshKeyNames) / sizeof(kSshKeyNames[0]))) {
        best.score = std::max<uint32_t>(best.score, exfil ? 75 : 65);
        best.signal = "ssh private key material referenced";
    }

    if (Contains(lower, "winscp.ini")) {
        /* WinSCP.ini is a stored-credential profile: a reference alone is
         * already the full signal (70) - reading it via `type` is not an
         * additional exfil step the way copying key material is. */
        best.score = std::max<uint32_t>(best.score, 70);
        best.signal = "winscp stored-credential profile referenced";
    }
    if (Contains(lower, ".kdbx") || Contains(lower, ".kdb")) {
        best.score = std::max<uint32_t>(best.score, exfil ? 75 : 70);
        best.signal = "keepass credential database referenced";
    }
    if (Contains(lower, "keepass")) {
        best.score = std::max<uint32_t>(best.score, 65);
        best.signal = "keepass credential database tool";
    }
    if (Contains(lower, ".netrc") || Contains(lower, "_netrc")) {
        best.score = std::max<uint32_t>(best.score, 70);
        best.signal = "netrc credential file referenced";
    }

    if (Contains(lower, "net use") && Contains(lower, "/savecred")) {
        best.score = std::max<uint32_t>(best.score, 65);
        best.signal = "credential caching via net use /savecred";
    }

    if (best.score == 0) return false;
    *out = best;
    return true;
}

void CredentialFileHuntDetector::Stamp(Event& event,
                                       const Finding& finding,
                                       const std::string& key) {
    event.fields[field::kCredFileHuntScore] = std::to_string(finding.score);
    event.fields[field::kCredFileHuntVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kCredFileHuntSignals] = finding.signal;
    event.fields[field::kCredFileHuntCommand] = key;
}

void CredentialFileHuntDetector::Enrich(Event& event) {
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

    /* Dedup per normalized command prefix. */
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
                "[edr-cred-file-hunt] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr