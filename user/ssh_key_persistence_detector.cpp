/*
 * ssh_key_persistence_detector.cpp - SSH authorized-keys backdoor
 * detector (T1098.004).
 */
#include "ssh_key_persistence_detector.h"

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

/* Write verbs that place key material into a destination file. */
constexpr const char* kWriteVerbs[] = {
    "echo", "set-content", "add-content", "out-file", "tee-object",
    "copy ", "copy-item", "xcopy", "robocopy", "move ", "move-item",
    "install-authorizedkey", "type nul >",
};

constexpr const char* kAuthorizedKeyFiles[] = {
    "authorized_keys", "administrators_authorized_keys",
};

constexpr const char* kSshdConfigOptions[] = {
    "pubkeyauthentication", "authorizedkeysfile",
    "permitrootlogin", "strictmodes",
};

} // namespace

SshKeyPersistenceDetector::SshKeyPersistenceDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool SshKeyPersistenceDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_RENAME;
}

bool SshKeyPersistenceDetector::Analyze(const std::string& lower,
                                        Finding* out) const {
    /* Command / script plane. */
    const bool hasAuthKeys =
        ContainsAny(lower, kAuthorizedKeyFiles,
                    sizeof(kAuthorizedKeyFiles) /
                    sizeof(kAuthorizedKeyFiles[0]));
    const bool hasWriteVerb = ContainsAny(
        lower, kWriteVerbs, sizeof(kWriteVerbs) / sizeof(kWriteVerbs[0]));

    /* ssh-keygen chained with an install destination: generation plus
     * placement is a full backdoor flow but the key is attacker-owned
     * rather than stolen, so it sits below direct authorized_keys
     * writes. Checked before the generic write-verb match. */
    if (Contains(lower, "ssh-keygen") && hasAuthKeys) {
        *out = Finding{75, "key generation chained with authorized_keys "
                           "install"};
        return true;
    }

    if (hasAuthKeys && hasWriteVerb) {
        *out = Finding{85, "public key material installed into "
                           "authorized_keys"};
        return true;
    }

    if (hasAuthKeys &&
        Contains(lower, ">")) {
        *out = Finding{70, "redirect into authorized_keys"};
        return true;
    }

    /* sshd_config tampering to widen key-based access. */
    if (Contains(lower, "sshd_config") &&
        ContainsAny(lower, kSshdConfigOptions,
                    sizeof(kSshdConfigOptions) /
                    sizeof(kSshdConfigOptions[0]))) {
        *out = Finding{65, "sshd_config option modification"};
        return true;
    }

    return false;
}

void SshKeyPersistenceDetector::Stamp(Event& event,
                                      const Finding& finding,
                                      const std::string& key) {
    event.fields[field::kSshKeyPersistScore] =
        std::to_string(finding.score);
    event.fields[field::kSshKeyPersistVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kSshKeyPersistSignals] = finding.signal;
    event.fields[field::kSshKeyPersistText] = key;
}

void SshKeyPersistenceDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty() && (event.type == EDR_EVT_FILE_CREATE ||
                         event.type == EDR_EVT_FILE_RENAME)) {
        auto pathIt = event.fields.find(field::kFilePath);
        if (pathIt == event.fields.end())
            pathIt = event.fields.find(field::kTargetPath);
        if (pathIt == event.fields.end()) return;

        /* File plane: creation/rename of the key store itself, or the
         * .ssh staging directory ahead of a key install. */
        const std::string lowerPath = ToLowerAscii(pathIt->second);
        const bool isKeyStore =
            Contains(lowerPath, "authorized_keys") ||
            Contains(lowerPath, "administrators_authorized_keys");
        const bool isSshDir =
            lowerPath.size() >= 5 &&
            lowerPath.compare(lowerPath.size() - 5, 5, "\\.ssh") == 0;
        if (!isKeyStore && !isSshDir) return;

        Finding finding;
        finding.score = isKeyStore ? 80u : 55u;
        finding.signal = isKeyStore
            ? "SSH key store file written"
            : ".ssh directory staged";
        if (finding.score >= m_minScore)
            Stamp(event, finding, lowerPath.substr(0, 160));
        return;
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
                "[edr-ssh-key-persist] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
