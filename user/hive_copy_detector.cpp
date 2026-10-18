/*
 * hive_copy_detector.cpp - Sensitive registry hive copy / export
 * (T1003.002 SAM, T1003.004 LSA Secrets).
 */
#include "registry_hive_detector.h"

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

/* True when the command line refers to the whole hive root, e.g.
 * "hklm\sam" / "hklm\system" not a subkey path like
 * "hklm\system\currentcontrolset\..." (which would continue past the
 * hive name). */
bool RefersToHiveRoot(const std::string& lower, const char* hive) {
    static const char* const kPrefixes[] = {
        "hklm\\", "hkey_local_machine\\",
    };
    for (const char* prefix : kPrefixes) {
        const std::string needle = std::string(prefix) + hive;
        size_t pos = 0;
        while ((pos = lower.find(needle, pos)) != std::string::npos) {
            const size_t after = pos + needle.size();
            if (after >= lower.size() || lower[after] == ' ' ||
                lower[after] == '\t' || lower[after] == '"' ||
                lower[after] == '\'' || lower[after] == '>' ||
                lower[after] == '|')
                return true;
            pos = after;
        }
    }
    return false;
}

/* True when the text references the live hive file itself, e.g.
 * \windows\system32\config\sam — but not the "systemprofile" user
 * directory, whose name merely begins with the same letters. */
bool RefersToHiveFile(const std::string& lower, const char* hive) {
    const std::string needle = std::string("\\config\\") + hive;
    size_t pos = 0;
    while ((pos = lower.find(needle, pos)) != std::string::npos) {
        const size_t after = pos + needle.size();
        if (after >= lower.size() ||
            !std::isalnum(static_cast<unsigned char>(lower[after]))) {
            return true;
        }
        pos = after;
    }
    return false;
}

/* Output landed in a public / desktop / UNC staging location, i.e. the
 * extracted hive is being prepared for exfiltration. Temp is deliberately
 * excluded: it is a routine scratch location and does not distinguish
 * staging from ordinary tooling output. */
bool IsStagingTarget(const std::string& lower) {
    return lower.find("\\public\\") != std::string::npos ||
           lower.find("\\desktop") != std::string::npos ||
           lower.find("%public%") != std::string::npos ||
           lower.find("\\\\") != std::string::npos; /* UNC share */
}

constexpr const char* kCopyVerbs[] = {
    "copy ", "copy-item", "xcopy", "robocopy", "move ", "move-item",
    "type ", "cat ",
};

} // namespace

HiveCopyDetector::HiveCopyDetector(bool enabled, uint32_t minScore,
                                   uint32_t dedupWindowSeconds,
                                   size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool HiveCopyDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool HiveCopyDetector::Analyze(const std::string& lower,
                               Finding* out) const {
    const bool hasHiveKey =
        RefersToHiveRoot(lower, "sam") ||
        RefersToHiveRoot(lower, "security") ||
        RefersToHiveRoot(lower, "system");

    const bool staging = IsStagingTarget(lower);

    if (hasHiveKey) {
        const bool regSave = Contains(lower, "reg save") ||
                             Contains(lower, "reg.exe save");
        const bool regExport = Contains(lower, "reg export") ||
                               Contains(lower, "reg.exe export");
        if (regSave) {
            *out = staging ? Finding{90, "sensitive hive saved to staging location"}
                           : Finding{85, "sensitive registry hive saved"};
            return true;
        }
        if (regExport) {
            *out = staging ? Finding{75, "sensitive hive exported to staging location"}
                           : Finding{70, "sensitive registry hive exported"};
            return true;
        }
    }

    if (Contains(lower, "esentutl") &&
        (RefersToHiveFile(lower, "sam") ||
         RefersToHiveFile(lower, "security") ||
         RefersToHiveFile(lower, "system"))) {
        *out = Finding{85, "esentutl hive extraction"};
        return true;
    }

    if (ContainsAny(lower, kCopyVerbs,
                    sizeof(kCopyVerbs) / sizeof(kCopyVerbs[0])) &&
        (RefersToHiveFile(lower, "sam") ||
         RefersToHiveFile(lower, "security") ||
         RefersToHiveFile(lower, "system"))) {
        *out = staging ? Finding{90, "hive file copied to staging location"}
                       : Finding{85, "sensitive hive file copied"};
        return true;
    }

    return false;
}

void HiveCopyDetector::Stamp(Event& event, const Finding& finding,
                             const std::string& key) {
    event.fields[field::kHiveCopyScore] = std::to_string(finding.score);
    event.fields[field::kHiveCopyVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kHiveCopySignals] = finding.signal;
    event.fields[field::kHiveCopyCommand] = key;
}

void HiveCopyDetector::Enrich(Event& event) {
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
                "[edr-hive-copy] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr