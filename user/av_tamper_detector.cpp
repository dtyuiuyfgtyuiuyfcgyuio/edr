/*
 * av_tamper_detector.cpp - AV / EDR tampering (T1562.001).
 */
#include "av_tamper_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

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

} // namespace

AvTamperDetector::AvTamperDetector(bool enabled, uint32_t minScore,
                                   uint32_t dedupWindowSeconds,
                                   size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool AvTamperDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

/* Command-line / script tampering families, evaluated on lowercased
 * text. Order matters: the most specific (and highest) signal wins. */
bool AvTamperDetector::AnalyzeCommand(const std::string& lower,
                                      Finding* out) const {
    const bool mpPreference =
        Contains(lower, "set-mppreference") ||
        Contains(lower, "add-mppreference");

    /* Set-MpPreference / Add-MpPreference disabling an engine
     * capability. Match the switch name itself so both full cmdlet
     * spellings and -c shorthand one-liners hit; require a Defender
     * cmdlet in play to avoid false positives on unrelated products. */
    static const char* const kDisableSwitches[] = {
        "disablerealtimemonitoring",
        "disablebehaviormonitoring",
        "disableioavprotection",
        "disablescriptscanning",
        "disableintrusionpreventionsystem",
        "disablearchivescanning",
        "disablecatchupfullscan",
        "disablecatchupquickscan",
        "disableremovabledrivescanning",
        "disablescanningmappednetworkdrivesforfullscan",
        "disableblockatfirstseen",
    };
    if (mpPreference) {
        for (const char* sw : kDisableSwitches) {
            if (!Contains(lower, sw)) continue;
            *out = Finding{90,
                "defender capability disabled via mpPreference"};
            return true;
        }
    }

    /* Exclusion additions: exclusionpath / exclusionprocess /
     * exclusionextension / exclusionipaddress with a Defender cmdlet. */
    if ((Contains(lower, "exclusionpath") ||
         Contains(lower, "exclusionprocess") ||
         Contains(lower, "exclusionextension") ||
         Contains(lower, "exclusionipaddress")) &&
        mpPreference) {
        *out = Finding{80, "defender exclusion added"};
        return true;
    }

    /* Signature wipe via MpCmdRun. */
    if (Contains(lower, "mpcmdrun") &&
        Contains(lower, "removedefinitions")) {
        *out = Finding{75, "defender signature removal via mpcmdrun"};
        return true;
    }

    /* Uninstall of Defender itself (MSI package names or the
     * Uninstall-WindowsFeature/WindowsDefender family). */
    if (Contains(lower, "uninstall-windowsdefender") ||
        (Contains(lower, "msiexec") &&
         (Contains(lower, "/x") || Contains(lower, "/uninstall")) &&
         (Contains(lower, "windows-defender") ||
          Contains(lower, "windowsdefender") ||
          Contains(lower, "microsoft defender")))) {
        *out = Finding{85, "defender uninstall attempt"};
        return true;
    }
    return false;
}

/* Policy registry writes that blind Defender, plus the WDigest
 * cleartext-cache re-enable. Two producer shapes must both work:
 *   - driver/imonitor: kRegKey = bare key path,
 *     kRegValue = value NAME.
 *   - sysmon / reg_watch / reg_baseline snapshots:
 *     kRegKey = full path INCLUDING the value name,
 *     kRegValue = value DATA.
 * Disable-value names are therefore matched either as the kRegValue
 * name (driver shape) or as the trailing key component (snapshot). */
bool AvTamperDetector::AnalyzeRegistryWrite(const std::string& lowerKey,
                                            const std::string& lowerValue,
                                            Finding* out) const {
    std::string nameTail; /* trailing component of lowerKey */
    const size_t slash = lowerKey.find_last_of('\\');
    if (slash != std::string::npos) nameTail = lowerKey.substr(slash + 1);
    const auto IsDisableName = [](const std::string& candidate) {
        return candidate == "disableantispyware" ||
               candidate == "disablerealtimemonitoring" ||
               candidate == "disableioavprotection" ||
               candidate == "disablescriptscanning";
    };

    if (Contains(lowerKey, "policies\\microsoft\\windows defender")) {
        if (IsDisableName(lowerValue) || IsDisableName(nameTail)) {
            *out = Finding{85, "defender policy disable via registry"};
            return true;
        }
        /* Any value written under an Exclusions subkey (Paths,
         * Processes, Extensions, IPAddresses, ...) is an exclusion
         * addition; the concrete item is the value name / final key
         * component depending on the producer shape. */
        if (Contains(lowerKey, "\\exclusions")) {
            *out = Finding{75, "defender exclusion key written"};
            return true;
        }
        return false;
    }

    /* WDigest cleartext credential caching re-enabled; the reg_watch
     * collector already targets this exact value. */
    if ((lowerValue == "uselogoncredential" ||
         nameTail == "uselogoncredential") &&
        Contains(lowerKey, "wdigest")) {
        *out = Finding{85, "wdigest cleartext caching enabled"};
        return true;
    }
    return false;
}

void AvTamperDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kAvTamperScore] = std::to_string(finding.score);
    event.fields[field::kAvTamperVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kAvTamperSignals] = finding.signal;
}

void AvTamperDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    std::string key;

    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        const std::string lowerKey = ToLowerAscii(keyIt->second);
        auto valueIt = event.fields.find(field::kRegValue);
        const std::string lowerValue =
            valueIt == event.fields.end() ? std::string()
                                          : ToLowerAscii(valueIt->second);
        if (!AnalyzeRegistryWrite(lowerKey, lowerValue, &finding)) return;
        if (finding.score < m_minScore) return;
        key = "reg:" + lowerKey + "\\" + lowerValue;
    } else {
        /* PROCESS_START command line first; fall back to the image for
         * bare MpCmdRun invocations without a captured command line.
         * POWERSHELL_SCRIPT events carry the script body in
         * kScriptBlockText (see powershell_parser / reassembler). */
        std::string text;
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() &&
            event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
        if (text.empty()) {
            auto imgIt = event.fields.find(field::kImage);
            if (imgIt == event.fields.end()) return;
            text = imgIt->second;
        }
        const std::string lower = ToLowerAscii(text);
        if (!AnalyzeCommand(lower, &finding)) return;
        if (finding.score < m_minScore) return;
        key = "cmd:" + lower.substr(0, 160);
    }

    /* Dedup on the event's own timestamp so tests are reproducible and
     * ordering follows the single-consumer contract. */
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
                "[edr-av-tamper] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
