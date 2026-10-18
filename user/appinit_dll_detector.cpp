/*
 * appinit_dll_detector.cpp - AppInit_DLLs / AppCertDlls persistence
 * detector (T1546.010 / T1546.009).
 */
#include "appinit_dll_detector.h"

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

std::string LastComponent(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool IsBlank(const std::string& value) {
    return value.empty() || value == "\"\"" || value == "''";
}

bool IsReadOnlyQuery(const std::string& lower) {
    if (Contains(lower, "reg query") ||
        Contains(lower, "get-itemproperty") ||
        Contains(lower, "get-item ")) {
        return !Contains(lower, "reg add") &&
               !Contains(lower, "set-itemproperty") &&
               !Contains(lower, "new-itemproperty");
    }
    return false;
}

bool NamesAppInit(const std::string& text) {
    return Contains(text, "appinit_dlls");
}

bool NamesAppCert(const std::string& text) {
    return Contains(text, "appcertdlls");
}

bool NamesLoadAppInit(const std::string& text) {
    return Contains(text, "loadappinit_dlls");
}

bool NamesRequireSigned(const std::string& text) {
    return Contains(text, "requiresignedappinit_dlls");
}

} // namespace

AppinitDllDetector::AppinitDllDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool AppinitDllDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool AppinitDllDetector::Analyze(const std::string& lower,
                                 bool registryPlane,
                                 Finding* out) const {
    if (!registryPlane && IsReadOnlyQuery(lower)) return false;

    const bool appCert = NamesAppCert(lower);
    const bool loadFlag = NamesLoadAppInit(lower);
    const bool signedFlag = NamesRequireSigned(lower);
    /* AppInit_DLLs is a suffix of LoadAppInit_DLLs /
     * RequireSignedAppInit_DLLs; check those names first. */
    const bool appInit = NamesAppInit(lower) && !loadFlag && !signedFlag;
    if (!appInit && !appCert && !loadFlag && !signedFlag) return false;

    if (appCert) {
        *out = Finding{90, "AppCertDlls planted"};
        return true;
    }
    const bool writesZero =
        Contains(lower, "/d 0") || Contains(lower, "=0") ||
        Contains(lower, "= 0") || Contains(lower, "-value 0") ||
        (lower.size() >= 2 &&
         lower.compare(lower.size() - 2, 2, " 0") == 0);
    const bool writesOne =
        Contains(lower, "/d 1") || Contains(lower, "=1") ||
        Contains(lower, "= 1") || Contains(lower, "-value 1") ||
        (lower.size() >= 2 &&
         lower.compare(lower.size() - 2, 2, " 1") == 0);
    if (loadFlag && !writesZero && (writesOne || registryPlane)) {
        *out = Finding{80, "LoadAppInit_DLLs enabled"};
        return true;
    }
    if (signedFlag && writesZero) {
        *out = Finding{70, "RequireSignedAppInit_DLLs disabled"};
        return true;
    }
    if (appInit) {
        *out = Finding{90, "AppInit_DLLs planted"};
        return true;
    }
    return false;
}

void AppinitDllDetector::Stamp(Event& event, const Finding& finding,
                               const std::string& key) {
    event.fields[field::kAppinitDllScore] = std::to_string(finding.score);
    event.fields[field::kAppinitDllVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kAppinitDllSignals] = finding.signal;
    event.fields[field::kAppinitDllText] = key;
}

void AppinitDllDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    bool registryPlane = false;
    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        auto valIt = event.fields.find(field::kRegValue);
        if (keyIt != event.fields.end()) text = keyIt->second;
        if (valIt != event.fields.end()) {
            if (!text.empty()) text += " ";
            text += valIt->second;
        }
        if (keyIt != event.fields.end() && valIt != event.fields.end()) {
            const std::string lowerKey = ToLowerAscii(keyIt->second);
            const std::string lowerVal = ToLowerAscii(valIt->second);
            const std::string last = LastComponent(lowerKey);
            /* Snapshot empty-data cleanup of AppInit_DLLs. */
            if ((last == "appinit_dlls" || last == "appcertdlls") &&
                lowerVal != last && IsBlank(lowerVal))
                return;
        }
        registryPlane = true;
    } else {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
        if (text.empty()) {
            auto imgIt = event.fields.find(field::kImage);
            if (imgIt == event.fields.end()) return;
            text = imgIt->second;
        }
    }
    if (text.empty()) return;
    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!Analyze(lower, registryPlane, &finding)) return;
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
                "[edr-appinit-dll] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
