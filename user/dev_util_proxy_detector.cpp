/*
 * dev_util_proxy_detector.cpp - Trusted developer utilities proxy
 * execution detector (T1127 / T1218.004).
 */
#include "dev_util_proxy_detector.h"

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

std::string Basename(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool IsUserWritable(const std::string& lower) {
    return Contains(lower, "\\temp\\") ||
           Contains(lower, "%temp%") ||
           Contains(lower, "%tmp%") ||
           Contains(lower, "$env:temp") ||
           Contains(lower, "$env:tmp") ||
           Contains(lower, "$env:appdata") ||
           Contains(lower, "$env:localappdata") ||
           Contains(lower, "\\appdata\\") ||
           Contains(lower, "\\users\\") ||
           Contains(lower, "\\public\\") ||
           Contains(lower, "\\programdata\\") ||
           Contains(lower, "\\downloads\\") ||
           Contains(lower, "\\desktop\\") ||
           Contains(lower, "\\documents\\");
}

bool HasProjectPayload(const std::string& lower) {
    return Contains(lower, ".proj") || Contains(lower, ".csproj") ||
           Contains(lower, ".vbproj") || Contains(lower, ".xml");
}

} // namespace

DevUtilProxyDetector::DevUtilProxyDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool DevUtilProxyDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool DevUtilProxyDetector::Analyze(const std::string& lower,
                                   const std::string& imageLower,
                                   Finding* out) const {
    const std::string base = Basename(imageLower);
    const bool userWritable = IsUserWritable(lower);

    const bool msbuild =
        base == "msbuild.exe" || Contains(lower, "msbuild.exe") ||
        Contains(lower, "msbuild ");
    if (msbuild) {
        if (Contains(lower, "codetaskfactory") ||
            Contains(lower, "inlinetask") ||
            Contains(lower, "usingtask")) {
            *out = Finding{90, "MSBuild inline task execution"};
            return true;
        }
        if (userWritable && HasProjectPayload(lower)) {
            *out = Finding{75, "MSBuild user-writable project"};
            return true;
        }
    }

    const bool csc =
        base == "csc.exe" || Contains(lower, "csc.exe");
    if (csc && userWritable &&
        (Contains(lower, "/t:exe") || Contains(lower, "/t:winexe") ||
         Contains(lower, "/t:library") || Contains(lower, ".cs"))) {
        *out = Finding{85, "csc compile from user-writable path"};
        return true;
    }

    const bool installUtil =
        base == "installutil.exe" || Contains(lower, "installutil");
    if (installUtil &&
        (Contains(lower, ".dll") || Contains(lower, ".exe")) &&
        !Contains(lower, "/help") && !Contains(lower, "-help") &&
        !Contains(lower, "/?")) {
        *out = Finding{85, "InstallUtil proxy execution"};
        return true;
    }

    if ((base == "jsc.exe" || Contains(lower, "jsc.exe")) &&
        userWritable) {
        *out = Finding{80, "jsc compile from user-writable path"};
        return true;
    }

    if ((base == "ilasm.exe" || Contains(lower, "ilasm.exe")) &&
        userWritable) {
        *out = Finding{80, "ilasm assemble from user-writable path"};
        return true;
    }

    if (base == "microsoft.workflow.compiler.exe" ||
        Contains(lower, "workflow.compiler")) {
        *out = Finding{80, "Workflow.Compiler proxy execution"};
        return true;
    }

    if ((base == "vbc.exe" || Contains(lower, "vbc.exe")) &&
        userWritable &&
        (Contains(lower, "/t:exe") || Contains(lower, "/t:winexe") ||
         Contains(lower, "/t:library") || Contains(lower, ".vb"))) {
        *out = Finding{75, "vbc compile from user-writable path"};
        return true;
    }

    return false;
}

void DevUtilProxyDetector::Stamp(Event& event, const Finding& finding,
                                 const std::string& key) {
    event.fields[field::kDevUtilProxyScore] =
        std::to_string(finding.score);
    event.fields[field::kDevUtilProxyVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kDevUtilProxySignals] = finding.signal;
    event.fields[field::kDevUtilProxyText] = key;
}

void DevUtilProxyDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    std::string image;
    auto imgIt = event.fields.find(field::kImage);
    if (imgIt != event.fields.end()) image = imgIt->second;
    if (text.empty() && image.empty()) return;

    const std::string combined = ToLowerAscii(image + " " + text);
    const std::string imageLower = ToLowerAscii(image);

    Finding finding;
    if (!Analyze(combined, imageLower, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = combined.substr(0, 160);
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
                "[edr-dev-util-proxy] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
